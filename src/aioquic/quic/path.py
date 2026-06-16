import binascii
import logging
import os
from collections import deque
from dataclasses import dataclass
from typing import (
    Any,
    Deque,
    Dict,
    List,
    Optional,
    Set,
)
from .. import tls
from .recovery import QuicPacketRecovery, QuicPacketSpace

NetworkAddress = Any


def dump_cid(cid: bytes) -> str:
    return binascii.hexlify(cid).decode("ascii")


@dataclass
class QuicConnectionId:
    cid: bytes
    sequence_number: Optional[int]
    stateless_reset_token: bytes = b""
    was_sent: bool = False


class PathTuple:
    def __init__(
        self, 
        local_addr: NetworkAddress, 
        remote_addr: NetworkAddress, 
        is_validated: bool = False
    ):
        self.local_addr: NetworkAddress = local_addr
        self.remote_addr: NetworkAddress = remote_addr
        self.bytes_received: int = 0
        self.bytes_sent: int = 0
        self.is_validated: bool = is_validated
        self.local_challenges: Deque[bytes] = deque()
        self.local_challenge_sent: bool = False
        self.remote_challenges: Deque[bytes] = deque()

    def can_send(self, size: int) -> bool:
        return self.is_validated or (self.bytes_sent + size) <= 3 * self.bytes_received


class QuicNetworkPath:
    def __init__(
        self,
        path_id: int,
        path_tuple: Optional[PathTuple],
        host_cid: Optional[QuicConnectionId],
        peer_cid: Optional[QuicConnectionId],
        loss: QuicPacketRecovery,
        logger: Optional[logging.LoggerAdapter] = None,
    ):
        # host_cid, peer_cid, and path_tuple can be None for paths in stock only.
        self.path_id: int = path_id
        self.host_cid: bytes = b''
        self.host_cids: List[QuicConnectionId] = []
        self.host_cid_seq: int = 1
        self.peer_cid: Optional[QuicConnectionId] = None
        self.path_tuples: List[PathTuple] = []
        self.active_path_tuple: Optional[PathTuple] = path_tuple
        self.pacing_at: Optional[float] = None
        self.packet_number: int = 0
        self.peer_cid_available: List[QuicConnectionId] = []
        self.peer_cid_sequence_numbers: Set[int] = set()
        self.peer_retire_prior_to = 0
        self.loss = loss
        self.loss_at: Optional[float] = None
        self.spaces: Dict[tls.Epoch, QuicPacketSpace] = {}

        self._logger = logger

        # things to send
        self.retire_connection_ids: List[int] = []

        if host_cid is not None:
            self.host_cid = host_cid.cid
            self.host_cids = [host_cid]
        if peer_cid is not None:
            self.peer_cid = peer_cid
            self.peer_cid_sequence_numbers.add(0)
        if path_tuple is not None:
            self.path_tuples: List[PathTuple] = [path_tuple]

        
    def change_connection_id(self) -> None:
        """
        Switch to the next available connection ID and retire
        the previous one.

        """
        if self.peer_cid_available:
            # retire previous CID
            self.retire_peer_cid(self.peer_cid)

            # assign new CID
            self.consume_peer_cid()
    
    def consume_peer_cid(self) -> None:
        """
        Update the destination connection ID by taking the next
        available connection ID provided by the peer.
        """

        self.peer_cid = self.peer_cid_available.pop(0)
        self._logger.debug(
            "Switching to CID %s (%d) for path %d",
            dump_cid(self.peer_cid.cid),
            self.peer_cid.sequence_number,
            self.path_id,
        )

    def discard_epoch(self, epoch: tls.Epoch) -> None:
        self.loss.discard_space(self.spaces[epoch])
        self.spaces[epoch].discarded = True
    
    def handle_new_connection_id_frame(
            self, 
            sequence_number: int, 
            retire_prior_to: int, 
            connection_id: bytes, 
            stateless_reset_token: bytes,
        ) -> bool:
        record_path_id = False

        # only accept retire_prior_to if it is bigger than the one we know
        self.peer_retire_prior_to = max(retire_prior_to, self.peer_retire_prior_to)

        # determine which CIDs to retire
        change_cid = False
        retire = [
            cid
            for cid in self.peer_cid_available
            if cid.sequence_number < self.peer_retire_prior_to
        ]
        if self.peer_cid is not None and self.peer_cid.sequence_number < self.peer_retire_prior_to:
            change_cid = True
            retire.insert(0, self.peer_cid)

        # update available CIDs
        self.peer_cid_available = [
            cid
            for cid in self.peer_cid_available
            if cid.sequence_number >= self.peer_retire_prior_to
        ]
        if (
            sequence_number >= self.peer_retire_prior_to
            and sequence_number not in self.peer_cid_sequence_numbers
        ):
            self.peer_cid_available.append(
                QuicConnectionId(
                    cid=connection_id,
                    sequence_number=sequence_number,
                    stateless_reset_token=stateless_reset_token,
                )
            )
            self.peer_cid_sequence_numbers.add(sequence_number)
            record_path_id = True

        # retire previous CIDs
        for quic_connection_id in retire:
            self.retire_peer_cid(quic_connection_id)

        # assign new CID if we retired the active one
        if change_cid:
            self.consume_peer_cid()
        
        return record_path_id
    
    def init_peer_cid(self, source_cid: bytes, sequence_number: int) -> None:
        # self.peer_cid.sequence_number is None must be checked prior to this function call
        self.peer_cid.cid = source_cid
        self.peer_cid.sequence_number = sequence_number
    
    def replenish_connection_ids(
            self, connection_id_length: int, remote_active_connection_id_limit: int
        ) -> List[bytes]:
        """
        Generate new connection IDs. 
        Return generated IDs.
        """
        cids = []
        while len(self.host_cids) < min(8, remote_active_connection_id_limit):
            cid = os.urandom(connection_id_length)
            self.host_cids.append(
                QuicConnectionId(
                    cid=cid,
                    sequence_number=self.host_cid_seq,
                    stateless_reset_token=os.urandom(16),
                )
            )
            self.host_cid_seq += 1
            cids.append(cid)
        return cids

    def retire_peer_cid(self, quic_connection_id: QuicConnectionId) -> None:
        """
        Retire a destination connection ID.
        """
        self._logger.debug(
            "Retiring CID %s (%d) [%d] for path %d",
            dump_cid(quic_connection_id.cid),
            quic_connection_id.sequence_number,
            len(self.retire_connection_ids) + 1,
            self.path_id,
        )
        self.retire_connection_ids.append(quic_connection_id.sequence_number)
    
