"""Stub for federation_pb2 protobuf classes.

This is a temporary stub to fix import errors while the protobuf
dependencies are being resolved.
"""

from typing import Any


class FederationEnvelope:
    """Stub for FederationEnvelope protobuf class."""
    
    def __init__(self, **kwargs: Any) -> None:
        self.sender_instance = kwargs.get('sender_instance', '')
        self.timestamp = kwargs.get('timestamp', 0)
        self.message_type = kwargs.get('message_type', '')
        self.message_data = kwargs.get('message_data', b'')
        self.signature = kwargs.get('signature', b'')
    
    def SerializeToString(self) -> bytes:
        """Serialize to bytes."""
        return b''
    
    def ParseFromString(self, data: bytes) -> None:
        """Parse from bytes."""
        pass


class UserRegistration:
    """Stub for UserRegistration protobuf class."""
    
    def __init__(self, **kwargs: Any) -> None:
        self.user_pubkey = kwargs.get('user_pubkey', b'')
        self.registration_day = kwargs.get('registration_day', 0)
        self.day_proof_hash = kwargs.get('day_proof_hash', b'')
    
    def SerializeToString(self) -> bytes:
        """Serialize to bytes."""
        return b''


class ModerationEvent:
    """Stub for ModerationEvent protobuf class."""
    
    def __init__(self, **kwargs: Any) -> None:
        self.target_ref = kwargs.get('target_ref', b'')
        self.action = kwargs.get('action', '')
        self.reason_hash = kwargs.get('reason_hash', b'')
        self.moderator_pubkey_hash = kwargs.get('moderator_pubkey_hash', b'')
        self.creation_day = kwargs.get('creation_day', 0)
    
    def SerializeToString(self) -> bytes:
        """Serialize to bytes."""
        return b''
