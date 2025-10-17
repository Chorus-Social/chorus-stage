# src/chorus_stage/services/crypto.py
"""Cryptographic services for Chorus."""

import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptoService:
    """Service handling cryptographic operations."""

    @staticmethod
    def validate_and_decode_pubkey(pubkey_hex: str) -> bytes:
        """Validate and decode a hex-encoded Ed25519 public key.

        Args:
            pubkey_hex: Hex-encoded Ed25519 public key

        Returns:
            Decoded public key as bytes

        Raises:
            ValueError: If the public key is invalid
        """
        try:
            return bytes.fromhex(pubkey_hex)
        except ValueError as e:
            raise ValueError(f"Invalid public key format: {e}")

    @staticmethod
    def verify(pubkey_bytes: bytes, message: str, signature: bytes) -> bool:
        """Verify an Ed25519 signature.

        Args:
            pubkey_bytes: Ed25519 public key as bytes
            message: Message that was signed
            signature: Signature to verify

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            pubkey.verify(signature, message.encode())
            return True
        except (InvalidSignature, ValueError):
            return False

    @staticmethod
    def generate_session_key_pair() -> tuple[str, str]:
        """Generate a new Ed25519 key pair for client sessions.

        Returns:
            Tuple of (private_key_hex, public_key_hex)
        """
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        private_hex = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()

        public_hex = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()

        return private_hex, public_hex

    @staticmethod
    def derive_key_from_pgp(pgp_fingerprint: str) -> bytes:
        """Derive a symmetric key from a PGP fingerprint for E2E encryption.

        Args:
            pgp_fingerprint: PGP public key fingerprint

        Returns:
            Derived symmetric key
        """
        salt = b"chorus-derivation-salt-v1"
        info = b"pgp-e2e-message-encryption"

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=info,
        )

        derived: bytes = hkdf.derive(pgp_fingerprint.encode())
        return derived

    @staticmethod
    def generate_nonce() -> str:
        """Generate a cryptographically secure nonce.

        Returns:
            Hex-encoded nonce
        """
        return secrets.token_hex(32)
