# src/chorus_stage/services/crypto.py
"""Cryptographic services for Chorus."""

from __future__ import annotations

import base64
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from chorus_stage.core.settings import settings
from chorus_stage.utils.hash import blake3_digest

PUBKEY_LENGTH_BYTES = 32
CHALLENGE_PAYLOAD_BYTES = 48


class CryptoService:
    """Service handling cryptographic operations."""

    @staticmethod
    def _decode_base64(data: str) -> bytes:
        """Decode a URL-safe base64 string, accepting omitted padding."""
        padding = "=" * (-len(data) % 4)
        try:
            return base64.urlsafe_b64decode(data + padding)
        except Exception as err:
            raise ValueError(f"Invalid base64 encoding: {err}") from err

    @staticmethod
    def _decode_hex(data: str) -> bytes:
        try:
            return bytes.fromhex(data)
        except ValueError as err:
            raise ValueError(f"Invalid hex encoding: {err}") from err

    @staticmethod
    def validate_and_decode_pubkey(pubkey_encoded: str) -> bytes:
        """Validate and decode an Ed25519 public key."""
        cleaned = pubkey_encoded.strip()
        errors: list[str] = []
        for decoder in (
            CryptoService._decode_base64,
            CryptoService._decode_hex,
        ):
            try:
                result = decoder(cleaned)
            except ValueError as err:
                errors.append(str(err))
                continue
            if len(result) != PUBKEY_LENGTH_BYTES:
                errors.append("Ed25519 public keys must be 32 bytes")
                continue
            return result
        joined = "; ".join(errors) if errors else "unknown decoding error"
        raise ValueError(f"Invalid public key format: {joined}")

    @staticmethod
    def verify_signature_bytes(pubkey_bytes: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature over raw bytes."""
        try:
            pubkey = Ed25519PublicKey.from_public_bytes(pubkey_bytes)
            pubkey.verify(signature, message)
            return True
        except (InvalidSignature, ValueError):
            return False

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
    def generate_nonce() -> str:
        """Generate a cryptographically secure nonce.

        Returns:
            Hex-encoded nonce
        """
        return secrets.token_hex(32)

    @staticmethod
    def issue_auth_challenge(intent: str, pubkey_bytes: bytes) -> tuple[str, str]:
        """Generate a signed challenge for registration/login handshakes.

        Args:
            intent: Either "register" or "login"
            pubkey_bytes: Raw public key bytes

        Returns:
            Tuple of (pow_target_hex, challenge_base64)
        """
        if not intent:
            raise ValueError("Challenge intent must be provided")

        nonce_bytes = secrets.token_bytes(16)
        pow_target = nonce_bytes.hex()
        secret: bytes = str(settings.secret_key).encode()
        payload = b"|".join(
            (
                intent.encode(),
                pubkey_bytes,
                pow_target.encode(),
                secret,
            )
        )
        mac = blake3_digest(payload)
        challenge_bytes = nonce_bytes + mac
        challenge_b64 = base64.urlsafe_b64encode(challenge_bytes).decode().rstrip("=")
        return pow_target, challenge_b64

    @staticmethod
    def validate_auth_challenge(
        intent: str,
        pubkey_bytes: bytes,
        pow_target: str,
        challenge_b64: str,
    ) -> str:
        """Validate a previously issued authentication challenge.

        Args:
            intent: Challenge intent ("register" or "login")
            pubkey_bytes: Raw public key bytes
            pow_target: Client-supplied PoW target
            challenge_b64: Base64-encoded challenge payload

        Returns:
            The server nonce (hex encoded) if validation succeeds

        Raises:
            ValueError: If the challenge payload is invalid or forged
        """
        challenge_bytes = CryptoService._decode_base64(challenge_b64)
        if len(challenge_bytes) != CHALLENGE_PAYLOAD_BYTES:
            raise ValueError("Invalid challenge payload size")

        nonce_bytes = challenge_bytes[:16]
        supplied_mac = challenge_bytes[16:]

        if nonce_bytes.hex() != pow_target:
            raise ValueError("Challenge does not match provided proof target")

        secret_key_str: str = str(settings.secret_key)
        secret: bytes = secret_key_str.encode()
        payload = b"|".join(
            (
                intent.encode(),
                pubkey_bytes,
                pow_target.encode(),
                secret,
            )
        )
        expected_mac = blake3_digest(payload)
        if not secrets.compare_digest(supplied_mac, expected_mac):
            raise ValueError("Challenge signature mismatch")

        return nonce_bytes.hex()

    @staticmethod
    def sign_message(private_key_bytes: bytes, message: bytes) -> bytes:
        """Sign a message with an Ed25519 private key.

        Args:
            private_key_bytes: Raw Ed25519 private key bytes
            message: Message to sign

        Returns:
            Raw signature bytes
        """
        try:
            private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
            return private_key.sign(message)
        except ValueError as err:
            raise ValueError(f"Invalid private key: {err}") from err

    @staticmethod
    def sign_message_hex(private_key_hex: str, message: bytes) -> bytes:
        """Sign a message with a hex-encoded Ed25519 private key.

        Args:
            private_key_hex: Hex-encoded Ed25519 private key
            message: Message to sign

        Returns:
            Raw signature bytes
        """
        try:
            private_key_bytes = bytes.fromhex(private_key_hex)
            return CryptoService.sign_message(private_key_bytes, message)
        except ValueError as err:
            raise ValueError(f"Invalid private key hex: {err}") from err
