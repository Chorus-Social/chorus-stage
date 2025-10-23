# Security and Cryptography Overview

This document summarizes the current security posture, the cryptographic
primitives used across Chorus Stage, and our audit roadmap.

Scope focuses on the server runtime (this repository). Client-side encryption
details are included at a high level to clarify expectations for what the
server stores and processes.

## Threat Model (Server)

- Server is untrusted for message content: end-to-end encrypted message payloads are produced and verified by clients; the server stores opaque byte blobs.
- Server enforces proof-of-work (PoW) and replay protection to rate-limit abuse and prevent nonce reuse.
- Server never stores plaintext user identifiers; only the BLAKE3 hash of an Ed25519 public key is kept as the `user_id`.
- Bearer JWTs identify sessions; JWTs do not contain personally identifying information and are scoped to the hashed `sub`.

Out of scope: traffic analysis, metadata deanonymization across multiple
communities, and endpoint enumeration by a global network adversary.

## Primitives in Use

- Identity: Ed25519 keypairs (RFC 8032). Public keys are supplied as URL–safe base64 or hex and validated to be 32 bytes. See `services/crypto.py`.
- Hashing: BLAKE3 for user ID derivation and internal MACs; SHA‑256 for PoW evaluations and content integrity checks.
- Authentication: stateless JWTs signed with HS256 (configurable). See
  `api/v1/endpoints/auth.py` and `core/settings.py` for algorithm/expiry.
- Replay protection: Redis-backed (if available) nonce tracking with in-process fallback during tests. See `services/replay.py`.
- Proof-of-work: leading‑zero SHA‑256 over
  `action:pubkey_hex:challenge:nonce` with per‑action difficulty and optional
  adaptive “lease” credit. See `services/pow.py`.

## Direct Messaging: E2E Expectations

- Encryption is performed client‑side. The server accepts and returns:
  - `ciphertext` (opaque bytes, base64-encoded over the wire)
  - optional `header_blob` for protocol metadata (e.g., sender’s ephemeral key)
- A compatible client SHOULD use modern, audited constructions such as
  libsodium’s `crypto_box_seal` (X25519 + XChaCha20‑Poly1305) or a double‑ratchet
  variant that provides forward secrecy and post‑compromise security.
- The server does not and cannot decrypt message content.

## Proof-of-Work: Abuse Throttling

- Per‑action difficulties are configured via environment variables
  (e.g., `POW_DIFFICULTY_POST`, `POW_DIFFICULTY_VOTE`).
- Replays are rejected by tracking PoW nonces for a TTL.
- Optional adaptive leases reduce UX friction: after a valid PoW is registered,
  clients receive a short‑lived allowance to perform a small number of actions
  without recomputing PoW. Tuned via `POW_ENABLE_LEASES`, `POW_LEASE_SECONDS`,
  `POW_LEASE_ACTIONS`.

## Key Handling

- Registration/Login challenges are MACed with a server secret using BLAKE3 to
  prevent forgery and bound to the presented public key.
- Public keys are the only long‑term identifier; private keys never leave the
  client.

## Audit Roadmap

1. Short‑term: expand unit tests around signature verification and challenge
   binding, including negative tests and malformed encodings.
2. Crypto review (internal): validate Ed25519 usage, BLAKE3 contexts, and PoW
   construction for obvious foot‑guns; verify JWT configuration and rotation
   procedures.
3. External review: commission a focused audit on the authentication handshake
   and replay protection surfaces, and a separate protocol review for the client
   E2E scheme once public reference clients are released.
4. Hardening: adopt key pinning for service‑to‑service calls (if applicable),
   add device binding optionality, and publish a formal security whitepaper.

If you discover a vulnerability, please open a security‑only channel (see
CONTRIBUTING.md) and avoid filing public issues until coordinated disclosure is
agreed.

