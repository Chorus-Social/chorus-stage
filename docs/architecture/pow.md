# Proof-of-Work Design

Chorus uses proof-of-work (PoW) as an anti‑abuse primitive across write paths
(registration, login, posts, votes, messaging). This document explains the
construction, configuration, and the adaptive “lease” feature to reduce UX
friction without sacrificing abuse resistance.

## Construction

Hash function: SHA‑256 over the UTF‑8 bytes of

```
action : pubkey_hex : challenge : nonce
```

where `challenge` is a server‑issued value that changes every 5 minutes and
`nonce` is provided by the client. The PoW is valid if the resulting hex digest
has a required number of leading zero bits (configurable per action).

Replay protection is enforced by recording used nonces for a TTL.

## Configuration

Environment variables (defaults shown in `src/chorus_stage/core/settings.py`):

- `POW_DIFFICULTY_POST`, `POW_DIFFICULTY_VOTE`, `POW_DIFFICULTY_MESSAGE`,
  `POW_DIFFICULTY_MODERATE`, `POW_DIFFICULTY_REGISTER`, `POW_DIFFICULTY_LOGIN`.
- `POW_ENABLE_LEASES` (default: true): enable adaptive credit after a success.
- `POW_LEASE_SECONDS` (default: 120): TTL for a lease credit window.
- `POW_LEASE_ACTIONS` (default: 3): number of actions allowed during the window
  without recomputing PoW.

## Adaptive Leases

After a client successfully performs PoW for an action, the server grants a
short‑lived lease keyed to the user’s public key. During the lease window, the
client can perform up to `POW_LEASE_ACTIONS` additional write actions without
presenting a fresh PoW. This balances user experience with rate‑limiting.

Implementation details:

- Backed by Redis when available; falls back to an in‑process cache during
  tests. Keys are isolated per user to preserve anonymity.
- Leases are only granted after a successful PoW registration; they are consumed
  atomically per action and expire automatically after `POW_LEASE_SECONDS`.
- Endpoints continue to register PoW nonces as before; lease handling is
  transparent to callers via `PowService.verify_pow(...)`.

## Tuning Guidance

- Lower difficulties for mobile clients and increase lease actions slightly to
  maintain UX while ensuring replay detection is enforced.
- Raise `POW_LEASE_SECONDS` during small‑community testing to reduce friction;
  reduce in production if abuse patterns emerge.
- Start conservative and observe metrics; PoW and lease knobs are runtime
  configurable.

