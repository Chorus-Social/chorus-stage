# Chorus Agents

Chorus Stage is organized around a small set of domain-focused “agents.” Each agent owns a slice of behavior and collaborates with the others to deliver the anonymous-by-design social network. This document explains who they are, where they live in the codebase, and how they coordinate.

## Runtime API Agents

### FastAPI Gateway
- **Role**: Binds all public REST endpoints and exposes health checks.
- **Entry point**: `src/chorus_stage/main.py`
- **Key collaborations**: Mounts the routers exported from `chorus_stage.api.v1`, wires shared dependencies (DB sessions, PoW service), and hosts the OpenAPI schema.

### Auth Agent
- **Role**: Owns Ed25519-based registration/login and JWT issuance.
- **Code**: `src/chorus_stage/api/v1/endpoints/auth.py`
- **Key flows**: Validates URL-safe base64 keys via `CryptoService`, enforces registration proof-of-work and signature challenges, persists identities in the `anon_key` table, and issues bearer tokens using `core.settings`.
- **Endpoints**:
  - `POST /api/v1/auth/register`
  - `POST /api/v1/auth/login`
- **Schemas**: `schemas.user.RegisterRequest`, `schemas.user.RegisterResponse`

### Post Agent
- **Role**: Handles feed ordering, post CRUD, and proof-of-work checks for submissions.
- **Code**: `src/chorus_stage/api/v1/endpoints/posts.py`
- **Key flows**: Verifies PoW through `PowService`, enforces integrity with content hashes, and advances the monotonic ordering via the `SystemClock`.

### Vote Agent
- **Role**: Applies per-user votes with replay protection and moderation bookkeeping.
- **Code**: `src/chorus_stage/api/v1/endpoints/votes.py`
- **Key flows**: Uses `PowService` and `ReplayProtectionService` to throttle abuse, updates `PostVote` / post aggregates, and updates harmful vote counters.

### Community Agent
- **Role**: Manages community metadata and membership lifecycles.
- **Code**: `src/chorus_stage/api/v1/endpoints/communities.py`
- **Key flows**: Creates deterministic `Community.order_index` values via `SystemClock`, maintains the `CommunityMember` join table, and exposes community-specific post listings.

### Messaging Agent
- **Role**: Stores and retrieves end-to-end encrypted direct messages.
- **Code**: `src/chorus_stage/api/v1/endpoints/messages.py`
- **Key flows**: Validates recipients, checks PoW, registers replay nonces, and preserves ciphertext/header blobs without decryption.

### Moderation Agent
- **Role**: Coordinates token-based moderation triggers, case state transitions, and community voting.
- **Code**: `src/chorus_stage/api/v1/endpoints/moderation.py`, `src/chorus_stage/services/moderation.py`
- **Key flows**: Spends user moderation tokens, opens `ModerationCase` records, tallies `ModerationVote`s, and drives post state transitions (`OPEN` → `CLEARED`/`HIDDEN`).

## Cross-Cutting Support Agents

### Crypto Agent
- **Role**: Provides Ed25519 validation/signature utilities and key derivation helpers.
- **Code**: `src/chorus_stage/services/crypto.py`, `src/chorus_stage/core/security.py`
- **Consumers**: Auth, voting, and messaging flows.

### Proof-of-Work Agent
- **Role**: Issues challenges, validates PoW submissions, and records nonce reuse.
- **Code**: `src/chorus_stage/services/pow.py`, `src/chorus_stage/core/pow.py`
- **Dependencies**: Delegates replay tracking to `ReplayProtectionService`; difficulty thresholds come from `core.settings`.

### Replay Protection Agent
- **Role**: Detects reused session/client nonces across actions.
- **Code**: `src/chorus_stage/services/replay.py`
- **Runtime modes**: Prefers Redis (configured via `REDIS_URL`) but falls back to in-process caches in tests or when Redis is unavailable.

### Persistence Agent
- **Role**: Configures SQLAlchemy, exposes `SessionLocal`, and registers ORM models.
- **Code**: `src/chorus_stage/db/session.py`, `src/chorus_stage/models/*`
- **Schemas**: Models capture posts, votes, communities, users, moderation, system clock monotonic counters, and replay records.

### Deterministic Clock Agent
- **Role**: Supplies timestamp-free ordering primitives.
- **Code**: `src/chorus_stage/models/system_clock.py`, helpers in `posts.py`, `messages.py`, `moderation.py`
- **Usage**: Every state transition that needs ordering (posts, messages, moderation cases) increments `SystemClock.day_seq`.

## Operational Agents

### Database Agent
- **Role**: PostgreSQL container that backs the application.
- **Definition**: `compose.yml` (`chorus_db` service) with optional `adminer` UI.
- **Tooling**: `src/chorus_stage/scripts/ensure_db.py` and Alembic migrations in `migrations/`.

### Maintenance Agent
- **Role**: Daily housekeeping (moderation token resets, system clock advances, nonce cleanup).
- **Script**: `src/chorus_stage/scripts/tokens.py`
- **Schedule**: Intended for cron; expects Redis when cleaning stale nonces.

### Alpha Check Agent
- **Role**: End-to-end readiness verifier for local environments.
- **Script**: `src/chorus_stage/scripts/alpha_check.py`
- **Checks**: Repository hygiene, dependency/tool availability, API smoke tests, and cryptographic signing round-trips.

## Interaction Summary

1. **Client onboarding**: The Auth Agent validates an Ed25519 keypair by checking PoW and a signed challenge, stores only the BLAKE3 user hash, and issues JWTs for downstream requests.
2. **Content lifecycle**: Post Agent accepts content after PoW validation, indexing via the Deterministic Clock Agent. Vote Agent updates sentiment and harmful counters while replay protection prevents duplicate submissions.
3. **Moderation loop**: Users spend tokens (tracked by Maintenance Agent) to open cases. Moderation Agent tallies votes and, when thresholds from `core.settings` are met, updates post visibility.
4. **Private communication**: Messaging Agent ensures only encrypted blobs are stored, while Proof-of-Work and Replay Protection Agents rate-limit spam attempts.

Understanding these agents and their touchpoints should make it straightforward to extend Chorus Stage or plug in additional infrastructure.
