# API Error Semantics

This page documents common error cases and HTTP status codes across the v1 API.
It is intended to remove ambiguity around edge cases and help clients provide
good UX for recovery.

Conventions:

- 400 Bad Request: malformed input, invalid encodings, insufficient PoW.
- 401 Unauthorized: authentication/authorization failure (bad signature, bad JWT).
- 403 Forbidden: attempting to act on resources you do not own.
- 404 Not Found: missing resources or lookups (user, post, community).
- 409 Conflict: content integrity mismatches where applicable.
- 429 Too Many Requests: replay detected or rate-limiting via nonce reuse.

## Authentication

- POST /auth/challenge
  - 400: invalid public key format, invalid intent.

- POST /auth/register
  - 400: malformed base64 fields; insufficient PoW difficulty; invalid PoW.
  - 401: signature doesn’t validate against the provided challenge/public key.
  - 429: challenge replay detected for this public key.

- POST /auth/login
  - 400: malformed base64 fields; insufficient PoW difficulty; invalid PoW.
  - 401: invalid signature.
  - 404: user not found for supplied public key.
  - 429: challenge replay detected for this public key.

## Posts

- GET /posts/{id}
  - 404: post not found or soft‑deleted.

- POST /posts
  - 400: insufficient/invalid PoW; content hash mismatch; invalid hex encodings.
  - 401: missing/invalid bearer token.
  - 404: parent post or community not found.
  - 429: PoW nonce replay.

- DELETE /posts/{id}
  - 401: missing/invalid bearer token.
  - 403: attempting to delete a post you do not own.
  - 404: post not found or already deleted.

## Votes

- POST /votes
  - 400: invalid PoW for vote.
  - 401: missing/invalid bearer token.
  - 404: post not found.
  - 429: replay detected (PoW or client nonce); harmful vote cool-down active.

## Messages

- POST /messages
  - 400: invalid PoW; malformed base64 for ciphertext/header; invalid recipient key.
  - 401: missing/invalid bearer token.
  - 404: recipient user not found.
  - 429: replay detected for PoW nonce.

- GET /messages/inbox, /messages/sent
  - 401: missing/invalid bearer token.

## Moderation and Communities

Endpoints follow the same conventions above. Additional 403 cases appear for
community‑restricted actions (e.g., membership‑gated operations) where
applicable.

- POST /moderation/trigger
  - 429: global moderation trigger cool-down active.
