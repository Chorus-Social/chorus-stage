# Chorus Stage API Overview

All REST endpoints are exposed beneath the FastAPI gateway at:

- Base URL (default): `http://127.0.0.1:8080`
- OpenAPI schema: `http://127.0.0.1:8080/openapi.json`
- Interactive docs: `http://127.0.0.1:8080/docs`

The API is versioned under the `/api/v1` prefix. Unless otherwise noted, JSON
payloads should be encoded as UTF‑8 and requests must include the
`Content-Type: application/json` header. Endpoints that mutate state typically
expect a valid bearer token produced by the authentication flow.

This documentation set is organised by feature area:

- [`auth.md`](auth.md) – anonymous identity handshake and token issuance
- [`posts.md`](posts.md) – deterministic feed, post creation, and retrieval
- [`votes.md`](votes.md) – sentiment and harmful vote capture
- [`communities.md`](communities.md) – community metadata and membership
- [`messages.md`](messages.md) – end-to-end encrypted direct messaging
- [`moderation.md`](moderation.md) – moderation triggers, voting, and audit data
- [`system.md`](system.md) – health checks and utility endpoints
- [`users.md`](users.md) – anonymized user summaries and recent activity
  - Includes transparency endpoints for config, clock, and moderation stats

> ℹ️ **Authentication tokens**  
> The “Authentication” subsection on each endpoint describes whether the
> `Authorization: Bearer <token>` header is required. Tokens are issued by
> `/api/v1/auth/login` and inherit the configured expiry window
> (`ACCESS_TOKEN_EXPIRE_MINUTES`).
