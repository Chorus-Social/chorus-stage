# Vote Endpoints

Votes capture sentiment and harmful signals while enforcing replay protection.
All endpoints require a valid bearer token.

## POST `/api/v1/votes`

- **Summary:** Cast or toggle a vote on a post with proof-of-work replay protection.
- **Authentication:** Required (`Authorization: Bearer <token>`)
- **Status Codes:** `201 Created`, `400 Bad Request`, `401 Unauthorized`,
  `404 Not Found`, `429 Too Many Requests`

### Request Body
```json
{
  "post_id": 42,
  "direction": 1,
  "pow_nonce": "b73d…",
  "client_nonce": "16b8e3d2"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `post_id` | integer | ID of the target post. |
| `direction` | integer | `1` for upvote, `-1` for harmful/downvote. |
| `pow_nonce` | string | Nonce satisfying the vote difficulty. |
| `client_nonce` | string | Client-supplied nonce to prevent replay (typically 8-byte hex). |

### Successful Response — `201 Created`
```json
{ "status": "success" }
```

### Behaviour

- If a matching vote already exists with the same `direction`, the vote is removed (toggle off).
- Switching from upvote to downvote (or vice versa) adjusts the aggregated counts.
- Harmful votes update `harmful_vote_count` on the post.

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid PoW nonce or direction outside `{-1, 1}`. |
| `401 Unauthorized` | Missing/invalid bearer token. |
| `404 Not Found` | Target post does not exist or is deleted. |
| `429 Too Many Requests` | PoW or client nonce replay detected. |

## GET `/api/v1/votes/{post_id}/my-vote`

- **Summary:** Retrieve the caller’s current vote on a specific post.
- **Authentication:** Required

### Successful Response — `200 OK`
```json
{ "direction": 1 }
```

| Value | Meaning |
|-------|---------|
| `1` | Upvote recorded |
| `-1` | Harmful vote recorded |
| `0` | No vote |

### Error Responses

| Status | Description |
|--------|-------------|
| `401 Unauthorized` | Missing or invalid bearer token. |
| `404 Not Found` | Post no longer exists. |
