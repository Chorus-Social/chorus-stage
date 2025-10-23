# Posts & Feed Endpoints

These endpoints manage deterministic content ordering, post creation, and
hierarchical replies. All post mutations require a valid bearer token.

## GET `/api/v1/posts`

- **Summary:** Fetch the global feed ordered by the deterministic system clock.
- **Authentication:** Optional (bearer recommended for personalised fields).
- **Query Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `limit` | integer (default `50`, max `100`) | Maximum number of posts to return. |
| `before` | integer | Return posts with `order_index` less than this value. |
| `community_slug` | string | Limit results to the specified community slug. |

### Successful Response — `200 OK`
An array of post objects:
```json
[
  {
    "id": 12,
    "order_index": 20034,
    "author_user_id": "URL_SAFE_B64",
    "author_pubkey": "HEX",
    "parent_post_id": null,
    "community_id": 4,
    "body_md": "Post content…",
    "content_hash": "SHA256_HEX",
    "moderation_state": 0,
    "harmful_vote_count": 1,
    "upvotes": 4,
    "downvotes": 0,
    "deleted": false
  }
]
```

## GET `/api/v1/posts/{post_id}`

- **Summary:** Retrieve a single post by ID.
- **Authentication:** Optional
- **Response:** `200 OK` with a `PostResponse` object as above, or `404 Not Found`.

## GET `/api/v1/posts/{post_id}/children`

- **Summary:** Fetch replies to a post in deterministic order.
- **Authentication:** Optional
- **Query Parameters:** `limit` (default `50`, max `100`), `before` (integer).
- **Response:** `200 OK` with an array of `PostResponse` objects, or `404` if the
  parent does not exist.

## POST `/api/v1/posts`

- **Summary:** Create a new post or threaded reply after validating PoW and the content hash.
- **Authentication:** Required (`Authorization: Bearer <token>`)
- **Status Codes:** `201 Created`, `400 Bad Request`, `401 Unauthorized`,
  `404 Not Found`, `429 Too Many Requests`

### Request Body
```json
{
  "content_md": "Hello Chorus!",
  "community_internal_slug": "alpha-723be5",
  "parent_post_id": null,
  "pow_nonce": "f7ab12…",
  "pow_difficulty": 20,
  "content_hash": "SHA256_HEX"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `content_md` | string | Markdown body. |
| `community_internal_slug` | string | Optional slug; if omitted the post is global. |
| `parent_post_id` | integer | Optional; set when creating a reply. |
| `pow_nonce` | string | Nonce satisfying the post difficulty. |
| `pow_difficulty` | integer | Difficulty level achieved by the client (must meet or exceed server expectation). |
| `content_hash` | string | Hexadecimal SHA-256 of `content_md`. |

### Successful Response — `201 Created`
`PostResponse` object for the created post.

### Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid content hash, insufficient PoW, or malformed payload. |
| `401 Unauthorized` | Missing or invalid bearer token. |
| `404 Not Found` | Provided `parent_post_id` or community slug not found. |
| `429 Too Many Requests` | Replayed PoW nonce detected. |

## Data Model Notes

- `moderation_state` values: `0` (OPEN), `1` (HIDDEN), `2` (CLEARED).
- `content_hash` is stored as raw bytes; API converts to hex for clients.
- Vote counts (`upvotes`, `downvotes`, `harmful_vote_count`) are consistent across requests thanks to the deterministic clock.
