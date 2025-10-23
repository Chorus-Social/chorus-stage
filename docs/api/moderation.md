# Moderation Endpoints

Moderation tokens allow users to flag content, vote on cases, and inspect
history. All endpoints require bearer authentication.

## GET `/api/v1/moderation/queue`

- **Summary:** Retrieve posts currently in the moderation queue (`state == OPEN`).
- **Authentication:** Required
- **Query Parameters:** `limit` (default `50`, max `100`), `before` (integer)
- **Response:** `200 OK` with an array of `PostResponse` objects.

## POST `/api/v1/moderation/trigger`

- **Summary:** Spend a moderation token to trigger review for a post.
- **Authentication:** Required
- **Parameters:** Query string `post_id=<int>`
- **Status Codes:** `201 Created`, `401 Unauthorized`, `404 Not Found`, `429 Too Many Requests`

### Successful Response
```json
{ "status": "moderation_triggered", "case_id": 42 }
```

### Notes
- Requires available moderation tokens (`UserState.mod_tokens_remaining`).
- Triggering the same post within the current epoch returns `429`.

## POST `/api/v1/moderation/vote`

- **Summary:** Cast or update a moderation vote on a case.
- **Authentication:** Required
- **Parameters:**

| Name | Type | Description |
|------|------|-------------|
| `post_id` | integer | Target post ID (query string). |
| `is_harmful` | boolean | `true` to mark harmful, `false` to clear. |

- **Status Codes:** `201 Created`, `401 Unauthorized`, `404 Not Found`
- **Response:**
```json
{ "status": "vote_recorded" }
```

Moderation state transitions are computed server-side based on community size
and configured thresholds (`HARMFUL_HIDE_THRESHOLD`, `CLEAR_THRESHOLD`).

## GET `/api/v1/moderation/history`

- **Summary:** List moderation cases that involve posts authored by the caller.
- **Authentication:** Required
- **Query Parameters:** `limit` (default `50`, max `100`), `before` (integer)
- **Successful Response — `200 OK`**
```json
[
  {
    "post_id": 6,
    "state": 0,
    "opened_order_index": 12345
  }
]
```

| Field | Description |
|-------|-------------|
| `state` | Current moderation state (`0` OPEN, `1` HIDDEN, `2` CLEARED). |
| `opened_order_index` | Deterministic ordering hint from `SystemClock`. |
