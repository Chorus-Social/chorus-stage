# Community Endpoints

Communities organise posts and membership. Creation and membership changes
require bearer authentication.

## GET `/api/v1/communities`

- **Summary:** List all communities ordered by `order_index`.
- **Authentication:** Optional
- **Response:** `200 OK` with an array of community objects.

Community object:
```json
{
  "id": 4,
  "internal_slug": "alpha-723be5",
  "display_name": "Alpha-723be5-display",
  "description_md": "Community description",
  "is_profile_like": false,
  "order_index": 123
}
```

## GET `/api/v1/communities/{community_id}`

- **Summary:** Retrieve metadata for a specific community.
- **Authentication:** Optional
- **Status Codes:** `200 OK`, `404 Not Found`

## POST `/api/v1/communities`

- **Summary:** Create a new community; order index is assigned via the deterministic clock.
- **Authentication:** Required
- **Status Codes:** `201 Created`, `400 Bad Request`, `401 Unauthorized`, `409 Conflict`

### Request Body
```json
{
  "internal_slug": "alpha-723be5",
  "display_name": "My Community",
  "description_md": "Markdown description"
}
```

| Field | Type | Notes |
|-------|------|-------|
| `internal_slug` | string | Must be unique; conflict returns `409`. |
| `display_name` | string | Human-readable label. |
| `description_md` | string | Optional markdown description. |

### Successful Response — `201 Created`
Community object as above.

## POST `/api/v1/communities/{community_id}/join`

- **Summary:** Join the community; creates a `CommunityMember` row.
- **Authentication:** Required
- **Status Codes:** `201 Created`, `401 Unauthorized`, `404 Not Found`, `409 Conflict`

## DELETE `/api/v1/communities/{community_id}/leave`

- **Summary:** Leave the specified community (removes membership).
- **Authentication:** Required
- **Status Codes:** `204 No Content`, `401 Unauthorized`, `404 Not Found`

## GET `/api/v1/communities/{community_id}/posts`

- **Summary:** Fetch posts for a community using the deterministic ordering.
- **Authentication:** Optional
- **Query Parameters:** `limit` (default `50`, max `100`), `before` (integer).
- **Status Codes:** `200 OK`, `404 Not Found`

## Notes

- Community membership enforces uniqueness per user/community pair; joining an
  already joined community returns `409 Conflict`.
- The deterministic clock is advanced whenever a community is created to ensure
  stable ordering across services.
