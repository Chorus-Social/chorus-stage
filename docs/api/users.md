# User Transparency Endpoints

These endpoints provide anonymized overviews of a single user, identified by
their `user_id` (URL‑safe base64 of the BLAKE3 hash of their public key).

Base path: `/api/v1/users`

## GET `/{user_id}/summary`

- Summary: High‑level overview of posts, votes cast, moderation participation, and community count.
- Authentication: None

Example response:
{
  "user_id": "AbCd…",
  "profile": {"display_name": "Optional", "accent_color": "#ffaa33"},
  "posts": {"total": 12, "comments": 4},
  "votes_cast": {"up": 30, "down": 9},
  "moderation": {"votes": {"harmful": 2, "not_harmful": 8}, "triggers": 1, "tokens_remaining": 2},
  "communities": {"count": 3}
}

## GET `/{user_id}/recent-posts`

- Summary: Minimal view of recent posts authored by the user.
- Authentication: None

Example response:
[
  {"id": 7, "order_index": 1234, "community_id": 1, "moderation_state": 0, "upvotes": 10, "downvotes": 2}
]

## GET `/{user_id}/communities`

- Summary: Communities the user has posted in, with post counts.
- Authentication: None

Example response:
[
  {"community_id": 1, "internal_slug": "general", "posts": 5}
]

Notes:
- Cross‑community linking is inherent for a given `user_id`. Users wishing to avoid linkability should use different keys per context.

