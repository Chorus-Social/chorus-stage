# System and Transparency Endpoints

These endpoints expose non-sensitive, aggregated information about the running
service to support transparency and community oversight.

Base path: `/api/v1/system`

## GET `/config`

- Summary: Return a sanitized snapshot of runtime configuration.
- Authentication: None

Example response:
{
  "app": {"name": "Chorus Stage", "version": "0.1.0", "jwt_algorithm": "HS256", "access_token_expire_minutes": 43200, "debug": false},
  "pow": {"difficulties": {"post": 20, "vote": 15, "message": 18, "moderate": 16, "register": 18, "login": 16}, "challenge_window_seconds": 300, "leases": {"enabled": true, "seconds": 120, "actions": 3}},
  "moderation": {"thresholds": {"min_votes": 5.0, "hide_ratio": 0.2}, "min_community_size": 25, "cooldowns": {"harmful_vote_author_seconds": 900, "harmful_vote_post_seconds": 120, "trigger_seconds": 60}}
}

## GET `/clock`

- Summary: Expose the deterministic system clock counters.
- Authentication: None

Example response:
{ "day_seq": 1234, "hour_seq": 17 }

## GET `/moderation-stats`

- Summary: Return aggregated moderation stats without revealing identities.
- Authentication: None

Example response:
{
  "cases": {"total": 42, "open": 10, "cleared": 20, "hidden": 12},
  "votes": {"harmful": 100, "not_harmful": 250},
  "per_community": [{"community_id": 1, "internal_slug": "general", "cases": 12}],
  "top_flagged_posts": [{"post_id": 7, "harmful_vote_count": 9, "moderation_state": 2}]
}

