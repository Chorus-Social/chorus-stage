# src/chorus_stage/scripts/tokens.py
"""
Cron job to refresh moderation tokens and other time-based operations.

This script should be run daily to:
1. Add moderation tokens back to users
2. Clean up old nonces
3. Update system clock for day/hour tracking
"""

import os
import time

import redis
from sqlalchemy.orm import Session

from chorus_stage.core.settings import settings
from chorus_stage.db.session import SessionLocal
from chorus_stage.models import SystemClock, User

MODERATION_TOKENS_PER_DAY = 3
HOURS_PER_DAY = 24
STALE_NONCE_DAYS = 30
SECONDS_PER_DAY = 86_400


def refresh_moderation_tokens(db: Session) -> None:
    """Give users back their moderation tokens each day.

    Args:
        db: Database session
    """
    # Reset moderation tokens for all users (they get 3 per day)
    db.query(User).update({"mod_tokens_remaining": MODERATION_TOKENS_PER_DAY})
    db.commit()
    print("Refreshed moderation tokens for all users")


def update_system_clock(db: Session) -> None:
    """Update the system clock for deterministic ordering.

    Args:
        db: Database session
    """
    # Get or create clock
    clock = db.query(SystemClock).first()
    if not clock:
        clock = SystemClock(id=1, day_seq=0, hour_seq=0)
        db.add(clock)

    # Increment day and hour sequence numbers
    clock.day_seq += 1
    # Reset hour_seq at "midnight" (every 24 increments)
    clock.hour_seq = (clock.hour_seq + 1) % HOURS_PER_DAY

    db.commit()
    print(f"Updated system clock: day={clock.day_seq}, hour={clock.hour_seq}")


def cleanup_old_nonces() -> None:
    """Clean up old entry nonce values to prevent memory issues.

    This function removes old nonce entries from Redis to prevent memory bloat.
    """
    redis_client = redis.from_url(settings.redis_url)  # type: ignore[no-untyped-call]

    # Delete entries older than 30 days
    nonce_keys = redis_client.keys("nonce:*")
    for key_bytes in nonce_keys:
        key = key_bytes.decode() if isinstance(key_bytes, bytes) else str(key_bytes)
        ttl = redis_client.ttl(key)
        # If key has a TTL we're fine, otherwise manually clean very old ones
        if ttl == -1:  # No expiry set
            parts = key.split(':')
            if len(parts) >= 3:
                try:
                    day_seq = int(parts[2])
                    current_day = int(time.time() // SECONDS_PER_DAY)
                    if current_day - day_seq > STALE_NONCE_DAYS:
                        redis_client.delete(key)
                except ValueError:
                    # Key format not as expected, delete it
                    redis_client.delete(key)

    print("Cleaned up old nonces")


if __name__ == "__main__":
    # Set environment variable to avoid validation issues in tests
    os.environ["PYTEST_RUNNING"] = "true"

    # Run daily maintenance tasks
    db = SessionLocal()
    try:
        refresh_moderation_tokens(db)
        update_system_clock(db)
        cleanup_old_nonces()
    finally:
        db.close()
