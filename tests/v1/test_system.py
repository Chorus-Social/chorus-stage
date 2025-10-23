"""Tests for system and transparency endpoints."""

from fastapi import status


def test_system_config(client) -> None:
    r = client.get("/api/v1/system/config")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert "app" in data and "pow" in data and "moderation" in data
    assert "difficulties" in data["pow"]
    assert "leases" in data["pow"]
    assert "cooldowns" in data["moderation"]


def test_system_clock(client) -> None:
    r = client.get("/api/v1/system/clock")
    assert r.status_code == status.HTTP_200_OK
    data = r.json()
    assert "day_seq" in data and "hour_seq" in data


def test_moderation_stats(client, auth_token, other_auth_token) -> None:
    # Create a couple of posts and votes to produce stats
    import hashlib

    def mkc(content: str) -> tuple[str, str]:
        return content, hashlib.sha256(content.encode()).hexdigest()

    c1, h1 = mkc("Stat Post 1")
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c1, "pow_nonce": "s1", "pow_difficulty": 20, "content_hash": h1},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p1 = r.json()["id"]

    c2, h2 = mkc("Stat Post 2")
    r = client.post(
        "/api/v1/posts/",
        json={"content_md": c2, "pow_nonce": "s2", "pow_difficulty": 20, "content_hash": h2},
        headers=other_auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED
    p2 = r.json()["id"]

    # Cast a harmful and a not-harmful vote
    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p1, "direction": -1, "pow_nonce": "sv1", "client_nonce": "sc1"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    r = client.post(
        "/api/v1/votes/",
        json={"post_id": p2, "direction": 1, "pow_nonce": "sv2", "client_nonce": "sc2"},
        headers=auth_token,
    )
    assert r.status_code == status.HTTP_201_CREATED

    # Fetch stats
    r = client.get("/api/v1/system/moderation-stats")
    assert r.status_code == status.HTTP_200_OK
    stats = r.json()
    assert "cases" in stats and "votes" in stats and "top_flagged_posts" in stats
    assert isinstance(stats["votes"]["harmful"], int)
