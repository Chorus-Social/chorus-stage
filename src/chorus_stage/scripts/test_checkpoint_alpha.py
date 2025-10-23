"""End-to-end alpha checkpoint script that exercises the live API."""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib
import json
import os
import sys
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from secrets import token_hex
from typing import Any, cast
from urllib.parse import urljoin

from nacl.bindings import crypto_sign_ed25519_pk_to_curve25519
from nacl.public import PublicKey, SealedBox

requests = importlib.import_module("requests")

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_NO_CONTENT = 204

LOG_PREFIX = "[alpha-check]"


def log(msg: str) -> None:
    print(f"{LOG_PREFIX} {msg}")


def log_step(step: str) -> None:
    log(f"→ {step}")


def log_result(result: str) -> None:
    log(f"✓ {result}")


def warn(msg: str) -> None:
    print(f"{LOG_PREFIX} WARN: {msg}", file=sys.stderr)


def fail(msg: str) -> None:
    raise RuntimeError(msg)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_b64url(payload: str) -> bytes:
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding)


def _pow_seed(action: str, pubkey_hex: str, target: str, nonce: str) -> bytes:
    return f"{action}:{pubkey_hex}:{target}:{nonce}".encode()


def _pow_satisfies(action: str, pubkey_hex: str, target: str, nonce: str, difficulty: int) -> bool:
    if difficulty <= 0:
        return True
    digest = hashlib.sha256(_pow_seed(action, pubkey_hex, target, nonce)).hexdigest()
    leading = 0
    for char in digest:
        if char == "0":
            leading += 4
            if leading >= difficulty:
                return True
            continue
        hex_digit = int(char, 16)
        for bit in range(3, -1, -1):
            if (hex_digit >> bit) & 1:
                return leading >= difficulty
            leading += 1
            if leading >= difficulty:
                return True
        break
    return leading >= difficulty


def solve_pow(
    action: str,
    pubkey_hex: str,
    target: str,
    difficulty: int,
    *,
    timeout_s: float = 15.0,
) -> tuple[str, int]:
    deadline = time.time() + timeout_s
    attempts = 0
    while time.time() < deadline:
        nonce = token_hex(8)
        attempts += 1
        if _pow_satisfies(action, pubkey_hex, target, nonce, difficulty):
            return nonce, attempts
    fail(f"PoW solve timeout for {action} at difficulty {difficulty} after {attempts} attempts")
    raise RuntimeError  # unreachable


def pow_target_for(action: str, pubkey_hex: str) -> str:
    bucket = int(time.time() // 300)
    seed = f"{action}:{pubkey_hex}:{bucket}".encode()
    return hashlib.sha256(seed).hexdigest()


@dataclass
class Identity:
    signing_key_hex: str
    pubkey_hex: str

    @property
    def pubkey_bytes(self) -> bytes:
        return bytes.fromhex(self.pubkey_hex)


@dataclass
class SessionContext:
    identity: Identity
    user_id_b64: str
    bearer_token: str
    session_nonce: str
    display_name: str
    accent_color: str

    @property
    def headers(self) -> Mapping[str, str]:
        return {"Authorization": f"Bearer {self.bearer_token}"}


def http_get(
    base_url: str,
    path: str,
    *,
    timeout: int,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
) -> Any:
    url = urljoin(base_url, path)
    response = requests.get(url, timeout=timeout, headers=headers, params=params)
    return response


def http_post(
    base_url: str,
    path: str,
    json_body: dict[str, Any] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int | None = None,
    **request_kwargs: Any,
) -> Any:
    url = urljoin(base_url, path)
    response = requests.post(
        url,
        json=json_body,
        headers=headers,
        timeout=timeout,
        **request_kwargs,
    )
    return response


def http_put(
    base_url: str,
    path: str,
    json_body: dict[str, Any] | None = None,
    *,
    headers: Mapping[str, str] | None = None,
    timeout: int | None = None,
    **request_kwargs: Any,
) -> Any:
    url = urljoin(base_url, path)
    response = requests.put(
        url,
        json=json_body,
        headers=headers,
        timeout=timeout,
        **request_kwargs,
    )
    return response


def http_delete(
    base_url: str,
    path: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    timeout: int,
) -> Any:
    url = urljoin(base_url, path)
    response = requests.delete(
        url,
        headers=headers,
        params=params,
        timeout=timeout,
    )
    return response


class AlphaCheckpointClient:
    def __init__(self, base_url: str, timeout: int, runtime_dir: Path) -> None:
        self.base_url = base_url
        self.timeout = timeout
        self.runtime_dir = runtime_dir
        self.runtime_dir.mkdir(parents=True, exist_ok=True)

    def run(self) -> None:
        log_step("Checking service health")
        self._check_health()
        log_result("Health endpoint OK")

        user_a = self._register_and_login(random_display_name("alpha-a"), random_accent_color())
        user_b = self._register_and_login(random_display_name("alpha-b"), random_accent_color())

        community = self._create_community(user_a, slug=f"alpha-{token_hex(3)}")
        self._exercise_community_listing(user_a, community["id"])
        self._join_and_leave_community(user_b, community["id"])

        post_id = self._create_post(user_a, community_slug=community["internal_slug"])
        comment_timestamp = time.strftime('%FT%TZ', time.gmtime())
        comment_body = f"Alpha checkpoint comment on post {post_id} at {comment_timestamp}"
        comment_id = self._create_post(
            user_a,
            community_slug=community["internal_slug"],
            parent_post_id=post_id,
            content_md=comment_body,
        )

        self._inspect_feed(post_id, community["id"])

        self._cast_vote(user_b, post_id, direction=1)
        self._verify_vote_state(user_b, post_id)

        self._cast_vote(user_b, comment_id, direction=1)
        self._verify_vote_state(user_b, comment_id)

        message_a_to_b = self._send_message(
            sender=user_a,
            recipient=user_b,
            body=f"Hello from {user_a.display_name}! ({user_a.accent_color})",
        )
        message_b_to_a = self._send_message(
            sender=user_b,
            recipient=user_a,
            body=f"Reply from {user_b.display_name}! ({user_b.accent_color})",
        )
        self._check_messages(sender=user_a, recipient=user_b, message_id=message_a_to_b)
        self._check_messages(sender=user_b, recipient=user_a, message_id=message_b_to_a)

        self._moderation_flow(actor=user_b, author=user_a, post_id=post_id)

        log_result("Alpha checkpoint scenario completed successfully")

    # --- helpers ---

    def _check_health(self) -> None:
        response = http_get(self.base_url, "/health", timeout=self.timeout)
        if response.status_code != HTTP_OK:
            fail(f"Health check failed: {response.status_code} {response.text}")

    def _register_and_login(self, display_name: str, accent_color: str) -> SessionContext:
        log_step(f"Creating user '{display_name}' with accent color {accent_color}")

        from nacl.signing import SigningKey  # local import to avoid global dependency

        signing_key = SigningKey.generate()
        identity = Identity(
            signing_key_hex=signing_key.encode().hex(),
            pubkey_hex=signing_key.verify_key.encode().hex(),
        )
        log(f"Generated keypair with public key {identity.pubkey_hex}")

        register_payload = self._build_auth_payload(
            identity,
            intent="register",
            display_name=display_name,
            accent_color=accent_color,
        )
        response = http_post(
            self.base_url,
            "/api/v1/auth/register",
            json_body=register_payload,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_CREATED:
            fail(f"Registration failed: {response.status_code} {response.text}")

        user_id = response.json()["user_id"]
        log_result(f"Registered '{display_name}' with user_id {user_id}")

        login_payload = self._build_auth_payload(identity, intent="login")
        login_response = http_post(
            self.base_url,
            "/api/v1/auth/login",
            json_body=login_payload,
            timeout=self.timeout,
        )
        if login_response.status_code != HTTP_OK:
            fail(f"Login failed: {login_response.status_code} {login_response.text}")

        login_body = login_response.json()
        token = login_body["access_token"]
        session_nonce = login_body["session_nonce"]

        self._persist_identity(
            identity,
            display_name=display_name,
            accent_color=accent_color,
            user_id=user_id,
        )

        return SessionContext(
            identity=identity,
            user_id_b64=user_id,
            bearer_token=token,
            session_nonce=session_nonce,
            display_name=display_name,
            accent_color=accent_color,
        )

    def _build_auth_payload(
        self,
        identity: Identity,
        *,
        intent: str,
        display_name: str | None = None,
        accent_color: str | None = None,
    ) -> dict[str, Any]:
        challenge = self._fetch_auth_challenge(identity.pubkey_hex, intent=intent)
        difficulty = int(challenge["pow_difficulty"])
        target = challenge["pow_target"]
        nonce, attempts = solve_pow(intent, identity.pubkey_hex, target, difficulty)
        log_result(f"Solved {intent} PoW (difficulty {difficulty}) after {attempts} attempts")

        from nacl.signing import SigningKey

        signing_key = SigningKey(bytes.fromhex(identity.signing_key_hex))
        signature = signing_key.sign(_decode_b64url(challenge["signature_challenge"])).signature

        payload: dict[str, Any] = {
            "pubkey": _b64url(identity.pubkey_bytes),
            "pow": {
                "nonce": nonce,
                "difficulty": difficulty,
                "target": target,
            },
            "proof": {
                "challenge": challenge["signature_challenge"],
                "signature": _b64url(signature),
            },
        }
        if intent == "register":
            payload["display_name"] = display_name
            if accent_color is not None:
                payload["accent_color"] = accent_color
        return payload

    def _fetch_auth_challenge(self, pubkey_hex: str, *, intent: str) -> dict[str, Any]:
        payload = {"pubkey": _b64url(bytes.fromhex(pubkey_hex)), "intent": intent}
        response = http_post(
            self.base_url,
            "/api/v1/auth/challenge",
            json_body=payload,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_OK:
            fail(f"Challenge fetch failed: {response.status_code} {response.text}")
        data = response.json()
        if not isinstance(data, dict):
            fail("Challenge response was not a JSON object")
        return cast(dict[str, Any], data)

    def _persist_identity(
        self,
        identity: Identity,
        *,
        display_name: str,
        accent_color: str,
        user_id: str,
    ) -> None:
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in display_name)
        base = self.runtime_dir / f"{safe_name}_{timestamp}"
        pub_path = base.with_suffix(".pub")
        priv_path = base.with_suffix(".key")
        meta_path = base.with_suffix(".json")

        pub_path.write_text(identity.pubkey_hex, encoding="utf-8")
        priv_path.write_text(identity.signing_key_hex, encoding="utf-8")
        metadata = {
            "display_name": display_name,
            "accent_color": accent_color,
            "user_id": user_id,
            "pubkey_hex": identity.pubkey_hex,
        }
        meta_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        log_result(f"Stored identity artifacts at {meta_path}")

    def _create_community(self, user: SessionContext, *, slug: str) -> dict[str, Any]:
        log_step(f"Creating community with slug '{slug}'")
        payload = {
            "internal_slug": slug,
            "display_name": f"{slug}-display",
            "description_md": "Alpha checkpoint community",
        }
        response = http_post(
            self.base_url,
            "/api/v1/communities",
            json_body=payload,
            headers=user.headers,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_CREATED:
            fail(f"Community creation failed: {response.status_code} {response.text}")
        community = cast(dict[str, Any], response.json())
        log_result(f"Created community {community['id']} ({slug})")
        return community

    def _exercise_community_listing(self, user: SessionContext, community_id: int) -> None:
        log_step("Validating community listing details")
        listing = http_get(self.base_url, "/api/v1/communities", timeout=self.timeout)
        if listing.status_code != HTTP_OK:
            fail(f"Community listing failed: {listing.status_code} {listing.text}")
        if not any(item["id"] == community_id for item in listing.json()):
            fail(f"Community {community_id} not present in listing")
        detail = http_get(
            self.base_url,
            f"/api/v1/communities/{community_id}",
            timeout=self.timeout,
        )
        if detail.status_code != HTTP_OK:
            fail(f"Community detail failed: {detail.status_code} {detail.text}")
        log_result("Community listing verified")

    def _join_and_leave_community(self, user: SessionContext, community_id: int) -> None:
        log_step(f"{user.display_name} joining community {community_id}")
        join = http_post(
            self.base_url,
            f"/api/v1/communities/{community_id}/join",
            json_body={},
            headers=user.headers,
            timeout=self.timeout,
        )
        if join.status_code != HTTP_CREATED:
            fail(f"Community join failed: {join.status_code} {join.text}")
        posts = http_get(
            self.base_url,
            f"/api/v1/communities/{community_id}/posts",
            timeout=self.timeout,
        )
        if posts.status_code != HTTP_OK:
            fail(f"Community posts fetch failed: {posts.status_code} {posts.text}")
        log_result(f"{user.display_name} joined community {community_id}")

    def _create_post(
        self,
        user: SessionContext,
        *,
        community_slug: str,
        parent_post_id: int | None = None,
        content_md: str | None = None,
    ) -> int:
        timestamp = time.strftime("%FT%TZ", time.gmtime())
        body = content_md or f"Alpha checkpoint post at {timestamp}"
        difficulty = 20
        target = pow_target_for("post", user.identity.pubkey_hex)
        nonce, attempts = solve_pow("post", user.identity.pubkey_hex, target, difficulty)

        payload: dict[str, Any] = {
            "content_md": body,
            "community_internal_slug": community_slug,
            "pow_nonce": nonce,
            "pow_difficulty": difficulty,
            "content_hash": hashlib.sha256(body.encode()).hexdigest(),
        }
        if parent_post_id is not None:
            payload["parent_post_id"] = parent_post_id

        endpoint = "/api/v1/posts"
        response = http_post(
            self.base_url,
            endpoint,
            json_body=payload,
            headers=user.headers,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_CREATED:
            fail(f"Post creation failed: {response.status_code} {response.text}")
        created = response.json()
        if parent_post_id is None:
            log_result(f"Created post {created['id']} in {attempts} attempts")
        else:
            log_result(
                f"Created comment {created['id']} on post {parent_post_id} in {attempts} attempts"
            )
        return int(created["id"])

    def _inspect_feed(self, post_id: int, community_id: int) -> None:
        log_step("Verifying feed determinism")
        feed_a = http_get(self.base_url, "/api/v1/posts", timeout=self.timeout)
        if feed_a.status_code != HTTP_OK:
            fail(f"Feed fetch failed: {feed_a.status_code} {feed_a.text}")
        data_a = feed_a.json()
        if not any(item["id"] == post_id for item in data_a):
            fail(f"Post {post_id} missing from feed")
        detail = http_get(self.base_url, f"/api/v1/posts/{post_id}", timeout=self.timeout)
        if detail.status_code != HTTP_OK:
            fail(f"Post detail failed: {detail.status_code} {detail.text}")
        children = http_get(
            self.base_url,
            f"/api/v1/posts/{post_id}/children",
            timeout=self.timeout,
        )
        if children.status_code != HTTP_OK:
            fail(f"Fetching post children failed: {children.status_code} {children.text}")
        community_posts = http_get(
            self.base_url,
            f"/api/v1/communities/{community_id}/posts",
            timeout=self.timeout,
        )
        if community_posts.status_code != HTTP_OK:
            fail(f"Community feed failed: {community_posts.status_code} {community_posts.text}")
        feed_b = http_get(self.base_url, "/api/v1/posts", timeout=self.timeout)
        if feed_b.status_code != HTTP_OK:
            fail(f"Second feed fetch failed: {feed_b.status_code} {feed_b.text}")
        if data_a != feed_b.json():
            fail("Feed ordering changed between requests")
        log_result("Feed determinism verified")

    def _cast_vote(self, user: SessionContext, post_id: int, *, direction: int) -> None:
        log_step(f"{user.display_name} casting vote {direction} on post {post_id}")
        difficulty = 15
        target = pow_target_for("vote", user.identity.pubkey_hex)
        nonce, attempts = solve_pow("vote", user.identity.pubkey_hex, target, difficulty)

        payload = {
            "post_id": post_id,
            "direction": direction,
            "pow_nonce": nonce,
            "client_nonce": token_hex(8),
        }

        response = http_post(
            self.base_url,
            "/api/v1/votes",
            json_body=payload,
            headers=user.headers,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_CREATED:
            fail(f"Vote failed: {response.status_code} {response.text}")
        log_result(f"Vote recorded after {attempts} attempts")

    def _verify_vote_state(self, user: SessionContext, post_id: int) -> None:
        status = http_get(
            self.base_url,
            f"/api/v1/votes/{post_id}/my-vote",
            headers=user.headers,
            timeout=self.timeout,
        )
        if status.status_code != HTTP_OK:
            fail(f"Vote status fetch failed: {status.status_code} {status.text}")
        direction = status.json().get("direction")
        if direction not in (-1, 1):
            fail(f"Unexpected vote direction {direction}")
        log_result(f"Vote direction {direction} confirmed for post {post_id}")

    def _send_message(
        self,
        sender: SessionContext,
        recipient: SessionContext,
        *,
        body: str,
    ) -> int:
        log_step(f"{sender.display_name} sending message to {recipient.display_name}")
        difficulty = 18
        target = pow_target_for("message", sender.identity.pubkey_hex)
        nonce, attempts = solve_pow("message", sender.identity.pubkey_hex, target, difficulty)

        ciphertext = self._encrypt_for_recipient(body, recipient)
        payload = {
            "ciphertext": ciphertext,
            "recipient_pubkey_hex": recipient.identity.pubkey_hex,
            "header_blob": None,
            "pow_nonce": nonce,
        }

        response = http_post(
            self.base_url,
            "/api/v1/messages",
            json_body=payload,
            headers=sender.headers,
            timeout=self.timeout,
        )
        if response.status_code != HTTP_CREATED:
            fail(f"Message send failed: {response.status_code} {response.text}")
        message_id = response.json()["message_id"]
        log_result(
            f"Message {message_id} sent from {sender.display_name} to "
            f"{recipient.display_name} after {attempts} attempts"
        )
        return int(message_id)

    def _check_messages(
        self,
        sender: SessionContext,
        recipient: SessionContext,
        *,
        message_id: int,
    ) -> None:
        log_step(f"Validating message delivery for {recipient.display_name}")
        inbox = http_get(
            self.base_url,
            "/api/v1/messages/inbox",
            headers=recipient.headers,
            timeout=self.timeout,
        )
        if inbox.status_code != HTTP_OK:
            fail(f"Inbox fetch failed: {inbox.status_code} {inbox.text}")
        if not any(item["id"] == message_id for item in inbox.json()):
            fail(f"Message {message_id} missing from inbox")

        sent = http_get(
            self.base_url,
            "/api/v1/messages/sent",
            headers=sender.headers,
            timeout=self.timeout,
        )
        if sent.status_code != HTTP_OK:
            fail(f"Sent messages fetch failed: {sent.status_code} {sent.text}")
        if not any(item["id"] == message_id for item in sent.json()):
            fail(f"Message {message_id} missing from sent items")

        mark_read = http_put(
            self.base_url,
            f"/api/v1/messages/{message_id}/read",
            json_body={},
            headers=recipient.headers,
            timeout=self.timeout,
        )
        if mark_read.status_code != HTTP_OK:
            fail(f"Message read failed: {mark_read.status_code} {mark_read.text}")
        log_result(f"Message {message_id} marked as read by {recipient.display_name}")

    def _encrypt_for_recipient(self, message: str, recipient: SessionContext) -> str:
        """Encrypt message for the recipient using NaCl sealed boxes."""
        recipient_curve = PublicKey(
            crypto_sign_ed25519_pk_to_curve25519(bytes.fromhex(recipient.identity.pubkey_hex))
        )
        sealed_box = SealedBox(recipient_curve)
        ciphertext = sealed_box.encrypt(message.encode("utf-8"))
        return base64.b64encode(ciphertext).decode("utf-8")

    def _moderation_flow(
        self,
        actor: SessionContext,
        author: SessionContext,
        *,
        post_id: int,
    ) -> None:
        log_step(f"{actor.display_name} triggering moderation on post {post_id}")
        trigger = http_post(
            self.base_url,
            "/api/v1/moderation/trigger",
            json_body={},
            params={"post_id": post_id},
            headers=actor.headers,
            timeout=self.timeout,
        )
        if trigger.status_code != HTTP_CREATED:
            fail(f"Moderation trigger failed: {trigger.status_code} {trigger.text}")

        queue = http_get(self.base_url, "/api/v1/moderation/queue", timeout=self.timeout)
        if queue.status_code != HTTP_OK:
            fail(f"Moderation queue fetch failed: {queue.status_code} {queue.text}")
        log_result("Moderation queue retrieved")

        vote = http_post(
            self.base_url,
            "/api/v1/moderation/vote",
            json_body={},
            params={"post_id": post_id, "is_harmful": True},
            headers=actor.headers,
            timeout=self.timeout,
        )
        if vote.status_code != HTTP_CREATED:
            fail(f"Moderation vote failed: {vote.status_code} {vote.text}")

        history = http_get(
            self.base_url,
            "/api/v1/moderation/history",
            headers=author.headers,
            timeout=self.timeout,
        )
        if history.status_code != HTTP_OK:
            fail(f"Moderation history failed: {history.status_code} {history.text}")
        log_result(
            f"Moderation history for {author.display_name}: {json.dumps(history.json())}"
        )


def random_display_name(prefix: str) -> str:
    return f"{prefix}-{token_hex(4)}"


def random_accent_color() -> str:
    return f"#{token_hex(3)}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the alpha checkpoint scenario")
    parser.add_argument(
        "--base-url",
        default=os.getenv("ALPHA_BASE_URL", "http://127.0.0.1:8080"),
        help="Base URL for the Chorus API",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("ALPHA_TIMEOUT", "20")),
        help="HTTP timeout in seconds",
    )
    parser.add_argument(
        "--runtime-dir",
        type=Path,
        default=Path(os.getenv("ALPHA_RUNTIME_DIR", "tests/runtime")),
        help="Directory to store generated key material",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    log(f"Base URL: {args.base_url}")
    log(f"Runtime directory: {args.runtime_dir}")
    client = AlphaCheckpointClient(
        base_url=args.base_url,
        timeout=args.timeout,
        runtime_dir=args.runtime_dir,
    )
    try:
        client.run()
    except Exception as exc:  # pragma: no cover - integration script
        warn(str(exc))
        sys.exit(1)


if __name__ == "__main__":
    main()
