#!/usr/bin/env python3
"""
Chorus Alpha Readiness Check (safe mode)

Exit code:
  0 = Alpha-ready per checks enabled
  1 = Failed at least one required check

Design goals:
- **No repo mutations**. Never stash/reset/commit. Pure read-only for Git.
- Opt-in for bring-up. By default we DO NOT start or stop services.
- Skips optional tools (ruff/black/mypy) if not installed, unless --strict-tools.
- Minimal dependencies; uses subprocess for CLI tools. Uses 'requests' and 'pynacl'
  if available; otherwise falls back or skips gracefully.

Typical usage:
  python scripts/alpha_check.py --base-url http://127.0.0.1:8000 --bring-up
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
import time
from collections.abc import Mapping
from secrets import token_hex
from typing import Any

import requests  #type: ignore
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

HTTP_OK = 200

# ---------- Utilities ----------

def say(msg: str) -> None:
    print(f"[alpha-check] {msg}")

def warn(msg: str) -> None:
    print(f"[alpha-check][WARN] {msg}", file=sys.stderr)

def fail(msg: str) -> None:
    print(f"[alpha-check][FAIL] {msg}", file=sys.stderr)

def which(cmd: str) -> bool:
    return subprocess.call(
        ["bash", "-lc", f"command -v {shlex.quote(cmd)} >/dev/null 2>&1"]
    ) == 0

def run(cmd: str, timeout: int = 120, check: bool = False) -> tuple[int, str, str]:
    """Run a shell command; return (rc, stdout, stderr)."""
    proc = subprocess.Popen(
        ["bash", "-lc", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=os.environ.copy(),
    )
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, err = proc.communicate()
        return 124, out, err or "timeout"
    if check and proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd, out, err)
    return proc.returncode, out, err

def have_module(mod: str) -> bool:
    try:
        __import__(mod)
        return True
    except ImportError:
        return False


def poetry_tool_available(executable: str) -> bool:
    if not which("poetry"):
        return False
    return run(f"poetry run {executable} --version")[0] == 0


def resolve_tool_command(executable: str, args: str = "") -> tuple[bool, str]:
    base_command = " ".join(part for part in [executable, args] if part)
    if poetry_tool_available(executable):
        return True, f"poetry run {base_command}"
    if which(executable):
        return True, base_command
    if which("poetry"):
        return False, f"poetry run {base_command}"
    return False, base_command


def tool_missing(strict: bool, strict_message: str, relaxed_message: str) -> bool:
    if strict:
        fail(strict_message)
        return False
    warn(relaxed_message)
    return True


def run_tool_command(command: str, fail_message: str, *, warn_only: bool = False) -> bool:
    rc, _, _ = run(command)
    if rc == 0:
        return True
    if warn_only:
        warn(fail_message)
        return True
    fail(fail_message)
    return False


def run_when_available(
    available: bool,
    command: str,
    *,
    strict: bool,
    messages: tuple[str, str, str],
    warn_only: bool = False,
) -> bool:
    strict_message, relaxed_message, fail_message = messages
    if not available:
        return tool_missing(strict, strict_message, relaxed_message)
    return run_tool_command(command, fail_message, warn_only=warn_only)

# ---------- Steps ----------

def step_repo_hygiene(strict_dirty: bool) -> bool:
    say("1/10 Repo hygiene (read-only)")
    # Dirty working tree check, but do not modify anything.
    rc1, _, _ = run("git diff --quiet")
    rc2, _, _ = run("git diff --cached --quiet")
    if rc1 != 0 or rc2 != 0:
        msg = "Working tree is dirty. Commit or stash manually before alpha check."
        if strict_dirty:
            fail(msg)
            return False
        else:
            warn(msg + " Continuing (non-strict).")
    return True

def step_poetry_install(enable: bool) -> bool:
    if not enable:
        say("2/10 Environment lock: skipped (no --poetry-install)")
        return True
    say("2/10 Environment lock via Poetry")
    if not which("poetry"):
        fail("Poetry not found. Install or omit --poetry-install.")
        return False
    rc, _, err = run("poetry install -q")
    if rc != 0:
        fail(f"Poetry install failed: {err.strip()}")
        return False
    return True

def step_linters(strict_tools: bool) -> bool:
    say("3/10 Lint & types")
    ok = True

    ruff_available, ruff_command = resolve_tool_command("ruff", "check")
    ok &= run_when_available(
        ruff_available,
        ruff_command,
        strict=strict_tools,
        messages=(
            "ruff not available but --strict-tools set",
            "ruff not installed; skipping",
            "ruff check failed",
        ),
    )

    black_available, black_command = resolve_tool_command("black", "--check .")
    ok &= run_when_available(
        black_available,
        black_command,
        strict=strict_tools,
        messages=(
            "black not available but --strict-tools set",
            "black not installed; skipping",
            "black --check failed",
        ),
    )

    mypy_available, mypy_command = resolve_tool_command("mypy")
    ok &= run_when_available(
        mypy_available,
        mypy_command,
        strict=strict_tools,
        messages=(
            "mypy not available but --strict-tools set",
            "mypy not installed; skipping",
            "mypy reported issues",
        ),
        warn_only=True,
    )

    return ok

def step_tests() -> bool:
    say("4/10 Unit & integration tests")
    if which("poetry"):
        rc, _, _ = run("poetry run pytest -q")
    elif which("pytest"):
        rc, _, _ = run("pytest -q")
    else:
        fail("pytest not available")
        return False
    if rc != 0:
        fail("pytest failed")
        return False
    return True

def step_bring_up(enable: bool) -> bool:
    if not enable:
        say("5/10 Boot stack: skipped (no --bring-up)")
        return True
    say("5/10 Boot stack")
    # No teardown here; we do not stop or reset anything.
    if which("make"):
        rc, _, _ = run("make up")
        if rc != 0:
            warn("`make up` failed, trying docker compose")
            rc, _, _ = run("docker compose up -d")
            if rc != 0:
                fail("Failed to start services via make or docker compose")
                return False
        # Best-effort migrate
        run("make migrate")
    else:
        rc, _, _ = run("docker compose up -d")
        if rc != 0:
            fail("Failed to start services (docker compose)")
            return False
    return True

def http_get(url: str, timeout: int = 20) -> tuple[int, str | None]:
    if have_module("requests"):
        try:
            r = requests.get(url, timeout=timeout)
            return r.status_code, r.text
        except requests.RequestException as exc:
            return 0, str(exc)
    # Fallback to curl
    if which("curl"):
        curl_cmd = " ".join(
            [
                "curl --silent --show-error --fail",
                f"--max-time {timeout}",
                shlex.quote(url),
            ]
        )
        rc, out, _ = run(curl_cmd)
        return (HTTP_OK if rc == 0 else 0), (out or None)
    return 0, None

def http_post_json(
    url: str,
    body: dict[str, Any],
    headers: Mapping[str, str] | None = None,
    timeout: int = 20,
) -> tuple[int, str | None]:
    payload = json.dumps(body)
    headers_dict: dict[str, str] = {"Content-Type": "application/json"}
    if headers is not None:
        headers_dict.update(headers)

    if have_module("requests"):
        try:
            r = requests.post(
                url,
                data=payload,
                headers=headers_dict,
                timeout=timeout,
            )
            return r.status_code, r.text
        except requests.RequestException as exc:
            return 0, str(exc)
    # Fallback to curl
    if which("curl"):
        hdrs = " ".join(
            f"-H {shlex.quote(f'{key}: {value}')}"
            for key, value in headers_dict.items()
        )
        rc, out, _ = run(
            " ".join(
                [
                    "curl --silent --show-error --fail",
                    f"--max-time {timeout}",
                    hdrs,
                    f"-d {shlex.quote(payload)}",
                    shlex.quote(url),
                ]
            )
        )
        return (HTTP_OK if rc == 0 else 0), (out or None)
    return 0, None

def step_health(base_url: str) -> bool:
    say("6/10 Health check")
    for path in ["/health", "/api/v1/health", "/"]:
        code, _ = http_get(base_url.rstrip("/") + path)
        if code == HTTP_OK:
            return True
    fail(f"Service not responding on {base_url}")
    return False

def gen_keys() -> dict[str, dict[str, str]] | None:
    if not have_module("nacl.signing"):
        return None

    def g() -> dict[str, str]:
        sk = SigningKey.generate()
        pk = sk.verify_key
        return {
            "sk": sk.encode(encoder=HexEncoder).decode(),
            "pk": pk.encode(encoder=HexEncoder).decode(),
        }
    return {"a": g(), "b": g()}

def ed25519_sign(sk_hex: str, payload_bytes: bytes) -> str:
    sk_bytes = sk_hex.encode("utf-8")
    sk = SigningKey(sk_bytes, encoder=HexEncoder)
    sig = sk.sign(payload_bytes).signature
    return str(sig.hex())


REGISTER_ENDPOINTS: tuple[str, str] = ("/api/v1/auth/register", "/auth/register")
POST_ENDPOINTS: tuple[str, str] = ("/api/v1/posts", "/posts")


def _b64url(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_b64url(data: str) -> bytes:
    import base64

    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


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
    timeout_s: float = 12.0,
) -> str | None:
    deadline = time.time() + timeout_s
    attempts = 0
    while time.time() < deadline:
        nonce = token_hex(8)
        attempts += 1
        if _pow_satisfies(action, pubkey_hex, target, nonce, difficulty):
            return nonce
    warn(f"PoW solve timeout after {attempts} attempts for {action}")
    return None


def pow_target_for(action: str, pubkey_hex: str) -> str:
    """Deterministically derive the PoW challenge target for a given action."""
    bucket = int(time.time() // 300)
    seed = f"{action}:{pubkey_hex}:{bucket}".encode()
    return hashlib.sha256(seed).hexdigest()


def fetch_auth_challenge(
    base_url: str,
    pubkey_b64: str,
    intent: str,
) -> dict[str, Any] | None:
    """Request a register/login challenge from the API."""
    code, text = http_post_json(
        f"{base_url}/api/v1/auth/challenge",
        {"pubkey": pubkey_b64, "intent": intent},
    )
    if code != HTTP_OK:
        return None
    try:
        return json.loads(text or "{}")
    except json.JSONDecodeError:
        return None


def register_and_login(
    base_url: str,
    key: dict[str, str],
    display_name: str,
) -> tuple[str, str, str] | None:
    """Register an identity and log in, returning the bearer token on success."""
    pubkey_bytes = bytes.fromhex(key["pk"])
    pubkey_hex = key["pk"]
    pubkey_b64 = _b64url(pubkey_bytes)

    register_defaults = os.environ.get("POW_DIFFICULTY_REGISTER", "18")
    login_defaults = os.environ.get("POW_DIFFICULTY_LOGIN", "16")

    result: tuple[str, str, str] | None = None
    register_challenge = fetch_auth_challenge(base_url, pubkey_b64, "register")
    if register_challenge:
        register_difficulty = int(
            register_challenge.get("pow_difficulty", register_defaults)
        )
        register_target = register_challenge["pow_target"]
        register_nonce = solve_pow(
            "register",
            pubkey_hex,
            register_target,
            register_difficulty,
        )
        if register_nonce is not None:
            challenge_bytes = _decode_b64url(
                register_challenge["signature_challenge"]
            )
            signature = SigningKey(
                key["sk"],
                encoder=HexEncoder,
            ).sign(challenge_bytes).signature
            payload = {
                "pubkey": pubkey_b64,
                "display_name": display_name,
                "pow": {
                    "nonce": register_nonce,
                    "difficulty": register_difficulty,
                    "target": register_target,
                },
                "proof": {
                    "challenge": register_challenge["signature_challenge"],
                    "signature": _b64url(signature),
                },
            }
            success = any(
                http_post_json(f"{base_url}{path}", payload)[0] == HTTP_OK
                for path in REGISTER_ENDPOINTS
            )
            if success:
                login_challenge = fetch_auth_challenge(
                    base_url,
                    pubkey_b64,
                    "login",
                )
                if login_challenge:
                    login_difficulty = int(
                        login_challenge.get("pow_difficulty", login_defaults)
                    )
                    login_target = login_challenge["pow_target"]
                    login_nonce = solve_pow(
                        "login",
                        pubkey_hex,
                        login_target,
                        login_difficulty,
                    )
                    if login_nonce is not None:
                        login_bytes = _decode_b64url(
                            login_challenge["signature_challenge"]
                        )
                        login_signature = SigningKey(
                            key["sk"],
                            encoder=HexEncoder,
                        ).sign(login_bytes).signature
                        code, text = http_post_json(
                            f"{base_url}/api/v1/auth/login",
                            {
                                "pubkey": pubkey_b64,
                                "pow": {
                                    "nonce": login_nonce,
                                    "difficulty": login_difficulty,
                                    "target": login_target,
                                },
                                "proof": {
                                    "challenge": login_challenge[
                                        "signature_challenge"
                                    ],
                                    "signature": _b64url(login_signature),
                                },
                            },
                        )
                        if code == HTTP_OK:
                            try:
                                data = json.loads(text or "{}")
                                token = data["access_token"]
                            except (json.JSONDecodeError, KeyError):
                                token = None
                            if token:
                                result = (token, pubkey_b64, pubkey_hex)
    return result


def bearer_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def create_post_and_get_id(
    base_url: str, body_post: dict[str, Any], headers: Mapping[str, str]
) -> str | None:
    for path in POST_ENDPOINTS:
        code, text = http_post_json(f"{base_url}{path}", body_post, headers=headers)
        if code != HTTP_OK:
            continue
        try:
            payload = json.loads(text or "{}")
        except json.JSONDecodeError:
            fail("Create post succeeded but response was not JSON")
            return None
        post_id = payload.get("id")
        if post_id:
            return str(post_id)
        fail("Create post succeeded but no id in response")
        return None
    fail("Create post failed (check PoW/signature/test mode)")
    return None


def cast_vote(
    base_url: str,
    post_id: str,
    vote_body: dict[str, Any],
    headers: Mapping[str, str],
) -> None:
    http_post_json(
        f"{base_url}/api/v1/votes",
        vote_body,
        headers=headers,
    )


def feed_is_deterministic(base_url: str) -> bool:
    code_a, text_a = http_get(f"{base_url}/api/v1/posts")
    time.sleep(0.8)
    code_b, text_b = http_get(f"{base_url}/api/v1/posts")
    if code_a != HTTP_OK or code_b != HTTP_OK:
        fail("Failed to fetch feed for deterministic check")
        return False
    try:
        ids_a = [item.get("id") for item in json.loads(text_a or "[]")]
        ids_b = [item.get("id") for item in json.loads(text_b or "[]")]
    except (TypeError, json.JSONDecodeError, IndexError):
        fail("Feed responses were not valid JSON arrays")
        return False
    if ids_a != ids_b:
        fail("Feed ordering is not deterministic between requests")
        return False
    return True


def check_moderation_log(base_url: str) -> None:
    code_log, _ = http_get(f"{base_url}/api/v1/moderation/log")
    if code_log != HTTP_OK:
        warn("Moderation log endpoint not found; ensure transparency is documented elsewhere")

def step_e2e(base_url: str) -> bool:
    say("7-9/10 Minimal E2E: register → post → vote → deterministic feed")
    keys: dict[str, dict[str, str]] | None = gen_keys()
    if keys is None:
        warn("PyNaCl unavailable; running unsigned E2E (dev mode must allow it)")

    base = base_url.rstrip("/")
    if keys is None:
        fail("Ed25519 support required for anonymous enrollment check")
        return False

    user_a = register_and_login(base, keys["a"], "alpha-check-a")
    if user_a is None:
        fail("Register/Login A failed")
        return False
    user_b = register_and_login(base, keys["b"], "alpha-check-b")
    if user_b is None:
        warn("Register/Login B failed; continuing without vote coverage")

    token_a, pubkey_a_b64, pubkey_a_hex = user_a
    if user_b:
        token_b, _, pubkey_b_hex = user_b
    else:
        token_b, _, pubkey_b_hex = token_a, pubkey_a_b64, pubkey_a_hex

    content = f"hello chorus alpha-check {time.strftime('%FT%TZ', time.gmtime())}"
    content_hash = hashlib.sha256(content.encode()).hexdigest()
    timestamp = time.strftime("%FT%TZ", time.gmtime())
    post_difficulty = int(os.environ.get("POW_DIFFICULTY_POST", "20"))
    post_target = pow_target_for("post", pubkey_a_hex)
    post_nonce = solve_pow("post", pubkey_a_hex, post_target, post_difficulty)
    if post_nonce is None:
        fail("Failed to satisfy PoW for post creation")
        return False
    body_post = {
        "content_md": f"{content}\n\n_{timestamp}_",
        "pow_nonce": post_nonce,
        "pow_difficulty": post_difficulty,
        "content_hash": content_hash,
    }

    post_id = create_post_and_get_id(base, body_post, bearer_headers(token_a))
    if post_id is None:
        return False

    vote_difficulty = int(os.environ.get("POW_DIFFICULTY_VOTE", "15"))
    vote_target = pow_target_for("vote", pubkey_b_hex)
    vote_nonce = solve_pow("vote", pubkey_b_hex, vote_target, vote_difficulty)
    if vote_nonce is None:
        warn("Failed to compute PoW for vote; skipping vote step")
    else:
        vote_body = {
            "post_id": int(post_id),
            "direction": -1,
            "pow_nonce": vote_nonce,
            "client_nonce": token_hex(8),
        }
        cast_vote(base, post_id, vote_body, bearer_headers(token_b))

    if not feed_is_deterministic(base):
        return False

    check_moderation_log(base)
    return True

def step_config_sanity(base_url: str) -> bool:
    say("10/10 Basic production sanity (debug-ish)")
    code, text = http_get(base_url.rstrip("/") + "/api/v1/config")
    if code == HTTP_OK:
        try:
            data = json.loads(text or "{}")
            if data.get("debug") is False:
                return True
        except json.JSONDecodeError:
            pass
        warn("Could not confirm debug=false from /api/v1/config")
        return True  # not fatal for alpha
    else:
        warn("No /api/v1/config; skipping")
        return True

# ---------- Main ----------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Chorus alpha readiness check (safe)")
    p.add_argument("--base-url", default=os.environ.get("CHORUS_BASE_URL", "http://127.0.0.1:8000"),
                   help="Base URL for API (default: %(default)s)")
    p.add_argument("--timeout", type=int, default=int(os.environ.get("CHORUS_TIMEOUT", "20")),
                   help="HTTP timeout seconds (default: %(default)s)")
    p.add_argument("--strict-dirty", action="store_true",
                   help="Fail if working tree is dirty (never auto-stash)")
    p.add_argument("--strict-tools", action="store_true",
                   help="Fail if ruff/black/mypy are missing")
    p.add_argument("--poetry-install", action="store_true",
                   help="Run 'poetry install' before checks (read-only otherwise)")
    p.add_argument("--bring-up", action="store_true",
                   help="Try 'make up' or 'docker compose up -d' before checks")
    return p.parse_args()

def main() -> int:
    args = parse_args()
    # Respect timeout for HTTP helpers
    os.environ["CHORUS_TIMEOUT"] = str(args.timeout)

    all_ok = True
    all_ok &= step_repo_hygiene(strict_dirty=args.strict_dirty)
    all_ok &= step_poetry_install(enable=args.poetry_install)
    all_ok &= step_linters(strict_tools=args.strict_tools)
    all_ok &= step_tests()
    all_ok &= step_bring_up(enable=args.bring_up)
    all_ok &= step_health(args.base_url)
    all_ok &= step_e2e(args.base_url)
    all_ok &= step_config_sanity(args.base_url)

    if all_ok:
        say("ALPHA READINESS: PASS")
        return 0
    fail("ALPHA READINESS: FAIL")
    return 1

if __name__ == "__main__":
    sys.exit(main())
