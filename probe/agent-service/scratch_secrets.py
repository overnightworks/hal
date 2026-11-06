"""The dummy logins of both CLIs, for the image probe: throwaway files of the shape each CLI's
reader accepts, which reach no one."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe

from litellm_ca import write_new

DUMMY_ACCESS_TOKEN_LIFETIME = timedelta(days=10)


def write_dummy_token(path: Path) -> None:
    """A new file at `path` (mode 0600) with a line of the shape `claude setup-token` prints; it
    is no credential and reaches no one."""
    write_new(path, f"sk-ant-oat01-{token_urlsafe(72)}\n".encode(), 0o600)


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _dummy_access_token() -> str:
    """A JWT-shaped token with random signature that reaches no one. The service renews a login
    whose access token has less than half its life left or whose timing it cannot read, so the
    token is fresh with a long life: nothing renews and no CLI starts."""
    issued_at = datetime.now(UTC)
    claims = {
        "iat": int(issued_at.timestamp()),
        "exp": int((issued_at + DUMMY_ACCESS_TOKEN_LIFETIME).timestamp()),
    }
    header = _base64url(json.dumps({"alg": "none"}).encode())
    payload = _base64url(json.dumps(claims).encode())
    return f"{header}.{payload}.{token_urlsafe(32)}"


def _codex_document() -> dict:
    """A document of the shape agent-runtime's Codex reader accepts, with random values."""
    return {
        "auth_mode": "chatgpt",
        "last_refresh": datetime.now(UTC).isoformat(),
        "tokens": {
            "id_token": token_urlsafe(48),
            "access_token": _dummy_access_token(),
            "refresh_token": token_urlsafe(48),
            "account_id": token_urlsafe(48),
        },
    }


def write_dummy_codex_login(path: Path) -> None:
    """A new file at `path` (mode 0600) with a complete Codex sign-in; it reaches no one."""
    write_new(path, json.dumps(_codex_document()).encode(), 0o600)
