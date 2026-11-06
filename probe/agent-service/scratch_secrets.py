"""The secret files the real service mounts, as throwaway ones in a probe's scratch HOME: the root
of litellm_ca.py's scratch CA where compose.yaml's `step_ca_root_certificate` points, and a signing
pair where `agent_service_signing_key` points. The key pair is made with the argument lists and
names of signing_key.py, so
the format has one owner; nothing here prints a byte of either key. It is also the one owner of
the dummy logins of both CLIs: throwaway files of the shape each CLI's reader accepts, in the
folders the secrets manifest names."""

from __future__ import annotations

import base64
import json
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe

from litellm_ca import ScratchCa, openssl, write_new, write_scratch_ca
from signing_key import (
    DERIVE_PUBLIC_KEY,
    GENERATE_PRIVATE_KEY,
    PRIVATE_FILE,
    PRIVATE_KEY_MODE,
    PUBLIC_FILE,
    PUBLIC_KEY_MODE,
    SIGNING_DIRECTORY,
)

from hal.workstation.secrets_view import MANIFEST_PATH

SECRETS_DIRECTORY = Path(".secrets")
SIGNING_FOLDER = SECRETS_DIRECTORY / "agent-service" / SIGNING_DIRECTORY
ROOT_CERTIFICATE = SECRETS_DIRECTORY / "step-ca" / "root_ca.crt"
# The manifest entry of each provider's login.
LOGIN_ENTRIES = {"anthropic": "agent-service-claude", "openai": "agent-service/codex"}


@dataclass(frozen=True)
class ScratchSecrets(ScratchCa):
    """Where the scratch files are: the CA (outside the HOME), its root in the HOME, and the
    signing pair in the HOME."""

    root: Path
    signing_private: Path
    signing_public: Path


def private_folder(home: Path, relative: Path) -> None:
    """Every level of `relative` below `home`, owner-only like the live secrets folders."""
    folder = home
    for part in relative.parts:
        folder /= part
        folder.mkdir(exist_ok=True)
        folder.chmod(0o700)


def login_file(provider: str) -> Path:
    """The login file of `provider` below a HOME, as the secrets manifest names it."""
    manifest = tomllib.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    entry = next(entry for entry in manifest["secret"] if entry["name"] == LOGIN_ENTRIES[provider])
    return Path(entry["paths"][0].removeprefix("~/").removesuffix("*"))


LOGIN_DIRECTORY = login_file("anthropic").parent


DUMMY_ACCESS_TOKEN_LIFETIME = timedelta(days=10)


def write_dummy_token(path: Path) -> None:
    """A new file at `path` (mode 0600) with a line of the shape `claude setup-token` prints; it
    is no credential and reaches no one."""
    write_new(path, f"sk-ant-oat01-{token_urlsafe(72)}\n".encode(), 0o600)


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def dummy_access_token() -> str:
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


def codex_document() -> dict:
    """A document of the shape agent-runtime's Codex reader accepts, with random values."""
    return {
        "auth_mode": "chatgpt",
        "last_refresh": datetime.now(UTC).isoformat(),
        "tokens": {
            "id_token": token_urlsafe(48),
            "access_token": dummy_access_token(),
            "refresh_token": token_urlsafe(48),
            "account_id": token_urlsafe(48),
        },
    }


def write_dummy_codex_login(path: Path) -> None:
    """A new file at `path` (mode 0600) with a complete Codex sign-in; it reaches no one."""
    write_new(path, json.dumps(codex_document()).encode(), 0o600)


def write_incomplete_codex_login(path: Path) -> None:
    """A new file at `path` (mode 0600) with a Codex sign-in that lacks its access token, which
    the reader calls incomplete."""
    document = codex_document()
    del document["tokens"]["access_token"]
    write_new(path, json.dumps(document).encode(), 0o600)


DUMMY_LOGIN_WRITERS: dict[str, Callable[[Path], None]] = {
    "anthropic": write_dummy_token,
    "openai": write_dummy_codex_login,
}


def write_login_folders(home: Path) -> None:
    """Both providers' login folders (0700) under `home`, each holding its dummy login (0600)."""
    for provider, write_login in DUMMY_LOGIN_WRITERS.items():
        private_folder(home, login_file(provider).parent)
        write_login(home / login_file(provider))


def login_values(path: Path) -> list[str]:
    """The secret values in a dummy login, for the check that a log holds none of them."""
    text = path.read_text(encoding="utf-8")
    try:
        return list(json.loads(text)["tokens"].values())
    except ValueError:
        return [text.strip()]


def write_scratch_secrets(home: Path, ca_directory: Path) -> ScratchSecrets:
    """A scratch CA in `ca_directory`, its root and a signing pair under `home`."""
    authority = write_scratch_ca(ca_directory)
    secrets = ScratchSecrets(
        ca_certificate=authority.ca_certificate,
        ca_key=authority.ca_key,
        root=home / ROOT_CERTIFICATE,
        signing_private=home / SIGNING_FOLDER / PRIVATE_FILE,
        signing_public=home / SIGNING_FOLDER / PUBLIC_FILE,
    )
    private_folder(home, ROOT_CERTIFICATE.parent)
    private_folder(home, SIGNING_FOLDER)
    write_new(secrets.root, secrets.ca_certificate.read_bytes(), 0o644)
    private = openssl(*GENERATE_PRIVATE_KEY)
    write_new(secrets.signing_private, private, PRIVATE_KEY_MODE)
    write_new(secrets.signing_public, openssl(*DERIVE_PUBLIC_KEY, stdin=private), PUBLIC_KEY_MODE)
    return secrets
