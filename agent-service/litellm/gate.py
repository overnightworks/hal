"""The decision of LiteLLM's custom auth hook: pure and standard library only, so CI tests it case
by case without LiteLLM (tests/test_litellm_gate.py). auth.py is the thin adapter that hands it
the request.

A request passes only as `POST` on exactly /v1/chat/completions, with no query string (LiteLLM
reads `model` from the query too), exactly one Content-Type of exactly `application/json` (LiteLLM
parses form bodies by their media type, so a body is judged only as the JSON LiteLLM will parse),
no header named `x-litellm-…` (LiteLLM reads per-request retries and timeouts from them) or
`anthropic-…` (LiteLLM forwards `anthropic-version` and `anthropic-beta` to the provider), the
service credential's `shared_key` as the bearer, and a UTF-8 JSON body whose keys are exactly those
agent-runtime's one posting function sends. Anything else, including a credential file that is
missing or one agent-runtime's credential reader would refuse, is refused. A reason never carries
the credential or the bearer.
"""

from __future__ import annotations

import hmac
import json
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path

METHOD = "POST"
PATH = "/v1/chat/completions"
BODY_KEYS = frozenset({"model", "messages", "tools"})
CREDENTIAL_FIELDS = frozenset({"shared_key", "app_keys"})
# agent-runtime's credential syntax (agent_runtime_service.api_credentials._credential).
CREDENTIAL = re.compile(r"[A-Za-z0-9._~+/-]+=*")
BEARER_PREFIX = "Bearer "
# What agent-runtime sends; LiteLLM drops parameters and parses any non-form body as UTF-8 JSON,
# so the exact value leaves no normalisation for the two to disagree on.
CONTENT_TYPE = "application/json"
# Header names LiteLLM acts on or forwards to the provider; agent-runtime sends none of them.
REFUSED_HEADER_PREFIXES = ("x-litellm-", "anthropic-")


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str


def decide(
    *,
    method: str,
    path: str,
    query: str,
    authorization: str | None,
    content_types: Sequence[str],
    header_names: Iterable[str],
    body: bytes,
    credential_file: Path,
) -> Verdict:
    if method != METHOD or path != PATH:
        return Verdict(False, "only POST /v1/chat/completions is served")
    if query:
        return Verdict(False, "a query string is not accepted")
    if list(content_types) != [CONTENT_TYPE]:
        return Verdict(False, "the body must be sent as one Content-Type: application/json")
    if any(name.lower().startswith(REFUSED_HEADER_PREFIXES) for name in header_names):
        return Verdict(False, "an x-litellm- or anthropic- header is not accepted")
    try:
        shared_key = shared_key_of(credential_file.read_bytes())
    except OSError:
        shared_key = None
    if shared_key is None:
        return Verdict(False, "the service credential is missing or invalid")
    if not _bearer_matches(authorization, shared_key):
        return Verdict(False, "the bearer does not match")
    if _body_keys(body) != BODY_KEYS:
        return Verdict(False, "the body keys are not exactly model, messages and tools")
    return Verdict(True, "")


def shared_key_of(document_bytes: bytes) -> str | None:
    """The `shared_key` of a credential document agent-runtime's reader would accept, else None."""
    try:
        document = json.loads(document_bytes.decode("utf-8"), object_pairs_hook=_unique_fields)
    except (ValueError, RecursionError):
        return None
    if not isinstance(document, dict) or document.keys() - CREDENTIAL_FIELDS:
        return None
    app_keys = document.get("app_keys", {})
    if not isinstance(app_keys, dict) or not all(map(_is_credential, app_keys.values())):
        return None
    shared_key = document.get("shared_key")
    return shared_key if _is_credential(shared_key) else None


def _unique_fields(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document = dict(pairs)
    if len(document) != len(pairs):
        raise ValueError("duplicate credential field")
    return document


def _is_credential(value: object) -> bool:
    return isinstance(value, str) and CREDENTIAL.fullmatch(value) is not None


def _bearer_matches(authorization: str | None, shared_key: str) -> bool:
    if authorization is None or not authorization.startswith(BEARER_PREFIX):
        return False
    return hmac.compare_digest(
        authorization.removeprefix(BEARER_PREFIX).encode(), shared_key.encode()
    )


def _body_keys(body: bytes) -> frozenset[str] | None:
    try:
        document = json.loads(body.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return frozenset(document) if isinstance(document, dict) else None
