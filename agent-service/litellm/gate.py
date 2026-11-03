"""The syntax of the service credential: frozen for its one reader, agent-service/api_credential.py,
until the credential path leaves whole (HAL-2.9b). No service reads the credential; LiteLLM's own
keys decide who may call."""

from __future__ import annotations

import json
import re

CREDENTIAL_FIELDS = frozenset({"shared_key", "app_keys"})
# agent-runtime's credential syntax (agent_runtime_service.api_credentials._credential).
CREDENTIAL = re.compile(r"[A-Za-z0-9._~+/-]+=*")


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
