"""Reading one key of a secrets-manifest table, and the error that names what is wrong."""

from __future__ import annotations

from collections.abc import Mapping
from enum import Enum
from pathlib import Path


class ManifestError(ValueError):
    """The manifest cannot be trusted; `hal secrets` exits 2 on it."""


def fail(path: Path, where: str, message: str) -> ManifestError:
    return ManifestError(f"{path}: {where}: {message}")


def string(path: Path, where: str, raw: Mapping[str, object], key: str) -> str:
    value = raw[key]
    if not isinstance(value, str) or not value.strip():
        raise fail(path, where, f"{key} must be a non-empty string")
    return value


def strings(path: Path, where: str, raw: Mapping[str, object], key: str) -> tuple[str, ...]:
    value = raw[key]
    if not isinstance(value, list) or not all(isinstance(item, str) and item.strip() for item in value):
        raise fail(path, where, f"{key} must be a list of non-empty strings")
    return tuple(value)


def https_link(path: Path, where: str, raw: Mapping[str, object], key: str) -> str:
    value = string(path, where, raw, key)
    if not value.startswith("https://"):
        raise fail(path, where, f"{key} must be an https:// link")
    return value


def require_key_of_kind(path: Path, where: str, raw: Mapping[str, object], key: str, entry_kind: Enum, owner_kind: Enum) -> None:
    """A key that belongs to every entry of one kind and to no other."""
    if (entry_kind is owner_kind) != (key in raw):
        raise fail(path, where, f"{key} belongs to every {owner_kind.value} entry and to no other kind")


def flag(path: Path, where: str, raw: Mapping[str, object], key: str) -> bool:
    value = raw.get(key, False)
    if not isinstance(value, bool):
        raise fail(path, where, f"{key} must be true or false")
    return value


def value_prefix(path: Path, where: str, raw: Mapping[str, object], entry_kind: Enum, owner_kind: Enum) -> str:
    """The text `hal setup` puts before a value it generates; empty when absent, refused on any kind but the owner's."""
    if "value_prefix" not in raw:
        return ""
    if entry_kind is not owner_kind:
        raise fail(path, where, f"value_prefix belongs to a {owner_kind.value} entry only")
    return string(path, where, raw, "value_prefix")
