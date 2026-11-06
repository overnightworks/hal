"""The tunnel id, read at run time from the machine's own tunnel config, so no tree file names it."""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

import yaml

# World-readable; the running tunnel reads the same file.
TUNNEL_CONFIG = Path("/etc/cloudflared/config.yml")
TUNNEL_ID_PLACEHOLDER = "{tunnel_id}"
TUNNEL_ID_FORM = re.compile(r"[0-9A-Za-z-]+")


class TunnelIdUnknown(OSError):
    """The tunnel config is missing, unreadable or names no usable `tunnel:`; no credential file can be named."""


def tunnel_id(config: Path) -> str:
    try:
        document = yaml.safe_load(config.read_text())
    except OSError as error:
        raise TunnelIdUnknown(f"{config} cannot be read: {error.strerror or error}") from error
    except yaml.YAMLError as error:
        raise TunnelIdUnknown(f"{config} is not valid YAML") from error
    identifier = document.get("tunnel") if isinstance(document, dict) else None
    if not isinstance(identifier, str) or not TUNNEL_ID_FORM.fullmatch(identifier):
        raise TunnelIdUnknown(f"{config} names no usable `tunnel:` id")
    return identifier


def with_tunnel_id(pattern: PurePosixPath) -> PurePosixPath:
    """The pattern with its placeholder filled in from the config; unchanged when it has none."""
    if TUNNEL_ID_PLACEHOLDER not in pattern.name:
        return pattern
    return pattern.with_name(pattern.name.replace(TUNNEL_ID_PLACEHOLDER, tunnel_id(TUNNEL_CONFIG)))


def as_wildcard(name: str) -> str:
    """For naming only: an unresolved tunnel id still names its credential file, which is never an unknown one."""
    return name.replace(TUNNEL_ID_PLACEHOLDER, "*")
