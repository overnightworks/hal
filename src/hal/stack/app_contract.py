"""What an app's `compose.yaml` may contain (#255, the contract for an app repository).

The one owner of that decision, pure over the text of `git show <sha>:compose.yaml`. It parses with
SafeLoader and does not interpolate, so a `$` in a value that decides a rule (a label key, a restart
policy, a short-form volume entry, a long form's type or target, a tmpfs mount, a labelled service's
healthcheck `test` and `disable`) is refused: Compose would resolve it from the `.env` the release
tracks. A short-form volume entry whose first section is one letter is refused too (Compose reads it
as a Windows drive): write it in the long form. Scalars stay strings as Compose reads them (`yes` is
no boolean).
`check` runs before the operator's `yes`: a refusal means the app cannot be planned. The image half
of the volume rule needs the built image and runs after build and pull, before `create`:
`check_image_volumes`.

Every refusal is one line that names the entry, the tag, the service and the key, never a value.
A one-shot service and a `depends_on` that waits for health or completion are refused for now.
"""

import re
from collections.abc import Collection, Iterator, Mapping, Sequence
from typing import Any

import yaml

from hal.exposure.docker import EDGE_ALIAS_LABEL, EDGE_NAME_LABEL, TRAEFIK_NAME
from hal.output import printable

_TRAEFIK_ENABLE = "traefik.enable"
_WAITING_CONDITIONS = {"service_healthy", "service_completed_successfully"}
_RESTART = "unless-stopped"
_DISABLED_HEALTHCHECK = "NONE"
_DECIDING_LABELS = {EDGE_NAME_LABEL, EDGE_ALIAS_LABEL, _TRAEFIK_ENABLE}
_COMPOSE_TRUE = {"true", "yes", "on", "y"}


class _ComposeLoader(yaml.SafeLoader):
    """SafeLoader with YAML 1.2 booleans: only true and false, so `yes`, `no`, `on` and `off` stay
    strings as in Compose."""


_ComposeLoader.yaml_implicit_resolvers = {
    first: [(tag, pattern) for tag, pattern in resolvers if tag != "tag:yaml.org,2002:bool"]
    for first, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_ComposeLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"), list("tTfF")
)


class ContractError(Exception):
    """The compose file breaks the contract; the message is one line."""


def check(
    text: str | None,
    entry: str,
    tag: str,
    hosts: Sequence[str],
    *,
    served_elsewhere: Collection[str],
) -> tuple[str, ...]:
    """The services of a release's compose file when it keeps the contract for the entry's
    `hosts`; else ContractError. A host in `served_elsewhere` needs no labelled service, but a
    label may still name it."""

    def refuse(reason: str) -> ContractError:
        return ContractError(f"services.{entry}: compose.yaml at {tag}: {reason}")

    document = _document(text, refuse)
    services = document["services"]
    if "include" in document:
        raise refuse("uses include (include); an app is self-contained")
    if "name" in document and document["name"] != entry:
        raise refuse(f"names its project other than {entry} (name)")
    for name, definition in services.items():
        if reason := _service_refusal(definition):
            raise refuse(f"service {printable(str(name))} {reason}")
    for reason in _routing_refusals(services, hosts, served_elsewhere):
        raise refuse(reason)
    return tuple(str(name) for name in services)


def check_image_volumes(
    text: str, entry: str, tag: str, declared: Mapping[str, Sequence[str]]
) -> None:
    """Raises ContractError for a volume that the image of a service declares (`declared` maps
    each service to its paths) and that no named volume, bind or tmpfs of that service covers:
    Docker would keep its data in an anonymous volume that the next release does not find."""
    for name, definition in yaml.load(text, _ComposeLoader)["services"].items():  # noqa: S506 - the loader subclasses SafeLoader
        covered = _covered_paths(definition)
        for path in declared.get(str(name), ()):
            if path.rstrip("/") not in covered:
                raise ContractError(
                    f"services.{entry}: image of service {printable(str(name))} at {tag} "
                    "declares a volume that no named volume of the service covers (volumes); "
                    "give it a named volume"
                )


def _document(text: str | None, refuse: Any) -> dict:
    if text is None:
        raise refuse("none at the root of the repository")
    try:
        document = yaml.load(text, _ComposeLoader)  # noqa: S506 - the loader subclasses SafeLoader
    except yaml.YAMLError as error:
        raise refuse(f"cannot be read ({type(error).__name__})") from None
    services = document.get("services") if isinstance(document, dict) else None
    if not isinstance(services, dict) or not services:
        raise refuse("must be a map with services")
    return document


def _service_refusal(definition: object) -> str | None:
    """Why a service definition breaks the contract; None when it keeps it."""
    if not isinstance(definition, dict):
        return "must be a map"
    if "profiles" in definition:
        return "uses profiles (profiles); an app's services are all started"
    if "extends" in definition:
        return "uses extends (extends); not yet supported"
    return (
        _published_port_refusal(definition)
        or _dependency_refusal(definition)
        or _restart_refusal(definition)
        or _volume_refusal(definition)
    )


def _published_port_refusal(definition: dict) -> str | None:
    if "ports" in definition:
        return "publishes a port (ports); an app is reached through Traefik only"
    network_mode = definition.get("network_mode")
    if _interpolates(network_mode):
        return "interpolates network_mode ($); an app is reached through Traefik only"
    if network_mode == "host":
        return "uses the host network (network_mode); an app is reached through Traefik only"
    return None


def _dependency_refusal(definition: dict) -> str | None:
    conditions = definition.get("depends_on")
    if not isinstance(conditions, dict):
        return None
    waits = [d.get("condition") for d in conditions.values() if isinstance(d, dict)]
    if any(_interpolates(value) for value in waits):
        return "interpolates a depends_on condition ($); not yet supported"
    if any(value in _WAITING_CONDITIONS for value in waits):
        return "waits for health or completion (depends_on condition); not yet supported"
    return None


def _restart_refusal(definition: dict) -> str | None:
    restart = definition.get("restart")
    if _interpolates(restart):
        return "interpolates restart ($); not yet supported"
    if restart is False or restart == "no":
        return "is a one-shot (restart no); not yet supported"
    if restart != _RESTART:
        return f"must restart {_RESTART} (restart)"
    return None


def _volume_refusal(definition: dict) -> str | None:
    for volume in _mounts(definition):
        if _mount_interpolates(volume):
            return "interpolates a volume entry ($); not yet supported"
        match volume:
            case str() if _is_drive_letter_entry(volume):
                return (
                    "has a volume entry that starts with one letter (volumes); "
                    "write it in the long form"
                )
            case str() if _short_target(volume) is None:
                return "has a volume entry without a source (volumes); give it a named volume"
            case dict() if volume.get("type") != "tmpfs" and not volume.get("source"):
                return "has a volume entry without a source (volumes); give it a named volume"
    if any(_interpolates(mount) for mount in _tmpfs_mounts(definition)):
        return "interpolates a tmpfs mount ($); not yet supported"
    return None


def _mount_interpolates(volume: object) -> bool:
    """A `$` where it decides a rule. A short entry is read without interpolation, so any `$` in
    it is refused; a long entry is refused in its type, its target and the source of a named
    volume (a bind's source and the other fields change no rule)."""
    if not isinstance(volume, dict):
        return _interpolates(volume)
    if volume.get("type") == "tmpfs":
        return _interpolates(str(volume))
    deciding = [volume.get("type"), volume.get("target")]
    if volume.get("type") == "volume":
        deciding.append(volume.get("source"))
    return any(_interpolates(part) for part in deciding)


def _routing_refusals(
    services: dict, hosts: Sequence[str], served_elsewhere: Collection[str]
) -> Iterator[str]:
    """Each host hal's tunnel serves has exactly one service labelled with its name, or with it as
    `edge.alias`, and `traefik.enable: "true"`, and a host another tunnel serves at most one; a
    labelled service names hosts of the entry and has a healthcheck."""
    holders: dict[str, list[str]] = {}
    for name, definition in services.items():
        yield from _service_refusals(str(name), definition, hosts, holders)
    for host in hosts:
        held = len(holders.get(host, []))
        elsewhere = host in served_elsewhere
        if held > 1 or (held == 0 and not elsewhere):
            yield (
                f"host {printable(host)} needs {'at most' if elsewhere else 'exactly'} one "
                f"service labelled {EDGE_NAME_LABEL} or {EDGE_ALIAS_LABEL} with it (labels)"
            )


def _service_refusals(
    key: str, definition: dict, hosts: Sequence[str], holders: dict[str, list[str]]
) -> Iterator[str]:
    """One service's refusals; the hosts it holds are added to `holders`."""
    service = f"service {printable(key)}"
    if (interpolated := _interpolated_label(definition)) is not None:
        named = f" ({interpolated})" if interpolated in _DECIDING_LABELS else ""
        yield f"{service} interpolates a label ($){named}; not yet supported"
        return
    labels = _labels(definition)
    if EDGE_NAME_LABEL not in labels:
        if EDGE_ALIAS_LABEL in labels:
            yield f"{service} has {EDGE_ALIAS_LABEL} without {EDGE_NAME_LABEL} (labels)"
        return
    if labels.get(_TRAEFIK_ENABLE) != "true":
        yield f"{service} has {EDGE_NAME_LABEL} without {_TRAEFIK_ENABLE} true (labels)"
    if labels[EDGE_NAME_LABEL] not in hosts:
        yield f"{service} labels a name the entry does not list ({EDGE_NAME_LABEL})"
    holders.setdefault(labels[EDGE_NAME_LABEL], []).append(key)
    yield from _alias_refusals(service, labels, hosts, holders, key)
    if reason := _healthcheck_refusal(definition.get("healthcheck")):
        yield f"{service} {reason}"


def _alias_refusals(
    service: str,
    labels: dict[str, str],
    hosts: Sequence[str],
    holders: dict[str, list[str]],
    key: str,
) -> Iterator[str]:
    """`edge.alias` is one more host of the entry for the service that carries `edge.name`: the
    name must be one Traefik's provider accepts, the alias too, and differ from the name."""
    if EDGE_ALIAS_LABEL not in labels:
        return
    alias = labels[EDGE_ALIAS_LABEL]
    if not TRAEFIK_NAME.fullmatch(labels[EDGE_NAME_LABEL]):
        yield (
            f"{service} has {EDGE_ALIAS_LABEL} beside an {EDGE_NAME_LABEL} Traefik "
            "does not route (labels)"
        )
    elif not TRAEFIK_NAME.fullmatch(alias):
        yield f"{service} labels an {EDGE_ALIAS_LABEL} outside [a-z0-9-]{{1,63}} (labels)"
    elif alias == labels[EDGE_NAME_LABEL]:
        yield f"{service} labels an {EDGE_ALIAS_LABEL} equal to its {EDGE_NAME_LABEL} (labels)"
    elif alias not in hosts:
        yield f"{service} labels an alias the entry does not list ({EDGE_ALIAS_LABEL})"
    else:
        holders.setdefault(alias, []).append(key)


def _healthcheck_refusal(health: object) -> str | None:
    if not isinstance(health, dict) or _healthcheck_disabled(health):
        return "has no healthcheck (healthcheck); the publish phase asks it for ready"
    for key in ("test", "disable"):
        if _interpolates(str(health.get(key))):
            return f"interpolates the healthcheck {key} ($); not yet supported"
    return None


def _healthcheck_disabled(health: dict) -> bool:
    test = health.get("test")
    named = test[0] if isinstance(test, list) and test else test
    return _compose_true(health.get("disable")) or named == _DISABLED_HEALTHCHECK


def _compose_true(value: object) -> bool:
    """Compose's boolean: `no`, `off` and `false` are false, `yes`, `on`, `y` and `true` are true,
    quoted or not, in any case."""
    return value is True or (isinstance(value, str) and value.lower() in _COMPOSE_TRUE)


def _interpolated_label(definition: dict) -> str | None:
    """The key of the first label with a `$` in its key, or in its value when the contract reads
    that label: it could resolve to another label or host from the `.env` the release tracks."""
    return next(
        (
            key
            for key, value in _label_pairs(definition)
            if _interpolates(key) or (key in _DECIDING_LABELS and _interpolates(value))
        ),
        None,
    )


def _labels(definition: dict) -> dict[str, str]:
    return {
        str(key): str(value).lower() if isinstance(value, bool) else str(value)
        for key, value in _label_pairs(definition)
    }


def _label_pairs(definition: dict) -> list[tuple[object, object]]:
    labels = definition.get("labels")
    if isinstance(labels, dict):
        return list(labels.items())
    if isinstance(labels, list):
        return [(key, value) for key, _, value in (str(item).partition("=") for item in labels)]
    return []


def _covered_paths(definition: dict) -> set[str]:
    """The container paths that a named volume, a bind or a tmpfs of the service mounts."""
    covered = set()
    for volume in _mounts(definition):
        target = volume.get("target") if isinstance(volume, dict) else _short_target(str(volume))
        if isinstance(target, str):
            covered.add(target.rstrip("/"))
    for mount in _tmpfs_mounts(definition):
        covered.add(str(mount).split(":")[0].rstrip("/"))
    return covered


def _short_target(volume: str) -> str | None:
    """The container path of a short volume entry `source:target[:mode]`; Compose reads an
    entry of at most two characters as a bare target, so it has no source."""
    parts = volume.split(":")
    has_source = len(volume) > 2 and len(parts) > 1 and not _is_drive_letter_entry(volume)
    return parts[1] if has_source else None


def _is_drive_letter_entry(volume: str) -> bool:
    """Compose reads a first section of one letter as a drive, not as a source; hal does not
    parse that grammar and refuses the entry. Only a letter is a drive (`.`, `~`, `/`, `1` and
    `_` are sources)."""
    first_section = volume.split(":")[0]
    return len(first_section) == 1 and first_section.isalpha() and ":" in volume


def _mounts(definition: dict) -> list:
    volumes = definition.get("volumes")
    return volumes if isinstance(volumes, list) else []


def _tmpfs_mounts(definition: dict) -> list:
    tmpfs = definition.get("tmpfs") or ()
    return [tmpfs] if isinstance(tmpfs, str) else list(tmpfs)


def _interpolates(value: object) -> bool:
    return isinstance(value, str) and "$" in value
