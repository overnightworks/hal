"""`fleet.yaml`, the service catalog: the one owner of reading it and of its typed schemas.

`hal apply` reads the entries that have a `run` block and no `repo`: the units of this
repository. A unit's key is a compose profile (docs/naming.md). An entry with `repo` and `run` is
an app: its key is its repository's name under `github.org`, its compose project and its checkout
`~/srv/<key>`; `apps()` reads them. Entries without `run` are no units and no apps, and `units()`
and `apps()` ignore them; `host_only_keys()` reads those with no `repo` either, the apps edge only
fronts. `hosts()` is the separate reader of every entry's `hosts` list (an entry without `run` is
enabled). `units()` also reads each unit's hosts, enabled or not, and needs a valid
`cloudflare.zone` once a unit declares one.
"""

import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

FLEET_FILE = "fleet.yaml"
_RUN_KEYS = {"enabled", "setup"}
_APP_RUN_KEYS = {"enabled"}
_REPO_KEYS = {"default_branch"}
_BOOL_TAG = "tag:yaml.org,2002:bool"
_TRUE_OR_FALSE = re.compile(r"^(?:true|false)$")
_FLOAT_TAG = "tag:yaml.org,2002:float"
_INT_TAG = "tag:yaml.org,2002:int"
# Forms other YAML readers take as numbers and PyYAML leaves as strings: not labels.
_EXPONENT_NUMBER = re.compile(r"^[-+]?\d+[eE][-+]?\d+$")
_OCTAL_NUMBER = re.compile(r"^0o[0-7]+$")

DEFAULT_TARGET = "http://127.0.0.1:8081"  # Traefik
_HOST_KEYS = {"name", "exposure", "reason", "ready", "deny_public", "tunnel"}
# Lowercase unreserved segments, no query or trailing slash: the rendering embeds it in a rule.
_DENIED_PATH = re.compile(r"(/[a-z0-9._~-]+)+")
_HTTPS_URL = re.compile(r"https://[a-z0-9.-]+(:\d+)?(/[a-z0-9._~/-]*)?")
_REDIRECT_KEYS = {"hosts", "target", "serve"}
_SERVE_KEYS = {"pages", "files"}
_FILES_PREFIX = re.compile(r"(/[a-z0-9._~-]+)+/")
_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
# A tunnel's name is a DNS label, the same shape as a host's name.
_TUNNEL_NAME = _LABEL
# A compose project name: it is also the repository and the directory name of an app.
_APP_KEY = re.compile(r"[a-z0-9][a-z0-9_-]*")
_GITHUB_ORGANISATION = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
# What `git check-ref-format --branch` accepts, narrowed to what never needs quoting.
_BRANCH = re.compile(r"\w[\w.-]*(/\w[\w.-]*)*", re.ASCII)
APEX = "@"
WILDCARD = "*"


class CatalogError(Exception):
    """The catalog is invalid; the message is one line that names the key."""


class _CatalogLoader(yaml.SafeLoader):
    """Only `true` and `false` are booleans, and the numbers other readers take are no strings.

    YAML 1.1 words (`yes`, `no`, `on`, `off`, `y`, `n`, `True`) read as booleans in some YAML
    readers and PyYAML disagrees on some of them; only `true` and `false` mean the same to every
    reader, so every other spelling is refused.
    """


_CatalogLoader.yaml_implicit_resolvers = {
    first_character: [(tag, pattern) for tag, pattern in resolvers if tag != _BOOL_TAG]
    for first_character, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_CatalogLoader.add_implicit_resolver(_BOOL_TAG, _TRUE_OR_FALSE, list("tf"))
_CatalogLoader.add_implicit_resolver(_FLOAT_TAG, _EXPONENT_NUMBER, list("-+0123456789"))
_CatalogLoader.add_implicit_resolver(_INT_TAG, _OCTAL_NUMBER, ["0"])


@dataclass(frozen=True)
class Unit:
    key: str
    enabled: bool
    setup: str | None
    hosts: tuple[str, ...] = ()
    served_elsewhere: tuple[Host, ...] = ()  # the hosts another tunnel serves


@dataclass(frozen=True)
class App:
    key: str
    enabled: bool
    default_branch: str
    hosts: tuple[str, ...] = ()
    served_elsewhere: tuple[Host, ...] = ()  # the hosts another tunnel serves


def read(catalog_file: Path) -> Any:
    """The catalog's document."""
    return parse(read_bytes(catalog_file), catalog_file.name)


def read_bytes(catalog_file: Path) -> bytes:
    """The catalog file as it is now: a caller that must compare two reads keeps the bytes."""
    try:
        return catalog_file.read_bytes()
    except OSError as error:
        raise CatalogError(
            f"{catalog_file.name}: cannot read it ({type(error).__name__})"
        ) from error


def parse(raw: bytes, name: str = FLEET_FILE) -> Any:
    """The document of catalog bytes already read; `name` is the file the message names."""
    try:
        return yaml.load(raw.decode(), Loader=_CatalogLoader)  # noqa: S506 - the loader subclasses SafeLoader
    except yaml.YAMLError as error:
        raise CatalogError(f"{name}: cannot read it ({type(error).__name__})") from error


def load(repository: Path, profile_services: Mapping[str, tuple[str, ...]]) -> tuple[Unit, ...]:
    return units(read(repository / FLEET_FILE), profile_services, repository)


def units(
    document: Any, profile_services: Mapping[str, tuple[str, ...]], repository: Path
) -> tuple[Unit, ...]:
    """The units of the repository's catalog, each checked against the compose profiles."""
    return tuple(
        _unit(key, entry, profile_services, repository, document)
        for key, entry in _entries(document).items()
        if _is_unit(entry)
    )


def _entries(document: Any) -> dict:
    """The `services` map of the catalog's document."""
    if not isinstance(document, dict):
        raise CatalogError(f"{FLEET_FILE}: must be a map")
    entries = document.get("services", {})
    if not isinstance(entries, dict):
        raise CatalogError("services: must be a map of entries")
    return entries


def _is_unit(entry: Any) -> bool:
    return isinstance(entry, dict) and "run" in entry and "repo" not in entry


def is_app(entry: object) -> bool:
    return isinstance(entry, dict) and "run" in entry and "repo" in entry


def host_only_keys(document: Any) -> tuple[str, ...]:
    """The entries with neither `repo` nor `run`: apps edge only fronts, whose checkout
    `~/srv/<key>` is somebody else's to deploy."""
    return tuple(
        key
        for key, entry in _entries(document).items()
        if isinstance(entry, dict) and "run" not in entry and "repo" not in entry
    )


def apps(
    document: Any, profile_services: Mapping[str, tuple[str, ...]], edge_project: str
) -> tuple[App, ...]:
    """The apps of the catalog: the entries with `repo` and `run`. A `repo` entry without `run` is
    a library and stays ignored. No app takes a profile or the project name `edge_project` of
    edge's own stack."""
    return tuple(
        _app(key, entry, profile_services, edge_project, document)
        for key, entry in _entries(document).items()
        if is_app(entry)
    )


def is_enabled_app(document: Any, key: str) -> bool:
    """Whether the catalog has an enabled app `key` whose key and `run` are valid; a malformed
    catalog or entry is not one, and planning reports it."""
    try:
        entry = _entries(document).get(key)
        return is_app(entry) and _enabled(key, _app_run(key, entry))
    except CatalogError:
        return False


def github_org(document: Any) -> str:
    """The GitHub organisation that owns the repositories of the apps (`github.org`)."""
    github = document.get("github") if isinstance(document, dict) else None
    organisation = github.get("org") if isinstance(github, dict) else None
    if not isinstance(organisation, str) or not _GITHUB_ORGANISATION.fullmatch(organisation):
        raise CatalogError("github.org: must be a GitHub organisation name")
    return organisation


def _app(
    key: str,
    entry: dict,
    profile_services: Mapping[str, tuple[str, ...]],
    edge_project: str,
    document: Any,
) -> App:
    if key in profile_services or key == edge_project:
        raise CatalogError(f"services.{key}: an app's key is no compose profile or project of edge")
    run = _app_run(key, entry)
    entered = _entered_hosts(key, entry, document)
    _require_ready(entered)
    enabled = _enabled(key, run)
    return App(
        key,
        enabled,
        _default_branch(key, entry["repo"]),
        _names(entered),
        _served_elsewhere(entered, enabled),
    )


def _app_run(key: str, entry: dict) -> dict:
    """The `run` map of an app entry, once its key is a compose project name, which is also a
    safe file name, and every key of `run` is known."""
    if not _APP_KEY.fullmatch(key):
        raise CatalogError(f"services.{key}: an app's key must be a compose project name")
    run = entry["run"]
    if not isinstance(run, dict):
        raise CatalogError(f"services.{key}.run: must be a map")
    for run_key in run:
        if run_key not in _APP_RUN_KEYS:
            raise CatalogError(f"services.{key}.run.{run_key}: unknown key for an app")
    return run


def _default_branch(key: str, repo: Any) -> str:
    if not isinstance(repo, dict):
        raise CatalogError(f"services.{key}.repo: must be a map")
    for repo_key in repo:
        if repo_key not in _REPO_KEYS:
            raise CatalogError(f"services.{key}.repo.{repo_key}: unknown key")
    branch = repo.get("default_branch")
    if not isinstance(branch, str) or not _is_branch_name(branch):
        raise CatalogError(f"services.{key}.repo.default_branch: must be a branch name")
    return branch


def _is_branch_name(branch: str) -> bool:
    return (
        bool(_BRANCH.fullmatch(branch))
        and ".." not in branch
        and not branch.endswith((".", ".lock"))
    )


def _unit(
    key: str,
    entry: dict,
    profile_services: Mapping[str, tuple[str, ...]],
    repository: Path,
    document: Any,
) -> Unit:
    run = entry["run"]
    if key not in profile_services:
        profiles = ", ".join(sorted(profile_services))
        raise CatalogError(
            f"services.{key}: no compose profile of that name (profiles: {profiles})"
        )
    if not isinstance(run, dict):
        raise CatalogError(f"services.{key}.run: must be a map")
    for run_key in run:
        if run_key not in _RUN_KEYS:
            raise CatalogError(f"services.{key}.run.{run_key}: unknown key")
    entered = _entered_hosts(key, entry, document)
    enabled = _enabled(key, run)
    return Unit(
        key,
        enabled,
        _setup(key, run.get("setup"), repository),
        _names(entered),
        _served_elsewhere(entered, enabled),
    )


def _names(entered: list[tuple[str, Host]]) -> tuple[str, ...]:
    """The catalog names an entry declares, enabled or not: the emergency barrier covers all."""
    return tuple(one.name for _, one in entered)


def _served_elsewhere(entered: list[tuple[str, Host]], enabled: bool) -> tuple[Host, ...]:
    """The hosts another tunnel serves; a disabled entry publishes none, as `hosts` has it."""
    return tuple(one for _, one in entered if enabled and one.tunnel is not None)


def _enabled(key: str, run: dict) -> bool:
    enabled = run.get("enabled")
    if not isinstance(enabled, bool):
        raise CatalogError(f"services.{key}.run.enabled: must be true or false")
    return enabled


def _setup(key: str, setup: Any, repository: Path) -> str | None:
    if setup is None:
        return None
    path = (repository / str(setup)).resolve()
    inside = path.is_relative_to(repository.resolve())
    if not (isinstance(setup, str) and inside and path.is_file() and os.access(path, os.X_OK)):
        raise CatalogError(f"services.{key}.run.setup: {setup!r} is not an executable file")
    return setup


class Exposure(StrEnum):
    PUBLIC = "public"
    BYPASS = "bypass"
    PROTECTED = "protected"


@dataclass(frozen=True)
class Host:
    service: str
    name: str
    fqdn: str
    exposure: Exposure
    reason: str | None
    ready: str | None
    target: str
    deny_public: tuple[str, ...] = ()
    tunnel: str | None = None  # the other tunnel that serves the host; None: hal's own


def hosts(document: Any) -> tuple[Host, ...]:
    """The hosts of the enabled entries; the hosts of disabled entries are checked, not returned."""
    if not isinstance(document, dict):
        raise CatalogError(f"{FLEET_FILE}: must be a map")
    zone_name = zone(document)
    entries = document.get("services", {})
    if not isinstance(entries, dict):
        raise CatalogError("services: must be a map of entries")
    enabled_hosts: list[tuple[str, Host]] = []
    for key, entry in entries.items():
        if not isinstance(entry, dict) or "hosts" not in entry:
            continue
        entered = _entry_hosts(key, entry["hosts"], zone_name)
        if is_app(entry):
            _require_ready(entered)
        if _entry_enabled(key, entry):
            enabled_hosts += entered
    _check_together(enabled_hosts)
    _check_redirect(document, zone_name, {host.fqdn for _, host in enabled_hosts})
    return tuple(host for _, host in enabled_hosts)


def fqdn_of(name: str, zone: str) -> str:
    """The full name of a catalog host name: '@' is the zone's apex."""
    return zone if name == APEX else f"{name}.{zone}"


def zone(document: Any) -> str:
    """The catalog's `cloudflare.zone`, validated the way every reader of it needs."""
    cloudflare = document.get("cloudflare") if isinstance(document, dict) else None
    name = cloudflare.get("zone") if isinstance(cloudflare, dict) else None
    if not isinstance(name, str) or not _is_dotted_labels(name):
        raise CatalogError("cloudflare.zone: must be a lowercase name without a trailing dot")
    return name


def _is_dotted_labels(zone: str) -> bool:
    labels = zone.split(".")
    return len(labels) >= 2 and all(_LABEL.fullmatch(label) for label in labels)


def _require_ready(entered: list[tuple[str, Host]]) -> None:
    """An app's host needs its `ready` path, so planning refuses one without it before anything
    starts: the tunnel's owner asks it there before the host moves."""
    for path, one in entered:
        if one.ready is None:
            raise CatalogError(f"{path}.ready: an app's host needs a `ready` path")


def _entry_enabled(key: str, entry: dict) -> bool:
    if "run" not in entry:
        return True
    if not isinstance(entry["run"], dict):
        raise CatalogError(f"services.{key}.run: must be a map")
    return _enabled(key, entry["run"])


def _entry_hosts(key: str, listed: Any, zone: str) -> list[tuple[str, Host]]:
    if not isinstance(listed, list):
        raise CatalogError(f"services.{key}.hosts: must be a list")
    return [
        (f"services.{key}.hosts[{index}]", _host(key, f"services.{key}.hosts[{index}]", item, zone))
        for index, item in enumerate(listed)
    ]


def _entered_hosts(key: str, entry: dict, document: Any) -> list[tuple[str, Host]]:
    if "hosts" not in entry:
        return []
    return _entry_hosts(key, entry["hosts"], zone(document))


def _host(service: str, path: str, item: Any, zone: str) -> Host:
    if not isinstance(item, dict):
        raise CatalogError(f"{path}: must be a map")
    for field in item:
        if field not in _HOST_KEYS:
            raise CatalogError(f"{path}.{field}: unknown key")
    name = _name(path, item.get("name"))
    exposure = _exposure(path, item.get("exposure"))
    _check_exposure_fits_name(path, name, exposure)
    fqdn = fqdn_of(name, zone)
    return Host(
        service=service,
        name=name,
        fqdn=fqdn,
        exposure=exposure,
        reason=_reason(path, item.get("reason"), exposure),
        ready=_ready(path, item),
        target=DEFAULT_TARGET,
        deny_public=_deny_public(path, item.get("deny_public", [])),
        tunnel=_tunnel(path, fqdn, item),
    )


def _name(path: str, name: Any) -> str:
    if not isinstance(name, str) or not (name in (APEX, WILDCARD) or _LABEL.fullmatch(name)):
        raise CatalogError(f"{path}.name: must be '@', '*' or one lowercase DNS label")
    return name


def _exposure(path: str, exposure: Any) -> Exposure:
    try:
        return Exposure(exposure)
    except ValueError:
        values = ", ".join(member.value for member in Exposure)
        raise CatalogError(f"{path}.exposure: must be one of {values}") from None


def _check_exposure_fits_name(path: str, name: str, exposure: Exposure) -> None:
    if name == WILDCARD and exposure is not Exposure.PROTECTED:
        raise CatalogError(f"{path}.exposure: the wildcard must be protected")
    if exposure is Exposure.PROTECTED and name != WILDCARD:
        raise CatalogError(f"{path}.exposure: only the wildcard may be protected")


def _reason(path: str, reason: Any, exposure: Exposure) -> str | None:
    if reason is not None and not isinstance(reason, str):
        raise CatalogError(f"{path}.reason: must be a string")
    if exposure is not Exposure.PROTECTED and not (reason and reason.strip()):
        raise CatalogError(f"{path}.reason: a {exposure} host needs one")
    return reason


def _ready(path: str, item: dict) -> str | None:
    if "ready" not in item:
        return None
    ready = item["ready"]
    if not isinstance(ready, str) or not _is_request_path(ready):
        raise CatalogError(
            f"{path}.ready: must be a path of printable ASCII, no space, that starts with one '/'"
        )
    return ready


def _is_request_path(ready: str) -> bool:
    """What the probe can send as a request target: its request line has room for no more."""
    return (
        ready.startswith("/")
        and not ready.startswith("//")
        and ready.isascii()
        and ready.isprintable()
        and " " not in ready
    )


def _deny_public(path: str, denied: Any) -> tuple[str, ...]:
    if not isinstance(denied, list) or not all(
        isinstance(entry, str) and _DENIED_PATH.fullmatch(entry) for entry in denied
    ):
        raise CatalogError(
            f"{path}.deny_public: must be a list of lowercase absolute paths "
            "(letters, digits, . _ ~ -), no query, no trailing slash"
        )
    return tuple(denied)


def _tunnel(path: str, fqdn: str, item: dict) -> str | None:
    """The other tunnel that serves the host; the wildcard stays with hal's Access and tunnel."""
    if "tunnel" not in item:
        return None
    tunnel = item["tunnel"]
    if not isinstance(tunnel, str) or not _TUNNEL_NAME.fullmatch(tunnel):
        raise CatalogError(f"{path}.tunnel: must be one lowercase DNS label")
    if item.get("name") == WILDCARD:
        raise CatalogError(f"{path}.tunnel: the wildcard {fqdn} stays on hal's tunnel")
    return tunnel


def _check_together(enabled_hosts: list[tuple[str, Host]]) -> None:
    wildcard_exists = any(host.name == WILDCARD for _, host in enabled_hosts)
    seen: set[str] = set()
    for path, host in enabled_hosts:
        if wildcard_exists and host.exposure is Exposure.PUBLIC and host.name != APEX:
            raise CatalogError(
                f"{path}.exposure: a public host needs its own bypass while '*' exists"
            )
        if host.fqdn in seen:
            raise CatalogError(f"{path}.name: {host.fqdn} is listed twice")
        seen.add(host.fqdn)


def _check_redirect(document: dict, zone: str, taken: set[str]) -> None:
    """`cloudflare.redirect`: the zone's names that leave the tunnel for a redirect at the edge.

    A malformed one is refused when the catalog is read.
    """
    redirect = document["cloudflare"].get("redirect")
    if redirect is None:
        return
    path = "cloudflare.redirect"
    if not isinstance(redirect, dict):
        raise CatalogError(f"{path}: must be a map")
    for field in redirect:
        if field not in _REDIRECT_KEYS:
            raise CatalogError(f"{path}.{field}: unknown key")
    serve = redirect.get("serve")
    apex = fqdn_of(APEX, zone)
    # Only while the apex serves pages may it be a service host and a redirected name.
    unclaimed = taken - {apex} if serve is not None else taken
    _check_redirect_hosts(f"{path}.hosts", redirect.get("hosts"), zone, unclaimed)
    target = redirect.get("target")
    if not (isinstance(target, str) and _HTTPS_URL.fullmatch(target) and _has_valid_origin(target)):
        raise CatalogError(f"{path}.target: must be an https URL without query or fragment")
    if serve is not None:
        _check_serve(path, redirect, apex in taken)


def _check_serve(redirect_path: str, redirect: dict, apex_is_host: bool) -> None:
    """`serve`: the apex's own pages and files are answered by the tunnel, not redirected."""
    path = f"{redirect_path}.serve"
    serve = redirect["serve"]
    if not isinstance(serve, dict):
        raise CatalogError(f"{path}: must be a map")
    for field in serve:
        if field not in _SERVE_KEYS:
            raise CatalogError(f"{path}.{field}: unknown key")
    if APEX not in redirect["hosts"] or not apex_is_host:
        raise CatalogError(f"{path}: needs '@' among the redirected names and as an enabled host")
    pages, files = _serve_pages_and_files(path, serve)
    files_stem = files.rstrip("/")
    if files_stem in pages:
        raise CatalogError(f"{path}.pages: {files_stem} is also the files prefix")


def _serve_pages_and_files(path: str, serve: dict) -> tuple[list[str], str]:
    pages, files = serve.get("pages"), serve.get("files")
    if not (
        isinstance(pages, list)
        and pages
        and all(isinstance(page, str) and _DENIED_PATH.fullmatch(page) for page in pages)
        and len(set(pages)) == len(pages)
    ):
        raise CatalogError(f"{path}.pages: must be a list of different lowercase absolute paths")
    if not (isinstance(files, str) and _FILES_PREFIX.fullmatch(files)):
        raise CatalogError(f"{path}.files: must be a lowercase absolute path prefix ending in '/'")
    return pages, files


def _check_redirect_hosts(path: str, names: Any, zone: str, taken: set[str]) -> None:
    labels_only = (
        isinstance(names, list)
        and bool(names)
        and all(
            isinstance(name, str) and (name == APEX or _LABEL.fullmatch(name)) for name in names
        )
    )
    if not labels_only or len(set(names)) != len(names):
        raise CatalogError(f"{path}: must be a list of different names, '@' or one lowercase label")
    for name in names:
        fqdn = fqdn_of(name, zone)
        if fqdn in taken:
            raise CatalogError(f"{path}: {fqdn} is also a host of a service")


def _has_valid_origin(url: str) -> bool:
    """The hostname is dot-separated lowercase labels and the port, if any, is a real one."""
    parts = urlsplit(url)
    try:
        port = parts.port
    except ValueError:
        return False
    labels = (parts.hostname or "").split(".")
    return all(_LABEL.fullmatch(label) for label in labels) and port != 0
