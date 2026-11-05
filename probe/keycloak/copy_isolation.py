"""The isolation of an edge copy that runs Keycloak beside the live stack: the one allocation a copy
holds (`Isolation`), the rewrites every file installed into it takes (`install`), and the checks
that refuse a copy whose files or resolved configuration could reach the live stack
(`expect_isolated` before every `hal apply`, `expect_call_isolated` before every compose call that
starts something, with the files that call merges). `expect_guards_refuse` proves the checks on
negative cases before anything starts. in_copy.py imports it once probe/ and src/ are on the path.
"""

from __future__ import annotations

import functools
import importlib.machinery
import importlib.util
import json
import re
import shlex
import sys
from collections.abc import Callable, Iterable, Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass, replace
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

import edge_copy
import yaml
from edge_copy import ProbeFailed, expect

from hal.backup.apps import parse_apps
from hal.backup.cli import DEFAULT_APPS
from hal.backup.docker import PROJECT_LABEL
from hal.exposure.docker import EDGE_NAME_LABEL
from hal.output import write_line
from hal.stack import barrier, catalog, compose, deploy_checkout
from hal.stack.realm.reconcile import CONFIG_CLI, KEYCLOAK_SERVICE, REALM_UNIT

REPO = Path(__file__).resolve().parents[2]


def load_by_path(name: str, path: Path) -> ModuleType:
    """The module at `path` under `name`: probe/keycloak/probe.py as `keycloak_probe`, so it never
    clashes with another probe directory's `probe` module."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    expect(spec is not None, f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # its dataclasses resolve their annotations through it
    loader.exec_module(module)
    return module


keycloak = sys.modules.get("keycloak_probe") or load_by_path(
    "keycloak_probe", REPO / "probe" / "keycloak" / "probe.py"
)
go_live = keycloak.load_go_live()

# Upper case: the live constraint's LabelRegex refuses it, so the live Traefik never routes the
# copy's Keycloak; the copy's Traefik routes by the project label instead.
SCRATCH_EDGE_NAME = "PROBE"
COMPOSE_FILE = deploy_checkout.COMPOSE_FILE
TRAEFIK_FILE = barrier.TRAEFIK_FILE
FLEET_FILE = catalog.FLEET_FILE
APPS_FILE = str(DEFAULT_APPS.relative_to(compose.REPOSITORY))
SHIPPED_FLEET = catalog.parse((REPO / FLEET_FILE).read_bytes())["services"]
GO_LIVE_FILE = SHIPPED_FLEET[REALM_UNIT]["run"]["setup"]
TRAEFIK_SERVICE = "traefik"  # the one service on the host network: its addresses are traefik.yml's
SOCKET_PROXY = "socket-proxy"
# The one bind outside the scratch tree: the copy's socket proxy reads the daemon through it and
# answers only the copy's Traefik, with GET and HEAD alone.
DOCKER_SOCKET_BIND = (SOCKET_PROXY, "/var/run/docker.sock")
STARTING_VERBS = frozenset({"up", "run", "start", "restart", "create"})
NAMESPACE_KEYS = ("network_mode", "pid", "ipc")
FOREIGN_CONTAINER = "container:"
SERVICE_REFERENCE = "service:"
HOST_NAMESPACE = "host"
FILE_SOURCES = ("secrets", "configs")
TRUSTED_ADDRESSES = "KC_PROXY_TRUSTED_ADDRESSES"  # Keycloak's setting, compose.yaml's anchor
ADMIN_HOSTNAME = "KC_HOSTNAME_ADMIN"
TOP_LEVEL_NAME = re.compile(r"^(name: )(\S+)$", re.M)
KEYCLOAK_SUBNET_ANCHOR = re.compile(r"(&keycloak-subnet )(\S+)")
ADMIN_HOSTNAME_ANCHOR = re.compile(r"(&admin-hostname )(\S+)")
GO_LIVE_ADDRESS = re.compile(r'^(?P<constant>ADMIN_URL|EDGE_URL) = "(?P<value>[^"]*)"$', re.M)
UNIT_SWITCH = re.compile(r"^( {2}(?P<unit>[\w-]+):\n {4}run:\n {6}enabled: )(?:true|false)$", re.M)
LIVE_NAME_CONSTRAINT = re.compile(r"LabelRegex\(`edge\.name`, `(?P<pattern>[^`]+)`\)")
SHORT_SECONDS = 120
LIVE_PORTS = {
    int(a.rpartition(":")[2]) for a in (keycloak.LIVE_EDGE_ADDRESS, keycloak.LIVE_ADMIN_ADDRESS)
}


@dataclass(frozen=True)
class Isolation:
    """The scratch names, ports, subnets and addresses one copy holds for its whole life: every
    install reapplies exactly these."""

    project: str
    edge_port: int
    admin_port: int
    keycloak_subnet: str
    pinned: Mapping[str, str]  # the live /24 prefix of each pinned network -> the copy's

    @classmethod
    def allocate(cls, project: str, shipped_compose: str) -> Isolation:
        """Two free loopback ports and free /24s, none of them the shipped compose.yaml's own, so
        the copy keeps clear of the live stack even while it is down."""
        edge_port, admin_port = keycloak.free_loopback_ports(2)
        expect(not {edge_port, admin_port} & LIVE_PORTS, "a free port is a live entrypoint's")
        live_pinned = edge_copy.live_pinned_prefixes(shipped_compose)
        live_keycloak = KEYCLOAK_SUBNET_ANCHOR.search(shipped_compose)
        expect(live_keycloak is not None, f"{COMPOSE_FILE} has no &keycloak-subnet anchor")
        occupied = [
            *edge_copy.daemon_subnets(),
            live_keycloak[2],
            *(f"{prefix}0/24" for prefix in live_pinned.values()),
        ]
        candidates = keycloak.SUBNET_CANDIDATES
        pinned = edge_copy.free_probe_prefixes(live_pinned, candidates, occupied)
        occupied += [f"{prefix}0/24" for prefix in pinned.values()]
        subnet = str(edge_copy.free_subnet(candidates, occupied))
        return cls(project, edge_port, admin_port, subnet, pinned)

    @property
    def edge_address(self) -> str:
        return f"{keycloak.LOOPBACK_ADDRESS}:{self.edge_port}"

    @property
    def admin_address(self) -> str:
        return f"{keycloak.LOOPBACK_ADDRESS}:{self.admin_port}"

    @property
    def edge_url(self) -> str:
        return f"http://{self.edge_address}"

    @property
    def admin_url(self) -> str:
        return f"http://localhost:{self.admin_port}"  # the admin router's rule is Host(`localhost`)

    @property
    def master_token_url(self) -> str:
        return f"{self.admin_url}/realms/master/protocol/openid-connect/token"

    @property
    def constraint(self) -> str:
        return f"Label(`{PROJECT_LABEL}`, `{self.project}`)"

    @property
    def netlocs(self) -> frozenset[str]:
        return frozenset(urlsplit(url).netloc for url in (self.edge_url, self.admin_url))

    @property
    def subnets(self) -> frozenset[str]:
        return frozenset({self.keycloak_subnet, *(f"{p}0/24" for p in self.pinned.values())})


@dataclass(frozen=True)
class Fleet:
    """The copy's fleet.yaml: the units of `units_on` on, every other unit off, no app the shipped
    file names, and the caller's `app_entries` appended under `services` as written. An app's key
    is its compose project, so each one starts with the copy's project and a dash."""

    units_on: frozenset[str]
    app_entries: str = ""

    def apps(self) -> dict[str, object]:
        """The caller's entries as hal's catalog reads them, by key."""
        if not self.app_entries:
            return {}
        return fleet_services(f"services:\n{self.app_entries}", "the caller's app entries")


@dataclass(frozen=True)
class CopyStand:
    """One isolated copy: where it is, its allocation and fleet, the guard of its compose calls
    and the environment every command in it runs with."""

    copy: Path
    isolation: Isolation
    fleet: Fleet
    guard: edge_copy.NetworkGuard
    environment: Mapping[str, str]

    @property
    def home(self) -> Path:
        """The scratch HOME: the copy and every scratch secret lie under it."""
        return Path(self.environment["HOME"])

    @property
    def projects(self) -> frozenset[str]:
        """The copy's compose project and each app's."""
        return frozenset({self.isolation.project, *self.fleet.apps()})


def run_checked(
    command: list[str], environment: Mapping[str, str], *, cwd: Path | None = None,
    timeout: int = SHORT_SECONDS,
) -> str:  # fmt: skip
    result = edge_copy.run_command(command, text=True, env=environment, cwd=cwd, timeout=timeout)
    tail = compose.last_line(result.stderr or result.stdout)
    expect(result.returncode == 0, f"{shlex.join(command[:6])} exited {result.returncode}: {tail}")
    return result.stdout


def fleet_services(text: str, what: str) -> dict[str, object]:
    """The `services` of fleet.yaml `text`, read by hal's catalog."""
    try:
        document = catalog.parse(text.encode())
    except catalog.CatalogError as error:
        raise ProbeFailed(f"{what} do not parse: {error}") from error
    services = document.get("services") if isinstance(document, dict) else None
    expect(isinstance(services, dict), f"{what} have no services")
    return services


def replaced_once(text: str, pattern: re.Pattern[str], value: str, file: str) -> str:
    """`text` with the one match of `pattern` keeping its first group and taking `value`."""
    moved, count = pattern.subn(lambda found: f"{found[1]}{value}", text)
    expect(count == 1, f"{file} holds {pattern.pattern!r} {count} times, not once")
    return moved


def literal_replaced_once(text: str, old: str, new: str, file: str) -> str:
    expect(text.count(old) == 1, f"{file} holds {old!r} {text.count(old)} times, not once")
    return text.replace(old, new)


def live_project_name() -> str:
    return edge_copy.compose_project_name((REPO / COMPOSE_FILE).read_text())


def isolated_compose(text: str, stand: CopyStand) -> str:
    """compose.yaml under the copy's project, so no compose call in the copy resolves to the live
    project, even one without the project in its environment."""
    isolation = stand.isolation
    text = replaced_once(text, TOP_LEVEL_NAME, isolation.project, COMPOSE_FILE)
    text = edge_copy.namespaced_compose(text, isolation.project)
    text = edge_copy.moved_to_probe_subnets(text, isolation.pinned)
    text = replaced_once(text, KEYCLOAK_SUBNET_ANCHOR, isolation.keycloak_subnet, COMPOSE_FILE)
    text = replaced_once(text, ADMIN_HOSTNAME_ANCHOR, isolation.admin_url, COMPOSE_FILE)
    live_name = yaml.safe_load(text)["services"][KEYCLOAK_SERVICE]["labels"][EDGE_NAME_LABEL]
    return literal_replaced_once(
        text, f"{EDGE_NAME_LABEL}: {live_name}\n", f"{EDGE_NAME_LABEL}: {SCRATCH_EDGE_NAME}\n",
        COMPOSE_FILE,
    )  # fmt: skip


def isolated_traefik(text: str, stand: CopyStand) -> str:
    isolation = stand.isolation
    for live, scratch in {
        keycloak.LIVE_EDGE_ADDRESS: isolation.edge_address,
        keycloak.LIVE_ADMIN_ADDRESS: isolation.admin_address,
        keycloak.LIVE_CONSTRAINTS: isolation.constraint,
    }.items():
        text = literal_replaced_once(text, live, scratch, TRAEFIK_FILE)
    return text


def go_live_addresses(isolation: Isolation) -> dict[str, str]:
    return {"ADMIN_URL": isolation.admin_url, "EDGE_URL": isolation.edge_url}


def isolated_go_live(text: str, stand: CopyStand) -> str:
    """go-live's two hardcoded addresses moved to the copy's, so a go-live that `hal apply` might
    start on a failed `--check` reaches the copy's entrypoints, never the live ones."""
    wanted = go_live_addresses(stand.isolation)
    moved, count = GO_LIVE_ADDRESS.subn(
        lambda found: f'{found["constant"]} = "{wanted[found["constant"]]}"', text
    )
    expect(count == len(wanted), f"{GO_LIVE_FILE} sets its addresses {count} times, not twice")
    return moved


def probe_fleet(text: str, stand: CopyStand) -> str:
    fleet = stand.fleet
    without = edge_copy.without_inherited_apps(text)
    found = {switch["unit"] for switch in UNIT_SWITCH.finditer(without)}
    expect(fleet.units_on <= found, f"{FLEET_FILE} switches no {sorted(fleet.units_on - found)}")
    switched = UNIT_SWITCH.sub(
        lambda switch: f"{switch[1]}{str(switch['unit'] in fleet.units_on).lower()}", without
    )
    result = switched + fleet.app_entries
    expect_fleet_isolated(result, stand)
    return result


def backup_records(text: str, stand: CopyStand) -> str:
    return edge_copy.backup_records_at_project(text, stand.isolation.project, live_project_name())


REWRITES: dict[str, Callable[[str, CopyStand], str]] = {
    COMPOSE_FILE: isolated_compose,
    TRAEFIK_FILE: isolated_traefik,
    GO_LIVE_FILE: isolated_go_live,
    FLEET_FILE: probe_fleet,
    APPS_FILE: backup_records,
}


def shipped_files(repository: Path) -> dict[str, str]:
    """The files of `repository` the rewrites own, as they are there: a caller's base set."""
    return {name: (repository / name).read_text() for name in REWRITES}


def installed_name(stand: CopyStand, name: str) -> str:
    """`name` as the path in the copy it writes, by which its rewrite is found (`./fleet.yaml` and
    `a/../fleet.yaml` are `fleet.yaml`); refused when it is absolute or leaves the copy."""
    expect(not PurePosixPath(name).is_absolute(), f"the install path {name!r} is absolute")
    copy = stand.copy.resolve()
    target = (copy / name).resolve()
    expect(target != copy and target.is_relative_to(copy), f"{name!r} leaves the copy")
    return target.relative_to(copy).as_posix()


def install(stand: CopyStand, files: Mapping[str, str | None], message: str) -> str:
    """Installs a file set into the copy and returns `expect_isolated`'s line: each file is written
    under the copy's allocation (a rewrite of `REWRITES` first, the others as given; an existing
    file keeps its mode), a None removes it, so a file only a candidate has is absent at base and
    gone on revert. The copy is published and its isolation checked again before anything runs."""
    for given, text in files.items():
        name = installed_name(stand, given)
        target = stand.copy / name
        if text is None:
            target.unlink(missing_ok=True)
            continue
        rewrite = REWRITES.get(name)
        isolated = rewrite(text, stand) if rewrite else text
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(isolated)
    edge_copy.publish(stand.copy, message)
    line = expect_isolated(stand)
    write_line(line, flush=True)
    return line


@functools.cache
def live_routed_name() -> re.Pattern[str]:
    """The names the live Traefik routes: the pattern of its one constraint, as traefik.yml
    ships it."""
    shipped = yaml.safe_load((REPO / TRAEFIK_FILE).read_text())["providers"]["docker"]
    constraint = shipped["constraints"]
    expect(constraint == keycloak.LIVE_CONSTRAINTS, f"the live constraint is {constraint!r}")
    found = LIVE_NAME_CONSTRAINT.fullmatch(constraint)
    expect(found is not None, f"no edge.name pattern in {constraint!r}")
    return re.compile(found["pattern"])


def routable_by_live_edge(labels: Mapping[str, str] | None) -> bool:
    name = (labels or {}).get(EDGE_NAME_LABEL)
    return name is not None and live_routed_name().search(name) is not None


def expect_isolated(stand: CopyStand) -> str:
    """Refuses a copy whose files or resolved configuration could reach the live stack; the line
    that says what holds."""
    units = expect_files_isolated(stand)
    started = expect_resolved_isolated(stand, units)
    isolation = stand.isolation
    return (
        f"copy isolated: project {isolation.project}, edge {isolation.edge_address}, admin "
        f"{isolation.admin_url}, keycloak subnet {isolation.keycloak_subnet}, pinned "
        f"{sorted(isolation.pinned.values())}; {started} started services, none routable by the "
        "live edge, none publishing a port, only traefik on the host network, no bind or secret "
        "file outside the scratch HOME but the socket proxy's docker socket, no namespace of a "
        "container outside the copy; every fixed name and the backup records in the project"
    )


def copy_texts(stand: CopyStand) -> dict[str, str]:
    return {name: (stand.copy / name).read_text() for name in REWRITES}


def expect_files_isolated(stand: CopyStand) -> frozenset[str]:
    """`expect_texts_isolated` over the copy's files as they are now."""
    return expect_texts_isolated(copy_texts(stand), stand)


def expect_texts_isolated(texts: Mapping[str, str], stand: CopyStand) -> frozenset[str]:
    """Refuses the copy's rewritten files, by name, when one could reach the live stack; the units
    its fleet.yaml switches on."""
    isolation = stand.isolation
    for name in (COMPOSE_FILE, TRAEFIK_FILE):
        live = [address for address in keycloak.LIVE_GO_LIVE_ADDRESSES if address in texts[name]]
        expect(not live, f"the copy's {name} names the live {live}")
    project = yaml.safe_load(texts[COMPOSE_FILE]).get("name")
    expect(project == isolation.project, f"the copy's {COMPOSE_FILE} names project {project!r}")
    expect_traefik_isolated(texts[TRAEFIK_FILE], isolation)
    addresses = GO_LIVE_ADDRESS.finditer(texts[GO_LIVE_FILE])
    found = {match["constant"]: match["value"] for match in addresses}
    expect(found == go_live_addresses(isolation), f"the copy's go-live reaches {found}")
    projects = {app.compose_project for app in parse_apps(texts[APPS_FILE])}
    expect(projects <= {isolation.project}, f"the copy's backup records name {projects}")
    return expect_fleet_isolated(texts[FLEET_FILE], stand)


def expect_traefik_isolated(text: str, isolation: Isolation) -> None:
    traefik = yaml.safe_load(text)
    addresses = sorted(entry["address"] for entry in traefik["entryPoints"].values())
    wanted = sorted((isolation.edge_address, isolation.admin_address))
    expect(addresses == wanted, f"the copy's Traefik listens on {addresses}, not {wanted}")
    constraint = traefik["providers"]["docker"]["constraints"]
    expect(constraint == isolation.constraint, f"the copy's Traefik routes {constraint!r}")


def expect_apps_in_project(keys: Iterable[str], project: str) -> None:
    """An app's key is its compose project: refuses one outside the copy's (a live app's)."""
    foreign = sorted(key for key in keys if not key.startswith(f"{project}-"))
    expect(not foreign, f"apps outside the project {project}: {foreign}")


def expect_fleet_isolated(text: str, stand: CopyStand) -> frozenset[str]:
    """The units fleet.yaml `text` switches on, read as hal reads it, once they are the stand's and
    its apps are exactly the caller's, each under the copy's project."""
    fleet, what = stand.fleet, f"the copy's {FLEET_FILE}"
    supplied = fleet.apps()
    expect_apps_in_project(supplied, stand.isolation.project)
    services = fleet_services(text, what)
    enabled = frozenset(
        key
        for key, entry in services.items()
        if isinstance(entry, dict) and not catalog.is_app(entry)
        and (entry.get("run") or {}).get("enabled")
    )  # fmt: skip
    expect(enabled == fleet.units_on, f"{what} switches on {sorted(enabled)}")
    apps = {key: entry for key, entry in services.items() if catalog.is_app(entry)}
    expect(apps == supplied, f"{what} has the apps {sorted(apps)}, not {sorted(supplied)}")
    return enabled


def resolution(stand: CopyStand, prefix: Sequence[str]) -> dict[str, Any]:
    """What compose resolves for `prefix` (its files and profiles, no verb) with every profile."""
    command = [*prefix, "--profile", "*", "config", "--format", "json"]
    return json.loads(run_checked(command, stand.environment))


def expect_resolved_isolated(stand: CopyStand, units: frozenset[str]) -> int:
    """The number of services `hal apply` starts from the copy's own compose.yaml with the fleet's
    `units` on, once their resolved configuration is checked."""
    prefix = edge_copy.copy_compose_prefix(stand.copy)
    stand.guard.expect(edge_copy.copy_compose_command(stand.copy), once=False)
    resolved = resolution(stand, prefix)
    started = expect_started_isolated(resolved, stand, units | {go_live.APPLY_PROFILE})
    expect_keycloak_moved(resolved, stand.isolation)
    return len(started)


def starting_verb(command: Sequence[str]) -> int | None:
    return next((index for index, word in enumerate(command) if word in STARTING_VERBS), None)


def expect_call_isolated(stand: CopyStand, command: Sequence[str]) -> None:
    """Refuses a compose `command` that starts something when what it starts, in the configuration
    its own files merge to (an overlay included), could reach the live stack."""
    verb = starting_verb(command)
    if verb is not None:
        expect_command_isolated(resolution(stand, command[:verb]), stand, command, verb)


def expect_command_isolated(
    resolved: Mapping[str, Any], stand: CopyStand, command: Sequence[str], verb: int
) -> None:
    """`expect_started_isolated` for the services `command` starts: those of its profiles and each
    one it names after its `verb`."""
    prefix = command[:verb]
    profiles = {prefix[index + 1] for index, word in enumerate(prefix[:-1]) if word == "--profile"}
    expect_started_isolated(resolved, stand, profiles, command[verb + 1 :])


def started_services(
    services: Mapping[str, Any], profiles: set[str], targets: Sequence[str] = ()
) -> dict[str, Any]:
    """The services a call with `profiles` that names `targets` starts: those of no profile or one
    of `profiles` (all for `*`), each it names, and what they depend on."""
    every = "*" in profiles
    names = {
        name
        for name, service in services.items()
        if every or not service.get("profiles") or set(service["profiles"]) & profiles
    }
    names |= {word for word in targets if word in services}
    pending = list(names)
    while pending:
        for dependency in services[pending.pop()].get("depends_on") or {}:
            if dependency not in names:
                names.add(dependency)
                pending.append(dependency)
    return {name: services[name] for name in names}


def expect_started_isolated(
    resolved: Mapping[str, Any], stand: CopyStand, profiles: set[str],
    targets: Sequence[str] = (),
) -> dict[str, Any]:  # fmt: skip
    """Refuses a resolved configuration whose started services could reach the live stack; those
    services."""
    started = started_services(resolved["services"], profiles, targets)
    routable = sorted(n for n, s in started.items() if routable_by_live_edge(s.get("labels")))
    expect(not routable, f"the live Traefik would route {routable}")
    published = sorted(name for name, service in started.items() if service.get("ports"))
    expect(not published, f"{published} publish a host port")
    on_host = {n for n, s in started.items() if s.get("network_mode") == HOST_NAMESPACE}
    expect(on_host <= {TRAEFIK_SERVICE}, f"{sorted(on_host)} run on the host network")
    expect_sources_in_scratch(resolved, started, stand.home)
    expect_namespaces_in_project(started, resolved["services"], stand.isolation.project)
    subnets = {
        config["subnet"]
        for network in (resolved.get("networks") or {}).values()
        for config in (network.get("ipam") or {}).get("config") or []
    }
    outside = subnets - stand.isolation.subnets
    expect(not outside, f"subnets not the copy's: {sorted(outside)}")
    return started


def outside(path: str, root: Path) -> bool:
    return not Path(path).resolve().is_relative_to(root)


def expect_sources_in_scratch(
    resolved: Mapping[str, Any], started: Mapping[str, Any], home: Path
) -> None:
    """Refuses a bind of a started service and a secret or config file outside the scratch HOME,
    but the socket proxy's docker socket."""
    root = home.resolve()
    binds = sorted(
        f"{name}: {mount.get('source')}"
        for name, service in started.items()
        for mount in service.get("volumes") or []
        if mount.get("type") == "bind"
        and (name, mount.get("source")) != DOCKER_SOCKET_BIND
        and outside(mount.get("source") or "", root)
    )
    expect(not binds, f"binds outside the scratch HOME: {binds}")
    files = sorted(
        f"{section}.{key}: {entry['file']}"
        for section in FILE_SOURCES
        for key, entry in (resolved.get(section) or {}).items()
        if "file" in entry and outside(entry["file"], root)
    )
    expect(not files, f"files outside the scratch HOME: {files}")


def foreign_namespace(key: str, mode: str, services: Mapping[str, Any]) -> bool:
    """A namespace mode that joins a container outside the copy's services, or the host's
    process or IPC namespace (the host network is checked apart)."""
    if mode.startswith(SERVICE_REFERENCE):
        return mode.removeprefix(SERVICE_REFERENCE) not in services
    return mode.startswith(FOREIGN_CONTAINER) or (key != "network_mode" and mode == HOST_NAMESPACE)


def expect_namespaces_in_project(
    started: Mapping[str, Any], services: Mapping[str, Any], project: str
) -> None:
    """Refuses a started service that joins the namespace or takes the volumes of a container
    outside the copy's services, or has a fixed container name outside the project."""
    foreign = []
    for name, service in started.items():
        foreign += [
            f"{name}.{key}: {service[key]}"
            for key in NAMESPACE_KEYS
            if foreign_namespace(key, service.get(key) or "", services)
        ]
        foreign += [
            f"{name}.volumes_from: {source}"
            for source in service.get("volumes_from") or []
            if source.startswith(FOREIGN_CONTAINER) or source.partition(":")[0] not in services
        ]
        fixed = service.get("container_name")
        if fixed is not None and not fixed.startswith(f"{project}-"):
            foreign.append(f"{name}.container_name: {fixed}")
    expect(not foreign, f"outside the copy: {foreign}")


def expect_keycloak_moved(resolved: Mapping[str, Any], isolation: Isolation) -> None:
    services = resolved["services"]
    keycloak_service = services[KEYCLOAK_SERVICE]
    trusted = keycloak_service["environment"][TRUSTED_ADDRESSES]
    expect(trusted == isolation.keycloak_subnet, f"Keycloak trusts {trusted}")
    for name in (KEYCLOAK_SERVICE, CONFIG_CLI):
        admin = services[name]["environment"][ADMIN_HOSTNAME]
        expect(admin == isolation.admin_url, f"{name}'s admin front end is {admin}")
    name = keycloak_service["labels"][EDGE_NAME_LABEL]
    expect(name == SCRATCH_EDGE_NAME, f"Keycloak's {EDGE_NAME_LABEL} is {name!r}")
    network = resolved["networks"][REALM_UNIT]["ipam"]["config"][0]["subnet"]
    expect(network == isolation.keycloak_subnet, f"the keycloak network is on {network}")


def compose_prefix(stand: CopyStand, *, bootstrap: bool = False) -> list[str]:
    """Compose in the copy, with go-live's bootstrap overlay when `bootstrap`."""
    command = edge_copy.copy_compose_prefix(stand.copy)
    if bootstrap:
        command += ["--file", str(stand.copy / go_live.BOOTSTRAP_OVERLAY)]
    return command


def removed_whatever_fails(down: Callable[[], object], sweep: Callable[[], object]) -> None:
    """`down`, then `sweep` even when `down` raised, whose error then propagates: a copy whose files
    cannot be read or are no longer isolated is still removed by its labels, before the scratch
    that holds them is emptied."""
    try:
        down()
    finally:
        sweep()


@dataclass(frozen=True)
class Refusal:
    """A negative case: `check` raises ProbeFailed while the guard it names holds."""

    case: str
    check: Callable[[], object]


def expect_guards_refuse(stand: CopyStand, bootstrap_start: Sequence[str]) -> int:
    """Every negative case refused, before anything of the copy starts, one line each; a case a
    guard accepts stops the probe. `bootstrap_start` is the compose call that starts Keycloak with
    go-live's overlay. The number of cases."""
    refusals = [*file_refusals(stand), *start_refusals(stand, bootstrap_start)]
    for refusal in refusals:
        try:
            refusal.check()
        except ProbeFailed as failure:
            write_line(f"self-check: {refusal.case} refused: {failure}", flush=True)
        else:
            raise ProbeFailed(f"self-check: {refusal.case} was accepted")
    for line in (canonical_install_line(stand), teardown_sweep_line(stand)):
        write_line(line, flush=True)
    return len(refusals) + 2


def file_refusals(stand: CopyStand) -> list[Refusal]:
    """The copy's files, changed in memory to name the live project, enable a unit the stand has
    off or add a live app, each refused by the recheck; a fleet entry of a live app and an install
    path that leaves the copy, each refused by the install. The unchanged files pass first, so
    each refusal is the change's."""
    texts, units_on, other = copy_texts(stand), stand.fleet.units_on, "legal"
    expect_texts_isolated(texts, stand)
    expect(other not in units_on, f"self-check: {other} is a unit the stand has on")
    switched = UNIT_SWITCH.sub(
        lambda found: f"{found[1]}{str(found['unit'] in {*units_on, other}).lower()}",
        texts[FLEET_FILE],
    )
    live_app = keycloak.HOPIN.client_id
    entry = f"  {live_app}:\n    repo: {{}}\n    run:\n      enabled: true\n"
    with_live_app = replace(stand, fleet=replace(stand.fleet, app_entries=entry))
    changed = {
        f"a {COMPOSE_FILE} naming the live project": {
            COMPOSE_FILE: TOP_LEVEL_NAME.sub(rf"\g<1>{live_project_name()}", texts[COMPOSE_FILE])
        },
        f"a raw {FLEET_FILE} enabling {other}": {FLEET_FILE: switched},
        f"a raw {FLEET_FILE} with the app {live_app}": {FLEET_FILE: texts[FLEET_FILE] + entry},
    }
    return [
        *(
            Refusal(case, functools.partial(expect_texts_isolated, {**texts, **change}, stand))
            for case, change in changed.items()
        ),
        Refusal(f"the app key {live_app}", lambda: probe_fleet(texts[FLEET_FILE], with_live_app)),
        *(
            Refusal(f"the install path {path}", functools.partial(installed_name, stand, path))
            for path in ("/etc/hal.yaml", f"../{FLEET_FILE}")
        ),
    ]


def with_keycloak(resolved: Mapping[str, Any], **changes: object) -> dict[str, Any]:
    """A deep copy of `resolved` whose keycloak service takes `changes`."""
    changed = deepcopy(dict(resolved))
    changed["services"][KEYCLOAK_SERVICE].update(changes)
    return changed


def start_refusals(stand: CopyStand, bootstrap_start: Sequence[str]) -> list[Refusal]:
    """The bootstrap start's real merged configuration, changed in memory as an overlay or a raw
    file could change it, each refused by the check the start runs."""
    verb = starting_verb(bootstrap_start)
    expect(verb is not None, f"self-check: {bootstrap_start} starts nothing")
    merged = resolution(stand, bootstrap_start[:verb])
    expect_command_isolated(merged, stand, bootstrap_start, verb)  # the change is what is refused
    keycloak_service = merged["services"][KEYCLOAK_SERVICE]
    labels = keycloak_service.get("labels") or {}
    live_name = yaml.safe_load((REPO / COMPOSE_FILE).read_text())["services"][KEYCLOAK_SERVICE]
    live_name = live_name["labels"][EDGE_NAME_LABEL]
    live_container = f"{FOREIGN_CONTAINER}{live_project_name()}-{TRAEFIK_SERVICE}-1"
    live_bind = {"type": "bind", "source": str(REPO), "target": "/opt/live"}
    secret = next(iter(merged["secrets"]))
    live_secret = deepcopy(dict(merged))
    live_secret["secrets"][secret]["file"] = str(REPO / COMPOSE_FILE)
    cases = {
        f"an overlay setting keycloak's {EDGE_NAME_LABEL} {live_name}":
            with_keycloak(merged, labels={**labels, EDGE_NAME_LABEL: live_name}),
        "an overlay publishing a keycloak port":
            with_keycloak(merged, ports=[{"target": 8080, "published": "8080"}]),
        "an overlay putting keycloak on the host network":
            with_keycloak(merged, network_mode=HOST_NAMESPACE),
        f"a bind of {REPO} outside the scratch HOME":
            with_keycloak(merged, volumes=[*keycloak_service.get("volumes", []), live_bind]),
        f"the secret file {REPO / COMPOSE_FILE}": live_secret,
        f"network_mode {live_container}": with_keycloak(merged, network_mode=live_container),
        f"pid {live_container}": with_keycloak(merged, pid=live_container),
        "ipc host": with_keycloak(merged, ipc=HOST_NAMESPACE),
        f"volumes_from {live_container}": with_keycloak(merged, volumes_from=[live_container]),
        f"the container_name {live_project_name()}-{KEYCLOAK_SERVICE}":
            with_keycloak(merged, container_name=f"{live_project_name()}-{KEYCLOAK_SERVICE}"),
    }  # fmt: skip
    check = functools.partial(expect_command_isolated, stand=stand, command=bootstrap_start)
    return [
        Refusal(case, functools.partial(check, changed, verb=verb))
        for case, changed in cases.items()
    ]


def canonical_install_line(stand: CopyStand) -> str:
    """`./fleet.yaml` and `a/../fleet.yaml` install as fleet.yaml, through its rewrite: the shipped
    fleet, which switches on more units, is written with the stand's alone."""
    aliases = (f"./{FLEET_FILE}", f"a/../{FLEET_FILE}")
    names = {installed_name(stand, alias) for alias in aliases}
    expect(names == {FLEET_FILE}, f"self-check: {aliases} install as {sorted(names)}")
    shipped = (REPO / FLEET_FILE).read_text()
    shipped_on = {
        found["unit"] for found in UNIT_SWITCH.finditer(shipped) if found[0].endswith("true")
    }
    written = expect_fleet_isolated(REWRITES[names.pop()](shipped, stand), stand)
    return (
        f"self-check: {' and '.join(aliases)} install as {FLEET_FILE}, through its rewrite: the "
        f"shipped fleet with {sorted(shipped_on)} on is written with {sorted(written)} on"
    )


def teardown_sweep_line(stand: CopyStand) -> str:
    """A copy whose files are missing at the teardown: the label sweep runs, and the read's error
    still stops the teardown."""
    swept: list[bool] = []
    missing = replace(stand, copy=stand.copy / "missing")
    try:
        removed_whatever_fails(lambda: expect_isolated(missing), lambda: swept.append(True))
    except OSError as failure:
        expect(bool(swept), "self-check: a missing copy file skipped the label sweep")
        return (
            f"self-check: a missing copy file at the teardown: the label sweep ran, then "
            f"{type(failure).__name__} stopped the teardown"
        )
    raise ProbeFailed("self-check: a missing copy file at the teardown raised nothing")
