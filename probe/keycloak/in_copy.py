"""Probe that brings Keycloak and step-ca up in an edge copy through `hal apply --local` (#1030
cells H1-H6), beside the live stack and isolated from it, so later probes drive Keycloak changes
through hal itself.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/keycloak/in_copy.py --scratch DIR

The copy is edge_copy's, under the project `edge-kc-in-copy`. `install` is the one way a file
set enters it: each file is rewritten under the copy's one allocation (`Isolation`, see `REWRITES`),
the copy is published and its resolved configuration checked (`expect_isolated`), which `apply` and
the teardown check again before they act. Every request of probe.py's reused helpers goes to the
copy's two entrypoints or is refused before it leaves (`ScratchOnlyHttp`). Keycloak is bootstrapped
as go-live does it, never by running go-live (`KeycloakCopy.bootstrap`), and the copy's
`keycloak/go-live --check` must exit 0 before the first `hal apply`. Exit 0: every cell held.
"""

from __future__ import annotations

import base64
import functools
import grp
import hashlib
import importlib.machinery
import importlib.util
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlsplit

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "probe"), str(REPO / "src")]  # also when loaded by path

import edge_copy  # noqa: E402
from edge_copy import HAL_OK, NOTHING_TO_CHANGE, ProbeFailed, expect  # noqa: E402

from hal.backup.apps import parse_apps  # noqa: E402
from hal.backup.cli import DEFAULT_APPS  # noqa: E402
from hal.backup.docker import PROJECT_LABEL  # noqa: E402
from hal.backup.settings import Settings  # noqa: E402
from hal.exposure.docker import EDGE_NAME_LABEL  # noqa: E402
from hal.output import write_line  # noqa: E402
from hal.stack import barrier, catalog, compose, deploy_checkout  # noqa: E402
from hal.stack.realm.reconcile import CONFIG_CLI, KEYCLOAK_SERVICE, REALM_UNIT  # noqa: E402
from hal.stack.result_rows import ResultEvent  # noqa: E402


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

PROJECT = "edge-kc-in-copy"
# Upper case: the live constraint's LabelRegex refuses it, so the live Traefik never routes the
# copy's Keycloak; the copy's Traefik routes by the project label instead.
SCRATCH_EDGE_NAME = "PROBE"
COMPOSE_FILE = deploy_checkout.COMPOSE_FILE
TRAEFIK_FILE = barrier.TRAEFIK_FILE
FLEET_FILE = catalog.FLEET_FILE
APPS_FILE = str(DEFAULT_APPS.relative_to(compose.REPOSITORY))
SHIPPED_FLEET = catalog.parse((REPO / FLEET_FILE).read_bytes())["services"]
STEP_CA_UNIT = "step-ca"
GO_LIVE_FILE = SHIPPED_FLEET[REALM_UNIT]["run"]["setup"]
STEP_CA_SETUP = SHIPPED_FLEET[STEP_CA_UNIT]["run"]["setup"]
TRAEFIK_SERVICE = "traefik"  # the one service on the host network: its addresses are traefik.yml's
CORE_SERVICES = ("socket-proxy", TRAEFIK_SERVICE)
KEYCLOAK_DATABASE = "keycloak-db"
# go-live's main() and compose.yaml's secrets: name this folder under HOME
KEYCLOAK_SECRETS = Path(".secrets") / REALM_UNIT
KEYCLOAK_PROFILE = ("--profile", go_live.KEYCLOAK_PROFILE)
TRUSTED_ADDRESSES = "KC_PROXY_TRUSTED_ADDRESSES"  # Keycloak's setting, compose.yaml's anchor
ADMIN_HOSTNAME = "KC_HOSTNAME_ADMIN"
KEYCLOAK_SUBNET_ANCHOR = re.compile(r"(&keycloak-subnet )(\S+)")
ADMIN_HOSTNAME_ANCHOR = re.compile(r"(&admin-hostname )(\S+)")
GO_LIVE_ADDRESS = re.compile(r'^(?P<constant>ADMIN_URL|EDGE_URL) = "(?P<value>[^"]*)"$', re.M)
UNIT_SWITCH = re.compile(r"^( {2}(?P<unit>[\w-]+):\n {4}run:\n {6}enabled: )(?:true|false)$", re.M)
LIVE_NAME_CONSTRAINT = re.compile(r"LabelRegex\(`edge\.name`, `(?P<pattern>[^`]+)`\)")
REALM_APPLIED = re.compile(
    rf"{REALM_UNIT}\s+{ResultEvent.REALM_APPLIED}\b.*?snapshot (?P<snapshot>\S+) proven"
)
YES_PROMPT = "Type yes"
COMPOSE_SECONDS = 900
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
    file names, and the caller's `app_entries` appended under `services` as written."""

    units_on: frozenset[str]
    app_entries: str = ""


@dataclass(frozen=True)
class CopyStand:
    """One isolated copy: where it is, its allocation and fleet, the guard of its compose calls
    and the environment every command in it runs with."""

    copy: Path
    isolation: Isolation
    fleet: Fleet
    guard: edge_copy.NetworkGuard
    environment: Mapping[str, str]


def replaced_once(text: str, pattern: re.Pattern[str], value: str, file: str) -> str:
    """`text` with the one match of `pattern` keeping its first group and taking `value`."""
    moved, count = pattern.subn(lambda found: f"{found[1]}{value}", text)
    expect(count == 1, f"{file} holds {pattern.pattern!r} {count} times, not once")
    return moved


def literal_replaced_once(text: str, old: str, new: str, file: str) -> str:
    expect(text.count(old) == 1, f"{file} holds {old!r} {text.count(old)} times, not once")
    return text.replace(old, new)


def isolated_compose(text: str, stand: CopyStand) -> str:
    isolation = stand.isolation
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
    try:
        services = catalog.parse(result.encode())["services"]
    except catalog.CatalogError as error:
        raise ProbeFailed(f"the copy's {FLEET_FILE} does not parse: {error}") from error
    enabled = {
        key
        for key, entry in services.items()
        if not catalog.is_app(entry) and (entry.get("run") or {}).get("enabled")
    }
    expect(enabled == fleet.units_on, f"the copy's {FLEET_FILE} switches on {sorted(enabled)}")
    return result


def backup_records(text: str, stand: CopyStand) -> str:
    live = edge_copy.compose_project_name((REPO / COMPOSE_FILE).read_text())
    return edge_copy.backup_records_at_project(text, stand.isolation.project, live)


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


def install(stand: CopyStand, files: Mapping[str, str | None], message: str) -> str:
    """Installs a file set into the copy and returns `expect_isolated`'s line: each file is written
    under the copy's allocation (a rewrite of `REWRITES` first, the others as given; an existing
    file keeps its mode), a None removes it, so a file only a candidate has is absent at base and
    gone on revert. The copy is published and its isolation checked again before anything runs."""
    for name, text in files.items():
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


def run_checked(
    command: list[str], environment: Mapping[str, str], *, cwd: Path | None = None,
    timeout: int = SHORT_SECONDS,
) -> str:  # fmt: skip
    result = edge_copy.run_command(command, text=True, env=environment, cwd=cwd, timeout=timeout)
    tail = compose.last_line(result.stderr or result.stdout)
    expect(result.returncode == 0, f"{shlex.join(command[:6])} exited {result.returncode}: {tail}")
    return result.stdout


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
    expect_files_isolated(stand)
    started = expect_resolved_isolated(stand)
    isolation = stand.isolation
    return (
        f"copy isolated: project {isolation.project}, edge {isolation.edge_address}, admin "
        f"{isolation.admin_url}, keycloak subnet {isolation.keycloak_subnet}, pinned "
        f"{sorted(isolation.pinned.values())}; {started} started services, none routable by the "
        "live edge, none publishing a port, only traefik on the host network; every fixed name "
        "and the backup records in the project"
    )


def expect_files_isolated(stand: CopyStand) -> None:
    copy, isolation = stand.copy, stand.isolation
    for name in (COMPOSE_FILE, TRAEFIK_FILE):
        text = (copy / name).read_text()
        live = [address for address in keycloak.LIVE_GO_LIVE_ADDRESSES if address in text]
        expect(not live, f"the copy's {name} names the live {live}")
    traefik = yaml.safe_load((copy / TRAEFIK_FILE).read_text())
    addresses = sorted(entry["address"] for entry in traefik["entryPoints"].values())
    wanted = sorted((isolation.edge_address, isolation.admin_address))
    expect(addresses == wanted, f"the copy's Traefik listens on {addresses}, not {wanted}")
    constraint = traefik["providers"]["docker"]["constraints"]
    expect(constraint == isolation.constraint, f"the copy's Traefik routes {constraint!r}")
    found = {
        match["constant"]: match["value"]
        for match in GO_LIVE_ADDRESS.finditer((copy / GO_LIVE_FILE).read_text())
    }
    expect(found == go_live_addresses(isolation), f"the copy's go-live reaches {found}")
    projects = {app.compose_project for app in parse_apps((copy / APPS_FILE).read_text())}
    expect(projects <= {isolation.project}, f"the copy's backup records name {projects}")


def expect_resolved_isolated(stand: CopyStand) -> int:
    """The number of services the fleet starts, once their resolved configuration is checked."""
    command = edge_copy.copy_compose_command(stand.copy)
    stand.guard.expect(command, once=False)
    resolved = json.loads(run_checked([*command, "config", "--format", "json"], stand.environment))
    profiles = stand.fleet.units_on | {go_live.APPLY_PROFILE}
    started = {
        name: service
        for name, service in resolved["services"].items()
        if not service.get("profiles") or set(service["profiles"]) & profiles
    }
    routable = sorted(n for n, s in started.items() if routable_by_live_edge(s.get("labels")))
    expect(not routable, f"the live Traefik would route {routable}")
    published = sorted(name for name, service in started.items() if service.get("ports"))
    expect(not published, f"{published} publish a host port")
    on_host = {name for name, s in started.items() if s.get("network_mode") == "host"}
    expect(on_host <= {TRAEFIK_SERVICE}, f"{sorted(on_host)} run on the host network")
    expect_keycloak_moved(resolved, stand.isolation)
    return len(started)


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
    subnets = {
        config["subnet"]
        for network in resolved["networks"].values()
        for config in (network.get("ipam") or {}).get("config") or []
    }
    expect(subnets <= isolation.subnets, f"subnets not the copy's: {subnets - isolation.subnets}")
    network = resolved["networks"][REALM_UNIT]["ipam"]["config"][0]["subnet"]
    expect(network == isolation.keycloak_subnet, f"the keycloak network is on {network}")


def apply(stand: CopyStand, *, exit_code: int = HAL_OK, typed: bytes = b"yes\n") -> str:
    """`hal apply --local` in the copy at a pty, once the copy is checked isolated again."""
    expect_isolated(stand)
    return edge_copy.run_hal(
        stand.copy, stand.environment, "apply", "--local", terminal=True, exit_code=exit_code,
        typed=typed,
    )  # fmt: skip


class ScratchOnlyHttp:
    """Stands in for probe.py's `http`, through which every request of its helpers goes: a request
    to any address but the copy's two entrypoints is refused before it is sent."""

    def __init__(self, module: ModuleType, allowed: frozenset[str]) -> None:
        self.send, self.allowed, self.sent = module.http, allowed, 0
        module.http = self

    def __call__(self, method: str, url: str, **kwargs: Any) -> Any:
        netloc = urlsplit(url).netloc
        expect(netloc in self.allowed, f"a request to {netloc} is not to the copy: {method} {url}")
        self.sent += 1
        return self.send(method, url, **kwargs)


def scratch_environment(home: Path) -> dict[str, str]:
    """What every command of the copy runs with: the scratch HOME, the probe's project, no Compose
    setting inherited from the shell and no browser."""
    inherited = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("COMPOSE_")
        and key not in {"DISPLAY", "WAYLAND_DISPLAY", "DOCKER_STEPCA_INIT_PASSWORD"}
    }
    return {
        **inherited, "HOME": str(home), "COMPOSE_PROJECT_NAME": PROJECT, "BROWSER": "true",
        "EDGE_DOMAIN": keycloak.DOMAIN,
        "DOCKER_GID": os.environ.get("DOCKER_GID") or str(grp.getgrnam("docker").gr_gid),
    }  # fmt: skip


def write_secret(home: Path, relative: Path, value: str, mode: int = 0o644) -> None:
    """A new file at `relative` under `home`, as go-live writes one: in 0700 folders."""
    folder = home
    for part in relative.parent.parts:
        folder /= part
        folder.mkdir(mode=0o700, exist_ok=True)
    descriptor = os.open(home / relative, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "w") as file:
        file.write(value)


def live_network_ids() -> set[str]:
    listing = run_checked(["docker", "network", "ls", "--format", "{{.Name}} {{.ID}}"], os.environ)
    return {line for line in listing.splitlines() if line.startswith(edge_copy.LIVE_NETWORK_PREFIX)}


def key_id(token: str) -> str:
    header = token.split(".")[0]
    return json.loads(base64.urlsafe_b64decode(header + "=" * (-len(header) % 4)))["kid"]


def project_resources(kind: str) -> list[str]:
    """The containers (any state), networks or volumes that carry the probe's project label."""
    every = ["--all"] if kind == "container" else []
    listing = run_checked(
        ["docker", kind, "ls", *every, "--quiet", "--filter", f"label={PROJECT_LABEL}={PROJECT}"],
        os.environ,
    )
    return listing.split()


class KeycloakCopy:
    """Keycloak and step-ca brought up in an isolated edge copy through `hal apply --local`; the
    stand a later probe drives its own installs and applies on."""

    def __init__(self, scratch: Path) -> None:
        self.scratch, self.home = scratch, scratch / "home"
        self.home.mkdir(mode=0o700)
        self.environment = scratch_environment(self.home)
        self.live_before = edge_copy.live_project(REPO)
        self.live_networks_before = live_network_ids()
        self.guard = edge_copy.NetworkGuard(
            PROJECT, lambda command: run_checked(command, self.environment)
        )
        self.stand: CopyStand | None = None
        self.http: ScratchOnlyHttp | None = None
        self.kc: Any = None
        self.inspected: list[str] = []  # the moments every container was looked at

    @property
    def secrets_dir(self) -> Path:
        return self.home / KEYCLOAK_SECRETS

    def secret(self, name: str) -> str:
        return (self.secrets_dir / name).read_text()

    def prepare(self, fleet: Fleet) -> str:
        """The copy, its allocation, its first install and its scratch secrets; the install's
        line."""
        copy = edge_copy.repository_copy(REPO, self.home, self.scratch, PROJECT)
        isolation = Isolation.allocate(PROJECT, (REPO / COMPOSE_FILE).read_text())
        self.stand = CopyStand(copy, isolation, fleet, self.guard, self.environment)
        self.http = ScratchOnlyHttp(keycloak, isolation.netlocs)
        # probe.py's helpers read edge_url, admin_url and master_token_url of their stack
        self.kc = keycloak.Probe(isolation)
        line = install(self.stand, shipped_files(REPO), "probe: Keycloak isolated in the copy")
        self.write_keycloak_secrets()
        self.guard.expect([*edge_copy.copy_compose_prefix(copy), "--profile", STEP_CA_UNIT])
        run_checked([str(copy / STEP_CA_SETUP)], self.environment, cwd=copy, timeout=600)
        settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        password = settings.password_file.relative_to(self.home)
        write_secret(self.home, password, secrets.token_urlsafe(32), mode=0o600)
        edge_copy.run_hal(copy, self.environment, "backup", "--init", terminal=True)
        return line

    def compose(
        self, *arguments: str, bootstrap: bool = False, timeout: int = SHORT_SECONDS
    ) -> str:
        """Compose in the copy, with go-live's bootstrap overlay when `bootstrap`; a call that
        starts or removes something is checked by the guard first."""
        command = edge_copy.copy_compose_prefix(self.stand.copy)
        if bootstrap:
            command += ["--file", str(self.stand.copy / go_live.BOOTSTRAP_OVERLAY)]
        command += arguments
        self.guard.expect_call(command)
        return run_checked(command, self.environment, timeout=timeout)

    def write_keycloak_secrets(self) -> None:
        """go-live's three files and one per client the copy's resolved configuration names."""
        relative = self.secrets_dir.relative_to(self.home)
        for name in go_live.SECRET_FILES:
            write_secret(self.home, relative / name, go_live.new_secret_value())
        resolved = json.loads(
            self.compose(*KEYCLOAK_PROFILE, "--profile", go_live.APPLY_PROFILE, "config",
                         "--format", "json")
        )  # fmt: skip
        prefix = f"{self.secrets_dir / go_live.CLIENT_SECRETS_DIR}/"
        files = [entry.get("file", "") for entry in resolved["secrets"].values()]
        clients = [file.removeprefix(prefix) for file in files if file.startswith(prefix)]
        expect(keycloak.HOPIN.client_id in clients, f"the copy names the clients {clients}")
        for client in clients:
            path = relative / go_live.CLIENT_SECRETS_DIR / client
            write_secret(self.home, path, go_live.new_secret_value())

    def bootstrap(self) -> Any:
        """go-live's steps 3 to 5 and 7 on the copy, never go-live itself; the config-cli admin."""
        self.compose(*KEYCLOAK_PROFILE, "up", "--detach", "--wait", KEYCLOAK_SERVICE,
                     bootstrap=True, timeout=COMPOSE_SECONDS)  # fmt: skip
        self.compose("up", "--detach", "--wait", *CORE_SERVICES, timeout=COMPOSE_SECONDS)
        self.expect_hidden_from_live_edge("the bootstrap start")
        keycloak.wait_until_ready(self.stand.isolation.admin_url)
        overlay = (self.stand.copy / go_live.BOOTSTRAP_OVERLAY).read_text()
        script = re.search(r":(/\S+/admin-frontend\.sh):ro", overlay)
        expect(script is not None, f"{go_live.BOOTSTRAP_OVERLAY} mounts no admin-frontend.sh")
        self.compose(*KEYCLOAK_PROFILE, "exec", "-T", KEYCLOAK_SERVICE, script[1], bootstrap=True)
        self.compose(*KEYCLOAK_PROFILE, "run", "--rm", "--no-deps", CONFIG_CLI, bootstrap=True,
                     timeout=COMPOSE_SECONDS)  # fmt: skip
        admin = self.kc.admin_with_client(self.secret("config-cli-secret"))
        realm = admin.get(f"/{keycloak.REALM}")["realm"]
        expect(realm == keycloak.REALM, f"the realm {keycloak.REALM} is {realm!r}")
        self.retire_bootstrap_admin(admin)
        self.compose(*KEYCLOAK_PROFILE, "rm", "--stop", "--force", KEYCLOAK_SERVICE,
                     KEYCLOAK_DATABASE)  # fmt: skip
        return admin

    def retire_bootstrap_admin(self, admin: Any) -> None:
        listing = f"/master/users?username={go_live.BOOTSTRAP_ADMIN}&exact=true"
        for user in admin.get(listing):
            admin.must("DELETE", f"/master/users/{user['id']}")
        expect(not admin.get(listing), f"{go_live.BOOTSTRAP_ADMIN} is still in master")
        (self.secrets_dir / go_live.BOOTSTRAP_SECRET).unlink()

    def gate(self) -> str:
        """The copy's `keycloak/go-live --check` under the scratch environment: its line once it
        exits 0. It only reads files and compose's configuration."""
        copy = self.stand.copy
        self.guard.expect([*edge_copy.copy_compose_prefix(copy), *KEYCLOAK_PROFILE])
        result = edge_copy.run_command(
            [str(copy / GO_LIVE_FILE), "--check"], text=True, env=self.environment, cwd=copy,
            timeout=SHORT_SECONDS,
        )  # fmt: skip
        line = compose.last_line(result.stdout + result.stderr)
        expect(result.returncode == 0, f"go-live --check exited {result.returncode}: {line}")
        return line

    def running(self) -> set[str]:
        listed = self.compose("--profile", "*", "ps", "--status", "running", "--services")
        return set(listed.split())

    def expect_hidden_from_live_edge(self, moment: str) -> None:
        """Every container of the project, in any state, carries no `edge.name` the live
        constraint accepts, so the live Traefik never takes one as a server."""
        containers = project_resources("container")
        if containers:
            inspected = run_checked(
                ["docker", "container", "inspect", "--format", "{{json .Config.Labels}}",
                 *containers], os.environ,
            )  # fmt: skip
            routable = [labels for labels in map(json.loads, inspected.splitlines())
                        if routable_by_live_edge(labels)]  # fmt: skip
            expect(not routable, f"{moment}: the live Traefik would route {routable}")
        self.inspected.append(f"{moment} ({len(containers)})")

    def tear_down(self) -> float:
        """Removes everything of the project, the copy rechecked first; the seconds it took. A copy
        that is not isolated any more is removed by its project label alone, and then refused."""
        started = time.monotonic()
        stray = project_resources("container")
        if stray:
            run_checked(["docker", "rm", "--force", *stray], os.environ, timeout=SHORT_SECONDS)
        unsafe = None
        if self.stand is not None:
            try:
                expect_isolated(self.stand)
            except ProbeFailed as failure:
                unsafe = failure
            else:
                self.compose("--profile", "*", "down", "--volumes", "--remove-orphans",
                             "--timeout", "10", timeout=COMPOSE_SECONDS)  # fmt: skip
        for kind in ("network", "volume"):
            if found := project_resources(kind):
                run_checked(["docker", kind, "rm", *found], os.environ, timeout=SHORT_SECONDS)
        named = run_checked(
            ["docker", "volume", "ls", "--quiet", "--filter", f"name={PROJECT}_"], os.environ
        ).split()
        left = [*project_resources("container"), *project_resources("volume"), *named]
        expect(not left, f"the teardown left {left}")
        self.guard.expect_clean_teardown()
        expect(unsafe is None, f"the copy was not isolated at the teardown: {unsafe}")
        expect(live_network_ids() == self.live_networks_before, "the hal_ network ids changed")
        return time.monotonic() - started


class Probe(KeycloakCopy):
    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.held: list[str] = []

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held: {how}", flush=True)
        self.held.append(cell)

    def drive(self) -> None:
        self.cell_h1()
        self.cell_h2()
        self.cell_h3()
        self.cell_h4()
        self.cell_h5()

    def cell_h1(self) -> None:
        line = self.prepare(Fleet(frozenset({REALM_UNIT, STEP_CA_UNIT})))
        first = self.rewritten_digests()
        install(self.stand, shipped_files(REPO), "probe: the shipped files installed again")
        again = self.rewritten_digests()
        changed = sorted(name for name in REWRITES if first[name] != again[name])
        expect(not changed, f"H1: a reinstall changed {changed}")
        self.hold(
            "H1",
            f"{line}; the shipped files installed again are byte-identical in "
            f"{', '.join(REWRITES)}: the same allocation",
        )

    def rewritten_digests(self) -> dict[str, str]:
        return {n: hashlib.sha256((self.stand.copy / n).read_bytes()).hexdigest() for n in REWRITES}

    def cell_h2(self) -> None:
        self.bootstrap()
        gate = self.gate()
        gone = not (self.secrets_dir / go_live.BOOTSTRAP_SECRET).exists()
        expect(gone, f"H2: {go_live.BOOTSTRAP_SECRET} is still there")
        self.hold(
            "H2",
            f"the realm {keycloak.REALM} exists, {go_live.BOOTSTRAP_ADMIN} is deleted and "
            f"{go_live.BOOTSTRAP_SECRET} gone; `{gate}`; {self.http.sent} requests, every one to "
            f"{sorted(self.stand.isolation.netlocs)}; go-live itself never ran",
        )

    def cell_h3(self) -> None:
        first = apply(self.stand)
        on = [f"{unit} is on" for unit in sorted(self.stand.fleet.units_on)]
        expect(all(line in first for line in on), f"H3: the first apply said {first[-400:]}")
        wanted = {KEYCLOAK_SERVICE, KEYCLOAK_DATABASE, STEP_CA_UNIT, *CORE_SERVICES}
        running = self.running()
        expect(wanted <= running, f"H3: running {sorted(running)}")
        self.expect_hidden_from_live_edge("the first apply")
        keycloak.wait_until_ready(self.stand.isolation.admin_url)
        realm = REALM_APPLIED.search(first)
        applies = 1
        if realm is None:
            realm, applies = REALM_APPLIED.search(second := apply(self.stand)), 2
            expect(realm is not None, f"H3: the second apply said {second[-400:]}")
        quiet = apply(self.stand)
        expect(NOTHING_TO_CHANGE in quiet and YES_PROMPT not in quiet, f"H3: then {quiet[-300:]}")
        self.expect_hidden_from_live_edge("the last apply")
        self.hold(
            "H3",
            f"{', '.join(on)}, {sorted(wanted)} run; apply {applies}: `{realm[0]}`; the next "
            f"apply: {NOTHING_TO_CHANGE}, no question",
        )

    def cell_h4(self) -> None:
        kc, hopin = self.kc, keycloak.HOPIN
        client_secret = self.secret(hopin.secret_file)
        workload = kc.tokens_from(
            f"{hopin.client_id} workload",
            kc.through_tunnel("POST", keycloak.PUBLIC_TOKEN_PATH, form={
                "grant_type": "client_credentials", "client_id": hopin.client_id,
                "client_secret": client_secret,
            }),
        )  # fmt: skip
        admin = kc.admin_with_client(self.secret("config-cli-secret"))
        username = f"probe-{hopin.client_id}-member"
        password = kc.keep_secret(f"{username} password", secrets.token_urlsafe(16))
        admin.join_group(admin.create_user(keycloak.REALM, username, password), hopin.group)
        browser = kc.browser(hopin.client_id)
        member = kc.app_client_sign_in(hopin, browser, username, password, client_secret)
        jwks = kc.through_tunnel("GET", f"{keycloak.REALM_PATH}/protocol/openid-connect/certs")
        expect(jwks.status == 200, f"H4: the key set answered {jwks.status}")
        kids = {key["kid"] for key in jwks.json()["keys"]}
        tokens = {
            "the workload access token": workload["access_token"],
            "the member's access token": member["access_token"],
            "the member's ID token": member["id_token"],
        }
        for name, token in tokens.items():
            issuer = keycloak.claims(token)["iss"]
            expect(issuer == keycloak.PUBLIC_ISSUER, f"H4: {name} has iss {issuer}")
            expect(key_id(token) in kids, f"H4: {name}'s kid is not in the copy's key set")
        self.hold(
            "H4",
            f"{', '.join(tokens)} of {hopin.client_id} (client_credentials; a member of "
            f"{hopin.group} through PKCE S256) through {self.stand.isolation.edge_url} carry iss "
            f"{keycloak.PUBLIC_ISSUER} and a kid of the copy's key set ({len(kids)} keys)",
        )

    def cell_h5(self) -> None:
        self.expect_hidden_from_live_edge("H4")
        live = edge_copy.expect_live_project_unchanged(self.live_before, REPO)
        networks = live_network_ids()
        expect(networks == self.live_networks_before, "H5: the hal_ network ids changed")
        self.hold(
            "H5",
            f"{live}; the {len(networks)} hal_ networks have their ids; every container of "
            f"{PROJECT}, inspected after {', '.join(self.inspected)}, carries no edge.name the "
            f"live constraint accepts; {self.http.sent} requests, every one to the copy",
        )

    def teardown(self) -> None:
        seconds = self.tear_down()
        live = edge_copy.expect_live_project_unchanged(self.live_before, REPO)
        self.hold("H6", f"project {PROJECT} removed in {seconds:.1f} s; {live}")


def prove(probe: Probe) -> int:
    try:
        probe.drive()
    except (ProbeFailed, keycloak.ProbeFailure, subprocess.TimeoutExpired, OSError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(
        __doc__.splitlines()[0], argv, Probe, prove,
        lambda probe: edge_copy.passed_line(f"PASSED: {', '.join(probe.held)}"),
    )  # fmt: skip


if __name__ == "__main__":
    sys.exit(main())
