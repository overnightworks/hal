"""Probe that brings Keycloak and step-ca up in an edge copy through `hal apply --local`.

Its cells H1-H6 hold it beside the live stack and isolated from it, so later probes drive Keycloak
changes through hal itself.

    probe-run \\
        uv run --frozen python3 probe/keycloak/in_copy.py --scratch DIR

The copy is edge_copy's, under the project `edge-kc-in-copy`. copy_isolation's `install` is the
one way a file set enters it, under the copy's one allocation; `apply`, every compose call that
starts something and the teardown check the copy again before they act, and the probe proves those
checks on negative cases before anything starts. Every request of probe.py's reused helpers goes to
the copy's two entrypoints or is refused before it leaves (`ScratchOnlyHttp`). Keycloak is
bootstrapped as go-live does it, never by running go-live (`KeycloakCopy.bootstrap`), and the
copy's `keycloak/go-live --check` must exit 0 before the first `hal apply`. Exit 0: every cell
held.
"""

from __future__ import annotations

import base64
import grp
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

PROBE_DIRECTORY = Path(__file__).resolve().parent
sys.path[:0] = [str(PROBE_DIRECTORY.parent), str(PROBE_DIRECTORY.parents[1] / "src")]
sys.path.append(str(PROBE_DIRECTORY))  # copy_isolation, after every other probe directory

import edge_copy  # noqa: E402
from copy_isolation import (  # noqa: E402
    COMPOSE_FILE,
    GO_LIVE_FILE,
    KEYCLOAK_SECRETS,
    REPO,
    REWRITES,
    SHIPPED_FLEET,
    SOCKET_PROXY,
    TRAEFIK_SERVICE,
    CopyStand,
    Fleet,
    Isolation,
    compose_prefix,
    expect_call_isolated,
    expect_guards_refuse,
    expect_isolated,
    go_live,
    install,
    keycloak,
    removed_whatever_fails,
    routable_by_live_edge,
    run_checked,
    shipped_files,
)
from edge_copy import HAL_OK, NOTHING_TO_CHANGE, ProbeFailed, expect  # noqa: E402

from hal.backup.docker import PROJECT_LABEL  # noqa: E402
from hal.backup.settings import Settings  # noqa: E402
from hal.output import CONFIRMATION, write_line  # noqa: E402
from hal.stack import compose  # noqa: E402
from hal.stack.realm.reconcile import CONFIG_CLI, KEYCLOAK, KEYCLOAK_SERVICE, REALM_UNIT  # noqa: E402
from hal.stack.result_rows import ResultEvent  # noqa: E402

PROJECT = "edge-kc-in-copy"
STEP_CA_UNIT = "step-ca"
STEP_CA_SETUP = SHIPPED_FLEET[STEP_CA_UNIT]["run"]["setup"]
CORE_SERVICES = (SOCKET_PROXY, TRAEFIK_SERVICE)
KEYCLOAK_PROFILE = ("--profile", go_live.KEYCLOAK_PROFILE)
BOOTSTRAP_START = (*KEYCLOAK_PROFILE, "up", "--detach", "--wait", KEYCLOAK_SERVICE)
REALM_APPLIED = re.compile(
    rf"{REALM_UNIT}\s+{ResultEvent.REALM_APPLIED}\b.*?snapshot (?P<snapshot>\S+) proven"
)
YES_PROMPT = f"Type {CONFIRMATION}"
COMPOSE_SECONDS = 900
SHORT_SECONDS = 120


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

    def __init__(self, send: Callable[..., Any], allowed: frozenset[str]) -> None:
        self.send, self.allowed, self.sent = send, allowed, 0

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


def project_resources(kind: str, projects: Sequence[str] = (PROJECT,)) -> list[str]:
    """The containers (any state), networks or volumes that carry the label of one of `projects`."""
    every = ["--all"] if kind == "container" else []
    return [
        found
        for project in projects
        for found in run_checked(
            ["docker", kind, "ls", *every, "--quiet", "--filter",
             f"label={PROJECT_LABEL}={project}"], os.environ,
        ).split()
    ]  # fmt: skip


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
        # the copy's project and the project of each app its fleet ran: what every check of the
        # live edge's view and every label sweep covers
        self.projects: list[str] = [PROJECT]
        self.self_checks = 0

    @property
    def secrets_dir(self) -> Path:
        return self.home / KEYCLOAK_SECRETS

    def secret(self, name: str) -> str:
        return (self.secrets_dir / name).read_text()

    def prepare(self, fleet: Fleet) -> None:
        """The copy, its allocation, its first install, the self-checks and its scratch secrets."""
        copy = edge_copy.repository_copy(REPO, self.home, self.scratch, PROJECT)
        isolation = Isolation.allocate(PROJECT, (REPO / COMPOSE_FILE).read_text())
        self.stand = CopyStand(copy, isolation, fleet, self.guard, self.environment)
        keycloak.http = self.http = ScratchOnlyHttp(keycloak.http, isolation.netlocs)
        # probe.py's helpers read edge_url, admin_url and master_token_url of their stack
        self.kc = keycloak.Probe(isolation)
        install(self.stand, shipped_files(REPO), "probe: Keycloak isolated in the copy")
        bootstrap_start = [*compose_prefix(self.stand, bootstrap=True), *BOOTSTRAP_START]
        self.self_checks = expect_guards_refuse(self.stand, bootstrap_start)
        write_line(self.teardown_sweep_line(), flush=True)
        self.self_checks += 1
        self.write_keycloak_secrets()
        step_ca = [*edge_copy.copy_compose_prefix(copy), "--profile", STEP_CA_UNIT]
        self.guard.expect(step_ca, once=False)
        run_checked([str(copy / STEP_CA_SETUP)], self.environment, cwd=copy, timeout=600)
        settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        password = settings.password_file.relative_to(self.home)
        write_secret(self.home, password, secrets.token_urlsafe(32), mode=0o600)
        edge_copy.run_hal(copy, self.environment, "backup", "--init", terminal=True)

    def compose(
        self, *arguments: str, bootstrap: bool = False, timeout: int = SHORT_SECONDS
    ) -> str:
        """Compose in the copy, with go-live's bootstrap overlay when `bootstrap`; a call that
        starts or removes something is checked by the guard first, and one that starts something
        by `expect_call_isolated` over the configuration its files merge to."""
        command = [*compose_prefix(self.stand, bootstrap=bootstrap), *arguments]
        self.guard.expect_call(command)
        expect_call_isolated(self.stand, command)
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

    def bootstrap(self) -> None:
        """go-live's steps 3 to 5 and 7 on the copy, never go-live itself."""
        self.compose(*BOOTSTRAP_START, bootstrap=True, timeout=COMPOSE_SECONDS)
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
                     KEYCLOAK.database)  # fmt: skip

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
        self.guard.expect([*edge_copy.copy_compose_prefix(copy), *KEYCLOAK_PROFILE], once=False)
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
        """Every container of the copy's project and its apps', in any state, carries no
        `edge.name` the live constraint accepts, so the live Traefik never takes one as a server."""
        containers = project_resources("container", self.projects)
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
        """Removes everything of the copy's project, the copy rechecked before its compose down;
        the seconds it took. A copy whose files cannot be read or are not isolated any more is
        removed by its project label alone, and its error then stops the teardown."""
        started = time.monotonic()
        if stray := project_resources("container", self.projects):
            run_checked(["docker", "rm", "--force", *stray], os.environ, timeout=SHORT_SECONDS)
        removed_whatever_fails(self.checked_down, self.sweep)
        return time.monotonic() - started

    def teardown_sweep_line(self) -> str:
        """The teardown's path on a copy whose files are missing, with one volume carrying the
        project's label and nothing started: the real label sweep removes the volume, and the
        read's error still stops the teardown."""
        stand = self.stand
        if stand is None:
            raise ProbeFailed("self-check: the teardown self-check ran before prepare")
        volume = f"{PROJECT}_teardown-self-check"
        label = f"{PROJECT_LABEL}={PROJECT}"
        run_checked(["docker", "volume", "create", "--label", label, volume], os.environ)
        missing = replace(stand, copy=stand.copy / "missing")
        try:
            removed_whatever_fails(
                lambda: expect_isolated(missing),  # NOSONAR(S5655) replace() keeps type
                self.sweep,
            )
        except FileNotFoundError as failure:
            expect(not project_resources("volume"), f"self-check: the sweep left {volume}")
            swept = f"the label sweep removed the volume {volume}"
            stopped = f"{type(failure).__name__} stopped the teardown"
            return f"self-check: a missing copy file at the teardown: {swept}, then {stopped}"
        raise ProbeFailed("self-check: a missing copy file at the teardown raised nothing")

    def checked_down(self) -> None:
        if self.stand is not None:
            expect_isolated(self.stand)
            self.compose("--profile", "*", "down", "--volumes", "--remove-orphans",
                         "--timeout", "10", timeout=COMPOSE_SECONDS)  # fmt: skip

    def sweep(self) -> None:
        """Removes the networks and volumes labelled with one of the projects and checks that
        nothing of them is left and the live networks kept their ids."""
        for kind in ("network", "volume"):
            if found := project_resources(kind, self.projects):
                run_checked(["docker", kind, "rm", *found], os.environ, timeout=SHORT_SECONDS)
        named = [
            volume
            for project in self.projects
            for volume in run_checked(
                ["docker", "volume", "ls", "--quiet", "--filter", f"name={project}_"], os.environ
            ).split()
        ]
        left = [
            *(found for kind in ("container", "network", "volume")
              for found in project_resources(kind, self.projects)),
            *named,
        ]  # fmt: skip
        expect(not left, f"the teardown left {left}")
        self.guard.expect_clean_teardown()
        expect(live_network_ids() == self.live_networks_before, "the hal_ network ids changed")


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
        self.prepare(Fleet(frozenset({REALM_UNIT, STEP_CA_UNIT})))
        first = self.rewritten_digests()
        line = install(self.stand, shipped_files(REPO), "probe: the shipped files installed again")
        again = self.rewritten_digests()
        changed = sorted(name for name in REWRITES if first[name] != again[name])
        expect(not changed, f"H1: a reinstall changed {changed}")
        self.hold(
            "H1",
            f"{line}; the shipped files installed again are byte-identical in "
            f"{', '.join(REWRITES)}: the same allocation; {self.self_checks} self-checks held",
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
        on = [
            rf"\b{unit}\s+{ResultEvent.SWITCHED_ON}\b" for unit in sorted(self.stand.fleet.units_on)
        ]
        expect(all(re.search(row, first) for row in on), f"H3: the first apply said {first[-400:]}")
        wanted = {KEYCLOAK_SERVICE, KEYCLOAK.database, STEP_CA_UNIT, *CORE_SERVICES}
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
