"""What the `test_stack_apply` tests share with other test modules."""

import dataclasses
import fcntl
import io
import json
import os
import shutil
import stat
import sys
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime
from functools import partial
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml
from support.git_support import (
    committed_main,
    plain_git,
    with_origin,
)
from support.stack_apply_fakes import (
    Ingress,
    RealmBackup,
    ScriptedCompose,
    ScriptedGit,
    Setup,
    SetupRun,
    Terminal,
)
from support.stack_core import bind, bind_core_files, sha256

from hal.stack import (
    apply,
    apps,
    checkout,
    compose,
    core,
    emergency,
    environment,
    setup,
    switches,
)
from hal.stack.plan_rows import PlanEvent

REPOSITORY = Path(__file__).resolve().parents[2]


STEP_CA_SERVICES = ("step-ca", "traefik-mcp-acme-owner", "traefik-mcp")


ENABLED = "services:\n  step-ca:\n    run: {enabled: true, setup: step-ca/init}\n"


DISABLED = "services:\n  step-ca:\n    run: {enabled: false, setup: step-ca/init}\n"


SWITCHED_OFF_AT = "2026-10-17T22:10:04+02:00"


PROBE_ENABLED = ENABLED + "  probe:\n    run: {enabled: true}\n"


ZONE = "edge-fixture.invalid"


DOCKER_GID = 998


NOW = datetime.fromisoformat("2026-10-18T08:00:00+02:00")


STEP_CA_BUMP = f"smallstep/step-ca:0.30.3@sha256:{'1' * 64}"


@pytest.fixture(autouse=True)
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """A stray real marker would keep a live unit down: every test gets its own HOME, and git its
    own global config there."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "home" / ".config"))
    monkeypatch.setenv("LC_ALL", "C")  # git's own lines in English, whatever the machine speaks
    return tmp_path / "home"


@pytest.fixture
def state(home: Path) -> Path:
    return switches.default_state_directory()


def marker(state: Path, unit: str = "step-ca") -> str | None:
    return switches.Switches(state).since(unit)


def switch_off(state: Path, since: str = SWITCHED_OFF_AT, unit: str = "step-ca") -> None:
    switches.Switches(state).record(unit, datetime.fromisoformat(since))


def edge_tree(tree: Path) -> Path:
    """A tree of this repository's shape at `tree`, a main worktree (its `.git` is a directory)."""
    (tree / ".git").mkdir(parents=True)
    for directory, name in (("step-ca", "init"), ("keycloak", "init"), ("agent-service", "setup")):
        (tree / directory).mkdir(exist_ok=True)
        setup = tree / directory / name
        setup.write_text("#!/bin/sh\n")
        setup.chmod(setup.stat().st_mode | stat.S_IXUSR)
    (tree / "fleet.yaml").write_text(f"cloudflare:\n  zone: {ZONE}\n" + ENABLED)
    (tree / "dynamic").mkdir()
    (tree / "dynamic" / ".gitkeep").touch()
    (tree / "traefik.yml").write_text('entryPoints:\n  edge:\n    address: "127.0.0.1:8081"\n')
    (tree / ".env").write_text(f"EDGE_DOMAIN={ZONE}\nDOCKER_GID={DOCKER_GID}\n")
    return tree


def docker_group(name: str) -> SimpleNamespace:
    """The group lookup of a PC whose `docker` group has `DOCKER_GID`."""
    if name != environment.DOCKER_GROUP:
        raise KeyError(name)
    return SimpleNamespace(gr_gid=DOCKER_GID)


def writing_environment(group_lookup=docker_group) -> apply.EnsureEnvironment:
    """The real `.env` step on a PC with that group lookup."""
    return partial(environment.ensure, group_lookup=group_lookup)


def trusted_environment(_tree: Path) -> None:
    """The `.env` step of the tests that are about something else: it is happy."""


@pytest.fixture
def repository(home: Path, seed_appkit) -> Path:
    """The live checkout `$HOME/srv/hal` of the test's own HOME (#79 cell 1)."""
    return seed_appkit(edge_tree(checkout.live_checkout(home)))


@pytest.fixture
def scripted_git() -> ScriptedGit:
    return ScriptedGit()


@pytest.fixture
def ingress(repository: Path) -> Ingress:
    return Ingress(repository)


@pytest.fixture
def scripted() -> ScriptedCompose:
    return ScriptedCompose()


@pytest.fixture
def realm_backup() -> RealmBackup:
    return RealmBackup()


@pytest.fixture
def setup_check() -> Setup:
    return Setup()


@pytest.fixture
def setup_run(setup_check: Setup) -> SetupRun:
    return SetupRun(setup_check)


@pytest.fixture
def at_terminal(monkeypatch: pytest.MonkeyPatch) -> Callable[[str], None]:
    """Stdin and stdout are a terminal; the operator will type `answer`."""

    def operator_types(answer: str, while_prompt_waits: Callable[[], None] | None = None) -> None:
        keyboard = Terminal(f"{answer}\n")
        keyboard.while_prompt_waits = while_prompt_waits
        monkeypatch.setattr(sys, "stdin", keyboard)
        monkeypatch.setattr(sys, "stdout", Terminal())

    return operator_types


@pytest.fixture
def switch(
    repository, scripted, setup_check, setup_run, at_terminal, capsys, state, home, ingress,
    scripted_git, monkeypatch, realm_backup,
):  # fmt: skip
    """Run `hal apply --local` from the live checkout (or `tree`); `yes` at a terminal."""

    def run(
        answer: str = "yes",
        while_prompt_waits=None,
        *,
        tree: Path | None = None,
        from_home: Path | None = None,
        git: checkout.Runner | None = None,
        run_setup: setup.SetupRunner | None = None,
        at_a_terminal: bool = True,
        ensure_environment: apply.EnsureEnvironment = trusted_environment,
        installed_backup: bool = False,
        app_runtime: apps.AppRuntime | None = None,
        rename=os.rename,
        clock=None,
    ) -> tuple[int, str, str]:
        at_terminal(answer, while_prompt_waits)
        if not at_a_terminal:
            monkeypatch.setattr(sys, "stdin", io.StringIO(f"{answer}\n"))
        tree = tree or repository
        exit_code = apply.apply_local(
            state,
            compose.Compose(scripted.run, tree),
            tree,
            setup_check,
            run_setup or setup_run,
            from_home or home,
            dataclasses.replace(ingress.verifier, clock=clock) if clock else ingress.verifier,
            ingress.watch,
            git or scripted_git,
            ensure_environment,
            None if installed_backup else realm_backup,
            app_runtime,
            rename,
        )
        return exit_code, sys.stdout.getvalue(), capsys.readouterr().err

    return run


@pytest.fixture
def start(repository, scripted, at_terminal, capsys, state, ingress, setup_check):
    """Run `hal start <unit>`; the operator types `yes` unless told otherwise."""

    def run(
        answer: str = "yes", unit: str = "step-ca", while_prompt_waits=None
    ) -> tuple[int, str, str]:
        at_terminal(answer, while_prompt_waits)
        exit_code = emergency.start_unit(
            switches.Switches(state),
            unit,
            compose.Compose(scripted.run, repository),
            repository,
            ingress.verifier,
            setup_check,
            ingress.watch,
        )
        return exit_code, sys.stdout.getvalue(), capsys.readouterr().err

    return run


def write_fleet(repository: Path, text: str) -> None:
    (repository / "fleet.yaml").write_text(text)


STEP_CA_ON = {"step-ca": "running", "traefik-mcp-acme-owner": "exited", "traefik-mcp": "running"}


APP_EXITED = STEP_CA_ON | {"traefik-mcp": "exited"}


@pytest.fixture
def agent_service_unit(repository, scripted) -> set[str]:
    """The repository's `agent-service` unit and compose.yaml, the other units off; its services."""
    real = yaml.safe_load((REPOSITORY / "fleet.yaml").read_text())["services"]["agent-service"]
    fleet = {"cloudflare": {"zone": ZONE}, "services": {"agent-service": real}}
    write_fleet(repository, yaml.safe_dump(fleet))
    shutil.copytree(REPOSITORY / "agent-service" / "image", repository / "agent-service" / "image")
    services = yaml.safe_load((REPOSITORY / "compose.yaml").read_text())["services"]
    profile = {n: d for n, d in services.items() if "agent-service" in d.get("profiles", ())}
    for name, definition in profile.items():
        scripted.config["services"][name] = definition | {
            "volumes": [_resolved_mount(mount) for mount in definition.get("volumes", [])]
        }
    return set(profile)


def _resolved_mount(mount: str | dict) -> dict:
    """A volume as `docker compose config` spells it: the short form `source:target[:ro]` of
    compose.yaml becomes the long form."""
    if isinstance(mount, dict):
        return mount
    source, target, *mode = mount.split(":")
    return {"type": "bind", "source": source, "target": target, "read_only": mode == ["ro"]}


NOT_SET_UP_LINE = "password is not done"


@pytest.fixture
def missing_setup(setup_check: Setup) -> Setup:
    setup_check.exit_code, setup_check.line = 1, NOT_SET_UP_LINE
    return setup_check


TWO_SETUPS = (
    ENABLED + "  keycloak:\n    run: {enabled: true, setup: keycloak/init}\n"
)  # catalog order: step-ca, keycloak


def apply_lock(state: Path) -> Path:
    return state / apply.APPLY_LOCK


@contextmanager
def apply_lock_held(state: Path) -> Iterator[None]:
    """`apply.lock` held as another apply holds it: its own open file, flocked."""
    state.mkdir(parents=True, exist_ok=True)
    with apply_lock(state).open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        yield


def interrupted_at_the_prompt() -> None:
    raise KeyboardInterrupt


@pytest.fixture
def real_main(repository: Path, tmp_path: Path) -> Path:
    """The live checkout as a real git repository: its files committed on a fresh `main`, pushed
    to its bare remote `origin` (`tmp_path/origin.git`)."""
    (repository / ".git").rmdir()
    with_origin(committed_main(repository), tmp_path / "origin.git")
    return repository


@pytest.fixture
def origin(real_main: Path, tmp_path: Path) -> Path:
    return tmp_path / "origin.git"


def short(tree: Path, revision: str = "HEAD") -> str:
    return plain_git(tree, "rev-parse", "--short", revision).stdout.strip()


def put_unit_in(situation: str, scripted, repository, state) -> None:
    """A: on, no marker. B: switched off, stopped. E: disabled in the catalog, gone."""
    if situation == "A":
        scripted.containers = {
            "step-ca": "running",
            "traefik-mcp-acme-owner": "exited",
            "traefik-mcp": "running",
        }
    if situation == "B":
        scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "exited")
        switch_off(state)
    if situation == "E":
        write_fleet(repository, DISABLED)


def put_probe_in_b(scripted, state, ingress) -> None:
    scripted.containers = {"hello": "exited"}
    switch_off(state, unit="probe")


RECREATE_TRAEFIK = ["--profile", "*", "up", "-d", "--no-deps", "--force-recreate", "traefik"]


@pytest.fixture
def core_files(scripted, repository):
    """The core as compose.yaml resolves it, with traefik's bind of `traefik.yml`, both running;
    no unit has anything to change."""
    bind_core_files(scripted.config, repository)
    scripted.put_containers({"socket-proxy": "running", "traefik": "running"})
    write_fleet(repository, DISABLED)


def applied(state: Path) -> dict | None:
    record = state / "applied.json"
    return json.loads(record.read_text()) if record.exists() else None


def edit_traefik_yml(repository: Path) -> None:
    with (repository / "traefik.yml").open("a") as file:
        file.write("# a harmless edit\n")


def up_calls(scripted) -> list[list[str]]:
    return [call for call in scripted.calls if call[2] == "up"]


@pytest.fixture
def applied_core(core_files, switch, scripted):
    """The core as last applied: traefik.yml recorded, both containers from the current
    definitions; the calls of that first run are forgotten."""
    assert switch()[0] == 0
    scripted.calls.clear()


@pytest.fixture
def unreadable_profile_bind(applied_core, monkeypatch):
    """The step that finds the services edge follows, which runs only after the yes, fails."""

    def refuse(*_: object) -> frozenset[str]:
        raise core.CoreError("cannot read locked/hello.yml (Permission denied)")

    monkeypatch.setattr(core, "followed_services", refuse)


FOLLOWER_FILE = "traefik-mcp.yml"


RECREATE_FOLLOWER = [*RECREATE_TRAEFIK[:-1], "traefik-mcp"]


def bind_traefik_mcp_files(config: dict, repository: Path) -> None:
    """compose.yaml's binds of traefik-mcp, resolved for `repository`: its static config at
    Traefik's path and `mcp/dynamic` as a directory."""
    (repository / FOLLOWER_FILE).write_text("entryPoints: {}\n")
    (repository / "mcp" / "dynamic").mkdir(parents=True)
    config["services"]["traefik-mcp"]["volumes"] += [
        bind(repository / FOLLOWER_FILE, "/etc/traefik/traefik.yml"),
        bind(repository / "mcp" / "dynamic", "/mcp/dynamic"),
    ]


def follower_digest(repository: Path) -> dict:
    return {FOLLOWER_FILE: sha256(repository / FOLLOWER_FILE)}


@pytest.fixture
def step_ca_applied(applied_core, scripted, repository, state):
    """step-ca on and applied: traefik.yml and traefik-mcp.yml recorded, every container created
    from the current definitions; the calls so far are forgotten."""
    bind_traefik_mcp_files(scripted.config, repository)
    write_fleet(repository, ENABLED)
    scripted.put_containers(STEP_CA_ON)
    (state / "applied.json").write_text(
        json.dumps(applied(state) | {"traefik-mcp": follower_digest(repository)})
    )
    scripted.calls.clear()


OLD_IMAGE = str(PlanEvent.OLD_IMAGE)


KEYCLOAK_ENABLED = "services:\n  keycloak:\n    run: {enabled: true, setup: keycloak/init}\n"


@pytest.fixture
def realm_unit(repository, scripted) -> None:
    """Keycloak enabled, set up and running; its realm files, and config-cli as compose.yaml
    resolves it: it binds `entrypoint.sh` from the checkout, so edge follows it (#242)."""
    write_fleet(repository, KEYCLOAK_ENABLED)
    (repository / "keycloak/realm.yaml").write_text("realm: one\n")
    (repository / "keycloak/master.yaml").write_text("master: one\n")
    (repository / "keycloak/entrypoint.sh").write_text("#!/bin/sh\n")
    scripted.config["services"]["keycloak-config-cli"] = {
        "profiles": ["apply"],
        "volumes": [bind(repository / "keycloak/entrypoint.sh", "/opt/edge/entrypoint.sh")],
    }
    scripted.put_containers({"keycloak": "running"})
