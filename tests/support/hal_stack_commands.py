"""What the `test_hal_stack_commands` tests share with other test modules."""

import dataclasses
import functools
import io
import os
import stat
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path

import pytest
from support.app_support import KEY, ScriptedDocker, origin_at, runtime_of
from support.git_support import plain_git
from support.stack_apply import (
    PROBE_ENABLED,
    REPOSITORY,
    apply_lock_held,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    marker,
    put_probe_in_b,
    put_unit_in,
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    trusted_environment,
    write_fleet,
)
from support.stack_apply_fakes import (
    Ingress,
    ScriptedCompose,
)
from support.stack_global_stop import FakeSystemd, hosts_asked  # noqa: F401 the fixture, used by `fakes`

from hal import cli
from hal.stack import apply, barrier, catalog, checkout, compose, emergency, tunnel

REAL_STOP_UNIT = emergency.stop_unit


REAL_START_UNIT = emergency.start_unit


REAL_START_ALL = emergency.start_all


REAL_FROM_ENVIRONMENT = tunnel.Tunnel.from_environment


SYSTEM_COMMANDS = ("systemctl", "docker", "sudo", "pkcheck")


UNIT = "step-ca"


@dataclass
class Guard:
    """The directory of stand-ins for the commands no test may run, and the log they write."""

    directory: Path
    log: Path

    def calls(self) -> list[str]:
        return self.log.read_text().splitlines() if self.log.exists() else []

    def first_on(self, path: str) -> str:
        return f"{self.directory}{os.pathsep}{path}"


@pytest.fixture(autouse=True)
def system_commands(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    directory = tmp_path / "guard-bin"
    directory.mkdir()
    guard = Guard(directory, tmp_path / "guard-calls")
    for name in SYSTEM_COMMANDS:
        script = directory / name
        script.write_text(f'#!/bin/sh\necho "{name} $*" >> "{guard.log}"\nexit 99\n')
        script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", guard.first_on(os.environ["PATH"]))
    yield guard
    assert guard.calls() == [], "a test reached a real system command"


class UnreadableStdin(io.StringIO):
    """Stdin of an agent: not a terminal, and nobody may read it."""

    def isatty(self) -> bool:
        return False

    def read(self, *_arguments) -> str:
        raise AssertionError("stdin was read")

    def readline(self, *_arguments) -> str:
        raise AssertionError("stdin was read")


@dataclass
class Result:
    exit_code: int
    out: str
    err: str

    @property
    def text(self) -> str:
        return self.out + self.err


@pytest.fixture
def hal(at_terminal, capsys, monkeypatch, system_commands):  # noqa: F811
    """One run of `hal.cli.main`: at a terminal where the operator types `answers`, otherwise with
    a stdin nobody may read. PATH starts with the guard whatever a fixture set meanwhile."""

    def run(*arguments: str, answers: tuple[str, ...] | None = None, while_prompt_waits=None):
        monkeypatch.setenv("PATH", system_commands.first_on(os.environ["PATH"]))
        if answers is None:
            monkeypatch.setattr(sys, "stdin", UnreadableStdin())
        else:
            at_terminal("\n".join(answers), while_prompt_waits)
        exit_code = cli.main(list(arguments))
        captured = capsys.readouterr()
        out = captured.out if answers is None else sys.stdout.getvalue()
        return Result(exit_code, out, captured.err)

    return run


REAL_APPLY_LOCAL = apply.apply_local


CATALOG = """\
cloudflare: {zone: example.test}
services:
  step-ca:
    run: {enabled: true, setup: step-ca/init}
  site:
    hosts:
      - {name: "@", exposure: public, reason: the site}
"""


@dataclass
class World:
    """Plain `hal apply` over the scripted local part."""

    scripted: object
    scripted_git: object
    state: Path
    stack: ExitStack
    collaborators: apply.Collaborators


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    return home


def commit(tree: Path, *arguments: str) -> None:
    plain_git(
        tree,
        *("-c", "user.name=edge test", "-c", "user.email=test@edge.invalid"),
        *("-c", "core.hooksPath=/dev/null", *arguments),
    )


def commit_catalog(tree: Path, text: str) -> None:
    (tree / "fleet.yaml").write_text(text)
    commit(tree, "commit", "--quiet", "--all", "--message", "catalog")


@pytest.fixture
def live_checkout(home) -> Path:
    """`~/srv/hal` as the operator has it: the main worktree, a clean `main` with one commit."""
    tree = checkout.live_checkout(home)
    tree.mkdir(parents=True)
    (tree / ".gitignore").write_text((REPOSITORY / ".gitignore").read_text())
    (tree / "fleet.yaml").write_text((REPOSITORY / "fleet.yaml").read_text())
    commit(tree, "init", "--quiet", "--initial-branch", "main")
    commit(tree, "add", "--all")
    commit(tree, "commit", "--quiet", "--message", "init")
    return tree


@pytest.fixture
def repository(live_checkout, seed_appkit) -> Path:
    """`~/srv/hal`: one real checkout, the catalog committed, the appkit files the last apply left
    in it (ignored by git, as in this repository)."""
    step_ca_setup = live_checkout / "step-ca" / "init"
    step_ca_setup.parent.mkdir()
    step_ca_setup.write_text("#!/bin/sh\n")
    step_ca_setup.chmod(0o755)
    (live_checkout / "dynamic").mkdir()
    (live_checkout / "dynamic" / ".gitkeep").write_text("")
    (live_checkout / "traefik.yml").write_text(
        'entryPoints:\n  edge:\n    address: "127.0.0.1:8081"\n'
    )
    (live_checkout / ".gitignore").write_text((REPOSITORY / ".gitignore").read_text())
    commit(live_checkout, "add", "--all")
    commit_catalog(live_checkout, CATALOG)
    seed_appkit(live_checkout)
    return live_checkout


@pytest.fixture
def world(
    repository, scripted, scripted_git, setup_check, setup_run, ingress, state,  # noqa: F811
    at_terminal, monkeypatch,  # noqa: F811
):  # fmt: skip
    collaborators = apply.Collaborators(
        engine=compose.Compose(scripted.run, repository),
        check=setup_check,
        run_setup=setup_run,
        verifier=ingress.verifier,
        watch=ingress.watch,
        git=scripted_git,
        ensure_environment=trusted_environment,
    )
    monkeypatch.setattr(
        apply,
        "apply_local",
        functools.partial(REAL_APPLY_LOCAL, repository=repository, collaborators=collaborators),
    )
    with ExitStack() as stack:
        yield World(scripted, scripted_git, state, stack, collaborators)


@pytest.fixture
def applying(world) -> World:
    """The world of `hal apply`: scripted local part, one terminal."""
    return world


def lock_held(world: World) -> None:
    world.stack.enter_context(apply_lock_held(world.state))


def not_on_main(world: World) -> None:
    world.scripted_git.reference = b"refs/heads/feature\n"


def start_fails(world: World) -> None:
    world.scripted.failing_verb = "up"


@pytest.fixture
def failing_app(world, repository, home, tmp_path, monkeypatch):
    """The catalog also declares the app `hopin`, whose newest release never becomes healthy."""
    commit_catalog(
        repository,
        CATALOG.replace(
            "services:\n",
            "github: {org: overnightworks}\nservices:\n  hopin:\n"
            "    repo: {default_branch: master}\n    run: {enabled: true}\n",
            1,
        ),
    )
    origin_at(tmp_path, home).release("v2026.10.22.1")
    docker = ScriptedDocker(world.state, home / "srv" / KEY, health_after_start="unhealthy")
    monkeypatch.setattr(
        apply,
        "apply_local",
        functools.partial(
            REAL_APPLY_LOCAL,
            repository=repository,
            collaborators=dataclasses.replace(
                world.collaborators, app_runtime=runtime_of(home, world.state, docker)
            ),
        ),
    )


def nothing(_world: World) -> None:
    """The local part is happy; only the answers decide."""


@pytest.fixture
def systemd() -> FakeSystemd:
    return FakeSystemd()


@dataclass
class Fakes:
    """The stack's scripted boundaries, and the situation a unit of the catalog is put in."""

    repository: Path
    scripted: ScriptedCompose
    ingress: Ingress
    state: Path
    hosts_asked: list[str]

    def unit_in(self, situation: str) -> None:
        put_unit_in(situation, self.scripted, self.repository, self.state)

    def probe_switched_off_behind_a_barrier(self) -> None:
        write_fleet(self.repository, PROBE_ENABLED)
        put_probe_in_b(self.scripted, self.state, self.ingress)
        unit = catalog.Unit("probe", enabled=True, setup=None)
        barrier.Barrier.of_unit(
            self.scripted.config, ("hello",), self.repository, unit, self.ingress.verifier
        ).close()

    def marker(self) -> str | None:
        return marker(self.state, UNIT)


@pytest.fixture
def fakes(repository, scripted, ingress, setup_check, systemd, state, hosts_asked, monkeypatch):  # noqa: F811
    """The stack's boundaries are scripted: Compose, Traefik, the setup check and systemctl."""
    boundaries = {
        "engine": compose.Compose(scripted.run, repository),
        "repository": repository,
        "verifier": ingress.verifier,
    }
    monkeypatch.setattr(emergency, "stop_unit", functools.partial(REAL_STOP_UNIT, **boundaries))
    monkeypatch.setattr(
        emergency,
        "start_unit",
        functools.partial(REAL_START_UNIT, **boundaries, check=setup_check, watch=ingress.watch),
    )
    monkeypatch.setattr(emergency, "start_all", functools.partial(REAL_START_ALL, **boundaries))
    monkeypatch.setattr(
        tunnel.Tunnel,
        "from_environment",
        classmethod(
            lambda _cls, environment: dataclasses.replace(
                REAL_FROM_ENVIRONMENT(environment), run=systemd.run
            )
        ),
    )
    return Fakes(repository, scripted, ingress, state, hosts_asked)


def ctrl_c(*_arguments) -> None:
    raise KeyboardInterrupt
