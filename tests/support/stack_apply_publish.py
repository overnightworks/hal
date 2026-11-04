"""What the `test_stack_apply_publish` tests share with other test modules."""

import dataclasses
import functools
import sys
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from support.app_support import KEY, ScriptedDocker, origin_at, runtime_of
from support.stack_apply import (
    NOT_SET_UP_LINE,
    REPOSITORY,
    apply_lock_held,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    trusted_environment,
)
from support.stack_external import (
    CLEAN_SNAPSHOT,
    FakeProber,
    FakeReader,
    commit_catalog,
    fake_tofu,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
    plain_git,
)
from support.stack_plan_rows import plain

from hal import cli
from hal.stack import apply, compose
from hal.stack.external import cli as external_cli
from hal.stack.external import tofu

REAL_APPLY_LOCAL = apply.apply_local


REAL_PUBLISH = external_cli.apply_command


REAL_CHECK = external_cli.check_command


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
class Result:
    exit_code: int
    out: str
    err: str


@dataclass
class World:
    """Plain `hal apply` over the scripted local part and the fake publish."""

    run: functools.partial[Result]
    settle_local: functools.partial[None]
    scripted: object
    scripted_git: object
    setup_check: object
    setup_run: object
    state: Path
    stack: ExitStack
    reader: FakeReader
    fake_tofu: object
    collaborators: apply.Collaborators
    publish_entries: list[tuple] = field(default_factory=list)
    check_entries: list[None] = field(default_factory=list)

    def make_setup_missing(self) -> None:
        self.setup_check.exit_code, self.setup_check.line = 1, NOT_SET_UP_LINE

    def publish_never_began(self) -> bool:
        return not (self.publish_entries or self.check_entries or self.fake_tofu.calls())


@pytest.fixture
def repository(live_checkout, monkeypatch, seed_appkit) -> Path:  # noqa: F811
    """`~/srv/hal`: one real checkout that both parts read, the catalog committed, the appkit
    files the last apply left in it (ignored by git, as in this repository)."""
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
    plain_git(live_checkout, "add", "--all")
    commit_catalog(live_checkout, CATALOG)
    seed_appkit(live_checkout)
    monkeypatch.setattr(tofu, "PROJECT_ROOT", live_checkout)
    return live_checkout


@pytest.fixture
def world(
    repository, scripted, scripted_git, setup_check, setup_run, ingress, state, fake_tofu,  # noqa: F811
    at_terminal, capsys, monkeypatch,  # noqa: F811
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
    reader = FakeReader(CLEAN_SNAPSHOT)
    made = World(
        None, None, scripted, scripted_git, setup_check, setup_run, state, ExitStack(),
        reader, fake_tofu, collaborators,
    )  # fmt: skip

    def spy_on_publish(*arguments, **keywords):
        made.publish_entries.append((arguments, keywords))
        return REAL_PUBLISH(*arguments, **keywords)

    def spy_on_check(*arguments, **keywords):
        made.check_entries.append(None)
        return REAL_CHECK(*arguments, cloudflare=reader, prober=FakeProber(), **keywords)

    monkeypatch.setattr(external_cli, "apply_command", spy_on_publish)
    monkeypatch.setattr(external_cli, "check_command", spy_on_check)

    def run(*answers: str, arguments=("apply",), while_prompt_waits=None) -> Result:
        at_terminal("\n".join(answers), while_prompt_waits)
        exit_code = cli.main(list(arguments))
        return Result(exit_code, plain(sys.stdout.getvalue()), capsys.readouterr().err)

    def settle_local() -> None:
        """The local part has applied before; the publish has not run."""
        at_terminal("yes")
        assert apply.apply_local(state) == 0
        capsys.readouterr()

    made.run, made.settle_local = run, settle_local
    with made.stack:
        yield made


def lock_held(world: World) -> None:
    world.stack.enter_context(apply_lock_held(world.state))


def not_on_main(world: World) -> None:
    world.scripted_git.reference = b"refs/heads/feature\n"


def start_fails(world: World) -> None:
    world.scripted.failing_verb = "up"


@pytest.fixture
def failing_app(world, repository, home, tmp_path, monkeypatch):  # noqa: F811
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
