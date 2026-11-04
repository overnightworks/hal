"""What the `test_stack_apps` tests share with other test modules."""

import dataclasses
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import support.throwaway_home as throwaway_home
from support.app_support import (
    FLEET,
    KEY,
    NOW,
    Origin,
    ScriptedDocker,
    origin_at,
    runtime_of,
)
from support.git_support import committed_main
from support.stack_apply import REPOSITORY, ZONE, write_fleet
from support.stack_apply_apps import AppWorld

from hal.stack import apps, switches
from hal.stack.unit_plans import Fleet, Progress

home = throwaway_home.home


EDGE_FLEET = Fleet({"name": "edge"}, {}, ())


FIRST, SECOND, THIRD = "v2026.10.22.1", "v2026.10.22.2", "v2026.10.22.3"


@pytest.fixture
def origin(tmp_path: Path, home: Path) -> Origin:
    return origin_at(tmp_path, home)


@pytest.fixture
def state(tmp_path: Path) -> Path:
    return tmp_path / "state"


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    tree = tmp_path / "edge"
    tree.mkdir()
    (tree / "fleet.yaml").write_text(FLEET)
    return tree


@pytest.fixture
def docker(home: Path, state: Path) -> ScriptedDocker:
    return ScriptedDocker(state, home / "srv" / KEY)


@pytest.fixture
def runtime(home: Path, state: Path, docker: ScriptedDocker) -> apps.AppRuntime:
    return runtime_of(home, state, docker)


@dataclasses.dataclass
class World:
    repository: Path
    state: Path
    srv: Path
    runtime: apps.AppRuntime
    docker: ScriptedDocker

    def plan(self) -> apps.AppsPlan:
        return apps.plan_apps(self.repository, self.fleet, self.runtime, self.marks)

    def run(self, plan: apps.AppsPlan | None = None) -> list[apps.AppResult]:
        """The result of each app's run."""
        planned = plan or self.plan()
        return list(planned.run(self.marks, self.progress))

    def held_off_causes(self, plan: apps.AppsPlan | None = None) -> list[str]:
        """The causes of the runs a stop won; fails when any other result came."""
        results = self.run(plan)
        assert all(isinstance(result, apps.AppHeldOff) for result in results)
        return [result.cause for result in results]

    def deployed(self) -> dict[str, str] | None:
        record = self.state / "deployed" / KEY
        return json.loads(record.read_text()) if record.exists() else None

    marks: switches.Switches = dataclasses.field(init=False)
    progress: Progress = dataclasses.field(default_factory=Progress)
    fleet: Fleet = EDGE_FLEET

    def __post_init__(self) -> None:
        self.marks = switches.Switches(self.state)


@pytest.fixture
def world(repository, state, home, runtime, docker) -> World:
    return World(repository, state, home / "srv" / KEY, runtime, docker)


def deploy(world: World, origin: Origin, tag: str, files: dict[str, str] | None = None) -> str:
    """The app switched on at a new release `tag`, healthy and recorded; its sha."""
    sha = origin.release(tag, files)
    [result] = world.run()
    assert isinstance(result, apps.AppOn)
    assert world.deployed()["sha"] == sha
    return sha


PRIVACY_FILE = "legal/datenschutz.html"


@dataclasses.dataclass
class LegalApps:
    """The app of `app_world` beside an enabled legal unit that builds the pages from the
    repository's own frame and general part, and how its releases carry the app's own text."""

    world: AppWorld

    @property
    def origin(self) -> Origin:
        return self.world.origin

    def catalog(self, *, enabled: bool) -> None:
        app = FLEET.replace("run: {enabled: true}", f"run: {{enabled: {str(enabled).lower()}}}")
        legal = "  legal:\n    run: {enabled: true}\n"
        write_fleet(self.world.repository, f"cloudflare:\n  zone: {ZONE}\n{app}{legal}")

    def release(self, tag: str, privacy: str | None = None) -> str:
        """A release `tag`, its privacy file `privacy` or the previous release's; its sha."""
        files = {"release": tag} | ({PRIVACY_FILE: privacy} if privacy is not None else {})
        return self.origin.release(tag, files)

    def deploy(self, tag: str, privacy: str) -> str:
        """The app switched on at a release `tag` carrying `privacy`; its sha."""
        sha = self.release(tag, privacy)
        self.catalog(enabled=True)
        assert self.world.apply()[0] == 0
        return sha

    def page(self, name: str = "datenschutz") -> str:
        return (self.world.repository / "legal/built" / f"{name}.html").read_text()

    def stop(self) -> None:
        """The app as `hal stop` leaves it: its marker, its containers exited."""
        switches.Switches(self.world.state).record(KEY, NOW)
        for row in self.world.docker.rows:
            row["State"], row["Health"] = "exited", ""

    def dated_release(self, tag: str, privacy: str, when: str) -> None:
        """A release `tag` carrying `privacy`, its commit dated `when` (ISO 8601)."""
        work = self.origin.work
        (work / PRIVACY_FILE).parent.mkdir(parents=True, exist_ok=True)
        (work / PRIVACY_FILE).write_text(privacy)
        plain = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
        dated = plain | {"GIT_AUTHOR_DATE": when, "GIT_COMMITTER_DATE": when}
        no_hooks = ["-c", "core.hooksPath=/dev/null"]
        for arguments in (["add", "--all"], [*no_hooks, "commit", "--quiet", "-m", tag]):
            subprocess.run(
                ["git", "-C", str(work), *arguments],
                check=True, capture_output=True, stdin=subprocess.DEVNULL, env=dated,
            )  # fmt: skip
        self.origin.push("master")
        self.origin.tag(tag)


@pytest.fixture
def legal_apps(app_world: AppWorld) -> LegalApps:
    """The legal unit enabled and the app in the catalog, disabled and never released; the pages
    built once, without the app's block."""
    tree = app_world.repository
    shutil.copytree(REPOSITORY / "legal/frame", tree / "legal/frame")
    shutil.copytree(REPOSITORY / "legal/sections/allgemein", tree / "legal/sections/allgemein")
    (tree / "legal/built").mkdir()
    (tree / "legal/built/.gitkeep").touch()
    app_world.scripted.config["services"]["legal"] = {
        "image": "nginxinc/nginx-unprivileged:test",
        "restart": "unless-stopped",
        "profiles": ["legal"],
    }
    world = LegalApps(app_world)
    world.catalog(enabled=False)
    shutil.rmtree(tree / ".git")
    committed_main(tree)
    assert app_world.apply()[0] == 0
    return world
