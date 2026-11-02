"""What the `test_stack_apps` tests share with other test modules."""

import dataclasses
import json
from pathlib import Path

import pytest
import support.throwaway_home as throwaway_home
from support.app_support import (
    FLEET,
    KEY,
    Origin,
    ScriptedDocker,
    origin_at,
    runtime_of,
)

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
