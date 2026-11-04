"""The key step's gate: it reads only while the unit `litellm` is on and this run neither starts
LiteLLM nor recreates it or its database."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from support.stack_plan_rows import unit_plan

from hal.stack import api_limits, compose, core, litellm_keys
from hal.stack.catalog import Unit
from hal.stack.litellm_keys import LITELLM, KeysPlan, KeysStep
from hal.stack.realm.reconcile import REALM_UNIT
from hal.stack.unit_plans import Action, Recreate, Restart, UnitPlan

REPOSITORY = Path(__file__).resolve().parents[1]
RUNNING = {service: {"running"} for service in (LITELLM.service, LITELLM.database, "litellm-front")}
EMPTY_READ = json.dumps({"apps": {}, "budget": None, "models": [], "admin": None})


@dataclass
class Runner:
    """Compose's runner: the key step's one-off reads an empty LiteLLM; it records what ran."""

    commands: list[list[str]] = field(default_factory=list)

    def __call__(
        self, command: list[str], _timeout: int, _stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        return subprocess.CompletedProcess(command, 0, EMPTY_READ, "")


def switched_on() -> UnitPlan:
    return unit_plan(Action.ON, unit=Unit(LITELLM.key, True, None))


@pytest.mark.parametrize(
    ("gate", "plans", "recreates", "expected"),
    [
        pytest.param(None, [], [], None, id="no unit litellm in the catalog"),
        pytest.param(core.Gate.OFF, [], [], None, id="off with its containers running"),
        pytest.param(
            core.Gate.SWITCHED_OFF, [], [], None, id="switched off with its containers running"
        ),
        pytest.param(core.Gate.ON, [switched_on()], [], Restart.SERVICE, id="switched on"),
        pytest.param(
            core.Gate.ON,
            [],
            [Recreate(LITELLM.key, LITELLM.service)],
            Restart.SERVICE,
            id="litellm recreated",
        ),
        pytest.param(
            core.Gate.ON,
            [],
            [Recreate(LITELLM.key, LITELLM.database)],
            Restart.DATABASE,
            id="litellm-db recreated",
        ),
        pytest.param(core.Gate.ON, [], [], KeysPlan, id="on and running"),
    ],
)
def test_the_step_reads_only_while_the_unit_is_on_and_this_run_starts_neither_service(
    gate: core.Gate | None,
    plans: list[UnitPlan],
    recreates: list[Recreate],
    expected: Restart | type[KeysPlan] | None,
) -> None:
    runner = Runner()
    gates = {REALM_UNIT: core.Gate.OFF} | ({} if gate is None else {LITELLM.key: gate})
    step: KeysStep = litellm_keys.plan_keys(
        compose.Compose(run=runner, repository=REPOSITORY),
        RUNNING,
        REPOSITORY,
        api_limits.NONE_SET,
        gates,
        plans,
        recreates,
    )

    assert (KeysPlan if isinstance(step, KeysPlan) else step) == expected
    assert litellm_keys.reads(step) is (expected is KeysPlan)
    ran = [command for command in runner.commands if litellm_keys.KEYS_SERVICE in command]
    assert bool(ran) is (expected is KeysPlan)
