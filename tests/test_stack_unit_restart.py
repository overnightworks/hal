"""What a run starts of a unit whose service reads its own database."""

from collections.abc import Callable
from pathlib import Path

import pytest
import yaml
from support.stack_plan_rows import STEP_CA, unit_plan

from hal.stack import compose, litellm_keys
from hal.stack.catalog import Unit
from hal.stack.realm import reconcile
from hal.stack.unit_plans import Action, DatabaseUnit, Recreate, Restart, UnitPlan, restart_of

REPOSITORY = Path(__file__).resolve().parents[1]
RECORDS = [reconcile.KEYCLOAK, litellm_keys.LITELLM]

type Run = Callable[[DatabaseUnit], tuple[list[UnitPlan], list[Recreate]]]


def own_plan(unit: DatabaseUnit, action: Action) -> UnitPlan:
    return unit_plan(action, unit=Unit(unit.key, True, None))


@pytest.fixture
def shipped_profiles() -> dict[str, tuple[str, ...]]:
    return compose.profile_services(yaml.safe_load((REPOSITORY / "compose.yaml").read_text()))


@pytest.mark.parametrize("unit", RECORDS, ids=lambda unit: unit.key)
@pytest.mark.parametrize(
    ("run", "expected"),
    [
        pytest.param(
            lambda unit: ([own_plan(unit, Action.ON)], []),
            Restart.SERVICE,
            id="the unit is switched on",
        ),
        pytest.param(
            lambda unit: ([], [Recreate(unit.key, unit.service)]),
            Restart.SERVICE,
            id="the service is recreated",
        ),
        pytest.param(
            lambda unit: ([], [Recreate(unit.key, unit.database)]),
            Restart.DATABASE,
            id="only the database is recreated",
        ),
        pytest.param(
            lambda unit: (
                [],
                [Recreate(unit.key, unit.database), Recreate(unit.key, unit.service)],
            ),
            Restart.SERVICE,
            id="the database and the service are recreated",
        ),
        pytest.param(
            lambda unit: ([own_plan(unit, Action.OFF)], []),
            None,
            id="the unit is switched off",
        ),
        pytest.param(
            lambda unit: ([unit_plan(Action.ON)], []), None, id="another unit is switched on"
        ),
        pytest.param(
            lambda unit: (
                [],
                [Recreate(STEP_CA.key, unit.service), Recreate(STEP_CA.key, unit.database)],
            ),
            None,
            id="another unit's services are recreated",
        ),
        pytest.param(
            lambda unit: ([], [Recreate(unit.key, "another-service")]),
            None,
            id="another service of the unit is recreated",
        ),
        pytest.param(lambda unit: ([], []), None, id="nothing starts"),
    ],
)
def test_a_run_starts_the_service_or_only_the_database_of_the_unit(
    unit: DatabaseUnit, run: Run, expected: Restart | None
) -> None:
    plans, recreates = run(unit)
    assert restart_of(plans, recreates, unit) is expected


@pytest.mark.parametrize("unit", RECORDS, ids=lambda unit: unit.key)
def test_the_service_and_the_database_of_the_unit_are_services_of_its_profile(
    unit: DatabaseUnit, shipped_profiles: dict[str, tuple[str, ...]]
) -> None:
    assert {unit.service, unit.database} <= set(shipped_profiles[unit.key])
