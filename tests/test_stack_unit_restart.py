"""What a run starts of a unit whose service reads its own database."""

import pytest
from support.stack_plan_rows import STEP_CA, unit_plan

from hal.stack.catalog import Unit
from hal.stack.realm import reconcile
from hal.stack.unit_plans import Action, Recreate, Restart, UnitPlan, restart_of

REALM = reconcile.REALM
REALM_UNIT = Unit(REALM.unit, True, None)


def realm_plan(action: Action) -> UnitPlan:
    return unit_plan(action, unit=REALM_UNIT)


@pytest.mark.parametrize(
    ("plans", "recreates", "expected"),
    [
        pytest.param([realm_plan(Action.ON)], [], Restart.SERVICE, id="the unit is switched on"),
        pytest.param(
            [],
            [Recreate(REALM.unit, REALM.service)],
            Restart.SERVICE,
            id="the service is recreated",
        ),
        pytest.param(
            [],
            [Recreate(REALM.unit, REALM.database)],
            Restart.DATABASE,
            id="only the database is recreated",
        ),
        pytest.param(
            [],
            [Recreate(REALM.unit, REALM.database), Recreate(REALM.unit, REALM.service)],
            Restart.SERVICE,
            id="the database and the service are recreated",
        ),
        pytest.param([realm_plan(Action.OFF)], [], None, id="the unit is switched off"),
        pytest.param([unit_plan(Action.ON)], [], None, id="another unit is switched on"),
        pytest.param(
            [],
            [Recreate(STEP_CA.key, REALM.service), Recreate(STEP_CA.key, REALM.database)],
            None,
            id="another unit's services are recreated",
        ),
        pytest.param([], [], None, id="nothing starts"),
    ],
)
def test_a_run_starts_the_service_or_only_the_database_of_the_unit(
    plans: list[UnitPlan], recreates: list[Recreate], expected: Restart | None
) -> None:
    assert restart_of(plans, recreates, REALM) is expected
