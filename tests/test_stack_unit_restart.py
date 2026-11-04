"""What a run starts of a unit whose service reads its own database."""

from pathlib import Path

import pytest
import yaml
from support.stack_plan_rows import STEP_CA, unit_plan

from hal.stack import compose
from hal.stack.catalog import Unit
from hal.stack.realm import reconcile
from hal.stack.unit_plans import Action, Recreate, Restart, UnitPlan, restart_of

KEYCLOAK = reconcile.KEYCLOAK
KEYCLOAK_CATALOG_UNIT = Unit(KEYCLOAK.key, True, None)
REPOSITORY = Path(__file__).resolve().parents[1]


def realm_plan(action: Action) -> UnitPlan:
    return unit_plan(action, unit=KEYCLOAK_CATALOG_UNIT)


@pytest.fixture
def shipped_profiles() -> dict[str, tuple[str, ...]]:
    return compose.profile_services(yaml.safe_load((REPOSITORY / "compose.yaml").read_text()))


@pytest.mark.parametrize(
    ("plans", "recreates", "expected"),
    [
        pytest.param([realm_plan(Action.ON)], [], Restart.SERVICE, id="the unit is switched on"),
        pytest.param(
            [],
            [Recreate(KEYCLOAK.key, KEYCLOAK.service)],
            Restart.SERVICE,
            id="the service is recreated",
        ),
        pytest.param(
            [],
            [Recreate(KEYCLOAK.key, KEYCLOAK.database)],
            Restart.DATABASE,
            id="only the database is recreated",
        ),
        pytest.param(
            [],
            [Recreate(KEYCLOAK.key, KEYCLOAK.database), Recreate(KEYCLOAK.key, KEYCLOAK.service)],
            Restart.SERVICE,
            id="the database and the service are recreated",
        ),
        pytest.param([realm_plan(Action.OFF)], [], None, id="the unit is switched off"),
        pytest.param([unit_plan(Action.ON)], [], None, id="another unit is switched on"),
        pytest.param(
            [],
            [Recreate(STEP_CA.key, KEYCLOAK.service), Recreate(STEP_CA.key, KEYCLOAK.database)],
            None,
            id="another unit's services are recreated",
        ),
        pytest.param(
            [],
            [Recreate(KEYCLOAK.key, "another-service")],
            None,
            id="another service of the unit is recreated",
        ),
        pytest.param([], [], None, id="nothing starts"),
    ],
)
def test_a_run_starts_the_service_or_only_the_database_of_the_unit(
    plans: list[UnitPlan], recreates: list[Recreate], expected: Restart | None
) -> None:
    assert restart_of(plans, recreates, KEYCLOAK) is expected


def test_the_service_and_the_database_of_the_unit_are_services_of_its_profile(
    shipped_profiles: dict[str, tuple[str, ...]],
) -> None:
    assert {KEYCLOAK.service, KEYCLOAK.database} <= set(shipped_profiles[KEYCLOAK.key])
