"""The owner of the API numbers (#889): per number an app's own table, else `[api]`, else the code
default; the person budget `[api]`'s, else the code default. And of the log depth's variables,
which compose.yaml hands to LiteLLM (#1084)."""

import json
from collections.abc import Mapping
from functools import partial
from pathlib import Path

import pytest

from hal.stack import api_limits, compose
from hal.stack.api_limits import ApiSettings, AppLimits, AppNumbers, LogDepth

DEFAULT_LIMITS = AppLimits(api_limits.APP_BUDGET_DOLLARS, api_limits.MAX_PARALLEL_REQUESTS)


@pytest.mark.parametrize(
    ("settings", "hopin", "presentator", "person"),
    [
        pytest.param(
            api_limits.NONE_SET,
            DEFAULT_LIMITS,
            DEFAULT_LIMITS,
            api_limits.PERSON_BUDGET_DOLLARS,
            id="nothing set gives the code defaults",
        ),
        pytest.param(
            ApiSettings(AppNumbers(4.0, 3), person_budget_dollars=1.5),
            AppLimits(4.0, 3),
            AppLimits(4.0, 3),
            1.5,
            id="[api] alone sets every app and the person",
        ),
        pytest.param(
            ApiSettings(AppNumbers(4.0, 3), {"hopin": AppNumbers(budget_dollars=6.0)}),
            AppLimits(6.0, 3),
            AppLimits(4.0, 3),
            api_limits.PERSON_BUDGET_DOLLARS,
            id="an app table setting one number takes the other from [api]",
        ),
        pytest.param(
            ApiSettings(apps={"hopin": AppNumbers(max_parallel_requests=1)}),
            AppLimits(api_limits.APP_BUDGET_DOLLARS, 1),
            DEFAULT_LIMITS,
            api_limits.PERSON_BUDGET_DOLLARS,
            id="an app table setting one number takes the other from the code default",
        ),
        pytest.param(
            ApiSettings(AppNumbers(4.0, 3), {"hopin": AppNumbers(0.0, 0)}, 0.0),
            AppLimits(0.0, 0),
            AppLimits(4.0, 3),
            0.0,
            id="zero is a number, not nothing set",
        ),
    ],
)
def test_each_number_is_the_app_tables_else_the_api_tables_else_the_code_default(
    settings: ApiSettings, hopin: AppLimits, presentator: AppLimits, person: float
) -> None:
    assert (
        settings.limits_of("hopin"),
        settings.limits_of("presentator"),
        settings.person_budget(),
    ) == (hopin, presentator, person)


ROOT = Path(__file__).resolve().parents[1]
LITELLM_LEVEL, LITELLM_MESSAGE_LOGGING_OFF = "LITELLM_LOG", "HAL_TURN_OFF_MESSAGE_LOGGING"


@pytest.fixture
def compose_variables(monkeypatch) -> None:
    """The variables compose.yaml demands, and none of the log depth's from the shell."""
    monkeypatch.setenv("DOCKER_GID", "999")
    monkeypatch.setenv("EDGE_DOMAIN", "edge.test")
    for variable in api_limits.log_environment(LogDepth.METADATA):
        monkeypatch.delenv(variable, raising=False)


def litellm_environment(passed: Mapping[str, str]) -> dict[str, str]:
    """litellm's environment as `docker compose config` resolves compose.yaml with `passed`."""
    result = compose.run_docker(
        ["docker", "compose", "--project-directory", str(ROOT), "-f", str(ROOT / "compose.yaml"),
         "--profile", "litellm", "config", "--format", "json"],
        compose.READ_SECONDS,
        environment=passed,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)["services"]["litellm"]["environment"]


@pytest.mark.parametrize(
    ("passed", "depth"),
    [
        pytest.param(
            api_limits.log_environment(LogDepth.METADATA), LogDepth.METADATA, id="metadata"
        ),
        pytest.param(
            api_limits.log_environment(LogDepth.EVERYTHING), LogDepth.EVERYTHING, id="everything"
        ),
        pytest.param({}, LogDepth.METADATA, id="nothing passed logs at metadata"),
    ],
)
@pytest.mark.usefixtures("compose_variables")
def test_litellm_logs_at_the_depth_whose_variables_compose_is_given(passed, depth):
    environment = litellm_environment(passed)
    wanted = api_limits.log_environment(depth)

    assert environment[LITELLM_LEVEL] == wanted[api_limits.LOG_LEVEL_VARIABLE]
    assert (
        environment[LITELLM_MESSAGE_LOGGING_OFF] == wanted[api_limits.MESSAGE_LOGGING_OFF_VARIABLE]
    )


@pytest.mark.usefixtures("compose_variables")
def test_a_changed_log_depth_changes_the_definition_hash_the_plan_compares():
    hashes = {
        depth: compose.Compose(
            partial(compose.run_docker, environment=api_limits.log_environment(depth)), ROOT
        ).config_hashes(("litellm",))["litellm"]
        for depth in LogDepth
    }

    assert len(set(hashes.values())) == len(LogDepth)
