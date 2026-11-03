"""The owner of the API numbers (#889): per number an app's own table, else `[api]`, else the code
default; the person budget `[api]`'s, else the code default."""

import pytest

from hal.stack import api_limits
from hal.stack.api_limits import ApiSettings, AppLimits, AppNumbers

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
