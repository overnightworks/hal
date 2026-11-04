"""The key step plans with the numbers of the operator's record (#889): which number reaches which
row, and an app table naming no app the one-off read."""

import pytest
from support.stack_litellm_found import APPS, BUDGET_ID, changed_fields, found

from hal.stack import litellm_keys
from hal.stack.api_limits import ApiSettings, AppNumbers


def test_a_number_the_record_changes_is_sent_alone_and_never_with_a_period() -> None:
    api = ApiSettings(AppNumbers(4.0, 3), {"hopin": AppNumbers(budget_dollars=6.0)}, 1.5)

    plan = litellm_keys.planned(found(), BUDGET_ID, api)

    assert {change.subject: changed_fields(change) for change in plan.changes} == {
        BUDGET_ID: {"max_budget": 1.5},
        "hopin": {"max_budget": 6.0, "max_parallel_requests": 3},
        "presentator": {"max_budget": 4.0, "max_parallel_requests": 3},
        "songmaker": {"max_budget": 4.0, "max_parallel_requests": 3},
    }


def test_an_app_table_naming_no_app_read_cannot_be_planned_and_names_the_apps_read() -> None:
    api = ApiSettings(apps={"hopn": AppNumbers(budget_dollars=1.0)})
    rows = found()

    with pytest.raises(litellm_keys.UnknownApps) as raised:
        litellm_keys.planned(rows, BUDGET_ID, api)

    assert "[api.hopn]" in str(raised.value)
    assert all(app in str(raised.value) for app in APPS)


def test_an_app_whose_name_is_taken_gets_no_change_whatever_its_table_says() -> None:
    api = ApiSettings(apps={"hopin": AppNumbers(budget_dollars=6.0)})

    plan = litellm_keys.planned(found(taken=("hopin",)), BUDGET_ID, api)

    assert plan.changes == ()
    assert plan.name_taken == ("hopin",)
