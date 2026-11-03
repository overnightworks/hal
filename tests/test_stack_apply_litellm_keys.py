"""`hal apply`'s key step (#964): its rows in the one question, its run after the realm step and
before the apps, and every ending of the item's table "How the run ends"."""

import re
import subprocess

import pytest
import yaml
from support.stack_apply import (
    DISABLED,
    ENABLED,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    write_fleet,
)
from support.stack_apply_apps import (
    RELEASE,
    app_world,  # noqa: F401 the fixture, requested by name below
)
from support.stack_apply_fakes import ScriptedCompose
from support.stack_plan_rows import find_row, plain

from hal.stack import litellm_keys
from hal.stack.plan_rows import KeysEvent, PlanGroup
from hal.stack.result_rows import ResultEvent

APPS = ("hopin", "presentator", "songmaker")
BUDGET_ID = "scenario-budget"


def lines_of(text: str) -> list[str]:
    return plain(text).splitlines()


def desired_row(app: str, models: tuple[str, ...]) -> dict:
    desired = litellm_keys.desired_key(app, models)
    return {
        name: list(value) if isinstance(value, tuple) else value for name, value in desired.items()
    }


@pytest.fixture
def keys(repository, scripted: ScriptedCompose):  # noqa: F811
    """LiteLLM running beside a disabled fleet, its config naming the budget id; every key and the
    person budget as desired, so the step alone has nothing to change."""
    write_fleet(repository, DISABLED)
    config = repository / litellm_keys.CONFIG_FILE
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        yaml.safe_dump({"litellm_settings": {litellm_keys.BUDGET_ID_SETTING: BUDGET_ID}})
    )
    scripted.config["services"][litellm_keys.LITELLM_SERVICE] = {"profiles": ["litellm"]}
    scripted.put_containers({litellm_keys.LITELLM_SERVICE: "running"})
    scripted.keys.rows = {app: desired_row(app, scripted.keys.models) for app in APPS}
    scripted.keys.budget = dict(litellm_keys.desired_budget())
    return scripted.keys


def with_other_change(repository) -> None:  # noqa: F811
    write_fleet(repository, ENABLED)


def test_no_row_and_no_one_off_while_litellm_neither_runs_nor_starts(switch, scripted, repository):  # noqa: F811
    write_fleet(repository, DISABLED)

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert "nothing to change" in out
    assert not [call for call in scripted.calls if litellm_keys.KEYS_SERVICE in call]
    assert PlanGroup.LITELLM not in plain(out)


def test_keys_as_desired_are_nothing_to_change_and_write_nothing(switch, keys):  # noqa: F811
    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert "nothing to change" in out
    assert keys.writes == []


def test_the_plan_names_the_person_budget_and_each_new_key_and_the_run_makes_them_in_order(
    switch,  # noqa: F811
    keys,
):
    keys.rows = dict.fromkeys(APPS)
    keys.budget = None

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    plan, _, result = plain(out).partition("Type yes")
    assert "apply 4 changes" in plain(out)
    assert find_row(plan, BUDGET_ID, KeysEvent.NEW_BUDGET)
    assert all(find_row(plan, app, KeysEvent.NEW_KEY) for app in APPS)
    assert [(change["target"], change["subject"]) for change in keys.writes[0]] == [
        ("budget", BUDGET_ID),
        *(("key", app) for app in APPS),
    ]
    assert all(find_row(result, app, KeysEvent.NEW_KEY) for app in APPS)
    assert switch()[0] == 0
    assert len(keys.writes) == 1


def test_a_changed_number_shows_its_old_and_new_value(switch, keys):  # noqa: F811
    keys.rows["songmaker"] |= {"max_budget": 7.0, "rpm_limit": 60}

    exit_code, out, _ = switch()

    assert exit_code == 0
    row = find_row(plain(out).partition("Type yes")[0], "songmaker", KeysEvent.KEY_CHANGED)
    assert row
    assert f"7 → {litellm_keys.APP_BUDGET_DOLLARS:g}" in row.group(0)
    assert "60 → none" in row.group(0)
    assert keys.writes == [
        [
            {
                "target": "key",
                "subject": "songmaker",
                "new": False,
                "fields": {"max_budget": litellm_keys.APP_BUDGET_DOLLARS, "rpm_limit": None},
            }
        ]
    ]


def test_keys_not_read_with_nothing_else_to_change_ask_nothing_and_refuse(switch, keys):  # noqa: F811
    keys.read_fails = True

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "Type yes" not in plain(out)
    assert find_row(plain(out), PlanGroup.LITELLM, KeysEvent.NOT_READ)
    assert lines_of(err) == [
        "error: litellm: keys not read (`docker compose run` exited 1: "
        "litellm-keys: status 502 at /v2/key/info)",
        "next: hal apply",
    ]


def test_keys_not_read_beside_another_change_are_skipped_after_the_one_yes(
    switch,  # noqa: F811
    keys,
    repository,  # noqa: F811
    scripted,  # noqa: F811
):
    keys.read_fails = True
    with_other_change(repository)

    exit_code, out, err = switch()

    assert exit_code == 1
    assert plain(out).count("Type yes") == 1
    assert "up" in scripted.changing_verbs()
    assert find_row(
        plain(out).partition("Type yes")[2], PlanGroup.LITELLM, ResultEvent.KEYS_SKIPPED
    )
    assert lines_of(err) == ["error: partial, litellm keys skipped", "next: hal apply"]


def test_a_taken_name_beside_another_change_writes_nothing_for_that_app_and_ends_partial(
    switch,  # noqa: F811
    keys,
    repository,  # noqa: F811
):
    keys.rows["hopin"] = None
    keys.taken = {"hopin"}
    keys.rows["songmaker"] |= {"max_parallel_requests": 2}
    with_other_change(repository)

    exit_code, out, err = switch()

    assert exit_code == 1
    plan, _, result = plain(out).partition("Type yes")
    assert re.search(r"^  ! hopin +name taken", plan, re.M)
    assert [change["subject"] for change in keys.writes[0]] == ["songmaker"]
    assert re.search(r"^  ! hopin +name taken", result, re.M)
    assert lines_of(err) == ["error: partial, hopin name taken"]


def test_a_taken_name_beside_a_unit_switch_alone_is_a_partial_end_with_nothing_written(
    switch,  # noqa: F811
    keys,
    repository,  # noqa: F811
):
    keys.rows["hopin"] = None
    keys.taken = {"hopin"}
    with_other_change(repository)

    exit_code, out, err = switch()

    assert exit_code == 1
    assert re.search(r"^  ! hopin +name taken", plain(out).partition("Type yes")[2], re.M)
    assert keys.writes == []
    assert lines_of(err) == ["error: partial, hopin name taken"]


def test_the_key_step_writes_before_the_apps_are_started(
    keys,
    app_world,  # noqa: F811
):
    app_world.origin.release(RELEASE)
    keys.rows["hopin"] = None
    started_before_the_write = []
    keyed = keys.run

    def recording(command, arguments, stdin):
        if "--write" in arguments:
            started_before_the_write.extend(app_world.docker.verbs)
        return keyed(command, arguments, stdin)

    keys.run = recording

    exit_code, _, err = app_world.apply()

    assert (exit_code, err) == (0, "")
    assert keys.writes
    assert "create" not in started_before_the_write
    assert "create" in app_world.docker.verbs


def test_a_taken_name_with_nothing_else_to_change_asks_nothing_and_names_it(switch, keys):  # noqa: F811
    keys.rows["hopin"] = None
    keys.taken = {"hopin"}

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "Type yes" not in plain(out)
    assert keys.writes == []
    assert lines_of(err) == ["error: litellm: hopin name taken; nothing changed"]


def test_a_failed_write_stops_the_step_and_names_it_and_every_change_not_made(
    switch,  # noqa: F811
    keys,
):
    keys.rows = dict.fromkeys(APPS)
    keys.budget = None
    keys.fail_at = 1
    keys.cause = "name taken"

    exit_code, out, err = switch()

    assert exit_code == 1
    result = plain(out).partition("Type yes")[2]
    assert re.search(rf"^  ✓ {BUDGET_ID} +{KeysEvent.NEW_BUDGET}", result, re.M)
    assert re.search(r"^  ✗ hopin +new key +name taken", result, re.M)
    assert all(
        re.search(rf"^  · {app} +{ResultEvent.NOT_MADE} +new key", result, re.M)
        for app in ("presentator", "songmaker")
    )
    assert lines_of(err) == ["error: partial, hopin new key failed", "next: hal apply"]
    assert keys.rows["songmaker"] is None


def test_a_write_the_one_off_could_not_finish_is_a_failed_step(switch, keys, scripted):  # noqa: F811
    keys.rows["hopin"] = None
    plan_then_fail = scripted.keys.run

    def failing(command, arguments, stdin):
        if "--write" in arguments:
            return subprocess.CompletedProcess(command, 130, "", "litellm-keys: stopped\n")
        return plan_then_fail(command, arguments, stdin)

    scripted.keys.run = failing  # type: ignore[method-assign]

    exit_code, out, err = switch()

    assert exit_code == 1
    assert re.search(
        r"^  ✗ litellm +keys failed +`docker compose run` exited 130: litellm-keys: stopped",
        plain(out),
        re.M,
    )
    assert lines_of(err) == ["error: partial, litellm keys failed", "next: hal apply"]
