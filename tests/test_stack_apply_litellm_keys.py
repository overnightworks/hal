"""`hal apply`'s key step (#964, #965, #889): its rows in the one question, its run before the
apps, every ending of the item's table "How the run ends", the admin group's rows, and the
operator's numbers handed to it."""

import json
import re
import subprocess

import pytest
from agent_runtime_client.turn import Principal, person_fingerprint
from support.stack_apply import (
    APP_KEYS,
    DISABLED,
    ENABLED,
    LITELLM_ON,
    MASTER_KEY,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    litellm_running,
    realm_backup,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    secret_files,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    switch_off,
    write_fleet,
)
from support.stack_apply import (
    LITELLM_UNIT_SERVICES as UNIT_SERVICES,
)
from support.stack_apply_apps import (
    RELEASE,
    app_world,  # noqa: F401 the fixture, requested by name below
)
from support.stack_apply_fakes import ScriptedCompose
from support.stack_core import bind, sha256
from support.stack_litellm_found import APPS, BUDGET_ID
from support.stack_plan_rows import find_row, plain

from hal.stack import api_limits, core, litellm_keys
from hal.stack.api_limits import ApiSettings, AppNumbers
from hal.stack.apply import ApplyExit
from hal.stack.litellm_keys import ADMIN_BUDGET_ID, LITELLM
from hal.stack.plan_rows import KeysEvent, PlanEvent, PlanGroup
from hal.stack.realm.reconcile import KEYCLOAK_SERVICE
from hal.stack.result_rows import ResultEvent


def lines_of(text: str) -> list[str]:
    return plain(text).splitlines()


@pytest.fixture
def keys(repository, scripted: ScriptedCompose, secret_files):  # noqa: F811
    """The unit `litellm` on beside a disabled step-ca; see `litellm_running`."""
    write_fleet(repository, DISABLED + LITELLM_ON)
    return litellm_running(repository, scripted, secret_files)


def with_other_change(repository) -> None:  # noqa: F811
    write_fleet(repository, ENABLED + LITELLM_ON)


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
    assert f"7 → {api_limits.APP_BUDGET_DOLLARS:g}" in row.group(0)
    assert "60 → none" in row.group(0)
    assert keys.writes == [
        [
            {
                "target": "key",
                "subject": "songmaker",
                "new": False,
                "fields": {"max_budget": api_limits.APP_BUDGET_DOLLARS, "rpm_limit": None},
            }
        ]
    ]


def test_an_app_table_of_the_record_shows_its_change_and_writes_that_number_alone(switch, keys):  # noqa: F811
    exit_code, out, _ = switch(api=ApiSettings(apps={"hopin": AppNumbers(budget_dollars=6.0)}))

    assert exit_code == 0
    row = find_row(plain(out).partition("Type yes")[0], "hopin", KeysEvent.KEY_CHANGED)
    assert row
    assert f"{api_limits.APP_BUDGET_DOLLARS:g} → 6" in row.group(0)
    assert keys.writes == [
        [{"target": "key", "subject": "hopin", "new": False, "fields": {"max_budget": 6.0}}]
    ]


def test_an_app_table_naming_no_app_read_cannot_plan_and_asks_nothing(switch, keys):  # noqa: F811
    exit_code, out, err = switch(api=ApiSettings(apps={"hopn": AppNumbers(budget_dollars=1.0)}))

    assert exit_code == ApplyExit.CANNOT_PLAN
    assert "Type yes" not in plain(out)
    assert "cannot plan, [api.hopn] names no app" in plain(err)
    assert keys.writes == []


def test_keys_not_read_with_nothing_else_to_change_ask_nothing_and_refuse(switch, keys):  # noqa: F811
    keys.read_fails = True

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "Type yes" not in plain(out)
    assert find_row(plain(out), PlanGroup.LITELLM, KeysEvent.NOT_READ)
    assert lines_of(err) == [
        "error: litellm: keys not read (litellm-keys exited 1: "
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
    with (app_world.repository / "fleet.yaml").open("a") as fleet:
        fleet.write(LITELLM_ON)
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
        r"^  ✗ litellm +keys failed +litellm-keys exited 130: litellm-keys: stopped",
        plain(out),
        re.M,
    )
    assert lines_of(err) == ["error: partial, litellm keys failed", "next: hal apply"]


# --- the admin group's rows (#965) ---------------------------------------------------------------


KEYCLOAK_OFF = "services:\n  keycloak:\n    run: {enabled: false, setup: keycloak/init}\n"


def fingerprint_of(compose: ScriptedCompose, subject: str) -> str:
    return person_fingerprint(Principal(iss=compose.realm_issuer, sub=subject))


def admin_rows(keys) -> dict[str, str | None]:
    return {fingerprint: row["budget_id"] for fingerprint, row in keys.customers.items()}


def assert_no_value_printed(out: str, err: str, *values: str) -> None:
    assert not any(value in out + err for value in values)


def test_the_members_rows_are_linked_and_a_former_members_row_unlinked_after_the_one_yes(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
):
    """A2 and A5 through hal apply: one counted row, the writes, then nothing to change."""
    scripted.realm_members = ["subject-p"]
    member, former = fingerprint_of(scripted, "subject-p"), "fp-" + "0" * 64
    keys.customers = {former: {"budget_id": ADMIN_BUDGET_ID, "spend": 1.0}}

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    plan, _, result = plain(out).partition("Type yes")
    assert find_row(plan, ADMIN_BUDGET_ID, KeysEvent.CUSTOMER_ROWS, "1 linked · 1 unlinked")
    assert find_row(result, ADMIN_BUDGET_ID, KeysEvent.CUSTOMER_ROWS, "1 linked · 1 unlinked")
    assert admin_rows(keys) == {former: None, member: ADMIN_BUDGET_ID}
    assert_no_value_printed(out, err, member, former, "subject-p")
    again = switch()
    assert (again[0], "nothing to change" in again[1]) == (0, True)


@pytest.mark.parametrize(
    ("arrange", "cause"),
    [
        pytest.param(
            lambda compose: compose.containers.pop(KEYCLOAK_SERVICE),
            "Keycloak is not running",
            id="Keycloak not running",
        ),
        pytest.param(
            lambda compose: setattr(compose, "realm_members", None),
            "realm-observer exited 1: realm-observer: hallucinai has no group "
            + litellm_keys.ADMIN_GROUP,
            id="the group absent",
        ),
    ],
)
def test_members_not_read_with_nothing_else_to_change_ask_nothing_and_refuse_naming_keycloak(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    arrange,
    cause: str,
):
    """A4 and A8: the rows stay, the run ends exit 1 naming Keycloak."""
    linked = {"fp-" + "0" * 64: {"budget_id": ADMIN_BUDGET_ID, "spend": 1.0}}
    keys.customers = dict(linked)
    arrange(scripted)

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "Type yes" not in plain(out)
    assert find_row(plain(out), ADMIN_BUDGET_ID, KeysEvent.MEMBERS_NOT_READ, cause)
    assert lines_of(err) == [
        f"error: {ADMIN_BUDGET_ID}: members not read from Keycloak ({cause})",
        "next: hal apply",
    ]
    assert (keys.writes, keys.customers) == ([], linked)


def test_members_not_read_beside_a_key_change_make_the_key_and_end_partial_naming_keycloak(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
):
    """A4 with a key change: the key is made, the rows stay, exit 1."""
    scripted.containers.pop(KEYCLOAK_SERVICE)
    keys.rows["hopin"] = None
    linked = {"fp-" + "0" * 64: {"budget_id": ADMIN_BUDGET_ID, "spend": 1.0}}
    keys.customers = dict(linked)

    exit_code, out, err = switch()

    assert exit_code == 1
    result = plain(out).partition("Type yes")[2]
    assert find_row(result, "hopin", KeysEvent.NEW_KEY)
    assert find_row(result, ADMIN_BUDGET_ID, KeysEvent.MEMBERS_NOT_READ)
    assert lines_of(err) == [
        f"error: partial, {ADMIN_BUDGET_ID} members not read from Keycloak",
        "next: hal apply",
    ]
    assert [change["subject"] for change in keys.writes[0]] == ["hopin"]
    assert keys.customers == linked


@pytest.mark.parametrize(
    ("running", "realm_changed"),
    [
        pytest.param(False, False, id="Keycloak off, the realm unchanged"),
        pytest.param(False, True, id="Keycloak off, the realm changed"),
        pytest.param(True, False, id="a running Keycloak switched off by this run"),
    ],
)
def test_keycloak_held_holds_the_admin_rows_with_a_row_and_leaves_the_ending_as_it_is(
    switch,  # noqa: F811
    realm_unit,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    repository,  # noqa: F811
    running: bool,
    realm_changed: bool,
):
    """Decision 13: no members read, no customer change, a held row and exit 0."""
    write_fleet(repository, KEYCLOAK_OFF + LITELLM_ON)
    if not running:
        scripted.containers.pop(KEYCLOAK_SERVICE)
    if realm_changed:
        (repository / "keycloak/realm.yaml").write_text("realm: changed\n")
    scripted.realm_members = ["subject-p"]

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert find_row(plain(out), ADMIN_BUDGET_ID, KeysEvent.ROWS_HELD, "Keycloak is off")
    assert not [call for call in scripted.calls if "--members" in call]
    assert (keys.writes, keys.customers) == ([], {})


# --- the gate: the unit off, stopped, starting or recreated ------------------------------------


def one_offs(scripted: ScriptedCompose) -> list[list[str]]:  # noqa: F811
    return [call for call in scripted.calls if litellm_keys.KEYS_SERVICE in call]


def key_step_rows(text: str) -> list[str]:
    """The rows the key step prints under `litellm`, none of a unit or a service."""
    return re.findall(r"^  \S litellm +keys .*$", plain(text), re.M)


def switched_on(scripted: ScriptedCompose) -> None:  # noqa: F811
    for service in UNIT_SERVICES:
        scripted.containers.pop(service)


@pytest.mark.parametrize(
    ("arrange", "reason"),
    [
        pytest.param(switched_on, "LiteLLM starts now", id="switched on"),
        pytest.param(
            lambda compose: compose.change_definition(LITELLM.service),
            "LiteLLM starts now",
            id="litellm recreated",
        ),
        pytest.param(
            lambda compose: compose.change_definition(LITELLM.database),
            "its database restarts now",
            id="litellm-db recreated",
        ),
    ],
)
def test_a_run_that_starts_litellm_or_its_database_plans_the_keys_for_the_next_apply(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    arrange,
    reason: str,
):
    keys.rows["hopin"] = None
    arrange(scripted)

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    plan, _, result = plain(out).partition("Type yes")
    assert find_row(plan, LITELLM.key, KeysEvent.LATER, f"{reason} · next apply checks them")
    assert not find_row(plan, "hopin", KeysEvent.NEW_KEY)
    assert (one_offs(scripted), keys.writes) == ([], [])
    assert key_step_rows(result) == []


def test_a_first_start_with_an_app_key_file_absent_is_not_refused(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    secret_files,  # noqa: F811
):
    switched_on(scripted)
    secret_files[APP_KEYS[0]].unlink()

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert find_row(plain(out), LITELLM.key, KeysEvent.LATER)


def test_a_switch_off_reads_no_keys_and_removes_the_containers_keeping_the_volume(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    keys.rows["hopin"] = None
    write_fleet(repository, DISABLED + "  litellm:\n    run: {enabled: false}\n")

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    plan, _, result = plain(out).partition("Type yes")
    assert find_row(plan, LITELLM.key, PlanEvent.SWITCH_OFF, "volumes litellm-db kept")
    assert key_step_rows(plan) == []
    assert (one_offs(scripted), keys.writes) == ([], [])
    assert find_row(result, "litellm", ResultEvent.SWITCHED_OFF)


def test_a_stop_that_keeps_litellm_off_reads_no_keys_and_changes_nothing(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    keys.rows["hopin"] = None
    switch_off(state, unit=LITELLM.key)

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert find_row(plain(out), LITELLM.key, PlanEvent.STAYS_STOPPED)
    assert "nothing to change" in out
    assert one_offs(scripted) == []


def test_a_litellm_that_restarts_in_a_loop_after_it_was_on_ends_partial_without_a_read(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
):
    """B3: `up --no-recreate` leaves the looping container as it is."""
    scripted.containers[LITELLM.service] = "restarting"

    exit_code, out, err = switch()

    assert exit_code == ApplyExit.REFUSED
    plan = plain(out).partition("Type yes")[0]
    assert find_row(plan, LITELLM.key, PlanEvent.SWITCH_ON)
    assert find_row(plan, LITELLM.key, KeysEvent.LATER, "LiteLLM starts now")
    assert one_offs(scripted) == []
    assert lines_of(err) == ["error: partial, litellm is not on after the change"]


@pytest.mark.parametrize("missing", [MASTER_KEY, APP_KEYS[0]], ids=["master key", "app key"])
def test_a_missing_file_of_the_one_off_refuses_the_run_before_the_question(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    secret_files,  # noqa: F811
    missing: str,
):
    """B2, decision 11: the read ran, so its files join the refusal before the yes."""
    keys.rows["hopin"] = None
    secret_files[missing].unlink()

    exit_code, out, err = switch()

    assert exit_code == ApplyExit.GUARD_REFUSED
    assert "Type yes" not in plain(out)
    assert lines_of(err) == [
        f"error: {litellm_keys.KEYS_SERVICE} needs {secret_files[missing]}; nothing switched",
        "next: hal setup",
    ]
    assert keys.writes == []


def test_a_recreate_of_the_front_alone_leaves_the_key_step_as_without_it(
    switch,  # noqa: F811
    keys,
    scripted,  # noqa: F811
    repository,  # noqa: F811
    state,  # noqa: F811
):
    """The front is a follower: its recreate never reaches the step's restart."""
    (repository / "front.yml").write_text("entryPoints: {}\n")
    scripted.config["services"]["litellm-front"]["volumes"] = [
        bind(repository / "front.yml", core.TRAEFIK_STATIC_CONFIG)
    ]
    state.mkdir(parents=True, exist_ok=True)
    (state / "applied.json").write_text(
        json.dumps({"litellm-front": {"front.yml": sha256(repository / "front.yml")}})
    )
    scripted.change_definition("litellm-front")
    keys.rows["hopin"] = None

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    plan, _, result = plain(out).partition("Type yes")
    assert find_row(plan, "litellm-front", PlanEvent.RECREATE)
    assert not find_row(plan, LITELLM.key, KeysEvent.LATER)
    assert find_row(plan, "hopin", KeysEvent.NEW_KEY)
    assert [change["subject"] for change in keys.writes[0]] == ["hopin"]
    assert find_row(result, "hopin", KeysEvent.NEW_KEY)
