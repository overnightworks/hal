"""The key step's host side (#964, #965, #889): the desired key, person budget and admin budget
from the numbers of the operator's record, the diff against what the one-off read, and the admin
group's members and their rows."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml
from agent_runtime_client import turn as client_turn
from agent_runtime_client.turn import Principal, person_fingerprint
from support.stack_litellm_found import (
    APPS,
    BUDGET_ID,
    HELD,
    MODELS,
    changed_fields,
    found,
    found_budget,
    found_key,
)

from hal.stack import api_limits, compose, core, litellm_keys
from hal.stack.api_limits import NONE_SET, ApiSettings, AppLimits, AppNumbers
from hal.stack.litellm_keys import (
    AdminFound,
    AdminHeld,
    Change,
    CustomerRow,
    FieldChange,
    Found,
    KeysPlan,
    KeysStep,
    NotRead,
    Target,
)
from hal.stack.realm import OBSERVER_SERVICE
from hal.stack.realm import observe as observer
from hal.stack.realm.declared import declared_realm
from hal.stack.realm.reconcile import KEYCLOAK_SERVICE, NO_MEMBERS, REALM_UNIT, MembersNotRead
from hal.stack.unit_plans import Recreate

ROOT = Path(__file__).resolve().parents[1]


def test_a_new_key_carries_its_app_as_name_its_numbers_and_every_model_litellm_lists() -> None:
    desired = litellm_keys.desired_key("hopin", MODELS, AppLimits(6.0, 3))

    assert desired == {
        "key_alias": "hopin",
        "max_budget": 6.0,
        "budget_duration": litellm_keys.BUDGET_DURATION,
        "models": MODELS,
        "allowed_routes": litellm_keys.ROUTES,
        "max_parallel_requests": 3,
        "rpm_limit": None,
        "tpm_limit": None,
    }


def test_the_person_budget_holds_its_dollars_for_the_period() -> None:
    assert litellm_keys.desired_budget(1.5) == {
        "max_budget": 1.5,
        "budget_duration": litellm_keys.BUDGET_DURATION,
    }


@pytest.mark.parametrize(
    ("row", "expected"),
    [
        pytest.param({}, None, id="an unchanged key changes nothing"),
        pytest.param(
            {"models": list(reversed(MODELS))}, None, id="models in another order change nothing"
        ),
        pytest.param({"max_budget": 10}, None, id="a whole-number budget equals its float"),
        pytest.param(
            {"max_budget": 7.0, "max_parallel_requests": 2},
            {"max_budget": 10.0, "max_parallel_requests": 5},
            id="a pure limit change",
        ),
        pytest.param(
            {"rpm_limit": 60, "tpm_limit": 1000},
            {"rpm_limit": None, "tpm_limit": None},
            id="a set rpm and tpm are cleared",
        ),
        pytest.param(
            {"key_alias": None}, {"key_alias": "hopin"}, id="a key without its name gets it"
        ),
        pytest.param(
            {"models": ["text/opus"]}, {"models": MODELS}, id="a model litellm lists now is added"
        ),
        pytest.param(
            {"allowed_routes": []},
            {"allowed_routes": litellm_keys.ROUTES},
            id="a key without its routes gets them",
        ),
    ],
)
def test_a_found_key_is_changed_in_exactly_the_fields_that_differ(
    row: dict, expected: dict | None
) -> None:
    plan = litellm_keys.planned(
        found(
            keys={app: found_key(app, **row) if app == "hopin" else found_key(app) for app in APPS}
        ),
        BUDGET_ID,
        NONE_SET,
    )

    hopin = [change for change in plan.changes if change.subject == "hopin"]
    if expected is None:
        assert hopin == []
    else:
        assert [(change.target, change.new) for change in hopin] == [(Target.KEY, False)]
        assert changed_fields(hopin[0]) == {
            name: (tuple(MODELS) if name == "models" else value) for name, value in expected.items()
        }


def test_a_pure_limit_change_sends_no_period_so_the_reset_stays() -> None:
    plan = litellm_keys.planned(
        found(
            keys={app: found_key(app, max_budget=7.0) for app in APPS},
            budget=found_budget(max_budget=1.5),
        ),
        BUDGET_ID,
        NONE_SET,
    )

    assert plan.changes
    assert all("budget_duration" not in change.wire()["fields"] for change in plan.changes)


def test_a_cleared_rpm_travels_as_null() -> None:
    plan = litellm_keys.planned(
        found(keys={app: found_key(app, rpm_limit=60) for app in APPS}), BUDGET_ID, NONE_SET
    )

    assert {json.dumps(change.wire()["fields"]) for change in plan.changes} == {
        '{"rpm_limit": null}'
    }


@pytest.mark.parametrize(
    ("keys", "taken", "new_keys", "conflicts"),
    [
        pytest.param({}, (), APPS, (), id="an absent key is new, so a deleted key is made anew"),
        pytest.param(
            {"songmaker": found_key("songmaker")},
            ("hopin",),
            ("presentator",),
            ("hopin",),
            id="a taken name is a conflict and gets no change",
        ),
        pytest.param(None, (), (), (), id="every key as desired"),
    ],
)
def test_the_plan_makes_absent_keys_and_names_taken_names(
    keys: dict | None, taken: tuple[str, ...], new_keys: tuple[str, ...], conflicts: tuple[str, ...]
) -> None:
    plan = litellm_keys.planned(found(keys=keys, taken=taken), BUDGET_ID, NONE_SET)

    assert tuple(change.subject for change in plan.changes if change.new) == new_keys
    assert plan.name_taken == conflicts
    new = [change for change in plan.changes if change.new]
    assert all(
        changed_fields(change)
        == {
            name: value
            for name, value in litellm_keys.desired_key(
                change.subject, MODELS, NONE_SET.limits_of(change.subject)
            ).items()
            if value is not None
        }
        for change in new
    )


def test_the_person_budget_comes_first_then_the_apps_in_name_order() -> None:
    plan = litellm_keys.planned(
        Found(
            keys=dict.fromkeys(reversed(APPS)),
            name_taken=frozenset(),
            budget=None,
            models=MODELS,
            admin=HELD,
        ),
        BUDGET_ID,
        NONE_SET,
    )

    assert [(change.target, change.subject) for change in plan.changes] == [
        (Target.BUDGET, BUDGET_ID),
        *((Target.KEY, app) for app in APPS),
    ]
    assert plan.changes[0] == Change(
        Target.BUDGET,
        BUDGET_ID,
        True,
        tuple(
            FieldChange(name, None, value)
            for name, value in litellm_keys.desired_budget(NONE_SET.person_budget()).items()
        ),
    )


def test_a_changed_person_budget_is_changed_in_its_amount_alone() -> None:
    plan = litellm_keys.planned(found(budget=found_budget(max_budget=1.5)), BUDGET_ID, NONE_SET)

    assert plan.changes == (
        Change(
            Target.BUDGET,
            BUDGET_ID,
            False,
            (FieldChange("max_budget", 1.5, api_limits.PERSON_BUDGET_DOLLARS),),
        ),
    )


# --- whether the step reads (decision 14) ------------------------------------------------------


@dataclass(frozen=True)
class Answer:
    exit_code: int = 0
    stdout: str = ""
    stderr: str = ""


@dataclass
class OneOff:
    """Compose's runner: the key step's one-off answers `answer` on stdout, failing with `stderr`
    as its last words when `exit_code` is set, and the realm observer answers `observer`; it
    records what ran."""

    answer: str = ""
    exit_code: int = 0
    observer: Answer = Answer()
    stderr: str = "litellm-keys: status 502 at /v2/key/info\n"
    calls: list[tuple[list[str], str | None]] = field(default_factory=list)

    def __call__(
        self, command: list[str], _timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, stdin))
        if OBSERVER_SERVICE in command:
            observed = self.observer
            return subprocess.CompletedProcess(
                command, observed.exit_code, observed.stdout, observed.stderr
            )
        stderr = self.stderr if self.exit_code else ""
        return subprocess.CompletedProcess(command, self.exit_code, self.answer, stderr)

    @property
    def one_offs(self) -> list[list[str]]:
        return [command for command, _ in self.calls if litellm_keys.KEYS_SERVICE in command]

    def stdin_of(self, service: str) -> str | None:
        (stdin,) = [stdin for command, stdin in self.calls if service in command]
        return stdin


def read_answer(found_state: Found, admin: dict | None = None) -> str:
    return json.dumps({
        "apps": {
            app: {"key": row, "name_taken": app in found_state.name_taken}
            for app, row in found_state.keys.items()
        },
        "budget": found_state.budget,
        "models": list(found_state.models),
        "admin": admin,
    })  # fmt: skip


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    config = tmp_path / litellm_keys.CONFIG_FILE
    config.parent.mkdir(parents=True)
    config.write_text(
        yaml.safe_dump({"litellm_settings": {litellm_keys.BUDGET_ID_SETTING: BUDGET_ID}})
    )
    return tmp_path


def test_while_litellm_runs_the_step_reads_with_the_budget_id_config_yaml_names(
    repository: Path,
) -> None:
    runner = OneOff(read_answer(found(keys={}, budget={})))
    plan = plan_with(runner, repository, LITELLM_RUNNING, None)

    assert [command[-3:] for command in runner.one_offs] == [
        [litellm_keys.KEYS_SERVICE, "--read", BUDGET_ID]
    ]
    assert plan.changes[0].subject == BUDGET_ID
    assert [change.subject for change in plan.changes[1:]] == list(APPS)


@pytest.mark.parametrize(
    ("answer", "exit_code", "reason"),
    [
        pytest.param("", 1, "litellm-keys: status 502 at /v2/key/info", id="a failed one-off"),
        pytest.param("not json", 0, "the key step answered no JSON", id="no JSON"),
        pytest.param(
            '{"apps": {}}', 0, "the key step answered an unexpected shape", id="a wrong shape"
        ),
        pytest.param(
            '{"apps": {"hopin": {"key": "a string", "name_taken": false}}, "budget": null,'
            ' "models": []}',
            0,
            "the key step answered an unexpected shape",
            id="a key entry that is no object",
        ),
    ],
)
def test_a_read_that_fails_while_litellm_runs_plans_nothing_and_says_why(
    repository: Path, answer: str, exit_code: int, reason: str
) -> None:
    plan = plan_with(OneOff(answer, exit_code), repository, LITELLM_RUNNING, None)

    assert isinstance(plan, NotRead)
    assert reason in plan.cause


@pytest.mark.parametrize("settings", [{}, {litellm_keys.BUDGET_ID_SETTING: ""}])
def test_a_config_yaml_without_the_budget_id_is_a_step_not_read(
    repository: Path, settings: dict
) -> None:
    config = repository / litellm_keys.CONFIG_FILE
    config.write_text(yaml.safe_dump({"litellm_settings": settings}))
    runner = OneOff()
    plan = plan_with(runner, repository, LITELLM_RUNNING, None)

    assert isinstance(plan, NotRead)
    assert litellm_keys.BUDGET_ID_SETTING in plan.cause
    assert runner.one_offs == []


def test_an_app_table_naming_no_app_read_is_no_step_not_read(repository: Path) -> None:
    runner = OneOff(read_answer(found()))
    api = ApiSettings(apps={"hopn": AppNumbers(budget_dollars=1.0)})

    with pytest.raises(litellm_keys.UnknownApps):
        plan_with(runner, repository, LITELLM_RUNNING, None, api=api)


def test_the_shipped_config_yaml_names_the_person_budget_id() -> None:
    assert litellm_keys.read_budget_id(ROOT)


# --- what the run makes of the one-off's answer ------------------------------------------------


TWO_KEYS = KeysPlan(
    (
        Change(Target.KEY, "hopin", True, (FieldChange("key_alias", None, "hopin"),)),
        Change(Target.KEY, "songmaker", True, (FieldChange("key_alias", None, "songmaker"),)),
    )
)


def outcome(subject: str, made: str, **cause: str) -> dict:
    return {"target": "key", "subject": subject, "outcome": made, **cause}


@pytest.mark.parametrize(
    "answer",
    [
        pytest.param({"done": True}, id="no list"),
        pytest.param([outcome("hopin", "done")], id="one outcome for two changes"),
        pytest.param([outcome("songmaker", "done"), outcome("hopin", "done")], id="other order"),
        pytest.param([outcome("hopin", "not made"), outcome("songmaker", "done")], id="a gap"),
        pytest.param([outcome("hopin", "failed"), outcome("songmaker", "not made")], id="no cause"),
    ],
)
def test_a_write_answer_that_does_not_account_for_each_change_in_order_is_a_failed_step(
    answer: object,
) -> None:
    result = litellm_keys.run_keys(TWO_KEYS, compose.Compose(run=OneOff(json.dumps(answer))))

    assert isinstance(result, litellm_keys.KeysFailed)
    assert (result.done, result.failed, result.not_made) == ((), None, ())
    assert "the key step answered" in result.cause


def test_the_run_sends_the_changes_in_their_planned_order_and_folds_the_answer() -> None:
    runner = OneOff(
        json.dumps([outcome("hopin", "done"), outcome("songmaker", "failed", cause="name taken")])
    )
    result = litellm_keys.run_keys(TWO_KEYS, compose.Compose(run=runner))

    assert result == litellm_keys.KeysFailed(
        TWO_KEYS.changes[:1], TWO_KEYS.changes[1], "name taken", (), ()
    )
    ((command, stdin),) = runner.calls
    assert command[-2:] == [litellm_keys.KEYS_SERVICE, "--write"]
    assert [change["subject"] for change in json.loads(stdin or "")] == ["hopin", "songmaker"]


# --- the admin group's rows (#965) ---------------------------------------------------------------


ISSUER = "https://auth.hallucinai.test/realms/hallucinai"
ADMIN = litellm_keys.ADMIN_BUDGET_ID
LITELLM_RUNNING = {litellm_keys.LITELLM_SERVICE: {"running"}}
KEYCLOAK_RUNNING = LITELLM_RUNNING | {KEYCLOAK_SERVICE: {"running"}}


def fingerprint_of(subject: str) -> str:
    return person_fingerprint(Principal(iss=ISSUER, sub=subject))


NO_ROW, UNLINKED, ELSEWHERE, LINKED, FORMER, FORMER_2 = map(
    fingerprint_of, ("o", "o2", "o3", "linked", "x", "x2")
)


def admin_found(
    members: dict[str, CustomerRow | None],
    others: tuple[str, ...] = (),
    budget: dict | None = None,
) -> AdminFound:
    desired = dict(litellm_keys.desired_admin_budget())
    return AdminFound(desired if budget is None else budget, members, others)


def row_changes(plan: KeysPlan) -> list[tuple[str, bool, str | None]]:
    wires = (change.wire() for change in plan.changes)
    return [
        (wire["subject"], wire["new"], wire["fields"]["budget_id"])
        for wire in wires
        if wire["target"] == Target.CUSTOMER
    ]


def members_answer(*subjects: str) -> Answer:
    return Answer(0, json.dumps({"issuer": ISSUER, "members": list(subjects)}))


def plan_with(
    runner: OneOff,
    repository: Path,
    states: dict[str, set[str]] = KEYCLOAK_RUNNING,
    gate: core.Gate | None = core.Gate.ON,
    recreates: tuple[Recreate, ...] = (),
    api: ApiSettings = NONE_SET,
) -> KeysStep:
    """The step with the unit `litellm` on and running; `gate` is Keycloak's, None outside the
    catalog."""
    engine = compose.Compose(run=runner, repository=repository)
    keycloak = {} if gate is None else {REALM_UNIT: gate}
    gates = {litellm_keys.UNIT: core.Gate.ON} | keycloak
    return litellm_keys.plan_keys(engine, states, repository, api, gates, (), recreates)


def test_the_admin_budget_has_no_limit_and_the_person_budgets_period() -> None:
    admin = litellm_keys.desired_admin_budget()

    assert admin["max_budget"] is None
    assert (
        admin["budget_duration"]
        == litellm_keys.desired_budget(NONE_SET.person_budget())["budget_duration"]
    )


@pytest.mark.parametrize(
    ("budget", "new", "fields"),
    [
        pytest.param(None, True, {"budget_duration": "1mo"}, id="a new one sends no limit"),
        pytest.param(
            {"max_budget": 5.0, "budget_duration": "1mo"},
            False,
            {"max_budget": None},
            id="a limit set by hand is cleared",
        ),
    ],
)
def test_the_admin_budget_is_made_or_changed_to_have_no_limit(
    budget: dict | None, new: bool, fields: dict
) -> None:
    admin = AdminFound(budget, {}, ())
    plan = litellm_keys.planned(found(admin=admin), BUDGET_ID, NONE_SET)

    assert [change.wire() for change in plan.changes] == [
        {"target": "budget", "subject": ADMIN, "new": new, "fields": fields}
    ]


@pytest.mark.parametrize(
    ("members", "others", "expected"),
    [
        pytest.param(
            {NO_ROW: None}, (), {(NO_ROW, True, ADMIN)}, id="a member with no row gets one"
        ),
        pytest.param(
            {UNLINKED: CustomerRow(None)},
            (),
            {(UNLINKED, False, ADMIN)},
            id="an unlinked row is linked",
        ),
        pytest.param(
            {ELSEWHERE: CustomerRow("by-hand")},
            (),
            {(ELSEWHERE, False, ADMIN)},
            id="a row linked to another budget is linked to the admin budget",
        ),
        pytest.param({LINKED: CustomerRow(ADMIN)}, (), set(), id="a linked row stays"),
        pytest.param(
            {}, (FORMER,), {(FORMER, False, None)}, id="a non-member on the admin budget unlinked"
        ),
        pytest.param({}, (), set(), id="a non-member the read names nowhere is untouched"),
        pytest.param(
            {},
            (FORMER, FORMER_2),
            {(FORMER, False, None), (FORMER_2, False, None)},
            id="the group present and empty unlinks every row on the admin budget",
        ),
    ],
)
def test_the_members_rows_are_linked_and_every_other_row_on_the_admin_budget_unlinked(
    members: dict, others: tuple[str, ...], expected: set
) -> None:
    plan = litellm_keys.planned(found(admin=admin_found(members, others)), BUDGET_ID, NONE_SET)

    assert set(row_changes(plan)) == expected
    assert plan.admin is None


def test_the_admin_budget_follows_the_person_budget_and_the_keys_then_unlinks_then_links() -> None:
    admin = admin_found({ELSEWHERE: CustomerRow("by-hand"), NO_ROW: None}, (FORMER,), budget={})
    plan = litellm_keys.planned(
        found(keys={}, budget=found_budget(max_budget=1.5), admin=admin), BUDGET_ID, NONE_SET
    )

    assert [(change.wire()["target"], change.wire()["subject"]) for change in plan.changes] == [
        (Target.BUDGET, BUDGET_ID),
        *((Target.KEY, app) for app in APPS),
        (Target.BUDGET, ADMIN),
        (Target.CUSTOMER, FORMER),
        (Target.CUSTOMER, ELSEWHERE),
        (Target.CUSTOMER, NO_ROW),
    ]


def test_with_keycloak_running_the_read_gets_the_fingerprints_of_the_groups_members(
    repository: Path,
) -> None:
    subjects = ("subject-p", "subject-q")
    admin = {
        "budget": None,
        "members": [{"budget_id": "elsewhere"}, None],
        "others": [{"fingerprint": FORMER, "spend": 1.0}],
    }
    runner = OneOff(read_answer(found(), admin), observer=members_answer(*subjects))
    plan = plan_with(runner, repository)

    observer_call = next(command for command, _ in runner.calls if OBSERVER_SERVICE in command)
    assert observer_call[-3:] == [OBSERVER_SERVICE, "--members", litellm_keys.ADMIN_GROUP]
    asked = json.loads(runner.stdin_of(litellm_keys.KEYS_SERVICE) or "")
    assert asked == {"budget": ADMIN, "members": sorted(map(fingerprint_of, subjects))}
    words = [word for command, _ in runner.calls for word in command]
    secrets = (*asked["members"], *subjects)
    assert not any(secret in word for secret in secrets for word in words)
    assert set(row_changes(plan)) == {
        (fingerprint_of(subjects[0]), False, ADMIN),
        (fingerprint_of(subjects[1]), True, ADMIN),
        (FORMER, False, None),
    }


def keycloak_running(observed: Answer, cause: str, id: str) -> object:
    return pytest.param(KEYCLOAK_RUNNING, (), observed, cause, id=id)


@pytest.mark.parametrize(
    ("states", "recreates", "observed", "cause"),
    [
        pytest.param(LITELLM_RUNNING, (), Answer(), "Keycloak is not running", id="not running"),
        pytest.param(
            LITELLM_RUNNING,
            (Recreate(REALM_UNIT, KEYCLOAK_SERVICE),),
            Answer(),
            "Keycloak starts in this run",
            id="started by this run",
        ),
        keycloak_running(
            Answer(1, json.dumps({"issuer": ISSUER, "members": ["subject-p"]}), "x: stopped\n"),
            "realm-observer exited 1: x: stopped",
            id="a failed read with members already on its stdout",
        ),
        keycloak_running(
            Answer(1, "", f"realm-observer: hallucinai has no group {litellm_keys.ADMIN_GROUP}\n"),
            f"realm-observer exited 1: realm-observer: hallucinai has no group "
            f"{litellm_keys.ADMIN_GROUP}",
            id="the group absent",
        ),
        keycloak_running(
            Answer(0, json.dumps({"issuer": ISSUER, "members": "subject-p"})),
            NO_MEMBERS,
            id="a members value that is no list",
        ),
        keycloak_running(
            Answer(0, "subject-p is not JSON"), NO_MEMBERS, id="an answer that is not JSON"
        ),
        keycloak_running(
            Answer(0, json.dumps({"members": ["subject-p"]})),
            NO_MEMBERS,
            id="an answer without issuer",
        ),
        keycloak_running(
            Answer(0, json.dumps({"issuer": ISSUER})), NO_MEMBERS, id="an answer without members"
        ),
        keycloak_running(
            Answer(0, json.dumps({"issuer": ISSUER, "members": ["subject-p", 7]})),
            NO_MEMBERS,
            id="a member that is a number",
        ),
        keycloak_running(
            Answer(0, json.dumps({"issuer": ISSUER, "members": ["subject-p", ""]})),
            NO_MEMBERS,
            id="an empty subject",
        ),
        keycloak_running(
            Answer(0, json.dumps({"issuer": "", "members": ["subject-p"]})),
            NO_MEMBERS,
            id="an empty issuer",
        ),
    ],
)
def test_members_not_read_leave_the_admin_rows_and_still_plan_the_keys_and_the_person_budget(
    repository: Path, states: dict, recreates: tuple[Recreate, ...], observed: Answer, cause: str
) -> None:
    runner = OneOff(read_answer(found(keys={})), observer=observed)
    plan = plan_with(runner, repository, states, recreates=recreates)

    assert plan.admin == MembersNotRead(cause)
    assert "subject-p" not in cause + repr(plan)
    assert json.loads(runner.stdin_of(litellm_keys.KEYS_SERVICE) or "") is None
    assert row_changes(plan) == []
    assert [change.subject for change in plan.changes] == list(APPS)


@pytest.mark.parametrize(
    ("gate", "states"),
    [
        pytest.param(core.Gate.OFF, LITELLM_RUNNING, id="Keycloak off"),
        pytest.param(core.Gate.SWITCHED_OFF, KEYCLOAK_RUNNING, id="switched off by this run"),
    ],
)
def test_keycloak_held_holds_the_admin_rows_and_reads_no_members(
    repository: Path, gate: core.Gate, states: dict
) -> None:
    runner = OneOff(read_answer(found()), observer=members_answer("p"))
    plan = plan_with(runner, repository, states, gate)

    assert plan.admin == AdminHeld(gate)
    assert all(OBSERVER_SERVICE not in command for command, _ in runner.calls)
    assert json.loads(runner.stdin_of(litellm_keys.KEYS_SERVICE) or "") is None
    assert plan.changes == ()


def test_keycloak_that_is_no_unit_of_the_catalog_counts_as_on(repository: Path) -> None:
    admin = {"budget": None, "members": [None], "others": []}
    runner = OneOff(read_answer(found(), admin), observer=members_answer("p"))
    plan = plan_with(runner, repository, gate=None)

    assert row_changes(plan) == [(fingerprint_of("p"), True, ADMIN)]


@pytest.mark.parametrize(
    ("observed", "fingerprint", "reason"),
    [
        pytest.param(
            members_answer("subject-\ud800"),
            None,
            "a member's subject fails the client's check",
            id="a subject the client refuses",
        ),
        pytest.param(
            members_answer("p"),
            "fp-" + "A" * 64,
            "a member's fingerprint is not fp- and 64 lowercase hex",
            id="a fingerprint of another form",
        ),
    ],
)
def test_a_value_that_fails_its_form_check_fails_the_read_naming_the_check_alone(
    repository: Path,
    monkeypatch: pytest.MonkeyPatch,
    observed: Answer,
    fingerprint: str | None,
    reason: str,
) -> None:
    if fingerprint is not None:
        monkeypatch.setattr(client_turn, "person_fingerprint", lambda _principal: fingerprint)
    runner = OneOff(read_answer(found()), observer=observed)
    plan = plan_with(runner, repository)

    assert plan == NotRead(reason)
    assert runner.one_offs == []


def test_a_failed_read_names_its_exit_and_last_error_line_never_the_fingerprints_on_stdout(
    repository: Path,
) -> None:
    on_stdout = json.dumps({"admin": {"others": [{"fingerprint": FORMER, "spend": 1.0}]}})
    runner = OneOff(on_stdout, 1, members_answer("p"), "litellm-keys: status 502 at /customer/list")
    plan = plan_with(runner, repository)

    assert plan == NotRead("litellm-keys exited 1: litellm-keys: status 502 at /customer/list")


@pytest.mark.parametrize(
    ("members", "others"),
    [
        pytest.param([], [{"fingerprint": FORMER}], id="no row for a member"),
        pytest.param([None], [{"fingerprint": 7}], id="other not text"),
        pytest.param([{"budget_id": 7}], [], id="budget id a number"),
    ],
)
def test_a_read_whose_admin_rows_do_not_fit_is_an_unexpected_shape(
    repository: Path, members: list, others: list
) -> None:
    admin = {"budget": None, "members": members, "others": others}
    runner = OneOff(read_answer(found(), admin), observer=members_answer("p"))
    plan = plan_with(runner, repository)

    assert plan == NotRead("the key step answered an unexpected shape")


def test_a_failed_write_names_its_exit_and_last_error_line_never_the_fingerprints_on_stdout() -> (
    None
):
    plan = litellm_keys.planned(found(admin=admin_found({}, (FORMER,))), BUDGET_ID, NONE_SET)
    done = [{"target": "customer", "subject": FORMER, "outcome": "done"}]
    runner = OneOff(json.dumps(done), 130, stderr="litellm-keys: stopped\n")
    result = litellm_keys.run_keys(plan, compose.Compose(run=runner))

    assert result == litellm_keys.KeysFailed(
        (), None, "litellm-keys exited 130: litellm-keys: stopped", (), ()
    )


@pytest.mark.parametrize("admin", [HELD, MembersNotRead("Keycloak is not running")])
def test_a_plan_that_changes_nothing_but_leaves_the_admin_rows_unsettled_ends_with_them(
    admin: AdminHeld | MembersNotRead,
) -> None:
    result = litellm_keys.run_keys(KeysPlan(admin=admin), compose.Compose(run=OneOff()))

    assert result == litellm_keys.KeysDone((), (), admin)


def test_the_admin_group_is_one_the_realm_declares() -> None:
    declared = declared_realm((ROOT / "keycloak/realm.yaml").read_text())

    assert litellm_keys.ADMIN_GROUP in declared.identities[observer.GROUP.name]
