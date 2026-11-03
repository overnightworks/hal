"""The key step's host side (#964, #889): the desired key and person budget from the numbers of
the operator's record, the diff against what the one-off read, and whether the step reads at all
(decision 14)."""

import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import yaml

from hal.stack import api_limits, compose, litellm_keys
from hal.stack.api_limits import NONE_SET, ApiSettings, AppLimits, AppNumbers
from hal.stack.litellm_keys import Change, FieldChange, Found, KeysPlan, Target

APPS = ("hopin", "presentator", "songmaker")
MODELS = ("text/haiku", "text/opus", "text/sonnet")
BUDGET_ID = "scenario-budget"
ROOT = Path(__file__).resolve().parents[1]


def found_key(app: str, **overrides: object) -> dict:
    """The live row of `app` as the one-off reports it: the desired settings, overridden."""
    desired = litellm_keys.desired_key(app, MODELS, NONE_SET.limits_of(app))
    return {
        name: list(value) if isinstance(value, tuple) else value for name, value in desired.items()
    } | overrides


def found_budget(**overrides: object) -> dict:
    return dict(litellm_keys.desired_budget(NONE_SET.person_budget())) | overrides


def found(
    keys: dict | None = None,
    taken: tuple[str, ...] = (),
    budget: dict | None = None,
    models: tuple[str, ...] = MODELS,
) -> Found:
    keys = {app: found_key(app) for app in APPS} if keys is None else keys
    return Found(
        keys={app: keys.get(app) for app in APPS},
        name_taken=frozenset(taken),
        budget=found_budget() if budget is None else budget,
        models=models,
    )


def changed_fields(change: Change | None) -> dict[str, object]:
    assert change is not None
    return {field_change.name: field_change.new for field_change in change.fields}


def test_a_new_key_carries_its_app_as_name_its_numbers_and_every_model_litellm_lists() -> None:
    desired = litellm_keys.desired_key("hopin", MODELS, AppLimits(6.0, 3))

    assert desired == {
        "key_alias": "hopin",
        "max_budget": 6.0,
        "budget_duration": litellm_keys.BUDGET_DURATION,
        "models": MODELS,
        "allowed_routes": (litellm_keys.ROUTE,),
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
            {"allowed_routes": (litellm_keys.ROUTE,)},
            id="a key without its route gets it",
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
            keys=dict.fromkeys(reversed(APPS)), name_taken=frozenset(), budget=None, models=MODELS
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

    with pytest.raises(litellm_keys.UnknownApps) as raised:
        litellm_keys.planned(found(), BUDGET_ID, api)

    assert "[api.hopn]" in str(raised.value)
    assert all(app in str(raised.value) for app in APPS)


def test_an_app_whose_name_is_taken_gets_no_change_whatever_its_table_says() -> None:
    api = ApiSettings(apps={"hopin": AppNumbers(budget_dollars=6.0)})

    plan = litellm_keys.planned(found(taken=("hopin",)), BUDGET_ID, api)

    assert plan.changes == ()
    assert plan.name_taken == ("hopin",)


# --- whether the step reads (decision 14) ------------------------------------------------------


@dataclass
class OneOff:
    """Compose's runner, answering the key step's one-off with `answer` and every other call with
    nothing; it records what ran."""

    answer: str = ""
    exit_code: int = 0
    calls: list[tuple[list[str], str | None]] = field(default_factory=list)

    def __call__(
        self, command: list[str], _timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.calls.append((command, stdin))
        if self.exit_code:
            return subprocess.CompletedProcess(
                command, self.exit_code, "", "litellm-keys: status 502 at /v2/key/info\n"
            )
        return subprocess.CompletedProcess(command, 0, self.answer, "")

    @property
    def one_offs(self) -> list[list[str]]:
        return [command for command, _ in self.calls if litellm_keys.KEYS_SERVICE in command]


def read_answer(found_state: Found) -> str:
    return json.dumps({
        "apps": {
            app: {"key": row, "name_taken": app in found_state.name_taken}
            for app, row in found_state.keys.items()
        },
        "budget": found_state.budget,
        "models": list(found_state.models),
    })  # fmt: skip


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    config = tmp_path / litellm_keys.CONFIG_FILE
    config.parent.mkdir(parents=True)
    config.write_text(
        yaml.safe_dump({"litellm_settings": {litellm_keys.BUDGET_ID_SETTING: BUDGET_ID}})
    )
    return tmp_path


@pytest.mark.parametrize("state", ["exited", "created", None])
def test_no_key_step_runs_while_litellm_does_not_run(repository: Path, state: str | None) -> None:
    runner = OneOff()
    states = {} if state is None else {litellm_keys.LITELLM_SERVICE: {state}}

    assert (
        litellm_keys.plan_keys(
            compose.Compose(run=runner, repository=repository), states, repository, NONE_SET
        )
        == KeysPlan()
    )
    assert runner.one_offs == []


def test_while_litellm_runs_the_step_reads_with_the_budget_id_config_yaml_names(
    repository: Path,
) -> None:
    runner = OneOff(read_answer(found(keys={}, budget={})))
    states = {litellm_keys.LITELLM_SERVICE: {"running"}}
    plan = litellm_keys.plan_keys(
        compose.Compose(run=runner, repository=repository), states, repository, NONE_SET
    )

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
    runner = OneOff(answer, exit_code)
    plan = litellm_keys.plan_keys(
        compose.Compose(run=runner, repository=repository),
        {litellm_keys.LITELLM_SERVICE: {"running"}},
        repository,
        NONE_SET,
    )

    assert plan.changes == ()
    assert plan.not_read is not None
    assert reason in plan.not_read


@pytest.mark.parametrize("settings", [{}, {litellm_keys.BUDGET_ID_SETTING: ""}])
def test_a_config_yaml_without_the_budget_id_is_a_step_not_read(
    repository: Path, settings: dict
) -> None:
    config = repository / litellm_keys.CONFIG_FILE
    config.write_text(yaml.safe_dump({"litellm_settings": settings}))
    runner = OneOff()
    states = {litellm_keys.LITELLM_SERVICE: {"running"}}
    plan = litellm_keys.plan_keys(
        compose.Compose(run=runner, repository=repository), states, repository, NONE_SET
    )

    assert plan.not_read is not None
    assert litellm_keys.BUDGET_ID_SETTING in plan.not_read
    assert runner.one_offs == []


def test_an_app_table_naming_no_app_read_is_no_step_not_read(repository: Path) -> None:
    runner = OneOff(read_answer(found()))
    states = {litellm_keys.LITELLM_SERVICE: {"running"}}

    with pytest.raises(litellm_keys.UnknownApps):
        litellm_keys.plan_keys(
            compose.Compose(run=runner, repository=repository),
            states,
            repository,
            ApiSettings(apps={"hopn": AppNumbers(budget_dollars=1.0)}),
        )


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
