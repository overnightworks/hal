"""The key step's one-off (#964): `src/hal/stack/litellm_admin.py` against a local fake LiteLLM
admin API, as the realm observer's tests drive it."""

import importlib.util
import re
import sys
from collections.abc import Callable
from pathlib import Path
from types import ModuleType

import pytest
from support.litellm_fake import (
    APPS,
    MODELS,
    NAME_TAKEN_BODY,
    FakeLitellm,
    Run,
    Scene,
    bystander_fixture,  # noqa: F401 the fixture, requested by name below
    hashed,
    scene_fixture,  # noqa: F401 the fixture, requested by name below
    short_requests_fixture,  # noqa: F401 the fixture, requested by name below
)

from hal.stack import litellm_admin as admin
from hal.stack import litellm_keys

BUDGET_ID = "scenario-budget"


def desired_row(app: str) -> dict:
    return {
        name: list(value) if isinstance(value, tuple) else value
        for name, value in litellm_keys.desired_key(app, MODELS).items()
    }


def plant_keys(scene: Scene, **overrides: dict) -> None:
    for app, key in scene.app_keys.items():
        scene.fake.keys[hashed(key)] = (
            desired_row(app) | overrides.get(app, {}) | {"spend": 3.0, "user_id": None}
        )


def key_change(app: str, new: bool, **fields: object) -> dict:
    return {"target": "key", "subject": app, "new": new, "fields": fields}


def budget_change(new: bool, **fields: object) -> dict:
    return {"target": "budget", "subject": BUDGET_ID, "new": new, "fields": fields}


def assert_nothing_secret_in(scene: Scene, run: Run) -> None:
    for secret in scene.everything_secret:
        assert secret not in run.stdout + run.stderr


# --- the read ---------------------------------------------------------------------------------


def test_the_read_reports_each_apps_live_key_by_its_hash_the_person_budget_and_the_models(
    scene: Scene,
) -> None:
    plant_keys(scene, hopin={"max_budget": 7.0})
    scene.fake.budgets[BUDGET_ID] = {
        "budget_id": BUDGET_ID,
        "max_budget": 1.5,
        "budget_duration": "1mo",
        "budget_reset_at": "2026-12-01T00:00:00Z",
    }
    run = scene.run("--read", BUDGET_ID)

    assert run.exit_code == 0, run.stderr
    assert run.document == {
        "apps": {
            app: {
                "key": {name: value for name, value in desired_row(app).items()}
                | ({"max_budget": 7.0} if app == "hopin" else {}),
                "name_taken": False,
            }
            for app in APPS
        },
        "budget": {"max_budget": 1.5, "budget_duration": "1mo"},
        "models": list(MODELS),
        "admin": None,
    }


def test_the_read_asks_by_hash_in_the_body_one_app_at_a_time_and_by_every_name_at_once(
    scene: Scene,
) -> None:
    scene.run("--read", BUDGET_ID)

    asked = [body for method, path, body in scene.fake.requests if path == "/v2/key/info"]
    assert asked == [
        *({"keys": [hashed(scene.app_keys[app])]} for app in APPS),
        {"key_aliases": list(APPS)},
    ]
    assert all(method == "POST" for method, path, _ in scene.fake.requests if path != "/v1/models")
    assert ("POST", "/budget/info", {"budgets": [BUDGET_ID]}) in scene.fake.requests


def test_an_app_whose_hash_no_live_key_has_while_another_key_holds_its_name_is_name_taken(
    scene: Scene,
) -> None:
    plant_keys(scene)
    scene.fake.keys[hashed("sk-the-old-file")] = scene.fake.keys.pop(
        hashed(scene.app_keys["hopin"])
    )
    run = scene.run("--read", BUDGET_ID)

    assert run.document["apps"]["hopin"] == {"key": None, "name_taken": True}
    assert run.document["apps"]["songmaker"]["name_taken"] is False


def test_an_empty_database_reads_every_key_and_the_budget_as_absent(scene: Scene) -> None:
    run = scene.run("--read", BUDGET_ID)

    assert run.document["apps"] == {app: {"key": None, "name_taken": False} for app in APPS}
    assert run.document["budget"] is None


def test_the_read_carries_no_token_hash_key_name_or_echoed_request(scene: Scene) -> None:
    plant_keys(scene)
    run = scene.run("--read", BUDGET_ID)

    assert_nothing_secret_in(scene, run)
    assert not re.search(r'"(token|key_name|spend|user_id)"', run.stdout)
    rows = [entry["key"] for entry in run.document["apps"].values()]
    assert all(set(row) == set(admin.KEY_FIELDS) for row in rows)


@pytest.mark.parametrize(
    ("arrange", "line"),
    [
        pytest.param(
            lambda fake: setattr(fake, "models", ()),
            "/v1/models lists no model",
            id="an empty model list",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/v2/key/info": (200, {"info": [{}, {}]})}),
            "/v2/key/info answers 2 keys for the hash of hopin",
            id="two keys for one hash",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/v2/key/info": (200, {"info": "none"})}),
            "no key rows at /v2/key/info",
            id="key rows that are no list",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/budget/info": (200, {"budgets": []})}),
            "no budget rows at /budget/info",
            id="budget rows that are no list",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/v1/models": (200, {"data": "none"})}),
            "no model list at /v1/models",
            id="a model list that is no list",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/v2/key/info": (502, {"error": "migrating"})}),
            "status 502 at /v2/key/info",
            id="502 while LiteLLM migrates",
        ),
    ],
)
def test_a_failed_read_is_one_named_line_on_stderr_nothing_on_stdout_and_exit_1(
    scene: Scene, arrange: Callable[[FakeLitellm], None], line: str
) -> None:
    plant_keys(scene)
    arrange(scene.fake)
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (1, "", f"litellm-keys: {line}\n")


@pytest.mark.usefixtures("short_requests")
def test_a_timed_out_read_is_one_named_line_on_stderr_nothing_on_stdout_and_exit_1(
    scene: Scene,
) -> None:
    scene.fake.slow.add("/v2/key/info")
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: LiteLLM does not answer /v2/key/info (timed out)\n",
    )


def test_a_master_key_litellm_refuses_is_its_status_alone(scene: Scene) -> None:
    scene.master_file.write_text("sk-wrong\n")
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: status 401 at /v2/key/info\n",
    )


def test_litellm_that_does_not_answer_is_one_line(scene: Scene) -> None:
    run = scene.run("--read", BUDGET_ID, at="http://127.0.0.1:9")

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: LiteLLM does not answer /v2/key/info (unreachable)\n",
    )


def test_an_answer_that_is_no_http_is_litellm_not_answering(scene: Scene) -> None:
    scene.fake.garbage.add("/v2/key/info")
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: LiteLLM does not answer /v2/key/info (unreachable)\n",
    )


@pytest.mark.parametrize(
    "content",
    ["sk-first\nsk-second", "sk-\x07bell"],
    ids=["a line break inside", "a control character"],
)
def test_a_master_key_file_that_is_no_single_printable_line_is_refused_naming_the_path_only(
    scene: Scene, content: str
) -> None:
    scene.master_file.write_text(content + "\n")
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout) == (1, "")
    assert (
        run.stderr
        == f"litellm-keys: the key file {scene.master_file} holds no single printable line\n"
    )
    assert scene.fake.arrivals == []
    assert "sk-first" not in run.stderr


def test_an_error_nobody_expected_ends_in_one_fixed_line_that_quotes_nothing(
    scene: Scene,
) -> None:
    scene.master_file.write_text("sk-key-\u0416\u0416\n")  # printable, yet no HTTP header value
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == "litellm-keys: unexpected UnicodeEncodeError\n"
    assert "\u0416" not in run.stderr


@pytest.mark.parametrize("path", ["/v2/key/info", "/budget/info"])
def test_a_stop_by_sigterm_mid_request_is_exit_130_with_nothing_on_stdout(
    scene: Scene, path: str
) -> None:
    scene.fake.interrupt.add(path)
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (130, "", "litellm-keys: stopped\n")


def test_an_app_key_directory_it_cannot_list_is_one_line(scene: Scene) -> None:
    for entry in scene.apps_directory.iterdir():
        entry.unlink()
    scene.apps_directory.rmdir()
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        f"litellm-keys: cannot list {scene.apps_directory}\n",
    )


# --- the master key's transport ---------------------------------------------------------------


def fresh_program(name: str) -> ModuleType:
    """litellm_admin.py loaded anew from its file, so its opener is built under the current
    environment rather than the one the test session imported it in."""
    spec = importlib.util.spec_from_file_location(name, Path(admin.__file__))
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


def test_a_proxy_in_the_environment_never_sees_the_master_key(
    scene: Scene, bystander: tuple[FakeLitellm, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Docker may inject HTTP(S)_PROXY; the master key still goes to LiteLLM alone."""
    proxy, proxy_url = bystander
    for variable in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(variable, proxy_url)
    for variable in ("no_proxy", "NO_PROXY"):
        monkeypatch.delenv(variable, raising=False)
    expected = scene.run("--read", BUDGET_ID)
    scene.fake.requests.clear()

    run = scene.run("--read", BUDGET_ID, program=fresh_program("litellm_admin_under_a_proxy"))

    assert (run.exit_code, run.stdout) == (0, expected.stdout)
    assert proxy.arrivals == []
    assert scene.fake.requests


@pytest.mark.parametrize(
    "location",
    ["{own}/elsewhere", "{other}/v2/key/info"],
    ids=["another path of LiteLLM", "another origin"],
)
def test_a_redirect_is_refused_as_its_status_and_never_followed(
    scene: Scene, bystander: tuple[FakeLitellm, str], location: str
) -> None:
    """urllib would send the master key along to the redirect's target."""
    other, other_url = bystander
    scene.fake.redirects["/v2/key/info"] = location.format(own=scene.base_url, other=other_url)
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: status 302 at /v2/key/info\n",
    )
    assert other.arrivals == []
    assert [path for _, path in scene.fake.arrivals] == ["/v2/key/info"]


# --- the write --------------------------------------------------------------------------------


def test_the_write_makes_the_changes_in_their_given_order_and_reports_each_done(
    scene: Scene,
) -> None:
    budget_fields = {"max_budget": 2.0, "budget_duration": "1mo"}
    key_fields = {
        app: {name: value for name, value in desired_row(app).items() if value is not None}
        for app in APPS
    }
    changes = [
        budget_change(True, **budget_fields),
        *(key_change(app, True, **key_fields[app]) for app in APPS),
    ]
    run = scene.run("--write", changes=changes)

    assert run.exit_code == 0, run.stderr
    assert run.document == [
        {"target": change["target"], "subject": change["subject"], "outcome": "done"}
        for change in changes
    ]
    assert [(path, body) for _, path, body in scene.fake.requests] == [
        ("/budget/new", {"budget_id": BUDGET_ID, **budget_fields}),
        *(("/key/generate", {"key": scene.app_keys[app], **key_fields[app]}) for app in APPS),
    ]
    assert {hashed(key) for key in scene.app_keys.values()} == set(scene.fake.keys)
    assert all(
        scene.fake.keys[hashed(key)]["key_alias"] == app for app, key in scene.app_keys.items()
    )
    assert_nothing_secret_in(scene, run)


def test_an_update_names_the_key_by_its_hash_and_sends_only_the_given_fields(scene: Scene) -> None:
    plant_keys(scene, songmaker={"max_budget": 7.0, "rpm_limit": 60})
    scene.fake.budgets[BUDGET_ID] = {
        "budget_id": BUDGET_ID,
        "max_budget": 1.5,
        "budget_duration": "1mo",
    }
    run = scene.run(
        "--write",
        changes=[
            budget_change(False, max_budget=2.0),
            key_change("songmaker", False, max_budget=10.0, rpm_limit=None),
        ],
    )

    assert run.exit_code == 0, run.stderr
    assert [(path, body) for _, path, body in scene.fake.requests] == [
        ("/budget/update", {"budget_id": BUDGET_ID, "max_budget": 2.0}),
        (
            "/key/update",
            {"key": hashed(scene.app_keys["songmaker"]), "max_budget": 10.0, "rpm_limit": None},
        ),
    ]


def test_the_first_failed_write_stops_the_rest_which_are_not_made(scene: Scene) -> None:
    scene.fake.statuses["/budget/new"] = (
        500,
        {"error": {"message": f"db down {scene.app_keys['hopin']}"}},
    )
    changes = [
        budget_change(True, max_budget=2.0),
        key_change("hopin", True, key_alias="hopin"),
        key_change("songmaker", True, key_alias="songmaker"),
    ]
    run = scene.run("--write", changes=changes)

    assert run.exit_code == 0
    assert [entry["outcome"] for entry in run.document] == ["failed", "not made", "not made"]
    assert run.document[0]["cause"] == "status 500"
    assert [path for _, path, _ in scene.fake.requests] == ["/budget/new"]
    assert_nothing_secret_in(scene, run)


def test_a_name_another_live_key_holds_is_the_cause_name_taken(scene: Scene) -> None:
    scene.fake.keys[hashed("sk-the-old-file")] = {"key_alias": "hopin"}
    run = scene.run(
        "--write",
        changes=[
            key_change("hopin", True, key_alias="hopin"),
            key_change("songmaker", True, key_alias="songmaker"),
        ],
    )

    assert run.document == [
        {"target": "key", "subject": "hopin", "outcome": "failed", "cause": "name taken"},
        {"target": "key", "subject": "songmaker", "outcome": "not made"},
    ]
    assert "already exists" not in run.stdout + run.stderr


@pytest.mark.parametrize(
    ("status", "body"),
    [
        pytest.param(400, {"error": {"param": "max_budget"}}, id="another parameter"),
        pytest.param(400, {"detail": "key_alias"}, id="no error object"),
        pytest.param(409, NAME_TAKEN_BODY["error"], id="the parameter at another status"),
    ],
)
def test_a_refusal_that_is_not_the_alias_rule_is_its_status_alone(
    scene: Scene, status: int, body: dict
) -> None:
    scene.fake.statuses["/key/generate"] = (status, body)
    run = scene.run("--write", changes=[key_change("hopin", True, key_alias="hopin")])

    assert run.document[0]["cause"] == f"status {status}"


@pytest.mark.usefixtures("short_requests")
def test_a_timed_out_write_is_the_cause_timed_out(scene: Scene) -> None:
    scene.fake.slow.add("/key/generate")
    run = scene.run(
        "--write",
        changes=[
            key_change("hopin", True, key_alias="hopin"),
            key_change("songmaker", True, key_alias="songmaker"),
        ],
    )

    assert [(entry["outcome"], entry.get("cause")) for entry in run.document] == [
        ("failed", "timed out"),
        ("not made", None),
    ]


def test_a_write_answered_with_no_http_is_failed_unreachable_and_the_rest_not_made(
    scene: Scene,
) -> None:
    scene.fake.garbage.add("/key/generate")
    run = scene.run(
        "--write",
        changes=[
            key_change("hopin", True, key_alias="hopin"),
            key_change("songmaker", True, key_alias="songmaker"),
        ],
    )

    assert run.exit_code == 0
    assert [(entry["outcome"], entry.get("cause")) for entry in run.document] == [
        ("failed", "unreachable"),
        ("not made", None),
    ]


@pytest.mark.parametrize(
    ("changes", "line"),
    [
        pytest.param(
            [key_change("stranger", True, key_alias="stranger")],
            "no key file for stranger",
            id="an app with no key file",
        ),
        pytest.param(
            [{"target": "team", "subject": "x", "new": True, "fields": {}}],
            "a change of an unknown kind",
            id="an unknown target",
        ),
        pytest.param(
            [{"target": "key", "subject": "songmaker", "new": True, "fields": "max_budget"}],
            "a change of an unknown kind",
            id="fields that are no object",
        ),
        pytest.param("not json", "no changes as JSON on stdin", id="no JSON"),
        pytest.param('{"target": "key"}', "no changes as JSON on stdin", id="JSON that is no list"),
    ],
)
def test_a_change_list_it_cannot_make_is_refused_before_any_write(
    scene: Scene, changes: object, line: str
) -> None:
    valid_first = [key_change("hopin", True, key_alias="hopin")]
    run = scene.run(
        "--write", changes=valid_first + changes if isinstance(changes, list) else changes
    )

    assert (run.exit_code, run.stdout, run.stderr) == (1, "", f"litellm-keys: {line}\n")
    assert scene.fake.requests == []


def test_an_unreadable_master_key_is_one_line_before_any_request(scene: Scene) -> None:
    scene.master_file.unlink()
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == f"litellm-keys: cannot read the key file {scene.master_file}\n"
    assert scene.fake.requests == []
