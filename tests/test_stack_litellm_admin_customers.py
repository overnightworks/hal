"""The key step's one-off and the admin group's customer rows (#965): `--read` per member and the
rows on the admin budget that are no member's, `--write`'s links and its unlink pair, against the
fake LiteLLM's `/customer/*` routes."""

import hashlib

import pytest
from support.litellm_fake import (
    NEW_BUDGET_FIELDS,
    Run,
    Scene,
    scene_fixture,  # noqa: F401 the fixture, requested by name below
)

ADMIN = "scenario-admin"
BUDGET_ID = "scenario-budget"
OWN_FIELDS = ("spend", "blocked", "alias", "allowed_model_region", "default_model", "models")


def fingerprint(name: str) -> str:
    return "fp-" + hashlib.sha256(name.encode()).hexdigest()


def customer(scene: Scene, name: str, budget_id: str | None = None, **fields: object) -> str:
    """A customer row as LiteLLM keeps it; its fingerprint."""
    user_id = fingerprint(name)
    scene.fake.customers[user_id] = {
        "user_id": user_id, "blocked": False, "alias": None, "spend": 0.0,
        "allowed_model_region": None, "default_model": None, "models": [],
        "budget_id": budget_id, "object_permission_id": None, "object_permission": None,
    } | fields  # fmt: skip
    return user_id


def admin_budget(scene: Scene) -> None:
    scene.fake.budgets[ADMIN] = {"budget_id": ADMIN, "max_budget": None, "budget_duration": "1mo"}


def read(scene: Scene, *members: str) -> Run:
    return scene.run("--read", BUDGET_ID, changes={"budget": ADMIN, "members": list(members)})


def link(user_id: str, new: bool) -> dict:
    return {"target": "customer", "subject": user_id, "new": new, "fields": {"budget_id": ADMIN}}


def unlink(user_id: str) -> dict:
    fields = {"budget_id": None}
    return {"target": "customer", "subject": user_id, "new": False, "fields": fields} | {
        "leaves": ADMIN
    }


def sent(scene: Scene) -> list[tuple[str, str]]:
    return [(method, path) for method, path, _ in scene.fake.requests]


# --- the read ---------------------------------------------------------------------------------


def test_the_read_answers_each_member_in_the_order_asked_and_the_admin_rows_of_no_member(
    scene: Scene,
) -> None:
    admin_budget(scene)
    elsewhere = customer(scene, "o3", "by-hand", spend=0.5)
    absent = fingerprint("o")
    linked = customer(scene, "linked", ADMIN, spend=0.25)
    unlinked = customer(scene, "o2", spend=1.0)
    former = customer(scene, "x", ADMIN, spend=1.0)
    bystanders = (customer(scene, "y"), customer(scene, "z", "by-hand"))

    run = read(scene, elsewhere, absent, linked, unlinked)

    assert run.exit_code == 0, run.stderr
    assert run.document["admin"] == {
        "budget": {"max_budget": None, "budget_duration": "1mo"},
        "members": [
            {"budget_id": "by-hand", "spend": 0.5},
            None,
            {"budget_id": ADMIN, "spend": 0.25},
            {"budget_id": None, "spend": 1.0},
        ],
        "others": [{"fingerprint": former, "spend": 1.0}],
    }
    assert all(bystander not in run.stdout for bystander in bystanders)


def test_the_read_lists_the_rows_once_and_asks_for_both_budgets_at_once(scene: Scene) -> None:
    read(scene, fingerprint("o"))

    assert ("GET", "/customer/list", None) in scene.fake.requests
    assert sent(scene).count(("GET", "/customer/list")) == 1
    assert ("POST", "/budget/info", {"budgets": [BUDGET_ID, ADMIN]}) in scene.fake.requests


def test_an_admin_budget_litellm_does_not_hold_reads_as_absent(scene: Scene) -> None:
    run = read(scene)

    assert run.document["admin"] == {"budget": None, "members": [], "others": []}


@pytest.mark.parametrize(
    ("arrange", "stdin", "line"),
    [
        pytest.param(
            lambda fake: fake.statuses.update({"/customer/list": (500, {"error": "db"})}),
            None,
            "status 500 at /customer/list",
            id="a list LiteLLM refuses",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/customer/list": (200, {"rows": []})}),
            None,
            "no customer rows at /customer/list",
            id="rows that are no list",
        ),
        pytest.param(lambda fake: None, "not json", "no members as JSON on stdin", id="no JSON"),
        pytest.param(
            lambda fake: None,
            {"budget": ADMIN, "members": [7]},
            "no members as JSON on stdin",
            id="a member that is no string",
        ),
        pytest.param(
            lambda fake: None,
            {"members": []},
            "no members as JSON on stdin",
            id="members without a budget",
        ),
    ],
)
def test_a_failed_read_of_the_rows_prints_one_line_without_a_fingerprint_and_nothing_on_stdout(
    scene: Scene, arrange, stdin: object, line: str
) -> None:
    member = customer(scene, "o2", spend=1.0)
    arrange(scene.fake)
    asked = {"budget": ADMIN, "members": [member]} if stdin is None else stdin

    run = scene.run("--read", BUDGET_ID, changes=asked)

    assert (run.exit_code, run.stdout, run.stderr) == (1, "", f"litellm-keys: {line}\n")


# --- the write ----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "change",
    [
        pytest.param({**link("o", True), "subject": 7}, id="a subject that is no string"),
        pytest.param(
            {**link("o", True), "fields": {"budget_id": ADMIN, "spend": 1.0}},
            id="fields beyond the budget",
        ),
        pytest.param(
            {"target": "customer", "subject": "o", "new": False, "fields": {"budget_id": None}},
            id="an unlink without the budget it leaves",
        ),
    ],
)
def test_a_customer_change_of_no_known_shape_is_refused_before_any_write(
    scene: Scene, change: dict
) -> None:
    admin_budget(scene)

    run = scene.run("--write", changes=[link(fingerprint("p"), True), change])

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: a change of an unknown kind\n",
    )
    assert sent(scene) == []


def test_a_link_makes_a_members_row_on_the_admin_budget_or_moves_its_row_there(
    scene: Scene,
) -> None:
    admin_budget(scene)
    absent = fingerprint("o")
    elsewhere = customer(scene, "o3", "by-hand", spend=0.5)

    run = scene.run("--write", changes=[link(elsewhere, False), link(absent, True)])

    assert run.exit_code == 0, run.stderr
    assert [entry["outcome"] for entry in run.document] == ["done", "done"]
    assert [(path, body) for _, path, body in scene.fake.requests] == [
        ("/customer/update", {"user_id": elsewhere, "budget_id": ADMIN}),
        ("/customer/new", {"user_id": absent, "budget_id": ADMIN}),
    ]
    assert {user_id: row["budget_id"] for user_id, row in scene.fake.customers.items()} == {
        elsewhere: ADMIN,
        absent: ADMIN,
    }
    assert scene.fake.customers[elsewhere]["spend"] == 0.5


def test_an_unlink_deletes_the_row_and_makes_it_again_from_a_read_right_before_it(
    scene: Scene,
) -> None:
    """Decision 4: LiteLLM's update drops a null budget, so the row is deleted and made again with
    its own fields and none of a budget, which would make a budget for it."""
    admin_budget(scene)
    permission = {"object_permission_id": "kept-apart", "models": ["text/opus"], "agents": []}
    former = customer(
        scene, "x", ADMIN, spend=1.0, blocked=True, alias="x", allowed_model_region="eu",
        default_model="text/opus", models=["text/opus"], object_permission_id="kept-apart",
        object_permission=permission,
    )  # fmt: skip
    before = dict(scene.fake.customers[former])
    budgets = dict(scene.fake.budgets)

    run = scene.run("--write", changes=[unlink(former)])

    assert run.exit_code == 0, run.stderr
    assert run.document == [{"target": "customer", "subject": former, "outcome": "done"}]
    assert sent(scene) == [
        ("GET", "/customer/list"),
        ("POST", "/customer/delete"),
        ("POST", "/customer/new"),
    ]
    remade = scene.fake.customers[former]
    assert remade["budget_id"] is None
    assert {name: remade[name] for name in OWN_FIELDS} == {
        name: before[name] for name in OWN_FIELDS
    }
    assert remade["object_permission"] | {"object_permission_id": None} == permission | {
        "object_permission_id": None
    }
    new_body = scene.fake.requests[-1][2] or {}
    assert not (NEW_BUDGET_FIELDS | {"budget_id", "object_permission_id"}) & new_body.keys()
    assert scene.fake.budgets == budgets


@pytest.mark.parametrize("budget_id", [None, "by-hand"], ids=["unlinked", "linked elsewhere"])
def test_an_unlink_whose_row_left_the_admin_budget_meanwhile_is_done_without_a_delete(
    scene: Scene, budget_id: str | None
) -> None:
    former = customer(scene, "x", budget_id, spend=1.0)

    run = scene.run("--write", changes=[unlink(former)])

    assert [entry["outcome"] for entry in run.document] == ["done"]
    assert sent(scene) == [("GET", "/customer/list")]
    assert scene.fake.customers[former]["budget_id"] == budget_id


@pytest.mark.parametrize(
    ("lost", "cause", "row_after"),
    [
        pytest.param("/customer/delete", "unreachable at /customer/delete", None, id="the delete"),
        pytest.param(
            "/customer/new", "unreachable at /customer/new after the delete", 1.0, id="the new"
        ),
    ],
)
def test_a_lost_answer_fails_the_unlink_and_the_retry_after_it_deletes_nothing_more(
    scene: Scene, lost: str, cause: str, row_after: float | None
) -> None:
    """The named gap: a delete whose answer is lost has lost the row and its spend; a lost answer
    of the new has made it, unlinked."""
    admin_budget(scene)
    former = customer(scene, "x", ADMIN, spend=1.0)
    scene.fake.lost.add(lost)

    failed = scene.run("--write", changes=[unlink(former)])
    scene.fake.lost.clear()
    scene.fake.requests.clear()
    retry = scene.run("--write", changes=[unlink(former)])

    assert failed.document == [
        {"target": "customer", "subject": former, "outcome": "failed", "cause": cause}
    ]
    assert [entry["outcome"] for entry in retry.document] == ["done"]
    assert sent(scene) == [("GET", "/customer/list")]
    row = scene.fake.customers.get(former)
    assert (None if row is None else (row["spend"], row["budget_id"])) == (
        None if row_after is None else (row_after, None)
    )


@pytest.mark.parametrize(
    ("path", "status", "cause", "kept"),
    [
        pytest.param("/customer/list", 502, "status 502 at /customer/list", True, id="the read"),
        pytest.param("/customer/delete", 404, "status 404 at /customer/delete", True, id="delete"),
        pytest.param(
            "/customer/new", 422, "status 422 at /customer/new after the delete", False, id="new"
        ),
    ],
)
def test_a_failing_unlink_names_its_call_and_status_and_never_the_fingerprint_litellm_quotes(
    scene: Scene, path: str, status: int, cause: str, kept: bool
) -> None:
    admin_budget(scene)
    former = customer(scene, "x", ADMIN, spend=1.0)
    scene.fake.statuses[path] = (status, {"error": {"message": f"End User Id={former} is wrong"}})

    run = scene.run("--write", changes=[unlink(former), link(fingerprint("o"), True)])

    assert run.exit_code == 0, run.stderr
    assert [(entry["outcome"], entry.get("cause")) for entry in run.document] == [
        ("failed", cause),
        ("not made", None),
    ]
    assert former not in run.document[0]["cause"] + run.stderr
    assert (former in scene.fake.customers) is kept
