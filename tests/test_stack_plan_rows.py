"""The rows `hal apply` prints for its app plan and its unit plan: what each kind of entry says,
from typed fields, and the `find_row` helper the apply tests share."""

from typing import Any

import pytest
from support.stack_plan_rows import (
    APP,
    DIGEST_A,
    DIGEST_B,
    KEYCLOAK,
    NEW,
    OLD,
    app_plan,
    groups_of,
    kept,
    unit_plan,
)

from hal.output import Glyph, Row
from hal.stack import checkout, releases
from hal.stack.apps import (
    AppKind,
    AppPlan,
    OffPlan,
    SkippedNote,
    StaysStoppedNote,
)
from hal.stack.built_image import ENDS_RUNS, BuiltRecreate
from hal.stack.catalog import App
from hal.stack.core import (
    Cause,
    CauseKind,
    CoreAction,
    CorePlan,
    FollowerAction,
    FollowerPlan,
    Gate,
)
from hal.stack.plan_rows import (
    CHECKOUT,
    CheckoutEvent,
    Effect,
    PlanEvent,
    PlanGroup,
    checkout_row,
    update_rows,
)
from hal.stack.realm.reconcile import REALM_UNIT, RealmAction, RealmPlan, RealmRestart
from hal.stack.unit_plans import Action, ImageReference, KeptImage, Recreate


def rows_of(**parts: object) -> tuple[Row, ...]:
    [legal, core, units, apps] = groups_of(**parts)
    assert (legal.heading, core.heading, units.heading, apps.heading) == (
        None,
        PlanGroup.CORE,
        PlanGroup.UNITS,
        PlanGroup.APPS,
    )
    return apps.rows


def unit_rows_of(**plan: Any) -> tuple[Row, ...]:
    return groups_of(**plan)[2].rows


@pytest.mark.parametrize(
    ("plans", "expected"),
    [
        pytest.param(
            (app_plan(AppKind.ON),),
            Row(Glyph.ADD, "hopin", PlanEvent.SWITCH_ON, f"{NEW} · into ~/srv/hopin"),
            id="switch on",
        ),
        pytest.param(
            (app_plan(AppKind.START_AGAIN, recorded_tag=NEW),),
            Row(Glyph.ADD, "hopin", PlanEvent.START_AGAIN, f"{NEW} · recorded"),
            id="start again",
        ),
        pytest.param(
            (app_plan(AppKind.UPDATE, recorded_tag=OLD),),
            Row(Glyph.CHANGE, "hopin", PlanEvent.UPDATE, f"{OLD} → {NEW}"),
            id="update",
        ),
        pytest.param(
            (app_plan(AppKind.UPDATE, recorded_tag=OLD, unfinished=NEW),),
            Row(
                Glyph.CHANGE,
                "hopin",
                PlanEvent.UPDATE,
                f"{OLD} → {NEW} · update to {NEW} did not finish",
            ),
            id="update after an unfinished update",
        ),
    ],
)
def test_an_app_plan_is_one_row_with_the_glyph_of_its_kind(
    plans: tuple[AppPlan, ...], expected: Row
) -> None:
    assert rows_of(plans=plans) == (expected,)


def test_an_app_switched_off_is_a_remove_row() -> None:
    off = OffPlan(APP)

    assert rows_of(offs=(off,)) == (
        Row(Glyph.REMOVE, "hopin", PlanEvent.SWITCH_OFF, "volumes kept · ~/srv/hopin kept"),
    )


@pytest.mark.parametrize(
    ("since", "fact"),
    [
        ("2026-10-18T08:00:00+02:00", "switched off since 18.10. 08:00"),
        (None, "barrier stands"),
    ],
    ids=["since a switch", "with a barrier"],
)
def test_an_app_that_stays_stopped_says_since_when_or_that_its_barrier_stands(
    since: str | None, fact: str
) -> None:
    kept = (StaysStoppedNote("hopin", since),)

    assert rows_of(kept=kept) == (Row(Glyph.UNCHANGED, "hopin", PlanEvent.STAYS_STOPPED, fact),)


def test_a_skipped_tag_is_a_row_with_the_tag_and_its_reason() -> None:
    kept = (SkippedNote("hopin", releases.SkippedTag("v2027.1.5.1", "not vYYYY.MM.DD.N")),)

    assert rows_of(kept=kept) == (
        Row(Glyph.UNCHANGED, "hopin", PlanEvent.TAG_SKIPPED, "v2027.1.5.1 · not vYYYY.MM.DD.N"),
    )


def test_the_rows_stand_in_the_order_the_work_runs_notes_then_switch_offs_then_the_rest() -> None:
    rows = rows_of(
        plans=(app_plan(AppKind.ON),),
        offs=(OffPlan(App("legal", False, "master")),),
        kept=(StaysStoppedNote("other", None),),
    )

    assert [row.event for row in rows] == [
        PlanEvent.STAYS_STOPPED,
        PlanEvent.SWITCH_OFF,
        PlanEvent.SWITCH_ON,
    ]


@pytest.mark.parametrize(
    ("image", "fact"),
    [
        pytest.param(
            kept(ImageReference(KEYCLOAK, DIGEST_A), ImageReference(KEYCLOAK, DIGEST_B)),
            f"{KEYCLOAK}@79c6… · compose.yaml @a78d…",
            id="same name",
        ),
        pytest.param(
            kept(
                ImageReference(KEYCLOAK, DIGEST_A),
                ImageReference(f"docker.io/{KEYCLOAK}", DIGEST_B),
            ),
            f"{KEYCLOAK}@79c6… · compose.yaml docker.io/{KEYCLOAK}@a78d…",
            id="differing names",
        ),
        pytest.param(
            kept(ImageReference(KEYCLOAK, DIGEST_A), ImageReference(KEYCLOAK, None)),
            f"{KEYCLOAK}@79c6… · compose.yaml {KEYCLOAK}",
            id="without a digest",
        ),
    ],
)
def test_a_kept_image_is_one_needs_you_row_with_both_versions(image: KeptImage, fact: str) -> None:
    assert unit_rows_of(images=(image,)) == (
        Row(Glyph.NEEDS_YOU, "keycloak", PlanEvent.OLD_IMAGE, fact),
    )


@pytest.mark.parametrize(
    ("realm", "expected"),
    [
        pytest.param(
            RealmPlan(RealmAction.RUN, why="keycloak/realm.yaml changed"),
            Row(
                Glyph.CHANGE,
                REALM_UNIT,
                PlanEvent.REALM_APPLY,
                "keycloak/*.yaml · keycloak/realm.yaml changed",
            ),
            id="run",
        ),
        pytest.param(
            RealmPlan(RealmAction.HELD, why="no realm apply is recorded", gate=Gate.OFF),
            Row(
                Glyph.UNCHANGED,
                REALM_UNIT,
                PlanEvent.REALM_HELD,
                "no realm apply is recorded · Keycloak is off",
            ),
            id="held",
        ),
        pytest.param(
            RealmPlan(RealmAction.NOT_CHECKED, restart=RealmRestart.DATABASE),
            Row(
                Glyph.UNCHANGED,
                REALM_UNIT,
                PlanEvent.REALM_LATER,
                "its database restarts now · next apply checks it",
            ),
            id="not checked",
        ),
        pytest.param(
            RealmPlan(RealmAction.UNREADABLE, error="the realm observer failed (x)"),
            Row(
                Glyph.NEEDS_YOU,
                REALM_UNIT,
                PlanEvent.REALM_SKIPPED,
                "the realm observer failed (x)",
            ),
            id="unreadable",
        ),
        pytest.param(RealmPlan(), None, id="nothing"),
    ],
)
def test_a_realm_plan_is_one_row_for_its_action_and_none_when_nothing_changes(
    realm: RealmPlan, expected: Row | None
) -> None:
    assert unit_rows_of(realm=realm) == (() if expected is None else (expected,))


def test_the_kept_images_come_before_the_realm_row_and_the_units_before_the_apps() -> None:
    image = kept(ImageReference(KEYCLOAK, DIGEST_A), ImageReference(KEYCLOAK, DIGEST_B))
    realm = RealmPlan(RealmAction.RUN, why="x")

    _, _, units, apps = groups_of(images=(image,), realm=realm, plans=(app_plan(AppKind.ON),))

    assert [row.event for row in units.rows] == [PlanEvent.OLD_IMAGE, PlanEvent.REALM_APPLY]
    assert apps.rows


SINCE = "2026-10-17T22:10:00"


def built(**overrides: Any) -> BuiltRecreate:
    fields: dict[str, Any] = {
        "unit": "agent-service",
        "service": "agent-service",
        "reference": "agent-service:local",
        "moved_from": (),
        "definition_changed": False,
        "rebuilt": False,
    }
    return BuiltRecreate(**{**fields, **overrides})


@pytest.mark.parametrize(
    ("parts", "row"),
    [
        pytest.param(
            {"recreates": (Recreate("keycloak", "keycloak-db"),)},
            Row(Glyph.CHANGE, "keycloak-db", PlanEvent.RECREATE, "definition changed"),
            id="recreate",
        ),
        pytest.param(
            {"built": (built(definition_changed=True),)},
            Row(
                Glyph.CHANGE,
                "agent-service",
                PlanEvent.RECREATE,
                f"definition changed · {ENDS_RUNS}",
            ),
            id="built definition",
        ),
        pytest.param(
            {"built": (built(moved_from=("agent-service:old", "agent-service:older")),)},
            Row(
                Glyph.CHANGE,
                "agent-service",
                PlanEvent.RECREATE,
                "image agent-service:old → agent-service:local"
                " · image agent-service:older → agent-service:local"
                f" · {ENDS_RUNS}",
            ),
            id="built image moved",
        ),
        pytest.param(
            {"built": (built(rebuilt=True),)},
            Row(
                Glyph.CHANGE,
                "agent-service",
                PlanEvent.RECREATE,
                f"image agent-service:local rebuilt · {ENDS_RUNS}",
            ),
            id="built rebuilt",
        ),
        pytest.param(
            {"built": (built(moved_from=("a:1",), definition_changed=True, rebuilt=True),)},
            Row(
                Glyph.CHANGE,
                "agent-service",
                PlanEvent.RECREATE,
                "image a:1 → agent-service:local · definition changed"
                f" · image agent-service:local rebuilt · {ENDS_RUNS}",
            ),
            id="built combination",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.ON, volumes=()),)},
            Row(Glyph.ADD, "step-ca", PlanEvent.SWITCH_ON, "step-ca, traefik-mcp"),
            id="switch on",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.OFF),)},
            Row(
                Glyph.REMOVE,
                "step-ca",
                PlanEvent.SWITCH_OFF,
                "step-ca, traefik-mcp · volumes step-ca kept",
            ),
            id="switch off with volumes",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.OFF, switched_off_since=SINCE),)},
            Row(
                Glyph.REMOVE,
                "step-ca",
                PlanEvent.SWITCH_OFF,
                "step-ca, traefik-mcp · volumes step-ca kept · its switch since 17.10. 22:10 stays",
            ),
            id="switch off with a switch since",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.OFF, volumes=()),)},
            Row(Glyph.REMOVE, "step-ca", PlanEvent.SWITCH_OFF, "step-ca, traefik-mcp"),
            id="switch off without volumes",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.STAYS_STOPPED, switched_off_since=SINCE),)},
            Row(
                Glyph.UNCHANGED,
                "step-ca",
                PlanEvent.STAYS_STOPPED,
                "switched off since 17.10. 22:10",
            ),
            id="stays stopped with a switch since",
        ),
        pytest.param(
            {"unit_plans": (unit_plan(Action.STAYS_STOPPED),)},
            Row(Glyph.UNCHANGED, "step-ca", PlanEvent.STAYS_STOPPED, "barrier stands"),
            id="stays stopped with a barrier",
        ),
    ],
)
def test_a_unit_part_is_one_row_of_its_typed_fields(parts: dict[str, Any], row: Row) -> None:
    assert unit_rows_of(**parts) == (row,)


def test_the_unit_rows_stand_built_then_recreates_then_plans_then_images_then_the_realm() -> None:
    image = kept(ImageReference(KEYCLOAK, DIGEST_A), ImageReference(KEYCLOAK, DIGEST_B))

    _, _, units, apps = groups_of(
        built=(built(rebuilt=True),),
        recreates=(Recreate("keycloak", "keycloak-db"),),
        unit_plans=(unit_plan(Action.ON), unit_plan(Action.STAYS_STOPPED)),
        images=(image,),
        realm=RealmPlan(RealmAction.RUN, why="x"),
        plans=(app_plan(AppKind.ON),),
    )

    assert [(row.subject, row.event) for row in units.rows] == [
        ("agent-service", PlanEvent.RECREATE),
        ("keycloak-db", PlanEvent.RECREATE),
        ("step-ca", PlanEvent.SWITCH_ON),
        ("step-ca", PlanEvent.STAYS_STOPPED),
        ("keycloak", PlanEvent.OLD_IMAGE),
        (REALM_UNIT, PlanEvent.REALM_APPLY),
    ]
    assert apps.rows


def core_rows_of(**parts: Any) -> tuple[Row, ...]:
    return groups_of(**parts)[1].rows


def core_plan(action: CoreAction, *why: Cause) -> CorePlan:
    return CorePlan("socket-proxy", action, why, {}, False)


def follower_plan(action: FollowerAction, gate: Gate, *why: Cause) -> FollowerPlan:
    return FollowerPlan("traefik-mcp", "step-ca", action, why, {}, gate)


DEFINITION = Cause(CauseKind.DEFINITION_CHANGED)
FOLLOWER_FILE = Cause(CauseKind.FILE_UNRECORDED, "traefik-mcp.yml")


@pytest.mark.parametrize(
    ("cause", "fact"),
    [
        pytest.param(DEFINITION, "definition changed", id="definition changed"),
        pytest.param(
            Cause(CauseKind.FILE_CHANGED, "traefik.yml"), "traefik.yml changed", id="file"
        ),
        pytest.param(
            Cause(CauseKind.FILE_UNRECORDED, "traefik.yml"),
            "traefik.yml has no applied record",
            id="file unrecorded",
        ),
        pytest.param(
            Cause(CauseKind.UNFINISHED), "the last recreate did not finish", id="unfinished"
        ),
        pytest.param(
            Cause(CauseKind.RECORD_UNTRUSTED, "/x/applied.json is malformed: it is not JSON"),
            "/x/applied.json is malformed: it is not JSON",
            id="record untrusted",
        ),
        pytest.param(
            Cause(CauseKind.RECORD_NAMES_OTHERS, "old.yml, older.yml"),
            "applied.json names old.yml, older.yml, which socket-proxy does not mount",
            id="record names others",
        ),
        pytest.param(
            Cause(CauseKind.PULLED_IN, "socket-proxy"), "socket-proxy is recreated", id="pulled in"
        ),
    ],
)
def test_every_cause_of_a_recreated_core_service_is_one_fact(cause: Cause, fact: str) -> None:
    plan = core_plan(CoreAction.RECREATE, cause)

    assert core_rows_of(core=(plan,)) == (
        Row(Glyph.CHANGE, "socket-proxy", PlanEvent.RECREATE, fact),
    )


def test_several_causes_are_one_row_in_the_order_they_are_planned() -> None:
    plan = CorePlan(
        "traefik",
        CoreAction.RECREATE,
        (DEFINITION, Cause(CauseKind.FILE_CHANGED, "traefik.yml")),
        {},
        False,
    )

    assert core_rows_of(core=(plan,)) == (
        Row(
            Glyph.CHANGE, "traefik", PlanEvent.RECREATE, "definition changed · traefik.yml changed"
        ),
    )


def test_a_core_service_that_is_not_running_is_a_row_that_says_it_is_not_started() -> None:
    plan = core_plan(CoreAction.NOT_STARTED, DEFINITION)

    assert core_rows_of(core=(plan,)) == (
        Row(
            Glyph.UNCHANGED,
            "socket-proxy",
            PlanEvent.NOT_STARTED,
            "definition changed · not running",
        ),
    )


@pytest.mark.parametrize(
    ("action", "gate", "row"),
    [
        pytest.param(
            FollowerAction.RECREATE,
            Gate.ON,
            Row(
                Glyph.CHANGE,
                "traefik-mcp",
                PlanEvent.RECREATE,
                "traefik-mcp.yml has no applied record",
            ),
            id="recreate",
        ),
        pytest.param(
            FollowerAction.STARTS_WITH_UNIT,
            Gate.ON,
            Row(
                Glyph.CHANGE,
                "traefik-mcp",
                PlanEvent.STARTS_LATER,
                "traefik-mcp.yml has no applied record · with step-ca",
            ),
            id="starts with its unit",
        ),
        pytest.param(
            FollowerAction.HELD,
            Gate.OFF,
            Row(
                Glyph.UNCHANGED,
                "traefik-mcp",
                PlanEvent.NOT_STARTED,
                "traefik-mcp.yml has no applied record · step-ca is off",
            ),
            id="held, unit off",
        ),
        pytest.param(
            FollowerAction.HELD,
            Gate.SWITCHED_OFF,
            Row(
                Glyph.UNCHANGED,
                "traefik-mcp",
                PlanEvent.NOT_STARTED,
                "traefik-mcp.yml has no applied record · step-ca is switched off",
            ),
            id="held, unit switched off",
        ),
    ],
)
def test_a_follower_is_one_row_and_a_waiting_one_ends_with_the_state_of_its_unit(
    action: FollowerAction, gate: Gate, row: Row
) -> None:
    assert core_rows_of(followers=(follower_plan(action, gate, FOLLOWER_FILE),)) == (row,)


def test_the_core_group_holds_core_plans_then_followers_and_stands_before_units_and_apps() -> None:
    _, core, units, apps = groups_of(
        core=(core_plan(CoreAction.RECREATE, DEFINITION),),
        followers=(follower_plan(FollowerAction.RECREATE, Gate.ON, DEFINITION),),
        unit_plans=(unit_plan(Action.ON),),
        plans=(app_plan(AppKind.ON),),
    )

    assert [group.heading for group in (core, units, apps)] == list(PlanGroup)
    assert [row.subject for row in core.rows] == ["socket-proxy", "traefik-mcp"]


def origin_main(behind: int, ahead: int = 0) -> checkout.Origin:
    return checkout.Origin("f" * 40, "ffffff0", "c280a80", "c" * 40, ahead, behind)


def test_a_current_checkout_is_one_done_row_naming_the_pinned_main() -> None:
    assert checkout_row(origin_main(0)) == Row(
        Glyph.DONE, CHECKOUT, CheckoutEvent.CURRENT, "ffffff0 · origin/main"
    )


@pytest.mark.parametrize("behind", [1, 3])
def test_a_checkout_behind_is_one_needs_you_row_with_no_manual_command(behind: int) -> None:
    """#783 decision 10: the row counts the waiting commits and names origin's short sha."""
    assert checkout_row(origin_main(behind)) == Row(
        Glyph.NEEDS_YOU,
        CHECKOUT,
        CheckoutEvent.BEHIND,
        "origin/main ffffff0",
        count=behind,
    )


def test_a_diverged_checkout_is_not_a_behind_row() -> None:
    """Behind is `Origin.standing`'s answer, not the behind count alone."""
    assert checkout_row(origin_main(behind=2, ahead=1)).event != CheckoutEvent.BEHIND


def update_row_texts(by_effect: dict[Effect, list[str]] | None, reason: str = "") -> list[str]:
    commits = [checkout.Commit("aaaaaaa", "first"), checkout.Commit("bbbbbbb", "second")]
    return [
        f"{row.subject}|{row.fact}|{row.count}|{'/'.join(row.details)}"
        for row in update_rows(origin_main(2), commits, by_effect, reason)
    ]


def test_the_update_lists_every_commit_under_the_behind_row() -> None:
    """A2: one detail line per waiting commit, none cut."""
    behind, *_ = update_rows(origin_main(500), [checkout.Commit("abcdef0", "x")] * 500, {})

    assert behind.event == CheckoutEvent.BEHIND
    assert len(behind.details) == 500
    assert behind.details[0] == "abcdef0 x"


def test_files_are_one_row_per_effect_group_and_an_empty_group_has_none() -> None:
    """A3: four groups at most; the lines promise no more than the configuration says."""
    rows = update_row_texts(
        {Effect.CODE: ["src/a.py"], Effect.DIRECTORY_BIND: ["legal/nginx/default.conf"]}
    )

    assert [row.partition("|")[0] for row in rows[1:]] == [Effect.CODE, Effect.DIRECTORY_BIND]
    assert rows[2].endswith("|1|legal/nginx/default.conf")
    for row in rows[1:]:
        assert not {"live", "active", "running", "applied"} & set(
            row.lower().replace(".", " ").split()
        )


def test_files_that_cannot_be_classified_are_one_row_with_the_reason() -> None:
    """A3: compose unreadable."""
    rows = update_row_texts(None, "cannot read compose.yaml")

    assert rows[1] == "files|cannot read compose.yaml|None|"
