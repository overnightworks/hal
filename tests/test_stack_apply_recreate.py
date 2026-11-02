"""Apply recreates a running unit service whose compose definition changed, never its image
(#376), on the scripted boundaries of `tests/support/stack_apply.py`."""

import pytest
from support.stack_apply import (
    APP_EXITED,
    DISABLED,
    ENABLED,
    OLD_IMAGE,
    RECREATE_FOLLOWER,
    RECREATE_TRAEFIK,
    STEP_CA_BUMP,
    STEP_CA_ON,
    STEP_CA_SERVICES,
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    interrupted_at_the_prompt,
    realm_backup,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    start,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    step_ca_applied,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    switch_off,
    up_calls,
    write_fleet,
)
from support.stack_apply_fakes import (
    IMAGE,
)
from support.stack_plan_rows import find_row, plain

from hal.stack.plan_rows import PlanEvent
from hal.stack.result_rows import ResultEvent

RECREATE_STEP_CA = [*RECREATE_TRAEFIK[:-1], "step-ca"]
RECREATE_KEYCLOAK_DB = [*RECREATE_TRAEFIK[:-1], "keycloak-db"]
RECREATE_KEYCLOAK = [*RECREATE_TRAEFIK[:-1], "keycloak"]
LOCAL_TAG = "edge-local:1"
REBUILT_IMAGE_ID = f"sha256:{'f' * 64}"
KEYCLOAK_DB_IMAGE = f"postgres:18@sha256:{'5' * 64}"
BOTH_UNITS = ENABLED + "  keycloak:\n    run: {enabled: true, setup: keycloak/init}\n"
DRIFTS = {
    "a unit service": (["step-ca"], [RECREATE_STEP_CA]),
    "a follower": (["traefik-mcp"], [RECREATE_FOLLOWER]),
    "a follower and a unit service, the follower in the core phase first": (
        ["traefik-mcp", "step-ca"],
        [RECREATE_FOLLOWER, RECREATE_STEP_CA],
    ),
    "the core and a unit service, the core first": (
        ["traefik", "step-ca"],
        [RECREATE_TRAEFIK, RECREATE_STEP_CA],
    ),
}


@pytest.fixture
def two_units_applied(
    step_ca_applied,  # noqa: F811
    realm_unit,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
    switch,  # noqa: F811
):
    """step-ca and Keycloak on and applied, every container from the current definitions; the
    services stand in the order Compose resolves them, alphabetical, so Keycloak comes before the
    database it depends on; the calls so far are forgotten."""
    services = scripted.config["services"]
    services["keycloak-db"] = {
        "image": KEYCLOAK_DB_IMAGE,
        "profiles": ["keycloak"],
        "volumes": [{"type": "volume", "source": "keycloak-db", "target": "/data"}],
    }
    services["keycloak"]["depends_on"] = {
        "keycloak-db": {"condition": "service_healthy", "required": True}
    }
    write_fleet(repository, BOTH_UNITS)
    scripted.put_containers({"keycloak-db": "running", "keycloak": "running"})
    scripted.volumes["keycloak-db"] = "the database"
    assert switch()[0] == 0
    scripted.calls.clear()


@pytest.mark.parametrize(("drifted", "recreated"), DRIFTS.values(), ids=DRIFTS)
def test_a_changed_definition_recreates_a_running_unit_service_alone_then_nothing_changes(
    drifted,
    recreated,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 slice 1, cells M3, M16, M19, M4: one plan, one yes, each recreate by its own argv
    with the other containers (the completed acme owner included) kept; a second run is quiet."""
    ids = dict(scripted.container_ids)
    for service in drifted:
        scripted.change_definition(service)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert bool(find_row(out, "step-ca", PlanEvent.RECREATE, "definition changed")) == (
        "step-ca" in drifted
    )
    for service in ("step-ca", "traefik-mcp"):
        assert bool(find_row(out, service, ResultEvent.RECREATED, "5s")) == (service in drifted)
    assert up_calls(scripted) == recreated
    assert {service for service in ids if scripted.container_ids[service] != ids[service]} == set(
        drifted
    )
    scripted.calls.clear()
    exit_code, out, _ = switch(answer="no")
    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def test_a_declined_yes_recreates_nothing(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 invariant 1, cell M2: the recreate is a plan line and a no changes nothing."""
    ids = dict(scripted.container_ids)
    scripted.change_definition("step-ca")

    exit_code, out, err = switch(answer="no")

    assert exit_code == 1
    assert find_row(out, "step-ca", PlanEvent.RECREATE, "definition changed")
    assert "aborted, nothing changed" in err
    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


def test_keycloak_is_recreated_alone_with_its_database_and_volume_kept_and_its_realm_not_checked(
    two_units_applied,
    switch,  # noqa: F811
    scripted,  # noqa: F811
    realm_backup,  # noqa: F811
):
    """#376 cells M1, M14, M21 (the go-live overlay's label differs the same way): the sign-in
    service gets a new container; the database keeps its id and volume, step-ca is untouched; the
    realm waits for the next apply."""
    ids = dict(scripted.container_ids)
    realm_before = (list(realm_backup.asked), scripted.realm_applies)
    scripted.change_definition("keycloak")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "keycloak", PlanEvent.RECREATE, "definition changed")
    assert PlanEvent.REALM_LATER in out
    assert up_calls(scripted) == [RECREATE_KEYCLOAK]
    assert scripted.container_ids["keycloak"] != ids["keycloak"]
    assert {s: scripted.container_ids[s] for s in ids if s != "keycloak"} == {
        s: ids[s] for s in ids if s != "keycloak"
    }
    assert scripted.volumes["keycloak-db"] == "the database"
    realm_after = (realm_backup.asked, scripted.realm_applies)
    assert realm_after == realm_before


def test_a_recreate_of_only_the_keycloak_database_holds_the_realm_check_and_says_so(
    two_units_applied,
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """M14 (#376): a recreate in the realm unit holds the realm check; a database-only one
    says the database restarts, not Keycloak."""
    scripted.change_definition("keycloak-db")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert PlanEvent.REALM_LATER in out
    assert "Keycloak starts now" not in out


def test_two_units_with_a_changed_definition_are_two_lines_in_dependency_order_under_one_yes(
    two_units_applied,
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 cells M11, M23: step-ca's unit first (catalog order), the database before Keycloak
    that depends on it, though Compose lists Keycloak first."""
    for service in ("keycloak", "keycloak-db", "step-ca"):
        scripted.change_definition(service)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert up_calls(scripted) == [RECREATE_STEP_CA, RECREATE_KEYCLOAK_DB, RECREATE_KEYCLOAK]


def test_an_image_change_is_named_and_a_definition_change_beside_it_recreates_nothing_else(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 invariant 2, cells M5, M6: the image of step-ca is never swapped; a service whose
    image differs is only named."""
    scripted.change_image("step-ca", STEP_CA_BUMP)
    scripted.change_definition("traefik-mcp")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert OLD_IMAGE in out
    assert not find_row(out, "step-ca", PlanEvent.RECREATE)
    assert up_calls(scripted) == [RECREATE_FOLLOWER]


def test_a_unit_switched_off_by_its_marker_stays_stopped_whatever_its_definition(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    """#376 invariant 4, cell M7."""
    switch_off(state)
    scripted.change_definition("step-ca")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.STAYS_STOPPED)
    assert not find_row(out, "step-ca", PlanEvent.RECREATE)
    assert scripted.changing_verbs() == []


def test_a_marker_that_appears_after_the_yes_wins_and_the_run_is_partial(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    """#376 invariant 4, cell M8: the recreate is taken under the switch lock."""
    ids = dict(scripted.container_ids)
    scripted.change_definition("step-ca")

    exit_code, out, err = switch(while_prompt_waits=lambda: switch_off(state))

    assert exit_code == 1
    assert not find_row(out, "step-ca", ResultEvent.RECREATED)
    assert "partial, step-ca was switched off meanwhile" in err
    assert "step-ca is not recreated" in err
    assert scripted.container_ids == ids


def test_a_disabled_unit_is_only_switched_off_not_recreated(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    """#376 invariant 4, cell M9."""
    scripted.change_definition("step-ca")
    write_fleet(repository, DISABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.SWITCH_OFF)
    assert not find_row(out, "step-ca", PlanEvent.RECREATE)
    assert up_calls(scripted) == []


def test_a_unit_planned_on_is_started_without_recreating_its_running_service(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 invariant 3, cell M10 (#75): the switch-on keeps `--no-recreate`."""
    scripted.put_containers(APP_EXITED)
    scripted.change_definition("step-ca")
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert not find_row(out, "step-ca", PlanEvent.RECREATE)
    assert up_calls(scripted) == [
        ["--profile", "step-ca", "up", "-d", "--no-recreate", *STEP_CA_SERVICES]
    ]
    assert scripted.container_ids["step-ca"] == ids["step-ca"]


def test_edge_start_keeps_the_running_service_of_a_changed_definition(
    start,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    """#376 invariant 3, cell M20."""
    switch_off(state)
    scripted.put_containers(STEP_CA_ON)
    scripted.change_definition("step-ca")
    ids = dict(scripted.container_ids)

    exit_code, _, _ = start()

    assert exit_code == 0
    assert scripted.container_ids == ids


NO_UNIT_SWITCHED = "; no unit switched"
FAILING_RECREATES = {
    "an up that fails": (
        lambda world: setattr(world, "failing_verb", "up"),
        "partial, could not recreate step-ca, `docker compose up` exited 1",
        NO_UNIT_SWITCHED,
    ),
    "a container that crashes in the watch": (
        lambda world: world.crash_loops.add("step-ca"),
        "partial, step-ca is not running after the step-ca recreate",
        NO_UNIT_SWITCHED,
    ),
    "a Ctrl-C": (
        lambda world: setattr(world, "after_up", interrupted_at_the_prompt),
        "interrupted while changing step-ca (recreate step-ca)",
        "its state may be partial",
    ),
}


@pytest.mark.parametrize(
    ("arrange", "line", "after"), FAILING_RECREATES.values(), ids=FAILING_RECREATES
)
def test_a_recreate_that_fails_is_partial_and_no_unit_is_switched(
    arrange,
    line,
    after,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 cells M12, M13, M22: exit 1 naming the step; after a failed recreate or a crash no unit
    is switched."""
    scripted.change_definition("step-ca")
    arrange(scripted)

    exit_code, _, err = switch()

    assert exit_code == 1
    assert line in err
    assert after in err


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("labels", "cannot plan, a step-ca container has no com.docker.compose.config-hash label"),
        (
            "images",
            "cannot plan, a live step-ca container's `docker compose ps` line names no Image",
        ),
    ],
    ids=["missing config hash", "missing image"],
)
def test_a_live_unit_container_without_required_metadata_cannot_be_planned(
    missing,
    message,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 Q2/M15 and #91 rule 3/E10: missing metadata exits 2 without changes."""
    getattr(scripted, missing)["step-ca"] = None

    exit_code, _, err = switch()

    assert exit_code == 2
    assert message in err
    assert scripted.changing_verbs() == []


def test_a_completed_one_shot_and_a_service_outside_the_catalog_are_left_alone(
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 cells M17, M18."""
    scripted.config["services"]["echo"] = {"image": IMAGE, "profiles": ["echo"]}
    scripted.put_containers({"echo": "running"})
    scripted.change_definition("echo")
    scripted.change_definition("traefik-mcp-acme-owner")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


@pytest.mark.parametrize(
    ("rebuilt", "recreated"), [(True, False), (False, True)], ids=["tag rebuilt", "tag kept"]
)
def test_a_local_tag_that_names_another_image_than_the_container_runs_is_named_not_recreated(
    rebuilt,
    recreated,
    step_ca_applied,  # noqa: F811
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """#376 Q1(a), invariant 2: a recreate resolves a tag that is not pinned by digest anew, so
    a changed definition beside a rebuilt tag swaps the image; it is only named."""
    scripted.config["services"]["step-ca"]["image"] = LOCAL_TAG
    scripted.images["step-ca"] = LOCAL_TAG
    scripted.change_definition("step-ca")
    if rebuilt:
        scripted.image_ids[LOCAL_TAG] = REBUILT_IMAGE_ID

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert bool(find_row(out, "step-ca", PlanEvent.RECREATE)) == recreated
    assert (OLD_IMAGE in out) == rebuilt
    assert up_calls(scripted) == ([RECREATE_STEP_CA] if recreated else [])
