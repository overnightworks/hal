"""What `hal apply` does about an app that `hal stop` switched off (#255 P5, D2-D6, D10, B5):
the plan names it and fetches nothing, and a stop that comes in during the run wins wherever it
comes in, against a real origin and a scripted Docker."""

import dataclasses
from collections.abc import Callable
from pathlib import Path

import pytest
from support.app_support import HOSTED_COMPOSE, HOSTED_FLEET, KEY, NOW, SENTINEL, Origin
from support.stack_apps import (
    EDGE_FLEET,
    FIRST,
    SECOND,
    World,
    deploy,
    docker,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    origin,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    runtime,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    world,  # noqa: F401 the fixture, requested by name below
)

from hal.stack import apps, barrier, catalog, switches

DOMAIN = "edge-fixture.invalid"
BARRIER = "the barrier a stop wrote\n"


@pytest.fixture
def hosted(world, repository, origin: Origin) -> World:  # noqa: F811
    """The world of an app with a host behind Traefik, so a stop leaves a barrier."""
    (repository / "fleet.yaml").write_text(f"cloudflare:\n  zone: {DOMAIN}\n{HOSTED_FLEET}")
    origin.commit({"compose.yaml": HOSTED_COMPOSE})
    origin.push("master")
    traefik = {"traefik": {"environment": {"EDGE_DOMAIN": DOMAIN}}}
    world.fleet = dataclasses.replace(EDGE_FLEET, config={"name": "edge", "services": traefik})
    return world


def barrier_file(world: World) -> Path:  # noqa: F811
    return world.repository / barrier.DYNAMIC_DIRECTORY / f"switch-{KEY}.yml"


def switch_off_meanwhile(world: World) -> None:  # noqa: F811
    """Another operator's `hal stop`: the marker first, then the barrier."""
    world.marks.record(KEY, NOW)
    barrier_file(world).parent.mkdir(exist_ok=True)
    barrier_file(world).write_text(BARRIER)


def in_the_first_look_after_the_start(world: World, happening: Callable[[], None]) -> None:  # noqa: F811
    """`happening` right after the first `ps` that follows `start`, the health wait's first look."""

    def once() -> None:
        world.docker.during.pop("ps")
        happening()

    world.docker.during["start"] = lambda: world.docker.during.update(ps=once)


STOPPED_LINE = "since 22.10. 12:00; not started"


def test_a_stopped_app_stays_stopped_and_is_neither_fetched_nor_built(world, origin):  # noqa: F811
    origin.release(FIRST)
    switch_off_meanwhile(world)
    world.runtime = dataclasses.replace(
        world.runtime, git=lambda *call: pytest.fail("git was asked")
    )

    plan = world.plan()

    assert plan.changes_nothing
    assert plan.kept == (apps.StaysStoppedNote(KEY, NOW.isoformat()),)
    assert world.docker.verbs == ["ps"]  # file-free: is anything of it still running?
    assert not world.srv.exists()


def test_a_barrier_left_without_a_marker_keeps_the_app_stopped(world, origin, repository):  # noqa: F811
    origin.release(FIRST)
    (repository / "dynamic").mkdir()
    (repository / "dynamic" / f"switch-{KEY}.yml").write_text("barrier\n")

    plan = world.plan()

    assert plan.changes_nothing
    assert plan.kept == (apps.StaysStoppedNote(KEY, None),)
    assert world.docker.verbs == ["ps"]  # file-free: is anything of it still running?


def test_a_stop_during_the_build_runs_no_create_and_keeps_the_record_and_the_barrier(
    hosted,
    origin,  # noqa: F811
):
    deploy(hosted, origin, FIRST)
    origin.release(SECOND)
    plan = hosted.plan()
    hosted.docker.calls.clear()
    hosted.docker.during["build"] = lambda: switch_off_meanwhile(hosted)

    assert hosted.held_off_causes(plan) == [STOPPED_LINE]

    assert "create" not in hosted.docker.verbs
    assert hosted.deployed()["tag"] == FIRST
    assert hosted.marks.mark(KEY) is not None
    assert barrier_file(hosted).read_text() == BARRIER


def test_a_stop_during_the_health_wait_ends_it_early_and_removes_what_started_under_the_lock(
    hosted,
    origin,  # noqa: F811
):
    hosted.docker.health_after_start = "starting"
    origin.release(FIRST)
    in_the_first_look_after_the_start(hosted, lambda: switch_off_meanwhile(hosted))

    assert hosted.held_off_causes() == [STOPPED_LINE]

    assert hosted.runtime.health.clock() < apps.HEALTH_SECONDS  # the wait ended early
    first_look = hosted.docker.calls[hosted.docker.verbs.index("start") + 1]
    assert first_look[0] == "ps"
    assert not first_look[2]  # the wait holds no lock a stop waits for
    assert hosted.deployed() is None
    assert hosted.docker.rows == []
    assert {"create", "start", "stop", "rm"} <= hosted.docker.locked_verbs()
    assert hosted.docker.verbs.count("start") == 1
    assert barrier_file(hosted).read_text() == BARRIER


def test_a_stop_in_the_look_that_finds_the_app_healthy_is_seen_under_the_lock_before_the_record(
    hosted,
    origin,  # noqa: F811
):
    origin.release(FIRST)
    in_the_first_look_after_the_start(hosted, lambda: switch_off_meanwhile(hosted))

    assert hosted.held_off_causes() == [STOPPED_LINE]

    assert hosted.deployed() is None
    assert hosted.docker.rows == []
    assert {"stop", "rm"} <= hosted.docker.locked_verbs()
    assert barrier_file(hosted).read_text() == BARRIER


def test_an_off_step_that_fails_after_a_stop_won_adds_its_failure_to_the_stop_line(
    hosted,
    origin,  # noqa: F811
):
    hosted.docker.health_after_start = "starting"
    hosted.docker.failing_verb = "stop"
    origin.release(FIRST)
    in_the_first_look_after_the_start(hosted, lambda: switch_off_meanwhile(hosted))

    [result] = hosted.run()

    failure = result.cause

    assert failure.startswith(f"{STOPPED_LINE}; could not stop the containers of {KEY}, ")
    assert SENTINEL not in failure
    assert hosted.deployed() is None


def test_a_start_that_ends_the_switch_before_apply_looks_again_is_not_undone_by_apply(
    hosted,
    origin,  # noqa: F811
    monkeypatch,
):
    hosted.docker.health_after_start = "starting"
    origin.release(FIRST)
    in_the_first_look_after_the_start(hosted, lambda: switch_off_meanwhile(hosted))
    taken_lock = switches.Switches.lock
    takes: list[None] = []

    def lock(marks: switches.Switches):
        takes.append(None)
        if len(takes) == 2:  # apply's look after the wait: the operator's `hal start` came first
            assert hosted.marks.clear(KEY, hosted.marks.mark(KEY))
            barrier_file(hosted).unlink()
        return taken_lock(marks)

    monkeypatch.setattr(switches.Switches, "lock", lock)

    [result] = hosted.run()
    assert isinstance(result, apps.AppFailed)
    assert result.cause == "was switched off and on again during the health wait; not recorded"

    assert hosted.deployed() is None
    assert {row["State"] for row in hosted.docker.rows} == {"running"}
    assert not {"stop", "rm"} & set(hosted.docker.verbs)


def test_a_barrier_that_appears_meanwhile_stops_the_run_like_a_marker(world, origin, repository):  # noqa: F811
    origin.release(FIRST)
    (repository / "dynamic").mkdir()

    def barrier_stands() -> None:
        (repository / "dynamic" / f"switch-{KEY}.yml").write_text("barrier\n")

    world.docker.during["build"] = barrier_stands

    assert world.held_off_causes() == ["not started"]
    assert "create" not in world.docker.verbs


def test_a_stop_is_reported_in_place_of_a_start_that_failed(world, origin):  # noqa: F811
    origin.release(FIRST)
    world.docker.failing_verb = "start"
    world.docker.during["create"] = lambda: switch_off_meanwhile(world)

    [result] = world.run()

    failure = result.cause

    assert failure == STOPPED_LINE


@pytest.mark.parametrize(
    ("document", "named"),
    [
        ({"services": {KEY: {"repo": {}, "run": {"enabled": True}}}}, True),
        ({"services": {KEY: {"repo": {}, "run": {"enabled": False}}}}, False),
        ({"services": {KEY: {"repo": {}, "run": {}}}}, False),
        ({"services": {KEY: {"repo": {}, "run": ["enabled"]}}}, False),
        ({"services": {KEY: {"run": {"enabled": True}}}}, False),
        ({"services": {"other": {"repo": {}, "run": {"enabled": True}}}}, False),
        (["services"], False),
    ],
)
def test_only_an_enabled_app_entry_of_the_catalog_is_named_an_enabled_app(document, named):
    assert catalog.is_enabled_app(document, KEY) is named
