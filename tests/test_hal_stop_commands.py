"""`hal stop <unit>` (#513): one row, the barrier and the stop as it observed them, and hal's exits.
Cells run in process through `hal.cli.main` on the fixtures of
`tests/support/hal_stack_commands.py`."""

import functools
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest
from support.app_support import FLEET, KEY
from support.hal_stack_commands import (
    UNIT,
    Fakes,
    Result,
    ctrl_c,
    fakes,  # noqa: F401 the fixture, requested by name below
    hal,  # noqa: F401 the fixture, requested by name below
    system_commands,  # noqa: F401 the autouse guard that no real system command runs
    systemd,  # noqa: F401 the fixture, used by `fakes`
)
from support.stack_apply import (
    PROBE_ENABLED,
    STEP_CA_SERVICES,
    ZONE,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    marker,
    realm_backup,  # noqa: F401 the fixture, used by `app_world`
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, used by `app_world`
    write_fleet,
)
from support.stack_apply_apps import (
    app_world,  # noqa: F401 the fixture, requested by name below
    deployed,
)
from support.stack_apply_fakes import (
    InterruptedWaitForLock,
)
from support.stack_apply_publish import repository  # noqa: F401 the fixture, requested by name below
from support.stack_external import (
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
)
from support.stack_global_stop import hosts_asked  # noqa: F401 the fixture, used by `fakes`

from hal.grammar import ExitCode
from hal.output import EVENT_WIDTH
from hal.stack import barrier, catalog, emergency, switch_events, switches
from hal.stack import cli as stack
from hal.stack.switch_events import SwitchEvent

# --- hal stop <unit> -------------------------------------------------------------------------


def squeezed(text: str) -> str:
    """The text with every run of blanks as one space, so a test names no column width."""
    return " ".join(text.split())


def assert_never_switched_off(result: Result) -> None:
    """The safety rule of a partial stop, at the row level: no `✓` and not the words, anywhere."""
    assert "✓" not in result.text
    assert "switched off" not in result.text


def assert_partial(result: Result, row: str, cause: str) -> None:
    """One `✗ … partial` row on stdout, then the error pair on stderr, and hal's exit 3."""
    assert result.exit_code == ExitCode.FAILURE
    assert squeezed(result.out) == f"✗ {UNIT} partial {row}"
    assert result.err.splitlines()[0].startswith(f"error: {UNIT} is only partly off · ")
    assert cause in result.err
    assert result.err.splitlines()[1:] == [f"next: hal stop {UNIT}"]
    assert_never_switched_off(result)


def probe_running(fakes: Fakes) -> None:  # noqa: F811
    write_fleet(fakes.repository, PROBE_ENABLED)
    fakes.scripted.containers = {"hello": "running"}


def interrupt_the_lock_wait(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        stack,
        "switches",
        SimpleNamespace(
            Switches=InterruptedWaitForLock,
            default_state_directory=switches.default_state_directory,
        ),
    )


def unrecordable(directory: Path, unit: str = UNIT) -> None:
    """The switch of `unit` cannot be written, but the lock can be taken."""
    (directory / "stopped" / unit).mkdir(parents=True)


def test_stop_of_a_unit_with_no_host_prints_one_row_and_writes_the_marker(hal, fakes):  # noqa: F811
    """S1"""
    fakes.unit_in("A")

    result = hal("stop", UNIT)

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == (
        f"✓ {UNIT} switched off no host, so no barrier · stopped · volumes kept"
    )
    assert result.err == ""
    assert fakes.marker() is not None
    assert fakes.scripted.containers == dict.fromkeys(STEP_CA_SERVICES, "exited")


def test_stop_of_a_unit_behind_traefik_says_the_barrier_is_up(hal, fakes):  # noqa: F811
    probe_running(fakes)

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == "✓ probe switched off barrier up · stopped · volumes kept"
    assert result.err == ""


def write_probe_with_a_moved_host(fakes: Fakes, enabled: bool = True) -> None:  # noqa: F811
    moved = "{name: probe, exposure: public, reason: elsewhere, tunnel: platform}"
    hosts = f"    hosts: [{moved}, {{name: own, exposure: public, reason: here}}]\n"
    entry = (
        PROBE_ENABLED
        if enabled
        else PROBE_ENABLED.replace(
            "probe:\n    run: {enabled: true}", "probe:\n    run: {enabled: false}"
        )
    )
    write_fleet(fakes.repository, f"cloudflare: {{zone: {ZONE}}}\n{entry}{hosts}")


def test_stop_of_a_unit_names_each_host_another_tunnel_still_serves(hal, fakes):  # noqa: F811
    fakes.scripted.containers = {"hello": "running"}
    write_probe_with_a_moved_host(fakes)

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == (
        "✓ probe switched off barrier up · stopped · volumes kept"
        f" · probe.{ZONE} stays served by tunnel platform"
    )


@pytest.mark.parametrize("barrier_lifted", [False, True], ids=["already off", "barrier back"])
def test_a_repeated_stop_of_a_unit_still_names_each_host_another_tunnel_serves(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    barrier_lifted,
):
    fakes.probe_switched_off_behind_a_barrier()
    write_probe_with_a_moved_host(fakes)
    if barrier_lifted:
        fakes.ingress.barrier_file().unlink()

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out).endswith(f" · probe.{ZONE} stays served by tunnel platform")


def test_stop_of_a_disabled_unit_names_no_host_it_does_not_publish(hal, fakes):  # noqa: F811
    fakes.scripted.containers = {"hello": "running"}
    write_probe_with_a_moved_host(fakes, enabled=False)

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.OK
    assert "stays served" not in result.out


def test_stop_of_a_switched_off_unit_says_since_when_and_changes_nothing(hal, fakes):  # noqa: F811
    fakes.unit_in("B")

    result = hal("stop", UNIT)

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == f"· {UNIT} already off since 17.10. 22:10"
    assert result.err == ""
    assert fakes.scripted.changing_verbs() == []


def test_stop_of_a_switched_off_unit_names_the_barrier_it_put_back(hal, fakes):  # noqa: F811
    fakes.probe_switched_off_behind_a_barrier()
    fakes.ingress.barrier_file().unlink()

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == "✓ probe barrier back off since 17.10. 22:10"


def test_stop_of_a_disabled_unit_that_nothing_runs_says_so(hal, fakes):  # noqa: F811
    fakes.unit_in("E")

    result = hal("stop", UNIT)

    assert result.exit_code == ExitCode.OK
    assert squeezed(result.out) == f"· {UNIT} disabled nothing of it runs"
    assert result.err == ""


def test_stop_of_an_unknown_unit_cannot_plan_and_writes_no_marker(hal, fakes):  # noqa: F811
    """S2"""
    result = hal("stop", "x")

    assert result.exit_code == ExitCode.FAILURE
    assert result.out == ""
    assert result.err.splitlines()[0].startswith(
        "error: cannot plan, x is not a unit of fleet.yaml"
    )
    assert result.err.splitlines()[1:] == ["next: hal stop x"]
    assert marker(fakes.state, "x") is None


def test_stop_that_fails_after_the_record_is_partial_with_the_switch_kept(hal, fakes):  # noqa: F811
    fakes.unit_in("A")
    fakes.scripted.failing_verb = "stop"

    result = hal("stop", UNIT)

    assert_partial(result, "switch recorded · no host, so no barrier · not stopped", "last line")
    assert fakes.marker() is not None


def test_stop_with_a_container_still_running_is_partial_and_keeps_the_marker(hal, fakes):  # noqa: F811
    """S4"""
    fakes.unit_in("A")
    fakes.scripted.verb_stop = lambda *_: ""

    result = hal("stop", UNIT)

    assert_partial(
        result,
        "switch recorded · no host, so no barrier · not stopped",
        "a container of it still runs",
    )
    assert fakes.marker() is not None


def test_stop_that_could_record_nothing_and_stop_nothing_is_partial(hal, fakes):  # noqa: F811
    fakes.unit_in("A")
    fakes.scripted.failing_verb = "stop"
    unrecordable(fakes.state)

    result = hal("stop", UNIT)

    assert_partial(
        result, "switch not recorded · no host, so no barrier · not stopped", "last line"
    )


def test_stop_that_stopped_but_could_not_record_says_apply_would_start_it_again(hal, fakes):  # noqa: F811
    fakes.unit_in("A")
    unrecordable(fakes.state)

    result = hal("stop", UNIT)

    assert_partial(
        result,
        "switch not recorded · no host, so no barrier · stopped, hal apply would start it again",
        "cannot read the switch of step-ca",
    )
    assert fakes.scripted.containers == dict.fromkeys(STEP_CA_SERVICES, "exited")


def test_stop_whose_lock_cannot_be_taken_is_partial_and_does_not_blame_the_record(hal, fakes):  # noqa: F811
    fakes.unit_in("A")
    (fakes.state / "switch.lock").mkdir(parents=True)

    result = hal("stop", UNIT)

    assert_partial(
        result,
        "switch recorded · no host, so no barrier · stopped · "
        "lock not taken, a start in progress may reopen it",
        "cannot take the switch lock",
    )


def test_stop_whose_barrier_traefik_rejects_is_partial_and_still_stops_the_unit(hal, fakes):  # noqa: F811
    probe_running(fakes)
    fakes.ingress.rejecting = True

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.FAILURE
    assert squeezed(result.out) == "✗ probe partial switch recorded · barrier not proven · stopped"
    assert "Traefik did not answer the barrier's 404" in result.err
    assert result.err.splitlines()[-1] == "next: hal stop probe"
    assert_never_switched_off(result)
    assert fakes.scripted.containers == {"hello": "exited"}


def test_stop_whose_barrier_is_not_proven_and_record_failed_says_both(hal, fakes):  # noqa: F811
    probe_running(fakes)
    fakes.ingress.down = True
    unrecordable(fakes.state, "probe")

    result = hal("stop", "probe")

    assert squeezed(result.out) == (
        "✗ probe partial switch not recorded · barrier not proven · "
        "stopped, hal apply would start it again"
    )
    assert_never_switched_off(result)


def test_stop_whose_barrier_is_not_proven_and_stop_failed_names_each_part(hal, fakes):  # noqa: F811
    probe_running(fakes)
    fakes.ingress.rejecting = True
    fakes.scripted.failing_verb = "stop"

    result = hal("stop", "probe")

    assert squeezed(result.out) == (
        "✗ probe partial switch recorded · barrier not proven · not stopped"
    )
    assert "Traefik did not answer the barrier's 404" in result.err
    assert "last line" in result.err
    assert_never_switched_off(result)


def test_stop_interrupted_while_waiting_for_a_switched_off_unit_keeps_the_marker(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
):
    fakes.unit_in("B")
    interrupt_the_lock_wait(monkeypatch)

    result = hal("stop", UNIT)

    assert_partial(
        result, "interrupted while waiting · switch recorded", "interrupted while waiting"
    )
    assert fakes.marker() is not None


def test_stop_interrupted_while_waiting_for_the_switch_lock_keeps_the_marker(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
):
    """S3 (E2)"""
    fakes.unit_in("A")
    interrupt_the_lock_wait(monkeypatch)

    result = hal("stop", UNIT)

    assert_partial(
        result, "interrupted while locking · switch recorded", "interrupted while locking"
    )
    assert "waiting to stop it" not in result.text
    assert fakes.marker() is not None


def test_stop_interrupted_while_raising_the_barrier_does_not_say_the_barrier_is_up(hal, fakes):  # noqa: F811
    probe_running(fakes)

    def interrupt() -> None:
        raise KeyboardInterrupt

    fakes.ingress.on_fetch = interrupt

    result = hal("stop", "probe")

    assert result.exit_code == ExitCode.FAILURE
    assert squeezed(result.out) == (
        "✗ probe partial interrupted while raising the barrier · switch recorded"
    )
    assert "barrier up" not in result.text
    assert_never_switched_off(result)


def test_stop_interrupted_while_stopping_keeps_what_was_proven(hal, fakes):  # noqa: F811
    fakes.unit_in("A")

    def interrupt(*_):
        raise KeyboardInterrupt

    fakes.scripted.verb_stop = interrupt

    result = hal("stop", UNIT)

    assert_partial(
        result,
        "interrupted while stopping · switch recorded · no host, so no barrier",
        "interrupted while stopping",
    )


def test_stop_without_a_terminal_switches_off_and_never_reads_stdin(hal, fakes):  # noqa: F811
    """S5: `hal` gives `UnreadableStdin` to a run without answers."""
    fakes.unit_in("A")

    result = hal("stop", UNIT)

    assert result.exit_code == ExitCode.OK
    assert "✓ step-ca" in result.out
    assert fakes.marker() is not None


@pytest.mark.parametrize("event", list(SwitchEvent))
def test_every_stop_event_fits_the_event_column_so_the_facts_align(event: SwitchEvent) -> None:
    assert len(event) <= EVENT_WIDTH


# --- a Ctrl-C while hal stop plans or records (#577) ----------------------------------------------

PLANNING = "planning"
RECORDING = "recording"


def stops_the_app(monkeypatch: pytest.MonkeyPatch, app_world) -> None:  # noqa: F811
    """`hal stop` on the app of `app_world`, over the same scripted boundaries as the units."""
    monkeypatch.setattr(
        emergency, "stop_unit", functools.partial(emergency.stop_unit, runtime=app_world.runtime)
    )


def interrupt_in(monkeypatch: pytest.MonkeyPatch, owner: object, name: str) -> None:
    monkeypatch.setattr(owner, name, ctrl_c)


def spy_on_marker_reads(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    reads: list[str] = []
    mark = switches.Switches.mark

    def spy(self, unit):
        reads.append(unit)
        return mark(self, unit)

    monkeypatch.setattr(switches.Switches, "mark", spy)
    return reads


def interrupt_after_the_publish(monkeypatch: pytest.MonkeyPatch) -> None:
    publish = switches._link_unless_present

    def publish_then_interrupt(source, path):
        publish(source, path)
        raise KeyboardInterrupt

    monkeypatch.setattr(switches, "_link_unless_present", publish_then_interrupt)


def interrupt_the_record(monkeypatch: pytest.MonkeyPatch, *, after_the_publish: bool) -> None:
    record = switches.Switches.record

    def interrupted_record(self, unit, now):
        if after_the_publish:
            record(self, unit, now)
        raise KeyboardInterrupt

    monkeypatch.setattr(switches.Switches, "record", interrupted_record)


def interrupt_the_barrier_of(monkeypatch: pytest.MonkeyPatch, constructor: str) -> None:
    monkeypatch.setattr(barrier.Barrier, constructor, ctrl_c)


def assert_nothing_changed(result: Result, key: str, step: str = PLANNING) -> None:
    assert result.exit_code == ExitCode.FAILURE
    assert result.out == ""
    assert result.err.splitlines() == [
        f"error: interrupted while {step} · nothing changed",
        f"next: hal stop {key}",
    ]
    assert_never_switched_off(result)


def assert_recorded(result: Result, key: str, step: str) -> None:
    assert result.exit_code == ExitCode.FAILURE
    assert squeezed(result.out) == f"✗ {key} partial interrupted while {step} · switch recorded"
    assert result.err.splitlines() == [
        f"error: {key} is only partly off · interrupted while {step}",
        f"next: hal stop {key}",
    ]
    assert_never_switched_off(result)
    assert "Traceback" not in result.err


def app_marker(app_world) -> str | None:  # noqa: F811
    return switches.Switches(app_world.state).since(KEY)


def test_stop_interrupted_reading_the_catalog_of_an_enabled_app_changes_nothing(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 1: the interrupt comes before any record is attempted."""
    interrupt_in(monkeypatch, catalog, "is_enabled_app")

    assert_nothing_changed(hal("stop", KEY), KEY)
    assert app_marker(app_world) is None


def test_stop_interrupted_before_the_record_is_published_leaves_no_marker_and_no_temporary_file(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 2"""
    interrupt_in(monkeypatch, switches, "_link_unless_present")

    assert_nothing_changed(hal("stop", KEY), KEY)
    assert [path for path in app_world.state.rglob("*") if path.is_file()] == []


def test_stop_interrupted_after_the_record_is_published_says_the_switch_is_recorded(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 3: the record raised, yet it is the marker that is read, not the return value."""
    interrupt_after_the_publish(monkeypatch)

    assert_recorded(hal("stop", KEY), KEY, PLANNING)
    assert app_marker(app_world) is not None


@pytest.mark.parametrize("marked", [False, True], ids=["no marker", "marker"])
def test_stop_of_a_running_app_interrupted_in_compose_config_says_the_switch_is_recorded(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    marked,
):
    """Cells 4 and 6b: record-first wrote the marker, or it stood."""
    deployed(app_world)
    if marked:
        switches.Switches(app_world.state).record(KEY, datetime(2026, 10, 1, tzinfo=UTC))
    fakes.scripted.verb_config = ctrl_c

    assert_recorded(hal("stop", KEY), KEY, PLANNING)
    assert app_marker(app_world) is not None


@pytest.mark.parametrize("situation", ["A", "B"], ids=["no marker", "marker of an earlier stop"])
def test_stop_of_a_unit_interrupted_in_compose_config_changes_nothing_and_reads_no_marker(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
    situation,
):
    """Cells 5 and 6: a marker that predates this run is not this run's."""
    fakes.unit_in(situation)
    fakes.scripted.verb_config = ctrl_c
    before = fakes.marker()
    reads = spy_on_marker_reads(monkeypatch)

    assert_nothing_changed(hal("stop", UNIT), UNIT)
    assert reads == []
    assert fakes.marker() == before
    assert (before is None) == (situation == "A")


def test_stop_of_a_disabled_app_interrupted_in_compose_config_changes_nothing(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 7"""
    write_fleet(
        app_world.repository,
        f"cloudflare:\n  zone: {ZONE}\n" + FLEET.replace("enabled: true", "enabled: false"),
    )
    fakes.scripted.verb_config = ctrl_c

    assert_nothing_changed(hal("stop", KEY), KEY)
    assert app_marker(app_world) is None


def test_stop_of_an_unknown_key_interrupted_reading_the_apps_names_the_key_as_typed(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
):
    """Cell 8"""
    interrupt_in(monkeypatch, catalog, "apps")

    assert_nothing_changed(hal("stop", "no-such-unit"), "no-such-unit")


def test_edge_stop_interrupted_while_planning_ends_with_exit_1_and_no_traceback(
    fakes,  # noqa: F811
    capsys,
):
    """Cell 20 under the stack's own entry: its exit, `ApplyExit.REFUSED`."""
    fakes.unit_in("A")
    fakes.scripted.verb_config = ctrl_c

    exit_code = emergency.stop_unit(
        switches.Switches(fakes.state), UNIT, datetime(2026, 10, 1, tzinfo=UTC)
    )

    assert exit_code == 1
    assert "Traceback" not in capsys.readouterr().err


def test_stop_of_a_key_that_is_a_path_builds_no_path_and_reads_no_marker(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
):
    """Cell 8b"""
    key = f"../{switches.GLOBAL_STOP_FILE}"
    fakes.scripted.verb_config = ctrl_c
    reads = spy_on_marker_reads(monkeypatch)

    assert_nothing_changed(hal("stop", key), key)
    assert reads == []


def test_stop_of_an_enabled_app_interrupted_while_planning_its_target_says_the_switch_is_recorded(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 9: the interrupt comes while the barrier of the app is built."""
    interrupt_the_barrier_of(monkeypatch, "of_app")

    assert_recorded(hal("stop", KEY), KEY, PLANNING)


def test_stop_of_an_enabled_app_interrupted_looking_for_containers_says_the_switch_is_recorded(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 11: the app's own `ps` is the look for containers."""
    stops_the_app(monkeypatch, app_world)
    app_world.docker.interrupted_verb = "ps"

    assert_recorded(hal("stop", KEY), KEY, PLANNING)


@pytest.mark.parametrize("situation", ["A", "B"], ids=["unit", "unit with a marker"])
def test_stop_of_a_unit_interrupted_while_planning_its_target_changes_nothing(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
    situation,
):
    """Cell 10 (and P5·d)"""
    fakes.unit_in(situation)
    interrupt_the_barrier_of(monkeypatch, "of_unit")

    assert_nothing_changed(hal("stop", UNIT), UNIT)


@pytest.mark.parametrize("situation", ["A", "B"], ids=["unit", "unit with a marker"])
def test_stop_of_a_unit_interrupted_looking_for_containers_changes_nothing(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    situation,
):
    """Cells 12-13: the first `ps` of a stop is the look for containers."""
    fakes.unit_in(situation)
    fakes.scripted.verb_ps = ctrl_c

    assert_nothing_changed(hal("stop", UNIT), UNIT)


@pytest.mark.parametrize(
    ("situation", "after_the_publish", "marker_stands"),
    [("A", False, False), ("A", True, True), ("B", False, True)],
    ids=["P7 no marker", "P8 no marker", "P7 marker"],
)
def test_stop_interrupted_in_the_record_before_the_lock_reads_the_marker_it_left(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
    situation,
    after_the_publish,
    marker_stands,
):
    """Cells 14-16. A unit with a marker that is running is closed, not waited for."""
    fakes.unit_in("A")
    if situation == "B":
        switches.Switches(fakes.state).record(UNIT, datetime(2026, 10, 1, tzinfo=UTC))
    interrupt_the_record(monkeypatch, after_the_publish=after_the_publish)

    result = hal("stop", UNIT)

    if marker_stands:
        assert_recorded(result, UNIT, RECORDING)
    else:
        assert_nothing_changed(result, UNIT, RECORDING)


def test_stop_interrupted_planning_an_app_whose_marker_cannot_be_read_gives_the_read_error(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    app_world,  # noqa: F811
    monkeypatch,
):
    """Cell 17: a record that failed is still an attempted one, and never `nothing changed`."""
    (app_world.state / switches.STOPPED_DIRECTORY / KEY).mkdir(parents=True)
    fakes.scripted.verb_config = ctrl_c

    result = hal("stop", KEY)

    assert result.exit_code == ExitCode.FAILURE
    assert result.out == ""
    assert result.err.splitlines()[0].startswith(
        f"error: interrupted while planning · cannot read the switch of {KEY} ("
    )
    assert "nothing changed" not in result.err
    assert result.err.splitlines()[1:] == [f"next: hal stop {KEY}"]


@pytest.mark.parametrize("report", ["report_cannot_plan", "report_disabled", "report_already_off"])
def test_a_ctrl_c_inside_a_report_of_stop_reaches_the_door_with_130(
    hal,  # noqa: F811
    fakes,  # noqa: F811
    monkeypatch,
    report,
):
    """Cells 18b-d: the span holds no report."""
    if report == "report_cannot_plan":
        key = "no-such-unit"
    elif report == "report_disabled":
        fakes.unit_in("E")
        fakes.scripted.containers = {}
        key = UNIT
    else:
        fakes.unit_in("B")
        key = UNIT
    interrupt_in(monkeypatch, switch_events, report)

    result = hal("stop", key)

    assert result.exit_code == ExitCode.INTERRUPTED
    assert "interrupted while" not in result.text
