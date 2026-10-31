"""`hal apply`, `stop`, `start`, `offline` and `online` (#208): the stack's switches behind hal's
door. Acting cells run in process through `hal.cli.main` on the fakes of the edge tests (scripted
Compose, fake systemctl, the world of `hal apply`); cells that act on nothing run as the console
script does (`run_hal`) under an empty HOME.

Nothing here may reach the real `systemctl`, `docker`, `sudo` or `pkcheck`: a directory of failing
stand-ins is first on PATH for every test, and every test ends by asserting that none was called.
The exits are hal's: 0, or 3 for every outcome of the stack that is not "applied or nothing to do"
(exception E in docs/stack.md)."""

from datetime import datetime
from pathlib import Path

import pytest
import support.hal_stack_commands as hal_stack_commands_support
from support.git_support import hal_program, run_hal
from support.hal_stack_commands import (
    UNIT,
    Guard,
    ctrl_c,
)
from support.stack_apply import (
    SWITCHED_OFF_AT,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    write_fleet,
)
from support.stack_apply_publish import (
    failing_app,  # noqa: F401 the fixture, requested by name below
    fake_tofu,  # noqa: F401 the fixture, requested by name below
    lock_held,
    not_on_main,
    nothing,
    repository,  # noqa: F401 the fixture, requested by name below
    start_fails,
    world,  # noqa: F401 the fixture, requested by name below
)
from support.stack_external import (
    CHANGING_PLAN,
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
)
from support.stack_global_stop import hosts_asked  # noqa: F401 the fixture, used by `fakes`

from hal import cli, stack_commands
from hal.grammar import ExitCode
from hal.stack import apply, checkout, emergency, switches, tunnel
from hal.stack import cli as stack
from hal.stack.update import UpdateEnd

(
    applying,
    fakes,
    hal,
    system_commands,
    systemd,
) = (
    hal_stack_commands_support.applying,
    hal_stack_commands_support.fakes,
    hal_stack_commands_support.hal,
    hal_stack_commands_support.system_commands,
    hal_stack_commands_support.systemd,
)  # fmt: skip

FIRST_STOP = datetime.fromisoformat("2026-10-17T22:10:04+02:00")


@pytest.fixture
def marks(fakes) -> switches.Switches:
    return switches.Switches(fakes.state)


@pytest.fixture
def stopped_tunnel(marks, systemd):
    marks.record_global(FIRST_STOP)
    systemd.active = False


@pytest.fixture
def empty_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """The HOME of a run that must touch nothing: `run_hal` asserts that it is still empty."""
    empty = tmp_path / "empty-home"
    empty.mkdir()
    monkeypatch.setenv("HOME", str(empty))
    return empty


def run_door(tmp_path: Path, guard: Guard, *arguments: str):
    return run_hal(tmp_path, hal_program(), *arguments, path_first=guard.directory)


# --- the door --------------------------------------------------------------------------------


def test_the_help_lists_the_five_beside_version_and_stop_names_its_unit(
    tmp_path, system_commands, empty_home
):
    """D1"""
    listing = run_door(tmp_path, system_commands, "--help")
    stop_help = run_door(tmp_path, system_commands, "stop", "--help")

    assert listing.returncode == ExitCode.OK
    for name in ("apply", "update", "stop", "start", "offline", "online", "version"):
        assert name in listing.stdout
    assert "external" not in listing.stdout
    assert stop_help.returncode == ExitCode.OK
    assert "unit" in stop_help.stdout
    update_help = run_door(tmp_path, system_commands, "update", "--help")
    assert update_help.returncode == ExitCode.OK
    assert "fast-forwards the checkout" in update_help.stdout
    assert "hal apply" in update_help.stdout


@pytest.mark.parametrize(
    ("arguments", "help_of"),
    [
        (["stop"], "stop"),
        (["start"], "start"),
        (["stop", "x", "--all"], "stop"),
        (["start", "x", "--all"], "start"),
        (["offline", "x"], "offline"),
        (["online", "x"], "online"),
        (["apply", "--closed"], "apply"),
    ],
    ids=[
        "stop alone",
        "start alone",
        "stop x --all",
        "start x --all",
        "offline x",
        "online x",
        "apply --closed",
    ],
)
def test_a_wrong_command_line_is_a_usage_error_and_no_stack_code_runs(
    tmp_path, system_commands, empty_home, arguments, help_of
):
    """D2: the parser refuses; HOME stays empty, so no state directory was made."""
    result = run_door(tmp_path, system_commands, *arguments)

    assert result.returncode == ExitCode.USAGE
    lines = result.stderr.splitlines()
    assert lines[0].startswith("error: ")
    if arguments == ["apply", "--closed"]:
        assert "unrecognized arguments: --closed" in lines[0]
    assert lines[1:] == [f"next: hal {help_of} --help"]


@pytest.mark.parametrize(
    ("stack_exit", "hal_exit"),
    [
        (apply.ApplyExit.APPLIED_OR_NOTHING, ExitCode.OK),
        (apply.ApplyExit.CANNOT_PLAN, ExitCode.FAILURE),
        (apply.ApplyExit.REFUSED, ExitCode.FAILURE),
    ],
    ids=lambda value: value.name,
)
def test_every_outcome_of_the_stack_has_one_exit_of_hal(monkeypatch, stack_exit, hal_exit):
    """D3: the door prints what the table says for each member of `ApplyExit`."""
    monkeypatch.setattr(stack, "stop_all", lambda: stack_exit)

    assert cli.main(["offline"]) == hal_exit


@pytest.mark.parametrize(
    ("update_end", "hal_exit"),
    [
        (UpdateEnd.DONE, ExitCode.OK),
        (UpdateEnd.DECLINED, ExitCode.FINDINGS),
        (UpdateEnd.REFUSED, ExitCode.REFUSED),
        (UpdateEnd.FAILED, ExitCode.FAILURE),
        (UpdateEnd.INTERRUPTED, ExitCode.INTERRUPTED),
    ],
    ids=lambda value: value.name,
)
def test_every_end_of_the_update_has_its_public_exit(monkeypatch, update_end, hal_exit):
    """#783 D1: the grammar's codes, one per end."""
    monkeypatch.setattr(stack, "update_checkout", lambda: update_end)

    assert cli.main(["update"]) == hal_exit


def test_the_update_table_names_every_member_of_its_enum():
    """#783 D1: an end added without an exit fails here."""
    assert set(stack_commands.EXIT_OF_UPDATE) == set(UpdateEnd)


def test_the_table_names_every_member_of_the_stack_enum():
    """D3: a member added to `ApplyExit` without an exit fails here, not at night in `hal stop`."""
    assert set(stack_commands.EXIT_OF_STACK) == set(apply.ApplyExit)


def test_a_ctrl_c_the_stack_does_not_catch_ends_with_130_and_no_traceback(hal, monkeypatch):
    """D4: the door's 130, with nothing printed."""
    monkeypatch.setattr(stack, "stop_unit", ctrl_c)

    result = hal("stop", UNIT)

    assert result.exit_code == ExitCode.INTERRUPTED
    assert result.out == ""
    assert result.err == ""


# --- hal apply -------------------------------------------------------------------------------


def test_apply_at_a_terminal_applies_the_local_part_then_publishes(hal, applying):
    """A1"""
    applying.fake_tofu.configure(**CHANGING_PLAN)

    result = hal("apply", answers=("yes", "yes"))

    assert result.exit_code == ExitCode.OK
    assert "hal apply: done" in result.err
    assert applying.fake_tofu.call("apply")


@pytest.mark.usefixtures("failing_app")
def test_apply_with_an_app_failing_health_is_exit_3_and_publishes_nothing(hal, applying):
    """#255 A21: edge's 1 for the partial app step is hal's 3."""
    result = hal("apply", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "partial, hopin is not healthy" in result.err
    assert applying.publish_never_began()


def test_apply_while_another_apply_runs_changes_nothing(hal, applying):
    """A2"""
    lock_held(applying)

    result = hal("apply", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "another `hal apply` or `hal update` is running; nothing changed" in result.err
    assert "hal apply: nothing published" in result.err
    assert applying.scripted.changing_verbs() == []
    assert applying.publish_never_began()


def test_apply_behind_origin_names_hal_update_and_publishes_nothing(hal, applying, monkeypatch):
    """#783 F2: the full apply ends with 3 and `nothing published`, no plan and no question."""
    monkeypatch.setattr(checkout.Git, "divergence", lambda _self, _sha: (0, 2))

    result = hal("apply", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "2 commits wait on origin main; nothing changed" in result.err
    assert "next: hal update" in result.err
    assert "hal apply: nothing published" in result.err
    assert applying.scripted.changing_verbs() == []
    assert applying.publish_never_began()


def test_apply_interrupted_at_the_plan_publishes_nothing_and_ends_with_3(hal, applying):
    """A3 (E2): the stack catches the Ctrl-C, so the exit is the stack's, not 130."""
    result = hal("apply", answers=("yes",), while_prompt_waits=ctrl_c)

    assert result.exit_code == ExitCode.FAILURE
    assert "hal apply: interrupted, nothing published" in result.err
    assert "Traceback" not in result.err
    assert applying.publish_never_began()


def test_apply_whose_compose_up_fails_is_partial_and_publishes_nothing(hal, applying):
    """A4"""
    start_fails(applying)

    result = hal("apply", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "partial, step-ca: could not" in result.err
    assert "nothing published" in result.err
    assert applying.publish_never_began()


def test_apply_without_a_terminal_is_refused_with_3_and_touches_nothing(
    tmp_path, system_commands, empty_home
):
    """A5 (E1)"""
    result = run_door(tmp_path, system_commands, "apply")

    assert result.returncode == ExitCode.FAILURE
    assert "refused, stdin and stdout must be a terminal" in result.stderr
    assert "nothing published" in result.stderr


def test_apply_local_applies_the_local_part_alone(hal, applying):
    """A6"""
    result = hal("apply", "--local", answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert "step-ca is on" in result.out
    assert applying.publish_never_began()


def test_apply_with_the_plan_declined_changes_nothing(hal, applying):
    """A7 (E1)"""
    nothing(applying)

    result = hal("apply", answers=("no",))

    assert result.exit_code == ExitCode.FAILURE
    assert "aborted, nothing changed" in result.err
    assert "nothing published" in result.err
    assert applying.scripted.changing_verbs() == []
    assert applying.publish_never_began()


def test_apply_from_a_checkout_that_is_not_a_clean_main_is_refused(hal, applying):
    """A8 (E1)"""
    not_on_main(applying)

    result = hal("apply", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "runs only on main" in result.err
    assert "nothing published" in result.err
    assert applying.scripted.changing_verbs() == []
    assert applying.publish_never_began()


# --- hal start <unit> ------------------------------------------------------------------------


def test_start_of_a_switched_off_unit_after_yes_clears_the_marker(hal, fakes):
    """T1"""
    fakes.unit_in("B")

    result = hal("start", UNIT, answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert f"{UNIT} is on" in result.out
    assert fakes.marker() is None


def test_start_with_any_answer_but_yes_aborts_and_keeps_the_marker(hal, fakes):
    """T2 (E1)"""
    fakes.unit_in("B")

    result = hal("start", UNIT, answers=("no",))

    assert result.exit_code == ExitCode.FAILURE
    assert "aborted, nothing changed" in result.err
    assert fakes.marker() == SWITCHED_OFF_AT


def test_start_interrupted_during_up_keeps_the_switch(hal, fakes):
    """T3 (E2)"""
    fakes.unit_in("B")
    fakes.scripted.verb_up = ctrl_c

    result = hal("start", UNIT, answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert f"interrupted while starting {UNIT}; its switch stays" in result.err
    assert fakes.marker() == SWITCHED_OFF_AT


def test_start_whose_compose_up_fails_is_partial_and_keeps_the_switch(hal, fakes):
    """T4"""
    fakes.unit_in("B")
    fakes.scripted.failing_verb = "up"

    result = hal("start", UNIT, answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert f"partial, could not start {UNIT}" in result.err
    assert "its switch stays" in result.err
    assert fakes.marker() == SWITCHED_OFF_AT


def test_start_without_a_terminal_is_refused_with_3_and_touches_nothing(
    tmp_path, system_commands, empty_home
):
    """T5 (E1)"""
    result = run_door(tmp_path, system_commands, "start", UNIT)

    assert result.returncode == ExitCode.FAILURE
    assert "hal start: refused, stdin and stdout must be a terminal" in result.stderr


# --- hal offline -----------------------------------------------------------------------------


def test_offline_stops_the_tunnel_and_records_the_global_switch(hal, fakes, systemd, marks):
    """O1"""
    result = hal("offline", answers=("",))

    assert result.exit_code == ExitCode.OK
    assert "the tunnel is stopped (since " in result.text
    assert "services keep running locally" in result.text
    assert marks.global_mark() is not None
    assert not systemd.active


def test_offline_with_an_invalid_tunnel_manager_cannot_plan(
    hal, fakes, systemd, marks, monkeypatch
):
    """O2"""
    monkeypatch.setenv(tunnel.MANAGER_VARIABLE, "bogus")

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "hal offline: cannot plan, " in result.err
    assert tunnel.MANAGER_VARIABLE in result.err
    assert systemd.calls == []
    assert marks.global_mark() is None


def test_offline_interrupted_while_the_tunnel_still_runs_is_partial(hal, fakes, systemd, marks):
    """O3 (E2): the interrupt is dropped; what is observed decides."""
    systemd.while_stopping = ctrl_c

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "partial: the global switch is recorded, but the tunnel still runs" in result.err
    assert "`systemctl stop cloudflared`" in result.err
    assert "sudo" not in result.err
    assert "interrupted" not in result.err
    assert marks.global_mark() is not None


def test_offline_interrupted_after_the_tunnel_stopped_is_a_success(hal, fakes, systemd, marks):
    """O3b (E2): the tunnel did stop, the marker is recorded, the boot drop-in is there."""

    def stopped_then_interrupted() -> None:
        systemd.active = False
        raise KeyboardInterrupt

    systemd.while_stopping = stopped_then_interrupted

    result = hal("offline")

    assert result.exit_code == ExitCode.OK
    assert "the tunnel is stopped (since " in result.text
    assert marks.global_mark() is not None


def test_offline_without_terminal_never_asks_for_a_password_and_never_reads_stdin(
    hal, fakes, systemd
):
    """O5"""
    result = hal("offline")

    assert result.exit_code == ExitCode.OK
    stop_call = next(call for call in systemd.calls if "stop" in call)
    assert "--no-ask-password" in stop_call


def test_offline_whose_global_marker_cannot_be_written_still_stops_the_tunnel(
    hal, fakes, systemd, marks
):
    """O6: a record that fails never keeps the tunnel open (the stack's rule, #70 rule 2)."""
    marks.directory.mkdir(parents=True)
    (marks.directory / switches.GLOBAL_STOP_FILE).mkdir()

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "the global switch could not be recorded" in result.err
    assert not systemd.active


def test_offline_whose_tunnel_state_cannot_be_read_is_not_called_stopped(
    hal, fakes, systemd, marks
):
    """O7"""

    def unreadable() -> None:
        raise tunnel.TunnelError("cannot run systemctl (timed out)")

    systemd.verb_is_active = unreadable

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "its state could not be read" in result.err
    assert marks.global_mark() is not None


def test_offline_without_the_boot_drop_in_is_incomplete(hal, fakes, systemd, marks):
    """O8"""
    systemd.drop_ins = []

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "incomplete: a reboot would reopen the tunnel" in result.err
    assert "`hal setup`" in result.err
    assert marks.global_mark() is not None


def test_offline_whose_stop_is_refused_and_times_out_is_3_never_4(hal, fakes, systemd, marks):
    """O4: the review's case; a partial result is never called "a guard refused"."""
    systemd.refuses_stop = True
    systemd.stop_times_out_after_stopping = True

    result = hal("offline")

    assert result.exit_code == ExitCode.FAILURE
    assert "the tunnel still runs; `systemctl stop cloudflared`" in result.err
    assert "stop failed: cannot run systemctl (timed out)" in result.err
    assert marks.global_mark() is not None


# --- hal online ------------------------------------------------------------------------------


def test_online_with_the_barriers_proven_reopens_the_tunnel(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N1"""
    fakes.probe_switched_off_behind_a_barrier()

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert "the barrier of probe is proven" in result.text
    assert "the tunnel is open; unit switches and barriers stay" in result.text
    assert marks.mark("probe") is not None
    assert systemd.active
    assert marks.global_mark() is None


def test_online_with_an_unproven_barrier_keeps_the_tunnel_closed(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N2 (E1)"""
    fakes.probe_switched_off_behind_a_barrier()
    fakes.ingress.rejecting = True

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "the tunnel stays closed: the barrier of probe is not proven" in result.err
    assert marks.global_mark() is not None
    assert "start" not in systemd.verbs()


def test_online_interrupted_while_reopening_records_the_switch_again(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N3 (E2)"""
    systemd.while_starting = ctrl_c

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "partial: interrupted while reopening the tunnel" in result.err
    assert "the global switch is recorded again" in result.err
    assert marks.global_mark() is not None


def test_online_whose_tunnel_does_not_start_records_the_switch_again(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N4"""
    systemd.start_fails = True

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "partial: the tunnel did not start; the global switch is recorded again" in result.err
    assert marks.global_mark() is not None


def test_online_without_a_terminal_is_refused_with_3_and_touches_nothing(
    tmp_path, system_commands, empty_home
):
    """N5 (E1)"""
    result = run_door(tmp_path, system_commands, "online")

    assert result.returncode == ExitCode.FAILURE
    assert "hal online: refused, stdin and stdout must be a terminal" in result.stderr


def test_online_with_yes_declined_keeps_the_global_switch(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N6 (E1)"""
    result = hal("online", answers=("no",))

    assert result.exit_code == ExitCode.FAILURE
    assert "aborted" in result.err
    assert marks.global_mark() is not None
    assert not systemd.active


def test_online_whose_authorization_is_denied_records_the_switch_again(
    hal, fakes, stopped_tunnel, systemd, marks
):
    """N7"""
    systemd.authorizes = False

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert "the system did not authorize the start" in result.err
    assert marks.global_mark() is not None
    assert "start" not in systemd.verbs()


def test_an_offline_while_online_waits_for_yes_wins(hal, fakes, stopped_tunnel, systemd, marks):
    """N8"""
    result = hal("online", answers=("yes",), while_prompt_waits=lambda: cli.main(["offline"]))

    assert result.exit_code == ExitCode.FAILURE
    assert marks.global_mark() is not None
    assert "start" not in systemd.verbs()
    assert not systemd.active


def test_start_of_an_unknown_unit_keeps_its_old_cannot_plan_line(hal, fakes):
    result = hal("start", "x", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert result.err.startswith(
        f"{emergency.START}: cannot plan, x is not a unit of fleet.yaml (units: "
    )
    assert result.err.count("\n") == 1


def test_online_with_a_fleet_that_cannot_be_read_keeps_its_old_cannot_plan_line(
    hal, fakes, stopped_tunnel
):
    write_fleet(fakes.repository, "not: [valid")

    result = hal("online", answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert result.err.startswith(f"{emergency.START_ALL}: cannot plan, ")
    assert result.err.count("\n") == 1
