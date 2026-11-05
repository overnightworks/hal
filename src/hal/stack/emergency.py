"""`hal stop <unit>` and `hal start <unit>`: the emergency switch of one unit; with `--all`, of
the tunnel (`stop_all`, `start_all`).

Stop records the switch, then stops the unit's services; it needs no terminal, so an agent may
run it (R4, D12). Start is the operator's step: a terminal and the exact `yes`. Exit codes are
`ApplyExit`'s. Containers and volumes are never removed here.

An app of the catalog is switched the same way under its key: the marker first, then the barrier
over its catalog hosts, then the file-free `stop` of its Compose project; its start is the
file-free `start` of the stopped containers, the health wait, then the barrier removed and the
marker cleared. A start that would create Keycloak or LiteLLM over its data only ends the switch.
"""

import os
from collections.abc import Callable, Iterable
from contextlib import ExitStack
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path

from hal.output import Stream, confirmed, write_line
from hal.output.command import Verb, command
from hal.stack import (
    app_compose,
    apps,
    barrier,
    catalog,
    compose,
    setup,
    switch_events,
    switches,
    terminal,
    tunnel,
    unit_plans,
)
from hal.stack.apply import DATABASE_UNITS, ApplyExit
from hal.stack.switch_events import BarrierPart, CannotPlan, Closing, Interruption, StopPart

STOP = command(Verb.STOP)
START = command(Verb.START)
ABORTED_UNCHANGED = "aborted, nothing changed"


def _say(command: str, line: str) -> None:
    write_line(f"{command}: {line}")


def _complain(command: str, line: str) -> None:
    write_line(f"{command}: {line}", stream=Stream.STDERR)


def _read_fleet(engine: compose.Compose, repository: Path) -> unit_plans.Fleet | CannotPlan:
    try:
        return unit_plans.read_fleet(engine, repository)
    except (compose.ComposeError, catalog.CatalogError) as error:
        return CannotPlan(str(error))


def _apps_of(fleet: unit_plans.Fleet, repository: Path) -> tuple[catalog.App, ...]:
    """The apps of the catalog; CatalogError when an entry of them is invalid."""
    document = catalog.read(repository / catalog.FLEET_FILE)
    return catalog.apps(document, fleet.profile_services, fleet.config["name"])


def _read_subject(
    engine: compose.Compose, repository: Path, key: str
) -> tuple[unit_plans.Fleet, catalog.Unit | catalog.App] | CannotPlan:
    fleet = _read_fleet(engine, repository)
    if isinstance(fleet, CannotPlan):
        return fleet
    unit = next((unit for unit in fleet.units if unit.key == key), None)
    if unit:
        return fleet, unit  # an invalid app entry never stands between an operator and a unit
    try:
        every = _apps_of(fleet, repository)
    except catalog.CatalogError as error:
        return CannotPlan(str(error))
    app = next((app for app in every if app.key == key), None)
    if app is None:
        known = ", ".join(sorted(unit.key for unit in fleet.units))
        named_apps = ", ".join(sorted(app.key for app in every))
        return CannotPlan(f"{key} is not a unit of fleet.yaml (units: {known}; apps: {named_apps})")
    return fleet, app


@dataclass(frozen=True)
class Target:
    """What a stop switches off: a unit of the compose project, or an app, which is one of its
    own."""

    key: str
    enabled: bool
    ingress: barrier.Barrier
    running: Callable[[], bool]
    stop: Callable[[], None]


def _project_of(app: catalog.App, runtime: apps.AppRuntime) -> app_compose.AppCompose:
    return app_compose.AppCompose(app.key, runtime.srv / app.key, runtime.docker)


def _target_of(
    subject: catalog.Unit | catalog.App,
    fleet: unit_plans.Fleet,
    engine: compose.Compose,
    repository: Path,
    verifier: barrier.Verifier,
    runtime: apps.AppRuntime,
) -> Target:
    if isinstance(subject, catalog.App):
        project = _project_of(subject, runtime)
        return Target(
            subject.key,
            subject.enabled,
            barrier.Barrier.of_app(fleet.config, repository, subject, verifier),
            lambda: any(compose.is_live(one.state) for one in project.containers()),
            project.stop,
        )
    key, services = subject.key, fleet.profile_services[subject.key]
    return Target(
        key,
        subject.enabled,
        barrier.Barrier.of_unit(fleet.config, services, repository, subject, verifier),
        lambda: compose.has_running_container(engine.states(), services),
        lambda: engine.stop(key, services),
    )


def stop_unit(
    marks: switches.Switches,
    key: str,
    now: datetime,
    engine: compose.Compose | None = None,
    repository: Path = compose.REPOSITORY,
    verifier: barrier.Verifier = barrier.PROVEN_OVER_HTTP,
    runtime: apps.AppRuntime | None = None,
) -> int:
    engine = engine or compose.Compose(repository=repository)
    runtime = runtime or apps.AppRuntime.of(Path.home(), marks.directory)
    attempted = False
    recorded = False
    try:
        attempted = _is_enabled_app(key, repository)
        recorded = attempted and _recorded_first(marks, key, now)
        planned = _planned(engine, repository, key, verifier, runtime)
    except KeyboardInterrupt:
        return _report_early_interrupt(marks, key, Interruption.PLANNING, attempted)
    if isinstance(planned, CannotPlan):
        switch_events.report_cannot_plan(key, planned, recorded)
        return ApplyExit.CANNOT_PLAN
    target, running = planned
    if not running and not target.enabled:
        switch_events.report_disabled(key)
        return ApplyExit.APPLIED_OR_NOTHING
    try:
        off = None if running else _confirmed_off(marks, target, now)
    except KeyboardInterrupt:
        return _report_close(
            key,
            Closing(record_failure=_recorded(marks, key, now), interruption=Interruption.WAITING),
        )
    if off:
        since, repaired = off
        switch_events.report_already_off(key, since, repaired)
        return ApplyExit.APPLIED_OR_NOTHING
    return _close(marks, target, now)


def _planned(
    engine: compose.Compose,
    repository: Path,
    key: str,
    verifier: barrier.Verifier,
    runtime: apps.AppRuntime,
) -> tuple[Target, bool] | CannotPlan:
    """The target of the stop and whether it runs, or why it cannot be planned."""
    try:
        read = _read_subject(engine, repository, key)
        if isinstance(read, CannotPlan):
            return read
        fleet, subject = read
        target = _target_of(subject, fleet, engine, repository, verifier, runtime)
        return target, target.running()
    except (compose.ComposeError, barrier.BarrierError) as error:
        return CannotPlan(str(error))


def _is_enabled_app(key: str, repository: Path) -> bool:
    """Whether the catalog names an enabled app under the key: the apps whose marker is recorded
    before anything is planned, so apply stops fetching and building it within the first moment of
    the stop (`compose config` and `ps` take seconds)."""
    try:
        return catalog.is_enabled_app(catalog.read(repository / catalog.FLEET_FILE), key)
    except catalog.CatalogError, OSError:
        return False


def _recorded_first(marks: switches.Switches, key: str, now: datetime) -> bool:
    """Whether the record succeeded. A failure here is not reported: the close records again and
    reports a record that failed."""
    try:
        marks.record(key, now)
    except OSError, switches.SwitchError:
        return False
    return True


def _report_early_interrupt(
    marks: switches.Switches, key: str, step: Interruption, attempted: bool
) -> int:
    """A Ctrl-C before the lock. The marker is read only when this run attempted a record, so a
    marker of an earlier stop is never reported as this run's and no path is built from a key the
    catalog did not resolve."""
    if not attempted:
        switch_events.report_interrupted_early(key, step)
        return ApplyExit.REFUSED
    try:
        mark = marks.mark(key)
    except switches.SwitchError as error:
        switch_events.report_interrupted_early(key, step, str(error))
        return ApplyExit.REFUSED
    if mark is None:
        switch_events.report_interrupted_early(key, step)
        return ApplyExit.REFUSED
    return _report_close(key, Closing(interruption=step))


def _confirmed_off(
    marks: switches.Switches, target: Target, now: datetime
) -> tuple[str, bool] | None:
    """(switch time, barrier repaired) of a unit or app that is off, decided under the lock so no
    start is between its look at the marker and its `up`, or an app's `start`.

    The marker is rewritten unchanged, so a start waiting at its prompt sees that a stop came in,
    and the barrier is rendered again from it and proven, in case the file was lost.

    An unmarked one is handed back to the stop unlocked, so the stop records before it waits.

    None when it is not switched off, or when anything stops us from being sure: then the
    stop closes it, and reports the record itself.
    """
    key = target.key
    try:
        if marks.since(key) is None:
            return None  # nothing is recorded yet: the stop records first, then waits for the lock
        with marks.lock():
            if target.running():
                return None
            if marks.since(key) is None:
                return None
            marks.record(key, now)
            repaired = target.ingress.close()
            since = marks.since(key)
            return (since, repaired) if since else None
    except compose.ComposeError, switches.SwitchError, barrier.BarrierError:
        return None


def _recorded(marks: switches.Switches, key: str, now: datetime) -> str | None:
    try:
        marks.record(key, now)
    except switches.SwitchError as error:
        return str(error)
    return None


def _close_ingress(ingress: barrier.Barrier, closing: Closing) -> Closing:
    try:
        ingress.close()
    except barrier.BarrierError as error:
        return closing.with_barrier(BarrierPart.NOT_PROVEN, str(error))
    except KeyboardInterrupt:
        return closing.interrupted(Interruption.RAISING_THE_BARRIER)
    return closing.with_barrier(BarrierPart.UP if ingress.names else BarrierPart.NO_HOST)


def _stop_target(target: Target, closing: Closing) -> Closing:
    try:
        target.stop()
        if target.running():
            return closing.with_stop(StopPart.NOT_STOPPED, "a container of it still runs")
    except compose.ComposeError as error:
        return closing.with_stop(StopPart.NOT_STOPPED, f"could not stop it, {error}")
    except KeyboardInterrupt:
        return closing.interrupted(Interruption.STOPPING)
    return closing.with_stop(StopPart.STOPPED)


def _close(marks: switches.Switches, target: Target, now: datetime) -> int:
    key = target.key
    try:
        closing = Closing(record_failure=_recorded(marks, key, now))
    except KeyboardInterrupt:
        return _report_early_interrupt(marks, key, Interruption.RECORDING, attempted=True)
    with ExitStack() as held:
        try:
            held.enter_context(marks.lock())
            # a start that cleared the marker meanwhile must not undo this
            closing = replace(closing, record_failure=_recorded(marks, key, now))
        except switches.SwitchError as error:
            closing = replace(closing, lock_failure=str(error))
        except KeyboardInterrupt:
            closing = replace(closing, interruption=Interruption.LOCKING)
        if closing.interruption is None:
            closing = _close_ingress(target.ingress, closing)
        if closing.interruption is None:
            closing = _stop_target(target, closing)
    return _report_close(key, closing)


def _report_close(key: str, closing: Closing) -> int:
    switch_events.report_closing(key, closing)
    return ApplyExit.APPLIED_OR_NOTHING if closing.complete else ApplyExit.REFUSED


def start_unit(
    marks: switches.Switches,
    key: str,
    engine: compose.Compose | None = None,
    repository: Path = compose.REPOSITORY,
    verifier: barrier.Verifier = barrier.PROVEN_OVER_HTTP,
    check: setup.SetupCheck = setup.run_setup_check,
    watch: compose.Watch = compose.SETTLED,
    runtime: apps.AppRuntime | None = None,
) -> int:
    if terminal.refused_without_terminal(START):
        return ApplyExit.REFUSED
    engine = engine or compose.Compose(repository=repository)
    runtime = runtime or apps.AppRuntime.of(Path.home(), marks.directory)
    try:
        planned = _read_subject(engine, repository, key)
        if isinstance(planned, CannotPlan):
            _complain(START, f"cannot plan, {planned.cause}")
            return ApplyExit.CANNOT_PLAN
        fleet, subject = planned
        target = _target_of(subject, fleet, engine, repository, verifier, runtime)
        read = marks.mark(key)
    except (compose.ComposeError, switches.SwitchError, barrier.BarrierError) as error:
        _complain(START, f"cannot plan, {error}")
        return ApplyExit.CANNOT_PLAN
    if not target.enabled:
        _complain(
            START,
            f"refused, {key} is disabled in the catalog; enable it by PR and "
            f"`{command(Verb.APPLY)}`",
        )
        return ApplyExit.REFUSED
    if not barrier.switched_off(read, target.ingress):
        _say(START, f"no change, {key} is not switched off")
        return ApplyExit.APPLIED_OR_NOTHING
    if isinstance(subject, catalog.App):
        return _start_app(marks, target, _project_of(subject, runtime), runtime, read)
    try:
        not_set_up = setup.refusal(subject, repository, check, f"{START} {key}")
    except setup.SetupUnclear as error:
        _complain(START, f"cannot start, {error}")
        return ApplyExit.CANNOT_PLAN
    if not_set_up:
        _complain(START, f"refused, {not_set_up}")
        return ApplyExit.REFUSED
    try:
        services, starts = _what_starts(engine, fleet, key)
    except compose.ComposeError as error:
        _complain(START, f"cannot plan, {error}")
        return ApplyExit.CANNOT_PLAN
    _say(START, f"{key}: start {starts}; {_ending(read)}")
    if not confirmed(f"start {key}"):
        _complain(START, ABORTED_UNCHANGED)
        return ApplyExit.REFUSED
    return _open(engine, marks, target.ingress, key, services, read, fleet.config, watch)


def _what_starts(
    engine: compose.Compose, fleet: unit_plans.Fleet, key: str
) -> tuple[tuple[str, ...], str]:
    """The services the start starts and its words for them; none over a database unit's data."""
    services = fleet.profile_services[key]
    over = unit_plans.snapshot_before_start(fleet, key, engine.states(), engine, DATABASE_UNITS)
    if over:
        return (), f"nothing over {over.name}'s data"
    return services, f"services {', '.join(services)}"


def _ending(read: switches.Mark | None) -> str:
    if read:
        return f"end the switch since {switches.describe_since(read.since)}"
    return "remove the barrier a stop left behind"


class _SwitchedOffAgain(Exception):
    """The app's marker is no longer the one `start` read: a stop came in meanwhile."""


def _start_app(
    marks: switches.Switches,
    target: Target,
    project: app_compose.AppCompose,
    runtime: apps.AppRuntime,
    read: switches.Mark | None,
) -> int:
    """The app's stopped containers started under the lock and waited for outside it, then, under
    it again and only if no stop came in meanwhile, the barrier removed and proven open and the
    marker cleared; a stop that came in wins and stops the containers again, under the lock."""
    key = target.key
    _say(START, f"{key}: start its containers; {_ending(read)}")
    if not confirmed(f"start {key}"):
        _complain(START, ABORTED_UNCHANGED)
        return ApplyExit.REFUSED

    def still_off() -> None:
        if marks.changed(key, read):
            raise _SwitchedOffAgain

    try:
        existed, unhealthy = _started_app(marks, project, runtime, still_off)
        with marks.lock():
            if changed := marks.changed(key, read):
                return _stopped_again(target, changed.current)
            return _end_app_switch(marks, target, read, existed, unhealthy)
    except (compose.ComposeError, switches.SwitchError) as error:
        _complain(START, f"partial, could not start {key}, {error}; its switch stays")
        return ApplyExit.REFUSED
    except KeyboardInterrupt:
        _complain(START, f"interrupted while starting {key}; its switch stays")
        return ApplyExit.REFUSED


def _started_app(
    marks: switches.Switches,
    project: app_compose.AppCompose,
    runtime: apps.AppRuntime,
    still_off: Callable[[], None],
) -> tuple[bool, str | None]:
    """(whether containers of the app exist, what is not settled by the deadline) after the start
    of what is stopped, under the lock so a stop waits for it, and the wait outside it. A stop that
    came in ends both early; the caller's locked look finds it."""
    try:
        with marks.lock():
            still_off()  # a stop that came in during the prompt starts nothing
            containers = project.containers()
            if not containers:
                return False, None
            project.start_stopped()
        unhealthy = apps.unhealthy_after_waiting(
            project, tuple(one.service for one in containers), runtime.health, still_off
        )
    except _SwitchedOffAgain:
        return False, None
    return True, unhealthy


def _end_app_switch(
    marks: switches.Switches,
    target: Target,
    read: switches.Mark | None,
    existed: bool,
    unhealthy: str | None,
) -> int:
    """Under the lock, with the marker as `start` read it."""
    key = target.key
    if unhealthy:
        _complain(
            START, f"partial, {key} is not healthy after the start ({unhealthy}); its switch stays"
        )
        return ApplyExit.REFUSED
    try:
        target.ingress.open()
    except barrier.BarrierError as error:
        _complain(START, f"partial, {key} is on but {error}; its switch stays")
        return ApplyExit.REFUSED
    if read and not marks.clear(key, read):
        _complain(START, _switched_off_again_line(key, marks.mark(key)))
        return ApplyExit.REFUSED
    if existed:
        _say(START, f"{key} is on")
    else:
        _say(START, f"{key}: no container of it exists; `{command(Verb.APPLY)}` starts it")
    return ApplyExit.APPLIED_OR_NOTHING


def _stopped_again(target: Target, current: switches.Mark | None) -> int:
    """A stop came in while `start` waited: it wins, and, under the lock, what `start` started is
    stopped again."""
    if current is not None:
        try:
            target.stop()
        except compose.ComposeError as error:
            _complain(
                START,
                f"partial: {target.key} was switched off again, but could not stop it, {error}",
            )
            return ApplyExit.REFUSED
    return _refused_before_up(target.key, current)


def _switched_off_again_line(key: str, current: switches.Mark | None) -> str:
    """The switch is not the one start read, after the start ran."""
    if current is None:
        return f"partial: {key} was started, but its switch had already been ended meanwhile"
    return (
        f"partial: {key} was switched off again (since {switches.describe_since(current.since)}); "
        "it stays switched off"
    )


def _refused_before_up(key: str, current: switches.Mark | None) -> int:
    """Rule 5: the switch is not the one start read; a stop wins, another start made it moot."""
    if current is None:
        _say(START, f"{key} was started meanwhile")
        return ApplyExit.APPLIED_OR_NOTHING
    _complain(
        START,
        f"partial: {key} was switched off meanwhile "
        f"(since {switches.describe_since(current.since)}); not started",
    )
    return ApplyExit.REFUSED


def _open(
    engine: compose.Compose,
    marks: switches.Switches,
    ingress: barrier.Barrier,
    key: str,
    services: tuple[str, ...],
    read: switches.Mark | None,
    config: dict,
    watch: compose.Watch,
) -> int:
    """Start `services`, then end the switch; with no service only the switch ends."""
    try:
        with marks.lock():
            if changed := marks.changed(key, read):
                return _refused_before_up(key, changed.current)
            if services:
                engine.start(key, services)
                if engine.down_while_watched(config, services, watch):
                    _complain(START, f"partial, {key} is not on after the start; its switch stays")
                    return ApplyExit.REFUSED
            try:
                ingress.open()
            except barrier.BarrierError as error:
                _complain(START, f"partial, {key} is on but {error}; its switch stays")
                return ApplyExit.REFUSED
            if read and not marks.clear(key, read):
                _complain(START, _switched_off_again_line(key, marks.mark(key)))
                return ApplyExit.REFUSED
    except (compose.ComposeError, switches.SwitchError) as error:
        _complain(START, f"partial, could not start {key}, {error}; its switch stays")
        return ApplyExit.REFUSED
    except KeyboardInterrupt:
        _complain(START, f"interrupted while starting {key}; its switch stays")
        return ApplyExit.REFUSED
    ended = f"{key}'s switch is ended; `{command(Verb.APPLY)}` starts it after a snapshot"
    _say(START, f"{key} is on" if services else ended)
    return ApplyExit.APPLIED_OR_NOTHING


STOP_ALL = command(Verb.OFFLINE)
START_ALL = command(Verb.ONLINE)


def _record_global(
    marks: switches.Switches, now: datetime, *, under_lock: bool
) -> switches.SwitchError | None:
    """Write the global switch; unlocked it never waits for a start that holds `switch.lock`."""
    try:
        with ExitStack() as held:
            if under_lock:
                held.enter_context(marks.lock())
            marks.record_global(now)
    except switches.SwitchError as error:
        return error
    except KeyboardInterrupt:
        return switches.SwitchError("interrupted while waiting for the lock")
    return None


def _global_time(marks: switches.Switches) -> str:
    try:
        mark = marks.global_mark()
    except switches.SwitchError:
        mark = None
    return switches.describe_since(mark.since if mark else switches.UNKNOWN_SWITCH_TIME)


def _named_unit(door: tunnel.Tunnel) -> str:
    """Empty for cloudflared; a probe's throwaway unit is named so the operator can tell."""
    return "" if door.unit == tunnel.CLOUDFLARED_UNIT else f"; unit {door.unit}"


def _ask_to_stop(door: tunnel.Tunnel) -> str | None:
    """Ask the system to stop the tunnel; what happened is read from the observation after it.

    Returns edge's own reason when the stop could not be asked, so the report can keep it.
    """
    # a refused or interrupted stop is judged by the state observed next, never assumed
    try:
        door.stop(may_ask_password=terminal.at_terminal())
    except tunnel.TunnelError as error:
        return str(error)
    except KeyboardInterrupt:
        pass
    return None


def _observed(door: tunnel.Tunnel) -> tuple[bool, bool, str | None]:
    """(stopped, boot protected, why it could not be observed) of the tunnel as it is now."""
    try:
        stopped = door.is_inactive()
        return stopped, door.has_boot_drop_in(), None
    except tunnel.TunnelError as error:
        return False, False, f"its state could not be read, {error}"


def _global_recorded(marks: switches.Switches) -> bool:
    try:
        return marks.global_mark() is not None
    except switches.SwitchError:
        return False


def _tunnel_state(stopped: bool, observation_failure: str | None) -> str:
    """The tunnel as observed; a state nobody could read is never called stopped or running."""
    if observation_failure:
        return f"is not confirmed stopped ({observation_failure})"
    return "is stopped" if stopped else "still runs"


def stop_all(marks: switches.Switches, now: datetime, door: tunnel.Tunnel) -> int:
    """Record the global switch first, stop the tunnel, record again under the lock, then report
    only what is observed.

    The first record is unlocked, so a start holding `switch.lock` through `up` cannot delay the
    stop; the second is under the lock, so a start that cleared the switch meanwhile cannot undo
    it. The units keep running on loopback and their switches are not touched.
    """
    _record_global(marks, now, under_lock=False)
    stop_failure = _ask_to_stop(door)
    lock_failure = _record_global(marks, now, under_lock=True)
    record_failure = lock_failure if not _global_recorded(marks) else None
    stopped, boot_protected, observation_failure = _observed(door)
    unit = door.unit.removesuffix(".service")
    tunnel_state = _tunnel_state(stopped, observation_failure)
    if record_failure:
        report = (
            f"the global switch could not be recorded ({record_failure}); "
            f"the tunnel {tunnel_state}, and a reboot reopens it"
        )
    else:
        report = f"the global switch is recorded, but the tunnel {tunnel_state}"
    if record_failure or not stopped:
        hint = "" if stopped else f"; `systemctl stop {unit}`"
        _complain(STOP_ALL, f"partial: {report}{hint}")
        if stop_failure and not stopped:
            _complain(STOP_ALL, f"stop failed: {stop_failure}")
        return ApplyExit.REFUSED
    if not boot_protected:
        _complain(
            STOP_ALL,
            "incomplete: a reboot would reopen the tunnel (the boot drop-in is not installed "
            f"yet; `{command(Verb.SETUP)}` installs it)",
        )
        return ApplyExit.REFUSED
    _say(
        STOP_ALL,
        f"the tunnel is stopped (since {_global_time(marks)}{_named_unit(door)}); "
        "services keep running locally",
    )
    return ApplyExit.APPLIED_OR_NOTHING


def _said_until_unproven(proofs: Iterable[barrier.ActiveProof]) -> str | None:
    """Say each proven barrier, one line each.

    The failure line (the tunnel stays closed) of the first barrier that cannot be proven.
    """
    for proof in proofs:
        match proof:
            case barrier.Proven(unit):
                _say(START_ALL, f"the barrier of {unit} is proven")
            case barrier.NoHost(unit):
                _say(START_ALL, f"{unit}: no host behind Traefik, so no barrier")
            case barrier.Unproven(unit, failure):
                return f"the tunnel stays closed: the barrier of {unit} is not proven ({failure})"
    return None


def _tunnel_closed_clause(door: tunnel.Tunnel) -> str:
    """Stop the tunnel if it runs, then say what was observed; never claim a closed state unseen."""
    try:
        if not door.is_inactive():
            door.stop(may_ask_password=terminal.at_terminal())
        if door.is_inactive():
            return "the tunnel is closed"
    except tunnel.TunnelError, KeyboardInterrupt:
        pass  # the reply below says it was not observed
    return f"the tunnel is not confirmed closed; check `systemctl is-active {door.unit}`"


def _partial_closed(
    reason: str, recording_failure: switches.SwitchError | None, door: tunnel.Tunnel
) -> int:
    recorded = (
        f"the global switch could not be recorded again ({recording_failure})"
        if recording_failure
        else "the global switch is recorded again"
    )
    _complain(START_ALL, f"partial: {reason}; {recorded}; {_tunnel_closed_clause(door)}")
    return ApplyExit.REFUSED


def _stopped_during_prompt(current: switches.Mark | None) -> int:
    """A stop that came in while the operator was asked wins; another start made this one moot."""
    if current is None:
        _say(START_ALL, "the tunnel was started meanwhile")
        return ApplyExit.APPLIED_OR_NOTHING
    _complain(
        START_ALL,
        f"partial: the tunnel was switched off again meanwhile "
        f"(since {switches.describe_since(current.since)}); not started",
    )
    return ApplyExit.REFUSED


def start_all(
    marks: switches.Switches,
    now: datetime,
    door: tunnel.Tunnel,
    engine: compose.Compose | None = None,
    repository: Path = compose.REPOSITORY,
    verifier: barrier.Verifier = barrier.PROVEN_OVER_HTTP,
) -> int:
    """Lift only the global switch, and only when every barrier stands and the system allows it.

    Order: prove the barriers, ask the operator, get the system's authorization, then (under the
    lock, a stop during the prompt wins) clear the switch, start the tunnel and observe it.
    """
    if terminal.refused_without_terminal(START_ALL):
        return ApplyExit.REFUSED
    engine = engine or compose.Compose(repository=repository)
    fleet = _read_fleet(engine, repository)
    if isinstance(fleet, CannotPlan):
        _complain(START_ALL, f"cannot plan, {fleet.cause}")
        return ApplyExit.CANNOT_PLAN
    try:
        read = marks.global_mark()
        if read is None and door.is_active():
            _say(START_ALL, "no change, the tunnel is not switched off")
            return ApplyExit.APPLIED_OR_NOTHING
        unproven = _said_until_unproven(
            barrier.prove_active(
                fleet.units,
                fleet.profile_services,
                fleet.config,
                marks,
                repository,
                verifier,
                _apps_of(fleet, repository),
            )
        )
    except (switches.SwitchError, tunnel.TunnelError, catalog.CatalogError) as error:
        _complain(START_ALL, f"cannot plan, {error}")
        return ApplyExit.CANNOT_PLAN
    if unproven:
        _complain(START_ALL, unproven)
        return ApplyExit.REFUSED
    _say(START_ALL, "host check not built yet (#50 SW3)")
    if not confirmed("reopen the tunnel"):
        _complain(START_ALL, ABORTED_UNCHANGED)
        return ApplyExit.REFUSED
    return _reopen(marks, now, door, read)


def _reopen(
    marks: switches.Switches, now: datetime, door: tunnel.Tunnel, read: switches.Mark | None
) -> int:
    try:
        if not door.authorized_to_start(os.getpid()):
            return _partial_closed(
                "the system did not authorize the start",
                _record_global(marks, now, under_lock=True),
                door,
            )
        with marks.lock():
            if changed := marks.global_changed(read):
                return _stopped_during_prompt(changed.current)
            if read:
                marks.clear_global(read)
            started = door.start() and door.is_active()
            failure = None if started else "the tunnel did not start"
    except (switches.SwitchError, tunnel.TunnelError) as error:
        failure = f"could not reopen the tunnel, {error}"
    except KeyboardInterrupt:
        failure = "interrupted while reopening the tunnel"
    if failure:
        # the lock is released here, so recording again may take it
        return _partial_closed(failure, _record_global(marks, now, under_lock=True), door)
    _say(START_ALL, f"the tunnel is open{_named_unit(door)}; unit switches and barriers stay")
    return ApplyExit.APPLIED_OR_NOTHING
