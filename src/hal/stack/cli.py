"""The stack's switches as typed functions: apply, stop and start of a unit, stop and start of the
tunnel. `hal` is their one door."""

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from hal.output import Stream, write_line
from hal.output.command import Verb, command
from hal.stack import apply, emergency, switches, tunnel, update
from hal.stack.external import cli as external_cli

COMMAND = command(Verb.APPLY)


def tunnel_of_environment(command: str) -> tunnel.Tunnel | None:
    """The tunnel the environment names; None, after saying why, when it names an invalid one."""
    try:
        return tunnel.Tunnel.from_environment(os.environ)
    except tunnel.TunnelError as error:
        write_line(f"{command}: cannot plan, {error}", stream=Stream.STDERR)
        return None


def stop_all() -> int:
    door = tunnel_of_environment(emergency.STOP_ALL)
    if door is None:
        return apply.ApplyExit.CANNOT_PLAN
    return emergency.stop_all(
        switches.Switches(switches.default_state_directory()),
        datetime.now().astimezone(),
        door,
    )


def start_all() -> int:
    door = tunnel_of_environment(emergency.START_ALL)
    if door is None:
        return apply.ApplyExit.CANNOT_PLAN
    return emergency.start_all(
        switches.Switches(switches.default_state_directory()),
        datetime.now().astimezone(),
        door,
    )


def stop_unit(unit: str) -> int:
    return emergency.stop_unit(
        switches.Switches(switches.default_state_directory()),
        unit,
        datetime.now().astimezone(),
    )


def start_unit(unit: str) -> int:
    return emergency.start_unit(switches.Switches(switches.default_state_directory()), unit)


@dataclass
class _Run:
    """What the interrupt handler of the composer knows, recorded where each fact is true."""

    publish_started: bool = False
    publish_exit: int | None = None


def update_checkout() -> update.UpdateEnd:
    return update.update_checkout(switches.default_state_directory())


def apply_units(local: bool) -> int:
    if local:
        return apply.apply_local(switches.default_state_directory())
    return _apply_then_publish()


def _apply_then_publish() -> int:
    """The local part, then the publish only if the local part ended clean. The exit is the local
    one unless it is 0, then the publish's with its 2 ("cannot plan") made 1: a 2 from here means
    the local part could not finish planning, and nothing was published. No signal handler is
    installed here; the one `except KeyboardInterrupt` (SIGINT) decides by what is recorded.

    Accepted windows, not covered: a SIGINT between the publish's return and the store of its
    exit (exit 1 and the check line although the publish finished); a SIGTERM after the publish
    left its own context (default action: the process ends by the signal); a second Ctrl-C while
    `_exit_after_interrupt` prints (ends with a traceback)."""
    run = _Run()
    try:
        local_exit = apply.apply_local(switches.default_state_directory())
        if local_exit != apply.ApplyExit.APPLIED_OR_NOTHING:
            write_line(f"{COMMAND}: nothing published", stream=Stream.STDERR)
            return local_exit
        run.publish_started = True
        run.publish_exit = _published_exit(external_cli.apply_command(Path.home()))
        _say_summary(run.publish_exit)
        return run.publish_exit
    except KeyboardInterrupt:
        return _exit_after_interrupt(run)


def _published_exit(publish_exit: int) -> int:
    if publish_exit == apply.ApplyExit.CANNOT_PLAN:
        return apply.ApplyExit.REFUSED
    return publish_exit


def _say_summary(publish_exit: int) -> None:
    if publish_exit == apply.ApplyExit.APPLIED_OR_NOTHING:
        write_line(f"{COMMAND}: done", stream=Stream.STDERR)
    else:
        write_line(
            f"{COMMAND}: the publish did not end clean (exit {publish_exit})", stream=Stream.STDERR
        )


def _exit_after_interrupt(run: _Run) -> int:
    if run.publish_exit is not None:
        return run.publish_exit
    if run.publish_started:
        write_line(
            f"{COMMAND}: interrupted during the publish; run `{command(Verb.CHECK, 'hosts')}`",
            stream=Stream.STDERR,
        )
    else:
        write_line(f"{COMMAND}: interrupted, nothing published", stream=Stream.STDERR)
    return apply.ApplyExit.REFUSED
