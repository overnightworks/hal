"""`hal apply`, `hal update`, `hal stop`, `hal start`, `hal offline` and `hal online`: the stack's
switches behind hal's door. Each calls a typed function of `hal.stack.cli`, so the guards, the
prompts, the state files and the lines are the stack's own; only the exit number is hal's."""

import argparse

from hal.grammar import Asks, Command, ExitCode
from hal.output.command import Verb, command
from hal.stack import apply
from hal.stack import cli as stack
from hal.stack.update import UpdateEnd

# Every outcome of the stack means "the command could not do its job"; the finer split waits until
# the owners classify their own outcomes. Naming every member keeps a new one from passing as 0.
EXIT_OF_STACK: dict[apply.ApplyExit, ExitCode] = {
    apply.ApplyExit.APPLIED_OR_NOTHING: ExitCode.OK,
    apply.ApplyExit.CANNOT_PLAN: ExitCode.FAILURE,
    apply.ApplyExit.REFUSED: ExitCode.FAILURE,
}


EXIT_OF_UPDATE: dict[UpdateEnd, ExitCode] = {
    UpdateEnd.DONE: ExitCode.OK,
    UpdateEnd.DECLINED: ExitCode.FINDINGS,
    UpdateEnd.REFUSED: ExitCode.REFUSED,
    UpdateEnd.FAILED: ExitCode.FAILURE,
    UpdateEnd.INTERRUPTED: ExitCode.INTERRUPTED,
}


def _exit_of(stack_exit: int) -> ExitCode:
    return EXIT_OF_STACK[apply.ApplyExit(stack_exit)]


def _configure_apply(parser: argparse.ArgumentParser) -> None:
    parser.description = (
        "The local part (`--local`: the units of this repository and the apps of the catalog, at a "
        "terminal, after `yes`), then, only if it ended clean, the publish to Cloudflare (after "
        "its own `yes`). Each part asks only when it has changes."
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="the local part alone: units of this repository and the apps of the catalog "
        "(checked out, built and run at their newest release), at a terminal, after `yes`",
    )


def _configure_update(parser: argparse.ArgumentParser) -> None:
    parser.description = (
        "Brings the live checkout to origin's main: shows the waiting commits and the changed "
        "files by what they change, asks you to type yes on the exact fetched commit, "
        "fast-forwards the checkout and syncs its locked dependencies. It changes no unit; "
        f"{command(Verb.APPLY)} does, with the new code."
    )


def _configure_unit(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("unit", help="a unit or an app of fleet.yaml")


def _configure_nothing(_parser: argparse.ArgumentParser) -> None:
    """`offline` and `online` take no argument."""


def _apply(arguments: argparse.Namespace) -> ExitCode:
    return _exit_of(stack.apply_units(arguments.local))


def _update(_arguments: argparse.Namespace) -> ExitCode:
    return EXIT_OF_UPDATE[stack.update_checkout()]


def _stop(arguments: argparse.Namespace) -> ExitCode:
    return _exit_of(stack.stop_unit(arguments.unit))


def _start(arguments: argparse.Namespace) -> ExitCode:
    return _exit_of(stack.start_unit(arguments.unit))


def _offline(_arguments: argparse.Namespace) -> ExitCode:
    return _exit_of(stack.stop_all())


def _online(_arguments: argparse.Namespace) -> ExitCode:
    return _exit_of(stack.start_all())


COMMANDS = (
    Command(
        Verb.APPLY,
        "switch the units of fleet.yaml on or off, then publish to Cloudflare",
        _apply,
        _configure_apply,
        json=False,
        asks=Asks.YES,
    ),
    Command(
        Verb.UPDATE,
        "bring the live checkout to origin's main and sync its dependencies (terminal, `yes`)",
        _update,
        _configure_update,
        json=False,
        asks=Asks.YES,
    ),
    Command(
        Verb.STOP,
        "switch a unit or an app off at once and keep it off (no terminal needed)",
        _stop,
        _configure_unit,
        json=False,
        asks=Asks.NEVER,
    ),
    Command(
        Verb.START,
        "end the switch of a unit or an app (terminal, `yes`)",
        _start,
        _configure_unit,
        json=False,
        asks=Asks.YES,
    ),
    Command(
        Verb.OFFLINE,
        "stop the tunnel, so the PC is off the internet (no terminal needed)",
        _offline,
        _configure_nothing,
        json=False,
        asks=Asks.NEVER,
    ),
    Command(
        Verb.ONLINE,
        "reopen the tunnel once every unit and app barrier is proven (terminal, `yes`)",
        _online,
        _configure_nothing,
        json=False,
        asks=Asks.YES,
    ),
)
