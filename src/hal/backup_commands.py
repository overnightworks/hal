"""`hal backup` and `hal restore`: the backup runner behind hal's door. The steps are the typed
functions of `hal.backup.cli` and `hal.backup.live`; this module adds the grammar, the one host
lock around every run, the SIGTERM that systemd stops a unit with, and the exit code. For
`restore --live` it reads what `hal.backup` may not: the unit's switch, the catalog and the
terminal, and hands plain values to the step."""

import argparse
import functools
import os
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from hal.backup import cli as steps
from hal.backup import host, live, restic
from hal.backup.apps import PRE_APPLY_TAG
from hal.backup.cli import StepExit
from hal.backup.runner import Interrupted, StepFailed
from hal.backup.settings import Settings
from hal.grammar import Asks, Command, ExitCode
from hal.output import write_error
from hal.output.command import Verb, command
from hal.stack import catalog, compose, switches, terminal, unit_plans
from hal.stack.external.apply import signals_ignored, terminate_like_interrupt

HAL_BACKUP = command(Verb.BACKUP)
HAL_RESTORE = command(Verb.RESTORE)
Ended = StepFailed | Interrupted | KeyboardInterrupt

Step = Callable[[Settings, argparse.Namespace], StepExit]
EXIT_OF_STEP: dict[StepExit, ExitCode] = {
    StepExit.OK: ExitCode.OK,
    StepExit.DECLINED: ExitCode.FINDINGS,
    StepExit.REFUSED: ExitCode.REFUSED,
    StepExit.FAILED: ExitCode.FAILURE,
}


def _configure_backup(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("app", nargs="?", help="back up this app only")
    parser.add_argument(
        "--pre-apply",
        action="store_true",
        help=f"tag the snapshot {PRE_APPLY_TAG} and keep the last {restic.KEEP_PRE_APPLY} "
        f"such snapshots of the app within {restic.PRE_APPLY_MAX_AGE.days} days (needs the "
        "app's name)",
    )
    parser.add_argument("--init", action="store_true", help="create the restic repository once")
    parser.add_argument("--unlock", action="store_true", help="remove stale restic locks")
    _add_apps(parser)


def _configure_restore(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("app", nargs="?", help="the app's name in apps.toml")
    parser.add_argument("--target", type=Path, help="a directory to create (restore needs it)")
    parser.add_argument(
        "--snapshot",
        help="this snapshot of the app (ID from `--list`) instead of the last successful "
        "backup's: the way when no status file survives (needs the app's name)",
    )
    parser.add_argument(
        "--test",
        action="store_true",
        help="restore the last successful backup's snapshot of every app (or one) and prove it "
        "is good, without keeping the data",
    )
    parser.add_argument("--list", action="store_true", help="list the repository's snapshots")
    parser.add_argument(
        "--live",
        action="store_true",
        help="load the snapshot into the app's live database while the app is switched off "
        "(hal stop <app>); asks yes at a terminal",
    )
    _add_apps(parser)


def _add_apps(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--apps",
        type=Path,
        default=steps.DEFAULT_APPS,
        help=f"the declared apps (default: {steps.DEFAULT_APPS})",
    )


def _backup_step(arguments: argparse.Namespace) -> Step | str:
    """The step the flags ask for, or the usage error they make."""
    maintenance = [flag for flag in ("init", "unlock") if getattr(arguments, flag)]
    if maintenance:
        others = arguments.app is not None or arguments.pre_apply or arguments.json
        if len(maintenance) > 1 or others:
            return "--init and --unlock stand alone, without an app, --pre-apply or --json"
        return steps.init if arguments.init else steps.unlock
    if arguments.pre_apply and arguments.app is None:
        return "--pre-apply needs the name of an app"
    if arguments.json and not arguments.pre_apply:
        return "--json needs --pre-apply"
    return steps.backup


def _restore_step(arguments: argparse.Namespace) -> Step | str:
    if arguments.list:
        given = (arguments.app, arguments.snapshot, arguments.target)
        if arguments.test or any(value is not None for value in given):
            return "--list stands alone"
        return steps.snapshots
    if arguments.test:
        if arguments.target is not None:
            return "--test restores to a throwaway, so --target does not apply"
        if arguments.snapshot is not None and arguments.app is None:
            return "--snapshot needs the name of an app"
        return steps.restore_test
    if arguments.app is None or arguments.target is None:
        return "restore needs the name of an app and --target or --live"
    return steps.restore


def _backup(arguments: argparse.Namespace) -> ExitCode:
    step = _backup_step(arguments)
    tell_ended = _tell_backup_ended if step is steps.backup else _tell_ended_plainly(HAL_BACKUP)
    return _run(HAL_BACKUP, step, arguments, tell_ended)


def _restore(arguments: argparse.Namespace) -> ExitCode:
    if arguments.live:
        return _restore_live(arguments)
    step = _restore_step(arguments)
    tell_ended = (
        _tell_restore_test_ended if step is steps.restore_test else _tell_ended_plainly(HAL_RESTORE)
    )
    return _run(HAL_RESTORE, step, arguments, tell_ended)


def _tell_restore_test_ended(ended: Ended) -> None:
    next_step = command(Verb.RESTORE, "--test")
    match ended:
        case StepFailed():
            write_error(ended.error_line or str(ended), ended.next_step or next_step)
        case Interrupted(app=str() as app):
            write_error(f"interrupted while testing the restore of {app}", next_step)
        case _:
            write_error("interrupted", next_step)


def _tell_backup_ended(ended: Ended) -> None:
    match ended:
        case StepFailed():
            write_error(ended.error_line or str(ended), ended.next_step or HAL_BACKUP)
        case Interrupted(app=str() as app):
            write_error(
                f"interrupted while backing up {app} · its state may be partial", HAL_BACKUP
            )
        case _:
            write_error("interrupted", HAL_BACKUP)


def _tell_ended_plainly(program: str) -> Callable[[Ended], None]:
    """The error line of the steps that keep their own wording: restore and the repository
    maintenance."""

    def tell(ended: Ended) -> None:
        reason = str(ended) if isinstance(ended, StepFailed) else "interrupted"
        write_error(f"{program}: failed: {reason}")

    return tell


@dataclass(frozen=True)
class _Refusal:
    exit_code: ExitCode
    line: str


def _switched_off(app: str) -> switches.Mark | _Refusal:
    """The marker of the enabled unit `app` names, read as `hal stop` finds its unit; the global
    switch is not read, so a unit on is refused whatever the tunnel."""
    try:
        fleet = unit_plans.read_fleet(compose.Compose(), compose.REPOSITORY)
        unit = next((unit for unit in fleet.units if unit.key == app), None)
        if unit is None:
            known = ", ".join(sorted(unit.key for unit in fleet.units))
            return _Refusal(ExitCode.REFUSED, f"{app} is not a unit of fleet.yaml (units: {known})")
        if not unit.enabled:
            return _Refusal(ExitCode.REFUSED, f"{app} is disabled in the catalog")
        mark = switches.Switches(switches.default_state_directory()).mark(app)
    except (compose.ComposeError, catalog.CatalogError, switches.SwitchError) as error:
        return _Refusal(ExitCode.FAILURE, str(error))
    if mark is None:
        return _Refusal(ExitCode.REFUSED, f"stop it first: {command(Verb.STOP, app)}")
    return mark


def _live_usage(arguments: argparse.Namespace) -> str | None:
    if arguments.app is None:
        return "--live needs the name of an app"
    if arguments.target is not None or arguments.test or arguments.list:
        return "--live loads into the app's database, so --target, --test and --list do not apply"
    return None


def _restore_live(arguments: argparse.Namespace) -> ExitCode:
    if usage := _live_usage(arguments):
        return _run(HAL_RESTORE, usage, arguments, _tell_live_ended(""))
    app = arguments.app
    mark = _switched_off(app)
    if isinstance(mark, _Refusal):
        write_error(mark.line)
        return mark.exit_code
    marks = switches.Switches(switches.default_state_directory())

    def switch_unchanged() -> bool:
        try:
            return marks.changed(app, mark) is None
        except switches.SwitchError:
            return False

    guards = live.Guards(signals_ignored, switch_unchanged, terminal.at_terminal())
    step = functools.partial(live.restore_live, guards=guards)
    return _run(HAL_RESTORE, step, arguments, _tell_live_ended(app))


def _tell_live_ended(app: str) -> Callable[[Ended], None]:
    """A failure before the spawn names the app once; only an interrupt the step raised before
    it spawned the client says that nothing was loaded."""

    def tell(ended: Ended) -> None:
        match ended:
            case StepFailed():
                reason = str(ended)
                write_error(reason if app in reason else f"{app}: {reason}")
            case Interrupted():
                write_error("interrupted · nothing loaded")
            case _:
                write_error("interrupted")

    return tell


def _run(
    program: str,
    step: Step | str,
    arguments: argparse.Namespace,
    tell_ended: Callable[[Ended], None],
) -> ExitCode:
    if isinstance(step, str):
        write_error(step, f"{program} --help")
        return ExitCode.USAGE
    settings = Settings.for_home(Path.home(), os.getuid(), os.getgid())
    decided: ExitCode | None = None
    with terminate_like_interrupt():
        try:
            # Every run holds the one host lock, so no two runs share the repository.
            with host.exclusive_lock(settings.lock_file):
                decided = EXIT_OF_STEP[step(settings, arguments)]
        except StepFailed as failure:
            tell_ended(failure)
            return ExitCode.FAILURE
        except (Interrupted, KeyboardInterrupt) as interrupt:
            # Once the step returned, its outcome line stands: an interrupt at the lock's
            # release changes neither that line nor its exit.
            if decided is not None:
                return decided
            tell_ended(interrupt)
            return ExitCode.INTERRUPTED
    return decided


COMMANDS = (
    Command(
        Verb.BACKUP,
        "dump, scan and back up every app (or one), then forget, prune and check",
        _backup,
        _configure_backup,
        json=True,
        asks=Asks.NEVER,
    ),
    Command(
        Verb.RESTORE,
        "restore one app's backup, load it into its live database with --live, prove the "
        "backups with --test, or list them with --list",
        _restore,
        _configure_restore,
        json=False,
        asks=Asks.YES,
    ),
)
