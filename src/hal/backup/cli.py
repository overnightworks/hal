"""The steps behind `hal backup` and `hal restore`: each returns its `StepExit`, and raises
`StepFailed` when it could not do its job. `hal.backup_commands` owns the lock, the signal and
the exit code each `StepExit` maps to."""

import argparse
import json
from collections.abc import Callable
from enum import Enum
from pathlib import Path

from hal.backup import host, restic, runner
from hal.backup.apps import App, AppsError, parse_apps
from hal.backup.runner import Interrupted, Run, StepFailed
from hal.backup.settings import Settings
from hal.backup.status import ExitCategory, first_attempt
from hal.output import (
    Glyph,
    Noun,
    Verdict,
    counted,
    format_moment,
    write_line,
    write_row,
    write_verdict,
)
from hal.output.command import Verb, command

# uv installs the project editable, so this file sits in the checkout: src/hal/backup/cli.py.
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_APPS = _PROJECT_ROOT / "backup" / "apps.toml"


class StepExit(Enum):
    """How a step ended, one member per exit it can return."""

    OK = "ok"
    DECLINED = "declined"  # the person answered anything but yes
    REFUSED = "refused"  # a guard of the step said no; nothing changed
    FAILED = "failed"  # the step ran and could not do its job


def init(settings: Settings, _: argparse.Namespace) -> StepExit:
    runner.require_password_file(settings)
    settings.repository.mkdir(mode=0o700, parents=True, exist_ok=True)
    checked(restic.init, settings)
    write_line(f"{command(Verb.BACKUP)}: repository created")
    return StepExit.OK


def backup(settings: Settings, arguments: argparse.Namespace) -> StepExit:
    """With `--json` only the snapshot is printed; otherwise a row per app, one for the
    repository and the verdict."""
    _require_declared(arguments)
    started = host.monotonic()
    rows = not arguments.json

    def step(settings: Settings, apps: tuple[App, ...], run: Run) -> None:
        try:
            runner.backup(
                settings,
                apps,
                run,
                only=arguments.app,
                pre_apply=arguments.pre_apply,
                report=write_row if rows else lambda _: None,
            )
        except StepFailed as failure:
            if failure.app is not None:
                _name_failed_apps(failure, run, rows=rows)
            raise

    def announce(run: Run) -> None:
        if arguments.json:
            write_line(json.dumps({"snapshot": run.snapshot_of(arguments.app)}))
        else:
            noun = AppCount.APP
            write_verdict(
                Verdict(
                    Glyph.DONE,
                    "backup done",
                    ((run.backed_up_apps, noun),),
                    elapsed_seconds=host.monotonic() - started,
                )
            )

    _recorded(settings, arguments, step, announce)
    return StepExit.OK


class AppCount(Noun):
    APP = "app"


def _app_failure_line(run: Run, failure: StepFailed) -> str:
    """`<app>: <reason>` of the first app that failed, also after a failed repository check."""
    first = run.first_app_failure or failure
    return f"{first.app}: {first}"


def _failed_apps_line(failed: list[str], total: int, outcome: str) -> str:
    """The one app that ran by name, else how many of the apps that ran."""
    if total == 1:
        return f"{failed[0]} {outcome}"
    return f"{len(failed)} of {counted(total, AppCount.APP)} {outcome}"


def _last_good_backup_fact(run: Run, app: str, total: int) -> str:
    """The app's last good backup from the status record, in local time; the app leads the fact
    only when several apps ran, since the line names it otherwise."""
    moment = run.last_backup_of(app)
    if moment is None:
        return "no good backup recorded" if total == 1 else f"{app} has no good backup recorded"
    shown = format_moment(moment, host.now())
    return f"last good backup {shown}" if total == 1 else f"{app}'s last good backup {shown}"


def _name_failed_apps(failure: StepFailed, run: Run, *, rows: bool) -> None:
    """The rows show each reason, so the error line counts and names the first failed app's last
    good backup; `--json` has no rows, so its error line carries the reason, which the realm step
    reads."""
    failed = run.failed_apps
    total = run.backed_up_apps + len(failed)
    if rows:
        counted_line = _failed_apps_line(failed, total, "not backed up")
        failure.error_line = f"{counted_line} · {_last_good_backup_fact(run, failed[0], total)}"
    else:
        failure.error_line = _app_failure_line(run, failure)
    failure.next_step = command(Verb.BACKUP, failed[0])


def restore_test(settings: Settings, arguments: argparse.Namespace) -> StepExit:
    """A row per app, one for the repository and the verdict. With `--snapshot` (one app) the
    error line carries the reason, which the realm step reads."""
    _require_declared(arguments)
    started = host.monotonic()

    def step(settings: Settings, apps: tuple[App, ...], run: Run) -> None:
        try:
            runner.restore_test(
                settings,
                apps,
                run,
                only=arguments.app,
                snapshot_prefix=arguments.snapshot,
                report=write_row,
            )
        except StepFailed as failure:
            if run.failed_apps:
                failed = run.failed_apps
                total = run.proven_apps + len(failed)
                if arguments.snapshot:
                    failure.error_line = _app_failure_line(run, failure)
                else:
                    failure.error_line = _failed_apps_line(failed, total, "not proven")
                failure.next_step = command(Verb.RESTORE, "--test", failed[0])
            raise

    def announce(run: Run) -> None:
        noun = AppCount.APP
        write_verdict(
            Verdict(
                Glyph.DONE,
                "restore test done",
                ((run.proven_apps, noun),),
                elapsed_seconds=host.monotonic() - started,
            )
        )

    _recorded(settings, arguments, step, announce)
    return StepExit.OK


def snapshots(settings: Settings, _: argparse.Namespace) -> StepExit:
    runner.require_secret_and_repository(settings)
    listing = checked(restic.snapshots, settings)
    write_line(listing, end="")
    return StepExit.OK


def unlock(settings: Settings, _: argparse.Namespace) -> StepExit:
    runner.require_secret_and_repository(settings)
    checked(restic.unlock, settings)
    return StepExit.OK


def restore(settings: Settings, arguments: argparse.Namespace) -> StepExit:
    apps = apps_of(arguments.apps)
    app = runner.declared_app(apps, arguments.app)
    snapshot_id = checked(runner.restore, settings, apps, app, arguments.target, arguments.snapshot)
    short = snapshot_id[: runner.MIN_SNAPSHOT_PREFIX]
    write_line(
        f"{command(Verb.RESTORE)}: snapshot {short} of {app.name} restored into {arguments.target}"
    )
    return StepExit.OK


def _recorded(
    settings: Settings,
    arguments: argparse.Namespace,
    step: Callable[[Settings, tuple[App, ...], Run], None],
    announce: Callable[[Run], None] = lambda _: None,
) -> None:
    """Every outcome lands in the status file; only a run that went through is `ok`."""
    started = host.now()
    try:
        previous = runner.previous_status(settings)
    except StepFailed:
        runner.sweep_leftover_staging(settings.work_dir)
        raise
    run = Run(
        settings.status_file,
        first_attempt(started) if previous is None else previous.attempt(started),
    )
    try:
        # Even a run that fails at once sweeps first, so a killed run's plaintext never waits.
        runner.sweep_leftover_staging(settings.work_dir)
        step(settings, apps_of(arguments.apps), run)
    except StepFailed as failure:
        run.failed(failure.category, failure.app, failure.phase)
        raise
    except KeyboardInterrupt as interrupt:
        run.failed(ExitCategory.INTERRUPTED)
        raise Interrupted(run.interrupted_app) from interrupt
    except BaseException:
        run.failed(ExitCategory.INTERNAL)
        raise
    run.succeeded()
    announce(run)


def _require_declared(arguments: argparse.Namespace) -> None:
    """A mistyped app is refused before any status is written: nothing ran."""
    if arguments.app is not None:
        runner.declared_app(apps_of(arguments.apps), arguments.app)


def apps_of(path: Path) -> tuple[App, ...]:
    try:
        return parse_apps(path.read_text(encoding="utf-8"))
    except OSError as error:
        raise StepFailed(
            ExitCategory.CONFIGURATION, f"apps.toml is not readable: {error.strerror}"
        ) from error
    except AppsError as error:
        raise StepFailed(ExitCategory.CONFIGURATION, str(error)) from error


def checked[**P, T](operation: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """The operation, a host failure turned into a failed step."""
    try:
        return operation(*args, **kwargs)
    except host.HostError as error:
        raise StepFailed(ExitCategory.COMMAND_FAILED, str(error)) from error
