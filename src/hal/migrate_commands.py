"""`hal migrate`: the transitional steps between two layouts of the workstation. `stack`: the stack
leaves the Compose project it ran under and starts under the one `compose.yaml` names. `state`:
hal's state leaves the directories of its old names for the ones its owners name now. Shape of
`hal rename`: the plan, one `yes`, `--dry-run` only shows."""

import argparse
import os
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from hal.backup.settings import Settings
from hal.grammar import Asks, Command, ExitCode, add_dry_run
from hal.output import (
    Glyph,
    Row,
    Verdict,
    confirmed,
    write_error,
    write_row,
    write_verdict,
)
from hal.output.command import Verb, command
from hal.stack import compose, project_move, switches
from hal.stack.apply import APPLY_LOCK
from hal.stack.compose import ComposeError, Runner
from hal.stack.project_move import Plan, Stage
from hal.stack.terminal import at_terminal
from hal.workstation import state_move
from hal.workstation.state_move import Action, SourcePlan

STACK = "stack"
STATE = "state"


class Event(StrEnum):
    REMOVE = "remove"
    REMOVED = "removed"
    KEEP = "keep"
    TAKE_OVER = "take over"
    START = "start"
    STARTED = "started"
    MOVE = "move"
    MOVED = "moved"
    CLOSE = "close"


@dataclass(frozen=True)
class World:
    """The boundaries to the outside: Docker and the terminal."""

    docker: Runner
    is_interactive: Callable[[], bool]


def real_world() -> World:
    return World(compose.run_docker, at_terminal)


def _write_plan(plan: Plan) -> None:
    named, unnamed = "named by compose.yaml", "not named by compose.yaml"
    taken_over = f"{named}: down removes one no app uses, project {plan.target} creates it again"
    rows = (
        (Glyph.REMOVE, "containers", Event.REMOVE, f"project {plan.source}", plan.containers),
        (Glyph.CHANGE, "networks", Event.TAKE_OVER, taken_over, plan.taken_over_networks),
        (Glyph.REMOVE, "networks", Event.REMOVE, unnamed, plan.removed_networks),
        (Glyph.UNCHANGED, "volumes", Event.KEEP, named, plan.kept_volumes),
        (Glyph.REMOVE, "volumes", Event.REMOVE, unnamed, plan.removed_volumes),
        (Glyph.ADD, "core", Event.START, f"project {plan.target}", plan.core),
    )
    for glyph, subject, event, fact, names in rows:
        if names:
            write_row(Row(glyph, subject, event, fact, details=names))


def _write_done(stage: Stage, names: tuple[str, ...], plan: Plan) -> None:
    removed_by_down = "containers" if plan.containers else "networks"
    subject, event, fact = {
        Stage.DOWN: (removed_by_down, Event.REMOVED, f"project {plan.source}"),
        Stage.VOLUME: ("volumes", Event.REMOVED, ", ".join(names)),
        Stage.START: ("core", Event.STARTED, f"project {plan.target}"),
    }[stage]
    details = names if stage is Stage.DOWN else ()
    write_row(Row(Glyph.DONE, subject, event, fact, details=details))


def _perform(plan: Plan, world: World) -> ExitCode:
    try:
        for stage, names in project_move.move(plan, world.docker):
            _write_done(stage, names, plan)
    except ComposeError as error:
        write_error(f"migrate stack stopped, {error} · rerun finishes what is left", _again(STACK))
        return ExitCode.FAILURE
    write_verdict(
        Verdict(
            Glyph.DONE, f"stack moved from {plan.source} to {plan.target}", (),
            next_step=command(Verb.APPLY),
        )
    )  # fmt: skip
    return ExitCode.OK


def _again(subject: str) -> str:
    return command(Verb.MIGRATE, subject)


def migrate_stack(world: World, dry_run: bool) -> ExitCode:
    try:
        plan = project_move.make_plan(world.docker)
    except project_move.Refusal as refusal:
        write_error(f"cannot migrate stack, {refusal} · nothing changed")
        return ExitCode.REFUSED
    except ComposeError as error:
        write_error(f"cannot migrate stack, {error} · nothing changed")
        return ExitCode.FAILURE
    if not plan.has_work:
        write_verdict(Verdict(Glyph.UNCHANGED, f"nothing to move, no stack of {plan.source}", ()))
        return ExitCode.OK
    _write_plan(plan)
    if dry_run:
        hint = f"run {_again(STACK)}"
        write_verdict(Verdict(Glyph.UNCHANGED, "plan only, nothing changed", (), hint=hint))
        return ExitCode.OK
    if not world.is_interactive():
        write_error("migrate stack asks yes at a terminal · nothing changed", _again(STACK))
        return ExitCode.REFUSED
    if not confirmed(f"move the stack from {plan.source} to {plan.target}"):
        write_error("aborted, nothing changed")
        return ExitCode.FINDINGS
    return _perform(plan, world)


def _state_targets() -> state_move.Targets:
    settings = Settings.for_home(Path.home(), os.getuid(), os.getgid())
    return state_move.Targets(
        state=switches.default_state_directory(),
        cache=settings.work_dir,
        lock_names=frozenset({APPLY_LOCK, switches.LOCK_FILE, settings.lock_file.name}),
    )


def _shown(home: Path, path: Path) -> str:
    return f"~/{path.relative_to(home).as_posix()}"


def _write_state_plan(home: Path, plans: tuple[SourcePlan, ...]) -> None:
    for plan in plans:
        source, target = _shown(home, plan.source), _shown(home, plan.target)
        rows = (
            (Glyph.CHANGE, Event.MOVE, f"into {target}", plan.names(Action.MOVE)),
            (Glyph.REMOVE, Event.REMOVE, f"{target} keeps its copy", plan.names(Action.REMOVE)),
            (
                Glyph.REMOVE,
                Event.CLOSE,
                "lock files, unlinked while held",
                plan.names(Action.CLOSE),
            ),
        )
        for glyph, event, fact, names in rows:
            if names or (event is Event.MOVE and not plan.entries):
                write_row(Row(glyph, source, event, fact, details=names))


def _move_state(home: Path, targets: state_move.Targets, plans: tuple[SourcePlan, ...]) -> ExitCode:
    try:
        with state_move.held_locks(home, targets):
            for plan in plans:
                state_move.move(plan)
                fact = f"into {_shown(home, plan.target)}"
                write_row(Row(Glyph.DONE, _shown(home, plan.source), Event.MOVED, fact))
    except state_move.Refusal as refusal:
        write_error(f"cannot migrate state, {refusal} · nothing moved", _again(STATE))
        return ExitCode.REFUSED
    except (state_move.Stopped, OSError) as error:
        why = error.strerror if isinstance(error, OSError) else error
        write_error(f"migrate state stopped, {why} · rerun finishes what is left", _again(STATE))
        return ExitCode.FAILURE
    summary = "hal's state is in its new directories"
    write_verdict(Verdict(Glyph.DONE, summary, (), next_step=command(Verb.SETUP)))
    return ExitCode.OK


def migrate_state(world: World, dry_run: bool) -> ExitCode:
    home, targets = Path.home(), _state_targets()
    try:
        plans = state_move.make_plan(home, targets)
    except state_move.Refusal as refusal:
        write_error(f"cannot migrate state, {refusal} · nothing changed")
        return ExitCode.REFUSED
    except OSError as error:
        write_error(f"cannot migrate state ({error.strerror}) · nothing changed", _again(STATE))
        return ExitCode.FAILURE
    if not plans:
        write_verdict(Verdict(Glyph.UNCHANGED, "nothing to move, no state under the old names", ()))
        return ExitCode.OK
    _write_state_plan(home, plans)
    if dry_run:
        hint = f"run {_again(STATE)}"
        write_verdict(Verdict(Glyph.UNCHANGED, "plan only, nothing changed", (), hint=hint))
        return ExitCode.OK
    if not world.is_interactive():
        write_error("migrate state asks yes at a terminal · nothing changed", _again(STATE))
        return ExitCode.REFUSED
    if not confirmed("move hal's state into its new directories"):
        write_error("aborted, nothing changed")
        return ExitCode.FINDINGS
    return _move_state(home, targets, plans)


def _configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("subject", choices=[STACK, STATE], help="what to move")
    add_dry_run(parser)


def _run(arguments: argparse.Namespace) -> ExitCode:
    if arguments.subject == STATE:
        return migrate_state(real_world(), arguments.dry_run)
    return migrate_stack(real_world(), arguments.dry_run)


COMMANDS = (
    Command(
        Verb.MIGRATE,
        "move the stack between its Compose projects, or hal's state out of its old directories"
        " (shows the plan, asks yes, moves; --dry-run only shows)",
        _run,
        _configure,
        json=False,
        asks=Asks.YES,
    ),
)
