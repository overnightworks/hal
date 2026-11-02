"""What `hal rename` prints: a row for each step of the plan and of the run, a row for each
finding, and the verdict or error that ends the run. The words are English; paths show `~` for
the home directory."""

import re
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path
from typing import Protocol

from hal.output import (
    Glyph,
    Noun,
    Row,
    Stream,
    Verdict,
    counted,
    format_duration,
    printable,
    write_error,
    write_line,
    write_row,
    write_verdict,
)
from hal.output.command import Verb, command


class Event(StrEnum):
    """The event column: what a step will do, what it did, and what a finding is."""

    MOVE = "move"
    MOVED = "moved"
    REPAIR = "repair"
    REPAIRED = "repaired"
    SET_URL = "set url"
    URL_SET = "url set"
    UV_SYNC = "uv sync"
    UV_SYNCED = "synced"
    CHECK = "check"


class StepKind(Enum):
    """A step's row subject, its event while planned and its event once done."""

    MOVE_CLONE = ("clone", Event.MOVE, Event.MOVED)
    MOVE_WORKTREES = ("worktrees", Event.MOVE, Event.MOVED)
    REPAIR_WORKTREES = ("worktrees", Event.REPAIR, Event.REPAIRED)
    SET_URL = ("origin", Event.SET_URL, Event.URL_SET)
    MOVE_MEMORY = ("memory", Event.MOVE, Event.MOVED)
    SYNC = ("venv", Event.UV_SYNC, Event.UV_SYNCED)


@dataclass(frozen=True)
class StepRow:
    """The row of one step."""

    kind: StepKind
    fact: str
    done_fact: str | None = None  # what the done row says when it differs from the planned fact

    @classmethod
    def of_move(cls, kind: StepKind, source: Path, target: Path) -> StepRow:
        if kind is StepKind.MOVE_MEMORY:
            return cls(kind, "Claude project memory of the clone")
        return cls(kind, f"{source} → {target}", str(target))

    @classmethod
    def of_repair(cls, worktrees: Path, count: int) -> StepRow:
        return cls(StepKind.REPAIR_WORKTREES, f"{count} in {worktrees}")

    @classmethod
    def of_origin(cls, url: str, deploy_checkout: Path | None) -> StepRow:
        fact = f"{url} · deploy checkout {deploy_checkout}" if deploy_checkout else url
        return cls(StepKind.SET_URL, fact)


@dataclass(frozen=True)
class Finding:
    """Something hal reports and never rewrites; `subject` names the thing it found."""

    subject: str
    sentence: str


class HasRow(Protocol):
    row: StepRow


class HasDescription(Protocol):
    description: str


class Label(Noun):
    CHANGE = "change"
    FINDING = "finding"


class Outcome(StrEnum):
    CHANGED = "changed"


def _home_as_tilde(text: str, home: Path) -> str:
    return re.sub(rf"(?<![\w/]){re.escape(str(home))}(?![\w.-])", "~", text)


def write_done_row(row: StepRow, home: Path, elapsed_seconds: float | None = None) -> None:
    """The done row of a step; the caller passes its duration when the row should show one."""
    subject, _, done = row.kind.value
    fact = _home_as_tilde(row.fact if row.done_fact is None else row.done_fact, home)
    if elapsed_seconds is not None:
        fact = f"{fact} · {format_duration(elapsed_seconds)}"
    write_row(Row(Glyph.DONE, subject, done, fact))


def write_findings(findings: Sequence[Finding], home: Path) -> None:
    for finding in findings:
        sentence = _home_as_tilde(finding.sentence, home)
        write_row(Row(Glyph.NEEDS_YOU, finding.subject, Event.CHECK, sentence))


def write_plan(steps: Sequence[HasRow], findings: Sequence[Finding], home: Path) -> None:
    """A planned row for each step, then the findings."""
    for row in (step.row for step in steps):
        subject, planned, _ = row.kind.value
        write_row(Row(Glyph.CHANGE, subject, planned, _home_as_tilde(row.fact, home)))
    write_findings(findings, home)


def apply_purpose(steps: int) -> str:
    """What the person agrees to by typing yes."""
    return f"apply {counted(steps, Label.CHANGE)}"


def write_plan_only(old: str, new: str) -> None:
    hint = f"run {command(Verb.RENAME, old, new)}"
    write_verdict(Verdict(Glyph.UNCHANGED, "plan only, nothing changed", (), hint=hint))


def write_nothing_to_do(old: str) -> None:
    write_verdict(Verdict(Glyph.UNCHANGED, f"nothing to do, no clone of {old} to move", ()))


def write_done(steps: int, findings: int, elapsed_seconds: float) -> None:
    glyph = Glyph.NEEDS_YOU if findings else Glyph.DONE
    counts = ((steps, Outcome.CHANGED), (findings, Label.FINDING))
    write_verdict(Verdict(glyph, "rename done", counts, elapsed_seconds=elapsed_seconds))


def write_declined() -> None:
    write_error("aborted, nothing changed")


def write_without_terminal(old: str, new: str) -> None:
    write_error(
        "rename asks yes at a terminal · nothing changed",
        f"{command(Verb.RENAME, old, new)} in your own terminal window",
    )


def write_halfway(
    old: str,
    new: str,
    failed: HasDescription,
    reason: str,
    done: Sequence[HasDescription],
    pending: Sequence[HasDescription],
) -> None:
    """The run stopped at `failed`; the way on is the same command, and the way back its reverse."""
    write_error(
        f"stopped halfway at `{failed.description}`: {reason}; "
        f"fix the cause and run `{command(Verb.RENAME, old, new)}` again to finish"
    )
    for label, steps in (("done", done), ("not done", pending)):
        for step in steps:
            write_line(printable(f"{label}: {step.description}"), stream=Stream.STDERR)
    write_line(f"next: {command(Verb.RENAME, new, old)}", stream=Stream.STDERR)


def write_refusals(reasons: Sequence[str]) -> None:
    for reason in reasons:
        write_error(f"cannot rename, {reason} · nothing changed")
