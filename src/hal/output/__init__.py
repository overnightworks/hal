"""The one owner of how this repository's tools print to a terminal: text from outside made safe
to show, and the form of a row, a verdict, an error, the indented detail lines under a row, an
aligned table and the `yes` that confirms an action, whether the run is `-v`, and under
`LOG_FORMAT=json` the same row, verdict and error as one journal event per line.
`hal.output.command` owns the program name, `hal.output.hidden_paste` a secret pasted unseen.
It imports nothing else of this repository."""

# ruff: noqa: T201 - this is the one output owner of the hal program

import json
import os
import sys
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum, StrEnum
from typing import TextIO

from hal.output.command import PROGRAM

CONFIRMATION = "yes"
DETAIL_INDENT = "    "
SUBJECT_WIDTH = 14
EVENT_WIDTH = 14
HEADING_THRESHOLD = 6
"""From this many rows a view groups."""

_RESET = "\x1b[0m"
_DIM = "2"
_BOLD_RED = "1;31"
_CYAN = "36"
_BOLD = "1"
"""The 16 base ANSI colours, so a terminal's own theme decides the shades."""


_verbose = False


@contextmanager
def verbose_run(enabled: bool) -> Iterator[None]:
    """`-v` for the length of one run, handed once by the door like `NO_COLOR`; a producer below it
    reads `is_verbose` without a parameter through every call. A plain module value, not a
    `ContextVar`: a reader thread does not inherit that."""
    global _verbose
    previous = _verbose
    _verbose = enabled
    try:
        yield
    finally:
        _verbose = previous


def is_verbose() -> bool:
    return _verbose


_logger = PROGRAM


@contextmanager
def logger_run(name: str) -> Iterator[None]:
    """The logger a JSON event names for the length of one run, handed once by the door like
    `verbose_run`."""
    global _logger
    previous = _logger
    _logger = name
    try:
        yield
    finally:
        _logger = previous


class LogFormat(StrEnum):
    TEXT = "text"
    JSON = "json"


LOG_FORMAT_VARIABLE = "LOG_FORMAT"


def log_format_refusal() -> str | None:
    """What is wrong with `LOG_FORMAT`, or None. The writers read the variable on every write and
    treat every value but `json` as text, so the door refuses a bad value before anything runs."""
    value = os.environ.get(LOG_FORMAT_VARIABLE)
    if value is None or value in LogFormat:
        return None
    return f"{LOG_FORMAT_VARIABLE} must be {LogFormat.JSON} or {LogFormat.TEXT}, not {value}"


def _json_on() -> bool:
    return os.environ.get(LOG_FORMAT_VARIABLE) == LogFormat.JSON


class Level(Enum):
    """A journal event's level with its syslog priority."""

    ERROR = ("error", 3)
    WARNING = ("warning", 4)
    INFO = ("info", 6)

    @classmethod
    def of(cls, glyph: "Glyph") -> "Level":
        return _LEVELS.get(glyph, cls.INFO)


def _write_event(level: Level, stream: TextIO, event: str, fields: dict[str, object]) -> None:
    """One flushed line: the priority `journald` strips, then a compact JSON object that leads
    with the common fields. A field with no value is left out; text from outside is escaped by
    the caller."""
    name, priority = level.value
    common = {
        "timestamp": datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "level": name,
        "logger": _logger,
        "service": PROGRAM,
        "event": event,
    }
    present = {key: value for key, value in fields.items() if value not in ("", [], None)}
    body = json.dumps({**common, **present}, ensure_ascii=False, separators=(",", ":"))
    print(f"<{priority}>{body}", file=stream, flush=True)


def _colour_on(stream: TextIO) -> bool:
    """Colour only for a person: the stream is a terminal, `NO_COLOR` is empty or unset, and the
    terminal is not `dumb`."""
    try:
        is_terminal = stream.isatty()
    except (AttributeError, ValueError):  # no stdout when daemonised, or a closed stream
        return False
    return is_terminal and not os.environ.get("NO_COLOR") and os.environ.get("TERM") != "dumb"


def _styled(text: str, style: str, stream: TextIO) -> str:
    return f"\x1b[{style}m{text}{_RESET}" if _colour_on(stream) else text


class Glyph(Enum):
    DONE = "✓"
    FAILED = "✗"
    NEEDS_YOU = "!"
    UNCHANGED = "·"
    CHANGE = "~"
    ADD = "+"
    REMOVE = "-"
    ANNOUNCE = "\u203a"

    @property
    def verdict_style(self) -> str:
        return _VERDICT_STYLES[self]


_LEVELS = {Glyph.FAILED: Level.ERROR, Glyph.NEEDS_YOU: Level.WARNING}

_ROW_STYLES = {
    Glyph.DONE: "32",
    Glyph.FAILED: "31",
    Glyph.NEEDS_YOU: "33",
    Glyph.CHANGE: "34",
    Glyph.ADD: "32",
    Glyph.REMOVE: "31",
    Glyph.ANNOUNCE: "36",
}
_VERDICT_STYLES = {
    Glyph.DONE: "1",
    Glyph.FAILED: _BOLD_RED,
    Glyph.NEEDS_YOU: "1;33",
    Glyph.UNCHANGED: _DIM,
    Glyph.CHANGE: "1;34",
}


class Tone(Enum):
    """How a detail line looks on a terminal: unstyled, dim, or in the needs-you row's yellow."""

    PLAIN = None
    DIM = _DIM
    WARNING = _ROW_STYLES[Glyph.NEEDS_YOU]


class Noun(StrEnum):
    """An event or label that names something to count: its value is the singular phrase, and a
    count other than one shows it with an `s` after its first word (`action`, `area checked`)."""


class TrailingNoun(StrEnum):
    """Like `Noun`, with the `s` after the last word (`new page`, `new pages`)."""


class Field(StrEnum):
    """A measured or named value of a row; the value is its key in the JSON event."""

    SNAPSHOT = "snapshot"
    BYTES = "bytes"
    SECONDS = "seconds"
    REASON = "reason"


@dataclass(frozen=True)
class Row:
    """One thing a command did or found. The caller owns its event enum; `fact` is one sentence;
    `count` is shown before the event, which takes the plural when it is a `Noun` or a
    `TrailingNoun`. `details` are dim lines under the row. `fields` hold raw values, shown after
    the fact in text (`BYTES` and `SECONDS` as units) and as keys of the JSON event."""

    glyph: Glyph
    subject: str
    event: StrEnum
    fact: str = ""
    count: int | None = None
    details: tuple[str, ...] = ()
    fields: tuple[tuple[Field, str | int | float], ...] = ()


@dataclass(frozen=True)
class Group:
    """The rows of one kind of thing in a plan, in the order the work runs; `heading` names the
    group, None for rows that never stand under one."""

    heading: StrEnum | None
    rows: tuple[Row, ...]


@dataclass(frozen=True)
class Verdict:
    """The last line of a run: the caller computes the glyph, the summary and the count of each
    of its labels, in the order to show them; the renderer leaves out a zero count. `hint` is the
    command to run next; `elapsed_seconds` is the run time, shown after the counts. Without a
    summary the counts are the headline. `details` are plain phrases after the counts and
    `next_step` is a `next:` line under the verdict."""

    glyph: Glyph
    summary: str
    counts: tuple[tuple[int, StrEnum], ...]
    hint: str = ""
    elapsed_seconds: float | None = None
    details: tuple[str, ...] = ()
    next_step: str = ""


SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = 3600


def format_duration(seconds: float) -> str:
    """Whole seconds rounded down: `<1s`, `47s`, `1m05s`, `1h02m`."""
    whole = int(seconds)
    if whole < 1:
        return "<1s"
    if whole < SECONDS_PER_MINUTE:
        return f"{whole}s"
    if whole < SECONDS_PER_HOUR:
        return f"{whole // SECONDS_PER_MINUTE}m{whole % SECONDS_PER_MINUTE:02d}s"
    minutes = whole % SECONDS_PER_HOUR // SECONDS_PER_MINUTE
    return f"{whole // SECONDS_PER_HOUR}h{minutes:02d}m"


def format_moment(moment: datetime, now: datetime) -> str:
    """The moment on this machine's wall clock: `18.10. 05:00`, with the year when it is not
    the current one: `18.10.2026 05:00`."""
    local = moment.astimezone()
    if local.year == now.astimezone().year:
        return f"{local:%d.%m. %H:%M}"
    return f"{local:%d.%m.%Y %H:%M}"


BYTE_UNITS = ("B", "KiB", "MiB", "GiB", "TiB")
BYTES_PER_UNIT = 1024
DECIMALS_BELOW = 10


def format_bytes(size: int) -> str:
    """Binary units, nearest rounding, the unit chosen after rounding: `999 B`, `1.0 KiB`,
    `4.2 MiB`, `60 MiB`; one decimal below 10 of a unit, none from 10."""
    value, unit = float(size), 0
    while value >= BYTES_PER_UNIT - 0.5 and unit < len(BYTE_UNITS) - 1:
        value /= BYTES_PER_UNIT
        unit += 1
    if unit == 0:
        return f"{size} B"
    if round(value, 1) < DECIMALS_BELOW:
        return f"{value:.1f} {BYTE_UNITS[unit]}"
    return f"{round(value)} {BYTE_UNITS[unit]}"


def printable(text: str) -> str:
    """`text` with every character a terminal would act on escaped (a newline as `\\n`, ESC as
    `\\x1b`), so text from outside, a path or a command's line, stays one line of plain text."""
    return "".join(
        character if character.isprintable() else character.encode("unicode_escape").decode()
        for character in text
    )


VOWELS = "aeiou"


def _plural(word: str) -> str:
    """`app` becomes `apps`, `entry` becomes `entries`, `day` becomes `days`."""
    if word.endswith("y") and word[-2:-1] not in VOWELS:
        return f"{word[:-1]}ies"
    return f"{word}s"


def _label(count: int, noun: StrEnum) -> str:
    text = printable(str(noun))
    if count != 1:
        if isinstance(noun, Noun):
            first, separator, rest = text.partition(" ")
            text = f"{_plural(first)}{separator}{rest}"
        elif isinstance(noun, TrailingNoun):
            text = _plural(text)
    return text


def counted(count: int, noun: StrEnum) -> str:
    """`1 app`, `3 apps`: the count before the label, which takes the plural when it is a `Noun`
    (after its first word) or a `TrailingNoun` (after its last)."""
    return f"{count} {_label(count, noun)}"


_FACT_SEPARATOR = " · "


def _field_text(field: Field, value: str | int | float) -> str:
    if field is Field.BYTES:
        return format_bytes(int(value))
    if field is Field.SECONDS:
        return format_duration(float(value))
    return str(value)


def _fact_text(row: Row) -> str:
    parts = [row.fact] if row.fact else []
    parts += [_field_text(field, value) for field, value in row.fields]
    return printable(_FACT_SEPARATOR.join(parts)).rstrip()


def _field_value(value: str | int | float) -> str | int | float:
    if isinstance(value, str):
        return printable(value).rstrip()
    return round(value, 1)


def write_row(row: Row) -> None:
    """The row on stdout; text from outside is escaped before it is padded, so columns hold.
    On a terminal only the glyph is coloured and the fact dim; a `·` row is dim as a whole."""
    stdout = sys.stdout
    if _json_on():
        _write_event(
            Level.of(row.glyph),
            stdout,
            printable(str(row.event)),
            {
                "subject": printable(row.subject),
                "count": row.count,
                "fact": printable(row.fact).rstrip(),
                **{field.value: _field_value(value) for field, value in row.fields},
                "details": [printable(detail) for detail in row.details],
            },
        )
        return
    subject = printable(row.subject)
    event = printable(str(row.event)) if row.count is None else counted(row.count, row.event)
    fact = _fact_text(row)
    columns = f"{subject:<{SUBJECT_WIDTH}}  {event:<{EVENT_WIDTH}}"
    if row.glyph is Glyph.UNCHANGED:
        line = f"  {row.glyph.value} {columns} {fact}".rstrip()
        print(_styled(line, _DIM, stdout))
    else:
        glyph = _styled(row.glyph.value, _ROW_STYLES[row.glyph], stdout)
        line = f"  {glyph} {columns}"
        print(f"{line} {_styled(fact, _DIM, stdout)}" if fact else line.rstrip())
    write_detail(*row.details, tone=Tone.DIM)


def write_groups(groups: Sequence[Group]) -> None:
    """The groups' rows on stdout in the order given, the rows without a heading first and an
    empty group not at all. Once `HEADING_THRESHOLD` rows are printed, each named group stands
    under its lowercase heading, unindented and bold on a terminal."""
    shown = [group for group in groups if group.rows]
    shown.sort(key=lambda group: group.heading is not None)
    headed = sum(len(group.rows) for group in shown) >= HEADING_THRESHOLD
    for group in shown:
        if headed and group.heading is not None:
            print(_styled(printable(str(group.heading)), _BOLD, sys.stdout))
        for row in group.rows:
            write_row(row)


def write_table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> None:
    """The table on stdout: each cell escaped before it is padded, each column as wide as its widest
    cell, two spaces apart, the last column unpadded; on a terminal the header is bold."""
    lines = [[printable(cell) for cell in line] for line in (headers, *rows)]
    widths = [max(len(line[column]) for line in lines) for column in range(len(headers))]
    printed = [
        "  ".join(cell.ljust(width) for cell, width in zip(line, widths, strict=True)).rstrip()
        for line in lines
    ]
    print(_styled(printed[0], _BOLD, sys.stdout))
    for line in printed[1:]:
        print(line)


def write_verdict(verdict: Verdict) -> None:
    """The last line of a command on stdout: the summary, its non-zero counts, the run time, then
    the hint. On a terminal the glyph and summary are bold in the glyph's colour, the counts and
    the run time dim; a `next:` line follows when the verdict has a next step."""
    stdout = sys.stdout
    shown_counts = ", ".join(counted(number, label) for number, label in verdict.counts if number)
    hint = [printable(verdict.hint)] if verdict.hint else []
    headline_text = printable(verdict.summary) or shown_counts
    if _json_on():
        counts = {_label(0, label): number for number, label in verdict.counts if number}
        _write_event(
            Level.of(verdict.glyph),
            stdout,
            headline_text,
            {
                **counts,
                "seconds": None
                if verdict.elapsed_seconds is None
                else _field_value(verdict.elapsed_seconds),
                "details": [printable(detail) for detail in verdict.details],
                "hint": printable(verdict.hint),
                "next": printable(verdict.next_step),
            },
        )
        return
    headline = _styled(
        f"{verdict.glyph.value} {headline_text}", verdict.glyph.verdict_style, stdout
    )
    counts = [_styled(shown_counts, _DIM, stdout)] if shown_counts and verdict.summary else []
    details = [_styled(printable(detail), _DIM, stdout) for detail in verdict.details]
    run_time = (
        [_styled(format_duration(verdict.elapsed_seconds), _DIM, stdout)]
        if verdict.elapsed_seconds is not None
        else []
    )
    print(_FACT_SEPARATOR.join([headline, *counts, *details, *run_time, *hint]))
    if verdict.next_step:
        print(f"{_styled('next:', _CYAN, stdout)} {printable(verdict.next_step)}")


def write_error(message: str, next_step: str | None = None, *, fresh_line: bool = False) -> None:
    """`error: <message>` and, when there is a way on, `next: <command>` on stderr; on a terminal
    the labels are bold red and cyan. `fresh_line` first ends a line a hidden prompt left open."""
    stderr = sys.stderr
    if _json_on():
        _write_event(
            Level.ERROR,
            stderr,
            "error",
            {"message": printable(message), "next": printable(next_step or "")},
        )
        return
    if fresh_line:
        print(file=stderr)
    print(f"{_styled('error:', _BOLD_RED, stderr)} {printable(message)}", file=stderr)
    if next_step:
        print(f"{_styled('next:', _CYAN, stderr)} {printable(next_step)}", file=stderr)


def write_detail(*lines: str, tone: Tone = Tone.PLAIN) -> None:
    """Each line on stdout under a row, indented and escaped; on a terminal it takes the tone's
    style."""
    stdout = sys.stdout
    for line in lines:
        text = f"{DETAIL_INDENT}{printable(line)}"
        print(text if tone.value is None else _styled(text, tone.value, stdout))


class Stream(Enum):
    STDOUT = "stdout"
    STDERR = "stderr"


def write_line(
    text: str, *, stream: Stream = Stream.STDOUT, end: str = "\n", flush: bool = False
) -> None:
    """`text` as one line on `stream`, exactly as given: for a line whose form its caller owns (a
    JSON document, a listing, a diagnostic that names its own program); `flush` for a reader that
    follows the output as it comes."""
    print(text, end=end, file=sys.stderr if stream is Stream.STDERR else sys.stdout, flush=flush)


def confirmed(purpose: str) -> bool:
    """Ask `Type yes to <purpose>: ` on stdout and return whether the answer is exactly `yes`: no
    trimming, no case folding; a closed stdin is a no, and Ctrl-C is not caught."""
    prompt = f"Type {_styled(CONFIRMATION, _BOLD, sys.stdout)} to {printable(purpose)}: "
    try:
        return input(prompt) == CONFIRMATION
    except EOFError:
        return False
