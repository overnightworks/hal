"""The live line of hal.output: one transient stderr line with the current task and its time."""

from __future__ import annotations

import io
import re
import sys
import threading
from collections.abc import Iterator
from enum import StrEnum
from types import SimpleNamespace

import pytest
from support.terminal_support import TerminalStream, put_on_terminals

import hal.output
from hal.output import Glyph, Row, live_line, verbose_run, write_row

ERASE = "\r\x1b[K"
ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")
SUBJECT = "system"


class Event(StrEnum):
    INTERRUPTED = "interrupted"


class FrameStream(TerminalStream):
    """A terminal that says when it has been handed a number of frames (a write past the erase)."""

    def __init__(self, frames_wanted: int = 1) -> None:
        super().__init__()
        self.frames_wanted = frames_wanted
        self.frames = 0
        self.reached = threading.Event()

    def write(self, text: str, /) -> int:
        written = super().write(text)
        if len(text) > len(ERASE):
            self.frames += 1
            if self.frames >= self.frames_wanted:
                self.reached.set()
        return written


def frames_of(stream: TerminalStream) -> list[str]:
    """The visible text of each frame, without colour and erase."""
    return [ANSI.sub("", frame) for frame in stream.getvalue().split("\r") if ANSI.sub("", frame)]


def clock_reading(*seconds: float) -> SimpleNamespace:
    readings: Iterator[float] = iter(seconds)
    return SimpleNamespace(monotonic=lambda: next(readings))


@pytest.fixture
def stills(monkeypatch: pytest.MonkeyPatch) -> None:
    """The thread never redraws, so every frame is one `show`."""
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 3600)


def stderr_terminal(
    monkeypatch: pytest.MonkeyPatch, frames_wanted: int = 1
) -> tuple[TerminalStream, FrameStream]:
    out, _ = put_on_terminals(monkeypatch)
    err = FrameStream(frames_wanted)
    monkeypatch.setattr(sys, "stderr", err)
    return out, err


@pytest.mark.usefixtures("stills")
def test_show_draws_an_erase_then_a_styled_frame_with_subject_text_and_time_on_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, err = stderr_terminal(monkeypatch)
    monkeypatch.setattr(hal.output, "time", clock_reading(0, 0.4))

    with live_line(SUBJECT) as show:
        show("Read the default log driver")
        drawn = err.getvalue()

    assert drawn.startswith(ERASE)
    assert "\x1b[" in drawn[len(ERASE) :]
    assert frames_of(err)[0].split() == [
        "⠋",
        SUBJECT,
        "Read",
        "the",
        "default",
        "log",
        "driver",
        "·",
        "<1s",
    ]
    assert out.getvalue() == ""


@pytest.mark.usefixtures("stills")
def test_the_end_of_the_block_erases_the_line_and_nothing_follows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch)
    threads_before = threading.active_count()

    with live_line(SUBJECT) as show:
        show("Write edge files")

    assert err.getvalue().endswith(ERASE)
    assert err.getvalue().count(ERASE) == 2
    assert threading.active_count() == threads_before


def test_without_a_new_show_a_later_frame_comes_with_a_later_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch, frames_wanted=3)
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    ticking = iter(range(1000))
    monkeypatch.setattr(hal.output, "time", SimpleNamespace(monotonic=lambda: float(next(ticking))))

    with live_line(SUBJECT) as show:
        show("Install packages")
        assert err.reached.wait(timeout=10)

    seconds = [int(re.search(r"· (\d+)s$", frame).group(1)) for frame in frames_of(err)]
    assert seconds[0] < seconds[-1]
    assert seconds == sorted(seconds)


@pytest.mark.usefixtures("stills")
def test_a_new_show_changes_the_text_and_restarts_the_time(monkeypatch: pytest.MonkeyPatch) -> None:
    _, err = stderr_terminal(monkeypatch)
    monkeypatch.setattr(hal.output, "time", clock_reading(0, 70, 100, 101))

    with live_line(SUBJECT) as show:
        show("first task")
        show("second task")

    first, second = frames_of(err)[:2]
    assert (first.endswith("first task · 1m10s"), second.endswith("second task · 1s")) == (
        True,
        True,
    )


def terminal_without_colour(monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_terminal(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")


def terminal_that_is_dumb(monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_terminal(monkeypatch)
    monkeypatch.setenv("TERM", "dumb")


def terminal_in_json(monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_terminal(monkeypatch)
    monkeypatch.setenv("LOG_FORMAT", "json")


def stderr_in_a_pipe(monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_terminal(monkeypatch)
    monkeypatch.setattr(sys, "stderr", io.StringIO())


@pytest.mark.parametrize(
    ("arrange", "verbose"),
    [
        (stderr_in_a_pipe, False),
        (terminal_without_colour, False),
        (terminal_that_is_dumb, False),
        (terminal_in_json, False),
        (lambda monkeypatch: stderr_terminal(monkeypatch), True),
    ],
    ids=["pipe", "NO_COLOR", "TERM=dumb", "LOG_FORMAT=json", "-v"],
)
@pytest.mark.usefixtures("stills")
def test_off_a_terminal_or_under_v_or_json_show_writes_nothing_and_starts_no_thread(
    monkeypatch: pytest.MonkeyPatch, arrange, verbose: bool
) -> None:
    arrange(monkeypatch)
    threads_before = threading.active_count()

    with verbose_run(verbose), live_line(SUBJECT) as show:
        show("Write edge files")
        threads_during = threading.active_count()

    assert (sys.stderr.getvalue(), threads_during) == ("", threads_before)


@pytest.mark.parametrize(
    ("name", "cut"),
    [("Install the packages the edge server needs to run", True), ("short", False)],
    ids=["long name", "short name"],
)
@pytest.mark.usefixtures("stills")
def test_a_name_wider_than_the_terminal_is_cut_to_one_column_less_with_an_ellipsis(
    monkeypatch: pytest.MonkeyPatch, name: str, cut: bool
) -> None:
    _, err = stderr_terminal(monkeypatch)
    monkeypatch.setenv("COLUMNS", "40")

    with live_line(SUBJECT) as show:
        show(name)

    (frame,) = frames_of(err)
    assert (
        ((len(frame), frame.endswith("…")) == (39, True))
        if cut
        else (name in frame and "…" not in frame)
    )


@pytest.mark.usefixtures("stills")
def test_a_name_with_escape_and_newline_is_one_escaped_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch)

    with live_line(SUBJECT) as show:
        show("a\x1b[31m\nb")
        drawn = err.getvalue()

    assert "\\x1b[31m\\nb" in drawn
    assert "\n" not in drawn
    assert "\x1b[31m" not in drawn


@pytest.mark.usefixtures("stills")
def test_a_block_that_never_shows_writes_no_byte(monkeypatch: pytest.MonkeyPatch) -> None:
    _, err = stderr_terminal(monkeypatch)
    threads_before = threading.active_count()

    with live_line(SUBJECT):
        assert threading.active_count() == threads_before

    assert err.getvalue() == ""


@pytest.mark.usefixtures("stills")
def test_a_ctrl_c_leaves_the_line_and_the_next_row_starts_on_its_own_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    shared = FrameStream()
    put_on_terminals(monkeypatch)
    monkeypatch.setattr(sys, "stdout", shared)
    monkeypatch.setattr(sys, "stderr", shared)

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("Restart Docker")
        raise KeyboardInterrupt
    left = shared.getvalue()
    write_row(Row(Glyph.FAILED, SUBJECT, Event.INTERRUPTED), fresh_line=True)

    assert not left.endswith(ERASE)
    assert "Restart Docker" in left
    lines = ANSI.sub("", shared.getvalue()).replace("\r", "\n").split("\n")
    assert [line for line in lines if line.strip()][-1].split() == ["✗", SUBJECT, "interrupted"]
    assert "\n\n" not in shared.getvalue()
