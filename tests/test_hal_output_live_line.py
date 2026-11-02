"""The live line of hal.output: one transient stderr line with the current task and its time."""

from __future__ import annotations

import io
import itertools
import re
import signal
import sys
import threading
from collections.abc import Iterator
from contextlib import nullcontext
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


class RedrawHeldAtTheLock:
    """The line's lock, with a redrawing thread that stops in front of it, past its wait, until the
    test opens it: the moment a stop can overtake a redraw."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.reached = threading.Event()
        self.opened = threading.Event()
        self.redrawer: threading.Thread | None = None

    def __enter__(self) -> None:
        if threading.current_thread() is not threading.main_thread():
            self.redrawer = threading.current_thread()
            self.reached.set()
            assert self.opened.wait(timeout=10)
        self.lock.acquire()

    def __exit__(self, *_exception: object) -> None:
        self.lock.release()

    def let_the_redrawer_end(self) -> None:
        self.opened.set()
        self.redrawer.join(timeout=10)
        assert not self.redrawer.is_alive()


def redraw_held_at_the_lock(
    monkeypatch: pytest.MonkeyPatch, thread: type[threading.Thread] = threading.Thread
) -> RedrawHeldAtTheLock:
    """A line that ticks fast, on `thread`, whose redraw waits at the lock and whose stop gives up
    on it at once."""
    held = RedrawHeldAtTheLock()
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 0.01)
    monkeypatch.setattr(
        hal.output,
        "threading",
        SimpleNamespace(Thread=thread, Lock=lambda: held, Event=threading.Event),
    )
    return held


def press_ctrl_c() -> None:
    signal.raise_signal(signal.SIGINT)


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


def test_a_line_redrawing_fast_across_two_shows_has_one_thread_and_ends_on_the_erase(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch, frames_wanted=4)
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    threads_before = threading.active_count()
    ctrl_c_before = signal.getsignal(signal.SIGINT)

    with live_line(SUBJECT) as show:
        show("first task")
        show("second task")
        threads_during = threading.active_count()
        assert err.reached.wait(timeout=10)

    assert threads_during == threads_before + 1
    assert threading.active_count() == threads_before
    assert err.getvalue().endswith(ERASE)
    assert signal.getsignal(signal.SIGINT) is ctrl_c_before


def test_without_a_new_show_a_later_frame_comes_with_a_later_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch, frames_wanted=3)
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    ticking = itertools.count()
    monkeypatch.setattr(
        hal.output, "time", SimpleNamespace(monotonic=lambda: float(min(next(ticking), 59)))
    )

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


LONG_NAME = "Install the packages the edge server needs to run"


@pytest.mark.parametrize(
    ("columns", "name", "seconds", "frame"),
    [
        (30, LONG_NAME, 0.4, "  ⠋ system          In… · <1s"),
        (30, LONG_NAME, 65, "  ⠋ system          … · 1m05s"),
        (33, "abcdef", 0.4, "  ⠋ system          abcdef · <1s"),
        (33, "abcdefg", 0.4, "  ⠋ system          abcde… · <1s"),
        (40, "short", 0.4, "  ⠋ system          short · <1s"),
        (27, LONG_NAME, 0.4, "  ⠋ system          Insta…"),
        (20, LONG_NAME, 0.4, "  ⠋ system        …"),
        (2, LONG_NAME, 0.4, "…"),
    ],
    ids=[
        "cut name keeps the time",
        "wider time leaves less name",
        "name that just fits",
        "one character too many",
        "short name",
        "no room for a name",
        "no room for the time",
        "one column to draw in",
    ],
)
@pytest.mark.usefixtures("stills")
def test_a_frame_stays_inside_the_terminal_and_gives_up_the_name_before_the_time(
    monkeypatch: pytest.MonkeyPatch, columns: int, name: str, seconds: float, frame: str
) -> None:
    _, err = stderr_terminal(monkeypatch)
    monkeypatch.setenv("COLUMNS", str(columns))
    monkeypatch.setattr(hal.output, "time", clock_reading(0, seconds))

    with live_line(SUBJECT) as show:
        show(name)

    assert frames_of(err) == [frame]
    assert len(frame) <= columns - 1


@pytest.mark.usefixtures("stills")
def test_a_terminal_of_one_column_gets_no_printable_byte_so_nothing_wraps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch)
    monkeypatch.setenv("COLUMNS", "1")

    with live_line(SUBJECT) as show:
        show(LONG_NAME)

    assert frames_of(err) == []


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


def test_a_redraw_past_its_wait_draws_nothing_once_a_ctrl_c_stopped_the_line(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The Ctrl-C lands as the thread starts, before the line has it to join."""
    _, err = stderr_terminal(monkeypatch)

    class CtrlCOnceStarted(threading.Thread):
        def start(self) -> None:
            super().start()
            assert held.reached.wait(timeout=10)
            press_ctrl_c()

    held = redraw_held_at_the_lock(monkeypatch, CtrlCOnceStarted)

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("Restart Docker")
    left = err.getvalue()
    held.let_the_redrawer_end()

    assert err.getvalue() == left


def test_a_ctrl_c_before_the_thread_starts_ends_the_block_without_a_frame_more(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch)

    class CtrlCBeforeStart(threading.Thread):
        def start(self) -> None:
            press_ctrl_c()

    monkeypatch.setattr(
        hal.output,
        "threading",
        SimpleNamespace(Thread=CtrlCBeforeStart, Lock=threading.Lock, Event=threading.Event),
    )

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("Restart Docker")

    assert ERASE not in err.getvalue()[len(ERASE) :]


@pytest.mark.parametrize("ctrl_c_in_the_block", [False, True], ids=["normal end", "second Ctrl-C"])
def test_a_ctrl_c_inside_the_stop_waits_for_the_stop_and_nothing_draws_after_it(
    monkeypatch: pytest.MonkeyPatch, ctrl_c_in_the_block: bool
) -> None:
    _, err = stderr_terminal(monkeypatch)

    class CtrlCsInTheJoin(threading.Thread):
        pressed = False

        def join(self, timeout: float | None = None) -> None:
            if not self.pressed:
                self.pressed = True
                press_ctrl_c()
                press_ctrl_c()
            super().join(timeout)

    held = redraw_held_at_the_lock(monkeypatch, CtrlCsInTheJoin)
    ctrl_c_before = signal.getsignal(signal.SIGINT)

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("Restart Docker")
        assert held.reached.wait(timeout=10)
        if ctrl_c_in_the_block:
            raise KeyboardInterrupt
    left = err.getvalue()
    held.let_the_redrawer_end()

    assert err.getvalue() == left
    assert left.count(ERASE) == 1
    assert signal.getsignal(signal.SIGINT) is ctrl_c_before


def test_a_ctrl_c_inside_a_normal_stop_leaves_the_line_for_the_row_below_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, err = stderr_terminal(monkeypatch)

    class CtrlCThenTheRedrawEnds(threading.Thread):
        def join(self, timeout: float | None = None) -> None:
            press_ctrl_c()
            held.opened.set()
            super().join(timeout)

    held = redraw_held_at_the_lock(monkeypatch, CtrlCThenTheRedrawEnds)
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 10)

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("Restart Docker")
        assert held.reached.wait(timeout=10)

    assert err.getvalue().count(ERASE) == 1


def returns_at_a_ctrl_c(_signal_number: int, _frame: object) -> None:
    """A caller's handler that lets the play go on."""


@pytest.mark.usefixtures("stills")
@pytest.mark.parametrize(
    "callers_handler", [signal.SIG_IGN, returns_at_a_ctrl_c], ids=["ignored", "returning"]
)
def test_a_callers_handler_stays_so_a_ctrl_c_keeps_the_play_and_the_line_and_the_end_erases(
    monkeypatch: pytest.MonkeyPatch, callers_handler: object
) -> None:
    _, err = stderr_terminal(monkeypatch)
    ctrl_c_before = signal.signal(signal.SIGINT, callers_handler)
    try:
        with live_line(SUBJECT) as show:
            show("first task")
            handler_in_the_block = signal.getsignal(signal.SIGINT)
            press_ctrl_c()
            show("second task")
            frames_drawn = frames_of(err)
        handler_after = signal.getsignal(signal.SIGINT)
    finally:
        signal.signal(signal.SIGINT, ctrl_c_before)

    assert handler_in_the_block is callers_handler
    assert len(frames_drawn) == 2
    assert "second task" in frames_drawn[-1]
    assert err.getvalue().endswith(ERASE)
    assert handler_after is callers_handler


@pytest.mark.usefixtures("stills")
def test_the_default_action_handler_stays_too(monkeypatch: pytest.MonkeyPatch) -> None:
    stderr_terminal(monkeypatch)
    ctrl_c_before = signal.signal(signal.SIGINT, signal.SIG_DFL)
    try:
        with live_line(SUBJECT) as show:
            show("first task")
            handler_in_the_block = signal.getsignal(signal.SIGINT)
        handler_after = signal.getsignal(signal.SIGINT)
    finally:
        signal.signal(signal.SIGINT, ctrl_c_before)

    assert handler_in_the_block == signal.SIG_DFL
    assert handler_after == signal.SIG_DFL


class CtrlCInTheSecondFrame(FrameStream):
    def write(self, text: str, /) -> int:
        written = super().write(text)
        if self.frames == 2 and len(text) > len(ERASE):
            press_ctrl_c()
        return written


@pytest.mark.usefixtures("stills")
def test_a_ctrl_c_in_the_middle_of_a_frame_leaves_that_frame_and_ends_the_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_on_terminals(monkeypatch)
    err = CtrlCInTheSecondFrame()
    monkeypatch.setattr(sys, "stderr", err)
    threads_before = threading.active_count()

    with pytest.raises(KeyboardInterrupt), live_line(SUBJECT) as show:
        show("first task")
        show("second task")

    assert threading.active_count() == threads_before
    assert frames_of(err)[-1].split()[-3:] == ["task", "·", "<1s"]
    assert not err.getvalue().endswith(ERASE)


class StoppedTerminal(FrameStream):
    """A terminal stopped with Ctrl-S: the redrawing thread's write hangs until it is resumed, or
    until a watchdog gives up, which only a stop without a bound lets happen."""

    def __init__(self) -> None:
        super().__init__()
        self.hanging = threading.Event()
        self.resumed = threading.Event()
        self.watchdog_fired = False
        self.writer: threading.Thread | None = None

    def write(self, text: str, /) -> int:
        if threading.current_thread() is not threading.main_thread():
            self.writer = threading.current_thread()
            self.hanging.set()
            self.watchdog_fired = not self.resumed.wait(timeout=10)
        return super().write(text)


@pytest.mark.parametrize("ctrl_c", [False, True], ids=["normal end", "Ctrl-C"])
def test_a_stopped_terminal_holds_the_thread_and_the_block_ends_within_the_bound(
    monkeypatch: pytest.MonkeyPatch, ctrl_c: bool
) -> None:
    put_on_terminals(monkeypatch)
    err = StoppedTerminal()
    monkeypatch.setattr(sys, "stderr", err)
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 0.01)

    with pytest.raises(KeyboardInterrupt) if ctrl_c else nullcontext(), live_line(SUBJECT) as show:
        show("Restart Docker")
        assert err.hanging.wait(timeout=10)
        if ctrl_c:
            press_ctrl_c()
    ended_within_the_bound = not err.watchdog_fired
    err.resumed.set()
    err.writer.join(timeout=10)

    assert ended_within_the_bound
    assert not err.getvalue().endswith(ERASE)
