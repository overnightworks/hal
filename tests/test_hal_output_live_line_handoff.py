"""The handoff of hal.output's live line: every writer erases a drawn frame first, a line a
Ctrl-C took gets one newline, and a stopped line draws no frame more, on a terminal whose stdout
and stderr are one buffer."""

from __future__ import annotations

import signal
import sys
import threading
from collections.abc import Iterator
from enum import StrEnum
from types import SimpleNamespace

import pytest
from support.terminal_support import (
    ANSI,
    ERASE,
    FrameStream,
    StoppedTerminal,
    TerminalStoppedAtTheErase,
    frames_of,
    no_newline_owed_after_the_test,  # noqa: F401 the autouse fixture, active in this module
    press_ctrl_c,
    put_on_terminals,
    ticking_line,
    type_at_prompt,
)

import hal.output
from hal.output import (
    Glyph,
    GroupWriter,
    Row,
    Verdict,
    confirmed,
    live_line,
    write_detail,
    write_error,
    write_line,
    write_row,
    write_table,
    write_verdict,
)

SUBJECT = "system"

TICKS = 5


class Step(StrEnum):
    RESTARTED = "restarted"
    INTERRUPTED = "interrupted"
    NOT_RUN = "not run"


class Heading(StrEnum):
    CORE = "core"


def one_terminal(monkeypatch: pytest.MonkeyPatch, stream: FrameStream | None = None) -> FrameStream:
    """Stdout and stderr on one terminal, so the order of erase and row is one buffer."""
    put_on_terminals(monkeypatch)
    shared = stream or FrameStream()
    monkeypatch.setattr(sys, "stdout", shared)
    monkeypatch.setattr(sys, "stderr", shared)
    return shared


def a_row() -> None:
    write_row(Row(Glyph.DONE, SUBJECT, Step.RESTARTED))


def a_heading() -> None:
    writer = GroupWriter(headed=True)
    writer.enter(Heading.CORE)
    writer.write(Row(Glyph.DONE, SUBJECT, Step.RESTARTED))


WRITERS = {
    "row": a_row,
    "heading": a_heading,
    "error and next": lambda: write_error("partial, traefik failed", "hal apply"),
    "verdict": lambda: write_verdict(Verdict(Glyph.DONE, "applied", ())),
    "table": lambda: write_table(["unit", "state"], [["traefik", "running"]]),
    "detail": lambda: write_detail("pre-apply snapshot ab12cd34"),
    "line": lambda: write_line("a listing line"),
    "prompt": lambda: confirmed("apply 1 change"),
}


@pytest.mark.parametrize("writer", WRITERS.values(), ids=WRITERS.keys())
def test_every_writer_erases_a_drawn_frame_first_and_the_line_returns_only_at_the_next_show(
    monkeypatch: pytest.MonkeyPatch, writer
) -> None:
    type_at_prompt(monkeypatch)
    shared = one_terminal(monkeypatch)
    writer()
    alone = shared.getvalue()
    shared = one_terminal(monkeypatch)
    ticks = ticking_line(monkeypatch)

    with live_line() as show:
        show(SUBJECT, "Restart Docker")
        assert shared.reached.wait(timeout=10)
        writer()
        assert ticks.passed(TICKS)
        given_way = shared.getvalue()
        show(SUBJECT, "Write edge files")
        shown_again = frames_of(shared)[-1]

    assert given_way.endswith(ERASE + alone)
    assert "Restart Docker" in ANSI.sub("", given_way.removesuffix(ERASE + alone).split("\r")[-1])
    assert "Write edge files" in shown_again


def kept_by_a_ctrl_c(show) -> None:
    show(SUBJECT, "Restart Docker")
    assert sys.stderr.reached.wait(timeout=10)
    press_ctrl_c()


def interrupted_rows(*, fresh_line: bool) -> None:
    write_row(Row(Glyph.FAILED, SUBJECT, Step.INTERRUPTED), fresh_line=fresh_line)
    write_row(Row(Glyph.UNCHANGED, SUBJECT, Step.NOT_RUN))


def visible_lines(text: str) -> list[list[str]]:
    return [line.split() for line in ANSI.sub("", text).split("\n")]


@pytest.mark.parametrize("fresh_line", [False, True], ids=["plain row", "fresh_line"])
@pytest.mark.parametrize("after_the_block", [False, True], ids=["in the block", "after it"])
def test_a_frame_a_ctrl_c_kept_gets_exactly_one_newline_from_the_next_writer(
    monkeypatch: pytest.MonkeyPatch, fresh_line: bool, after_the_block: bool
) -> None:
    shared = one_terminal(monkeypatch)
    ticks = ticking_line(monkeypatch)

    if after_the_block:
        with pytest.raises(KeyboardInterrupt), live_line() as show:
            kept_by_a_ctrl_c(show)
        kept = shared.getvalue()
        interrupted_rows(fresh_line=fresh_line)
    else:
        with live_line() as show:
            with pytest.raises(KeyboardInterrupt):
                kept_by_a_ctrl_c(show)
            kept = shared.getvalue()
            interrupted_rows(fresh_line=fresh_line)

    rest = shared.getvalue()[len(kept) :]
    assert ticks.redrawer_ended()
    assert "Restart Docker" in frames_of(shared)[-1]
    assert visible_lines(rest) == [
        [],
        ["✗", SUBJECT, "interrupted"],
        ["·", SUBJECT, "not", "run"],
        [],
    ]


class CtrlCAfterTheErase(FrameStream):
    """A terminal on which a Ctrl-C lands right after the main thread erased the frame, between a
    writer's erase and its print, once `ready` says so, when it is given."""

    pressed = False

    def __init__(self, ready: threading.Event | None = None) -> None:
        super().__init__()
        self.ready = ready

    def write(self, text: str, /) -> int:
        written = super().write(text)
        main_thread = threading.current_thread() is threading.main_thread()
        if text == ERASE and main_thread and not self.pressed:
            self.pressed = True
            if self.ready is not None:
                assert self.ready.wait(timeout=10)
            press_ctrl_c()
        return written


class LockThatReportsTheWait:
    """The line's lock, which says when the main thread or, once `armed`, the redraw thread goes to
    wait for it."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.armed = False
        self.main_waits = threading.Event()
        self.redraw_waits = threading.Event()

    def __enter__(self) -> None:
        if threading.current_thread() is threading.main_thread():
            if self.armed:
                self.main_waits.set()
        elif self.armed and self._lock.locked():
            self.redraw_waits.set()
        self._lock.acquire()

    def __exit__(self, *_exception: object) -> None:
        self._lock.release()


@pytest.mark.parametrize("fresh_line", [False, True], ids=["plain row", "fresh_line"])
@pytest.mark.parametrize(
    "redraw_waits", [False, True], ids=["right after the erase", "redraw waits at the lock"]
)
def test_a_ctrl_c_in_a_writers_erase_owes_one_newline_which_the_next_writer_pays_once(
    monkeypatch: pytest.MonkeyPatch, fresh_line: bool, redraw_waits: bool
) -> None:
    lock = LockThatReportsTheWait()
    shared = one_terminal(
        monkeypatch, CtrlCAfterTheErase(lock.redraw_waits if redraw_waits else None)
    )
    ticks = ticking_line(monkeypatch, lock=lambda: lock)
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 0.01)

    def block() -> None:
        with live_line() as show:
            show(SUBJECT, "Restart Docker")
            lock.armed = True
            assert shared.reached.wait(timeout=10)
            a_row()

    with pytest.raises(KeyboardInterrupt):
        block()
    assert ticks.redrawer_ended()
    left = shared.getvalue()
    write_row(Row(Glyph.FAILED, SUBJECT, Step.INTERRUPTED), fresh_line=fresh_line)

    rest = shared.getvalue()[len(left) :]
    assert left.endswith(ERASE)
    assert "restarted" not in left
    assert "\r" not in rest
    assert visible_lines(rest) == [[], ["✗", SUBJECT, "interrupted"], []]


@pytest.fixture
def stopped_terminal(monkeypatch: pytest.MonkeyPatch) -> Iterator[StoppedTerminal]:
    """A terminal stopped with Ctrl-S, which the teardown resumes; the test puts both streams on
    it."""
    stopped = StoppedTerminal()
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 0.01)
    yield from resumed_at_the_end(stopped)


def resumed_at_the_end(stopped: StoppedTerminal) -> Iterator[StoppedTerminal]:
    yield stopped
    stopped.resumed.set()
    if stopped.writer is not None:
        stopped.writer.join(timeout=10)


@pytest.fixture
def terminal_stopped_at_the_erase(monkeypatch: pytest.MonkeyPatch) -> Iterator[StoppedTerminal]:
    """A terminal stopped with Ctrl-S that holds the erase of the block's end, which the teardown
    resumes; the redraw thread never ticks."""
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 3600)
    monkeypatch.setattr(hal.output, "LIVE_STOP_SECONDS", 0.01)
    yield from resumed_at_the_end(TerminalStoppedAtTheErase())


def ctrl_c_once_the_main_thread_waits(lock: LockThatReportsTheWait) -> threading.Thread:
    def send() -> None:
        if lock.main_waits.wait(timeout=10):
            signal.pthread_kill(threading.main_thread().ident, signal.SIGINT)

    sender = threading.Thread(target=send)
    sender.start()
    return sender


def test_a_ctrl_c_ends_a_writers_wait_at_the_lock_and_no_frame_starts_after_it(
    monkeypatch: pytest.MonkeyPatch, stopped_terminal: StoppedTerminal
) -> None:
    one_terminal(monkeypatch, stopped_terminal)
    lock = LockThatReportsTheWait()
    ticking_line(monkeypatch, lock=lambda: lock)

    senders: list[threading.Thread] = []

    def block() -> None:
        with live_line() as show:
            show(SUBJECT, "Restart Docker")
            assert stopped_terminal.hanging.wait(timeout=10)
            lock.armed = True
            senders.append(ctrl_c_once_the_main_thread_waits(lock))
            a_row()

    with pytest.raises(KeyboardInterrupt):
        block()
    left = stopped_terminal.getvalue()
    senders[0].join(timeout=10)
    stopped_terminal.resumed.set()
    stopped_terminal.writer.join(timeout=10)
    released = stopped_terminal.getvalue()
    write_row(Row(Glyph.FAILED, SUBJECT, Step.INTERRUPTED))

    assert not stopped_terminal.watchdog_fired
    assert not stopped_terminal.writer.is_alive()
    assert released[len(left) :].count(ERASE) <= 1
    assert "restarted" not in released
    rest = stopped_terminal.getvalue()[len(released) :]
    assert visible_lines(rest) == [[], ["✗", SUBJECT, "interrupted"], []]


def test_a_ctrl_c_in_a_normal_ends_stop_after_the_erase_owes_one_newline_and_raises(
    monkeypatch: pytest.MonkeyPatch, terminal_stopped_at_the_erase: StoppedTerminal
) -> None:
    stopped = terminal_stopped_at_the_erase
    one_terminal(monkeypatch, stopped)

    class CtrlCOnceTheEraseLanded(threading.Thread):
        pressed = False

        def join(self, timeout: float | None = None) -> None:
            if not self.pressed:
                self.pressed = True
                assert stopped.hanging.wait(timeout=10)
                stopped.resumed.set()
                super().join(timeout=10)
                press_ctrl_c()
            super().join(timeout)

    monkeypatch.setattr(
        hal.output,
        "threading",
        SimpleNamespace(Thread=CtrlCOnceTheEraseLanded, Lock=threading.Lock, Event=threading.Event),
    )

    def block() -> None:
        with live_line() as show:
            show(SUBJECT, "Restart Docker")

    with pytest.raises(KeyboardInterrupt):
        block()
    left = stopped.getvalue()
    write_row(Row(Glyph.FAILED, SUBJECT, Step.INTERRUPTED))

    rest = stopped.getvalue()[len(left) :]
    assert not stopped.watchdog_fired
    assert left.endswith(ERASE)
    assert visible_lines(rest) == [[], ["✗", SUBJECT, "interrupted"], []]


def test_a_show_after_the_line_stopped_returns_at_once_while_the_redraw_holds_the_lock(
    monkeypatch: pytest.MonkeyPatch, stopped_terminal: StoppedTerminal
) -> None:
    one_terminal(monkeypatch, stopped_terminal)
    ticking_line(monkeypatch)

    with live_line() as show:
        show(SUBJECT, "apply the realm step")
        assert stopped_terminal.hanging.wait(timeout=10)
        with pytest.raises(KeyboardInterrupt):
            press_ctrl_c()
        show(SUBJECT, "apply the key step")
        returned_while_held = stopped_terminal.writer.is_alive()
        released_by_the_watchdog = stopped_terminal.watchdog_fired

    assert returned_while_held
    assert not released_by_the_watchdog
    assert not stopped_terminal.resumed.is_set()
    assert "apply the key step" not in stopped_terminal.getvalue()


def test_a_show_with_an_empty_text_erases_the_frame_and_the_line_stays_blank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    put_on_terminals(monkeypatch)
    err = FrameStream()
    monkeypatch.setattr(sys, "stderr", err)
    ticks = ticking_line(monkeypatch)

    with live_line() as show:
        show(SUBJECT, "write the appkit files")
        assert err.reached.wait(timeout=10)
        show(SUBJECT, "")
        assert ticks.passed(TICKS)
        blank = err.getvalue()

    assert ticks.redrawer_ended()
    assert blank.endswith(f"{ERASE}")
    assert "write the appkit files" in frames_of(err)[-1]
    assert err.getvalue() == blank
