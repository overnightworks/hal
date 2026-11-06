"""The terminal stand-in and the environment recipe of hal.output's colour contract, and the
stand-ins that watch its live line."""

import io
import re
import signal
import sys
import threading
from collections.abc import Callable, Iterator
from types import SimpleNamespace

import pytest

import hal.output

ERASE = "\r\x1b[K"
ANSI = re.compile(r"\x1b\[[0-9;]*[mK]")


class TerminalStream(io.StringIO):
    """A stream a person watches."""

    def isatty(self) -> bool:
        return True


def put_stdout_on_a_terminal(monkeypatch: pytest.MonkeyPatch) -> TerminalStream:
    """Stdout on a terminal, neither NO_COLOR nor TERM=dumb set. Called in the test body:
    pytest swaps `sys.stdout` again between fixture setup and the call."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    out = TerminalStream()
    monkeypatch.setattr(sys, "stdout", out)
    return out


def put_on_terminals(monkeypatch: pytest.MonkeyPatch) -> tuple[TerminalStream, TerminalStream]:
    """Both streams on a terminal, under the same conditions as `put_stdout_on_a_terminal`."""
    out = put_stdout_on_a_terminal(monkeypatch)
    err = TerminalStream()
    monkeypatch.setattr(sys, "stderr", err)
    return out, err


class FrameStream(TerminalStream):
    """A terminal that says when it has been handed a number of frames (a write past the erase)."""

    def __init__(self, frames_wanted: int = 1) -> None:
        super().__init__()
        self.frames_wanted = frames_wanted
        self.frames = 0
        self.reached = threading.Event()

    def write(self, text: str, /) -> int:
        written = super().write(text)
        if text.startswith(ERASE) and len(text) > len(ERASE):
            self.frames += 1
            if self.frames >= self.frames_wanted:
                self.reached.set()
        return written


def frames_of(stream: io.StringIO) -> list[str]:
    """The visible text of each frame, without colour and erase."""
    return [ANSI.sub("", frame) for frame in stream.getvalue().split("\r") if ANSI.sub("", frame)]


def press_ctrl_c() -> None:
    signal.raise_signal(signal.SIGINT)


@pytest.fixture(autouse=True)
def no_newline_owed_after_the_test() -> Iterator[None]:
    """A frame a test's Ctrl-C kept leaves a newline owed to that test's own stream, process-wide
    state: a writer after the test ends it, so the next test's first writer does not print it."""
    yield
    hal.output.write_line("", end="")


class StoppedTerminal(FrameStream):
    """A terminal stopped with Ctrl-S: the redrawing thread's write hangs until it is resumed, or
    until a watchdog gives up, which only a stop without a bound lets happen."""

    def __init__(self) -> None:
        super().__init__()
        self.hanging = threading.Event()
        self.resumed = threading.Event()
        self.watchdog_fired = False
        self.writer: threading.Thread | None = None

    def stops(self, text: str) -> bool:
        return threading.current_thread() is not threading.main_thread()

    def write(self, text: str, /) -> int:
        if self.stops(text):
            self.writer = threading.current_thread()
            self.hanging.set()
            self.watchdog_fired = not self.resumed.wait(timeout=10)
        return super().write(text)


class TerminalStoppedAtTheErase(StoppedTerminal):
    """A terminal stopped with Ctrl-S that lets the frames through and holds the erase."""

    def stops(self, text: str) -> bool:
        return super().stops(text) and text == ERASE


class CountedTicks(threading.Event):
    """The live line's wake, which counts the redraw thread's ticks: each wait past the first
    follows one tick, so `passed` is the positive marker an absence of frames waits for."""

    def __init__(self) -> None:
        super().__init__()
        self.waits = 0
        self.wanted: int | None = None
        self.reached = threading.Event()
        self.redrawer: threading.Thread | None = None

    def wait(self, timeout: float | None = None) -> bool:
        if threading.current_thread() is not threading.main_thread():
            self.redrawer = threading.current_thread()
            self.waits += 1
            if self.wanted is not None and self.waits >= self.wanted:
                self.reached.set()
        return super().wait(timeout)

    def passed(self, ticks: int) -> bool:
        """Whether the redraw thread passed `ticks` more ticks within the watchdog."""
        self.wanted = self.waits + ticks + 1
        self.reached.clear()
        return self.reached.wait(timeout=10)

    def redrawer_ended(self) -> bool:
        self.redrawer.join(timeout=10)
        return not self.redrawer.is_alive()


def ticking_line(
    monkeypatch: pytest.MonkeyPatch, lock: Callable[[], object] = threading.Lock
) -> CountedTicks:
    """A live line that ticks fast through the one seam its tests drive, the module's
    `threading`: its wake counts the ticks, and `lock` stands in for its lock."""
    ticks = CountedTicks()
    monkeypatch.setattr(hal.output, "LIVE_TICK_SECONDS", 0.001)
    monkeypatch.setattr(
        hal.output,
        "threading",
        SimpleNamespace(Thread=threading.Thread, Lock=lock, Event=lambda: ticks),
    )
    return ticks


class Typist:
    """The person at the yes prompt: one typed line, none (EOF), or Ctrl-C. `while_waiting` runs
    once the prompt is shown and before the answer comes, as time passes for a real person."""

    def __init__(
        self,
        answer: str | type[BaseException] | None,
        while_waiting: Callable[[], None] | None = None,
    ) -> None:
        self.answer = answer
        self.while_waiting = while_waiting

    def readline(self) -> str:
        if self.while_waiting:
            self.while_waiting()
        if isinstance(self.answer, type):
            raise self.answer
        return "" if self.answer is None else f"{self.answer}\n"


def type_at_prompt(
    monkeypatch: pytest.MonkeyPatch,
    answer: str | type[BaseException] | None = "yes",
    while_waiting: Callable[[], None] | None = None,
) -> Typist:
    typist = Typist(answer, while_waiting)
    monkeypatch.setattr(sys, "stdin", typist)
    return typist
