"""The doubles and the entry point the wizard's tests share: a terminal, a disk and a way to run the walk."""

from __future__ import annotations

import os
import signal
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

import pytest

from hal.workstation.layout import Layout
from hal.workstation.secrets_setup import TERMINAL_BOUNDARIES, Boundaries, Terminal, TokenVerifier, WalkEnd, run_setup

WIZARD_NOW = datetime(2026, 10, 17, 9, 0)


@dataclass
class FakeTerminal:
    """A terminal whose operator pastes the queued answers; an exception class in the queue is raised instead."""

    pastes: list[str | type[BaseException]] = field(default_factory=list)
    enter: type[BaseException] | None = None
    browser_opens: bool = True
    opened: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)

    def ask(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if self.enter:
            raise self.enter
        return ""

    def ask_hidden(self, prompt: str) -> str:
        self.prompts.append(prompt)
        answer = self.pastes.pop(0) if self.pastes else ""
        if isinstance(answer, type):
            raise answer
        return answer

    def open_page(self, page: str) -> bool:
        self.opened.append(page)
        return self.browser_opens

    def boundary(self) -> Terminal:
        return Terminal(lambda: True, self.ask, self.ask_hidden, self.open_page)


@dataclass
class FakeSync:
    """The disk under the walk; `interrupted` raises Ctrl-C while a file is synced, `ctrl_c` sends the real signal then."""

    interrupted: bool = False
    ctrl_c: bool = False

    def sync(self, descriptor: int) -> None:
        if self.interrupted:
            raise KeyboardInterrupt
        if self.ctrl_c:
            os.kill(os.getpid(), signal.SIGINT)
        os.fsync(descriptor)


def squeezed(output: str) -> list[str]:
    """The output's lines with each run of spaces squeezed to one, so a row reads as its columns in order."""
    return [" ".join(line.split()) for line in output.splitlines()]


def private_directory(home: Path, relative: str) -> Path:
    """A directory below ~/.secrets the way a tidy one is kept: every level 0700."""
    path = home
    for part in Path(relative).parts:
        path /= part
        path.mkdir(mode=0o700, exist_ok=True)
    return path


def secrets_terminal(at_a_terminal: bool) -> Boundaries:
    """A terminal that must never be asked for a value: the manifest holds only generated passwords."""

    def never_asked(_prompt: str) -> str:
        raise AssertionError("the wizard asked a person for a value it generates itself")

    terminal = Terminal(lambda: at_a_terminal, never_asked, never_asked, lambda _page: False)
    return Boundaries(
        terminal,
        lambda _source, _value: pytest.fail("a generated password is never verified"),
        lambda _descriptor: None,
    )


def guided_boundaries(ask_hidden: Callable[[str], str], verify: TokenVerifier) -> Boundaries:
    terminal = Terminal(lambda: True, lambda _prompt: "", ask_hidden, lambda _page: True)
    return Boundaries(terminal, verify, lambda _descriptor: None)


def run_wizard(home: Path, boundaries: Boundaries = TERMINAL_BOUNDARIES, now: datetime = WIZARD_NOW) -> WalkEnd:
    """The walk `hal setup` runs for its secrets step, and how it ended."""
    return run_setup(Layout(home), boundaries, now)
