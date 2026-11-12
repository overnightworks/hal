"""How a run meets the stop signals: SIGTERM ends it as Ctrl-C does, and a protected region drops
both signals so its work is one step."""

import signal
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

_STOP_SIGNALS = (signal.SIGINT, signal.SIGTERM)


def _raise_interrupt(_signal_number: int, _frame: object) -> None:
    raise KeyboardInterrupt


@contextmanager
def terminate_like_interrupt() -> Iterator[None]:
    """systemd stops a unit with SIGTERM: a run ends as on Ctrl-C, cleanup runs, the unit fails."""
    previous = signal.signal(signal.SIGTERM, _raise_interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@contextmanager
def signals_ignored() -> Iterator[None]:
    """A protected region: a stop signal inside it is dropped, so its work is one step."""
    previous: dict[int, Any] = {}
    try:
        for number in _STOP_SIGNALS:
            previous[number] = signal.signal(number, signal.SIG_IGN)
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
