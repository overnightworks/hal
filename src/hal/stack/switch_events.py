"""How `hal stop <unit>` reports itself: one row per unit, and a partial stop is never called
switched off.

`emergency` decides what happened and hands over a typed `Closing`; this module turns it into the
row and the error pair. The glyph follows from the event alone, so a partial state cannot be
built with a `✓`.
"""

from dataclasses import dataclass, replace
from enum import StrEnum

from hal.output import Glyph, Row, write_error, write_row
from hal.output.command import Verb, command
from hal.stack import switches

COMMAND = command(Verb.STOP)
NOTHING_CHANGED = "nothing changed"
LOCK_NOT_TAKEN = "lock not taken, a start in progress may reopen it"
APPLY_WOULD_START_IT = f"{command(Verb.APPLY)} would start it again"


class SwitchEvent(StrEnum):
    SWITCHED_OFF = "switched off"
    ALREADY_OFF = "already off"
    BARRIER_BACK = "barrier back"
    DISABLED = "disabled"
    PARTIAL = "partial"


_GLYPH_OF_EVENT = {
    SwitchEvent.SWITCHED_OFF: Glyph.DONE,
    SwitchEvent.ALREADY_OFF: Glyph.UNCHANGED,
    SwitchEvent.BARRIER_BACK: Glyph.DONE,
    SwitchEvent.DISABLED: Glyph.UNCHANGED,
    SwitchEvent.PARTIAL: Glyph.FAILED,
}


class Interruption(StrEnum):
    """The sites of the stop that a Ctrl-C ends."""

    PLANNING = "planning"
    RECORDING = "recording"
    WAITING = "waiting"
    LOCKING = "locking"
    RAISING_THE_BARRIER = "raising the barrier"
    STOPPING = "stopping"


class BarrierPart(StrEnum):
    UP = "barrier up"
    NOT_PROVEN = "barrier not proven"
    NO_HOST = "no host, so no barrier"


class StopPart(StrEnum):
    STOPPED = "stopped"
    NOT_STOPPED = "not stopped"


@dataclass(frozen=True)
class CannotPlan:
    """Why the fleet, or the unit asked for, could not be planned."""

    cause: str


@dataclass(frozen=True)
class Closing:
    """What the close sequence observed. A failure is separate from the others and a part is None
    until its step has returned, so nothing is said of a step that did not finish."""

    record_failure: str | None = None
    lock_failure: str | None = None
    barrier: BarrierPart | None = None
    barrier_failure: str | None = None
    stop: StopPart | None = None
    stop_failure: str | None = None
    interruption: Interruption | None = None

    def with_barrier(self, part: BarrierPart, failure: str | None = None) -> Closing:
        return replace(self, barrier=part, barrier_failure=failure)

    def with_stop(self, part: StopPart, failure: str | None = None) -> Closing:
        return replace(self, stop=part, stop_failure=failure)

    def interrupted(self, step: Interruption) -> Closing:
        return replace(self, interruption=step)

    @property
    def complete(self) -> bool:
        return not self.causes

    @property
    def causes(self) -> list[str]:
        failures = [
            self.record_failure,
            self.lock_failure,
            self.barrier_failure,
            self.stop_failure,
            f"interrupted while {self.interruption}" if self.interruption else None,
        ]
        return [failure for failure in failures if failure]

    @property
    def what_holds(self) -> str:
        record = "switch not recorded" if self.record_failure else "switch recorded"
        parts = [record]
        if self.barrier:
            parts.append(self.barrier)
        if self.stop:
            stopped_unrecorded = self.stop is StopPart.STOPPED and self.record_failure
            parts.append(
                f"{self.stop}, {APPLY_WOULD_START_IT}" if stopped_unrecorded else self.stop
            )
        if self.lock_failure:
            parts.append(LOCK_NOT_TAKEN)
        if self.interruption:
            parts.insert(0, f"interrupted while {self.interruption}")
        return " · ".join(parts)


def _write(key: str, event: SwitchEvent, fact: str) -> None:
    write_row(Row(_GLYPH_OF_EVENT[event], key, event, fact))


def report_closing(key: str, closing: Closing) -> None:
    if closing.complete:
        _write(
            key, SwitchEvent.SWITCHED_OFF, f"{closing.barrier} · {StopPart.STOPPED} · volumes kept"
        )
        return
    _write(key, SwitchEvent.PARTIAL, closing.what_holds)
    cause = "; ".join(closing.causes)
    write_error(f"{key} is only partly off · {cause}", f"{COMMAND} {key}")


def report_already_off(key: str, since: str, barrier_repaired: bool) -> None:
    time = switches.describe_since(since)
    if barrier_repaired:
        _write(key, SwitchEvent.BARRIER_BACK, f"off since {time}")
    else:
        _write(key, SwitchEvent.ALREADY_OFF, f"since {time}")


def report_disabled(key: str) -> None:
    _write(key, SwitchEvent.DISABLED, "nothing of it runs")


def report_cannot_plan(key: str, planning: CannotPlan, recorded: bool) -> None:
    """The switch of an enabled app is recorded before planning, and a row says so."""
    if recorded:
        _write(key, SwitchEvent.PARTIAL, "switch recorded · nothing stopped")
    write_error(f"cannot plan, {planning.cause}", f"{COMMAND} {key}")


def report_interrupted_early(key: str, step: Interruption, cause: str = NOTHING_CHANGED) -> None:
    """A Ctrl-C before any marker of this run stands, or one that could not be read: no row."""
    write_error(f"interrupted while {step} · {cause}", f"{COMMAND} {key}")
