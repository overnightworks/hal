"""`hal alarm`: the five-minute run over the services and the backup.

It runs the same two checks as the daily `hal check`, counts how many runs in a row each finding
has appeared in, and counts a finding only from the configured number of runs on. What it counts
joins the daily check's remembered set, so the mail, its words and the channels are the daily
check's, and neither run mails the other's news again. A counted finding leaves the set only after
it has been absent for the same number of runs in a row, so a finding that flaps is not mailed
as new and as done in turn. The news counts as told once the mail is delivered (or, with no mail
set up, once the popup was attempted); a failed popup beside a delivered mail is not retried.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from hal.output import Verdict, write_verdict
from hal.workstation import check
from hal.workstation.jobs import DEFAULT_ALARM_INTERVAL
from hal.workstation.layout import Layout
from hal.workstation.report import read_state_file, write_state_file

ALARM_AREAS = frozenset({"platform", "backup"})
STREAKS_FILE_NAME = "alarm-streaks.json"


@dataclass(frozen=True)
class AlarmSettings:
    interval: int = DEFAULT_ALARM_INTERVAL
    """Minutes between two runs."""
    runs: int = 2
    """Runs in a row that a finding must appear in before it counts."""


@dataclass(frozen=True)
class Counters:
    seen: dict[str, int]
    """Runs in a row that a finding appeared in, up to the configured number."""
    absent: dict[str, int]
    """Runs in a row that a remembered finding did not appear in."""


def _counters_file(layout: Layout) -> Path:
    return layout.hal_state_dir / STREAKS_FILE_NAME


def _run_counts(value: object) -> dict[str, int]:
    if not isinstance(value, dict) or not all(isinstance(identity, str) and type(count) is int for identity, count in value.items()):
        raise ValueError("alarm streaks invalid: expected identities with run counts")
    return value


def _read_counters(layout: Layout) -> Counters:
    text = read_state_file(layout.home, _counters_file(layout))
    if text is None:
        return Counters({}, {})
    stored = json.loads(text)
    if not isinstance(stored, dict) or set(stored) != {"seen", "absent"}:
        raise ValueError("alarm streaks invalid: expected identities with run counts")
    return Counters(_run_counts(stored["seen"]), _run_counts(stored["absent"]))


def _counted(observed: frozenset[str], counters: Counters, remembered: frozenset[str], runs: int) -> frozenset[str]:
    """What the run counts: a finding seen in `runs` runs in a row, or one already remembered, which must not wait for its count again; a remembered one that is gone stays until it was absent for `runs` runs."""
    appeared = (identity for identity in observed if counters.seen[identity] >= runs or identity in remembered)
    lingering = (identity for identity in counters.absent if counters.absent[identity] < runs)
    return frozenset(appeared) | frozenset(lingering)


def alarm(ctx: check.CheckContext, settings: AlarmSettings) -> None:
    layout = ctx.layout
    earlier = _read_counters(layout)
    previous = check.previous_identities(layout)
    results = check.run_areas(ctx, ALARM_AREAS)
    observed = check.remembered_identities(results, previous)
    remembered = previous or frozenset()
    remembered_here = frozenset(identity for identity in remembered if identity.partition("\t")[0] in ALARM_AREAS)
    counters = Counters(
        {identity: min(earlier.seen.get(identity, 0) + 1, settings.runs) for identity in observed},
        {identity: earlier.absent.get(identity, 0) + 1 for identity in remembered_here - observed},
    )
    write_state_file(layout.home, _counters_file(layout), json.dumps({"seen": counters.seen, "absent": counters.absent}, sort_keys=True) + "\n")
    current = _counted(observed, counters, remembered, settings.runs) | (remembered - remembered_here)
    outcome = check.deliver_news(ctx, current, previous)
    # Untold news stays unremembered, so the next run delivers it again.
    if outcome.told:
        check.remember(layout, current)
    write_verdict(Verdict(check.delivery_glyph(outcome.delivery), outcome.delivery, ()))
