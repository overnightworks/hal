"""The live canary of the direct route (docs/agent-service.md, "Proofs").

    cd ~/srv/hal && python3 agent-service/live_canary.py

It runs only at V3, on the operator's word: it makes a paid call, which spends from hopin's app
budget. It checks that each container of the direct route runs once (C0), runs `agent-canary` once,
which posts a random value through the front with hopin's key and asks for it back (C1), waits a
short settle, and runs the retention census over those containers for that value (C2), the dump of
`litellm-db` among the sinks. The dump reads the whole store into this program's memory; no line of
it is ever printed. Nothing is recreated and no one signs in; a failed C0 or C1 ends the run, and a
new run uses a new value.

stdout holds verdict lines of a closed grammar and the last line (`canary and census held` or
`canary and census FAILED`, matching the exit code); stderr holds nothing. No exception text, no
output of a child and no diagnostic of a clean-up is ever printed; each failure maps to a closed
reason. Only the standard library is used.
"""

from __future__ import annotations

import http
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import TextIO

from api_canary import EXCEPTION_NAME, crashed_line, verdicts
from live_smoke import (
    PAID_TURN_SECONDS,
    SETTLE_SECONDS,
    TIMED_OUT,
    Cell,
    Stack,
    Verdict,
    remove_smoke_containers,
)
from retention_census import (
    DATABASE,
    ROUTE_SERVICES,
    Census,
    DatabaseLogin,
    Run,
    Sweep,
    Target,
    run_docker,
)

CANARY_SERVICE = "agent-canary"
INSPECT_NAME = "{{.Name}}"


class Reason(StrEnum):
    CONTAINERS_RUN = "the route's containers run"
    CONTAINER_MISSING = "a container is missing"
    ANSWER_HELD_MARKER = "the answer held the marker"
    TURN_TIMED_OUT = "the turn timed out"
    TURN_NOT_STARTED = "the turn could not start"
    ANSWER_LACKED_MARKER = "the answer lacked the marker"
    CONTAINER_LEFT = "a container was left"


class Held(StrEnum):
    CANARY_AND_CENSUS = "canary and census held"
    NOT = "canary and census FAILED"


C0, C1, C2, CLEANUP = "C0 route", "C1 canary", "C2 census", "cleanup"
NAME = EXCEPTION_NAME.pattern
SINK = r"[\w.-]+ (?:log|/[\w./-]*|dump(?: \w+)?)"
CANARY_FAILURES = (Reason.TURN_TIMED_OUT, Reason.TURN_NOT_STARTED, Reason.ANSWER_LACKED_MARKER)


def alternatives(reasons: tuple[Reason, ...] | type[StrEnum]) -> str:
    return "|".join(re.escape(reason) for reason in reasons)


# The only lines the command prints, as `<cell> <verdict>: <figure>`.
GRAMMAR = re.compile(
    "|".join(
        [
            f"{C0} held: {re.escape(Reason.CONTAINERS_RUN)}",
            f"{C0} FAILED: {re.escape(Reason.CONTAINER_MISSING)}",
            f"{C1} held: {re.escape(Reason.ANSWER_HELD_MARKER)}",
            rf"{C1} FAILED: (?:{alternatives(CANARY_FAILURES)}|answer \d+|crashed {NAME}"
            r"|\d+ unknown lines)",
            rf"{C2} held: \d+ sinks searched, the canary is in none",
            rf"{C2} FAILED: (?:found in {SINK}|\d+ sinks not examined|crashed {NAME})",
            f"{CLEANUP} FAILED: {re.escape(Reason.CONTAINER_LEFT)}",
            alternatives(Held),
        ]
    )
)


class GrammarBroken(Exception):
    """A line the closed grammar does not know; it is never printed."""


@dataclass
class Verdicts:
    """The one place a line leaves the program."""

    out: TextIO
    failed: bool = False

    def say(self, name: str, verdict: Verdict, figure: str) -> None:
        line = Cell(name, verdict, figure).line()
        if GRAMMAR.fullmatch(line) is None:
            raise GrammarBroken
        self.failed = self.failed or verdict is Verdict.FAILED
        self.out.write(f"{line}\n")
        self.out.flush()

    def held(self, name: str, figure: str) -> None:
        self.say(name, Verdict.HELD, figure)

    def refuse(self, name: str, figure: str) -> None:
        self.say(name, Verdict.FAILED, figure)

    def last(self) -> int:
        self.out.write(f"{Held.NOT if self.failed else Held.CANARY_AND_CENSUS}\n")
        self.out.flush()
        return 1 if self.failed else 0


# --- C0: the containers ------------------------------------------------------------------------


def route_targets(stack: Stack) -> list[Target] | None:
    """The census targets of the route's running containers, the database with the login compose
    resolves for it, or None when one is not running."""
    targets = []
    for service, has_python in ROUTE_SERVICES.items():
        listed = stack.compose("ps", "-q", service)
        containers = listed.stdout.split()
        if listed.returncode != 0 or len(containers) != 1:
            return None
        named = stack.run(["docker", "inspect", "--format", INSPECT_NAME, containers[0]])
        name = named.stdout.strip().removeprefix("/")
        if named.returncode != 0 or not name:
            return None
        resolved = stack.configuration["services"]
        login = DatabaseLogin.of(resolved[DATABASE]) if service == DATABASE else None
        targets.append(Target(name, has_python, login))
    return targets


def running_route(stack: Stack, say: Verdicts) -> list[Target] | None:
    """C0. The targets when each container of the route runs once."""
    try:
        targets = route_targets(stack)
    except OSError, subprocess.TimeoutExpired:
        targets = None
    if targets is None:
        say.refuse(C0, Reason.CONTAINER_MISSING)
        return None
    say.held(C0, Reason.CONTAINERS_RUN)
    return targets


# --- C1: the canary ----------------------------------------------------------------------------


def canary_reason(process: subprocess.CompletedProcess[str]) -> str | None:
    """Why the turn did not hold, in a closed figure, or None when it held. The child's output is
    parsed against the grammar of `api_canary.verdicts`; its stderr is never read."""
    if process.returncode == TIMED_OUT:
        return Reason.TURN_TIMED_OUT
    seen = verdicts(process.stdout, process.returncode)
    if "crashed" in seen:
        return f"crashed {seen['crashed']}"
    if seen["unknown"] != "0":
        return f"{seen['unknown']} unknown lines"
    if "answer" not in seen:
        return Reason.TURN_NOT_STARTED
    if seen["answer"] != str(int(http.HTTPStatus.OK)):
        return f"answer {seen['answer']}"
    held = seen.get("marker") == "yes" and process.returncode == 0
    return None if held else Reason.ANSWER_LACKED_MARKER


def one_canary(stack: Stack, marker: str) -> subprocess.CompletedProcess[str]:
    """The one-off's run with no standard input; a run the host gave up on reads as timed out."""
    try:
        return stack.compose(
            "run", "--rm", "-T", CANARY_SERVICE, "--marker", marker, timeout=PAID_TURN_SECONDS
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess([], TIMED_OUT, "", "")


def canary_turn(stack: Stack, say: Verdicts, marker: str) -> bool:
    """C1 and the clean-up of the turn's container. True when the answer held the marker."""
    try:
        try:
            reason = canary_reason(one_canary(stack, marker))
        finally:
            cleanup = remove_smoke_containers(stack, CANARY_SERVICE)
    except Exception as failure:
        say.refuse(C1, crashed_line(failure))
        return False
    if reason is None:
        say.held(C1, Reason.ANSWER_HELD_MARKER)
    else:
        say.refuse(C1, reason)
    if cleanup is not None:
        say.refuse(CLEANUP, Reason.CONTAINER_LEFT)
    return reason is None


# --- C2: the census ----------------------------------------------------------------------------


def census_cells(sweep: Sweep, say: Verdicts) -> None:
    hit_sinks = sorted({sink for sinks in sweep.hits.values() for sink in sinks})
    for sink in hit_sinks:
        say.refuse(C2, f"found in {sink}")
    if sweep.problems:
        say.refuse(C2, f"{len(sweep.problems)} sinks not examined")
    elif not hit_sinks:
        searched = sum(len(sinks) for sinks in sweep.inventory.values())
        say.held(C2, f"{searched} sinks searched, the canary is in none")


def run_census(targets: list[Target], marker: str, census_run: Run, say: Verdicts) -> None:
    try:
        sweep = Census(census_run, secrets.token_bytes(16)).sweep(targets, {"canary": marker})
        census_cells(sweep, say)
    except Exception as failure:
        say.refuse(C2, crashed_line(failure))


def live_canary(
    stack: Stack,
    say: Verdicts,
    census_run: Run = run_docker,
    pause: Callable[[float], None] = time.sleep,
) -> int:
    """The whole run; the exit code matches the last line."""
    targets = running_route(stack, say)
    marker = f"canary-{secrets.token_hex(16)}"
    if targets is not None and canary_turn(stack, say, marker):
        pause(SETTLE_SECONDS)
        run_census(targets, marker, census_run, say)
    return say.last()


def main(
    *,
    stack_of: Callable[[], Stack] = Stack,
    pause: Callable[[float], None] = time.sleep,
    census_run: Run = run_docker,
    out: TextIO = sys.stdout,
) -> int:
    say = Verdicts(out)
    try:
        return live_canary(stack_of(), say, census_run, pause)
    except KeyboardInterrupt:
        interrupted = True
    except Exception:  # no text may leave: the last line is the whole report
        interrupted = False
    say.failed = True
    say.last()
    return 130 if interrupted else 1


if __name__ == "__main__":
    sys.exit(main())
