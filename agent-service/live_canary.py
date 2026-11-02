"""The live canary of the API route (docs/agent-service.md, "Proofs").

    cd ~/srv/hal && python3 agent-service/live_canary.py

It runs `api_canary.py` as the person you sign in as, then the retention census over the route's
containers, and prints only verdicts. The person must be in the API group and outside the
subscription group: any other route fails C1 and the census does not run. The order is fixed: the
route's containers, the service's gateway (it must be the front), the sign-in, the canary, a short
settle, the census. Nothing is recreated; a failed canary ends the run, and a new run uses a new
canary. It makes a paid call, so it runs only when the operator says so.

stdout holds verdict lines of a closed grammar and the last line (`canary and census held` or
`canary and census FAILED`, matching the exit code). stderr holds the sign-in prompt and nothing
else: you open its link yourself, no browser is started. No exception text, no output of a child and
no diagnostic of a clean-up is ever printed; each failure maps to a closed reason. Only the
standard library is used.
"""

from __future__ import annotations

import http
import re
import secrets
import subprocess
import sys
import time
import tomllib
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import TextIO
from urllib.parse import urlsplit

from api_canary import CLOSED_WORD, EXCEPTION_NAME, crashed_line, verdicts
from device_sign_in import SignInFailed, sign_in
from live_smoke import (
    CLIENT_SECRET_FILE,
    SETTLE_SECONDS,
    TIMED_OUT,
    Cell,
    LiveSmokeFailed,
    Stack,
    Verdict,
    paid_turn,
    read_secret,
)
from retention_census import (
    AGENT_SERVICE,
    FRONT,
    ROUTE_SERVICES,
    Census,
    Run,
    Sweep,
    Target,
    run_docker,
)
from smoke import Tokens

CANARY_SERVICE = "agent-canary"
MOUNTED_SERVICE_TOML = "/etc/agent-service/service.toml"
API_ROUTE = "api"
INSPECT_NAME = "{{.Name}}"
STARTED_AT = "{{.State.StartedAt}}"
MODIFIED_SECONDS = "%.9Y"


class Reason(StrEnum):
    FRONT_IS_THE_GATEWAY = "the service's gateway is the front"
    CONTAINER_MISSING = "a container is missing"
    CONFIGURATION_UNREADABLE = "the configuration could not be read"
    NO_API_TABLE = "the service has no api table"
    OTHER_GATEWAY = "the service names another gateway"
    FILE_NOT_LOADED = "the service has not loaded this file"
    ANSWER_HELD_MARKER = "route api, the answer held the marker"
    SIGN_IN_FAILED = "the sign-in failed"
    TURN_TIMED_OUT = "the turn timed out"
    TURN_NOT_STARTED = "the turn could not start"
    ANSWER_LACKED_MARKER = "the answer lacked the marker"
    CONTAINER_LEFT = "a container was left"


class Held(StrEnum):
    CANARY_AND_CENSUS = "canary and census held"
    NOT = "canary and census FAILED"


C0, C1, C2, CLEANUP = "C0 gateway", "C1 canary", "C2 census", "cleanup"
WORD, NAME = CLOSED_WORD.pattern, EXCEPTION_NAME.pattern
SINK = r"[\w.-]+ (?:log|/[\w./-]*)"
GATEWAY_FAILURES = (
    Reason.CONTAINER_MISSING, Reason.CONFIGURATION_UNREADABLE, Reason.NO_API_TABLE,
    Reason.OTHER_GATEWAY, Reason.FILE_NOT_LOADED,
)  # fmt: skip
CANARY_FAILURES = (
    Reason.SIGN_IN_FAILED, Reason.TURN_TIMED_OUT, Reason.TURN_NOT_STARTED,
    Reason.ANSWER_LACKED_MARKER,
)  # fmt: skip


def alternatives(reasons: tuple[Reason, ...] | type[StrEnum]) -> str:
    return "|".join(re.escape(reason) for reason in reasons)


# The only lines the command prints, as `<cell> <verdict>: <figure>`.
GRAMMAR = re.compile(
    "|".join(
        [
            f"{C0} held: {re.escape(Reason.FRONT_IS_THE_GATEWAY)}",
            f"{C0} FAILED: (?:{alternatives(GATEWAY_FAILURES)})",
            f"{C1} held: {re.escape(Reason.ANSWER_HELD_MARKER)}",
            f"{C1} FAILED: (?:{alternatives(CANARY_FAILURES)}"
            rf"|answer \d+|route {WORD}|code {WORD}|crashed {NAME}|\d+ unknown lines)",
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


# --- C0: the containers and the gateway --------------------------------------------------------


def route_targets(stack: Stack) -> list[Target] | None:
    """The census targets of the route's running containers, or None when one is not running."""
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
        targets.append(Target(name, has_python))
    return targets


def file_is_newer_than_the_service(stack: Stack) -> bool:
    """Whether the mounted file changed after the service container started, so the running
    service cannot have loaded it. ValueError when either time cannot be read."""
    container = stack.compose("ps", "-q", AGENT_SERVICE).stdout.strip()
    started = stack.run(["docker", "inspect", "--format", STARTED_AT, container])
    modified = stack.compose(
        "exec", "-T", AGENT_SERVICE, "stat", "-c", MODIFIED_SECONDS, MOUNTED_SERVICE_TOML
    )
    if started.returncode != 0 or modified.returncode != 0:
        raise ValueError("a time could not be read")
    return float(modified.stdout) > datetime.fromisoformat(started.stdout.strip()).timestamp()


def gateway_reason(stack: Stack) -> Reason | None:
    """Why the running service does not name the front as its gateway, or None when it does."""
    try:
        read = stack.compose("exec", "-T", AGENT_SERVICE, "cat", MOUNTED_SERVICE_TOML)
        if read.returncode != 0:
            return Reason.CONFIGURATION_UNREADABLE
        api = tomllib.loads(read.stdout).get("api")
        if not isinstance(api, dict):
            return Reason.NO_API_TABLE
        url = api.get("completion_url")
        host = urlsplit(url).hostname if isinstance(url, str) else None
        if host != FRONT:
            return Reason.OTHER_GATEWAY
        return Reason.FILE_NOT_LOADED if file_is_newer_than_the_service(stack) else None
    except ValueError:
        return Reason.CONFIGURATION_UNREADABLE


def bind_to_front(stack: Stack, say: Verdicts) -> list[Target] | None:
    """C0. The targets when the route's containers run and the service names the front."""
    try:
        targets = route_targets(stack)
        reason = Reason.CONTAINER_MISSING if targets is None else gateway_reason(stack)
    except OSError, subprocess.TimeoutExpired:
        targets, reason = None, Reason.CONTAINER_MISSING
    if reason is not None:
        say.refuse(C0, reason)
        return None
    say.held(C0, Reason.FRONT_IS_THE_GATEWAY)
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
    if seen.get("route") != API_ROUTE:
        return f"route {seen.get('route', 'none')}"
    if "code" in seen:
        return f"code {seen['code']}"
    held = seen.get("marker") == "yes" and process.returncode == 0
    return None if held else Reason.ANSWER_LACKED_MARKER


def canary_turn(
    stack: Stack, say: Verdicts, obtain_tokens: Callable[[], Tokens], marker: str
) -> bool:
    """C1 and the clean-up of the turn's container. True when the answer held the marker."""
    try:
        tokens = obtain_tokens()
    except LiveSmokeFailed, SignInFailed:
        say.refuse(C1, Reason.SIGN_IN_FAILED)
        return False
    except Exception as failure:
        say.refuse(C1, crashed_line(failure))
        return False
    try:
        turn = paid_turn(
            stack, tokens, service=CANARY_SERVICE,
            smoke_arguments=("--marker", marker, "--request-marker", marker),
        )  # fmt: skip
    except Exception as failure:
        say.refuse(C1, crashed_line(failure))
        return False
    reason = canary_reason(turn.process)
    if reason is None:
        say.held(C1, Reason.ANSWER_HELD_MARKER)
    else:
        say.refuse(C1, reason)
    if turn.cleanup is not None:
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
    obtain_tokens: Callable[[], Tokens],
    census_run: Run = run_docker,
    pause: Callable[[float], None] = time.sleep,
) -> int:
    """The whole run; the exit code matches the last line."""
    targets = bind_to_front(stack, say)
    marker = f"canary-{secrets.token_hex(16)}"
    if targets is not None and canary_turn(stack, say, obtain_tokens, marker):
        pause(SETTLE_SECONDS)
        run_census(targets, marker, census_run, say)
    return say.last()


def main(
    *,
    stack_of: Callable[[], Stack] = Stack,
    read_client_secret: Callable[[], str] = lambda: read_secret(
        CLIENT_SECRET_FILE, "the client secret"
    ),
    urlopen=urllib.request.urlopen,
    pause: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
    census_run: Run = run_docker,
    out: TextIO = sys.stdout,
) -> int:
    def obtain_tokens() -> Tokens:
        # the person opens the printed link by hand: no opener may write outside this boundary
        return sign_in(read_client_secret(), urlopen, pause, lambda _link: None, clock)

    say = Verdicts(out)
    try:
        return live_canary(stack_of(), say, obtain_tokens, census_run, pause)
    except KeyboardInterrupt:
        interrupted = True
    except Exception:  # no text may leave: the last line is the whole report
        interrupted = False
    say.failed = True
    say.last()
    return 130 if interrupted else 1


if __name__ == "__main__":
    sys.exit(main())
