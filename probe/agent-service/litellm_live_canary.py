"""Probe of the live canary: `live_canary()` of agent-service/live_canary.py
against the fake-only stack of litellm_retention.py, six runs: dirty, clean, a wrong answer, a
missing container, a gateway that is not the front and a configuration file the service has not
loaded. Nothing live and nothing paid: the stack
refuses to start unless `internet` is internal and holds only the two fake hosts, the tokens are the
stand-in issuer's and the sign-in is never reached (`main` is not called).

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_live_canary.py --scratch DIR

The wrapper runs through a `Stack` built from `compose_command(guard=True)` and the guard's own
environment, so the guard and the execution resolve the same inputs; before the first call the
stack's project is the probe's and every container name starts with it. Over all six outputs,
stdout and stderr, every line fits the grammar of the grammar table and none holds a canary, a
token, a JWT-shaped or a UUID-shaped string. Exit 0: every cell held.
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "agent-service"))

from egress import PROJECT  # noqa: E402
from issuer import ISSUER_ORIGIN  # noqa: E402
from litellm import (  # noqa: E402
    FRONT,
    LISTENING,
    LITELLM,
    SERVICE,
    expect,
    run_scratch_probe,
)
from litellm_retention import RetentionProbe  # noqa: E402
from live_canary import Verdicts, live_canary, route_targets  # noqa: E402
from live_smoke import Stack  # noqa: E402
from refusals import API_GROUP  # noqa: E402
from retention_census import run_docker  # noqa: E402
from smoke import Tokens  # noqa: E402

# The names and the token builder the service canary needs stand here, not in the probe base, which
# no longer calls through the service; frozen until HAL-2.8 re-points the canary.
CANARY, DEFAULT_APP = "agent-canary", "songmaker"

# The grammar of the grammar table, written from it and not from the program: a (cell, verdict)
# and the figures that may follow.
NAME = r"[A-Za-z]{1,60}"
SINK = r"[\w.-]+ (?:log|/[\w./-]*|dump(?: \w+)?)"
GRAMMAR = {
    ("C0 route", "held"): ["the route's containers run"],
    ("C0 route", "FAILED"): ["a container is missing"],
    ("C1 canary", "held"): ["the answer held the marker"],
    ("C1 canary", "FAILED"): [
        "the turn timed out",
        "the turn could not start",
        r"answer \d+",
        "the answer lacked the marker",
        f"crashed {NAME}",
        r"\d+ unknown lines",
    ],
    ("C2 census", "held"): [r"\d+ sinks searched, the canary is in none"],
    ("C2 census", "FAILED"): [f"found in {SINK}", r"\d+ sinks not examined", f"crashed {NAME}"],
    ("cleanup", "FAILED"): ["a container was left"],
}
LAST_LINES = {"canary and census held", "canary and census FAILED"}
JWT_SHAPE = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
UUID_SHAPE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def fits_grammar(line: str) -> bool:
    if line in LAST_LINES:
        return True
    for (cell, verdict), figures in GRAMMAR.items():
        head = f"{cell} {verdict}: "
        if line.startswith(head):
            return any(re.fullmatch(figure, line.removeprefix(head)) for figure in figures)
    return False


@dataclass(frozen=True)
class SteeredStack(Stack):
    """The live stack's commands; before the canary's container starts, the fake provider is told
    the value of the run it will see, which the wrapper chooses at random."""

    steer: Callable[[str], None] | None = None

    def compose(self, *arguments: str, stdin: str | None = None, timeout: int = 300):
        if CANARY in arguments and self.steer is not None:
            self.steer(arguments[arguments.index("--marker") + 1])
        return super().compose(*arguments, stdin=stdin, timeout=timeout)


class LiveCanaryProbe(RetentionProbe):
    """The retention probe's stack, driven through the wrapper instead of the census cells."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.printed: list[str] = []
        self.forbidden: list[str] = []

    def canary_input(self, app: str) -> str:
        """The two tokens of a person of the API group alone, as the canary reads them."""
        claims = {
            "sub": self.identity["sub"], "preferred_username": self.identity["username"],
            "email": self.identity["email"], "azp": app, "groups": [f"/apps/{app}", API_GROUP],
        }  # fmt: skip
        issuer = f"{ISSUER_ORIGIN}/realms/hallucinai"
        person = self.issuer.token(issuer, claims)
        workload = self.issuer.token(
            issuer,
            {"sub": "workload", "azp": app, "client_id": app,
             "realm_access": {"roles": ["agent-workload"]}},
        )  # fmt: skip
        return f"{person}\n{workload}\n"

    def drive(self) -> None:
        for service in (SERVICE, LITELLM):
            self.wait_until(service, LISTENING)
        self.steer()
        self.expect_the_probe_project()
        self.cell_dirty()
        self.recreate_route()
        self.cell_clean()
        self.cell_wrong_answer()
        self.cell_missing_container()
        self.cell_wrong_gateway()
        self.cell_file_not_loaded()
        self.cell_output()

    def stack(self, answered: Callable[[str], dict] | None = None) -> SteeredStack:
        def steer(marker: str) -> None:
            self.forbidden.append(marker)
            answer = answered(marker) if answered else {"marker": marker}
            self.steer(**answer, request_canary=marker)

        return SteeredStack(
            compose_prefix=tuple(self.compose_command(guard=True)),
            environment=self.environment, directory=REPO, steer=steer,
        )  # fmt: skip

    def expect_the_probe_project(self) -> None:
        stack = self.stack()
        expect(stack.project == PROJECT, f"the stack names the project {stack.project}")
        targets = route_targets(stack)
        expect(targets is not None, "a container of the route is not running")
        names = [target.name for target in targets]
        expect(all(name.startswith(f"{PROJECT}-") for name in names), f"container names {names}")

    def run_wrapper(self, answered: Callable[[str], dict] | None = None) -> tuple[int, list[str]]:
        """One run of `live_canary()` on stand-in tokens: its exit code and stdout lines."""
        person, workload = self.canary_input(DEFAULT_APP).split()
        self.forbidden += [person, workload]
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            code = live_canary(
                self.stack(answered), Verdicts(out), lambda: Tokens(person, workload), run_docker
            )
        expect(err.getvalue() == "", "the wrapper wrote to standard error")
        lines = out.getvalue().splitlines()
        self.printed += lines
        expect(lines[-1:] and lines[-1] in LAST_LINES, f"no last line: {lines}")
        expect((code == 0) == (lines[-1] == "canary and census held"), f"exit {code}: {lines}")
        return code, lines

    def cell_dirty(self) -> None:
        self.overlays.append(self.controls)
        for service in (LITELLM, FRONT):
            self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
        self.wait_until(LITELLM, LISTENING)
        self.wait_for_front()
        code, lines = self.run_wrapper()
        self.overlays.remove(self.controls)
        named = f"C2 census FAILED: found in {self.container_name(LITELLM)} log"
        expect(code == 1 and named in lines, f"dirty: {code} {lines}")
        self.hold("dirty", "with LiteLLM at DEBUG the wrapper exits 1 and names its log")

    def cell_clean(self) -> None:
        before = len(self.provider_requests())
        code, lines = self.run_wrapper()
        expect(code == 0 and len(lines) == 4, f"clean: {code} {lines}")
        expect(lines[2].startswith("C2 census held: "), f"clean: {lines}")
        reached = sum(r["request_canary_hits"] for r in self.provider_requests()[before:])
        expect(reached >= 1, "clean: the canary never reached the fake")
        self.hold("clean", f"exit 0, {lines[2].removeprefix('C2 census held: ')}")

    def cell_wrong_answer(self) -> None:
        code, lines = self.run_wrapper(lambda marker: {"marker": f"other-{marker[::-1]}"})
        expect(code == 1, f"wrong answer: {code} {lines}")
        expect("C1 canary FAILED: the answer lacked the marker" in lines, f"wrong answer: {lines}")
        expect(not any(line.startswith("C2") for line in lines), f"a census ran: {lines}")
        self.hold("wrong answer", "marker no: exit 1 and no census line")

    def cell_missing_container(self) -> None:
        before = len(self.provider_requests())
        self.compose("stop", FRONT)
        try:
            code, lines = self.run_wrapper()
        finally:
            self.compose("up", "--detach", "--no-deps", FRONT)
            self.wait_for_front()
        expect(code == 1 and lines[0] == "C0 gateway FAILED: a container is missing", f"{lines}")
        expect(len(self.provider_requests()) == before, "missing container: the fake was reached")
        self.hold("missing container", "the front stopped: exit 1 at C0 and no request to the fake")

    def cell_wrong_gateway(self) -> None:
        before = len(self.provider_requests())
        shipped = self.configuration.read_text(encoding="utf-8")
        self.configuration.write_text(
            shipped.replace(f"{FRONT}:4000", f"{LITELLM}:4000"), encoding="utf-8"
        )
        try:
            code, lines = self.run_wrapper()
        finally:
            self.configuration.write_text(shipped, encoding="utf-8")
        expect(code == 1, f"wrong gateway: {code} {lines}")
        expect(lines[0] == "C0 gateway FAILED: the service names another gateway", f"{lines}")
        expect(len(self.provider_requests()) == before, "wrong gateway: the fake was reached")
        self.hold("wrong gateway", "[api] naming another host: exit 1 at C0 and no request")

    def cell_file_not_loaded(self) -> None:
        before = len(self.provider_requests())
        self.configuration.write_text(
            self.configuration.read_text(encoding="utf-8"), encoding="utf-8"
        )
        code, lines = self.run_wrapper()
        expect(code == 1, f"file not loaded: {code} {lines}")
        expect(lines[0] == "C0 gateway FAILED: the service has not loaded this file", f"{lines}")
        expect(len(self.provider_requests()) == before, "file not loaded: the fake was reached")
        self.hold(
            "file not loaded",
            "the file rewritten with the same content: exit 1 at C0 and no request",
        )

    def cell_output(self) -> None:
        stray = [line for line in self.printed if not fits_grammar(line)]
        expect(not stray, f"lines outside the grammar: {len(stray)}")
        printed = "\n".join(self.printed)
        leaked = [value for value in self.forbidden if value in printed]
        expect(
            not leaked and not any(shape.search(printed) for shape in (JWT_SHAPE, UUID_SHAPE)),
            "a secret shape was printed",
        )
        self.hold("output", f"{len(self.printed)} lines over six runs, all in the grammar, "
                  "no canary, token, JWT or UUID")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LiveCanaryProbe)


if __name__ == "__main__":
    sys.exit(main())
