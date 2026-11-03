"""Probe of the live canary: `live_canary()` of agent-service/live_canary.py against the fake-only
stack of litellm_retention.py, with hopin's key made by `hal apply`'s key step from a scratch key
file (K0). Its runs: dirty, clean, a wrong answer, a missing container and hopin's key deleted
(R-key), then where the key went (K-rest), every printed line (output), and the compose hashes of
main against the checkout (R3). Nothing live and nothing paid: the stack refuses to start unless
`internet` is internal and holds only the fakes, and `main` is never called.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_live_canary.py --scratch DIR

The wrapper runs through a `Stack` built from `compose_command(guard=True)` and the guard's own
environment, so the guard and the execution resolve the same inputs; before the first call the
stack's project is the probe's and every container name starts with it. The stack records every
argv and standard input it runs, which K-rest searches with the key step's own. Over all outputs
every line fits the grammar of the grammar table and none holds a canary, a key, a JWT-shaped or a
UUID-shaped string. Exit 0: every cell held.
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "agent-service"))

from egress import PROJECT  # noqa: E402
from litellm import DATABASE, FRONT, LISTENING, LITELLM, expect, hashed, run_scratch_probe  # noqa: E402
from litellm_retention import RetentionProbe  # noqa: E402
from live_canary import Verdicts, live_canary, route_targets  # noqa: E402
from live_smoke import Stack  # noqa: E402
from retention_census import DUMP, Census, contains, run_docker  # noqa: E402

CANARY = "agent-canary"

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
    """The live stack's commands, each argv and standard input recorded; before the canary's
    container starts, the fake provider is told the value of the run it will see, which the
    wrapper chooses at random."""

    steer: Callable[[str], None] | None = None
    ran: list[str] = field(default_factory=list)

    def run(self, command, stdin=None, timeout=300):
        self.ran.extend((" ".join(command), stdin or ""))
        return super().run(command, stdin, timeout)

    def compose(self, *arguments: str, stdin: str | None = None, timeout: int = 300):
        if CANARY in arguments and self.steer is not None:
            self.steer(arguments[arguments.index("--marker") + 1])
        return super().compose(*arguments, stdin=stdin, timeout=timeout)


class LiveCanaryProbe(RetentionProbe):
    """The retention probe's stack, driven through the wrapper instead of the census cells."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.scratch = scratch
        self.printed: list[str] = []
        self.forbidden: list[str] = []
        self.ran: list[str] = []

    def drive(self) -> None:
        """K0, then the wrapper's runs in the order of the matrix; the first failure ends it."""
        self.wait_until_listening()
        for step in (
            self.cell_k0, self.steer, self.expect_the_probe_project, self.cell_dirty,
            self.recreate_route, self.cell_clean, self.cell_wrong_answer,
            self.cell_missing_container, self.cell_r_key, self.cell_k_rest, self.cell_output,
            self.cell_r3,
        ):  # fmt: skip
            step()

    def stack(self, answered: Callable[[str], dict] | None = None) -> SteeredStack:
        def steer(marker: str) -> None:
            self.forbidden.append(marker)
            answer = answered(marker) if answered else {"marker": marker}
            self.steer(**answer, request_canary=marker)

        return SteeredStack(
            compose_prefix=tuple(self.compose_command(guard=True)),
            environment=self.environment, directory=REPO, steer=steer, ran=self.ran,
        )  # fmt: skip

    def expect_the_probe_project(self) -> None:
        stack = self.stack()
        expect(stack.project == PROJECT, f"the stack names the project {stack.project}")
        targets = route_targets(stack)
        expect(targets is not None, "a container of the route is not running")
        names = [target.name for target in targets]
        expect(all(name.startswith(f"{PROJECT}-") for name in names), f"container names {names}")

    def run_wrapper(self, answered: Callable[[str], dict] | None = None) -> tuple[int, list[str]]:
        """One run of `live_canary()`: its exit code and stdout lines."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stderr(err):
            code = live_canary(self.stack(answered), Verdicts(out), run_docker)
        expect(err.getvalue() == "", "the wrapper wrote to standard error")
        lines = out.getvalue().splitlines()
        self.printed += lines
        expect(lines[-1:] and lines[-1] in LAST_LINES, f"no last line: {lines}")
        expect((code == 0) == (lines[-1] == "canary and census held"), f"exit {code}: {lines}")
        return code, lines

    def hopin_spend(self) -> float:
        (row,) = self.admin("POST", "/v2/key/info", {"keys": [hashed(self.key)]})["info"]
        return row["spend"]

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
        before, spent = len(self.provider_requests()), self.hopin_spend()
        code, lines = self.run_wrapper()
        expect(code == 0 and len(lines) == 4, f"clean: {code} {lines}")
        targets = route_targets(self.stack())
        searched = Census(run_docker, b"probe").sweep(targets, {"none": "-"}).inventory
        dumped = DUMP in searched[self.container_name(DATABASE)]
        count = sum(len(sinks) for sinks in searched.values())
        expect(dumped and lines[2] == f"C2 census held: {count} sinks searched, the canary is in "
               "none", f"clean: {lines}")  # fmt: skip
        reached = sum(r["request_canary_hits"] for r in self.provider_requests()[before:])
        expect(reached >= 1, "clean: the canary never reached the fake")
        self.wait_for("clean", "hopin's spend", lambda: self.hopin_spend() > spent)
        self.hold("clean", f"exit 0, {count} sinks with the dump, F reached, hopin's spend rose")

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
        expect(code == 1 and lines[0] == "C0 route FAILED: a container is missing", f"{lines}")
        expect(len(self.provider_requests()) == before, "missing container: the fake was reached")
        self.hold("missing container", "the front stopped: exit 1 at C0 and no request to the fake")

    def cell_r_key(self) -> None:
        before = len(self.provider_requests())
        self.admin("POST", "/key/delete", {"keys": [hashed(self.key)]})
        code, deleted = self.run_wrapper()
        expect(
            code == 1 and re.fullmatch(r"C1 canary FAILED: answer \d+", deleted[1]), f"{deleted}"
        )
        expect(len(self.provider_requests()) == before, "R-key: the fake was reached")
        self.run_step(self.read_plan("R-key"))
        code, lines = self.run_wrapper()
        expect(code == 0, f"R-key: after the step {lines}")
        self.hold("R-key", f"deleted: `{deleted[1]}`, exit 1 and F 0; remade by the step: "
                  "exit 0")  # fmt: skip

    def cell_k_rest(self) -> None:
        tokens = {"hopin's key": self.key}
        config = self.compose("config", CANARY).stdout
        places = {
            "the stack's argv and input": "\n".join(self.ran), "the step": self.seen.text(),
            "the canary's compose config": config, "the printed lines": "\n".join(self.printed),
        }  # fmt: skip
        holding = [place for place, text in places.items() if contains(text.encode(), tokens)]
        expect(not holding, f"K-rest: the key is in {holding}")
        found = self.sweep(tokens).found
        expect(not found, f"K-rest: the census found the key in {found}")
        key_file = (self.home / ".secrets/litellm/apps/hopin").read_bytes()
        expect(contains(key_file, tokens) == set(tokens), "K-rest: the control misses the key")
        self.hold("K-rest", f"hopin's key in none of {len(places)} places and no census sink; "
                  "the same search finds it in the scratch key file")  # fmt: skip

    def cell_output(self) -> None:
        stray = [line for line in self.printed if not fits_grammar(line)]
        expect(not stray, f"lines outside the grammar: {len(stray)}")
        printed = "\n".join(self.printed)
        leaked = [value for value in [*self.forbidden, *self.app_keys] if value in printed]
        expect(
            not leaked and not any(shape.search(printed) for shape in (JWT_SHAPE, UUID_SHAPE)),
            "a secret shape was printed",
        )
        self.hold("output", f"{len(self.printed)} lines, all in the grammar, no canary, key, "
                  "JWT or UUID")  # fmt: skip

    def cell_r3(self) -> None:
        main = self.scratch / "compose.main.yaml"
        main.write_text(self.run(["git", "show", "origin/main:compose.yaml"]).stdout)
        hashes = [self.compose_hashes(file) for file in (main, REPO / "compose.yaml")]
        changed = {service for service in hashes[0] if hashes[0][service] != hashes[1].get(service)}
        expect(changed == {CANARY} and set(hashes[0]) == set(hashes[1]), f"R3: {changed}")
        self.hold("R3", f"of {len(hashes[1])} services only {CANARY}'s compose hash changed")

    def compose_hashes(self, file: Path) -> dict[str, str]:
        listed = self.run([
            "docker", "compose", "--project-directory", str(REPO), "--file", str(file),
            "--profile", "*", "config", "--hash", "*",
        ]).stdout  # fmt: skip
        return {name: digest for name, digest in map(str.split, listed.splitlines())}


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LiveCanaryProbe)


if __name__ == "__main__":
    sys.exit(main())
