"""The key files and the key step of the LiteLLM probes: the three scratch app key files compose
mounts into `litellm-keys`, and `hal apply`'s key step run through a Compose runner on the probe's
project, which records every argv, standard input, standard output and standard error the step's
one-off sees. Keys are scratch values the probe generates and never prints.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import (
    DATABASE,
    FAKE_PROVIDER,
    FRONT,
    GATEWAY,
    LITELLM,
    REPO,
    LitellmProbe,
    expect,
    shipped_config,
)
from scratch_secrets import write_new

from hal.stack import compose, core, litellm_keys
from hal.stack.litellm_keys import KeysPlan, KeysStep, NotRead

APPS = ("hopin", "presentator", "songmaker")
APP_KEYS_FOLDER = Path(".secrets/litellm/apps")
READ_SECONDS = 180


@dataclass
class Seen:
    """What the step's one-offs saw and said."""

    argv: list[list[str]] = field(default_factory=list)
    stdin: list[str] = field(default_factory=list)
    output: list[str] = field(default_factory=list)

    def text(self) -> str:
        return "\n".join((*(" ".join(argv) for argv in self.argv), *self.stdin, *self.output))


class KeyFiles(LitellmProbe):
    """litellm.py's stack without the service and the issuer, with the app key files and the key
    step against it."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.home = Path(self.environment["HOME"])
        self.written: list[str] = []  # every app key file value, S6's replaced one included
        self.file_keys = {app: self.write_app_key(app) for app in APPS}
        self.seen = Seen()
        self.engine = compose.Compose(run=self.step_runner, repository=REPO)
        self.budget_id = shipped_config()["litellm_settings"][litellm_keys.BUDGET_ID_SETTING]

    def services_to_start(self) -> tuple[str, ...]:
        return (GATEWAY, FAKE_PROVIDER, FRONT, DATABASE, LITELLM)

    def write_app_key(self, app: str, replace: bool = False) -> str:
        key = f"sk-{secrets.token_urlsafe(32)}"
        folder = self.home / APP_KEYS_FOLDER
        folder.mkdir(mode=0o700, exist_ok=True)
        path = folder / app
        if replace:
            path.unlink()
        write_new(path, (key + "\n").encode(), 0o644)
        self.app_keys.append(key)
        self.written.append(key)
        return key

    def step_runner(
        self, command: list[str], timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        """The step's compose call on the probe's project: its verb and arguments after the
        probe's own files, overlays and project name."""
        verb_and_arguments = command[6:]  # docker compose --project-directory D --file F
        argv = [*self.compose_command(guard=True), *verb_and_arguments]
        result = subprocess.run(  # noqa: S603 - argv is the step's own compose call behind the probe's prefix
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            env=self.environment,
            cwd=REPO,
            check=False,
            timeout=timeout,
        )
        if "run" in verb_and_arguments:
            self.seen.argv.append(argv)
            self.seen.stdin.append(stdin or "")
            self.seen.output += [result.stdout, result.stderr]
        return result

    def plan(self) -> KeysStep:
        """The step with its gate passed: the unit on and nothing of it starting in this run."""
        gates = {litellm_keys.UNIT: core.Gate.ON}
        return litellm_keys.plan_keys(self.engine, self.engine.states(), REPO, gates, (), ())

    def read_plan(self, cell: str) -> KeysPlan:
        """The plan once the keys can be read: LiteLLM answers 502 while it migrates."""
        deadline = time.monotonic() + READ_SECONDS
        while isinstance(plan := self.plan(), NotRead):
            expect(time.monotonic() < deadline, f"{cell}: keys not read ({plan.cause})")
            time.sleep(3)
        expect(isinstance(plan, KeysPlan), f"{cell}: the gate held the read ({plan})")
        return plan

    def run_step(self, plan: KeysStep):
        return litellm_keys.run_keys(plan, self.engine)
