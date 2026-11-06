"""The scripted docker the live smoke and live signer tests share."""

import io
import json
import subprocess
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from live_smoke import Secrets, Stack
from smoke import Tokens, served_line

TOKENS = Tokens(person="person-token-0123456789", workload="workload-token-9876543210")
KNOWN = Secrets(TOKENS, login_token="login-token-abcdef", client_secret="client-secret-fedcba")
GATEWAY = "172.31.252.10"
LITELLM_GATEWAY = "172.31.239.10"
SERVICE_NETWORKS = {
    "agent-songmaker": "hal_agent_songmaker",
    "agent-presentator": "hal_agent_presentator",
    "agent-hopin": "hal_agent_hopin",
    "mcp": "edge_mcp",
    "egress": "edge_egress",
}
SECRET_FILES = {
    "agent_service_signing_key": Path.home() / ".secrets/agent-service/signing/private.pem",
    "step_ca_root_certificate": Path.home() / ".secrets/step-ca/root_ca.crt",
}


SERVED_LINE = served_line("anthropic/opus", "cli")
PAID_OUTPUT = (
    f"event: run_started\n{SERVED_LINE}\nevent: assistant_text\nok\nevent: succeeded\nok\n"
)


def resolved_configuration(image: str = "i:1") -> dict:
    """What `docker compose config --format json` gives for the service."""
    return {
        "name": "edge",
        "x-egress-address": GATEWAY,
        "x-litellm-egress-address": LITELLM_GATEWAY,
        "services": {
            "agent-service": {"image": image, "networks": dict.fromkeys(SERVICE_NETWORKS)}
        },
        "networks": {key: {"name": name} for key, name in SERVICE_NETWORKS.items()},
        "secrets": {name: {"file": str(path)} for name, path in SECRET_FILES.items()},
    }


def completed(stdout: str = "", returncode: int = 0, stderr: str = ""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeProcess:
    """The cancelling smoke: prints its lines, then ends, hangs until killed, or is interrupted."""

    def __init__(
        self, lines: list[str], returncode: int = 0, hangs: bool = False, interrupted: bool = False
    ) -> None:
        self.lines, self.returncode = lines, returncode
        self.hangs, self.interrupted = hangs, interrupted
        self.stdin = io.StringIO()
        self.exited = threading.Event()
        self.terminated = self.killed = False

    @property
    def stdout(self):
        yield from self.lines
        if self.interrupted:
            raise KeyboardInterrupt
        if self.hangs:
            self.exited.wait(10)

    def poll(self):
        return self.returncode if self.exited.is_set() else None

    def wait(self, timeout=None) -> int:
        self.exited.set()
        return -9 if self.killed else self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.exited.set()

    def kill(self) -> None:
        self.killed = True
        self.exited.set()


@dataclass(frozen=True)
class FakeStack(Stack):
    """A docker that answers by what is asked; `answer` gets the command after the prefix."""

    answer: Callable[[list[str]], subprocess.CompletedProcess] = lambda _: completed()
    cancelling: FakeProcess | None = None
    standin: object | None = None
    asked: list[list[str]] = field(default_factory=list)

    def run(self, command, stdin=None, timeout=300):
        self.asked.append([*command])
        return self.answer(list(command))

    def start(self, command):
        self.asked.append([*command])
        return self.standin if command[:2] == ["docker", "run"] else self.cancelling


def healthy_service(command: list[str]) -> subprocess.CompletedProcess:
    text = " ".join(command)
    if "config" in command:
        return completed(json.dumps(resolved_configuration()))
    if "cat /sys/fs/cgroup/memory" in text:
        return completed("1234\n")
    if "grep -c" in text:
        return completed("0\n")
    if "ps" in command:
        return completed("container-id\n")
    if "logs" in command:
        return completed("Uvicorn running on http://0.0.0.0:8080\n")
    if "agent-smoke" in command:
        return completed(PAID_OUTPUT)
    if "network" in command and "ls" in command:
        return completed("network-id\n")
    return completed("")
