"""The only place that touches the host: two read-only commands, fixed argv, no shell, and the
command line of a process."""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from hal.exposure.exposure import UnreadableOutputError


@dataclass(frozen=True)
class HostCommand:
    """A fixed argv and the name its failures are reported under."""

    name: str
    argv: tuple[str, ...]

    def with_arguments(self, *arguments: str) -> HostCommand:
        return HostCommand(self.name, (*self.argv, *arguments))


DOCKER_CONTAINER_IDS = HostCommand("docker ps", ("docker", "ps", "--all", "--quiet", "--no-trunc"))
DOCKER_INSPECT = HostCommand("docker inspect", ("docker", "inspect"))
SOCKET_LISTENERS = HostCommand("ss", ("ss", "-H", "-ltnupe"))
HOST_COMMAND_TIMEOUT_SECONDS = 30


class HostCommandError(RuntimeError):
    """A host command could not run, so the check cannot vouch for anything."""


def docker_inspect_json() -> str:
    container_ids = _run(DOCKER_CONTAINER_IDS).split()
    if not container_ids:
        return "[]"
    inspect_json = _run(DOCKER_INSPECT.with_arguments(*container_ids))
    _require_every_container_inspected(inspect_json, len(container_ids))
    return inspect_json


def socket_listeners() -> str:
    return _run(SOCKET_LISTENERS)


def command_line(pid: int) -> tuple[str, ...] | None:
    """The arguments the process was started with, or None when they cannot be read (another
    user's process, one that has ended)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    arguments = raw.decode(errors="replace").split("\0")
    return tuple(arguments[:-1]) if arguments[-1] == "" else tuple(arguments)


def _require_every_container_inspected(inspect_json: str, listed: int) -> None:
    """A short answer would make the check vouch for containers it never saw."""
    try:
        answer = json.loads(inspect_json)
    except json.JSONDecodeError:
        return  # the parser names what is wrong with it
    if isinstance(answer, list) and len(answer) < listed:
        raise UnreadableOutputError(
            f"docker inspect answered {len(answer)} containers, docker ps listed {listed}"
        )


def _run(command: HostCommand) -> str:
    try:
        completed = subprocess.run(  # noqa: S603 - argv comes from the host check's own commands and no shell runs
            command.argv,
            capture_output=True,
            text=True,
            check=True,
            timeout=HOST_COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise HostCommandError(
            f"{command.name} did not answer within {HOST_COMMAND_TIMEOUT_SECONDS:g} s"
        ) from error
    except FileNotFoundError as error:
        raise HostCommandError(f"{command.argv[0]} is not installed") from error
    except subprocess.CalledProcessError as error:
        raise HostCommandError(
            f"{command.name} failed with exit {error.returncode}: {error.stderr.strip()}"
        ) from error
    return completed.stdout
