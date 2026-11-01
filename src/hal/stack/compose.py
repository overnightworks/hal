"""Docker Compose for `hal apply`: what the stack is made of and what is running of it.

The pure part maps the profiles of a resolved or parsed compose file to their services. The
`Compose` class runs the stack's `docker compose` calls but the one `down` of `hal migrate
stack` (`project_move`); it never runs `down` and never names a volume, so a unit switched off
loses containers and keeps its data.
"""

import json
import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from hal.output import printable
from hal.stack.deploy_checkout import COMPOSE_FILE

REPOSITORY = Path(__file__).resolve().parents[3]
READ_SECONDS = 60
_COMPATIBILITY_VARIABLE = "COMPOSE_COMPATIBILITY"
CHANGE_SECONDS = 600
# A container that cannot load its configuration is running for a moment after `up`, then
# exits and Docker restarts it with a backoff that starts at 100 ms; seconds of watching see it.
SETTLE_SECONDS = 5.0
_SETTLE_POLL_SECONDS = 0.5
_COMPLETES = "service_completed_successfully"
_RUNNING = "running"
_COMPLETED = "completed"  # a container that exited 0: a one-shot has done its job
_CREATED = "created"  # created but never started: an `up` whose start failed
_NOT_RUNNING = {"exited", _COMPLETED, _CREATED, "dead"}
# Compose's record of the service definition a container was created from. Only this label is
# read out of ps's comma-joined `Labels`, so another label's value may hold commas.
CONFIG_HASH_LABEL = "com.docker.compose.config-hash"
IMAGE_ID_LABEL = "com.docker.compose.image"
_IMAGE_ID = re.compile(rf"(?:^|,){re.escape(IMAGE_ID_LABEL)}=(sha256:[0-9a-f]{{64}})(?:,|$)")
_CONFIG_HASH = re.compile(rf"(?:^|,){re.escape(CONFIG_HASH_LABEL)}=([0-9a-f]{{64}})(?:,|$)")
_HASH_LINE = re.compile(r"(\S+) ([0-9a-f]{64})")


class Runner(Protocol):
    """Runs a command; `stdin` is passed only by a caller that feeds the command's input."""

    def __call__(
        self, command: list[str], timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]: ...


class ComposeError(Exception):
    """A `docker compose` call failed or answered nonsense; the message is one line."""


def profile_services(config: Mapping[str, Any]) -> dict[str, tuple[str, ...]]:
    """Each profile of a compose file with the services that name it, in file order."""
    services: dict[str, list[str]] = {}
    for name, service in config["services"].items():
        for profile in service.get("profiles", []):
            services.setdefault(profile, []).append(name)
    return {profile: tuple(names) for profile, names in services.items()}


def one_shot_services(config: Mapping[str, Any]) -> set[str]:
    """Services another service waits on to complete; only these may be done after exiting 0."""
    return {
        name
        for service in config["services"].values()
        for name, dependency in service.get("depends_on", {}).items()
        if dependency.get("condition") == _COMPLETES
    }


def named_volumes(service: Mapping[str, Any]) -> tuple[str, ...]:
    """The compose volume keys a resolved service mounts."""
    return tuple(
        mount["source"] for mount in service.get("volumes", []) if mount.get("type") == "volume"
    )


def run_docker(
    command: list[str], timeout: int, stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    """Runs the command with COMPOSE_COMPATIBILITY off: an app's tracked `.env` could turn it on,
    and Compose would then name a built image `<project>_<service>`, not `<project>-<service>`."""
    try:
        return subprocess.run(  # noqa: S603 - argv is a docker command hal builds and no shell runs
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout,
            cwd=REPOSITORY,
            input=stdin,
            env={**os.environ, _COMPATIBILITY_VARIABLE: "false"},
        )
    except subprocess.TimeoutExpired as error:
        raise ComposeError(f"`{' '.join(command[:3])}` took longer than {timeout}s") from error
    except OSError as error:
        raise ComposeError(f"cannot run {command[0]}: {error.strerror}") from error


@dataclass(frozen=True)
class Watch:
    """How long a started container is watched before it counts as running."""

    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    seconds: float = SETTLE_SECONDS


SETTLED = Watch()


@dataclass(frozen=True)
class Container:
    """One container of the project as `ps` lists it. `config_hash` is the hash of the service
    definition it was created from, as Compose labelled it; None when the label is missing.
    `image` is the image reference it was created from, spelled as the definition named it then;
    None when `ps` names none. `image_id` is the id of the image it was created from, as Compose
    labelled it; None when the label is missing."""

    service: str
    state: str
    config_hash: str | None
    image: str | None
    image_id: str | None = None

    @property
    def live(self) -> bool:
        return is_live(self.state)


@dataclass(frozen=True)
class Compose:
    run: Runner = run_docker
    repository: Path = REPOSITORY

    def resolved_configuration(self) -> dict[str, Any]:
        """The configuration of every profile, as Compose resolves it."""
        output = self._call("*", "config", ["--format", "json"], READ_SECONDS)
        try:
            return json.loads(output)
        except json.JSONDecodeError as error:
            raise ComposeError("`docker compose config` did not answer JSON") from error

    def containers(self) -> list[Container]:
        """Every container of the project, of every profile."""
        output = self._call("*", "ps", ["--all", "--format", "json"], READ_SECONDS)
        return [_container(entry) for entry in ps_entries(output)]

    def states(self) -> dict[str, set[str]]:
        """Each service that has a container, with the states of its containers."""
        return states_of(self.containers())

    def config_hashes(self, services: tuple[str, ...]) -> dict[str, str]:
        """Compose's hash of each service's definition as it resolves the checkout now; the
        label of a container created from the same definition carries the same hash."""
        output = self._call("*", "config", ["--hash", ",".join(services)], READ_SECONDS)
        hashes = {}
        for line in filter(str.strip, output.splitlines()):
            if not (match := _HASH_LINE.fullmatch(line.strip())):
                raise ComposeError(f"`docker compose config --hash` answered {line.strip()!r}")
            hashes[match[1]] = match[2]
        if missing := [service for service in services if service not in hashes]:
            raise ComposeError(
                f"`docker compose config --hash` named no hash for {', '.join(missing)}"
            )
        return hashes

    def image_id(self, reference: str) -> str:
        """The id of the image the reference names in Docker now."""
        result = self.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", reference], READ_SECONDS
        )
        if result.returncode != 0:
            raise ComposeError(
                f"`docker image inspect {reference}` exited {result.returncode}: "
                f"{last_line(result.stderr + result.stdout)}"
            )
        return result.stdout.strip()

    def built_image_id(self, reference: str) -> str | None:
        """The id of the image the local tag names in Docker now; None when it is not built. A
        failing lookup or a tag that names two images is no answer."""
        result = self.run(
            [
                "docker",
                "image",
                "ls",
                "--no-trunc",
                "--quiet",
                "--filter",
                f"reference={reference}",
            ],
            READ_SECONDS,
        )
        if result.returncode != 0:
            raise ComposeError(
                f"`docker image ls {reference}` exited {result.returncode}: "
                f"{last_line(result.stderr + result.stdout)}"
            )
        ids = set(result.stdout.split())
        if len(ids) > 1:
            raise ComposeError(f"`docker image ls {reference}` names {len(ids)} images")
        return ids.pop() if ids else None

    def start(self, unit: str, services: tuple[str, ...]) -> None:
        self._call(unit, "up", ["-d", "--no-recreate", *services], CHANGE_SECONDS)

    def recreate(self, service: str) -> None:
        """A new container for one service, from the image its definition names now and with its
        files as checked out now; the services it depends on are left as they are, and its volumes
        are kept."""
        self._call("*", "up", ["-d", "--no-deps", "--force-recreate", service], CHANGE_SECONDS)

    def run_once(self, service: str, arguments: list[str], stdin: str = "") -> str:
        """A one-off container of one service, removed afterwards and started with nothing it
        depends on; its stdout. `stdin` is all its input, so it never reads the terminal."""
        return self._call(
            "*", "run", ["-T", "--rm", "--no-deps", service, *arguments], CHANGE_SECONDS, stdin
        )

    def down_while_watched(
        self, config: Mapping[str, Any], services: tuple[str, ...], watch: Watch
    ) -> tuple[str, ...]:
        """Every service found not up at any look through the watch, in the order given, none
        when all stay up: a container that dies right after it started and is restarting is not
        running, and a service that fails later than another is still named."""
        deadline = watch.clock() + watch.seconds
        seen_down: set[str] = set()
        while True:
            seen_down.update(not_up(self.states(), config, services))
            if watch.clock() >= deadline:
                return tuple(name for name in services if name in seen_down)
            watch.sleep(_SETTLE_POLL_SECONDS)

    def stop(self, unit: str, services: tuple[str, ...]) -> None:
        self._call(unit, "stop", list(services), CHANGE_SECONDS)

    def remove_containers(self, unit: str, services: tuple[str, ...]) -> None:
        self._call(unit, "rm", ["-f", *services], CHANGE_SECONDS)

    def _call(
        self, profile: str, verb: str, arguments: list[str], timeout: int, stdin: str | None = None
    ) -> str:
        prefix = [
            "docker", "compose", "--project-directory", str(self.repository),
            "--file", str(self.repository / COMPOSE_FILE),
        ]  # fmt: skip
        command = [*prefix, "--profile", profile, verb, *arguments]
        result = self.run(command, timeout) if stdin is None else self.run(command, timeout, stdin)
        if result.returncode != 0:
            raise ComposeError(_failure_line(verb, result))
        return result.stdout


def is_up(
    states: Mapping[str, set[str]], config: Mapping[str, Any], services: tuple[str, ...]
) -> bool:
    """Every service of the unit has a container: running, or for a one-shot also completed."""
    return not not_up(states, config, services)


def not_up(
    states: Mapping[str, set[str]], config: Mapping[str, Any], services: tuple[str, ...]
) -> tuple[str, ...]:
    """The services without a container that is running, or for a one-shot also completed."""
    one_shots = one_shot_services(config)
    return tuple(
        name
        for name in services
        if not (
            states.get(name, set())
            and states[name] <= ({_RUNNING, _COMPLETED} if name in one_shots else {_RUNNING})
        )
    )


def is_live(state: str) -> bool:
    """A container in this state is alive: running, restarting or paused."""
    return state not in _NOT_RUNNING


def has_running_container(states: Mapping[str, set[str]], services: tuple[str, ...]) -> bool:
    """Some container of the unit's services is alive: running, restarting or paused."""
    return any(is_live(state) for name in services for state in states.get(name, set()))


def never_started(states: Mapping[str, set[str]], service: str) -> bool:
    """Every container of the service was created and never started, as an `up` whose start
    failed leaves it; nobody stopped it."""
    return states.get(service) == {_CREATED}


def states_of(containers: Iterable[Container]) -> dict[str, set[str]]:
    """Each service that has a container, with the states of its containers."""
    states: dict[str, set[str]] = {}
    for container in containers:
        states.setdefault(container.service, set()).add(container.state)
    return states


def _container(entry: Mapping[str, Any]) -> Container:
    labels = entry.get("Labels", "")
    config_hash = _CONFIG_HASH.search(labels)
    image_id = _IMAGE_ID.search(labels)
    return Container(
        entry["Service"],
        _state_of(entry),
        config_hash[1] if config_hash else None,
        entry.get("Image") or None,
        image_id[1] if image_id else None,
    )


def _state_of(container: Mapping[str, Any]) -> str:
    if container["State"] == "exited" and container.get("ExitCode") == 0:
        return _COMPLETED
    return container["State"]


def is_gone(states: Mapping[str, set[str]], services: tuple[str, ...]) -> bool:
    """No container of the unit's services exists, running or not."""
    return not any(name in states for name in services)


def ps_entries(output: str) -> list[dict[str, Any]]:
    """The entries of `ps --format json`, one JSON array or one object per line by Compose
    version: the one parser of that answer."""
    text = output.strip()
    try:
        if text.startswith("["):
            return json.loads(text)
        return [json.loads(line) for line in text.splitlines()]
    except json.JSONDecodeError as error:
        raise ComposeError("`docker compose ps` did not answer JSON") from error


def _failure_line(verb: str, result: subprocess.CompletedProcess[str]) -> str:
    last = last_line(result.stderr + result.stdout)
    return f"`docker compose {verb}` exited {result.returncode}: {last}"


def last_line(output: str) -> str:
    """The last non-empty line of a command's output, stripped and printable; `no output` when
    there is none. The one owner for every refusal that quotes a command's own words."""
    lines = [line for line in output.splitlines() if line.strip()]
    return printable(lines[-1].strip()) if lines else "no output"
