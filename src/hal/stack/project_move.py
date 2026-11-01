"""The move of the stack between the Compose projects `edge` and `hal`: the reads, the plan and
the Docker calls of `hal migrate stack`.

The source is whichever of the two the resolved `compose.yaml` does not name. Everything is read
from Docker, so a rerun finishes what is left. Volumes are never removed by `down`: only the
source's volumes `compose.yaml` no longer names are removed, one by one, by name. Networks
follow the same rule: only those `compose.yaml` does not name are work for `down`.
"""

from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from hal.stack import compose, core
from hal.stack.compose import Compose, ComposeError, Runner
from hal.stack.deploy_checkout import COMPOSE_FILE

PROJECTS = ("edge", "hal")
PROJECT_LABEL = "com.docker.compose.project"


class Refusal(Exception):
    """`compose.yaml` names neither project; the message is one line."""


class Stage(Enum):
    DOWN = "down"
    VOLUME = "volume"
    START = "start"


@dataclass(frozen=True)
class Plan:
    """What the move does."""

    source: str
    target: str
    containers: tuple[str, ...]
    taken_over_networks: tuple[str, ...]
    removed_networks: tuple[str, ...]  # `down` removes them
    kept_volumes: tuple[str, ...]
    removed_volumes: tuple[str, ...]
    core: tuple[str, ...]  # the services to start; empty while the target's core is up

    @property
    def has_work(self) -> bool:
        return self.needs_down or bool(self.removed_volumes or self.core)

    @property
    def needs_down(self) -> bool:
        return bool(self.containers or self.removed_networks)


def make_plan(docker: Runner) -> Plan:
    cluster = Compose(run=docker)
    config = cluster.resolved_configuration()
    target = config["name"]
    if target not in PROJECTS:
        raise Refusal(f"compose.yaml names the project {target}, not edge or hal")
    source = next(project for project in PROJECTS if project != target)
    networks = _labelled(docker, ["network", "ls"], "{{.Name}}", source)
    named_networks = _resolved_names(config, "networks")
    volumes = _labelled(docker, ["volume", "ls"], "{{.Name}}", source)
    named_volumes = _resolved_names(config, "volumes")
    services = core.core_services(config)
    return Plan(
        source,
        target,
        _labelled(docker, ["ps", "--all"], "{{.Names}}", source),
        tuple(name for name in networks if name in named_networks),
        tuple(name for name in networks if name not in named_networks),
        tuple(name for name in volumes if name in named_volumes),
        tuple(name for name in volumes if name not in named_volumes),
        () if compose.is_up(cluster.states(), config, services) else services,
    )


def _resolved_names(config: Mapping[str, Any], section: str) -> set[str]:
    return {entry["name"] for entry in config.get(section, {}).values()}


def move(plan: Plan, docker: Runner) -> Iterator[tuple[Stage, tuple[str, ...]]]:
    """Each stage of the plan, yielded once it is done; a failing call raises `ComposeError`
    before the next stage."""
    if plan.needs_down:
        _call(docker, _down(plan.source), "docker compose down", compose.CHANGE_SECONDS)
        yield Stage.DOWN, plan.containers or plan.removed_networks
    for volume in plan.removed_volumes:
        command = ["docker", "volume", "rm", volume]
        _call(docker, command, f"docker volume rm {volume}", compose.CHANGE_SECONDS)
        yield Stage.VOLUME, (volume,)
    if plan.core:
        Compose(run=docker).start("*", plan.core)
        yield Stage.START, plan.core


def _down(source: str) -> list[str]:
    repository = compose.REPOSITORY
    return [
        "docker", "compose", "-p", source, "--project-directory", str(repository),
        "--file", str(repository / COMPOSE_FILE), "--profile", "*", "down", "--remove-orphans",
    ]  # fmt: skip


def _labelled(docker: Runner, listing: list[str], name_format: str, source: str) -> tuple[str, ...]:
    label = f"label={PROJECT_LABEL}={source}"
    command = ["docker", *listing, "--filter", label, "--format", name_format]
    return tuple(_call(docker, command, f"docker {listing[0]}", compose.READ_SECONDS).split())


def _call(docker: Runner, command: list[str], name: str, timeout_seconds: int) -> str:
    result = docker(command, timeout_seconds)
    if result.returncode != 0:
        output = result.stderr + result.stdout
        raise ComposeError(f"`{name}` exited {result.returncode}: {compose.last_line(output)}")
    return result.stdout
