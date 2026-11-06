"""What the probe tests share: the probe scripts they load as modules, each for the length of a
module-scoped fixture, and a docker daemon holding networks, whose subnets the probes' /24 rule
reads."""

import json
import os
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from support.script_module import loaded_script

from hal.backup.docker import PROJECT_LABEL

PROBES = Path(__file__).resolve().parents[2] / "probe"


@pytest.fixture(scope="module")
def step_ca_probe() -> Iterator[ModuleType]:
    yield from loaded_script("step_ca_probe", PROBES / "step-ca" / "probe.py")


@pytest.fixture(scope="module")
def litellm_stack() -> Iterator[ModuleType]:
    yield from loaded_script("litellm_stack", PROBES / "agent-service" / "litellm_stack.py")


@pytest.fixture(scope="module")
def apps_probe() -> Iterator[ModuleType]:
    yield from loaded_script("apps_probe", PROBES / "apps" / "probe.py", PROBES / "apps")


def a_daemon(directory: Path, monkeypatch: pytest.MonkeyPatch, networks: dict[str, str]) -> None:
    """A docker executable on PATH whose daemon holds `networks`, each subnet with the compose
    project that made it."""
    directory.mkdir()
    listed, inspected = directory / "ids", directory / "inspect.json"
    listed.write_text("".join(f"{subnet}\n" for subnet in networks))
    inspected.write_text(json.dumps([
        {"Labels": {PROJECT_LABEL: project}, "IPAM": {"Config": [{"Subnet": subnet}]}}
        for subnet, project in networks.items()
    ]))  # fmt: skip
    docker = directory / "docker"
    docker.write_text(
        f'#!/bin/sh\ncase "$*" in\n  "network ls -q") cat "{listed}" ;;\n'
        f'  "network inspect "*) cat "{inspected}" ;;\n  *) exit 1 ;;\nesac\n'
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{directory}{os.pathsep}{os.environ['PATH']}")
