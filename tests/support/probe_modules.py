"""What the probe tests share: the probe scripts they load as modules, each for the length of a
module-scoped fixture with `sys.path` as it was afterwards (a probe script puts its own
directories on it), and a docker daemon holding networks, whose subnets the probes' /24 rule
reads."""

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from support.script_module import loaded_script

from hal.backup.docker import PROJECT_LABEL

PROBES = Path(__file__).resolve().parents[2] / "probe"


def loaded_probe(name: str, path: Path, *directories: Path) -> Iterator[ModuleType]:
    """The module of the probe script at `path` under `name`, `directories` first on `sys.path`
    while it loads, until the iterator is resumed; then `sys.path` is restored."""
    path_before = list(sys.path)
    sys.path[:0] = [str(directory) for directory in directories]
    try:
        yield from loaded_script(name, path)
    finally:
        sys.path[:] = path_before


@pytest.fixture(scope="module")
def step_ca_probe() -> Iterator[ModuleType]:
    yield from loaded_probe("step_ca_probe", PROBES / "step-ca" / "probe.py")


@pytest.fixture(scope="module")
def egress_probe() -> Iterator[ModuleType]:
    yield from loaded_probe("egress_probe", PROBES / "agent-service" / "egress.py")


@pytest.fixture(scope="module")
def apps_probe() -> Iterator[ModuleType]:
    yield from loaded_probe("apps_probe", PROBES / "apps" / "probe.py", PROBES / "apps")


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
