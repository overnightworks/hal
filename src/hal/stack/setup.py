"""Whether a unit is set up: runs its `<setup> --check`, words the refusal and runs the setup.

The one owner of that question for `hal apply --local`, `hal start` and any later caller.
"""

import signal
import subprocess
from collections.abc import Callable, Collection, Mapping
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any

from hal.stack import catalog, compose

SETUP_CHECK_SECONDS = 300


class SetupCheckExit(IntEnum):
    SET_UP = 0
    NOT_SET_UP = 1


class SetupUnclear(Exception):
    """A setup check could not tell; the message is its own line."""


SetupCheck = Callable[[list[str]], subprocess.CompletedProcess[str]]


def run_setup_check(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the argv is a setup check the fleet file declares and no shell runs
        command, capture_output=True, text=True, check=False, timeout=SETUP_CHECK_SECONDS
    )


def not_set_up_line(unit: catalog.Unit, repository: Path, check: SetupCheck) -> str | None:
    """The check's last line when the unit is not set up, else None; raises SetupUnclear."""
    setup = unit.setup
    if setup is None:
        return None
    try:
        result = check([str(repository / setup), "--check"])
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupUnclear(f"`{setup} --check` did not run ({type(error).__name__})") from error
    if result.returncode == SetupCheckExit.SET_UP:
        return None
    last = compose.last_line(result.stdout + result.stderr)
    if result.returncode == SetupCheckExit.NOT_SET_UP:
        return last
    raise SetupUnclear(f"`{setup} --check` cannot tell: {last}")


def refusal(unit: catalog.Unit, repository: Path, check: SetupCheck, again: str) -> str | None:
    """None when the unit is set up, else the refusal naming `again`; raises SetupUnclear."""
    line = not_set_up_line(unit, repository, check)
    if line is None:
        return None
    return f"{unit.key} is not set up: run `{unit.setup}`, then `{again}` again; {line}"


@dataclass(frozen=True)
class AbsentSecretFile:
    service: str
    file: Path


def absent_secret_files(
    config: Mapping[str, Any], services: Collection[str]
) -> list[AbsentSecretFile]:
    """Each file of a resolved top-level `secrets` entry that one of the services names and that
    does not exist, in order, once each; a secret without a `file` is not looked at."""
    files = {
        name: entry["file"] for name, entry in config.get("secrets", {}).items() if "file" in entry
    }
    absent: dict[Path, AbsentSecretFile] = {}
    for service in services:
        for named in config["services"][service].get("secrets", ()):
            file = Path(files[named["source"]]) if named["source"] in files else None
            if file and not file.exists():
                absent.setdefault(file, AbsentSecretFile(service, file))
    return list(absent.values())


@dataclass(frozen=True)
class SetupRun:
    exit_code: int
    interrupted: bool


SetupRunner = Callable[[Path, Path], SetupRun]


def run_setup(command: Path, repository: Path) -> SetupRun:
    """Run the setup in the caller's terminal: inherited streams and environment, no time limit.

    Ctrl-C reaches the setup through the terminal; this process waits for it to finish its own
    interrupt handling instead of dying first. Raises OSError when the setup cannot start.
    """
    interrupted = False

    def note_interrupt(_signal: int, _frame: object) -> None:
        nonlocal interrupted
        interrupted = True

    previous = signal.signal(signal.SIGINT, note_interrupt)
    try:
        exit_code = subprocess.run([str(command)], cwd=repository, check=False).returncode  # noqa: S603 - runs the unit own setup script and no shell runs
    finally:
        signal.signal(signal.SIGINT, previous)
    return SetupRun(exit_code, interrupted or exit_code == -signal.SIGINT)
