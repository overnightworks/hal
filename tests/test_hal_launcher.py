"""bin/hal runs its own checkout's hal with that checkout's locked dependencies, from anywhere."""

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

BIN = Path(__file__).resolve().parents[1] / "bin"
LAUNCHER = BIN / "hal"
SYNC = BIN / "hal-sync"

FAKE_UV = """#!/bin/sh
printf '%s\\0' "$@" > "$FAKE_LOG/uv.args"
printf '%s' "${VIRTUAL_ENV-unset} ${UV_PROJECT_ENVIRONMENT-unset}" > "$FAKE_LOG/uv.env"
if [ -n "${FAKE_UV_FAILS-}" ]; then
    echo "uv: lock file is out of date" >&2
    exit 1
fi
"""

FAKE_HAL = """#!/bin/sh
printf '%s\\0' "$@" > "$FAKE_LOG/hal.args"
printf '%s' "${VIRTUAL_ENV-unset} ${UV_PROJECT_ENVIRONMENT-unset}" > "$FAKE_LOG/hal.env"
printf '%s' "$PPID" > "$FAKE_LOG/hal.ppid"
exit "${FAKE_HAL_EXIT-0}"
"""


def _executable(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)
    return path


@dataclass(frozen=True)
class Machine:
    checkout: Path
    elsewhere: Path
    log: Path
    path: str

    def run(
        self, *args: str, launcher: Path | None = None, **env: str
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(launcher or self.checkout / "bin/hal"), *args],
            cwd=self.elsewhere,
            env={"PATH": self.path, "FAKE_LOG": str(self.log), **env},
            capture_output=True,
            text=True,
            check=False,
        )

    def logged(self, name: str) -> str:
        return (self.log / name).read_text()

    def logged_args(self, name: str) -> list[str]:
        return self.logged(name).split("\0")[:-1]


@pytest.fixture
def machine(tmp_path) -> Machine:
    checkout = tmp_path / "checkout"
    (checkout / "bin").mkdir(parents=True)
    shutil.copy2(LAUNCHER, checkout / "bin/hal")
    shutil.copy2(SYNC, checkout / "bin/hal-sync")
    _executable(checkout / ".venv/bin/hal", FAKE_HAL)
    fake_bin = tmp_path / "fake-bin"
    _executable(fake_bin / "uv", FAKE_UV)
    (tmp_path / "log").mkdir()
    (tmp_path / "elsewhere").mkdir()
    return Machine(
        checkout=checkout,
        elsewhere=tmp_path / "elsewhere",
        log=tmp_path / "log",
        path=f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
    )


def test_syncs_the_checkout_locked_and_hands_hal_its_arguments_verbatim(machine):
    """#102 rule 1, cell L1: the checkout syncs locked; hal gets every argument unchanged."""
    arguments = ["external", "plan", "two words", "", "--flag=$HOME"]

    result = machine.run(*arguments)

    assert result.returncode == 0, result.stderr
    assert machine.logged_args("uv.args") == [
        "sync",
        "--locked",
        "--inexact",
        "--no-dev",
        "--quiet",
        "--project",
        str(machine.checkout),
    ]
    assert machine.logged_args("hal.args") == arguments


def test_exits_with_hal_exit_code(machine):
    """#102 rule 1, cell L2: the launcher exits with hal's own exit code."""
    assert machine.run("external", "apply", FAKE_HAL_EXIT="3").returncode == 3


def test_failed_sync_exits_3_with_error_and_next_and_never_runs_hal(machine):
    """#102 rule 2, cell L3: a failed sync ends in hal's error form with exit 3; hal never runs."""
    result = machine.run("--help", FAKE_UV_FAILS="1")

    assert result.returncode == 3
    assert "uv: lock file is out of date" in result.stderr
    assert result.stderr.splitlines()[-2:] == [
        "error: cannot sync the live checkout's dependencies",
        f"next: uv sync --locked --project {machine.checkout}",
    ]
    assert not (machine.log / "hal.args").exists()


def test_hal_replaces_the_launcher_instead_of_running_under_a_shell(machine):
    """#102 rule 1, cell L4: hal replaces the launcher process instead of running under a shell."""
    machine.run("--help")

    assert machine.logged("hal.ppid") == str(os.getpid())


def test_another_projects_environment_reaches_neither_uv_nor_hal(machine, tmp_path):
    """#102 rule 1, cell L5: another project's virtualenv reaches neither uv nor hal."""
    other = str(tmp_path / "other-project/.venv")

    machine.run("--help", VIRTUAL_ENV=other, UV_PROJECT_ENVIRONMENT=other)

    assert machine.logged("uv.env") == "unset unset"
    assert machine.logged("hal.env") == "unset unset"


def test_finds_its_checkout_through_a_symlink_in_another_directory(machine, tmp_path):
    """#102 rule 1, cell L6: a symlink elsewhere still finds its own checkout."""
    link = tmp_path / "home/.local/bin/hal"
    link.parent.mkdir(parents=True)
    link.symlink_to(machine.checkout / "bin/hal")

    result = machine.run("--help", launcher=link)

    assert result.returncode == 0, result.stderr
    assert machine.logged_args("uv.args")[-1] == str(machine.checkout)
    assert machine.logged_args("hal.args") == ["--help"]


def test_sync_without_a_program_runs_nothing_after_uv(machine):
    """#783 cell N2: without a program the script only syncs and runs no hal."""
    result = subprocess.run(
        [str(machine.checkout / "bin/hal-sync"), str(machine.checkout)],
        env={
            "PATH": machine.path,
            "FAKE_LOG": str(machine.log),
            "VIRTUAL_ENV": "/other/.venv",
        },
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert machine.logged_args("uv.args")[-1] == str(machine.checkout)
    assert machine.logged("uv.env") == "unset unset"
    assert not (machine.log / "hal.args").exists()


def test_failed_sync_without_a_program_exits_1_and_prints_only_uvs_line(machine):
    """#783 cell N2: the caller reports a failed sync; the script adds no error pair."""
    result = subprocess.run(
        [str(machine.checkout / "bin/hal-sync"), str(machine.checkout)],
        env={"PATH": machine.path, "FAKE_LOG": str(machine.log), "FAKE_UV_FAILS": "1"},
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr == "uv: lock file is out of date\n"
