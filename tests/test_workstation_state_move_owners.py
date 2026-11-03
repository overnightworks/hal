"""The owners of hal's state paths (#951 F1, F2, M8). They may not import each other, so this
module pins them to one directory, and proves that the stack's switches and their locks, run on
a scratch HOME, never create a directory the mover empties."""

import os
from pathlib import Path, PurePosixPath

import pytest
import yaml
from support.hal_stack_commands import (
    UNIT,
    fakes,  # noqa: F401 the fixture, requested by name below
    hal,  # noqa: F401 the fixture, requested by name below
    system_commands,  # noqa: F401 the autouse guard that no real system command runs
    systemd,  # noqa: F401 the fixture, used by `fakes`
)
from support.stack_apply import (
    at_terminal,  # noqa: F401 the fixture, used by `hal`
    ingress,  # noqa: F401 the fixture, used by `fakes`
    scripted,  # noqa: F401 the fixture, used by `fakes`
    setup_check,  # noqa: F401 the fixture, used by `fakes`
    state,  # noqa: F401 the fixture, used by `fakes`
)
from support.stack_apply_publish import repository  # noqa: F401 the fixture, used by `fakes`
from support.stack_external import (
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, used by `repository`
)
from support.stack_global_stop import hosts_asked  # noqa: F401 the fixture, used by `fakes`

from hal.backup import host
from hal.backup.settings import Settings
from hal.grammar import ExitCode
from hal.stack import apply, switches, tunnel
from hal.workstation import backup_check, platform_check, state_move
from hal.workstation.layout import Layout

PLAYBOOK = Path(__file__).resolve().parents[1] / "src/hal/workstation/system/playbook.yml"


def owned_state_paths(home_directory: Path) -> dict[str, Path]:
    """The state directory each owner names, below `home_directory`."""
    settings = Settings.for_home(home_directory, os.getuid(), os.getgid())
    layout = Layout(home_directory)
    return {
        "hal.stack.switches": switches.default_state_directory(),
        "hal.backup.settings status": settings.status_file.parent,
        "hal.backup.settings lock": settings.lock_file.parent,
        "hal.workstation.backup_check": (home_directory / backup_check.STATUS_FILE).parent,
        "hal.workstation.platform_check": (
            home_directory / platform_check.SWITCHES_DIRECTORY
        ).parent,
        "hal.workstation.layout": layout.hal_state_dir,
        "hal.workstation.layout secrets report": layout.secrets_report_file.parent,
    }


def old_directories(home_directory: Path) -> tuple[Path, ...]:
    return tuple(
        home_directory / below_home
        for below_home in (state_move.OLD_STATE, state_move.OLD_HOME_STATE, state_move.OLD_CACHE)
    )


def test_every_owner_of_a_state_path_names_one_directory(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))

    named = owned_state_paths(tmp_path)

    assert set(named.values()) == {Layout(tmp_path).hal_state_dir}, named


def test_the_check_reads_the_files_the_stack_and_the_backup_write(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    settings = Settings.for_home(tmp_path, os.getuid(), os.getgid())

    assert tmp_path / backup_check.STATUS_FILE == settings.status_file
    assert tmp_path / platform_check.SWITCHES_DIRECTORY == (
        switches.default_state_directory() / switches.STOPPED_DIRECTORY
    )


def test_no_owner_names_a_directory_the_mover_empties(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    work_dir = Settings.for_home(tmp_path, os.getuid(), os.getgid()).work_dir

    owned = [*owned_state_paths(tmp_path).values(), work_dir]

    assert [
        path for path in owned for old in old_directories(tmp_path) if path.is_relative_to(old)
    ] == []


def test_the_switches_and_every_lock_taker_never_create_the_old_state(hal, fakes, home):  # noqa: F811
    """M8, the stack's part: `hal stop`, `hal offline` and the three locks on a scratch HOME."""
    fakes.unit_in("A")
    state_directory = switches.default_state_directory()

    assert hal("stop", UNIT).exit_code == ExitCode.OK
    assert hal("offline").exit_code == ExitCode.OK
    with switches.Switches(state_directory).lock():
        pass
    os.close(apply.take_apply_lock(state_directory))
    with host.exclusive_lock(Settings.for_home(home, os.getuid(), os.getgid()).lock_file):
        pass

    assert [path for path in old_directories(home) if path.exists()] == []
    assert (state_directory / switches.GLOBAL_STOP_FILE).exists()


def retired_drop_ins() -> list[str]:
    """The drop-ins `hal setup` deletes, by name, as the playbook lists them."""
    retired = yaml.safe_load(PLAYBOOK.read_text())[0]["vars"]["retired_files"]
    paths = [PurePosixPath(entry["dest"]) for entry in retired]
    return [path.name for path in paths if path.suffix == ".conf"]


@pytest.mark.parametrize("drop_in", retired_drop_ins())
def test_offline_with_only_a_retired_drop_in_loaded_is_incomplete(hal, fakes, systemd, drop_in):  # noqa: F811
    """F2: the retired boot drop-in no longer certifies the reboot protection."""
    systemd.drop_ins = [drop_in]

    result = hal("offline")

    assert drop_in != tunnel.BOOT_DROP_IN
    assert "incomplete: a reboot would reopen the tunnel" in result.text
    assert result.exit_code == ExitCode.FAILURE
