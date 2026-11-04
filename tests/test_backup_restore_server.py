"""The throwaway restore server on the scripted Docker host: its name carries the home, and a
home's sweep removes only that home's leftovers (#969 C3)."""

import hashlib
import os
from pathlib import Path

from support.backup_support import RESTORE_SERVER_ID, removed_servers

from hal.backup import docker
from hal.backup.docker import RESTORE_SERVER_PREFIX, restore_server_name
from hal.backup.settings import Settings


def _lock_file(home: Path) -> Path:
    return Settings.for_home(home, os.getuid(), os.getgid()).lock_file


def test_the_servers_name_ends_in_the_first_8_hex_of_the_sha256_of_the_homes_lock_path(
    edge_backup, machine, home
):
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    digest = hashlib.sha256(str(_lock_file(home).absolute()).encode()).hexdigest()
    start = machine.argv_of(docker.SERVER_START_LABEL)
    assert start[start.index("--name") + 1] == f"{RESTORE_SERVER_PREFIX}-{digest[:8]}"


def test_two_homes_never_share_a_servers_name(tmp_path):
    names = {restore_server_name(_lock_file(tmp_path / home)) for home in ("one", "two")}

    assert len(names) == 2


def test_a_restore_test_sweeps_its_own_homes_leftover_and_never_another_homes_server(
    edge_backup, machine, home
):
    machine.leftover_servers = ["1eft0ver"]
    machine.other_home_servers = {"0th3rh0me": restore_server_name(_lock_file(home / "other"))}
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    assert removed_servers(machine) == ["1eft0ver", RESTORE_SERVER_ID]
