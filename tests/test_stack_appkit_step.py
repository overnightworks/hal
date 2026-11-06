"""The appkit step of the closed apply (#514): the installed appkit's static files, written to
`appkit-<version>/` in `legal/assets/` (served by the legal unit) and in each Keycloak theme's
`resources/`, on the scripted boundaries of `tests/support/stack_apply.py`."""

import os
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path

import pytest
from support.stack_apply import (
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
)
from support.stack_plan_rows import find_row, plain

from hal.stack import appkit_step, apply
from hal.stack.plan_rows import PlanEvent
from hal.stack.result_rows import ResultEvent

VERSION = metadata.version("overnightworks-appkit")


@dataclass
class World:
    """The repository fixture with its appkit files, and how to run the closed apply."""

    repository: Path
    switch: Callable[..., tuple[int, str, str]]

    @property
    def targets(self) -> tuple[Path, ...]:
        return appkit_step.served_directories(self.repository)

    @property
    def legal(self) -> Path:
        return self.targets[0]

    def relative(self, target: Path) -> str:
        return str(target.relative_to(self.repository))


@pytest.fixture
def world(repository: Path, switch) -> World:  # noqa: F811
    return World(repository, switch)


def files_of(directory: Path) -> dict[str, bytes]:
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


def test_a_fresh_checkout_names_the_new_directory_and_writes_every_target_after_yes(world):
    seeded = [files_of(target) for target in world.targets]
    for target in world.targets:
        shutil.rmtree(target)

    declined_exit, declined_out, _ = world.switch(answer="no")

    assert declined_exit == apply.ApplyExit.DECLINED
    assert find_row(declined_out, "appkit", PlanEvent.NEW_FILES, VERSION)
    assert "only" not in declined_out
    assert not any(target.exists() for target in world.targets)

    exit_code, out, err = world.switch()

    assert exit_code == 0, err
    assert find_row(out, "appkit", PlanEvent.NEW_FILES, VERSION)
    assert find_row(out, "appkit", ResultEvent.FILES_WRITTEN, VERSION)
    assert [files_of(target) for target in world.targets] == seeded


def test_the_targets_are_the_legal_assets_and_both_theme_resources(world):
    assert [world.relative(target.parent) for target in world.targets] == [
        "legal/assets",
        "keycloak/themes/hallucinai/login/resources",
        "keycloak/themes/hallucinai/account/resources",
    ]
    assert {target.name for target in world.targets} == {f"appkit-{VERSION}"}


def test_the_written_directories_and_files_are_readable_by_the_unit(world):
    for target in world.targets:
        shutil.rmtree(target)
    previous = os.umask(0o077)
    try:
        exit_code, _, err = world.switch()
    finally:
        os.umask(previous)

    assert exit_code == 0, err
    modes = {
        path: stat.S_IMODE(path.stat().st_mode)
        for target in world.targets
        for path in (target, *target.rglob("*"))
    }
    assert all(mode == (0o755 if path.is_dir() else 0o644) for path, mode in modes.items()), modes


def test_a_second_apply_changes_nothing_and_says_so(world):
    world.switch()

    exit_code, out, err = world.switch(answer="no")

    assert exit_code == 0, err
    assert "appkit" not in out
    assert "nothing to change" in out


def test_a_damaged_target_is_named_and_the_others_stay_untouched(world):
    damaged = world.targets[1]
    original = files_of(damaged)
    (damaged / "appkit.css").write_text("damaged")
    (damaged / "stray.txt").write_text("not the wheel's")

    _, out, _ = world.switch(answer="no")

    assert find_row(out, "appkit", PlanEvent.NEW_FILES, f"{VERSION} · only login theme")

    written = []

    def rename(source, destination):
        written.append(Path(destination))
        os.rename(source, destination)

    exit_code, _, err = world.switch(rename=rename)

    assert exit_code == 0, err
    assert files_of(damaged) == original
    assert [path for path in written if path in world.targets] == [damaged]


def test_only_the_steps_own_stale_directories_are_removed_in_every_target(world):
    stale = []
    for target in world.targets:
        (target.parent / "appkit-0.4.0").mkdir()
        (target.parent / "appkit-0.4.0" / "appkit.css").write_text("old")
        (target.parent / "other").mkdir(exist_ok=True)
        stale.append(world.relative(target.parent / "appkit-0.4.0"))

    _, out, _ = world.switch(answer="no")

    assert find_row(out, "appkit", PlanEvent.OLD_FILES, "appkit-0.4.0")
    assert "appkit-0.4.0, appkit-0.4.0" not in out
    assert all((world.repository / path).is_dir() for path in stale)

    exit_code, out, err = world.switch()

    assert exit_code == 0, err
    assert find_row(out, "appkit", ResultEvent.FILES_REMOVED, "appkit-0.4.0")
    assert not find_row(out, "appkit", ResultEvent.FILES_WRITTEN)
    assert not any((world.repository / path).exists() for path in stale)
    assert all((target.parent / "other").is_dir() and target.is_dir() for target in world.targets)


def test_a_write_leaves_no_temporary_directory_beside_a_served_one(world):
    for target in world.targets:
        (target / "appkit.css").write_text("damaged")

    world.switch()

    for target in world.targets:
        assert not [path for path in target.parent.iterdir() if path.name.startswith(".appkit-")]


def test_a_failing_target_is_named_and_stops_the_writes_there(world):
    for target in world.targets:
        shutil.rmtree(target)
    failing = world.targets[1]

    def rename(source, destination):
        if Path(destination) == failing:
            raise OSError(5, "interrupted")
        os.rename(source, destination)

    exit_code, out, err = world.switch(rename=rename)

    assert exit_code == 1
    assert find_row(
        out, "appkit", ResultEvent.NOT_WRITTEN, f"could not write {failing} (interrupted)"
    )
    assert not find_row(out, "appkit", ResultEvent.FILES_WRITTEN)
    assert err.splitlines() == [
        "error: partial, appkit not written · no unit switched",
        "next: hal apply",
    ]
    assert files_of(world.legal) == files_of(appkit_step.installed_static())
    assert not failing.exists()
    assert not world.targets[2].exists()


def test_a_failed_removal_of_a_stale_directory_names_that_directory(world):
    stale = world.targets[0].parent / "appkit-0.4.0"
    stale.mkdir()
    (stale / "appkit.css").write_text("old")
    stale.parent.chmod(0o500)
    try:
        exit_code, out, err = world.switch()
    finally:
        stale.parent.chmod(0o700)

    assert exit_code == 1
    assert find_row(out, "appkit", ResultEvent.NOT_WRITTEN, f"could not write {stale} (")
    assert "no unit switched" in err


def test_a_failed_copy_of_many_entries_names_the_first_reason_once(world, monkeypatch):
    for target in world.targets:
        shutil.rmtree(target)
    monkeypatch.setattr(appkit_step.shutil, "copytree", _failing_copy)

    exit_code, out, _ = world.switch()

    assert exit_code == 1
    row = next(line for line in plain(out).splitlines() if "appkit" in line and "could not" in line)
    assert row.endswith(" (No space left on device)")
    assert "(None)" not in out


def _failing_copy(*_arguments, **_keywords):
    full = "No space left on device"
    raise shutil.Error([("first", "first-copy", full), ("second", "second-copy", full)])


def test_a_missing_appkit_is_one_cannot_plan_error(repository):  # noqa: F811
    def not_installed(name: str):
        raise ModuleNotFoundError(name)

    with pytest.raises(appkit_step.AppkitError, match="appkit is not installed, run `uv sync`"):
        appkit_step.plan_appkit(repository, not_installed)


def _rename_failing_on(*failing_calls: int):
    calls = []

    def rename(source, destination):
        calls.append(source)
        if len(calls) in failing_calls:
            raise OSError(5, "interrupted")
        os.rename(source, destination)

    return rename


def test_a_failed_final_rename_keeps_the_previous_directory(world):
    served = world.legal
    (served / "appkit.css").write_text("previous")

    static, rename = appkit_step.installed_static(), _rename_failing_on(2)

    with pytest.raises(OSError, match="interrupted"):
        appkit_step._replace_directory(static, served, rename)

    assert (served / "appkit.css").read_text() == "previous"
    assert [path.name for path in served.parent.iterdir()] == [served.name]


def test_a_failed_restore_keeps_the_previous_copy_and_names_where(world):
    served = world.legal
    (served / "appkit.css").write_text("previous")

    static, rename = appkit_step.installed_static(), _rename_failing_on(2, 3)

    with pytest.raises(OSError, match="the previous copy is kept in") as caught:
        appkit_step._replace_directory(static, served, rename)

    kept = Path(str(caught.value.strerror).rsplit(" ", 1)[1])
    assert (kept / "appkit.css").read_text() == "previous"


def test_an_interrupted_restore_keeps_the_previous_copy_and_names_where(world):
    served = world.legal
    (served / "appkit.css").write_text("previous")
    calls = []

    def rename(source, destination):
        calls.append(source)
        if len(calls) == 2:
            raise OSError(5, "interrupted")
        if len(calls) == 3:
            raise KeyboardInterrupt
        os.rename(source, destination)

    static = appkit_step.installed_static()

    with pytest.raises(KeyboardInterrupt) as caught:
        appkit_step._replace_directory(static, served, rename)

    kept = Path(caught.value.__notes__[0].rsplit(" ", 1)[1])
    assert (kept / "appkit.css").read_text() == "previous"


def test_an_interrupted_restore_shows_the_operator_where_the_previous_copy_is(world):
    (world.legal / "appkit.css").write_text("previous")
    calls = []

    def rename(source, destination):
        calls.append(source)
        if len(calls) == 2:
            raise OSError(5, "interrupted")
        if len(calls) == 3:
            raise KeyboardInterrupt
        os.rename(source, destination)

    exit_code, _, err = world.switch(rename=rename)

    assert exit_code == 1
    assert "interrupted while changing" in err
    assert "the previous copy is kept in " in err


@pytest.mark.parametrize("which", range(3), ids=["legal assets", "login theme", "account theme"])
def test_a_missing_target_parent_is_named_at_plan_time(world, which):
    parent = world.targets[which].parent
    shutil.rmtree(parent)

    exit_code, _, err = world.switch()

    assert exit_code == 2
    assert "cannot plan," in err
    assert str(parent) in err


def test_the_seeding_helper_serves_the_installed_files(world, seed_appkit):
    for target in world.targets:
        shutil.rmtree(target)

    seed_appkit(world.repository)

    assert all(
        files_of(target) == files_of(appkit_step.installed_static()) for target in world.targets
    )


def test_the_module_writes_every_target_without_the_question(world):
    for target in world.targets:
        shutil.rmtree(target)

    finished = subprocess.run(
        [
            "uv",
            "run",
            "--project",
            str(Path(__file__).parents[1]),
            "python",
            "-m",
            "hal.stack.appkit_step",
            str(world.repository),
        ],
        capture_output=True,
        text=True,
        check=False,
    )

    assert finished.returncode == 0, finished.stderr
    assert all(
        files_of(target) == files_of(appkit_step.installed_static()) for target in world.targets
    )


def test_the_module_refuses_a_broken_checkout_with_exit_2(world, capsys):
    shutil.rmtree(world.targets[1].parent)

    exit_code = appkit_step.main([str(world.repository)])

    assert exit_code == 2
    assert f"{world.targets[1].parent} is missing" in capsys.readouterr().err


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores the read-only mode")
def test_the_module_names_the_failing_target_with_exit_1(world, capsys):
    failing = world.targets[2]
    shutil.rmtree(failing)
    failing.parent.chmod(0o555)
    try:
        exit_code = appkit_step.main([str(world.repository)])
    finally:
        failing.parent.chmod(0o755)

    assert exit_code == 1
    assert f"appkit: could not write {failing}" in capsys.readouterr().err
