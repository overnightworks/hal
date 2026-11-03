"""`hal migrate state` (#951 rows M1 to M7, M9, M10): the old directories merge into hal's, through
`hal.cli.main` on a real temporary filesystem. The old paths are the mover's own; the new ones
come from their owners."""

import errno
import fcntl
import os
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest
from support.terminal_support import type_at_prompt
from support.workstation_support import (
    RunnerWithCleanLogs,
    home_check,
)

from hal import alarm_commands, cli, migrate_commands
from hal.backup.runner import RUN_MARK_SUFFIX, STAGING_PREFIX
from hal.backup.settings import Settings
from hal.grammar import ExitCode
from hal.output import DETAIL_INDENT
from hal.output.command import Verb, command
from hal.stack import apply, switches
from hal.workstation import backup_check, state_move
from hal.workstation import ports as home_ports
from hal.workstation.layout import Layout

AGAIN = f"next: {command(Verb.MIGRATE, 'state')}"


def backup_settings(home: Path) -> Settings:
    return Settings.for_home(home, os.getuid(), os.getgid())


def lock_names() -> tuple[str, ...]:
    return (apply.APPLY_LOCK, switches.LOCK_FILE, backup_settings(Path()).lock_file.name)


def hal_state(home: Path) -> Path:
    return Layout(home).hal_state_dir


def hal_cache(home: Path) -> Path:
    return backup_settings(home).work_dir


def sources_and_targets(home: Path) -> tuple[tuple[Path, Path], ...]:
    return (
        (home / state_move.OLD_STATE, hal_state(home)),
        (home / state_move.OLD_HOME_STATE, hal_state(home)),
        (home / state_move.OLD_CACHE, hal_cache(home)),
    )


def plant(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return path


def plant_every_source(home: Path) -> dict[str, tuple[str, int]]:
    """Each old directory as old code left it, locks included; returns the union the move makes,
    path below home -> (text, inode)."""
    old_state, old_home_state, old_cache = (source for source, _ in sources_and_targets(home))
    planted = (
        plant(old_state / switches.GLOBAL_STOP_FILE, "2026-11-03T20:00:00+01:00\n"),
        plant(old_state / switches.STOPPED_DIRECTORY / "hopin", "2026-11-02T09:00:00+01:00\n"),
        plant(old_state / "deployed" / "presentator", "v12\n"),
        plant(old_state / "applied.json", "{}\n"),
        plant(old_home_state / "secrets-report.md", "# secrets\n"),
        plant(old_cache / f"{STAGING_PREFIX}killed" / "db" / "db.dump", "plaintext\n"),
        plant(old_cache / f"{STAGING_PREFIX}killed{RUN_MARK_SUFFIX}", ""),
    )
    for name in lock_names():
        plant(old_state / name, "")
    union = {}
    for path in planted:
        source, target = next(
            (s, t) for s, t in sources_and_targets(home) if path.is_relative_to(s)
        )
        moved = target / path.relative_to(source)
        union[moved.relative_to(home).as_posix()] = (path.read_text(), path.stat().st_ino)
    return union


def tree(home: Path) -> dict[str, tuple[str, int]]:
    """Every file below the old and the new directories, path below home -> (text, inode); the lock
    files in hal's state directory are left out, the mover takes them as hal's code does."""
    files = {}
    roots = {root for pair in sources_and_targets(home) for root in pair}
    for root in roots:
        for path in root.rglob("*") if root.exists() else ():
            if path.is_file() and not (
                path.parent == hal_state(home) and path.name in lock_names()
            ):
                files[path.relative_to(home).as_posix()] = (path.read_text(), path.stat().st_ino)
    return files


def directories(home: Path) -> set[str]:
    roots = {root for pair in sources_and_targets(home) for root in pair}
    found = {root for root in roots if root.is_dir()}
    found |= {path for root in found for path in root.rglob("*") if path.is_dir()}
    return {path.relative_to(home).as_posix() for path in found}


def old_directories_left(home: Path) -> list[Path]:
    return [source for source, _ in sources_and_targets(home) if source.exists()]


def plan_rows(out: str) -> dict[tuple[str, str], set[str]]:
    """The rows of the plan shown before `Type yes`, (subject, event) -> the names below it."""
    rows: dict[tuple[str, str], set[str]] = {}
    names: set[str] = set()
    for line in out.partition("Type yes")[0].splitlines():
        if line.startswith(DETAIL_INDENT):
            names.add(line.strip())
            continue
        columns = re.split(r"\s{2,}", line.strip())
        if len(columns) > 1:
            names = rows.setdefault((columns[0].split()[1], columns[1]), set())
    return rows


def shown(home: Path, path: Path) -> str:
    return f"~/{path.relative_to(home).as_posix()}"


@pytest.fixture
def migrate(capsys, monkeypatch) -> Callable[..., tuple[int, str, str]]:
    """`hal migrate state` through `hal.cli.main` at a terminal where the person types `yes`
    unless told otherwise: the exit code and both streams."""
    terminal = [True]
    monkeypatch.setattr(migrate_commands, "at_terminal", lambda: terminal[0])

    def run(
        *arguments: str, answer: str | None = "yes", at_terminal: bool = True, while_waiting=None
    ):
        terminal[:] = [at_terminal]
        type_at_prompt(monkeypatch, answer, while_waiting)
        code = cli.main(["migrate", "state", *arguments])
        captured = capsys.readouterr()
        return code, captured.out, captured.err

    return run


class Steps:
    """Every `link`, `unlink`, `rmdir` and `mkdir` of the run after the yes, numbered from 0:
    `before(step)` runs ahead of each, `after(step)` after each that did not raise."""

    def __init__(self) -> None:
        self.armed = False
        self.count = 0
        self.before: Callable[[int], None] = lambda _step: None
        self.after: Callable[[int], None] = lambda _step: None

    def arm(self) -> None:
        self.armed = True

    def wrap(self, function: Callable) -> Callable:
        def stepped(*arguments, **options):
            if not self.armed:
                return function(*arguments, **options)
            step, self.count = self.count, self.count + 1
            self.before(step)
            result = function(*arguments, **options)
            self.after(step)
            return result

        return stepped


@pytest.fixture
def steps(monkeypatch) -> Steps:
    recorder = Steps()
    for name in ("link", "unlink", "rmdir", "mkdir"):
        monkeypatch.setattr(os, name, recorder.wrap(getattr(os, name)))
    return recorder


def fail_at(step: int) -> Callable[[int], None]:
    def before(current: int) -> None:
        if current == step:
            raise OSError(errno.EIO, "injected failure")

    return before


# --- M1: the plan, the refusals before the yes, and the one yes ------------------------------


def test_a_dry_run_shows_every_source_and_changes_nothing(home, migrate):
    plant_every_source(home)
    before, before_directories = tree(home), directories(home)

    code, out, err = migrate("--dry-run")

    assert (code, err) == (ExitCode.OK, "")
    assert (tree(home), directories(home)) == (before, before_directories)
    rows = plan_rows(out)
    for source, _ in sources_and_targets(home):
        assert (shown(home, source), "move") in rows
    assert switches.GLOBAL_STOP_FILE in rows[(shown(home, home / state_move.OLD_STATE), "move")]
    assert set(lock_names()) == rows[(shown(home, home / state_move.OLD_STATE), "close")]


def test_without_a_terminal_it_refuses_with_exit_4_and_changes_nothing(home, migrate):
    plant_every_source(home)
    before, before_directories = tree(home), directories(home)

    code, _, err = migrate(at_terminal=False)

    assert code == ExitCode.REFUSED
    assert err.splitlines()[-1] == AGAIN
    assert (tree(home), directories(home)) == (before, before_directories)


@pytest.mark.parametrize("answer", ["no", "", "Yes", None])
def test_an_answer_other_than_yes_changes_nothing_and_exits_1(home, migrate, answer):
    plant_every_source(home)
    before, before_directories = tree(home), directories(home)

    code, _, _ = migrate(answer=answer)

    assert code == ExitCode.FINDINGS
    assert (tree(home), directories(home)) == (before, before_directories)


def test_one_yes_merges_every_source_into_hals_directories_keeping_each_inode(home, migrate):
    union = plant_every_source(home)

    code, out, err = migrate()

    assert (code, err) == (ExitCode.OK, "")
    assert tree(home) == union
    assert old_directories_left(home) == []
    assert out.splitlines()[-1] == f"next: {command(Verb.SETUP)}"


# --- M2: the two lock domains ----------------------------------------------------------------


@contextmanager
def held(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_WRONLY, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("domain", ["old", "hal"])
@pytest.mark.parametrize("lock", range(3), ids=lambda index: lock_names()[index])
def test_a_held_lock_refuses_names_the_lock_and_creates_nothing_in_the_old_state(
    home, migrate, domain, lock
):
    plant_every_source(home)
    directory = home / state_move.OLD_STATE if domain == "old" else hal_state(home)
    held_lock = directory / lock_names()[lock]
    before, before_directories = (
        tree(home),
        directories(home) | {hal_state(home).relative_to(home).as_posix()},
    )

    with held(held_lock):
        code, _, err = migrate()

    assert code == ExitCode.REFUSED
    assert str(held_lock) in err.replace("~", str(home))
    assert tree(home) == before
    assert directories(home) <= before_directories


def test_a_second_mover_is_refused_while_the_first_holds_the_locks(home, migrate, steps):
    union = plant_every_source(home)
    second = []

    def run_the_second_mover(step: int) -> None:
        if step == 0:
            steps.armed = False
            second.append(cli.main(["migrate", "state"]))
            steps.armed = True

    steps.before = run_the_second_mover
    code, _, _ = migrate(while_waiting=steps.arm)

    assert second == [ExitCode.REFUSED]
    assert code == ExitCode.OK
    assert tree(home) == union


def test_a_mover_whose_plan_another_mover_finished_meanwhile_ends_clean(home, migrate):
    union = plant_every_source(home)
    started, finished = [], []

    def finish_with_another_mover() -> None:
        if not started:
            started.append(True)
            finished.append(cli.main(["migrate", "state"]))

    code, _, _ = migrate(while_waiting=finish_with_another_mover)

    assert (finished, code) == ([ExitCode.OK], ExitCode.OK)
    assert tree(home) == union
    assert old_directories_left(home) == []


def test_a_missing_old_lock_is_never_created(home, migrate):
    plant(home / state_move.OLD_STATE / "applied.json", "{}\n")

    code, _, _ = migrate()

    assert code == ExitCode.OK
    assert not (home / state_move.OLD_STATE).exists()


# --- M3: collisions ---------------------------------------------------------------------------


def test_a_file_in_both_places_keeps_the_target_and_the_plan_names_the_source_remove(home, migrate):
    source = plant(home / state_move.OLD_STATE / "applied.json", "old\n")
    target = plant(hal_state(home) / "applied.json", "new\n")

    code, out, _ = migrate()

    assert code == ExitCode.OK
    assert plan_rows(out)[(shown(home, home / state_move.OLD_STATE), "remove")] == {"applied.json"}
    assert target.read_text() == "new\n"
    assert not source.exists()


def test_a_name_in_both_old_directories_moves_the_first_copy_and_removes_the_second(home, migrate):
    first = plant(home / state_move.OLD_STATE / "applied.json", "first\n")
    second = plant(home / state_move.OLD_HOME_STATE / "applied.json", "second\n")

    code, out, _ = migrate()

    assert code == ExitCode.OK
    assert plan_rows(out)[(shown(home, home / state_move.OLD_HOME_STATE), "remove")] == {
        "applied.json"
    }
    assert (hal_state(home) / "applied.json").read_text() == "first\n"
    assert not first.exists()
    assert not second.exists()
    assert old_directories_left(home) == []


def test_a_stop_names_the_entry_that_failed(home, migrate, monkeypatch):
    source = plant(home / state_move.OLD_STATE / "applied.json", "old\n")

    def refuse(path, *_arguments, **_options):
        raise OSError(errno.EIO, "injected failure", path)

    monkeypatch.setattr(os, "link", refuse)

    code, _, err = migrate()

    assert code == ExitCode.FAILURE
    assert shown(home, source) in err
    assert err.splitlines()[-1] == AGAIN


def test_directories_in_both_places_are_merged_entry_by_entry(home, migrate):
    old_stopped = home / state_move.OLD_STATE / switches.STOPPED_DIRECTORY
    plant(old_stopped / "hopin", "old hopin\n")
    plant(old_stopped / "radio", "old radio\n")
    hal_stopped = hal_state(home) / switches.STOPPED_DIRECTORY
    plant(hal_stopped / "hopin", "new hopin\n")
    inode = hal_stopped.stat().st_ino

    code, _, _ = migrate()

    assert code == ExitCode.OK
    assert {path.name: path.read_text() for path in hal_stopped.iterdir()} == {
        "hopin": "new hopin\n",
        "radio": "old radio\n",
    }
    assert hal_stopped.stat().st_ino == inode


@pytest.mark.parametrize("directory_side", ["old", "hal"])
def test_a_file_against_a_directory_is_refused_before_anything_moves(home, migrate, directory_side):
    plant_every_source(home)
    old, new = home / state_move.OLD_STATE / "deployed", hal_state(home) / "deployed"
    if directory_side == "old":
        plant(new, "a file where the old state has a directory\n")
    else:
        for path in old.iterdir():
            path.unlink()
        old.rmdir()
        plant(old, "a file where hal has a directory\n")
        plant(new / "presentator", "v13\n")
    before = tree(home)

    code, _, err = migrate()

    assert code == ExitCode.REFUSED
    assert "deployed" in err
    assert tree(home) == before


def test_an_old_name_that_is_no_directory_is_refused(home, migrate):
    plant(home / state_move.OLD_CACHE, "a file under the old name of the cache\n")
    before = tree(home)

    code, _, err = migrate()

    assert code == ExitCode.REFUSED
    assert str(home / state_move.OLD_CACHE) in err
    assert tree(home) == before


def test_an_old_directory_that_cannot_be_read_stops_the_plan_and_changes_nothing(home, migrate):
    union = plant_every_source(home)
    unreadable = home / state_move.OLD_STATE / switches.STOPPED_DIRECTORY
    unreadable.chmod(0)
    try:
        code, _, err = migrate()
    finally:
        unreadable.chmod(0o700)

    assert code == ExitCode.FAILURE
    assert err.splitlines()[-1] == AGAIN
    assert migrate()[0] == ExitCode.OK
    assert tree(home) == union


def test_a_target_published_after_the_plan_stays_and_the_rerun_removes_the_source(home, migrate):
    source = plant(home / state_move.OLD_STATE / "applied.json", "old\n")
    published = hal_state(home) / "applied.json"

    code, _, err = migrate(while_waiting=lambda: plant(published, "published\n"))

    assert code == ExitCode.FAILURE
    assert err.splitlines()[-1] == AGAIN
    assert published.read_text() == "published\n"
    assert migrate()[0] == ExitCode.OK
    assert published.read_text() == "published\n"
    assert not source.exists()


def test_a_copy_that_vanishes_after_the_plan_leaves_its_remove_source_for_the_rerun(home, migrate):
    edge = plant(home / state_move.OLD_STATE / "z", "edge\n")
    kept = plant(home / state_move.OLD_HOME_STATE / "z", "home\n")

    code, _, err = migrate(while_waiting=edge.unlink)

    assert code == ExitCode.FAILURE
    assert err.splitlines()[-1] == AGAIN
    assert kept.read_text() == "home\n"
    assert migrate()[0] == ExitCode.OK
    assert (hal_state(home) / "z").read_text() == "home\n"


def test_a_target_that_vanishes_after_the_plan_leaves_its_remove_source_for_the_rerun(
    home, migrate
):
    target = plant(hal_state(home) / "z", "target\n")
    source = plant(home / state_move.OLD_STATE / "z", "edge\n")

    code, _, err = migrate(while_waiting=target.unlink)

    assert code == ExitCode.FAILURE
    assert err.splitlines()[-1] == AGAIN
    assert source.read_text() == "edge\n"
    assert migrate()[0] == ExitCode.OK
    assert (hal_state(home) / "z").read_text() == "edge\n"


def test_a_crash_between_link_and_unlink_is_finished_by_the_rerun(home, migrate, steps):
    source = plant(home / state_move.OLD_STATE / "applied.json", "old\n")
    inode = source.stat().st_ino
    first_unlink = []

    def crash_at_the_first_unlink(_step: int) -> None:
        if source.exists() and (hal_state(home) / "applied.json").exists() and not first_unlink:
            first_unlink.append(True)
            raise OSError(errno.EIO, "injected crash")

    steps.before = crash_at_the_first_unlink
    code, _, _ = migrate(while_waiting=steps.arm)
    steps.armed = False

    assert code == ExitCode.FAILURE
    assert (hal_state(home) / "applied.json").stat().st_ino == inode == source.stat().st_ino
    rerun, out, _ = migrate()
    assert rerun == ExitCode.OK
    assert plan_rows(out)[(shown(home, home / state_move.OLD_STATE), "remove")] == {"applied.json"}
    assert (hal_state(home) / "applied.json").stat().st_ino == inode
    assert not source.exists()


# --- M4: a stop at any step, and the reruns ---------------------------------------------------


def test_a_failure_at_any_step_is_finished_by_the_rerun_without_losing_an_entry(
    tmp_path, monkeypatch, migrate, steps
):
    """One of the stops leaves the old state gone and home's left: the rerun moves the rest."""
    failed_steps, old_state_gone_home_left = 0, 0
    while True:
        home = tmp_path / f"stopped-at-{failed_steps}"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        union = plant_every_source(home)
        steps.armed, steps.count, steps.before = False, 0, fail_at(failed_steps)
        code, _, err = migrate(while_waiting=steps.arm)
        steps.armed = False
        if steps.count <= failed_steps:
            assert code == ExitCode.OK
            break
        if code == ExitCode.FAILURE:
            assert err.splitlines()[-1] == AGAIN
            left = old_directories_left(home)
            old_state_gone_home_left += (
                home / state_move.OLD_HOME_STATE in left and home / state_move.OLD_STATE not in left
            )
            assert migrate()[0] == ExitCode.OK, failed_steps
        else:
            assert code == ExitCode.OK, (
                err
            )  # `mkdir -p` of a directory that exists ignores its error
        assert tree(home) == union, failed_steps
        assert old_directories_left(home) == []
        failed_steps += 1
    assert failed_steps > len(union)
    assert old_state_gone_home_left > 0


def test_with_no_source_left_there_is_nothing_to_move(home, migrate):
    code, out, err = migrate()

    assert (code, err) == (ExitCode.OK, "")
    assert "nothing to move" in out
    assert "Type yes" not in out


def test_an_old_state_holding_only_lock_files_is_closed(home, migrate):
    for name in lock_names():
        plant(home / state_move.OLD_STATE / name, "")

    code, _, _ = migrate()

    assert code == ExitCode.OK
    assert old_directories_left(home) == []


# --- M5: the global stop at every step --------------------------------------------------------


def markers(home: Path) -> tuple[Path, Path]:
    return (
        home / state_move.OLD_STATE / switches.GLOBAL_STOP_FILE,
        switches.default_state_directory() / switches.GLOBAL_STOP_FILE,
    )


@pytest.mark.parametrize("planted_at", ["old", "hal", "both"])
def test_the_global_stop_is_at_one_of_its_paths_at_every_step(home, migrate, steps, planted_at):
    plant_every_source(home)
    old_marker, hal_marker = markers(home)
    if planted_at == "hal":
        old_marker.unlink()
    if planted_at in {"hal", "both"}:
        plant(hal_marker, "2026-11-03T21:00:00+01:00\n")
    unguarded = []
    steps.after = lambda step: (
        unguarded.append(step) if not (old_marker.exists() or hal_marker.exists()) else None
    )

    code, _, _ = migrate(while_waiting=steps.arm)

    assert code == ExitCode.OK
    assert steps.count > 0
    assert unguarded == []
    assert hal_marker.exists()


@pytest.mark.parametrize("stopped_at", ["old", "hal"])
def test_a_lock_free_stop_between_two_steps_keeps_a_marker_and_a_hit_source_fails_loud(
    tmp_path, monkeypatch, migrate, steps, stopped_at
):
    stop_step = 0
    while True:
        home = tmp_path / f"stop-at-{stop_step}"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        plant_every_source(home)
        old_marker, hal_marker = markers(home)
        written = markers(home)[0 if stopped_at == "old" else 1]
        unguarded, hit = [], []

        def stop_lock_free(step: int, written=written, hit=hit, stop_step=stop_step) -> None:
            if step == stop_step and written.parent.exists():
                hit.append(written.exists())
                written.write_text("2026-11-03T22:00:00+01:00\n")

        steps.armed, steps.count, steps.before = False, 0, stop_lock_free
        steps.after = lambda step, old=old_marker, new=hal_marker, seen=unguarded: (
            seen.append(step) if not (old.exists() or new.exists()) else None
        )
        code, _, err = migrate(while_waiting=steps.arm)
        steps.armed = False
        if steps.count <= stop_step:
            break
        assert unguarded == [], stop_step
        assert old_marker.exists() or hal_marker.exists(), stop_step
        if hit == [False]:
            assert code == ExitCode.FAILURE, stop_step
            assert err.splitlines()[-1] == AGAIN
        if code == ExitCode.FAILURE:
            assert migrate()[0] == ExitCode.OK, stop_step
        assert hal_marker.exists(), stop_step
        stop_step += 1


# --- M6, M9, M10 ------------------------------------------------------------------------------


def test_a_writer_holding_hals_state_directory_writes_into_it_across_the_move(home, migrate):
    plant_every_source(home)
    state = hal_state(home)
    state.mkdir(parents=True)
    inode = state.stat().st_ino
    descriptor = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
    try:
        code, _, _ = migrate()
        report = os.open("check-report.md", os.O_WRONLY | os.O_CREAT, 0o600, dir_fd=descriptor)
        os.write(report, b"# report\n")
        os.close(report)
    finally:
        os.close(descriptor)

    assert code == ExitCode.OK
    assert (state / "check-report.md").read_text() == "# report\n"
    assert state.stat().st_ino == inode


def test_the_staging_of_a_killed_run_in_the_old_cache_is_swept_by_the_next_backup(
    edge_backup, machine, home, migrate
):
    killed = home / state_move.OLD_CACHE / f"{STAGING_PREFIX}killed"
    plant(killed / "db" / "db.dump", "plaintext\n")
    plant(killed.with_name(killed.name + RUN_MARK_SUFFIX), "")
    assert migrate()[0] == ExitCode.OK

    outcome = edge_backup("backup")

    assert outcome.exit_code == ExitCode.OK, outcome.err
    assert list(hal_cache(home).iterdir()) == []
    assert not (home / state_move.OLD_CACHE).exists()


def test_a_backup_on_a_scratch_home_never_creates_the_old_state(edge_backup, machine, home):
    """M8, the backup's part; the stack's is in tests/test_workstation_state_move_owners.py."""
    outcome = edge_backup("backup")

    assert outcome.exit_code == ExitCode.OK, outcome.err
    assert old_directories_left(home) == []


def test_records_of_hal_apply_stay_and_stale_copies_are_named_and_kept_on_no(home, migrate):
    records = plant(hal_state(home) / "applied.json", "written by hal apply\n")
    plant(home / state_move.OLD_STATE / "applied.json", "written before the rename\n")
    current_report = plant(Layout(home).check_report_file, "current\n")
    plant(home / state_move.OLD_HOME_STATE / current_report.name, "stale\n")
    before = tree(home)

    code, out, _ = migrate(answer="no")

    assert code == ExitCode.FINDINGS
    assert tree(home) == before
    rows = plan_rows(out)
    assert rows[(shown(home, home / state_move.OLD_STATE), "remove")] == {"applied.json"}
    assert rows[(shown(home, home / state_move.OLD_HOME_STATE), "remove")] == {current_report.name}
    assert migrate()[0] == ExitCode.OK
    assert (records.read_text(), current_report.read_text()) == (
        "written by hal apply\n",
        "current\n",
    )
    assert old_directories_left(home) == []


# --- M7: the timers between `hal update` and the move -----------------------------------------


@pytest.mark.usefixtures("quiet_pc")
def test_unmoved_backup_state_is_a_finding_the_alarm_counts_at_its_second_run_and_the_move_clears(
    clean_home, mail_stub, migrate, monkeypatch
):
    runner = RunnerWithCleanLogs()
    monkeypatch.setattr(
        alarm_commands,
        "build_layout_and_ports",
        lambda: home_ports.build_layout_and_ports(home=clean_home, run=runner),
    )
    status = clean_home / backup_check.STATUS_FILE
    plant(clean_home / state_move.OLD_STATE / status.name, status.read_text())
    status.unlink()

    assert cli.main(["alarm"]) == ExitCode.OK
    assert mail_stub.sent == []
    assert cli.main(["alarm"]) == ExitCode.OK
    assert len(mail_stub.sent) == 1
    assert home_check(clean_home, runner) == ExitCode.FINDINGS
    assert backup_check.STATUS_SUBJECT in Layout(clean_home).check_report_file.read_text()

    assert migrate()[0] == ExitCode.OK
    assert cli.main(["alarm"]) == ExitCode.OK
    assert home_check(clean_home, runner) == ExitCode.OK
