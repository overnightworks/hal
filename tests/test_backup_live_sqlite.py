"""`hal restore presentator --live`: the script's `load` against real database files
without Docker, then the door on the scripted Docker host."""

import hashlib
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
from collections.abc import Callable
from contextlib import closing, contextmanager
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

import pytest
import yaml
from support.backup_support import (
    SQLITE_COPY,
    SQLITE_TOML,
    Machine,
    declare_apps,
    exit_with,
    mount_source,
)
from support.live_restore_support import (
    squeezed,
    switch_lock_is_held,
    switch_off,
    work_directory,
)
from support.terminal_support import type_at_prompt

from hal.backup import host, sqlite_copy
from hal.backup.docker import SQLITE_LOAD_LABEL, VOLUME_USERS_LABEL
from hal.backup.sqlite_copy import LoadExit
from hal.stack import compose, switches, terminal

KILLED_WRITER = """
import os, signal, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], isolation_level=None)
if sys.argv[2] == "committed":
    connection.execute("PRAGMA wal_autocheckpoint=0")
    connection.execute("INSERT INTO users (name) VALUES ('committed, never checkpointed')")
else:
    connection.execute("PRAGMA cache_size=1")
    connection.execute("BEGIN")
    connection.execute("UPDATE decks SET title = hex(randomblob(2000))")
os.kill(os.getpid(), signal.SIGKILL)
"""


def _generation(
    path: Path, generation: str, *, journal: str = "wal", page_size: int = 4096
) -> Path:
    """Two tables whose every value names the generation, so two generations never share a row."""
    connection = sqlite3.connect(path, isolation_level=None)
    connection.execute(f"PRAGMA page_size={page_size}")
    connection.execute(f"PRAGMA journal_mode={journal}")
    connection.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    connection.execute("CREATE TABLE decks (id INTEGER PRIMARY KEY, title TEXT, version INTEGER)")
    rows = 40 if generation == "old" else 25
    connection.executemany(
        "INSERT INTO users (name) VALUES (?)", [(f"{generation}-user-{n}",) for n in range(rows)]
    )
    connection.executemany(
        "INSERT INTO decks (title, version) VALUES (?, ?)",
        [(f"{generation}-deck-{n}-" + "x" * 900, n) for n in range(rows * 3)],
    )
    connection.close()
    return path


def _dump(path: Path) -> list[str]:
    """The whole logical content, every table and row, read through a fresh connection."""
    with closing(sqlite3.connect(path)) as connection:
        return list(connection.iterdump())


@dataclass(frozen=True)
class _Staged:
    file: Path
    content: list[str]

    def arguments(self, live: Path, table: str = "users") -> list[str]:
        data = self.file.read_bytes()
        return ["load", str(self.file), str(len(data)), hashlib.sha256(data).hexdigest(),
                str(live), table]  # fmt: skip


def _staged(tmp_path: Path, *, page_size: int = 4096) -> _Staged:
    """The `copy` of a WAL source whose last rows are committed and not checkpointed."""
    source = _generation(tmp_path / "source.sqlite3", "new", page_size=page_size)
    with closing(sqlite3.connect(source, isolation_level=None)) as writer:
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("INSERT INTO users (name) VALUES ('new-user-only-in-the-wal')")
        staged = tmp_path / "staged"
        staged.mkdir()
        file = staged / "db.sqlite3"
        file.write_bytes(sqlite_copy.copy(source))
        assert (source.with_name("source.sqlite3-wal")).stat().st_size > 0
        return _Staged(file, _dump(source))


def _live(tmp_path: Path, **options) -> Path:
    volume = tmp_path / "volume"
    volume.mkdir()
    return _generation(volume / "presentator.sqlite3", "old", **options)


def _load(capsys, arguments: list[str]) -> tuple[int, str]:
    code = sqlite_copy.main(arguments)
    return code, capsys.readouterr().out


def _killed_writer(live: Path, mode: str) -> None:
    writer = subprocess.run(
        [sys.executable, "-I", "-c", KILLED_WRITER, str(live), mode], check=False
    )
    assert writer.returncode == -signal.SIGKILL


def test_a_load_writes_the_staged_copy_whole_and_leaves_the_copy_as_it_was(tmp_path, capsys):
    staged = _staged(tmp_path)
    before = staged.file.read_bytes()
    live = _live(tmp_path)

    code, out = _load(capsys, staged.arguments(live))

    assert (code, out) == (0, "26\n")
    assert _dump(live) == staged.content
    assert staged.file.read_bytes() == before
    assert sorted(path.name for path in staged.file.parent.iterdir()) == ["db.sqlite3"]
    assert before[18:20] == b"\x02\x02"  # the copy of a WAL source is a WAL-format image


def test_a_load_over_stale_wal_frames_of_a_killed_writer_keeps_the_files_identity(tmp_path, capsys):
    staged = _staged(tmp_path)
    live = _live(tmp_path)
    _killed_writer(live, "committed")
    assert live.with_name(live.name + "-wal").stat().st_size > 0
    assert live.with_name(live.name + "-shm").exists()
    identity = live.stat()

    code, _ = _load(capsys, staged.arguments(live))

    assert code == 0
    assert _dump(live) == staged.content
    after = live.stat()
    assert (after.st_ino, after.st_uid, after.st_gid, after.st_mode) == (
        identity.st_ino, identity.st_uid, identity.st_gid, identity.st_mode,
    )  # fmt: skip
    with closing(sqlite3.connect(live)) as connection:
        assert connection.execute("PRAGMA journal_mode").fetchone() == ("wal",)


def test_a_load_over_a_hot_rollback_journal_writes_the_staged_copy(tmp_path, capsys):
    staged = _staged(tmp_path)
    live = _live(tmp_path, journal="delete")
    old = _dump(live)
    old_bytes = live.read_bytes()
    _killed_writer(live, "spilled")
    journal = live.with_name(live.name + "-journal")
    assert journal.stat().st_size > 0
    assert live.read_bytes() != old_bytes  # the killed transaction reached the file itself
    control = tmp_path / "control"
    control.mkdir()
    shutil.copy2(live, control / live.name)
    shutil.copy2(journal, control / journal.name)
    assert _dump(control / live.name) == old  # SQLite rolls the hot journal back when read

    code, _ = _load(capsys, staged.arguments(live))

    assert code == 0
    assert _dump(live) == staged.content
    assert not journal.exists()


def _cut_short(staged: _Staged, arguments: list[str]) -> list[str]:
    staged.file.write_bytes(staged.file.read_bytes()[:-4096])
    return arguments


def _corrupted(staged: _Staged, arguments: list[str]) -> list[str]:
    data = bytearray(staged.file.read_bytes())
    data[len(data) // 2 : len(data) // 2 + 4096] = b"\xff" * 4096
    staged.file.write_bytes(data)
    return staged.arguments(Path(arguments[4]))


@pytest.mark.parametrize(
    ("spoil", "page_size"),
    [
        (lambda staged, arguments: [*arguments[:2], "1", *arguments[3:]], 4096),
        (lambda staged, arguments: [*arguments[:3], "0" * 64, *arguments[4:]], 4096),
        (_cut_short, 4096),
        (_corrupted, 4096),
        (lambda staged, arguments: arguments, 8192),
        (
            lambda staged, arguments: [*arguments[:4], arguments[4] + ".missing", *arguments[5:]],
            4096,
        ),
    ],
    ids=["size", "sha256", "a copy cut short", "integrity", "page size", "a missing live file"],
)
def test_a_refusal_before_the_copy_began_leaves_the_live_content_unchanged(
    tmp_path, capsys, spoil, page_size
):
    staged = _staged(tmp_path, page_size=page_size)
    live = _live(tmp_path)
    old = _dump(live)

    code, out = _load(capsys, spoil(staged, staged.arguments(live)))

    assert (code, out) == (sqlite_copy.LoadExit.REFUSED, "")
    assert _dump(live) == old
    assert [path.name for path in live.parent.iterdir()] == [live.name]


def test_a_live_file_another_writer_holds_is_refused_as_busy_before_the_copy(
    tmp_path, capsys, monkeypatch
):
    monkeypatch.setattr(sqlite_copy, "BUSY_SECONDS", 0.1)
    staged = _staged(tmp_path)
    live = _live(tmp_path)
    old = _dump(live)

    with closing(sqlite3.connect(live, isolation_level=None)) as writer:
        writer.execute("BEGIN IMMEDIATE")
        code, out = _load(capsys, staged.arguments(live))
        writer.execute("ROLLBACK")

    assert (code, out) == (sqlite_copy.LoadExit.BUSY, "")
    assert _dump(live) == old


def _reader_holding(live: Path) -> sqlite3.Connection:
    """A read transaction: it lets the copy begin and blocks its commit in a rollback journal."""
    reader = sqlite3.connect(live, isolation_level=None)
    reader.execute("BEGIN")
    reader.execute("SELECT count(*) FROM users").fetchone()
    return reader


def _unwritable_directory(live: Path) -> None:
    """No journal can be created beside the file once the copy begins to write."""
    live.parent.chmod(0o555)


@pytest.mark.parametrize("fault", ["busy at the commit", "no journal"])
def test_a_failure_once_the_copy_began_is_unfinished_and_leaves_old_or_new(
    tmp_path, capsys, monkeypatch, fault
):
    monkeypatch.setattr(sqlite_copy, "BUSY_SECONDS", 0.1)
    staged = _staged(tmp_path)
    live = _live(tmp_path, journal="delete")
    old = _dump(live)
    reader = _reader_holding(live) if fault == "busy at the commit" else None
    if reader is None:
        _unwritable_directory(live)
    try:
        code, out = _load(capsys, staged.arguments(live))
    finally:
        live.parent.chmod(0o755)
        if reader is not None:
            reader.close()

    assert (code, out) == (sqlite_copy.LoadExit.UNFINISHED, "")
    assert _dump(live) in (old, staged.content)


def test_a_check_after_the_load_that_fails_is_its_own_exit(tmp_path, capsys):
    staged = _staged(tmp_path)
    live = _live(tmp_path)

    code, out = _load(capsys, staged.arguments(live, table="no_such_table"))

    assert (code, out) == (sqlite_copy.LoadExit.UNCHECKED, "")
    assert _dump(live) == staged.content


def test_the_owner_of_a_path_that_is_no_regular_file_is_refused(tmp_path):
    assert sqlite_copy.main(["owner", str(tmp_path)]) == sqlite_copy.VERDICT_EXIT


# The door, on the scripted Docker host: the loader and the containers on the volume answer here.

APP = "presentator"
VOLUME = "presentator_database"
COMPOSE_FILE = compose.REPOSITORY / "compose.yaml"


@dataclass
class _Loader:
    """The loader's container and `docker ps` of the volume; every other label goes to the
    machine. `held` records whether the switch lock was held at each of them."""

    machine: Machine
    home: Path
    volume_users: list[str] = field(default_factory=list)
    """The states of the containers that mount the volume."""
    volume_answer: bytes | int | None = None
    """What `docker ps` of the volume prints instead, or the exit it fails with."""
    exit_code: int = 0
    output: bytes | None = None
    """What the loader prints instead of the staged copy's rows."""
    during: Callable[[], None] | None = None
    loads: list[list[str]] = field(default_factory=list)
    new_session: list[bool] = field(default_factory=list)
    staged: list[bytes] = field(default_factory=list)
    """The bytes of each load's staged copy, as its mount shows them."""
    held: list[tuple[str, bool]] = field(default_factory=list)

    def run(self, argv, *, label: str, **options) -> bytes:
        if label not in (VOLUME_USERS_LABEL, SQLITE_LOAD_LABEL):
            return self.machine.run(argv, label=label, **options)
        self.held.append((label, switch_lock_is_held(self.home)))
        if label == VOLUME_USERS_LABEL:
            return self._volume_users()
        self.loads.append(list(argv))
        self.new_session.append(options.get("new_session", False))
        staged = Path(mount_source(argv, argv[argv.index("load") + 1])).read_bytes()
        self.staged.append(staged)
        if self.during:
            self.during()
        if self.exit_code:
            return exit_with(label, self.exit_code)
        rows = re.fullmatch(rb"SQLite rows=(\d+)", staged)
        return self.output if self.output is not None else rows[1] + b"\n"

    def _volume_users(self) -> bytes:
        if isinstance(self.volume_answer, int):
            return exit_with(VOLUME_USERS_LABEL, self.volume_answer)
        if self.volume_answer is not None:
            return self.volume_answer
        lines = [f"{number:064x} {state}" for number, state in enumerate(self.volume_users)]
        return "\n".join(lines).encode()


@pytest.fixture
def loader(machine, home, monkeypatch) -> _Loader:
    scripted = _Loader(machine, home)
    monkeypatch.setattr(host, "run", scripted.run)
    return scripted


@pytest.fixture
def live(edge_backup, machine, loader, home, monkeypatch, restored_signal_handlers):
    """A backup of presentator taken, its unit switched off, a terminal where the operator types
    `yes`; `run` restores it live and returns the outcome."""
    resolved = yaml.safe_load(COMPOSE_FILE.read_text())
    monkeypatch.setattr(compose.Compose, "resolved_configuration", lambda _: resolved)
    monkeypatch.setattr(terminal, "at_terminal", lambda: True)
    machine.other_volumes[APP] = [VOLUME]
    apps = declare_apps(home, SQLITE_TOML)
    assert edge_backup(*apps, "backup", APP).exit_code == 0
    switch_off(home, APP)
    type_at_prompt(monkeypatch, "yes")

    def run(*options: str, declared: tuple[str, str] = apps):
        return edge_backup(*declared, "restore", APP, "--live", *options)

    return run


def _snapshot(machine: Machine) -> str:
    return machine.snapshots[-1]["id"][:8]


def _restored(machine: Machine) -> bool:
    return "restic restore" in machine.labels()


def test_a_loaded_snapshot_names_hal_start_and_the_loader_runs_hardened_as_the_owner(
    live, machine, loader, home
):
    outcome = live()

    assert (outcome.exit_code, outcome.err) == (0, "")
    [row, next_line] = squeezed(outcome.out).splitlines()[-2:]
    assert row.split(": ")[-1].startswith(f"✓ {APP} loaded {_snapshot(machine)} · ")
    assert next_line == f"next: hal start {APP}"
    [argv] = loader.loads
    assert argv[argv.index("--user") + 1] == machine.sqlite_owner.decode().strip()
    assert {"--read-only", "--network", "none", "--cap-drop", "ALL"} <= set(argv)
    mounts = [argv[at + 1] for at, argument in enumerate(argv) if argument == "--mount"]
    live_file = PurePosixPath(argv[-2])
    assert live_file.name == "presentator.sqlite3"
    [volume] = [mount for mount in mounts if f"target={live_file.parent}" in mount]
    assert f"source={VOLUME}," in volume and not volume.endswith(",readonly")
    [staged] = [mount for mount in mounts if f"target={argv[argv.index('load') + 1]}," in mount]
    assert staged.endswith(",readonly")
    [copy] = loader.staged
    at = argv.index("load")
    assert argv[at + 2 : at + 4] == [str(len(copy)), hashlib.sha256(copy).hexdigest()]
    assert loader.new_session == [True]
    assert list(work_directory(home).iterdir()) == []
    assert str(home) not in outcome.out + outcome.err


def test_the_switch_lock_is_held_at_the_recheck_the_proof_and_the_load(
    live, loader, home, monkeypatch
):
    real_changed = switches.Switches.changed

    def watched_changed(self, *arguments):
        loader.held.append(("re-check", switch_lock_is_held(home)))
        return real_changed(self, *arguments)

    monkeypatch.setattr(switches.Switches, "changed", watched_changed)

    assert live().exit_code == 0
    assert loader.held == [
        ("re-check", True),
        (VOLUME_USERS_LABEL, True),
        (SQLITE_LOAD_LABEL, True),
    ]
    assert not switch_lock_is_held(home)


def test_without_a_terminal_it_refuses_and_restores_nothing(live, machine, loader, monkeypatch):
    monkeypatch.setattr(terminal, "at_terminal", lambda: False)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        ["error: restore --live asks yes at a terminal · nothing changed"],
    )
    assert not _restored(machine)
    assert loader.loads == []


@pytest.mark.parametrize("answer", ["no", "", None, "YES"])
def test_anything_but_yes_aborts_and_loads_nothing(live, loader, home, monkeypatch, answer):
    type_at_prompt(monkeypatch, answer)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (1, ["error: aborted, nothing changed"])
    assert loader.loads == []
    assert list(work_directory(home).iterdir()) == []


def test_a_switch_changed_after_the_question_is_refused(live, loader, home, monkeypatch):
    def stop_again():
        switch_off(home, APP).unlink()
        switch_off(home, APP)

    type_at_prompt(monkeypatch, "yes", while_waiting=stop_again)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        4,
        [f"error: {APP}'s switch changed · nothing loaded"],
    )
    assert loader.loads == []


@contextmanager
def _interrupted_on_entry(_):
    raise KeyboardInterrupt
    yield  # pragma: no cover - the generator form of a context manager


@pytest.mark.parametrize("where", ["at the question", "while waiting for the switch lock"])
def test_an_interrupt_before_the_load_loads_nothing_and_removes_the_copy(
    live, loader, home, monkeypatch, where
):
    if where == "at the question":
        type_at_prompt(monkeypatch, KeyboardInterrupt)
    else:
        monkeypatch.setattr(switches.Switches, "lock", _interrupted_on_entry)

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (
        130,
        ["error: interrupted · nothing loaded"],
    )
    assert loader.loads == []
    assert list(work_directory(home).iterdir()) == []


@pytest.mark.parametrize(
    ("owner", "copy", "reason"),
    [
        (
            b"0:0\n",
            SQLITE_COPY,
            "the owner of the database presentator.sqlite3 is unreadable or root",
        ),
        (
            b"1001:1001\n",
            None,
            "SQLite owner read ended with exit 3: presentator.sqlite3 is missing",
        ),
    ],
    ids=["root-owned", "missing or no regular file"],
)
def test_a_live_file_that_is_root_owned_or_missing_is_refused_before_the_question(
    live, machine, loader, owner, copy, reason
):
    machine.sqlite_owner, machine.sqlite_copy = owner, copy

    outcome = live()

    assert outcome.exit_code == 3
    assert outcome.err.startswith(f"error: {APP}: {reason}")
    assert "Type yes" not in outcome.out
    assert not _restored(machine)


@pytest.mark.parametrize(
    ("toml", "replaced", "reason"),
    [
        (SQLITE_TOML, {"db.sqlite3": None}, "the snapshot holds no SQLite database"),
        (SQLITE_TOML, {"db.sqlite3": b"torn"}, "the SQLite copy fails its check"),
        (SQLITE_TOML, {"db.sqlite3": b"SQLite rows=8"}, None),
        (SQLITE_TOML + "require_rows = true\n", {"db.sqlite3": b"SQLite rows=0"}, None),
    ],
    ids=["no copy", "integrity", "rows against the manifest", "require_rows"],
)
def test_a_snapshot_that_fails_its_verification_is_refused_before_the_question(
    live, machine, loader, home, toml, replaced, reason
):
    database = machine.snapshots[-1]["db"]
    for name, content in replaced.items():
        if content is None:
            del database[name]
        else:
            database[name] = content
    if toml.endswith("require_rows = true\n"):
        database["manifest.json"] = database["manifest.json"].replace(b'"rows": 7', b'"rows": 0')

    outcome = live(declared=declare_apps(home, toml))

    assert outcome.exit_code == 3
    assert outcome.err.startswith(f"error: {APP}: ")
    if reason is not None:
        assert outcome.err.splitlines() == [f"error: {APP}: {reason}"]
    assert "Type yes" not in outcome.out
    assert loader.loads == []
    assert list(work_directory(home).iterdir()) == []


@pytest.mark.parametrize(
    ("states", "refused"),
    [
        (["running"], True),
        (["paused"], True),
        (["restarting"], True),
        (["exited", "removing"], True),
        (["exited", "created", "dead"], False),
    ],
    ids=["running", "paused", "restarting", "one of two", "only stopped ones"],
)
def test_a_container_that_is_not_stopped_on_the_volume_refuses_the_load(
    live, loader, states, refused
):
    loader.volume_users = states

    outcome = live()

    if refused:
        assert (outcome.exit_code, outcome.err.splitlines()) == (
            4,
            [
                f"error: a container still uses {APP}'s database · nothing loaded",
                f"next: hal stop {APP}",
            ],
        )
        assert loader.loads == []
    else:
        assert (outcome.exit_code, len(loader.loads)) == (0, 1)


@pytest.mark.parametrize(
    ("answer", "reason"),
    [
        (1, "docker ps of the volume ended with exit 1"),
        (b"running\n", "docker ps printed a line that is no ID and state"),
        (b"\xff\n", "docker printed output that is not UTF-8"),
    ],
    ids=["failed", "no ID", "not UTF-8"],
)
def test_a_proof_that_cannot_be_read_is_refused_never_read_as_none(live, loader, answer, reason):
    loader.volume_answer = answer

    outcome = live()

    assert (outcome.exit_code, outcome.err.splitlines()) == (3, [f"error: {APP}: {reason}"])
    assert loader.loads == []


@pytest.mark.parametrize(
    ("exit_code", "output", "cause"),
    [
        (LoadExit.REFUSED, None, "the copy or the live file does not fit"),
        (LoadExit.BUSY, None, "another connection holds the live database"),
        (LoadExit.UNFINISHED, None, "the copy did not finish"),
        (LoadExit.UNCHECKED, None, "the check after the copy failed"),
        (137, None, "SQLite live load ended with exit 137"),
        (0, b"8\n", "the loaded database counts other rows than the snapshot"),
        (0, b"", "the row count of the loaded database is unreadable"),
    ],
    ids=["refused", "busy", "unfinished", "unchecked", "killed", "other rows", "no count"],
)
def test_a_load_that_did_not_end_as_loaded_says_whether_it_began_and_names_its_rerun(
    live, machine, loader, home, exit_code, output, cause
):
    loader.exit_code, loader.output = exit_code, output
    began = exit_code not in (LoadExit.REFUSED, LoadExit.BUSY)

    outcome = live()

    line = (
        f"error: {APP} load failed · {cause} · it holds the old or the new database · "
        "a rerun loads the snapshot whole"
        if began
        else f"error: {APP} load refused · {cause} · nothing changed"
    )
    assert (outcome.exit_code, outcome.err.splitlines()) == (
        3 if began else 4,
        [line, f"next: hal restore {APP} --live --snapshot {_snapshot(machine)}"],
    )
    assert "loaded" not in outcome.out
    assert list(work_directory(home).iterdir()) == []


class _ClosedPipe:
    """A stdout whose reader went away."""

    def write(self, _text: str) -> int:
        raise BrokenPipeError


def test_a_load_whose_count_cannot_be_printed_after_its_copy_says_old_or_new(
    tmp_path, monkeypatch, live, loader
):
    files = tmp_path / "loader"
    files.mkdir()
    staged = _staged(files)
    live_file = _live(files)
    with monkeypatch.context() as patched:
        patched.setattr(sys, "stdout", _ClosedPipe())
        loader.exit_code = sqlite_copy.main(staged.arguments(live_file))
    assert _dump(live_file) == staged.content

    outcome = live()

    [line, _] = outcome.err.splitlines()
    assert outcome.exit_code == 3
    assert line.startswith(f"error: {APP} load failed · ")
    assert line.endswith(
        " · it holds the old or the new database · a rerun loads the snapshot whole"
    )


def test_an_old_snapshot_with_built_decks_loads_only_its_database(
    live, edge_backup, machine, loader, home
):
    record_with_files = SQLITE_TOML.replace(
        "[app.presentator.restore_test]", 'files_volume = "builds"\n[app.presentator.restore_test]'
    )
    del machine.other_volumes[APP]
    machine.volumes_by_label |= {"database": [VOLUME], "builds": ["presentator_builds"]}
    machine.volume_files["presentator_builds"] = {"deck/index.html": b"<html>"}
    assert edge_backup(*declare_apps(home, record_with_files), "backup", APP).exit_code == 0
    assert machine.snapshots[-1]["volumes"]["builds"]
    database_only = declare_apps(home, SQLITE_TOML)
    target = home / "restored"

    assert live(declared=database_only).exit_code == 0
    assert len(loader.loads) == 1
    assert edge_backup(*database_only, "restore", "--test", APP).exit_code == 0
    assert edge_backup(*database_only, "restore", APP, "--target", str(target)).exit_code == 0
    assert (target / "db" / "db.sqlite3").is_file()
    assert (target / "builds" / "deck" / "index.html").read_bytes() == b"<html>"
