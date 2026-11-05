"""Runs inside the pinned `sqlite` image beside an app's database volume; stdlib only.

It prints a count, an owner or the copy's bytes and nothing else: no row value, no path.
`owner`, `copy` and `check` open read-only and never write or checkpoint a database file. `load`
writes a verified copy into the live file through SQLite's backup API, one write transaction of the
file's own journal or WAL, so the file holds the old or the new database, never a mix; its exit
says whether that transaction began.
"""

import hashlib
import sqlite3
import stat
import sys
from contextlib import ExitStack, closing
from enum import IntEnum
from pathlib import Path

# The script's verdict that the database or copy is bad, and for `load` an error no step of it
# placed; CPython's own exit 1 stays a crash.
VERDICT_EXIT = 3
# How long the load waits for another connection's lock before it gives up.
BUSY_SECONDS = 5.0
_BLOCKED = frozenset({sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED})


class LoadExit(IntEnum):
    """How `load` ended, when not with its count. No value is CPython's 1, the usage 2 or
    `main`'s catch-all `VERDICT_EXIT`, so an error no step of `load` placed never reads as
    unchanged."""

    UNFINISHED = 4  # the copy began and did not finish: SQLite keeps the old or the new content
    UNCHECKED = 5  # the copy is in; the check of the live file after it failed
    BUSY = 6  # another connection held the live file before the copy began: unchanged
    REFUSED = 7  # established before the copy began: the live content is unchanged


class LoadFailed(Exception):
    def __init__(self, exit_code: LoadExit) -> None:
        self.exit_code = exit_code
        super().__init__(exit_code.name)


def owner(database: Path) -> str:
    """`uid:gid` of the regular file, whose user must run the copy to take part as a WAL reader."""
    status = database.stat()
    if not stat.S_ISREG(status.st_mode):
        raise IsADirectoryError(database)
    return f"{status.st_uid}:{status.st_gid}"


def copy(database: Path) -> bytes:
    """One read snapshot taken in one step; a missing file fails instead of being created."""
    with (
        closing(sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True)) as source,
        closing(sqlite3.connect(":memory:")) as snapshot,
    ):
        source.backup(snapshot, pages=-1)
        return snapshot.serialize()


def check(database: Path, table: str) -> int:
    """The row count of a database whose integrity check answers exactly `ok`."""
    with closing(_immutable(database)) as connection:
        return _checked_rows(connection, table)


def load(staged: Path, size: int, sha256: str, live: Path, table: str) -> int:
    """The staged copy, verified against the host's size and digest, written into the live file
    whole; then the live file's row count. A missing live file is refused, never created."""
    with ExitStack() as connections:
        source, destination = _prepared(connections, staged, size, sha256, live)
        try:
            source.backup(destination, pages=-1, progress=_abort_when_blocked)
        except sqlite3.Error as error:
            raise LoadFailed(LoadExit.UNFINISHED) from error
        try:
            return _checked_rows(destination, table)
        except sqlite3.Error as error:
            raise LoadFailed(LoadExit.UNCHECKED) from error


def _prepared(
    connections: ExitStack, staged: Path, size: int, sha256: str, live: Path
) -> tuple[sqlite3.Connection, sqlite3.Connection]:
    """The verified copy and the live file opened, and what SQLite would refuse inside the copy
    established; the copy has not begun, so every failure here is a refusal."""
    try:
        _require_bytes(staged, size, sha256)
        source = connections.enter_context(closing(_immutable(staged)))
        destination = connections.enter_context(
            closing(
                sqlite3.connect(
                    f"{live.as_uri()}?mode=rw", uri=True, timeout=BUSY_SECONDS, isolation_level=None
                )
            )
        )
        _require_intact(source)
        _require_writable(source, destination)
    except (sqlite3.Error, OSError) as error:
        raise LoadFailed(LoadExit.REFUSED) from error
    return source, destination


def _immutable(database: Path) -> sqlite3.Connection:
    return sqlite3.connect(f"{database.as_uri()}?mode=ro&immutable=1", uri=True)


def _checked_rows(connection: sqlite3.Connection, table: str) -> int:
    _require_intact(connection)
    quoted = '"' + table.replace('"', '""') + '"'
    return connection.execute(f"SELECT count(*) FROM {quoted}").fetchone()[0]  # noqa: S608 - the table name is quoted by doubling its quotes


def _require_intact(connection: sqlite3.Connection) -> None:
    if connection.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
        raise sqlite3.DatabaseError("integrity_check")


def _require_bytes(staged: Path, size: int, sha256: str) -> None:
    with staged.open("rb") as file:
        if hashlib.file_digest(file, "sha256").hexdigest() != sha256 or file.tell() != size:
            raise LoadFailed(LoadExit.REFUSED)


def _require_writable(source: sqlite3.Connection, destination: sqlite3.Connection) -> None:
    """What SQLite would refuse only inside the copy, established before it: a WAL file keeps its
    page size (sqlite.org/wal.html), and another connection's write lock. Reading the file first
    lets SQLite recover a hot journal or a stale WAL as at any open."""
    try:
        journal = destination.execute("PRAGMA journal_mode").fetchone()[0]
        page_sizes = {
            connection.execute("PRAGMA page_size").fetchone()[0]
            for connection in (source, destination)
        }
        if journal == "wal" and len(page_sizes) > 1:
            raise LoadFailed(LoadExit.REFUSED)
        destination.execute("BEGIN IMMEDIATE")
        destination.execute("ROLLBACK")
    except sqlite3.OperationalError as error:
        if error.sqlite_errorcode & 0xFF in _BLOCKED:
            raise LoadFailed(LoadExit.BUSY) from error
        raise


def _abort_when_blocked(status: int, _remaining: int, _pages: int) -> None:
    """CPython retries a blocked step forever; raising here ends the copy and rolls it back."""
    if status in _BLOCKED:
        raise sqlite3.OperationalError("the live database stayed locked")


def main(arguments: list[str]) -> int:
    try:
        match arguments:
            case ["owner", database]:
                sys.stdout.write(owner(Path(database)) + "\n")
            case ["copy", database]:
                sys.stdout.buffer.write(copy(Path(database)))
            case ["check", database, table]:
                sys.stdout.write(f"{check(Path(database), table)}\n")
            case ["load", staged, size, sha256, live, table]:
                rows = load(Path(staged), int(size), sha256, Path(live), table)
                sys.stdout.write(f"{rows}\n")
            case _:
                return 2
    except LoadFailed as failure:
        return failure.exit_code
    except sqlite3.Error, OSError, ValueError:
        return VERDICT_EXIT
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
