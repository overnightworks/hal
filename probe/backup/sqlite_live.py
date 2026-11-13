"""Probe of `hal restore presentator --live`: the checkout's `hal backup presentator` and
`hal restore presentator --live` under a scratch HOME with its own restic repository, against a
stand-in database the probe writes itself.

    probe-run \\
        python3 probe/backup/sqlite_live.py --scratch DIR

A scratch `--apps` declares presentator with a probe-unique `compose_project`, so the door's
volume is the probe's own: a local volume over a directory of the scratch, whose files the probe
watches from the host. The database file belongs to a uid and gid that are not the operator's,
and every writer, the WAL writer the backup copies beside and the writers the probe kills, runs as
that owner on the pinned sqlite image. Logical contents are compared by the sha256 of a full
`iterdump`, read by a container; no row value is printed. `hal start` is never run: the stand-in's
reader is started by the probe. The restic password is a scratch value it generates and never
prints. No live container, volume, repository or HOME is named. It leaves --scratch empty,
passed or failed (`edge_copy`). Exit 0: every cell held as far as it drives it.
"""

from __future__ import annotations

import contextlib
import fcntl
import grp
import os
import pty
import re
import secrets
import select
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(REPO / "src"))  # hal's own facts

import edge_copy  # noqa: E402
from edge_copy import ProbeFailed, expect  # noqa: E402

from hal.backup.docker import PROJECT_LABEL, SERVICE_LABEL, VOLUME_LABEL  # noqa: E402
from hal.backup.settings import SQLITE_IMAGE, Settings  # noqa: E402
from hal.output import write_line  # noqa: E402
from hal.stack import switches  # noqa: E402

HAL = REPO / ".venv" / "bin" / "hal"
HAL_SECONDS = 600
DOCKER_SECONDS = 300
APP = "presentator"
FILE = "presentator.sqlite3"
OWNER = "10001:10002"  # neither the operator's uid nor a gid equal to the uid
NEW_BLOBS = 1800  # about 115 MiB of 64 KiB blobs: a load long enough to be caught writing
OLD_BLOBS = 4
MID_WRITE_BYTES = (8 << 20, 24 << 20, 48 << 20)  # WAL growth at which a kill lands mid-write
ANSI = re.compile(rb"\x1b\[[0-9;]*m")

# Rebuilds the database as one generation, every value naming it, then ends as told: closed, a
# running writer with its last row in the WAL, killed with that row committed in the WAL, or
# killed inside a transaction that spilled into the file (a hot journal). Prints the content's
# digest before any kill.
WRITER = r"""
import hashlib, os, signal, sqlite3, sys
path, generation, page_size, journal, end, blobs = sys.argv[1:]
db = sqlite3.connect(path, isolation_level=None)
db.execute("PRAGMA journal_mode=DELETE")
for table in ("users", "decks", "blobs"):
    db.execute(f"DROP TABLE IF EXISTS {table}")
db.execute(f"PRAGMA page_size={page_size}")
db.execute("VACUUM")
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
db.execute("CREATE TABLE decks (id INTEGER PRIMARY KEY, title TEXT, version INTEGER)")
db.execute("CREATE TABLE blobs (id INTEGER PRIMARY KEY, data BLOB)")
db.execute("BEGIN")
users = [(f"{generation}-user-{n}",) for n in range(30)]
db.executemany("INSERT INTO users (name) VALUES (?)", users)
db.executemany("INSERT INTO decks (title, version) VALUES (?, ?)",
               [(f"{generation}-deck-{n}-" + "x" * 900, n) for n in range(90)])
db.executemany("INSERT INTO blobs (data) VALUES (randomblob(65536))", [()] * int(blobs))
db.execute("COMMIT")
db.execute(f"PRAGMA journal_mode={journal}")
if end in ("serve", "stale-wal"):
    db.execute("PRAGMA wal_autocheckpoint=0")
    db.execute("INSERT INTO users (name) VALUES (?)", (f"{generation}-user-only-in-the-wal",))
digest = hashlib.sha256()
for line in db.iterdump():
    digest.update(line.encode() + b"\n")
print(digest.hexdigest(), flush=True)
if end == "hot-journal":
    db.execute("PRAGMA cache_size=1")
    db.execute("BEGIN")
    db.execute("UPDATE decks SET title = hex(randomblob(4000))")
if end == "serve":
    signal.pause()
if end in ("stale-wal", "hot-journal"):
    os.kill(os.getpid(), signal.SIGKILL)
db.close()
"""
# The digest of the whole logical content, the journal mode and the page size.
DUMPER = r"""
import hashlib, sqlite3, sys
db = sqlite3.connect(sys.argv[1])
digest = hashlib.sha256()
for line in db.iterdump():
    digest.update(line.encode() + b"\n")
mode = db.execute("PRAGMA journal_mode").fetchone()[0]
print(digest.hexdigest(), mode, db.execute("PRAGMA page_size").fetchone()[0])
"""


class SqliteLiveProbe:
    def __init__(self, scratch: Path) -> None:
        self.prefix = f"sqlite-live-probe-{secrets.token_hex(4)}"
        self.label = f"hal-sqlite-live-probe={self.prefix}"
        self.home = scratch / "home"
        self.data = scratch / "volume"
        self.control = scratch / "control"
        self.apps_file = scratch / "apps.toml"
        self.apps_file.write_text(
            f'[app.{APP}]\ncompose_project = "{self.prefix}"\ndump = "sqlite_online_copy"\n'
            f'database_volume = "database"\ndatabase_file = "{FILE}"\n'
            f'[app.{APP}.restore_test]\ncount_table = "users"\n'
        )
        self.volume = f"{self.prefix}_database"
        self.environment = {
            **{key: value for key, value in os.environ.items() if key != "LOG_FORMAT"},
            "HOME": str(self.home),
            "NO_COLOR": "1",
            "EDGE_DOMAIN": "probe.invalid",
            "DOCKER_GID": str(grp.getgrnam("docker").gr_gid),
            "COMPOSE_PROJECT_NAME": self.prefix,
        }
        self.settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        self.hal_pids: list[int] = []
        self.new = ""  # the snapshot's content digest
        self.snapshot = ""

    # --- plumbing -----------------------------------------------------------------------------

    def docker(self, *arguments: str, exit_codes: tuple[int, ...] = (0,)) -> str:
        result = subprocess.run(  # noqa: S603 - argv is built by the probe itself and no shell runs
            ["docker", *arguments],  # noqa: S607 - docker is found on PATH by design
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_SECONDS,
        )
        expect(
            result.returncode in exit_codes,
            f"docker {arguments[0]} exited {result.returncode}: {result.stderr.strip()[-300:]}",
        )
        return result.stdout

    def as_owner(self, script: str, *arguments: str, detach: bool = False, **labels: str) -> str:
        """A python of the pinned sqlite image as the file's owner over the volume; `--init`, so a
        writer that kills itself is no PID 1."""
        label_options = [
            option for key, value in labels.items() for option in ("--label", f"{key}={value}")
        ]
        return self.docker(
            "run", *(["--detach"] if detach else ["--rm"]), "--init", "--network", "none",
            "--label", self.label, *label_options, "--user", OWNER,
            "--mount", f"type=volume,source={self.volume},target=/data",
            "--entrypoint", "python", SQLITE_IMAGE, "-I", "-c", script, *arguments,
            exit_codes=(0, 137),
        )  # fmt: skip

    def write(self, generation: str, *, end: str, page_size: int = 4096, journal: str = "wal",
              blobs: int = OLD_BLOBS) -> str:  # fmt: skip
        output = self.as_owner(
            WRITER, f"/data/{FILE}", generation, str(page_size), journal, end, str(blobs)
        )
        return output.split()[0]

    def dumped(self) -> tuple[str, str, int]:
        digest, mode, page_size = self.as_owner(DUMPER, f"/data/{FILE}").split()
        return digest, mode, int(page_size)

    def identity(self) -> tuple[int, int, int, int]:
        status = (self.data / FILE).stat()
        return status.st_ino, status.st_uid, status.st_gid, status.st_mode

    def sidecar_bytes(self, suffix: str) -> int:
        path = self.data / f"{FILE}-{suffix}"
        return path.stat().st_size if path.exists() else -1

    def hal(self, *arguments: str, typed: bytes | None = b"yes\n",
            during: Callable[[int], None] | None = None) -> tuple[int, str]:  # fmt: skip
        """`hal <arguments> --apps <scratch>`: at a pty where `typed` answers the question, or
        with no terminal when `typed` is None. `during` runs beside it once it was answered."""
        argv = [str(HAL), *arguments, "--apps", str(self.apps_file)]
        if typed is None:
            result = subprocess.run(  # noqa: S603 - argv is built by the probe itself and no shell runs
                argv, stdin=subprocess.DEVNULL, capture_output=True, env=self.environment,
                timeout=HAL_SECONDS, check=False,
            )  # fmt: skip
            return result.returncode, _squeezed(result.stdout + result.stderr)
        primary, secondary = pty.openpty()
        process = subprocess.Popen(  # noqa: S603 - argv is built by the probe itself and no shell runs
            argv, stdin=secondary, stdout=secondary, stderr=secondary, env=self.environment
        )
        os.close(secondary)
        self.hal_pids.append(process.pid)
        output, failures, beside = bytearray(), [], []
        deadline = time.monotonic() + HAL_SECONDS
        try:
            self._answer_at_pty(primary, process.pid, typed, during,
                                (output, failures, beside), deadline)  # fmt: skip
            process.wait(timeout=max(1, deadline - time.monotonic()))
        finally:
            os.close(primary)
            for thread in beside:
                thread.join(timeout=HAL_SECONDS)
        if failures:
            raise failures[0]
        return process.returncode, _squeezed(bytes(output))

    @staticmethod
    def _answer_at_pty(
        primary: int,
        pid: int,
        typed: bytes,
        during: Callable[[int], None] | None,
        collected: tuple[bytearray, list, list],
        deadline: float,
    ) -> None:
        """Collects the pty output until it closes; types `typed` once the question shows and
        starts `during` beside it."""
        output, failures, beside = collected
        while time.monotonic() < deadline:
            ready, _, _ = select.select([primary], [], [], 0.05)
            if ready:
                chunk = _read_pty(primary)
                if not chunk:
                    break
                output += chunk
            if not beside and b"Type yes" in output:
                os.write(primary, typed)
                beside.append(threading.Thread(target=_run_beside, args=(during, pid, failures)))
                beside[0].start()

    def live(self, *options: str, **keywords) -> tuple[int, str]:
        return self.hal("restore", APP, "--live", *options, **keywords)

    def wait_for_wal_growth(self, past: int) -> int:
        """Polls the WAL from the host until the loader has written `past` bytes into it."""
        deadline = time.monotonic() + 120
        start = max(self.sidecar_bytes("wal"), 0)
        while time.monotonic() < deadline:
            grown = self.sidecar_bytes("wal") - start
            if grown >= past:
                return grown
            time.sleep(0.005)
        raise ProbeFailed(f"the WAL never grew by {past} bytes")

    def loader(self) -> str:
        running = self.docker("ps", "--quiet", "--filter", f"volume={self.volume}").split()
        expect(len(running) == 1, f"{len(running)} containers on the volume during the load")
        return running[0]

    def wait_until_volume_unused(self) -> None:
        deadline = time.monotonic() + 300
        while self.docker("ps", "--quiet", "--filter", f"volume={self.volume}").split():
            expect(time.monotonic() < deadline, "a container stayed on the volume")
            time.sleep(0.2)

    def held(self, cell: str, what: str, verdict: str = "held") -> None:
        write_line(f"#1026 {cell} {verdict}: {what}")

    # --- the stand ----------------------------------------------------------------------------

    def start(self) -> None:
        password = self.settings.password_file
        password.parent.mkdir(mode=0o700, parents=True)
        password.touch(mode=0o600, exist_ok=False)
        password.write_text(secrets.token_urlsafe(32))
        code, out = self.hal("backup", "--init", typed=None)
        expect(code == 0, f"backup --init exited {code}: {out[-300:]}")
        self.data.mkdir()
        self.data.chmod(0o777)  # the owner, not the operator, creates the database in it
        self.docker(
            "volume", "create", "--label", self.label,
            "--label", f"{PROJECT_LABEL}={self.prefix}", "--label", f"{VOLUME_LABEL}=database",
            "--opt", "type=none", "--opt", "o=bind", "--opt", f"device={self.data}", self.volume,
        )  # fmt: skip
        switch = self.home / ".local/state/edge/stopped" / APP
        switch.parent.mkdir(parents=True)
        switch.write_text("2026-11-05T12:00:00+01:00")

    # --- the cells ----------------------------------------------------------------------------

    def cell_m13_backup_beside_a_wal_writer(self) -> None:
        """The weekly copy while the owner's writer holds rows in the WAL: the snapshot's file is
        a WAL-format image of every committed row."""
        writer = self.as_owner(
            WRITER, f"/data/{FILE}", "new", "4096", "wal", "serve", str(NEW_BLOBS),
            detach=True, **{PROJECT_LABEL: self.prefix, SERVICE_LABEL: APP},
        ).strip()  # fmt: skip
        deadline = time.monotonic() + 300
        while not self.docker("logs", writer).strip():
            expect(time.monotonic() < deadline, "the WAL writer did not finish its rows")
            time.sleep(0.5)
        self.new = self.docker("logs", writer).split()[0]
        expect(self.sidecar_bytes("wal") > 0, "the writer left no rows in the WAL")
        code, out = self.hal("backup", APP, typed=None)
        expect(code == 0, f"backup exited {code}: {out[-300:]}")
        self.docker("kill", writer)
        self.docker("rm", writer)
        target = self.control / "target"
        code, out = self.hal("restore", APP, "--target", str(target), typed=None)
        expect(code == 0, f"restore --target exited {code}: {out[-300:]}")
        copy = (target / "db" / "db.sqlite3").read_bytes()
        expect(copy[18:20] == b"\x02\x02", f"the copy's header format is {copy[18:20]!r}")
        self.held(
            "M13",
            "the copy taken beside a running WAL writer is a WAL-format image (header 2,2), "
            f"{len(copy) >> 20} MiB",
        )

    def cell_m13_m14_m16_load_over_stale_wal(self) -> None:
        old = self.write("old", end="stale-wal")
        expect(self.sidecar_bytes("wal") > 0 and self.sidecar_bytes("shm") > 0, "no stale WAL")
        identity = self.identity()
        code, out = self.live()
        expect(code == 0, f"the load exited {code}: {out[-400:]}")
        loaded = re.search(rf"✓ {APP} loaded ([0-9a-f]{{8}}) · ", out)
        expect(
            loaded is not None and f"next: hal start {APP}" in out, f"no loaded row: {out[-300:]}"
        )
        self.snapshot = loaded[1]
        digest, mode, _ = self.dumped()
        expect(digest == self.new and digest != old, "the live content is not the snapshot's")
        expect(mode == "wal", f"journal mode {mode} after the load")
        expect(self.identity() == identity, f"identity {identity} became {self.identity()}")
        expect(not list(self.settings.work_dir.iterdir()), "the staging stayed")
        self.held(
            "M13 M14 M16",
            f"loaded {self.snapshot} over a killed writer's WAL and SHM into {FILE}: full dump "
            f"equals the snapshot's, journal wal, inode, uid:gid {OWNER} and mode unchanged",
        )

    def cell_m21_stand_in_reads_the_rows(self) -> None:
        reader = (
            "import sqlite3, sys; db = sqlite3.connect(sys.argv[1]); "
            "print(db.execute('SELECT count(*) FROM users').fetchone()[0])"
        )
        count = self.as_owner(
            reader, f"/data/{FILE}", **{PROJECT_LABEL: self.prefix, SERVICE_LABEL: APP}
        )
        expect(count.strip() == "31", f"the stand-in counts {count.strip()} users")
        self.held(
            "M21",
            "a one-shot reader with the service labels, started by the probe (not `hal start`), "
            "reads the snapshot's 31 users",
        )

    def cell_m2_m3_refusals_before_anything(self) -> None:
        before = self.dumped()
        code, out = self.live(typed=None)
        expect(
            code == 4 and "asks yes at a terminal · nothing changed" in out,
            f"no terminal: {code} {out[-200:]}",
        )
        code, out = self.live(typed=b"no\n")
        expect(code == 1 and "aborted, nothing changed" in out, f"declined: {code} {out[-200:]}")
        expect(self.dumped() == before, "a refusal changed the content")
        self.held("M2 M3", "no terminal: exit 4; `no`: exit 1; content unchanged")

    def cell_m9_consumers(self) -> None:
        before = self.dumped()
        sleeper = "import time; time.sleep(3600)"
        labels = {PROJECT_LABEL: self.prefix, SERVICE_LABEL: APP}
        running = self.as_owner(sleeper, detach=True, **labels).strip()
        seen = []
        for state in ("running", "paused"):
            if state == "paused":
                self.docker("pause", running)
            code, out = self.live()
            expect(
                code == 4 and f"a container still uses {APP}'s database · nothing loaded" in out,
                f"{state}: {code} {out[-200:]}",
            )
            seen.append(state)
        self.docker("rm", "--force", running)
        restarting = self.docker(
            "run", "--detach", "--restart", "always", "--network", "none", "--label", self.label,
            "--user", OWNER, "--mount", f"type=volume,source={self.volume},target=/data",
            "--entrypoint", "python", SQLITE_IMAGE,
            "-c", "import time; time.sleep(0.3); raise SystemExit(1)",
        ).strip()  # fmt: skip
        time.sleep(2)
        state = self.docker("inspect", "--format", "{{.State.Status}}", restarting).strip()
        code, out = self.live()
        expect(
            code == 4 and "a container still uses" in out,
            f"restarting ({state}): {code} {out[-200:]}",
        )
        seen.append(f"restart-always ({state} when inspected)")
        self.docker("rm", "--force", restarting)
        expect(self.dumped() == before, "a refused load changed the content")
        self.held("M9", f"refused with nothing loaded for a consumer {', '.join(seen)}")

    def cell_m11_page_size(self) -> None:
        self.write("eight", end="close", page_size=8192)
        before = self.dumped()
        expect(before[1:] == ("wal", 8192), f"the stand is {before[1:]}")
        code, out = self.live("--snapshot", self.snapshot)
        expect(
            code == 4
            and "load refused · the copy or the live file does not fit · nothing changed" in out,
            f"page size: {code} {out[-300:]}",
        )
        expect(self.dumped() == before, "the refused load changed the content")
        self.held(
            "M11",
            "a WAL live file with page size 8192 refuses the 4096 copy: exit 4, dump unchanged",
        )

    def cell_m15_hot_journal(self) -> None:
        old = self.write("old", end="hot-journal", journal="delete")
        journal = self.data / f"{FILE}-journal"
        expect(journal.exists() and journal.stat().st_size > 0, "no hot journal")
        self.control.mkdir(exist_ok=True)
        recovered = self.control / "recovered"
        recovered.mkdir()
        for name in (FILE, journal.name):
            (recovered / name).write_bytes((self.data / name).read_bytes())
        recovered.chmod(0o777)
        for path in recovered.iterdir():
            path.chmod(0o666)
        digest = self.docker(
            "run", "--rm", "--network", "none", "--label", self.label, "--user", OWNER,
            "--mount", f"type=bind,source={recovered},target=/data",
            "--entrypoint", "python", SQLITE_IMAGE, "-I", "-c", DUMPER, f"/data/{FILE}",
        ).split()[0]  # fmt: skip
        expect(digest == old, "the hot journal's copy does not read as the old content")
        code, out = self.live("--snapshot", self.snapshot)
        expect(code == 0, f"the load over the hot journal exited {code}: {out[-300:]}")
        expect(self.dumped()[0] == self.new and not journal.exists(), "not the snapshot's content")
        self.held(
            "M15",
            "a killed writer's hot rollback journal (a copy of it reads as the old content "
            "through SQLite) is recovered and the whole command loads the snapshot",
        )

    def cell_m17_sigkill_of_the_loader(self) -> None:
        outcomes = []
        for past in MID_WRITE_BYTES:
            old = self.write("old", end="close")

            def kill_the_loader(_pid: int, past: int = past) -> None:
                grown = self.wait_for_wal_growth(past)
                self.docker("kill", self.loader())
                outcomes.append(grown)

            code, out = self.live("--snapshot", self.snapshot, during=kill_the_loader)
            self.wait_until_volume_unused()
            digest = self.dumped()[0]
            expect(
                digest in (old, self.new), f"after a kill at {past} bytes the content is neither"
            )
            which = "old" if digest == old else "new"
            expect(
                code == 3 and "it holds the old or the new database" in out,
                f"kill: {code} {out[-300:]}",
            )
            outcomes[-1] = f"killed after {outcomes[-1] >> 20} MiB of WAL: {which}"
        expect(
            any(line.endswith("old") for line in outcomes), f"no kill landed mid-write: {outcomes}"
        )
        self.held("M17", "; ".join(outcomes) + "; exit 3 'old or new' each time")

    def cell_m18_m22_signals_during_the_load(self) -> None:
        self.write("old", end="close")
        lock = self.home / ".local/state/edge" / switches.LOCK_FILE
        evidence = []

        def signal_hal(pid: int) -> None:
            self.wait_for_wal_growth(MID_WRITE_BYTES[0])
            evidence.append(_is_locked(lock))
            for number in (signal.SIGINT, signal.SIGTERM, signal.SIGINT, signal.SIGTERM):
                os.kill(pid, number)
            evidence.append(self.sidecar_bytes("wal"))

        code, out = self.live("--snapshot", self.snapshot, during=signal_hal)
        expect(code == 0 and f"✓ {APP} loaded" in out, f"signals: {code} {out[-300:]}")
        expect(evidence[0] is True, "switch.lock was free while the loader wrote")
        expect(self.dumped()[0] == self.new, "not the snapshot's content after the signals")
        self.held(
            "M18 M22",
            f"SIGINT/SIGTERM x4 at {evidence[1] >> 20} MiB of WAL: the load finished, '✓ loaded' "
            "printed, exit 0; switch.lock refused LOCK_NB while it wrote",
        )

    def cell_m19_sigkill_of_hal(self) -> None:
        old = self.write("old", end="close")
        killed = []

        def kill_hal(pid: int) -> None:
            self.wait_for_wal_growth(MID_WRITE_BYTES[0])
            os.kill(pid, signal.SIGKILL)
            killed.append(
                bool(self.docker("ps", "--quiet", "--filter", f"volume={self.volume}").split())
            )

        code, _ = self.live("--snapshot", self.snapshot, during=kill_hal)
        expect(code == -signal.SIGKILL, f"hal was not killed: {code}")
        self.wait_until_volume_unused()
        after = self.dumped()[0]
        expect(after in (old, self.new), "after hal's kill the content is neither")
        code, out = self.live("--snapshot", self.snapshot)
        expect(code == 0 and self.dumped()[0] == self.new, f"the rerun: {code} {out[-300:]}")
        state = "the loader ran on after hal died" if killed[0] else "the loader had ended"
        which = "new" if after == self.new else "old"
        self.held(
            "M19",
            f"SIGKILL of hal mid-write: {state}, the file held the {which} content; the rerun "
            "with the question's snapshot loaded it; not driven: a rerun refused while the "
            "orphaned loader still runs",
            verdict="partly held",
        )

    def failure_of_the_cells(self) -> str | None:
        """The stand, then the cells in an order where each finds the premise the one before
        left: the snapshot first, then loads over ever other states of the live file. The first
        failure ends them; None when every cell held."""
        cells = (
            self.start,
            self.cell_m13_backup_beside_a_wal_writer,
            self.cell_m13_m14_m16_load_over_stale_wal,
            self.cell_m21_stand_in_reads_the_rows,
            self.cell_m2_m3_refusals_before_anything,
            self.cell_m9_consumers,
            self.cell_m11_page_size,
            self.cell_m15_hot_journal,
            self.cell_m17_sigkill_of_the_loader,
            self.cell_m18_m22_signals_during_the_load,
            self.cell_m19_sigkill_of_hal,
        )
        try:
            for cell in cells:
                cell()
        except (ProbeFailed, subprocess.TimeoutExpired, OSError, ValueError, IndexError) as failure:
            return str(failure)
        except KeyboardInterrupt:
            return "interrupted"
        return None

    def teardown(self) -> None:
        for pid in self.hal_pids:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        containers = {
            *self.docker("ps", "--all", "--quiet", "--filter", f"label={self.label}").split(),
            *self.docker("ps", "--all", "--quiet", "--filter", f"volume={self.volume}").split(),
        }
        if containers:
            self.docker("rm", "--force", *containers)
        volumes = self.docker("volume", "ls", "--quiet", "--filter", f"label={self.label}").split()
        if volumes:
            self.docker("volume", "rm", *volumes)
        left = self.docker("ps", "--all", "--quiet", "--filter", f"label={self.label}").split()
        expect(not left, f"teardown left {len(left)} containers")


def _read_pty(primary: int) -> bytes:
    """One chunk from the pty; empty once the child closed it."""
    try:
        return os.read(primary, 65536)
    except OSError:
        return b""


def _run_beside(during: Callable[[int], None] | None, pid: int, failures: list) -> None:
    try:
        (during or (lambda _: None))(pid)
    except (ProbeFailed, subprocess.TimeoutExpired, OSError) as failure:
        failures.append(failure)


def _squeezed(output: bytes) -> str:
    return " ".join(ANSI.sub(b"", output).decode(errors="replace").split())


def _is_locked(lock: Path) -> bool:
    with lock.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(handle, fcntl.LOCK_UN)
        return False


def prove(probe: SqliteLiveProbe) -> int:
    failure = probe.failure_of_the_cells()
    if failure is None:
        return 0
    write_line(f"PROBE FAILED: {failure}")
    return 1


def verdict(_probe: SqliteLiveProbe) -> int:
    return edge_copy.passed_line("PROBE PASSED: #1026 M2 M3 M9 M11 M13-M18 M21 M22, M19 partly")


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(__doc__.splitlines()[0], argv, SqliteLiveProbe, prove, verdict)


if __name__ == "__main__":
    sys.exit(main())
