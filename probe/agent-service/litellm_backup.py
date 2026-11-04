"""Probe of LiteLLM's backup (#970 cells B1-B7) and its live load (#974 cells L0-L6): `hal backup
litellm`, its pre-apply snapshot, `hal restore --test litellm`, a lost volume rebuilt through `hal
apply`'s key step, and `hal restore litellm --live` of B1's snapshot, on the stack of litellm.py in
its throwaway project. Nothing live and nothing paid: the probe refuses to start unless `internet`
is internal and holds only the fakes. It runs in hal's environment, which holds the agent-runtime
client:

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/agent-service/litellm_backup.py --scratch DIR

Measured on two runs: 4 to 7.5 minutes whole, of which the stack's start and B1 to B7 take 2 to
3.5 minutes, the L cells 2 to 4 minutes, and the teardown 11 s.

The checkout's `hal` runs under the scratch HOME, with its own restic repository, password and
status, and with `--apps` naming a scratch record: the shipped `litellm` record of
`backup/apps.toml` with only `compose_project` replaced by the probe's project. The key step
makes the person budget and the three app keys at the code defaults; steered usage puts hopin's
key past its budget and the fingerprint P, a random canary, past the person budget. F is the fake
provider's request log. Keys are scratch values the probe generates and never prints; the search
of the dump prints counts only. D is the digest of hal's six tables, read while LiteLLM and its
front are stopped, so its own writes cannot move it: just before and just after B1's backup, the
two equal. The probe never runs `hal stop` or `hal start`, which act on the live project: it writes
the switch marker under the scratch HOME, stops and starts its own containers, and answers the
question at a pseudo-terminal. A stall is a probe session holding ACCESS SHARE on the keys table
in an open transaction; it lasts until the probe ends it, since the load waits on a held lock
without bound. L2's load fails on a view of the keys table that the dump does not hold. A live run
gets LIVE_SECONDS, 120 s, from its answer to its end once no stall holds it: the database start and
the load of the probe's few rows take seconds. Exit 0: every cell held.
"""

from __future__ import annotations

import dataclasses
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import signal
import subprocess
import sys
import termios
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # edge_copy, the probes' helper

import edge_copy
from litellm import (
    DATABASE,
    FRONT,
    LITELLM,
    PERSON_PUSH,
    PROJECT,
    REPO,
    ProbeFailed,
    expect,
    hashed,
    run_scratch_probe,
)
from litellm_admission import APP_PUSH, AdmissionProbe
from litellm_expiry import HAL, HAL_SECONDS
from litellm_keys import APPS, TABLES, KeysProbe, first_of_next_month, parsed_time
from scratch_secrets import write_new

from hal.backup.apps import DB_FOLDER, parse_apps
from hal.backup.cli import DEFAULT_APPS
from hal.backup.docker import PG_RESTORE_APPLICATION
from hal.backup.runner import MIN_SNAPSHOT_PREFIX, STAGING_PREFIX
from hal.backup.settings import Settings
from hal.backup.verify import DUMP_NAME
from hal.grammar import ExitCode
from hal.output import write_line
from hal.output.command import Verb, command
from hal.stack import litellm_keys, switches
from hal.stack.litellm_keys import ADMIN_BUDGET_ID, KeysDone, Target

APP = "litellm"
HAL_TABLES = (
    "LiteLLM_BudgetTable",
    "LiteLLM_EndUserTable",
    "LiteLLM_DailyEndUserSpend",
    "LiteLLM_DailyToolSpend",
    "LiteLLM_ToolTable",
)
DAILY_TABLES = ("LiteLLM_DailyEndUserSpend", "LiteLLM_DailyToolSpend")
MIGRATIONS_TABLE = "_prisma_migrations"
DUMP_SECONDS = 120
# A TABLE or VIEW entry of `pg_restore --list`: "<id>; <oid> <oid> TABLE <schema> <name> <owner>".
LISTED = re.compile(r'^\d+; \d+ \d+ (TABLE|VIEW) (\S+) "?([^"\s]+)"? \S+$')
# D: hal's six tables, the keys among them.
DIGEST_TABLES = tuple(dict.fromkeys((*TABLES, *HAL_TABLES)))
KEYS_TABLE = "LiteLLM_VerificationToken"
# A view the dump does not hold: `--clean`'s DROP TABLE of the keys table fails on it.
BLOCKING_VIEW = "probe_l2_keys"
LIVE_SECONDS = 120
QUIET_SECONDS = 3
QUESTION = "Type yes"  # the start of hal's question, which the load waits to be answered
INTERRUPT = b"\x03"  # the pseudo-terminal's interrupt character, Ctrl-C


def _take_terminal() -> None:
    """In the child, after its new session: the pseudo-terminal on stdin becomes its controlling
    terminal, so Ctrl-C typed there reaches hal as at a real one."""
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


class LiveRun:
    """One `hal` at a pseudo-terminal of its own, which echoes nothing: the probe reads what hal
    prints, types at its question and signals it."""

    def __init__(self, argv: list[str], environment: dict[str, str]) -> None:
        primary, secondary = os.openpty()
        attributes = termios.tcgetattr(secondary)
        attributes[3] &= ~(termios.ECHO | termios.ECHOCTL)
        termios.tcsetattr(secondary, termios.TCSANOW, attributes)
        self.process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            argv, stdin=secondary, stdout=secondary, stderr=secondary, env=environment, cwd=REPO,
            start_new_session=True, preexec_fn=_take_terminal, close_fds=True,
        )  # fmt: skip
        os.close(secondary)
        self.primary: int | None = primary
        self.printed = b""

    def __enter__(self) -> LiveRun:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def text(self) -> str:
        return self.printed.decode(errors="replace").replace("\r\n", "\n")

    def read(self, seconds: float) -> bool:
        """What hal prints within `seconds`; False once its terminal is closed."""
        ready, _, _ = select.select([self.primary], [], [], seconds)
        if not ready:
            return True
        try:
            chunk = os.read(self.primary, 4096)
        except OSError:
            return False
        self.printed += chunk
        return bool(chunk)

    def read_until(self, wanted: str, seconds: int = HAL_SECONDS) -> None:
        deadline = time.monotonic() + seconds
        while wanted not in self.text:
            expect(time.monotonic() < deadline and self.read(1), f"hal never printed {wanted!r}: "
                   f"{self.text.strip()[-300:]!r}")  # fmt: skip

    def quiet_for(self, seconds: float) -> str:
        """What hal printed in the next `seconds`."""
        before, deadline = len(self.printed), time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not self.read(deadline - time.monotonic()):
                break
        return self.printed[before:].decode(errors="replace")

    def type(self, typed: bytes) -> None:
        os.write(self.primary, typed)

    def finish(self, seconds: int = LIVE_SECONDS) -> tuple[int, str]:
        deadline = time.monotonic() + seconds
        while self.read(1):
            expect(time.monotonic() < deadline, f"hal ran past {seconds} s")
        code = self.process.wait(timeout=HAL_SECONDS)
        self.close()
        return code, self.text

    def close(self) -> None:
        """Ends hal by its pid if it still runs, waits for it and closes the terminal; the
        client of a load it spawned has a session of its own and runs to its end."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=HAL_SECONDS)
        if self.primary is not None:
            os.close(self.primary)
            self.primary = None


class Stall:
    """A probe session holding ACCESS SHARE on the keys table in an open transaction, which
    `--clean`'s DROP TABLE waits on."""

    def __init__(self, argv: list[str], environment: dict[str, str]) -> None:
        self.process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, env=environment,
        )  # fmt: skip
        try:
            self.process.stdin.write(
                f"BEGIN;\nLOCK TABLE \"{KEYS_TABLE}\" IN ACCESS SHARE MODE;\nSELECT 'stalled';\n"
            )
            self.process.stdin.flush()
            for line in self.process.stdout:
                if line.strip() == "stalled":
                    return
            raise ProbeFailed(f"the stall's session ended with {self.process.wait()}")
        except BaseException:
            self.close()
            raise

    def __enter__(self) -> Stall:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    def end(self) -> None:
        self.process.stdin.write("COMMIT;\n")
        self.process.stdin.close()
        self.process.wait(timeout=HAL_SECONDS)

    def close(self) -> None:
        """Ends the session by its pid if it still runs, waits for it and closes its pipes."""
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=HAL_SECONDS)
        self.process.stdin.close()
        self.process.stdout.close()


def toml_table(name: str, record: dict) -> str:
    """The record as a TOML table of plain values and nested tables; JSON's string, integer and
    boolean literals are TOML's too."""
    plain = [f"{key} = {json.dumps(value)}" for key, value in record.items()
             if not isinstance(value, dict)]  # fmt: skip
    nested = [toml_table(f"{name}.{key}", value) for key, value in record.items()
              if isinstance(value, dict)]  # fmt: skip
    return "\n".join([f"[{name}]", *plain, ""]) + "".join(nested)


class BackupProbe(KeysProbe, AdmissionProbe):
    """litellm_keys.py's stack and key step, litellm_admission.py's steered usage, and `hal backup`
    and `hal restore` against them."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.scratch = scratch
        self.settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        password = self.settings.password_file
        password.parent.mkdir(mode=0o700)
        write_new(password, secrets.token_urlsafe(32).encode(), 0o600)
        self.apps_file = scratch / "apps.toml"
        self.write_scratch_record()
        self.person = self.fingerprint()
        state = self.home / switches.default_state_directory().relative_to(Path.home())
        self.switches = switches.Switches(state)

    def write_scratch_record(self) -> None:
        """The shipped record with the probe's project; it must parse to the shipped app with
        only that one field changed."""
        shipped_text = DEFAULT_APPS.read_text()
        record = {**tomllib.loads(shipped_text)["app"][APP], "compose_project": PROJECT}
        self.apps_file.write_text(toml_table(f"app.{APP}", record))
        (declared,) = parse_apps(self.apps_file.read_text())
        (shipped,) = (app for app in parse_apps(shipped_text) if app.name == APP)
        self.count_table = shipped.restore_test.count_table
        expect(
            declared == dataclasses.replace(shipped, compose_project=PROJECT),
            "the scratch record differs from the shipped one beyond its project",
        )

    # --- plumbing -----------------------------------------------------------------------------

    def secret_values(self) -> list[str]:
        """What must never appear in a dump or in hal's output: every key in clear, the master
        key and its hash, the provider key and the database password."""
        return [*self.written, self.master_key, hashed(self.master_key), self.provider_key,
                self.database_password]  # fmt: skip

    def hal(self, *arguments: str) -> subprocess.CompletedProcess:
        result = self.run(
            ["env", "-u", "LOG_FORMAT", "-u", "NO_COLOR", str(HAL), *arguments,
             "--apps", str(self.apps_file)],
            check=False, timeout=HAL_SECONDS,
        )  # fmt: skip
        shown = result.stdout + result.stderr
        leaked = sum(value in shown for value in self.secret_values())
        expect(leaked == 0, f"hal {arguments[0]} printed {leaked} secret values")
        return result

    def last_snapshot(self) -> str:
        status = json.loads(self.settings.status_file.read_text())
        return status["apps"][APP]["last_snapshot_id"]

    def backed_up(self, cell: str, *options: str) -> subprocess.CompletedProcess:
        result = self.hal("backup", APP, *options)
        expect(result.returncode == 0, f"{cell}: hal backup exited {result.returncode}: "
               f"{result.stderr.strip()[-300:]}")  # fmt: skip
        return result

    def dump_tool(self, dump: Path, *arguments: str) -> str:
        """pg_restore inside litellm-db with the dump on standard input; it connects to no
        server, it only reads the archive."""
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", "exec", "-i", self.container(DATABASE), "pg_restore", *arguments],  # noqa: S607 - docker is found on PATH by design
            input=dump.read_bytes(), capture_output=True, env=self.environment,
            check=False, timeout=DUMP_SECONDS,
        )  # fmt: skip
        expect(result.returncode == 0, f"pg_restore {arguments} exited {result.returncode}")
        return result.stdout.decode("utf-8", errors="replace")

    def count(self, table: str, condition: str = "TRUE") -> int:
        (counted,) = self.query(f'SELECT count(*) FROM "{table}" WHERE {condition};')  # noqa: S608 - table and condition are this probe's literals and tokens
        return int(counted)

    def person_rows(self) -> int:
        return self.count("LiteLLM_DailyEndUserSpend", f"end_user_id = '{self.person}'")

    def database_digest(self) -> str:
        """D: the digest of hal's six tables."""
        return hashlib.sha256("\n".join(self.digest(DIGEST_TABLES)).encode()).hexdigest()[:12]

    def database_argv(self, *psql: str) -> list[str]:
        return ["docker", "exec", "-i", self.container(DATABASE), "psql",
                *self.database_options(), "--no-psqlrc", "--tuples-only", "--no-align",
                "--set", "ON_ERROR_STOP=1", *psql]  # fmt: skip

    def state_of(self, service: str) -> str:
        (found,) = self.compose("ps", "--all", "--quiet", service).stdout.split()
        return self.run(
            ["docker", "inspect", "--format", "{{.State.Status}}", found]
        ).stdout.strip()

    def started_at(self, *services: str) -> dict[str, str]:
        """Each container's start moment by its id: of the named services, else of the project."""
        found = self.compose("ps", "--all", "--quiet", *services).stdout.split()
        lines = self.run(["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *found])
        pairs = (line.split(" ", 1) for line in lines.stdout.splitlines())
        return {container: moment for container, moment in pairs}

    def stop_app(self) -> None:
        """The probe's own stop of LiteLLM and its front; `hal stop` would act on the live
        project."""
        self.compose("stop", LITELLM, FRONT, timeout=120)

    def start_app(self) -> None:
        self.compose("start", FRONT, LITELLM, timeout=120)
        self.wait_until_listening()

    def changed_digest(self, cell: str) -> str:
        """D': hopin's key at a random spend, set while LiteLLM and its front are stopped."""
        self.stop_app()
        self.set_key("hopin", f"spend = {secrets.randbelow(10**6) / 100 + 1000}")
        changed = self.database_digest()
        expect(changed != self.digest_b1, f"{cell}: D' equals D at B1")
        return changed

    def restore_sessions(self, waiting: bool = False) -> int:
        condition = " AND wait_event_type = 'Lock'" if waiting else ""
        return self.count_rows(
            "pg_stat_activity", f"application_name = '{PG_RESTORE_APPLICATION}'{condition}"
        )

    def count_rows(self, view: str, condition: str) -> int:
        (counted,) = self.query(f"SELECT count(*) FROM {view} WHERE {condition};")  # noqa: S608 - the view and the condition are this probe's literals
        return int(counted)

    def wait_until_stalled(self, cell: str) -> None:
        self.wait_for(cell, "the load waiting on the stall", lambda: self.restore_sessions(True))

    def staging(self) -> set[str]:
        """The runs' staging directories, without the run mark each keeps beside its own."""
        work = self.settings.work_dir
        return {entry.name for entry in work.iterdir()
                if entry.is_dir() and entry.name.startswith(STAGING_PREFIX)}  # fmt: skip

    def live_run(self) -> LiveRun:
        """`hal restore litellm --live` of B1's snapshot at a pseudo-terminal of its own."""
        argv = ["env", "-u", "LOG_FORMAT", str(HAL), "restore", APP, "--live", "--snapshot",
                self.snapshot_b1, "--apps", str(self.apps_file)]  # fmt: skip
        return LiveRun(argv, {**self.environment, "NO_COLOR": "1"})

    def live_answered(self, cell: str, typed: bytes, wanted: int) -> str:
        """A live run answered `typed`, its exit `wanted`; its output, which holds no secret,
        key hash or P."""
        with self.live_run() as run:
            run.read_until(QUESTION)
            run.type(typed)
            code, output = run.finish()
        self.expect_no_leak(cell, output)
        expect(code == wanted, f"{cell}: exit {code}, wanted {wanted}: {output.strip()[-300:]!r}")
        return output

    def expect_no_leak(self, cell: str, output: str) -> None:
        hidden = [*self.secret_values(), *(hashed(self.file_keys[app]) for app in APPS),
                  self.person]  # fmt: skip
        leaked = sum(value in output for value in hidden)
        expect(leaked == 0, f"{cell}: hal printed {leaked} secret values, key hashes or P")

    def make_keys(self, cell: str, apps: tuple[str, ...], budget_new: bool) -> None:
        """The key step plans exactly these new keys (and the person budget and the admin group's
        when `budget_new`) and makes them."""
        plan = self.read_plan(cell)
        budget = [(Target.BUDGET, self.budget_id, True)] if budget_new else []
        admin = [(Target.BUDGET, ADMIN_BUDGET_ID, True)] if budget_new else []
        wanted = [*budget, *((Target.KEY, app, True) for app in apps), *admin]
        planned = [(change.target, change.subject, change.new) for change in plan.changes]
        expect(planned == wanted, f"{cell}: planned {planned}")
        result = self.run_step(plan)
        expect(
            isinstance(result, KeysDone) and len(result.done) == len(wanted), f"{cell}: {result}"
        )

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        live_before = edge_copy.live_project(REPO)
        initialised = self.hal("backup", "--init")
        expect(initialised.returncode == 0, f"hal backup --init exited {initialised.returncode}")
        self.steer_fake()
        self.wait_until_listening()
        self.cell_b1()
        self.cells_b2_b3()
        self.cell_b4()
        self.cell_b5()
        self.cell_b6()
        self.cell_b7()
        self.cell_l0()
        self.cell_l1()
        self.cell_l2()
        self.cells_l3_l4()
        self.cell_l5()
        self.cell_l6()
        write_line(edge_copy.expect_live_project_unchanged(live_before, REPO), flush=True)

    def cell_b1(self) -> None:
        self.make_keys("B1", APPS, budget_new=True)
        self.expect_default_keys(sorted(self.models()), first_of_next_month())
        self.push(self.file_keys["hopin"], self.fingerprint(), APP_PUSH)
        self.push(self.file_keys["songmaker"], self.person, PERSON_PUSH)
        self.wait_for(
            "B1",
            "hopin's spend past its budget",
            lambda: self.key_of("hopin")["spend"] > litellm_keys.APP_BUDGET_DOLLARS,
        )
        self.wait_for(
            "B1",
            "P's spend past the person budget",
            lambda: self.customer_spend(self.person) > litellm_keys.PERSON_BUDGET_DOLLARS,
        )
        self.wait_for("B1", "P's daily row", lambda: self.person_rows() > 0)  # fmt: skip
        self.expect_refused("B1", self.file_keys["hopin"], self.fingerprint())
        self.expect_refused("B1", self.file_keys["presentator"], self.person)
        self.stop_app()
        self.digest_b1 = self.database_digest()
        result = self.backed_up("B1")
        after = self.database_digest()
        expect(after == self.digest_b1, "B1: D changed during the backup with LiteLLM stopped")
        self.snapshot_b1 = self.last_snapshot()
        self.start_app()
        row = re.search(r"✓ litellm\s+backed up\s+(\w+) ·", result.stdout)
        expect(row is not None, f"B1: no backed-up row in {result.stdout.strip()[-300:]!r}")
        expect(self.last_snapshot().startswith(row[1]), "B1: the status names another snapshot")
        self.hold("B1", f"hopin's key past {litellm_keys.APP_BUDGET_DOLLARS} and P past "
                  f"{litellm_keys.PERSON_BUDGET_DOLLARS} dollars each refused, F unchanged; "
                  f"`hal backup litellm` exit 0, ✓ litellm backed up {row[1]}, the status "
                  f"names it; D {self.digest_b1} equal before and after it")  # fmt: skip

    def cells_b2_b3(self) -> None:
        target = self.scratch / "restored-litellm"
        restored = self.hal("restore", APP, "--target", str(target))
        expect(restored.returncode == 0, f"B2: hal restore exited {restored.returncode}")
        dump = target / DB_FOLDER / DUMP_NAME
        listed = {
            (found[1], found[3])
            for line in self.dump_tool(dump, "--list").splitlines()
            if (found := LISTED.match(line)) and found[2] == "public"
        }
        live = {
            tuple(line.split("|", 1))
            for line in self.query(
                "SELECT 'TABLE', tablename FROM pg_tables WHERE schemaname = 'public' UNION ALL"
                " SELECT 'VIEW', viewname FROM pg_views WHERE schemaname = 'public';"
            )
        }
        expect(listed == live, f"B2: dump only {sorted(listed - live)}, live only "
               f"{sorted(live - listed)}")  # fmt: skip
        tables = {name for kind, name in listed if kind == "TABLE"}
        missing = {MIGRATIONS_TABLE, self.count_table, *HAL_TABLES} - tables
        expect(not missing, f"B2: the dump lacks {sorted(missing)}")
        self.hold("B2", f"the dump lists {len(tables)} tables and {len(listed) - len(tables)} "
                  "views of schema public, exactly those of the live litellm-db; "
                  "_prisma_migrations and hal's six tables among them")  # fmt: skip
        rendered = self.dump_tool(dump, "--file=-")
        controls = [*(hashed(self.file_keys[app]) for app in APPS), self.person]
        found = sum(value in rendered for value in controls)
        leaked = sum(value in rendered for value in self.secret_values())
        expect(found == len(controls), f"B3: the search found {found} of {len(controls)} controls")
        expect(leaked == 0, f"B3: {leaked} secret values in the dump")
        self.hold("B3", f"the rendered dump holds {found} of {len(controls)} controls (each key's "
                  "SHA-256 and P) and none of the app keys in clear, the master key, its SHA-256, "
                  "the provider key and the database password")  # fmt: skip

    def cell_b4(self) -> None:
        tested = self.hal("restore", "--test", APP)
        snapshot = self.last_snapshot()[:8]
        expect(tested.returncode == 0, f"B4: hal restore --test exited {tested.returncode}: "
               f"{tested.stderr.strip()[-300:]}")  # fmt: skip
        expect(bool(re.search(rf"✓ litellm\s+restore proven {snapshot}", tested.stdout)),
               f"B4: {tested.stdout.strip()[-300:]!r}")  # fmt: skip
        self.hold("B4", f"`hal restore --test litellm` exit 0: ✓ litellm restore proven {snapshot}")

    def cell_b5(self) -> None:
        result = self.backed_up("B5", "--pre-apply", "--json")
        lines = result.stdout.strip().splitlines()
        expect(len(lines) == 1, f"B5: --json printed {len(lines)} lines")
        snapshot = json.loads(lines[0])["snapshot"]
        tested = self.hal("restore", "--test", APP, "--snapshot", snapshot)
        expect(tested.returncode == 0, f"B5: hal restore --test exited {tested.returncode}")
        expect(bool(re.search(rf"✓ litellm\s+restore proven {snapshot[:8]}", tested.stdout)),
               f"B5: {tested.stdout.strip()[-300:]!r}")  # fmt: skip
        self.hold("B5", f"--pre-apply --json printed one object naming {snapshot[:8]}; that "
                  "snapshot restore proven, exit 0")  # fmt: skip

    def lose_volume(self) -> None:
        self.compose("rm", "--stop", "--force", DATABASE, timeout=120)
        (volume,) = self.run([
            "docker", "volume", "ls", "--quiet",
            "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--filter", f"label=com.docker.compose.volume={DATABASE}",
        ]).stdout.split()  # fmt: skip
        self.run(["docker", "volume", "rm", volume])
        self.compose("up", "--detach", "--wait", "--no-deps", DATABASE, timeout=300)
        self.recreate_litellm()

    def cell_b6(self) -> None:
        self.lose_volume()
        self.make_keys("B6", APPS, budget_new=True)
        reset = first_of_next_month()
        rows = [self.key_of(app) for app in APPS]
        expect(all(row["spend"] == 0 for row in rows), "B6: a key's spend is not 0")
        expect(all(parsed_time(row["budget_reset_at"]) == reset for row in rows), "B6: a reset")
        expect(self.customer_row(self.person) is None, "B6: P has a customer row")
        daily = sum(self.count(table) for table in DAILY_TABLES)
        expect(daily == 0, f"B6: {daily} daily rows")
        before = len(self.provider_requests())
        answer = self.complete(self.file_keys["hopin"], user=self.person)
        self.served("B6", answer, self.provider_requests()[before:])
        self.hold("B6", f"after the volume's loss the key step planned the budget and three keys "
                  f"as new; each key by its hash at spend 0, reset {reset:%Y-%m-%d %H:%M} UTC; "
                  "P has no row, no daily rows; hopin's key with P served, F +1")  # fmt: skip

    def cell_b7(self) -> None:
        self.query(f'DELETE FROM "{self.count_table}";')  # noqa: S608 - the table is the shipped record's count_table
        self.backed_up("B7")
        snapshot = self.last_snapshot()
        tested = self.hal("restore", "--test", APP, "--snapshot", snapshot)
        line = rf"✗ litellm\s+not proven\s+verify: the restored table {self.count_table} is empty"
        expect(tested.returncode == ExitCode.FAILURE, f"B7: exit {tested.returncode}")
        expect(bool(re.search(line, tested.stdout)), f"B7: {tested.stdout.strip()[-300:]!r}")
        self.make_keys("B7", APPS, budget_new=False)
        self.hold("B7", f"no key rows: snapshot {snapshot[:8]} ✗ litellm not proven, verify: "
                  f"the restored table {self.count_table} is empty, exit "
                  f"{ExitCode.FAILURE.value}; the key step made the three keys again")  # fmt: skip

    # --- the live load (#974) ------------------------------------------------------------------

    def cell_l0(self) -> None:
        self.stop_app()
        digest, started = self.database_digest(), self.started_at()
        with self.live_run() as run:
            code, output = run.finish()
        refusal = f"stop it first: {command(Verb.STOP, APP)}"
        expect(code == ExitCode.REFUSED and refusal in output, f"L0: exit {code}: {output!r}")
        expect(self.started_at() == started, "L0: a container's StartedAt changed")
        expect(self.database_digest() == digest, "L0: D changed")
        self.hold("L0", f"no marker: exit {code}, {refusal}; no StartedAt changed; D unchanged")

    def cell_l1(self) -> None:
        self.switches.record(APP, datetime.now(UTC))
        self.compose("stop", DATABASE, timeout=120)
        output = self.live_answered("L1", b"yes\n", ExitCode.OK)
        loaded = f"litellm loaded {self.snapshot_b1[:MIN_SNAPSHOT_PREFIX]}"
        expect(loaded in " ".join(output.split()), f"L1: {output.strip()[-300:]!r}")
        states = {service: self.state_of(service) for service in (DATABASE, LITELLM, FRONT)}
        expect(states == {DATABASE: "running", LITELLM: "exited", FRONT: "exited"},
               f"L1: {states}")  # fmt: skip
        digest = self.database_digest()
        expect(digest == self.digest_b1, f"L1: D {digest} is not D at B1 {self.digest_b1}")
        self.start_app()
        self.expect_refused("L1", self.file_keys["hopin"], self.fingerprint())
        self.expect_refused("L1", self.file_keys["presentator"], self.person)
        changes = self.read_plan("L1").changes
        expect(not changes, f"L1: the key step plans {changes}")
        self.hold("L1", f"exit 0, ✓ {loaded}; {states}; D equals D at B1 ({digest}); hopin's "
                  "key and P refused before the provider, F unchanged; the key step plans no "
                  "change; no key hash and no P in the output")  # fmt: skip

    def cell_l2(self) -> None:
        changed = self.changed_digest("L2")
        self.query(f'CREATE VIEW "{BLOCKING_VIEW}" AS SELECT * FROM "{KEYS_TABLE}";')  # noqa: S608 - the names are this probe's literals
        try:
            output = " ".join(self.live_answered("L2", b"yes\n", ExitCode.FAILURE).split())
            digest = self.database_digest()
        finally:
            self.query(f'DROP VIEW "{BLOCKING_VIEW}";')
        failed = (
            "litellm load failed · pg_restore ended with exit 1 · a rerun loads the snapshot whole"
        )
        rerun = (f"next: {command(Verb.RESTORE, APP, '--live', '--snapshot')} "
                 f"{self.snapshot_b1[:MIN_SNAPSHOT_PREFIX]}")  # fmt: skip
        expect(failed in output and rerun in output, f"L2: {output[-300:]!r}")
        expect(digest == changed, f"L2: D {digest} is not D' {changed}")
        expect(self.state_of(LITELLM) == "exited", "L2: litellm runs")
        expect(self.person not in self.log_of(DATABASE), "L2: P in the database's log")
        self.hold("L2", "a view on the keys table the dump does not hold: exit 3, "
                  f"error: {failed}, {rerun}; D equals D' ({digest}); litellm stopped; P in "
                  "neither the output nor the database's log")  # fmt: skip

    def cells_l3_l4(self) -> None:
        digest = self.database_digest()
        self.compose("stop", DATABASE, timeout=120)
        self.live_answered("L3", b"no\n", ExitCode.FINDINGS)
        expect(self.state_of(DATABASE) == "exited", "L3: litellm-db runs")
        started = self.started_at()
        refused = self.hal("restore", APP, "--live", "--snapshot", self.snapshot_b1)
        expect(refused.returncode == ExitCode.REFUSED, f"L4: exit {refused.returncode}")
        expect(self.started_at() == started, "L4: a container started")
        self.compose("up", "--detach", "--wait", "--no-deps", DATABASE, timeout=300)
        expect(self.database_digest() == digest, "L3, L4: D changed")
        self.hold("L3", "answered no: exit 1; litellm-db still stopped; D unchanged")
        self.hold("L4", f"no terminal: exit 4, {refused.stderr.strip()!r}; nothing started; "
                  "D unchanged")  # fmt: skip

    def cell_l5(self) -> None:
        self.changed_digest("L5")
        litellm_started = self.started_at(LITELLM)
        with Stall(self.database_argv(), self.environment) as stall:
            with self.live_run() as killed:
                killed.read_until(QUESTION)
                killed.type(b"yes\n")
                self.wait_until_stalled("L5")
                killed.close()
            left = self.staging()
            expect(len(left) == 1, f"L5: {len(left)} staging directories after the kill")
            second = self.live_answered("L5", b"yes\n", ExitCode.REFUSED)
            expect("a load is still running" in second, f"L5: {second.strip()[-300:]!r}")
            stall.end()
        self.wait_for("L5", "no pg_restore session", lambda: not self.restore_sessions())
        expect(self.database_digest() == self.digest_b1, "L5: the killed run's load is not in")
        self.changed_digest("L5")
        self.live_answered("L5", b"yes\n", ExitCode.OK)
        expect(self.database_digest() == self.digest_b1, "L5: the third run did not load")
        expect(not left & self.staging(), "L5: the killed run's directory is still there")
        expect(self.state_of(LITELLM) == "exited", "L5: litellm runs")
        expect(self.started_at(LITELLM) == litellm_started, "L5: litellm was started")
        self.hold("L5", "the killed run's load ran to its own end (D equals D at B1); the second "
                  "run refused `a load is still running`, exit 4; the third loaded, exit 0, D "
                  "equals D at B1; the killed run's directory gone; litellm stopped")  # fmt: skip

    def cell_l6(self) -> None:
        changed = self.changed_digest("L6")
        with self.live_run() as control:
            control.read_until(QUESTION)
            control.type(INTERRUPT)
            code, output = control.finish()
        expect(code == ExitCode.INTERRUPTED and "interrupted · nothing loaded" in output,
               f"L6: control exit {code}: {output.strip()[-300:]!r}")  # fmt: skip
        expect(self.database_digest() == changed, "L6: the control changed D")
        with Stall(self.database_argv(), self.environment) as stall, self.live_run() as run:
            run.read_until(QUESTION)
            run.type(b"yes\n")
            self.wait_until_stalled("L6")
            run.type(INTERRUPT)
            time.sleep(1)
            run.process.send_signal(signal.SIGTERM)
            printed = run.quiet_for(QUIET_SECONDS)
            stall.end()
            code, output = run.finish()
        self.expect_no_leak("L6", output)
        expect(printed == "", f"L6: hal printed {printed!r} during the load")
        expect(code == ExitCode.OK and "✓ litellm" in output and "loaded" in output,
               f"L6: exit {code}: {output.strip()[-300:]!r}")  # fmt: skip
        expect(self.database_digest() == self.digest_b1, "L6: D is not D at B1")
        self.hold(
            "L6",
            f"control: Ctrl-C at the question, exit 130, interrupted · nothing "
            f"loaded, D equals D'; Ctrl-C and SIGTERM during the stall: nothing printed "
            f"for {QUIET_SECONDS} s, then ✓ litellm loaded, exit 0; D equals D at B1",
        )


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], BackupProbe)


if __name__ == "__main__":
    sys.exit(main())
