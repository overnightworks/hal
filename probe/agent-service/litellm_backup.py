"""Probe of LiteLLM's backup (#970 cells B1-B7): `hal backup litellm`, its pre-apply snapshot,
`hal restore --test litellm` and a lost volume rebuilt through `hal apply`'s key step, on the stack
of litellm.py in its throwaway project. Nothing live and nothing paid: the probe refuses to start
unless `internet` is internal and holds only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/litellm_backup.py --scratch DIR

Measured: a run takes about three minutes and its teardown a few seconds (K 50 s, CAP 1780 s).

The checkout's `hal` runs under the scratch HOME, with its own restic repository, password and
status, and with `--apps` naming a scratch record: the shipped `litellm` record of
`backup/apps.toml` with only `compose_project` replaced by the probe's project. The key step
makes the person budget and the three app keys at the code defaults; steered usage puts hopin's
key past its budget and the fingerprint P, a random canary, past the person budget. F is the fake
provider's request log. Keys are scratch values the probe generates and never prints; the search
of the dump prints counts only. Exit 0: every cell held.
"""

from __future__ import annotations

import dataclasses
import json
import re
import secrets
import subprocess
import sys
import tomllib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import DATABASE, PROJECT, expect, hashed, run_scratch_probe
from litellm_admission import APP_PUSH, PERSON_PUSH, AdmissionProbe
from litellm_expiry import HAL, HAL_SECONDS
from litellm_keys import APPS, KeysProbe, first_of_next_month, parsed_time
from scratch_secrets import write_new

from hal.backup.apps import parse_apps
from hal.backup.cli import DEFAULT_APPS
from hal.stack import litellm_keys
from hal.stack.litellm_keys import KeysDone, Target

APP = "litellm"
COUNT_TABLE = "LiteLLM_VerificationToken"
HAL_TABLES = (
    COUNT_TABLE,
    "LiteLLM_BudgetTable",
    "LiteLLM_EndUserTable",
    "LiteLLM_DailyEndUserSpend",
    "LiteLLM_DailyToolSpend",
    "LiteLLM_ToolTable",
)
DAILY_TABLES = ("LiteLLM_DailyEndUserSpend", "LiteLLM_DailyToolSpend")
MIGRATIONS_TABLE = "_prisma_migrations"
RESTIC_PASSWORD_FILE = Path(".secrets/restic/password")
STATUS_FILE = Path(".local/state/edge/backup-status.json")
DUMP_FILE = Path("db/db.dump")
DUMP_SECONDS = 120
FAILURE_EXIT = 3
# A TABLE or VIEW entry of `pg_restore --list`: "<id>; <oid> <oid> TABLE <schema> <name> <owner>".
LISTED = re.compile(r'^\d+; \d+ \d+ (TABLE|VIEW) (\S+) "?([^"\s]+)"? \S+$')


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
        password = self.home / RESTIC_PASSWORD_FILE
        password.parent.mkdir(mode=0o700)
        write_new(password, secrets.token_urlsafe(32).encode(), 0o600)
        self.apps_file = scratch / "apps.toml"
        self.write_scratch_record()
        self.person = self.fingerprint()

    def write_scratch_record(self) -> None:
        """The shipped record with the probe's project; it must parse to the shipped app with
        only that one field changed."""
        shipped_text = DEFAULT_APPS.read_text()
        record = {**tomllib.loads(shipped_text)["app"][APP], "compose_project": PROJECT}
        self.apps_file.write_text(toml_table(f"app.{APP}", record))
        (declared,) = parse_apps(self.apps_file.read_text())
        (shipped,) = (app for app in parse_apps(shipped_text) if app.name == APP)
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
        status = json.loads((self.home / STATUS_FILE).read_text())
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
            ["docker", "exec", "-i", self.container(DATABASE), "pg_restore", *arguments],
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

    def make_keys(self, cell: str, apps: tuple[str, ...], budget_new: bool) -> None:
        """The key step plans exactly these new keys (and the person budget when `budget_new`)
        and makes them."""
        plan = self.read_plan(cell)
        budget = [(Target.BUDGET, self.budget_id, True)] if budget_new else []
        wanted = [*budget, *((Target.KEY, app, True) for app in apps)]
        planned = [(change.target, change.subject, change.new) for change in plan.changes]
        expect(planned == wanted, f"{cell}: planned {planned}")
        result = self.run_step(plan)
        expect(
            isinstance(result, KeysDone) and len(result.done) == len(wanted), f"{cell}: {result}"
        )

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
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
        result = self.backed_up("B1")
        row = re.search(r"✓ litellm\s+backed up\s+(\w+) ·", result.stdout)
        expect(row is not None, f"B1: no backed-up row in {result.stdout.strip()[-300:]!r}")
        expect(self.last_snapshot().startswith(row[1]), "B1: the status names another snapshot")
        self.hold("B1", f"hopin's key past {litellm_keys.APP_BUDGET_DOLLARS} and P past "
                  f"{litellm_keys.PERSON_BUDGET_DOLLARS} dollars each refused, F unchanged; "
                  f"`hal backup litellm` exit 0, ✓ litellm backed up {row[1]}, the status "
                  "names it")  # fmt: skip

    def cells_b2_b3(self) -> None:
        target = self.scratch / "restored-litellm"
        restored = self.hal("restore", APP, "--target", str(target))
        expect(restored.returncode == 0, f"B2: hal restore exited {restored.returncode}")
        dump = target / DUMP_FILE
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
        missing = {MIGRATIONS_TABLE, *HAL_TABLES} - tables
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
        self.query(f'DELETE FROM "{COUNT_TABLE}";')  # noqa: S608 - the table is this probe's literal
        self.backed_up("B7")
        snapshot = self.last_snapshot()
        tested = self.hal("restore", "--test", APP, "--snapshot", snapshot)
        line = rf"✗ litellm\s+not proven\s+verify: the restored table {COUNT_TABLE} is empty"
        expect(tested.returncode == FAILURE_EXIT, f"B7: exit {tested.returncode}")
        expect(bool(re.search(line, tested.stdout)), f"B7: {tested.stdout.strip()[-300:]!r}")
        self.make_keys("B7", APPS, budget_new=False)
        self.hold("B7", f"no key rows: snapshot {snapshot[:8]} ✗ litellm not proven, verify: "
                  f"the restored table {COUNT_TABLE} is empty, exit {FAILURE_EXIT}; the key "
                  "step made the three keys again")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], BackupProbe)


if __name__ == "__main__":
    sys.exit(main())
