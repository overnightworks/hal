"""Probe of `hal expire` (#945 cells X1-X6): LiteLLM's database in the throwaway project of
litellm.py, with rows planted around the retention period, and the checkout's `hal expire`
pointed at that project. Nothing live and nothing paid: no request is sent, and the probe refuses
to start unless `internet` is internal and holds only the fakes.

    probe-run -k 50 1780 \\
        python3 probe/agent-service/litellm_expiry.py --scratch DIR

It starts `litellm-db` and `litellm`, waits until the database records every migration the
image ships as finished, then stops `litellm`, so no background job of LiteLLM writes while D is
taken. Rows are planted by SQL relative to the database's UTC day; fingerprints, tool names, keys
and budgets are random canaries, and no row value is printed. D is a digest per table of every
table but the five `hal expire` deletes from; D* the same over every table. Run it again on every
LiteLLM bump: a schema change shows here with the missing column's name, in production only as a
failed unit.

Exit 0: every cell held.
"""

from __future__ import annotations

import re
import secrets
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import (
    DATABASE,
    LITELLM,
    PROJECT,
    REPO,
    LitellmProbe,
    ProbeFailed,
    expect,
    run_scratch_probe,
)

from hal.litellm_expiry import RETENTION_DAYS, Kind

HAL = REPO / ".venv" / "bin" / "hal"
HAL_SECONDS = 300
MIGRATION_SECONDS = 600
# The number of migrations the image's litellm_proxy_extras ships, on the last line.
MIGRATIONS_PROGRAM = """\
import os, litellm_proxy_extras
folder = os.path.join(os.path.dirname(litellm_proxy_extras.__file__), "migrations")
print(sum(1 for entry in os.scandir(folder) if entry.is_dir() and entry.name[:1].isdigit()))
"""
HEALTHY_SECONDS = 120
TOOL_COLUMN = "last_used_at"
RENAMED_COLUMN = "last_used_at_probe"
EXPIRED_TABLES = {kind.value for kind in Kind}
ROW_LINE = re.compile(
    r" {2}[✓·] (person days|tool days|label days|tools|people) +deleted +(\d+) rows? · "
)
INSIDE, EDGE, OUTSIDE = RETENTION_DAYS - 1, RETENTION_DAYS, RETENTION_DAYS + 1


def canary(label: str) -> str:
    return f"{label}-{secrets.token_hex(10)}"


@dataclass(frozen=True)
class Run:
    exit_code: int
    out: list[str]
    err: list[str]


class ExpiryProbe(LitellmProbe):
    """litellm.py's database with LiteLLM's schema, and `hal expire` against it."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.canaries: list[str] = []

    def services_to_start(self) -> tuple[str, ...]:
        return (DATABASE, LITELLM)

    # --- plumbing -----------------------------------------------------------------------------

    def query(self, statement: str) -> list[str]:
        return self.sql(statement, "--tuples-only", "--no-align").stdout.splitlines()

    def name(self, label: str) -> str:
        value = canary(label)
        self.canaries.append(value)
        return value

    def digests(self, *, all_tables: bool) -> dict[str, str]:
        tables = self.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")
        chosen = [t for t in tables if all_tables or t not in EXPIRED_TABLES]
        expect(len(chosen) > len(EXPIRED_TABLES), f"the database holds {len(tables)} tables")
        union = " UNION ALL ".join(
            f"SELECT '{table}', coalesce(md5(string_agg(r::text, E'\\n' ORDER BY r::text)), '-')"  # noqa: S608 - the table names come from pg_tables and are quoted
            f' FROM "{table}" AS r'
            for table in chosen
        )
        return {line.split("|", 1)[0]: line.split("|", 1)[1] for line in self.query(union)}

    def present(self, table: str, column: str, value: str) -> bool:
        (count,) = self.query(f'SELECT count(*) FROM "{table}" WHERE "{column}" = \'{value}\'')  # noqa: S608 - table and column are this probe's literals and the value a token it generated
        return int(count) > 0

    def hal_expire(self) -> Run:
        result = self.run(
            ["env", "-u", "LOG_FORMAT", "-u", "NO_COLOR", str(HAL), "expire", "--project", PROJECT],
            check=False, timeout=HAL_SECONDS,
        )  # fmt: skip
        run = Run(result.returncode, result.stdout.splitlines(), result.stderr.splitlines())
        shown = result.stdout + result.stderr
        leaked = [value for value in self.canaries if value in shown]
        expect(not leaked, f"hal expire printed {len(leaked)} canaries")
        return run

    def wait_for_migrations(self) -> None:
        """Until every migration the image ships is recorded as finished, read from the database:
        no log line marks the end at every log level."""
        shipped = int(
            self.run(
                ["docker", "exec", "-i", self.container(LITELLM), "python3", "-"],
                stdin=MIGRATIONS_PROGRAM,
            ).stdout.split()[-1]
        )
        deadline = time.monotonic() + MIGRATION_SECONDS
        finished = total = 0
        while time.monotonic() < deadline:
            tables = set(self.query("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"))
            if "_prisma_migrations" in tables:
                (counted,) = self.query(
                    "SELECT count(finished_at), count(*) FROM _prisma_migrations"
                )
                finished, total = (int(number) for number in counted.split("|"))
                if finished == total >= shipped and tables >= EXPIRED_TABLES:
                    return
            time.sleep(2)
        state = self.run(
            ["docker", "inspect", "--format", "{{.State.Status}} restarts {{.RestartCount}}",
             self.container(LITELLM)]
        ).stdout.strip()  # fmt: skip
        raise ProbeFailed(f"{finished} of {total} migrations finished, {shipped} shipped; {state}")

    def wait_until_healthy(self) -> None:
        deadline = time.monotonic() + HEALTHY_SECONDS
        container = self.container(DATABASE)
        while time.monotonic() < deadline:
            state = self.run(
                ["docker", "inspect", "--format", "{{.State.Health.Status}}", container]
            ).stdout.strip()
            if state == "healthy":
                return
            time.sleep(1)
        expect(False, f"{DATABASE} is not healthy after {HEALTHY_SECONDS} s")

    # --- planting -----------------------------------------------------------------------------

    def person_day(self, fingerprint: str, days_back: int) -> None:
        self.sql(
            'INSERT INTO "LiteLLM_DailyEndUserSpend" (id, end_user_id, date, api_key, updated_at)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ('{self.name('day')}', '{fingerprint}', {utc_day(days_back)},"
            f" '{self.name('key-hash')}', now())"
        )

    def customer(self, fingerprint: str, spend: float, budget: str | None = None) -> None:
        link = "NULL" if budget is None else f"'{budget}'"
        self.sql(
            'INSERT INTO "LiteLLM_EndUserTable" (user_id, spend, budget_id)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ('{fingerprint}', {spend}, {link})"
        )

    def budget(self, max_budget: str) -> str:
        budget = self.name("budget")
        self.sql(
            'INSERT INTO "LiteLLM_BudgetTable" (budget_id, max_budget, created_by, updated_by)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ('{budget}', {max_budget}, 'probe', 'probe')"
        )
        return budget

    def tool_day(self, days_back: int) -> str:
        tool = self.name("tool")
        self.sql(
            'INSERT INTO "LiteLLM_DailyToolSpend" (date, tool_name, updated_at)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ({utc_day(days_back)}, '{tool}', now())"
        )
        return tool

    def tag_day(self, days_back: int) -> str:
        tag = self.name("tag")
        self.sql(
            'INSERT INTO "LiteLLM_DailyTagSpend" (id, tag, date, api_key, updated_at)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ('{self.name('tag-row')}', '{tag}', {utc_day(days_back)},"
            f" '{self.name('key-hash')}', now())"
        )
        return tag

    def tool(self, days_back: int) -> str:
        tool = self.name("tool")
        self.sql(
            'INSERT INTO "LiteLLM_ToolTable" (tool_id, tool_name, last_used_at)'  # noqa: S608 - every value is a token or a number this probe generated
            f" VALUES ('{self.name('tool-id')}', '{tool}', {utc_moment(days_back)})"
        )
        return tool

    def key(self) -> str:
        token = self.name("token")
        self.sql(f"INSERT INTO \"LiteLLM_VerificationToken\" (token) VALUES ('{token}')")  # noqa: S608 - every value is a token or a number this probe generated
        return token

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_for_migrations()
        self.compose("stop", LITELLM)
        planted = self.plant()
        before = self.digests(all_tables=False)
        first = self.hal_expire()
        self.cell_x1(first, planted)
        self.cell_x2(before, planted)
        self.cell_x3(first)
        self.cell_x4()
        fresh = self.plant_fresh()
        self.cell_x5(fresh)
        self.cell_x6(fresh)

    def plant(self) -> dict[str, str]:
        person = {name: self.name(f"person-{name}") for name in ("a", "b", "s", "l", "e", "d")}
        linked = self.budget("NULL")
        planted = {
            "budget-l": linked, "budget-other": self.budget("5"), "key": self.key(),
            "tool-day-inside": self.tool_day(INSIDE), "tool-day-outside": self.tool_day(OUTSIDE),
            "tool-day-edge": self.tool_day(EDGE),
            "tag-day-inside": self.tag_day(INSIDE), "tag-day-outside": self.tag_day(OUTSIDE),
            "tag-day-edge": self.tag_day(EDGE),
            "tool-inside": self.tool(INSIDE), "tool-outside": self.tool(OUTSIDE),
            **{f"person-{name}": value for name, value in person.items()},
        }  # fmt: skip
        self.person_day(person["a"], INSIDE)
        for name in ("b", "s", "l"):
            self.person_day(person[name], OUTSIDE)
        self.customer(person["a"], 0)
        self.customer(person["b"], 0)
        self.customer(person["s"], 0.25)
        self.customer(person["l"], 0, linked)
        self.person_day(person["e"], EDGE)
        self.person_day(person["d"], EDGE)
        self.customer(person["d"], 0)
        return planted

    def cell_x1(self, run: Run, planted: dict[str, str]) -> None:
        expect(run.exit_code == 0, f"X1: hal expire exited {run.exit_code}: {run.err[-2:]}")
        days = "LiteLLM_DailyEndUserSpend"
        expected = {
            (days, "end_user_id", planted["person-a"]): True,
            **{(days, "end_user_id", planted[f"person-{n}"]): False for n in ("b", "s", "l")},
            (days, "end_user_id", planted["person-e"]): True,
            (days, "end_user_id", planted["person-d"]): True,
            ("LiteLLM_DailyToolSpend", "tool_name", planted["tool-day-edge"]): True,
            ("LiteLLM_EndUserTable", "user_id", planted["person-d"]): True,
            ("LiteLLM_DailyToolSpend", "tool_name", planted["tool-day-inside"]): True,
            ("LiteLLM_DailyToolSpend", "tool_name", planted["tool-day-outside"]): False,
            ("LiteLLM_DailyTagSpend", "tag", planted["tag-day-edge"]): True,
            ("LiteLLM_DailyTagSpend", "tag", planted["tag-day-inside"]): True,
            ("LiteLLM_DailyTagSpend", "tag", planted["tag-day-outside"]): False,
            ("LiteLLM_ToolTable", "tool_name", planted["tool-inside"]): True,
            ("LiteLLM_ToolTable", "tool_name", planted["tool-outside"]): False,
            **{("LiteLLM_EndUserTable", "user_id", planted[f"person-{n}"]): True
               for n in ("a", "s", "l")},
            ("LiteLLM_EndUserTable", "user_id", planted["person-b"]): False,
        }  # fmt: skip
        wrong = [table for (table, column, value), kept in expected.items()
                 if self.present(table, column, value) is not kept]  # fmt: skip
        expect(not wrong, f"X1: {len(wrong)} planted rows wrong in {sorted(set(wrong))}")
        kept = sum(expected.values())
        self.hold("X1", f"exit 0; {len(expected) - kept} planted rows gone, {kept} kept, as wanted")

    def cell_x2(self, before: dict[str, str], planted: dict[str, str]) -> None:
        after = self.digests(all_tables=False)
        changed = sorted(table for table in before.keys() | after.keys()
                         if before.get(table) != after.get(table))  # fmt: skip
        expect(not changed, f"X2: D changed in {changed}")
        kept = [
            self.present("LiteLLM_VerificationToken", "token", planted["key"]),
            self.present("LiteLLM_BudgetTable", "budget_id", planted["budget-l"]),
            self.present("LiteLLM_BudgetTable", "budget_id", planted["budget-other"]),
        ]
        expect(all(kept), f"X2: key and budgets present {kept}")
        expect("_prisma_migrations" in after, "X2: D lacks _prisma_migrations")
        self.hold("X2", f"D equal over {len(after)} tables, key, budgets and migrations included")

    def cell_x3(self, run: Run) -> None:
        rows = [ROW_LINE.match(line) for line in run.out[:-1]]
        counts = [(match[1], int(match[2])) for match in rows if match]
        wanted = [
            ("person days", 3), ("tool days", 1), ("label days", 1), ("tools", 1), ("people", 1),
        ]  # fmt: skip
        expect(counts == wanted and len(rows) == len(wanted), f"X3: rows {counts}")
        expect(run.out[-1].startswith("✓ expire done · 7 rows · "), "X3: the verdict differs")
        expect(run.err == [], f"X3: stderr holds {len(run.err)} lines")
        self.hold("X3", f"rows {counts}, verdict {run.out[-1]!r}, no canary printed")

    def cell_x4(self) -> None:
        before = self.digests(all_tables=True)
        run = self.hal_expire()
        counts = [int(match[2]) for line in run.out if (match := ROW_LINE.match(line))]
        expect(run.exit_code == 0 and counts == [0] * 5, f"X4: exit {run.exit_code} {counts}")
        expect(self.digests(all_tables=True) == before, "X4: D* changed")
        self.hold("X4", f"exit 0, five rows of 0, D* equal over {len(before)} tables")

    def plant_fresh(self) -> dict[str, str]:
        person = self.name("person-f")
        self.person_day(person, OUTSIDE)
        self.customer(person, 0)
        return {
            "person": person, "tool-day": self.tool_day(OUTSIDE),
            "tag-day": self.tag_day(OUTSIDE), "tool": self.tool(OUTSIDE),
        }  # fmt: skip

    def fresh_present(self, fresh: dict[str, str]) -> bool:
        return all([
            self.present("LiteLLM_DailyEndUserSpend", "end_user_id", fresh["person"]),
            self.present("LiteLLM_EndUserTable", "user_id", fresh["person"]),
            self.present("LiteLLM_DailyToolSpend", "tool_name", fresh["tool-day"]),
            self.present("LiteLLM_DailyTagSpend", "tag", fresh["tag-day"]),
            self.present("LiteLLM_ToolTable", "tool_name", fresh["tool"]),
        ])  # fmt: skip

    def cell_x5(self, fresh: dict[str, str]) -> None:
        before = self.digests(all_tables=True)
        self.compose("stop", DATABASE)
        run = self.hal_expire()
        self.compose("start", DATABASE)
        self.wait_until_healthy()
        off = ["  · litellm         not running    nothing deleted", "✓ expire done"]
        expect(run.exit_code == 0 and run.out == off, f"X5: exit {run.exit_code} {run.out}")
        expect(self.digests(all_tables=True) == before, "X5: D* changed across the stop")
        expect(self.fresh_present(fresh), "X5: a fresh row is gone")
        self.hold("X5", f"exit 0, {run.out[0].strip()!r}; D* equal after the restart")

    def cell_x6(self, fresh: dict[str, str]) -> None:
        tools = '"LiteLLM_ToolTable"'
        self.sql(f"ALTER TABLE {tools} RENAME COLUMN {TOOL_COLUMN} TO {RENAMED_COLUMN}")
        try:
            before = self.digests(all_tables=True)
            run = self.hal_expire()
            after = self.digests(all_tables=True)
        finally:
            self.sql(f"ALTER TABLE {tools} RENAME COLUMN {RENAMED_COLUMN} TO {TOOL_COLUMN}")
        failed = ["  ✗ litellm         not expired    psql ended with exit 1 · nothing deleted"]
        error = ["error: litellm not expired · nothing deleted", "next: hal expire"]
        expect(run.exit_code == 3, f"X6: hal expire exited {run.exit_code}")
        expect(run.out == failed and run.err == error, f"X6: {run.out} {run.err}")
        expect(after == before and self.fresh_present(fresh), "X6: a row changed")
        self.hold("X6", f"exit 3, {run.out[0].strip()!r}, D* equal; the column renamed back")


def utc_day(days_back: int) -> str:
    return f"to_char((now() AT TIME ZONE 'utc')::date - {days_back}, 'YYYY-MM-DD')"


def utc_moment(days_back: int) -> str:
    return f"(now() AT TIME ZONE 'utc') - interval '{days_back} days'"


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], ExpiryProbe)


if __name__ == "__main__":
    sys.exit(main())
