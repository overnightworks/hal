"""Probe of `hal apply`'s key step (#964 cells S1-S9, HAL-2.6m's S10, #965 cells A2-A8, #894 cell
S0): the step's plan and run, through the one-off `litellm-keys`, against the LiteLLM of
litellm.py in its throwaway project.
Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and holds
only the fakes. It runs in hal's environment, which holds the agent-runtime client:

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/agent-service/litellm_keys.py --scratch DIR

Measured: a run takes about four minutes and its teardown a few seconds (K 30 s, CAP 1800 s).

It writes three app key files beside litellm.py's scratch secrets and drives the checkout's
`hal.stack.litellm_keys` with a Compose runner on the probe's project, which records every argv,
standard input, standard output and standard error the step's one-off sees. The step plans as
`hal apply` with Keycloak on and running; the runner answers its `realm-observer` call with the
scenario's members of the admin group (cell LM1 of probe/keycloak proves the real answer), an empty
group in the S cells. LiteLLM runs at log level INFO, as litellm.py sets it for LA. F is the fake
provider's request log, LA LiteLLM's log, D a digest of `LiteLLM_VerificationToken`,
`LiteLLM_BudgetTable` and `LiteLLM_EndUserTable` read by SQL, P the rows and partials the step's
plans and runs print. Keys, subjects and fingerprints are scratch values the probe generates and
never prints; the probe's own SQL names keys by alias, never by hash. LiteLLM starts on the
shipped config.yaml (S0) and gets the short budget period only at S5. Exit 0: every cell held.
"""

from __future__ import annotations

import contextlib
import io
import json
import secrets
import subprocess
import sys
import uuid
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import yaml
from agent_runtime_client.turn import Principal, person_fingerprint
from litellm import (
    DATABASE,
    DEFAULT_MODEL,
    LITELLM,
    REPO,
    error_of,
    expect,
    hashed,
    run_scratch_probe,
    shipped_config,
)
from litellm_ca import write_new
from litellm_key_files import APP_KEYS_FOLDER, APPS, KeyFiles

from hal.output import Row, write_line, write_row
from hal.output.command import Verb, command
from hal.stack import api_limits, core, litellm_keys
from hal.stack.litellm_keys import (
    ADMIN_BUDGET_ID,
    ADMIN_GROUP,
    Change,
    KeysDone,
    KeysFailed,
    KeysPlan,
    KeysResult,
    KeysStep,
    NotRead,
    RowChange,
    Target,
)
from hal.stack.plan_rows import keys_plan_rows
from hal.stack.realm import OBSERVER_SERVICE
from hal.stack.realm.reconcile import KEYCLOAK_SERVICE, REALM_UNIT, MembersNotRead
from hal.stack.result_rows import keys_partial, keys_rows

FOURTH_MODEL = "text/fourth"
TABLES = ("LiteLLM_VerificationToken", "LiteLLM_BudgetTable", "LiteLLM_EndUserTable")
CUSTOMERS = TABLES.index("LiteLLM_EndUserTable")
CUSTOMER_TABLE = TABLES[CUSTOMERS]
ISSUER = "https://auth.probe.invalid/realms/hallucinai"  # the scenario's; LM1 proves Keycloak's
PEOPLE = ("O", "O2", "O3", "X", "Y")
OTHER_BUDGET = "probe-by-hand"
OBSERVER_STOPPED = "realm-observer: stopped"
NOT_READ_PARTIAL = (
    f"partial, {ADMIN_BUDGET_ID} members not read from Keycloak",
    command(Verb.APPLY),
)


@dataclass(frozen=True)
class Person:
    """A scenario person: a Keycloak id and the fingerprint the client's recipe makes of it."""

    name: str
    subject: str = field(default_factory=lambda: str(uuid.uuid4()), repr=False)

    @property
    def fingerprint(self) -> str:
        return person_fingerprint(Principal(iss=ISSUER, sub=self.subject))


class KeysProbe(KeyFiles):
    """litellm.py's stack without the service, and the key step against it."""

    # S0 starts LiteLLM on the shipped config.yaml; S5's recreate brings the short budget period
    # that A7 waits on.
    rescheduled = False

    # The cells' methods in the order they run, each on what the ones before left.
    CELLS = ("cell_s1", "cell_s2", "cell_s3", "cell_s4", "cell_s5", "cell_s10", "cell_s6",
             "cell_s7", "cell_s9", "cell_a2", "cell_a5", "cell_a3", "cell_a7", "cell_a4", "cell_a8",
             "cell_a6", "cell_s8")  # fmt: skip

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.earlier_logs: list[str] = []
        self.people = {name: Person(name) for name in PEOPLE}
        self.members: list[str] | None = []  # the admin group's ids; None: no such group
        self.observer_stopped = False
        self.keycloak_running = True
        self.printed: list[str] = []  # P

    # --- plumbing -----------------------------------------------------------------------------

    def write_litellm_config(self, config: dict) -> None:
        if self.rescheduled:
            super().write_litellm_config(config)
            return
        self.litellm_config.write_text(yaml.safe_dump(config, sort_keys=False), encoding="utf-8")
        self.litellm_config.chmod(0o644)

    def key_rows(self, **asked: object) -> list[dict]:
        return self.admin("POST", "/v2/key/info", asked)["info"]

    def key_of(self, app: str) -> dict:
        (row,) = self.key_rows(keys=[hashed(self.file_keys[app])])
        return row

    def budget(self) -> dict:
        (row,) = self.admin("POST", "/budget/info", {"budgets": [self.budget_id]})
        return row

    def models(self) -> list[str]:
        return [entry["id"] for entry in self.admin("GET", "/v1/models")["data"]]

    def query(self, statement: str) -> list[str]:
        """psql with the statement on standard input."""
        command = [
            "docker",
            "exec",
            "-i",
            self.container(DATABASE),
            "psql",
            *self.database_options(),
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
        ]
        return self.run(command, stdin=statement).stdout.splitlines()

    def digest(self, tables: tuple[str, ...] = TABLES) -> list[str]:
        """Each table's complete rows as one md5; only the digests leave the database."""
        return [
            self.query(
                f"SELECT coalesce(md5(string_agg(r::text, E'\\n' ORDER BY r::text)), '-')"  # noqa: S608 - the table names are this probe's literals
                f' FROM "{table}" AS r;'
            )[0]
            for table in tables
        ]

    def set_key(self, app: str, assignments: str) -> None:
        table = "LiteLLM_VerificationToken"
        statement = f"UPDATE \"{table}\" SET {assignments} WHERE key_alias = '{app}';"  # noqa: S608 - the app and the assignments are this probe's literals
        self.query(statement)

    def change_budget(self, max_budget: float) -> None:
        self.admin(
            "POST", "/budget/update", {"budget_id": self.budget_id, "max_budget": max_budget}
        )

    def change_by_hand(self, app: str, **settings: object) -> None:
        self.admin("POST", "/key/update", {"key": self.file_keys[app], **settings})

    def step_runner(
        self, command: list[str], timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        if OBSERVER_SERVICE not in command:
            return super().step_runner(command, timeout, stdin)
        answer = self.observer_answer(command)
        self.seen.argv.append(command)
        self.seen.stdin.append("")  # one input per one-off, so a call's argv and input pair up
        self.seen.output += [answer.stdout, answer.stderr]
        return answer

    def observer_answer(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        """The members mode's answer as scenario data: absent, stopped after its output, or the
        members; its lines are the program's own."""
        if self.members is None:
            absent = f"realm-observer: hallucinai has no group {ADMIN_GROUP}\n"
            return subprocess.CompletedProcess(command, 1, "", absent)
        document = json.dumps({"issuer": ISSUER, "members": self.members}) + "\n"
        if self.observer_stopped:
            return subprocess.CompletedProcess(command, 1, document, f"{OBSERVER_STOPPED}\n")
        return subprocess.CompletedProcess(command, 0, document, "")

    def plan(self) -> KeysStep:
        """The step as `hal apply` plans it with the gates of LiteLLM and Keycloak on and nothing
        starting in this run; its rows go to P."""
        states = self.engine.states()
        if self.keycloak_running:
            states[KEYCLOAK_SERVICE] = {"running"}
        gates = {litellm_keys.UNIT: core.Gate.ON, REALM_UNIT: core.Gate.ON}
        plan = litellm_keys.plan_keys(self.engine, states, REPO, self.api_settings(), gates, (), ())
        self.print_rows(keys_plan_rows(plan))
        return plan

    def run_step(self, plan: KeysStep) -> KeysResult | None:
        result = super().run_step(plan)
        if result is not None:
            self.print_rows(keys_rows(result))
            if (partial := keys_partial(result)) is not None:
                self.printed.append(partial[0])
        return result

    def print_rows(self, rows: Iterable[Row]) -> None:
        with contextlib.redirect_stdout(io.StringIO()) as printed:
            for row in rows:
                write_row(row)
        self.printed += printed.getvalue().splitlines()

    def name_of(self, user_id: str) -> str:
        """A row's scenario name, so no message prints its fingerprint."""
        names = {person.fingerprint: person.name for person in self.people.values()}
        return names.get(user_id, "another row")

    def customer(self, person: Person, columns: str) -> list[str]:
        """The person's row in D's customer table, as `columns` of one SELECT name it."""
        row = f"\"{CUSTOMER_TABLE}\" AS r WHERE user_id = '{person.fingerprint}'"
        return self.query(f"SELECT {columns} FROM {row};")  # noqa: S608 - the columns and the fingerprint are the probe's own

    def customer_text(self, person: Person) -> list[str]:
        return self.customer(person, "r::text")

    def set_spend(self, person: Person, spend: float) -> None:
        row = f"user_id = '{person.fingerprint}'"
        self.query(f'UPDATE "{CUSTOMER_TABLE}" SET spend = {spend} WHERE {row};')  # noqa: S608 - the spend and the fingerprint are the probe's own

    def new_customer(self, person: Person, **fields: object) -> None:
        self.admin("POST", "/customer/new", {"user_id": person.fingerprint, **fields})

    def budget_ids(self) -> list[str]:
        return self.query('SELECT budget_id FROM "LiteLLM_BudgetTable" ORDER BY budget_id;')

    def row_changes(self, plan: KeysPlan) -> list[tuple[str, bool, bool]]:
        """The plan's row changes by name; any other change as a name of its own."""
        return [
            (self.name_of(change.fingerprint), change.link, change.new)
            if isinstance(change, RowChange)
            else (change.subject, False, False)
            for change in plan.changes
        ]

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.steer_fake()
        self.wait_until_listening()
        for cell in self.CELLS:
            getattr(self, cell)()

    def cell_s1(self) -> None:
        plan = self.read_plan("S1")
        planned = [(change.target, change.subject, change.new) for change in plan.changes]
        expect(
            planned
            == [
                (Target.BUDGET, self.budget_id, True),
                *((Target.KEY, app, True) for app in APPS),
                (Target.BUDGET, ADMIN_BUDGET_ID, True),
            ],
            f"S1: planned {planned}",
        )
        result = self.run_step(plan)
        expect(isinstance(result, KeysDone) and len(result.done) == 5, f"S1: {result}")
        budget = self.budget()
        expect(
            (budget["max_budget"], budget["budget_duration"])
            == (api_limits.PERSON_BUDGET_DOLLARS, litellm_keys.BUDGET_DURATION),
            "S1: budget",
        )
        models, reset = sorted(self.models()), first_of_next_month()
        self.expect_default_keys(models, reset)
        fingerprint = self.fingerprint()
        expect(not self.provider_requests(), "S0: F holds a request before S1's first call")
        for app in APPS:
            before = len(self.provider_requests())
            answer = self.complete(self.file_keys[app], user=fingerprint)
            self.served("S1", answer, self.provider_requests()[before:])
        self.hold(
            "S0",
            "on the shipped config.yaml, F held no request from the stack's start through "
            "LiteLLM's migration and S1's read and write; each of S1's calls then added its one "
            "line (the control)",
        )
        self.wait_for(
            "S1", "the person's row", lambda: self.end_user_budget(fingerprint) is not None
        )
        expect(self.end_user_budget(fingerprint) == [""], "S1: the person's row links a budget")
        self.wait_for(
            "S1", "each key's spend", lambda: all(self.key_of(app)["spend"] > 0 for app in APPS)
        )
        spent = sum(self.key_of(app)["spend"] for app in APPS)  # D holds once the row has it all
        self.wait_for(
            "S1", "the person's spend", lambda: abs(self.customer_spend(fingerprint) - spent) < 1e-9
        )
        self.hold(
            "S1",
            f"budget {self.budget_id} and three keys made by hash with the defaults, "
            f"models as /v1/models, reset {reset:%Y-%m-%d %H:%M} UTC, and {ADMIN_BUDGET_ID} for "
            "the empty admin group; each key served through the front; the person's row keeps "
            "budget_id NULL",
        )

    def expect_default_keys(self, models: list[str], reset: datetime) -> None:
        for app in APPS:
            row = self.key_of(app)
            settings = (
                row["key_alias"],
                row["max_budget"],
                row["budget_duration"],
                row["max_parallel_requests"],
                sorted(row["models"]),
                row["allowed_routes"],
                row["rpm_limit"],
                row["tpm_limit"],
            )
            wanted = (
                app,
                api_limits.APP_BUDGET_DOLLARS,
                litellm_keys.BUDGET_DURATION,
                api_limits.MAX_PARALLEL_REQUESTS,
                models,
                list(litellm_keys.ROUTES),
                None,
                None,
            )
            expect(settings == wanted, f"S1: {app}'s key holds {settings}")
            expect(
                parsed_time(row["budget_reset_at"]) == reset,
                f"S1: {app} resets {row['budget_reset_at']}",
            )

    def end_user_budget(self, fingerprint: str) -> list[str] | None:
        table = "LiteLLM_EndUserTable"
        statement = (
            f"SELECT coalesce(budget_id, '') FROM \"{table}\" WHERE user_id = '{fingerprint}';"  # noqa: S608 - the fingerprint is a token this probe generated
        )
        return self.query(statement) or None

    def cell_s2(self) -> None:
        before, calls = self.digest(), len(self.seen.argv)
        plan = self.read_plan("S2")
        expect(plan == KeysPlan(), f"S2: planned {plan}")
        expect(self.run_step(plan) is None, "S2: the step acted")
        ran = [argv for argv in self.seen.argv[calls:] if litellm_keys.KEYS_SERVICE in argv]
        expect(len(ran) == 1 and "--read" in ran[0], f"S2: {len(ran)} key one-offs ran")
        expect(self.digest() == before, "S2: D changed")
        self.hold(
            "S2",
            "nothing to change; one --read and no --write ran beside the members read; D unchanged",
        )

    def cell_s3(self) -> None:
        self.query("DELETE FROM \"LiteLLM_VerificationToken\" WHERE key_alias = 'hopin';")
        desired = litellm_keys.desired_key(
            "hopin", tuple(self.models()), api_limits.NONE_SET.limits_of("hopin")
        )
        made = {
            name: list(value) if isinstance(value, tuple) else value
            for name, value in desired.items()
            if value is not None
        }
        self.admin("POST", "/key/generate", {**made, "key": self.file_keys["hopin"]})
        self.set_key("hopin", "spend = 3")
        reset = self.key_of("hopin")["budget_reset_at"]
        self.change_budget(1.9)
        plan = self.read_plan("S3")
        expect([change.subject for change in plan.changes] == [self.budget_id], f"S3: {plan}")
        expect(isinstance(self.run_step(plan), KeysDone), "S3: the run failed")
        expect(len(self.key_rows(key_aliases=["hopin"])) == 1, "S3: hopin has another key")
        row = self.key_of("hopin")
        expect((row["spend"], row["budget_reset_at"]) == (3, reset), f"S3: spend {row['spend']}")
        self.hold("S3", "one key for hopin by hash and by alias; its spend 3 and reset unchanged")

    def cell_s4(self) -> None:
        self.change_by_hand(
            "songmaker", max_budget=7.0, max_parallel_requests=2, rpm_limit=60, tpm_limit=1000
        )
        self.set_key("songmaker", "spend = 1.25")
        self.change_budget(1.5)
        key_reset, budget_reset = (
            self.key_of("songmaker")["budget_reset_at"],
            self.budget()["budget_reset_at"],
        )
        plan = self.read_plan("S4")
        fields = {change.subject: {f.name for f in change.fields} for change in plan.changes}
        expect(
            fields
            == {
                self.budget_id: {"max_budget"},
                "songmaker": {"max_budget", "max_parallel_requests", "rpm_limit", "tpm_limit"},
            },
            f"S4: {fields}",
        )
        expect(isinstance(self.run_step(plan), KeysDone), "S4: the run failed")
        row, budget = self.key_of("songmaker"), self.budget()
        held = (
            row["max_budget"],
            row["max_parallel_requests"],
            row["rpm_limit"],
            row["tpm_limit"],
            budget["max_budget"],
        )
        wanted = (
            api_limits.APP_BUDGET_DOLLARS,
            api_limits.MAX_PARALLEL_REQUESTS,
            None,
            None,
            api_limits.PERSON_BUDGET_DOLLARS,
        )
        expect(held == wanted, f"S4: {held}")
        expect(
            (row["spend"], row["budget_reset_at"], budget["budget_reset_at"])
            == (1.25, key_reset, budget_reset),
            "S4: a spend or a reset moved",
        )
        self.hold(
            "S4",
            "10, 5, none, none and 2; no budget_duration sent; spend and both resets unchanged",
        )

    def cell_s5(self) -> None:
        config = shipped_config()
        self.rescheduled = True
        fourth = {**config["model_list"][0], "model_name": FOURTH_MODEL}
        self.write_litellm_config({**config, "model_list": [*config["model_list"], fourth]})
        self.earlier_logs.append(self.log_of(LITELLM))  # LA of the container the recreate ends
        self.recreate_litellm()
        plan = self.read_plan("S5")
        added = {
            change.subject: [f.new for f in change.fields if f.name == "models"]
            for change in plan.changes
        }
        expect(
            set(added) == set(APPS) and all(FOURTH_MODEL in models[0] for models in added.values()),
            f"S5: {added}",
        )
        expect(isinstance(self.run_step(plan), KeysDone), "S5: the run failed")
        models = sorted(self.models())
        expect(all(sorted(self.key_of(app)["models"]) == models for app in APPS), "S5: models")
        self.hold(
            "S5",
            f"the plan names each key's models change; after the run each key holds "
            f"the {len(models)} names /v1/models lists",
        )

    def cell_s10(self) -> None:
        self.write_litellm_config(shipped_config())  # the mirror of S5: its name leaves again
        self.earlier_logs.append(self.log_of(LITELLM))
        self.recreate_litellm()
        plan = self.read_plan("S10")
        kept = {
            change.subject: [f.new for f in change.fields if f.name == "models"]
            for change in plan.changes
        }
        dropped = all(len(new) == 1 and FOURTH_MODEL not in new[0] for new in kept.values())
        expect(set(kept) == set(APPS) and dropped, f"S10: {kept}")
        expect(isinstance(self.run_step(plan), KeysDone), "S10: the run failed")
        models = sorted(self.models())
        expect(FOURTH_MODEL not in models, f"S10: /v1/models still lists {FOURTH_MODEL}")
        for app in APPS:
            row, listed = sorted(self.key_of(app)["models"]), self.listed(self.file_keys[app])
            expect(row == listed == models, f"S10: {app}'s key holds {row} and lists {listed}")
        self.hold("S10", f"{FOURTH_MODEL} dropped from config.yaml: the plan names each key's "
                  "models change without it; after the run each key holds and lists through the "
                  f"front the {len(models)} names /v1/models lists")  # fmt: skip

    def cell_s6(self) -> None:
        old_key = self.file_keys["hopin"]
        self.file_keys["hopin"] = self.write_app_key("hopin", replace=True)
        self.steer_fake()
        self.change_budget(1.5)
        self.change_by_hand("songmaker", max_budget=7.0)
        plan = self.read_plan("S6")
        expect(plan.name_taken == ("hopin",), f"S6: name taken {plan.name_taken}")
        expect(
            [change.subject for change in plan.changes] == [self.budget_id, "songmaker"],
            f"S6: {plan.changes}",
        )
        result = self.run_step(plan)
        expect(isinstance(result, KeysDone) and result.name_taken == ("hopin",), f"S6: {result}")
        partial = keys_partial(result)
        expect(partial == ("partial, hopin name taken", None), f"S6: {partial}")
        (old,) = self.key_rows(keys=[hashed(old_key)])
        expect(old["key_alias"] == "hopin", "S6: the old key lost its name")
        expect(not self.key_rows(keys=[hashed(self.file_keys["hopin"])]), "S6: a key for the file")
        self.file_keys["hopin"] = old_key
        self.restore_app_key("hopin", old_key)
        self.hold(
            "S6",
            "! hopin name taken before the yes; budget and songmaker done, nothing for "
            "hopin; partial naming hopin, no next; the old key keeps the name",
        )

    def restore_app_key(self, app: str, key: str) -> None:
        path = self.home / APP_KEYS_FOLDER / app
        path.unlink()
        write_new(path, (key + "\n").encode(), 0o644)

    def cell_s7(self) -> None:
        self.change_budget(1.5)
        for app in APPS:
            self.change_by_hand(app, max_budget=7.0)
        plan = self.read_plan("S7")
        expect(len(plan.changes) == 4, f"S7: planned {len(plan.changes)} changes")
        self.compose("stop", DATABASE, timeout=120)
        try:
            result = self.run_step(plan)
        finally:
            self.compose("start", DATABASE, timeout=120)
        expect(
            isinstance(result, KeysFailed)
            and result.failed == plan.changes[0]
            and result.not_made == plan.changes[1:]
            and not result.done,
            f"S7: {result}",
        )
        cause = result.cause
        retry = self.read_plan("S7")
        expect(retry.changes == plan.changes, f"S7: the next plan is {retry.changes}")
        expect(isinstance(self.run_step(retry), KeysDone), "S7: the second run failed")
        self.hold(
            "S7",
            f"stopped at the person budget ({cause}), three keys not made; the next "
            "plan names exactly those four changes and its run completes",
        )

    def cell_s9(self) -> None:
        self.admin("POST", "/key/delete", {"keys": [hashed(self.file_keys["hopin"])]})
        plan = self.read_plan("S9")
        planned = [(change.subject, change.new) for change in plan.changes]
        expect(planned == [("hopin", True)], f"S9: planned {planned}")
        expect(isinstance(self.run_step(plan), KeysDone), "S9: the run failed")
        by_alias = self.key_rows(key_aliases=["hopin"])
        row = self.key_of("hopin")
        expect(
            len(by_alias) == 1 and row["max_budget"] == api_limits.APP_BUDGET_DOLLARS,
            "S9: hopin's key",
        )
        self.hold(
            "S9",
            "the deleted key planned as new; one live key for hopin by hash and by "
            "alias, with the defaults",
        )

    def cell_s8(self) -> None:
        canary = f"s8-canary-{secrets.token_hex(16)}"
        # A 404 path: no redaction filter of LiteLLM touches it, so its log line shows
        # that the search below sees what LA logs at INFO.
        answer = self.call(self.master_key, "GET", f"/{canary}", front=False)
        expect(answer["status"] == 404, f"S8: the canary path answered {answer['status']}")
        current = self.log_of(LITELLM)
        log = "\n".join((*self.earlier_logs, current))
        secret_values = [self.master_key, *self.written]
        hidden = [*secret_values, *map(hashed, secret_values)]
        resolved = self.run(
            [*self.compose_command(guard=True), "--profile", "apply", "--profile", "keycloak",
             "config", litellm_keys.KEYS_SERVICE]  # keycloak-config-cli needs its keycloak
        ).stdout  # fmt: skip
        places = (("the runner", self.seen.text()), ("LA", log), ("compose config", resolved))
        found = {where: sum(value in text for value in hidden) for where, text in places}
        control = canary in current
        write_line(f"S8 measured: canary in LA {control}; keys or hashes found {found}", flush=True)
        expect(control, "S8: the canary is not in LA: the search is blind")
        expect(not any(found.values()), f"S8: keys or hashes in {found}")
        expect(len(self.seen.argv) > 10, f"S8: the runner saw {len(self.seen.argv)} one-offs")
        self.hold(
            "S8",
            f"the canary of a 404 path found in LA; no app key, hash or master key in "
            f"{len(self.seen.argv)} argv and standard inputs, their output, LA or "
            "`compose config litellm-keys`",
        )

    # --- the admin group's rows (#965) --------------------------------------------------------

    def cell_a2(self) -> None:
        o, o2, o3, x, y = (self.people[name] for name in PEOPLE)
        self.admin("POST", "/budget/new", {"budget_id": OTHER_BUDGET})
        self.new_customer(o2)
        self.new_customer(o3, budget_id=OTHER_BUDGET)
        self.new_customer(
            x, budget_id=ADMIN_BUDGET_ID, alias="probe-x", default_model=DEFAULT_MODEL
        )
        self.new_customer(y)
        for person in (o2, x):
            self.set_spend(person, 1)
        y_before, budgets = self.customer_text(y), self.budget_ids()
        self.members = [o.subject, o2.subject, o3.subject]
        plan = self.read_plan("A2")
        links = sorted((o, o2, o3), key=lambda person: person.fingerprint)
        wanted = [("X", False, False), *((person.name, True, person is o) for person in links)]
        expect(self.row_changes(plan) == wanted, f"A2: planned {self.row_changes(plan)}")
        result = self.run_step(plan)
        expect(isinstance(result, KeysDone) and len(result.done) == 4, f"A2: {result}")
        linked = self.query(f'SELECT user_id FROM "{CUSTOMER_TABLE}" WHERE budget_id IS NOT NULL;')  # noqa: S608 - the table is this probe's literal
        names = sorted(map(self.name_of, linked))
        expect(names == ["O", "O2", "O3"], f"A2: the rows with a budget link are {names}")
        spends = [self.customer(person, "spend::text") for person in (o2, x)]
        expect(spends == [["1"], ["1"]], f"A2: O2's and X's spends {spends}")
        kept = self.customer(x, "coalesce(budget_id, '-') || '|' || alias || '|' || default_model")
        expect(kept == [f"-|probe-x|{DEFAULT_MODEL}"], f"A2: X's row holds {kept}")
        expect(self.budget_ids() == budgets, f"A2: the budgets are {self.budget_ids()}")
        expect(self.customer_text(y) == y_before, "A2: Y's row changed")
        (budget,) = self.admin("POST", "/budget/info", {"budgets": [ADMIN_BUDGET_ID]})
        settings = (budget["max_budget"], budget["budget_duration"])
        expect(
            settings == (None, litellm_keys.BUDGET_DURATION), f"A2: {ADMIN_BUDGET_ID} {settings}"
        )
        self.hold(
            "A2",
            f"O made, O2 and O3 linked to {ADMIN_BUDGET_ID}, O2's spend 1; X unlinked with spend "
            "1, its alias and default model, no new budget; Y untouched; the linked rows are O, "
            f"O2 and O3; {ADMIN_BUDGET_ID} has no max_budget and the period {settings[1]}",
        )

    def cell_a5(self) -> None:
        before = self.digest()
        plan = self.read_plan("A5")
        expect(plan == KeysPlan(), f"A5: planned {plan}")
        expect(self.run_step(plan) is None, "A5: the step acted")
        expect(self.digest() == before, "A5: D changed")
        self.hold("A5", "the same members again: nothing to change; D unchanged")

    def cell_a3(self) -> None:
        """O's key is presentator's and X's songmaker's, each with its budget left."""
        o, x = self.people["O"], self.people["X"]
        o_key, x_key = self.file_keys["presentator"], self.file_keys["songmaker"]
        o_spend = self.push_person("A3", o_key, o.fingerprint)
        before = len(self.provider_requests())
        answer = self.complete(o_key, user=o.fingerprint)
        self.served("A3", answer, self.provider_requests()[before:])
        x_spend = self.push_person("A3", x_key, x.fingerprint)
        before = len(self.provider_requests())
        refusal = self.complete(x_key, user=x.fingerprint)
        self.refused("A3", refusal, before)
        self.hold(
            "A3",
            f"O at {o_spend:.2f} dollars served; X, served at spend 1, at {x_spend:.2f} dollars "
            f"refused: {refusal['status']} {error_of(refusal)}, F 0",
        )

    def cell_a7(self) -> None:
        o = self.people["O"]
        before_reset = self.customer_spend(o.fingerprint)
        self.move_due("LiteLLM_BudgetTable", "budget_id", ADMIN_BUDGET_ID)
        took = self.wait_for("A7", "the reset", lambda: self.customer_spend(o.fingerprint) == 0)
        before = len(self.provider_requests())
        answer = self.complete(self.file_keys["presentator"], user=o.fingerprint)
        self.served("A7", answer, self.provider_requests()[before:])
        self.wait_for("A7", "O's spend", lambda: self.customer_spend(o.fingerprint) > 0)
        since = self.customer_spend(o.fingerprint)
        self.members = [self.people["O2"].subject, self.people["O3"].subject]
        plan = self.read_plan("A7")
        expect(self.row_changes(plan) == [("O", False, False)], f"A7: {self.row_changes(plan)}")
        expect(isinstance(self.run_step(plan), KeysDone), "A7: the unlink failed")
        (row,) = self.customer(o, "coalesce(budget_id, '-'), spend")
        link, spend = row.split("|")
        expect((link, float(spend)) == ("-", since), f"A7: O's row after the unlink {row}")
        self.hold(
            "A7",
            f"{ADMIN_BUDGET_ID} moved due: O's spend {before_reset:.2f} reset to 0 after "
            f"{took:.0f} s; O left the group, its row unlinked with the {since} dollars spent "
            "since the reset",
        )

    def cell_a4(self) -> None:
        """The members not read beside a key and budget change, then with no change."""
        not_read = MembersNotRead("Keycloak is not running")
        self.keycloak_running = False
        try:
            self.change_budget(1.5)
            self.change_by_hand("songmaker", max_budget=7.0)
            customers = self.digest()[CUSTOMERS]
            plan = self.read_plan("A4")
            subjects = [change.subject for change in plan.changes if isinstance(change, Change)]
            expect(len(subjects) == len(plan.changes), f"A4: planned {plan}")
            expect(
                subjects == [self.budget_id, "songmaker"] and plan.admin == not_read, f"A4: {plan}"
            )
            first = self.run_step(plan)
            expect(isinstance(first, KeysDone) and len(first.done) == 2, f"A4: {first}")
            partials = [keys_partial(first)]
            again = self.read_plan("A4")
            expect(again == KeysPlan(admin=not_read), f"A4: planned again {again}")
            partials.append(keys_partial(self.run_step(again)))
            expect(partials == [NOT_READ_PARTIAL] * 2, f"A4: {partials}")
            expect(self.digest()[CUSTOMERS] == customers, "A4: D of the customer rows changed")
        finally:
            self.keycloak_running = True
        self.hold(
            "A4",
            f"Keycloak not running: the person budget and songmaker done, then nothing to change; "
            f"D of the customer rows unchanged; both {NOT_READ_PARTIAL[0]!r}, next "
            f"{NOT_READ_PARTIAL[1]}",
        )

    def cell_a8(self) -> None:
        x = self.people["X"]
        self.admin(
            "POST", "/customer/update", {"user_id": x.fingerprint, "budget_id": ADMIN_BUDGET_ID}
        )
        members, self.members = self.members, None
        try:
            plan = self.read_plan("A8")
            result = self.run_step(plan)
        finally:
            self.members = members
        cause = f"realm-observer exited 1: realm-observer: hallucinai has no group {ADMIN_GROUP}"
        expect(plan == KeysPlan(admin=MembersNotRead(cause)), f"A8: planned {plan}")
        expect(keys_partial(result) == NOT_READ_PARTIAL, f"A8: {result}")
        linked = self.customer(x, "coalesce(budget_id, '-')")
        expect(linked == [ADMIN_BUDGET_ID], f"A8: X's row is linked to {linked}")
        self.hold("A8", f"the group absent: members not read ({cause}); X stays linked; partial")

    def cell_a6(self) -> None:
        """The failing runs, then one search of P for every subject, fingerprint, key and hash."""
        stopped = self.failing_members_read()
        plan = self.read_plan("A6")
        expect(self.row_changes(plan) == [("X", False, False)], f"A6: {self.row_changes(plan)}")
        self.compose("stop", DATABASE, timeout=120)
        try:
            failed, unread = self.run_step(plan), self.plan()
        finally:
            self.compose("start", DATABASE, timeout=120)
        expect(isinstance(failed, KeysFailed) and failed.failed == plan.changes[0], f"A6: {failed}")
        expect(isinstance(unread, NotRead), f"A6: read with the database stopped: {unread}")
        expect(isinstance(self.run_step(self.read_plan("A6")), KeysDone), "A6: the retry failed")
        people = self.people.values()
        secret_values = [self.master_key, *self.written]
        hidden = [*(value for p in people for value in (p.subject, p.fingerprint)), *secret_values]
        hidden += map(hashed, secret_values)
        found = sum(value in line for line in self.printed for value in hidden)
        sent = "\n".join(self.seen.stdin)
        control = sorted(person.name for person in people if person.fingerprint in sent)
        measured = f"{found} values in {len(self.printed)} lines of P; control {control}"
        write_line(f"A6 measured: {measured}", flush=True)
        expect(control == ["O", "O2", "O3", "X"], f"A6: the control finds {control}")
        expect(found == 0, f"A6: {found} values printed")
        expect(self.people["Y"].fingerprint not in self.seen.text(), "A6: Y's row left the one-off")
        self.hold(
            "A6",
            f"{len(self.printed)} lines of P, among them a failing members read ({stopped}), a "
            f"failing unlink ({failed.cause}) and a failing --read ({unread.cause}): no "
            "subject, fingerprint, key or hash; the control finds O, O2, O3 and X in "
            "litellm-keys' standard input, Y nowhere",
        )

    def failing_members_read(self) -> str:
        """The observer stopped after it printed the members: the cause quotes none of them."""
        self.observer_stopped = True
        try:
            plan = self.read_plan("A6")
        finally:
            self.observer_stopped = False
        cause = f"realm-observer exited 1: {OBSERVER_STOPPED}"
        expect(plan.admin == MembersNotRead(cause), f"A6: the members read gave {plan.admin}")
        return cause


def first_of_next_month() -> datetime:
    now = datetime.now(UTC)
    return datetime(now.year + now.month // 12, now.month % 12 + 1, 1, tzinfo=UTC)


def parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], KeysProbe)


if __name__ == "__main__":
    sys.exit(main())
