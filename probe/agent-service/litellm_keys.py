"""Probe of `hal apply`'s key step (#964 cells S1-S9): the step's plan and run, through the
one-off `litellm-keys`, against the LiteLLM of litellm.py in its throwaway project. Nothing live
and nothing paid: the probe refuses to start unless `internet` is internal and holds only the
fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_keys.py --scratch DIR

Measured: a run takes about four minutes and its teardown a few seconds (K 30 s, CAP 1800 s).

It writes three app key files beside litellm.py's scratch secrets and drives the checkout's
`hal.stack.litellm_keys` with a Compose runner on the probe's project, which records every argv,
standard input, standard output and standard error the step's one-off sees. LiteLLM runs at log
level INFO, as litellm.py sets it for LA. F is the fake provider's request log, LA LiteLLM's log,
D a digest of `LiteLLM_VerificationToken` and `LiteLLM_BudgetTable` read by SQL. Keys are scratch
values the probe generates and never prints; the probe's own SQL names keys by alias, never by
hash. Exit 0: every cell held.
"""

from __future__ import annotations

import secrets
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import (
    DATABASE,
    FAKE_PROVIDER,
    FRONT,
    GATEWAY,
    LITELLM,
    REPO,
    LitellmProbe,
    expect,
    hashed,
    run_scratch_probe,
    shipped_config,
)
from scratch_secrets import write_new

from hal.output import write_line
from hal.stack import api_limits, compose, litellm_keys
from hal.stack.litellm_keys import KeysDone, KeysFailed, KeysPlan, Target
from hal.stack.result_rows import keys_partial

APPS = ("hopin", "presentator", "songmaker")
APP_KEYS_FOLDER = Path(".secrets/litellm/apps")
READ_SECONDS = 180
FOURTH_MODEL = "text/fourth"
TABLES = ("LiteLLM_VerificationToken", "LiteLLM_BudgetTable")


@dataclass
class Seen:
    """What the step's one-offs saw and said."""

    argv: list[list[str]] = field(default_factory=list)
    stdin: list[str] = field(default_factory=list)
    output: list[str] = field(default_factory=list)

    def text(self) -> str:
        return "\n".join((*(" ".join(argv) for argv in self.argv), *self.stdin, *self.output))


class KeysProbe(LitellmProbe):
    """litellm.py's stack without the service, and the key step against it."""

    # The cells' methods in the order they run, each on what the ones before left.
    CELLS = ("cell_s1", "cell_s2", "cell_s3", "cell_s4", "cell_s5", "cell_s6", "cell_s7", "cell_s9",
             "cell_s8")  # fmt: skip

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.home = Path(self.environment["HOME"])
        self.written: list[str] = []  # every app key file value, S6's replaced one included
        self.file_keys = {app: self.write_app_key(app) for app in APPS}
        self.seen = Seen()
        self.earlier_logs: list[str] = []
        self.engine = compose.Compose(run=self.step_runner, repository=REPO)
        self.budget_id = shipped_config()["litellm_settings"][litellm_keys.BUDGET_ID_SETTING]

    def services_to_start(self) -> tuple[str, ...]:
        return (GATEWAY, FAKE_PROVIDER, FRONT, DATABASE, LITELLM)

    # --- scratch and plumbing -----------------------------------------------------------------

    def write_app_key(self, app: str, replace: bool = False) -> str:
        key = f"sk-{secrets.token_urlsafe(32)}"
        folder = self.home / APP_KEYS_FOLDER
        folder.mkdir(mode=0o700, exist_ok=True)
        path = folder / app
        if replace:
            path.unlink()
        write_new(path, (key + "\n").encode(), 0o644)
        self.app_keys.append(key)
        self.written.append(key)
        return key

    def step_runner(
        self, command: list[str], timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        """The step's compose call on the probe's project: its verb and arguments after the
        probe's own files, overlays and project name."""
        verb_and_arguments = command[6:]  # docker compose --project-directory D --file F
        argv = [*self.compose_command(guard=True), *verb_and_arguments]
        result = subprocess.run(  # noqa: S603 - argv is the step's own compose call behind the probe's prefix
            argv,
            input=stdin,
            capture_output=True,
            text=True,
            env=self.environment,
            cwd=REPO,
            check=False,
            timeout=timeout,
        )
        if "run" in verb_and_arguments:
            self.seen.argv.append(argv)
            self.seen.stdin.append(stdin or "")
            self.seen.output += [result.stdout, result.stderr]
        return result

    def api_settings(self) -> api_limits.ApiSettings:
        """The numbers the step plans with: the code defaults here."""
        return api_limits.NONE_SET

    def plan(self) -> KeysPlan:
        return litellm_keys.plan_keys(self.engine, self.engine.states(), REPO, self.api_settings())

    def read_plan(self, cell: str) -> KeysPlan:
        """The plan once the keys can be read: LiteLLM answers 502 while it migrates."""
        deadline = time.monotonic() + READ_SECONDS
        while (plan := self.plan()).not_read is not None:
            expect(time.monotonic() < deadline, f"{cell}: keys not read ({plan.not_read})")
            time.sleep(3)
        return plan

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

    def digest(self) -> list[str]:
        return [
            self.query(
                f"SELECT coalesce(md5(string_agg(r::text, E'\\n' ORDER BY r::text)), '-')"  # noqa: S608 - the table names are this probe's literals
                f' FROM "{table}" AS r;'
            )[0]
            for table in TABLES
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

    def run_step(self, plan: KeysPlan):
        return litellm_keys.run_keys(plan, self.engine)

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
            == [(Target.BUDGET, self.budget_id, True), *((Target.KEY, app, True) for app in APPS)],
            f"S1: planned {planned}",
        )
        result = self.run_step(plan)
        expect(isinstance(result, KeysDone) and len(result.done) == 4, f"S1: {result}")
        budget = self.budget()
        expect(
            (budget["max_budget"], budget["budget_duration"])
            == (api_limits.PERSON_BUDGET_DOLLARS, litellm_keys.BUDGET_DURATION),
            "S1: budget",
        )
        models, reset = sorted(self.models()), first_of_next_month()
        self.expect_default_keys(models, reset)
        fingerprint = self.fingerprint()
        for app in APPS:
            before = len(self.provider_requests())
            answer = self.complete(self.file_keys[app], user=fingerprint)
            self.served("S1", answer, self.provider_requests()[before:])
        self.wait_for(
            "S1", "the person's row", lambda: self.end_user_budget(fingerprint) is not None
        )
        expect(self.end_user_budget(fingerprint) == [""], "S1: the person's row links a budget")
        self.wait_for(
            "S1", "each key's spend", lambda: all(self.key_of(app)["spend"] > 0 for app in APPS)
        )
        self.hold(
            "S1",
            f"budget {self.budget_id} and three keys made by hash with the defaults, "
            f"models as /v1/models, reset {reset:%Y-%m-%d %H:%M} UTC; each key served "
            "through the front; the person's row keeps budget_id NULL",
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
                [litellm_keys.ROUTE],
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
        ran = self.seen.argv[calls:]
        expect(len(ran) == 1 and "--read" in ran[0], f"S2: {len(ran)} one-offs ran")
        expect(self.digest() == before, "S2: D changed")
        self.hold("S2", "nothing to change; one --read and no --write ran; D unchanged")

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


def first_of_next_month() -> datetime:
    now = datetime.now(UTC)
    return datetime(now.year + now.month // 12, now.month % 12 + 1, 1, tzinfo=UTC)


def parsed_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], KeysProbe)


if __name__ == "__main__":
    sys.exit(main())
