"""Probe of the operator's API numbers (#889 cells L1-L8): `[api]` and `[api.<app>]` of a scratch
HOME's `~/.config/hal/config.toml`, read by the checkout's `hal.config`, planned and set by the
key step of litellm_keys.py, against the LiteLLM of litellm.py in its throwaway project. Nothing
live and nothing paid: the probe refuses to start unless `internet` is internal and holds only the
fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_limits.py --scratch DIR

Each cell writes the settings file, plans and runs the step from the rows the step made at the
code defaults, each key with a spend and every reset R as LiteLLM set it. F is the fake provider's
request log, D litellm_keys.py's digest, W the recorded `--write` standard input, I `litellm`'s
container id and its `com.docker.compose.config-hash` label. A request is the wire body posted
through the front with an app's own key. Keys are scratch values the probe generates and never
prints. Exit 0: every cell held.
"""

from __future__ import annotations

import json
import sys
import time
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import LITELLM, error_of, expect, run_scratch_probe
from litellm_keys import APPS, KeysProbe

from hal import config as hal_config
from hal.output import write_line
from hal.stack import api_limits
from hal.stack.litellm_keys import KeysDone, KeysPlan, UnknownApps

KEY_TABLE = "LiteLLM_VerificationToken"
BUDGET_TABLE = "LiteLLM_BudgetTable"
BOOKKEEPING = frozenset({"settings_updated_at", "updated_at", "updated_by"})  # stamped on a write
SET_UP_SPEND = {"hopin": 0.25, "presentator": 0.5, "songmaker": 0.75}
SENT_ONLY_WITH_A_NEW_KEY = ("budget_duration", "models", "allowed_routes")
L1_SETTINGS = (
    "[api]\nbudget_dollars = 4\nmax_parallel_requests = 3\nperson_budget_dollars = 1.5\n"
    "[api.hopin]\nbudget_dollars = 6\n"
)
REPOST_SECONDS = 10
PERSON_BUDGET_WINDOW = 150


class Verdict(Enum):
    HELD = "held"
    WAIT = "wait"
    FAILED = "failed"


class Refusal(NamedTuple):
    """The status and LiteLLM's error type of a refused request."""

    status: int
    error_type: str


BUDGET_EXCEEDED = Refusal(422, "budget_exceeded")
TOO_MANY = Refusal(429, "throttling_error")

type Rows = dict[tuple[str, str], dict]
type Fields = dict[str, dict[str, tuple[object, object]]]


class LimitsProbe(KeysProbe):
    """litellm_keys.py's stack, the key step planning with the scratch HOME's settings file."""

    # L8 runs while every row is at the code defaults, so its control plans one change.
    CELLS = ("set_up", "cell_l1", "cell_l2", "cell_l3", "cell_l8", "cell_l4", "cell_l5", "cell_l6",
             "cell_l7")  # fmt: skip

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.l1_saw_its_change = False  # whether D told L1's rows apart, L2's control

    def api_settings(self) -> api_limits.ApiSettings:
        return hal_config.load(self.home).api

    def write_settings(self, text: str | None) -> None:
        """The settings file as `text`; None deletes it."""
        path = hal_config.config_path(self.home)
        if text is None:
            path.unlink(missing_ok=True)
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    # --- what the cells observe ---------------------------------------------------------------

    def rows(self) -> Rows:
        """Every key row by alias and every budget row by id, as LiteLLM's database holds them."""
        found: Rows = {}
        for table, name in ((KEY_TABLE, "key_alias"), (BUDGET_TABLE, "budget_id")):
            statement = f'SELECT row_to_json(r) FROM "{table}" AS r;'  # noqa: S608 - the table names are this probe's literals
            for line in self.query(statement):
                row = json.loads(line)
                found[(table, str(row[name]))] = row
        return found

    def instance(self) -> str:
        container = self.container(LITELLM)
        label = '{{index .Config.Labels "com.docker.compose.config-hash"}}'
        return self.run(["docker", "inspect", "--format", f"{{{{.Id}}}} {label}", container]).stdout

    def writes(self, since: int) -> list[list[dict]]:
        """W: each `--write` standard input since the `since`-th one-off."""
        ran = zip(self.seen.argv[since:], self.seen.stdin[since:], strict=True)
        return [json.loads(stdin) for argv, stdin in ran if "--write" in argv]

    def spend_and_resets(self) -> dict[str, tuple[object, object]]:
        rows = self.rows()
        found = {app: (rows[(KEY_TABLE, app)]["spend"], rows[(KEY_TABLE, app)]["budget_reset_at"])
                 for app in APPS}  # fmt: skip
        found[self.budget_id] = (None, rows[(BUDGET_TABLE, self.budget_id)]["budget_reset_at"])
        return found

    def post(self, app: str, user: str) -> tuple[dict, list[dict]]:
        """One request of `app` for `user`, and what F gained by it."""
        before = len(self.provider_requests())
        answer = self.complete(self.file_keys[app], user=user)
        return answer, self.provider_requests()[before:]

    def apply_settings(self, cell: str, text: str | None) -> Fields:
        """The file as `text`, then one plan and its run; the plan's fields, old and new."""
        self.write_settings(text)
        plan = self.read_plan(cell)
        expect(isinstance(self.run_step(plan), KeysDone), f"{cell}: the run failed")
        return fields_of(plan)

    def refused_as(self, cell: str, answer: dict, sent: list[dict], refusal: Refusal) -> str:
        found = Refusal(answer["status"], error_of(answer).partition("/")[0])
        expect(found == refusal, f"{cell}: {answer['status']} {error_of(answer)}")
        expect(not sent, f"{cell}: F gained {len(sent)}")
        return f"{answer['status']} {error_of(answer)} in {answer['seconds']:.1f} s"

    # --- the cells ----------------------------------------------------------------------------

    def set_up(self) -> None:
        """2.4a's S1 with no file, then a spend on each key."""
        self.write_settings(None)
        plan = self.read_plan("set-up")
        # the person budget, each app's key and the admin budget
        expect(len(plan.changes) == len(APPS) + 2, f"set-up: planned {plan.changes}")
        expect(isinstance(self.run_step(plan), KeysDone), "set-up: the run failed")
        for app, spend in SET_UP_SPEND.items():
            self.set_key(app, f"spend = {spend}")
        write_line("set-up: the rows at the code defaults, a spend on each key", flush=True)

    def cell_l1(self) -> None:
        before, digest, instance, calls = self.rows(), self.digest(), self.instance(), self.calls()
        planned = self.apply_settings("L1", L1_SETTINGS)
        default = (api_limits.APP_BUDGET_DOLLARS, api_limits.MAX_PARALLEL_REQUESTS)
        wanted = {
            self.budget_id: {"max_budget": (api_limits.PERSON_BUDGET_DOLLARS, 1.5)},
            "hopin": {"max_budget": (default[0], 6.0), "max_parallel_requests": (default[1], 3)},
            **{
                app: {"max_budget": (default[0], 4.0), "max_parallel_requests": (default[1], 3)}
                for app in ("presentator", "songmaker")
            },
        }
        expect(planned == wanted, f"L1: planned {planned}")
        sent = {
            name for write in self.writes(calls) for change in write for name in change["fields"]
        }
        expect(not sent & set(SENT_ONLY_WITH_A_NEW_KEY), f"L1: W sent {sorted(sent)}")
        changed, stamped = changed_fields(before, self.rows())
        expected = {(BUDGET_TABLE, self.budget_id, "max_budget")} | {
            (KEY_TABLE, app, name)
            for app in APPS
            for name in ("max_budget", "max_parallel_requests")
        }
        expect(changed == expected, f"L1: D changed in {sorted(changed)}")
        expect(self.instance() == instance, "L1: litellm was recreated")
        self.l1_saw_its_change = self.digest() != digest
        self.hold(
            "L1",
            f"hopin 10 → 6, presentator and songmaker 10 → 4, each 5 → 3, the person 2 → 1.5; W "
            f"sent {sorted(sent)}; D changed in exactly those 7 fields beside the stamps "
            f"{sorted(stamped)}; every spend and R unchanged; I unchanged",
        )

    def cell_l2(self) -> None:
        digest, calls = self.digest(), self.calls()
        self.write_settings(L1_SETTINGS)
        plan = self.read_plan("L2")
        expect(plan == KeysPlan(), f"L2: planned {plan}")
        expect(self.run_step(plan) is None, "L2: the step acted")
        expect(self.writes(calls) == [], "L2: a --write ran")
        expect(self.digest() == digest, "L2: D changed")
        expect(self.l1_saw_its_change, "L2: D did not see L1's change: D is blind")
        self.hold("L2", "nothing to change; no --write; D unchanged, while it saw L1's change")

    def cell_l3(self) -> None:
        self.change_by_hand("presentator", max_budget=7.0)
        before, instance = self.spend_and_resets(), self.instance()
        planned = self.apply_settings("L3", None)
        budget, parallel = api_limits.APP_BUDGET_DOLLARS, api_limits.MAX_PARALLEL_REQUESTS
        wanted = {
            self.budget_id: {"max_budget": (1.5, api_limits.PERSON_BUDGET_DOLLARS)},
            "hopin": {"max_budget": (6.0, budget), "max_parallel_requests": (3, parallel)},
            "presentator": {"max_budget": (7.0, budget), "max_parallel_requests": (3, parallel)},
            "songmaker": {"max_budget": (4.0, budget), "max_parallel_requests": (3, parallel)},
        }
        expect(planned == wanted, f"L3: planned {planned}")
        rows = self.rows()
        keys = {app: rows[(KEY_TABLE, app)] for app in APPS}
        held = {app: (row["max_budget"], row["max_parallel_requests"]) for app, row in keys.items()}
        expect(set(held.values()) == {(budget, parallel)}, f"L3: the keys hold {held}")
        person = rows[(BUDGET_TABLE, self.budget_id)]["max_budget"]
        expect(person == api_limits.PERSON_BUDGET_DOLLARS, f"L3: the person budget {person}")
        expect(self.spend_and_resets() == before, "L3: a spend or a reset moved")
        expect(self.instance() == instance, "L3: litellm was recreated")
        self.hold(
            "L3",
            "the file deleted: every key back to 10 and 5, the person to 2, presentator's hand-set "
            "7 planned back to 10; every spend and R unchanged; I unchanged",
        )

    def cell_l8(self) -> None:
        digest, calls = self.digest(), self.calls()
        self.write_settings("[api.hopn]\nbudget_dollars = 1\n")
        try:
            self.read_plan("L8")
        except UnknownApps as error:
            line = str(error)
        else:
            expect(False, "L8: an unknown app table was planned")
        expect("[api.hopn]" in line and all(app in line for app in APPS), f"L8: {line}")
        expect(self.writes(calls) == [], "L8: a --write ran")
        expect(self.digest() == digest, "L8: D changed")
        self.write_settings("[api.hopin]\nbudget_dollars = 1\n")
        control = fields_of(self.read_plan("L8"))
        wanted = {"hopin": {"max_budget": (api_limits.APP_BUDGET_DOLLARS, 1.0)}}
        expect(control == wanted, f"L8: control {control}")
        self.hold(
            "L8", f"UnknownApps: {line}; no --write; D unchanged; [api.hopin] plans one change"
        )

    def cell_l4(self) -> None:
        self.set_key("hopin", "spend = 3")
        before = self.spend_and_resets()["hopin"]
        self.apply_settings("L4", "[api.hopin]\nbudget_dollars = 2\n")
        user = self.fingerprint()
        refused = self.refused_as("L4", *self.post("hopin", user), BUDGET_EXCEEDED)
        expect(self.spend_and_resets()["hopin"] == before, "L4: hopin's spend or reset moved")
        answer, sent = self.post("presentator", user)
        self.served("L4", answer, sent)
        self.hold("L4", f"hopin at spend 3 over 2: {refused}, F 0; presentator served, F 1")

    def cell_l5(self) -> None:
        self.apply_settings("L5", "[api.hopin]\nmax_parallel_requests = 0\n")
        user = self.fingerprint()
        refused = self.refused_as("L5", *self.post("hopin", user), TOO_MANY)
        self.apply_settings("L5", "[api.hopin]\nmax_parallel_requests = 1\n")
        self.served("L5", *self.post("hopin", user))
        self.hold("L5", f"hopin at 0 parallel: {refused}, F 0; at 1 the same post is served")

    def cell_l6(self) -> None:
        self.set_key("songmaker", "spend = 0")
        self.apply_settings("L6", "[api.songmaker]\nbudget_dollars = 0\n")
        user = self.fingerprint()
        refused = self.refused_as("L6", *self.post("songmaker", user), BUDGET_EXCEEDED)
        self.apply_settings("L6", None)
        self.served("L6", *self.post("songmaker", user))
        self.hold("L6", f"songmaker at 0 dollars, spend 0: {refused}, F 0; removed, served")

    def cell_l7(self) -> None:
        person = self.fingerprint()
        self.served("L7", *self.post("presentator", person))
        self.wait_for("L7", "the person's spend", lambda: self.person_spend(person) > 0)
        spend = self.person_spend(person)
        self.apply_settings("L7", f"[api]\nperson_budget_dollars = {spend / 2!r}\n")
        started = time.monotonic()
        refusal = self.until_refused(person, lambda: time.monotonic() - started)
        delay = time.monotonic() - started
        fresh = self.fingerprint()
        self.served("L7", *self.post("presentator", fresh))
        write_line(f"L7 measured: the person budget bound after {delay:.0f} s", flush=True)
        self.hold(
            "L7",
            f"P at spend {spend:.6g} over {spend / 2:.6g}: {refusal} after {delay:.0f} s, "
            "reposting every 10 s; a fresh Q at spend 0 served in the same window",
        )

    def until_refused(self, person: str, elapsed: Callable[[], float]) -> str:
        while True:
            answer, sent = self.post("presentator", person)
            verdict = person_budget_verdict(answer["status"] != 200, elapsed())
            expect(verdict is not Verdict.FAILED, "L7: P not refused within 150 s")
            if verdict is Verdict.HELD:
                return self.refused_as("L7", answer, sent, BUDGET_EXCEEDED)
            time.sleep(REPOST_SECONDS)

    def person_spend(self, person: str) -> float:
        table = "LiteLLM_EndUserTable"
        statement = f"SELECT spend FROM \"{table}\" WHERE user_id = '{person}';"  # noqa: S608 - the fingerprint is a token this probe generated
        found = self.query(statement)
        return float(found[0]) if found else 0.0

    def calls(self) -> int:
        return len(self.seen.argv)


def person_budget_verdict(refused: bool, elapsed: float) -> Verdict:
    """An answer after the window fails L7, a refusal or not; within it, a refusal holds it."""
    if elapsed > PERSON_BUDGET_WINDOW:
        return Verdict.FAILED
    return Verdict.HELD if refused else Verdict.WAIT


def fields_of(plan: KeysPlan) -> Fields:
    return {
        change.subject: {field.name: (field.old, field.new) for field in change.fields}
        for change in plan.changes
    }


def changed_fields(before: Rows, after: Rows) -> tuple[set[tuple[str, str, str]], set[str]]:
    """Each (table, row, field) whose value differs, and apart from them the bookkeeping fields
    LiteLLM stamps on a write."""
    changed = {
        (table, row, name)
        for (table, row) in before.keys() | after.keys()
        for name in before.get((table, row), {}).keys() | after.get((table, row), {}).keys()
        if before.get((table, row), {}).get(name) != after.get((table, row), {}).get(name)
    }
    stamped = {name for _, _, name in changed if name in BOOKKEEPING}
    return {entry for entry in changed if entry[2] not in BOOKKEEPING}, stamped


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LimitsProbe)


if __name__ == "__main__":
    sys.exit(main())
