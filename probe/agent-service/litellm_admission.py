"""Probe of what LiteLLM admits on the API route (cells K5-K9, K11, M1, P1-P6, A1-A4, and #768
S1a's G4): the stack of litellm.py against a fake Anthropic that reports the usage the probe
steers or holds requests until the probe releases them. App keys, budgets and fingerprints are
the scenario of litellm.py: each key with a money budget per month and a parallel bound, the
person budget under the id config.yaml names, and the operator's fingerprint O linked to a budget
with no `max_budget`.
Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and holds
only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_admission.py --scratch DIR

Evidence: F is the fake provider's request log, A the callers' status, Retry-After and LiteLLM's
error type, S the spend LiteLLM reports (`/key/info`, `/customer/info`) and D its database. The
probe waits on observed events only: new request lines in F, the callers' lines, a spend in S.
A budget is moved due in D and reset by LiteLLM's own job, which the scratch config runs every few
seconds. Exit 0: every cell held.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))

from litellm import (
    APP_BUDGET,
    FAKE_PROVIDER,
    LISTENING,
    LITELLM,
    OPERATOR_BUDGET,
    PARALLEL,
    PERSON_BUDGET,
    PROJECT,
    REPO,
    ROUTE,
    SERVICE,
    TOO_MANY,
    LitellmProbe,
    error_of,
    expect,
    hashed,
    person_budget,
    run_scratch_probe,
    shipped_config,
    shipped_models,
    wire_body,
)

WORKERS = "NUM_WORKERS"
REQUEST_SECONDS = 60
HOLDER_SECONDS = 150
CACHE_SECONDS = 180
UPSTREAM_FAILURE = 529
# Steered usages on text/opus: one past the person budget, one past the app budget.
PERSON_PUSH = {"input_tokens": 600_000, "output_tokens": 1}
APP_PUSH = {"input_tokens": 3_000_000, "output_tokens": 1}


def first_of_next_month(now: datetime) -> datetime:
    """00:00 UTC on the first day of the month after `now`."""
    year, month = (now.year + 1, 1) if now.month == 12 else (now.year, now.month + 1)
    return datetime(year, month, 1, tzinfo=UTC)


class AdmissionProbe(LitellmProbe):
    """litellm.py's stack with the scenario's keys, budgets and fingerprints."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.holders: list[subprocess.Popen] = []
        self.client_count = 0

    # --- plumbing -----------------------------------------------------------------------------

    def start_client(self, key: str, user: str) -> subprocess.Popen:
        self.client_count += 1
        request = ("POST", ROUTE, json.dumps(wire_body(user=user)))
        argv, program = self.call_command(
            f"{PROJECT}-client-{self.client_count}", key, request, front=True
        )
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(program)
        process.stdin.close()
        self.holders.append(process)
        return process

    def finish(self, process: subprocess.Popen) -> dict:
        """The line a client prints when its request is answered."""
        out, err = process.communicate(timeout=HOLDER_SECONDS)
        expect(process.returncode == 0, f"a client failed: {err[-300:]}")
        return json.loads(out.strip().splitlines()[-1])

    def wait_for_requests(self, cell: str, count: int) -> None:
        deadline = time.monotonic() + REQUEST_SECONDS
        while len(self.provider_requests()) < count:
            ended = sum(process.poll() is not None for process in self.holders)
            expect(time.monotonic() < deadline, f"{cell}: F has {len(self.provider_requests())} "
                   f"of {count} requests; {ended} clients ended")  # fmt: skip
            time.sleep(1)

    def released(self) -> list[str]:
        return [line for line in self.log_of(FAKE_PROVIDER).splitlines() if line.startswith("held")]

    def push(self, key: str, user: str, usage: dict) -> None:
        """One served request whose steered usage LiteLLM prices."""
        self.steer_fake(usage=usage)
        answer = self.complete(key, user=user)
        self.steer_fake()
        expect(answer["status"] == 200, f"the push was refused: {answer['status']}")

    def push_person(self, cell: str, key: str, user: str) -> float:
        self.push(key, user, PERSON_PUSH)
        self.wait_for(cell, "the person's spend past the budget",
                      lambda: self.customer_spend(user) > PERSON_BUDGET)  # fmt: skip
        return self.customer_spend(user)

    def expect_served(self, cell: str, key: str, user: str) -> None:
        before = len(self.provider_requests())
        self.served(cell, self.complete(key, user=user), self.provider_requests()[before:])

    def expect_refused(self, cell: str, key: str, user: str) -> str:
        before = len(self.provider_requests())
        answer = self.complete(key, user=user)
        self.refused(cell, answer, before)
        return f"{answer['status']} {error_of(answer)}"

    def move_due(self, table: str, column: str, value: str) -> None:
        """Moves a budget's reset into the past in LiteLLM's database."""
        moved = "budget_reset_at = now() - interval '1 minute'"
        self.sql(f"UPDATE \"{table}\" SET {moved} WHERE {column} = '{value}'")  # noqa: S608 - the probe names the table and the value

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until(SERVICE, LISTENING)
        self.wait_until_listening()
        self.admin("POST", "/budget/new", person_budget())
        self.admin("POST", "/budget/new", {"budget_id": OPERATOR_BUDGET})
        operator = self.fingerprint()
        self.admin("POST", "/customer/new", {"user_id": operator, "budget_id": OPERATOR_BUDGET})
        key, second = self.make_key(), self.make_key()
        try:
            self.cell_k9(key, second)
        finally:
            for process in self.holders:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
        self.cell_m1(key)
        self.cells_p1_p2(key)
        self.cell_k6()
        self.cell_k11(key)
        person = self.cells_p3_p4(key, second)
        self.cells_a1_a3(key, operator)
        self.cell_a4()
        over = self.cell_k5()
        self.hold(
            "A2",
            f"O through the key past its budget: {self.expect_refused('A2', over, operator)}, F 0",
        )
        self.cells_k7_p5(over, key, person)
        self.cell_k8(over)
        self.cell_p6(key, person)
        self.cell_g4(key)

    def cell_k9(self, key: str, second: str) -> None:
        """B0 to B6 of the bound, judged per key."""
        environment = json.loads(self.compose("config", "--format", "json").stdout)["services"][
            LITELLM
        ]["environment"]
        expect(WORKERS not in environment, f"K9: {WORKERS} is {environment.get(WORKERS)!r}")
        self.steer_fake(mode="hold")
        base = len(self.provider_requests())
        held = [self.start_client(key, self.fingerprint()) for _ in range(PARALLEL)]
        self.wait_for_requests("K9", base + PARALLEL)
        over = self.finish(self.start_client(key, self.fingerprint()))
        retry = over["retry_after"]
        expect(over["status"] == TOO_MANY, f"K9: the sixth got {over['status']} {error_of(over)}")
        expect(
            retry is not None and retry.isdigit() and int(retry) >= 1, f"K9: Retry-After {retry!r}"
        )
        expect(not self.released() and all(p.poll() is None for p in held), "K9: a held one ended")
        held += [self.start_client(second, self.fingerprint()) for _ in range(PARALLEL)]
        self.wait_for_requests("K9", base + 2 * PARALLEL)
        expect(all(p.poll() is None for p in held), "K9: the second key's requests were refused")
        self.steer_fake()
        answered = [self.finish(process)["status"] for process in held]
        expect(answered == [200] * 2 * PARALLEL, f"K9: the held ones ended {answered}")
        self.expect_served("K9", key, self.fingerprint())
        self.steer_fake(mode="status", status=UPSTREAM_FAILURE)
        failed = [
            self.complete(key, user=self.fingerprint())["status"] for _ in range(PARALLEL + 1)
        ]
        self.steer_fake()
        expect(TOO_MANY not in failed and 200 not in failed, f"K9: failed requests {failed}")
        self.hold("K9", f"one worker; {PARALLEL} held at F, the sixth 429 Retry-After {retry} "
                  f"after {over['seconds']:.2f} s; the second key's {PARALLEL} reached F "
                  f"meanwhile; all ended 200, the next served; {PARALLEL + 1} upstream failures "
                  f"kept no slot ({failed})")  # fmt: skip

    def cell_m1(self, key: str) -> None:
        user, seen = self.fingerprint(), {}
        for model, parameters in shipped_models().items():
            before = len(self.provider_requests())
            answer = self.complete(key, model, user)
            sent = self.provider_requests()[before:]
            self.served("M1", answer, sent, model)
            seen[model] = sent[0]["max_tokens"]
            expect(seen[model] == parameters["max_tokens"], f"M1: {model}: F saw {seen[model]}")
        self.hold("M1", f"no max_tokens sent; F saw config.yaml's value per name: {seen}")

    def cells_p1_p2(self, key: str) -> None:
        user, before = self.fingerprint(), len(self.provider_requests())
        self.complete(key, user=user)
        sent = [request["user_id"] for request in self.provider_requests()[before:]]
        expect(sent == [user], f"P1: F saw {len(sent)} requests, the sent user {user in sent}")
        self.hold("P1", "F saw exactly the sent `user` as metadata.user_id")
        before = len(self.provider_requests())
        answer = self.complete(key)
        self.refused("P2", answer, before)
        self.hold("P2", f"no `user`: {answer['status']} {error_of(answer)}, F 0")

    def cell_k6(self) -> None:
        key, spends = self.make_key(), [0.0]
        self.steer_fake(usage={"input_tokens": 1000, "output_tokens": 1000})
        for model in shipped_models():
            answer = self.complete(key, model, self.fingerprint())
            expect(answer["status"] == 200, f"K6: {model}: {answer['status']}")
            self.wait_for("K6", f"the spend after {model}",
                          lambda: self.key_info(key)["spend"] > spends[-1])  # fmt: skip
            spends.append(self.key_info(key)["spend"])
        self.steer_fake()
        self.hold("K6", f"the key's spend in /key/info rose after each name: {spends[1:]}")

    def cell_k11(self, key: str) -> None:
        results = []
        routes = (("GET", f"/key/info?key={hashed(key)}", None), ("POST", "/key/generate", {}),
                  ("GET", "/v1/models", None))  # fmt: skip
        for method, path, body in routes:
            refused = self.call(key, method, path, body, front=False)
            control = self.call(self.master_key, method, path, body, front=False)
            expect(
                refused["status"] in {401, 403}, f"K11: {path}: the app key got {refused['status']}"
            )
            expect(control["status"] == 200, f"K11: {path}: the master key got {control['status']}")
            results.append(f"{path.split('?')[0]} {refused['status']} {error_of(refused)}")
        self.hold("K11", f"the app key at litellm:4000 refused: {results}; the master key 200 each")

    def cells_p3_p4(self, key: str, second: str) -> str:
        person, other = self.fingerprint(), self.fingerprint()
        spend = self.push_person("P3", key, person)
        refusal = self.expect_refused("P3", key, person)
        self.expect_served("P3", key, other)
        self.hold("P3", f"X at {spend:.2f} dollars refused: {refusal}, F 0; Y on the key served")
        self.hold(
            "P4", f"X through the second key: {self.expect_refused('P4', second, person)}, F 0"
        )
        return person

    def cells_a1_a3(self, key: str, operator: str) -> None:
        spend = self.push_person("A1", key, operator)
        self.expect_served("A1", key, operator)
        self.hold("A1", f"O at {spend:.2f} dollars still served, each request at F")
        other = self.fingerprint()
        spend = self.push_person("A3", key, other)
        refusal = self.expect_refused("A3", key, other)
        self.expect_served("A3", key, operator)
        self.hold("A3", f"Y at {spend:.2f} dollars refused: {refusal}, F 0, while O is served")

    def cell_a4(self) -> None:
        key, person = self.make_key(), self.fingerprint()
        self.expect_served("A4", key, person)
        self.wait_for("A4", "the row of the first request", lambda: self.customer(person))
        linked = time.monotonic()
        self.admin("POST", "/customer/update", {"user_id": person, "budget_id": OPERATOR_BUDGET})
        spend = self.push_person("A4", key, person)
        refused = 0
        while self.complete(key, user=person)["status"] != 200:
            refused += 1
            expect(time.monotonic() - linked < CACHE_SECONDS, f"A4: refused {refused} times")
            time.sleep(1)
        self.hold("A4", f"linked by /customer/update after a request of its own: served at "
                  f"{spend:.2f} dollars {time.monotonic() - linked:.0f} s after the link, "
                  f"{refused} refusals before")  # fmt: skip

    def cell_k5(self) -> str:
        key = self.make_key()
        self.push(key, self.fingerprint(), APP_PUSH)
        self.wait_for("K5", "the key's spend past its budget",
                      lambda: self.key_info(key)["spend"] > APP_BUDGET)  # fmt: skip
        refusal = self.expect_refused("K5", key, self.fingerprint())
        self.hold("K5", f"past max_budget the next request is refused before the provider: "
                  f"{refusal}, F 0")  # fmt: skip
        return key

    def cells_k7_p5(self, over: str, key: str, person: str) -> None:
        self.recreate_litellm()
        refusal = self.expect_refused("K7", over, self.fingerprint())
        self.hold("K7", f"after the recreate the key over budget: {refusal}")
        self.hold("P5", f"after the recreate X: {self.expect_refused('P5', key, person)}")

    def cell_k8(self, over: str) -> None:
        reset_at = datetime.fromisoformat(self.key_info(over)["budget_reset_at"])
        expect(reset_at.tzinfo is not None, f"K8: budget_reset_at {reset_at} names no zone")
        wanted = first_of_next_month(datetime.now(UTC))
        expect(reset_at == wanted, f"K8: budget_reset_at {reset_at}, not {wanted}")
        self.move_due("LiteLLM_VerificationToken", "token", hashed(over))
        took = self.wait_for("K8", "the reset", lambda: self.key_info(over)["spend"] == 0)
        self.expect_served("K8", over, self.fingerprint())
        self.hold("K8", f"budget_reset_at {reset_at.isoformat()}; moved due, spend 0 after "
                  f"{took:.0f} s, the next request served")  # fmt: skip

    def cell_p6(self, key: str, person: str) -> None:
        budget_id = person_budget()["budget_id"]
        self.move_due("LiteLLM_BudgetTable", "budget_id", budget_id)
        took = self.wait_for("P6", "the reset", lambda: self.customer_spend(person) == 0)
        self.expect_served("P6", key, person)
        self.hold("P6", f"the person budget moved due: X's spend 0 after {took:.0f} s, X served")

    def cell_g4(self, key: str) -> None:
        config = shipped_config()
        models = {entry["model_name"]: entry["litellm_params"] for entry in config["model_list"]}
        old, new = models["text/opus"]["model"], models["text/sonnet"]["model"]
        expect(old != new, "G4: the two families share an id")
        models["text/opus"]["model"] = new
        self.write_litellm_config(config)
        self.recreate_litellm()
        before = len(self.provider_requests())
        answer = self.complete(key, user=self.fingerprint())
        sent = [request["model"] for request in self.provider_requests()[before:]]
        expect(answer["status"] == 200 and sent == [new.split("/", 1)[1]], f"G4: {sent}")
        self.hold("G4", "a remapped config reaches LiteLLM after its recreate")


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], AdmissionProbe)


if __name__ == "__main__":
    sys.exit(main())
