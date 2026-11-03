"""Probe of the API route's failures, keys and rotation (#807 S1b cells F0-F21): the stack of
litellm.py (the real service, the one-route front, LiteLLM and the gateway's second entrypoint,
against a fake Anthropic) with the fake steered through its control file. Nothing live and nothing
paid: the probe refuses to start unless `internet` is internal and holds only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_failures.py --scratch DIR

Measured: a run takes about 8 minutes (F10 waits for the fake's 120 s hold limit) and its
teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: F is the fake provider's request log, R the canary's verdict lines, I `docker inspect`,
L the container logs, LA LiteLLM's access log. F0 is the baseline run that proves the zero
observations of F2 and F21 could have been something else. The probe differs from production as
litellm.py does, plus: the fake's control file; F5 only, LiteLLM's lower `request_timeout`;
F9 only, the fake's certificate from a second scratch CA. Exit 0: every cell held.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))

from api_canary import verdicts
from litellm import (
    CANARY_SECONDS,
    CREDENTIAL_FILE,
    DATABASE,
    DATABASE_PASSWORD_FILE,
    DEFAULT_APP,
    FAKE_PROVIDER,
    FRONT,
    GATEWAY,
    LABEL,
    LISTENING,
    LITELLM,
    MASTER_KEY_FILE,
    PROJECT,
    PROVIDER_HOST,
    PROVIDER_KEY_FILE,
    REPO,
    ROUTE,
    SERVICE,
    LitellmProbe,
    ProbeFailed,
    expect,
    run_scratch_probe,
)
from scratch_secrets import issue_certificate, write_new, write_scratch_secrets

UNAVAILABLE = "provider_unavailable"
LOWER_TIMEOUT_SECONDS = 5
HOLD_END_SECONDS = 150
DATABASE_WAIT_SECONDS = 600
CENSUS_PROGRAM = """\
import json, os, sys
names = [name.encode() + b"=" for name in sys.argv[1:]]
rows = {}
for entry in os.listdir("/proc"):
    if entry.isdigit() and int(entry) != os.getpid():
        fields = open(f"/proc/{entry}/stat").read().rpartition(")")[2].split()
        environ = open(f"/proc/{entry}/environ", "rb").read().split(b"\\0")
        holds = [n[:-1].decode() for n in names if any(item.startswith(n) for item in environ)]
        status = open(f"/proc/{entry}/status").read().splitlines()
        uid = next(line for line in status if line.startswith("Uid:")).split()[1]
        limits = open(f"/proc/{entry}/limits").read().splitlines()
        core = next(line for line in limits if line.startswith("Max core file size"))
        rows[entry] = {
            "parent": int(fields[1]), "holds": holds, "uid": int(uid),
            "name": open(f"/proc/{entry}/comm").read().strip(),
            "executable": os.path.basename(os.readlink(f"/proc/{entry}/exe")),
            "core": core.split()[-3:-1],
        }
print(json.dumps({"processes": rows}))
"""
SECRET_NAMES = ("ANTHROPIC_API_KEY", "LITELLM_MASTER_KEY", "DATABASE_URL")
ENGINE_EXECUTABLE = "query-engine"


class FailureProbe(LitellmProbe):
    """litellm.py's stack, with the provider and the keys made to fail."""

    def __init__(self, scratch: Path) -> None:
        self.corpus: list[str] = []
        super().__init__(scratch)
        self.scratch = scratch
        self.home = Path(self.environment["HOME"])
        self.master_key = (self.home / MASTER_KEY_FILE).read_text().strip()
        self.every_value = [
            self.provider_key,
            self.credential,
            self.master_key,
            self.database_password,
        ]

    # --- plumbing -----------------------------------------------------------------------------

    def steer(self, **steering: object) -> None:
        self.steer_fake(provider_key=self.provider_key, credential=self.credential, **steering)

    def record(self, *texts: str) -> None:
        """The one way into the corpus F15 and F16 search."""
        self.corpus.extend(texts)

    def run(self, command: list[str], **options: object) -> subprocess.CompletedProcess:
        """Every command the probe runs: its stdout and stderr enter the corpus. A command that
        fails its check ends the probe before F15, so only the outputs F15 can see are kept."""
        result = super().run(command, **options)
        self.record(result.stdout or "", result.stderr or "")
        return result

    def hold(self, cell: str, how: str) -> None:
        super().hold(cell, how)
        self.record(f"{cell} held: {how}")

    def containers_of(self, service: str) -> list[str]:
        """Every container of `service`, stopped ones included."""
        return self.run([
            "docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--filter", f"label=com.docker.compose.service={service}",
        ]).stdout.split()  # fmt: skip

    def every_container(self) -> list[str]:
        """Every container of the probe, stopped ones included: the project's, the issuers' among
        them, and the ones it labels."""
        found: list[str] = []
        for label in (f"com.docker.compose.project={PROJECT}", LABEL):
            found += self.run(["docker", "ps", "-aq", "--filter", f"label={label}"]).stdout.split()
        return list(dict.fromkeys(found))

    def harvest_containers(self, containers: list[str]) -> None:
        """I and L of `containers` into the corpus, through `run`."""
        for container in containers:
            self.run(["docker", "inspect", container])
            self.run(["docker", "logs", container], check=False)

    def harvest(self, *services: str) -> None:
        """Keeps I and L of the containers of `services` before a recreate takes them away."""
        self.harvest_containers([c for service in services for c in self.containers_of(service)])

    def values_in_corpus(self, values: list[str]) -> list[str]:
        """The `values` that I and L of every container and the probe's output hold."""
        self.harvest_containers(self.every_container())
        text = "\n".join(self.corpus)
        return [value for value in values if value in text]

    def recreate_litellm(self) -> None:
        self.harvest(LITELLM)
        super().recreate_litellm()

    def recreate(self, service: str) -> None:
        self.harvest(service)
        self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)

    def start_again(self, service: str) -> None:
        self.compose("up", "--detach", "--no-deps", service)

    def wait_for_front(self) -> None:
        """The front answers and reaches LiteLLM: its hook refuses a request without a bearer."""
        deadline = time.monotonic() + 60
        while True:
            try:
                if self.http("POST", ROUTE, None, self.good_body()) == 401:
                    return
            except ProbeFailed:
                pass
            expect(time.monotonic() < deadline, "the front does not answer")
            time.sleep(1)

    def replace_by_rename(self, relative: Path, contents: str, mode: int = 0o600) -> None:
        """A new file at the secret's path: a new inode, as a writer that renames makes it."""
        target = self.home / relative
        draft = target.with_name(target.name + ".new")
        write_new(draft, contents.encode(), mode)
        draft.replace(target)

    def credential_document(self, value: str) -> str:
        return json.dumps({"shared_key": value})

    def counts(self) -> tuple[int, int]:
        return len(self.provider_requests()), len(self.access_lines())

    def failed_run(self, cell: str, *, provider_sees: int | None) -> None:
        """A run that ends `failed: provider_unavailable` on route api; the fake got
        `provider_sees` requests when that is given."""
        before = len(self.provider_requests())
        run = self.canary(DEFAULT_APP)
        expect(run.get("route") == "api" and run.get("code") == UNAVAILABLE, f"{cell}: {run}")
        expect(run["exit"] != "0", f"{cell}: the failed run exited 0")
        seen = len(self.provider_requests()) - before
        expect(provider_sees in (None, seen), f"{cell}: the fake provider got {seen} requests")

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until(SERVICE, LISTENING)
        self.wait_until(LITELLM, LISTENING)
        self.steer()
        self.cell_f0()
        self.cells_stopped_hops()
        self.cells_provider_failures()
        self.cell_f9()
        self.cell_f10()
        self.cells_f11_f12_f18()
        self.cell_f17()
        self.cells_f13_f14()
        self.cell_f20()
        self.cell_d6()
        self.cells_f15_f16()
        self.cell_f19()

    def cell_f0(self) -> None:
        before_f, before_la = self.counts()
        run = self.canary(DEFAULT_APP)
        expect(run.get("exit") == "0" and run.get("route") == "api", f"F0: {run}")
        sent, lines = self.counts()
        expect((sent - before_f, lines - before_la) == (1, 1), f"F0: F {sent - before_f}, LA")
        self.hold("F0", "succeeded on route api, F 1, LA one line")

    def cells_stopped_hops(self) -> None:
        """F1, F2 and F21: a hop of the path stopped, then brought back."""
        self.compose("stop", LITELLM)
        self.failed_run("F1", provider_sees=0)
        self.hold("F1", "LiteLLM stopped: route api, provider_unavailable")
        self.recreate(LITELLM)
        self.wait_until(LITELLM, LISTENING)
        self.compose("stop", FRONT)
        _, before = self.counts()
        self.failed_run("F21", provider_sees=0)
        expect(self.counts()[1] == before, "F21: LiteLLM's log grew")
        self.hold("F21", "the front stopped: provider_unavailable, LiteLLM's log has 0 new lines")
        self.start_again(FRONT)
        self.wait_for_front()
        self.compose("stop", GATEWAY)
        self.failed_run("F2", provider_sees=0)
        self.hold("F2", "the gateway stopped: provider_unavailable, F 0")
        self.start_again(GATEWAY)
        self.wait_until_the_gateway_answers()
        run = self.canary(DEFAULT_APP)
        expect(run["exit"] == "0", f"F2: the stack did not recover: {run}")

    def cells_provider_failures(self) -> None:
        """F3, F4 and F6 to F8: one run per answer of the fake, F7 with both answers of a used-up
        balance."""
        for cell, steerings, how in (
            ("F3", ({"mode": "status", "status": 500},), "upstream 500"),
            ("F4", ({"mode": "status", "status": 529},), "upstream 529"),
            ("F6", ({"mode": "reset"},), "connection reset"),
            ("F7", ({"mode": "billing"}, {"mode": "low_credit"}),
             "a used-up balance as 402 billing_error and as 400 credit balance too low"),
            ("F8", ({"mode": "broken"},), "200 with a broken body"),
        ):  # fmt: skip
            for steering in steerings:
                self.steer(**steering)
                self.failed_run(cell, provider_sees=1)
            self.hold(cell, f"{how}: F 1 per answer, provider_unavailable")
        self.cell_f5()

    def cell_f5(self) -> None:
        shipped = self.litellm_config.read_text(encoding="utf-8")
        lower = f"litellm_settings:\n  request_timeout: {LOWER_TIMEOUT_SECONDS}\n"
        self.litellm_config.write_text(
            shipped.replace("litellm_settings:\n", lower, 1), encoding="utf-8"
        )
        self.recreate_litellm()
        self.steer(mode="hold")
        already = len(self.hold_ends())
        self.failed_run("F5", provider_sees=1)
        ended = self.wait_for_hold_end("F5", already)
        expect(ended == "disconnected", "F5: LiteLLM kept the request")
        self.hold("F5", "upstream timeout: F 1, provider_unavailable")
        self.litellm_config.write_text(shipped, encoding="utf-8")
        self.recreate_litellm()
        self.steer()

    def cell_f9(self) -> None:
        other_home = self.scratch / "other-home"
        other_home.mkdir()
        other = write_scratch_secrets(other_home, self.scratch / "other-ca")
        folder = self.fake / PROVIDER_HOST
        issue_certificate(other, PROVIDER_HOST, folder)
        for file in folder.iterdir():
            file.chmod(0o644)
        self.recreate(FAKE_PROVIDER)
        self.failed_run("F9", provider_sees=0)
        self.hold("F9", "a certificate of an untrusted CA: F 0, provider_unavailable")
        issue_certificate(self.scratch_secrets, PROVIDER_HOST, folder)
        for file in folder.iterdir():
            file.chmod(0o644)
        self.recreate(FAKE_PROVIDER)
        run = self.canary(DEFAULT_APP)
        expect(run["exit"] == "0", f"F9: the stack did not recover: {run}")

    def hold_ends(self) -> list[str]:
        return re.findall(r"^held (disconnected|timed out)$", self.log_of(FAKE_PROVIDER), re.M)

    def wait_for_hold_end(self, cell: str, already: int) -> str:
        """How the fake's next held request ended, `disconnected` or `timed out`; one that ends
        neither way within the fake's hold time fails the cell."""
        deadline = time.monotonic() + HOLD_END_SECONDS
        while time.monotonic() < deadline:
            ended = self.hold_ends()
            if len(ended) > already:
                return ended[already]
            time.sleep(1)
        raise ProbeFailed(f"{cell}: the held request never ended")

    def cell_f10(self) -> None:
        self.steer(mode="hold")
        before, already = len(self.provider_requests()), len(self.hold_ends())
        run = self.canary(DEFAULT_APP, ("--cancel",))
        expect(run.get("route") == "api" and run.get("status") == "cancelled", f"F10: {run}")
        sent = len(self.provider_requests()) - before
        expect(sent == 1, f"F10: the provider got {sent} requests")
        ended = self.wait_for_hold_end("F10", already)
        self.steer()
        after = len(self.provider_requests()) - before
        expect(after == 1, f"F10: the provider got {after} requests by the end of the hold")
        self.hold(
            "F10",
            f"status cancelled, F 1 request and none after; observed: its request ended {ended}",
        )

    def cells_f11_f12_f18(self) -> None:
        malformed = secrets.token_hex(12)
        self.every_value.append(malformed)
        for cell, value, contents, mode, how in (
            ("F11", malformed, f"not a credential {malformed}", 0o600, "a malformed credential"),
            ("F12", self.credential, self.credential_document(self.credential), 0o000,
             "the valid credential made unreadable"),
        ):  # fmt: skip
            self.replace_by_rename(CREDENTIAL_FILE, contents, mode)
            self.recreate_litellm()
            status = self.http("POST", ROUTE, self.credential, self.good_body())
            expect(status == 401, f"{cell}: the front answered {status}")
            self.failed_run(cell, provider_sees=0)
            expect(value not in self.log_of(LITELLM), f"{cell}: a log line holds a value")
            self.hold(cell, f"{how}: 401, provider_unavailable, F 0, no value in LiteLLM's log")
        self.cell_f18()

    def cell_f18(self) -> None:
        old, new = self.credential, secrets.token_urlsafe(32)
        self.every_value.append(new)
        self.replace_by_rename(CREDENTIAL_FILE, self.credential_document(new))
        self.recreate_litellm()
        self.credential = new
        expect(self.http("POST", ROUTE, old, self.good_body()) == 401, "F18: the old one passed")
        self.steer()
        self.failed_run("F18", provider_sees=0)
        self.recreate(SERVICE)
        self.wait_until(SERVICE, LISTENING)
        run = self.canary(DEFAULT_APP)
        expect(run["exit"] == "0", f"F18: after the service's recreate: {run}")
        self.hold(
            "F18", "old credential 401 after LiteLLM's recreate; the service fails until its own"
        )

    def cell_f17(self) -> None:
        new = secrets.token_urlsafe(32)
        self.every_value.append(new)
        self.replace_by_rename(PROVIDER_KEY_FILE, new + "\n")
        self.provider_key = new
        self.steer()
        before = len(self.provider_requests())
        self.canary(DEFAULT_APP)
        stale = self.provider_requests()[before:]
        expect([r["key_ok"] for r in stale] == [False], "F17: the old inode did not hold")
        self.recreate_litellm()
        before = len(self.provider_requests())
        run = self.canary(DEFAULT_APP)
        sent = self.provider_requests()[before:]
        expect(run["exit"] == "0" and [r["key_ok"] for r in sent] == [True], f"F17: {run} {sent}")
        self.hold("F17", "only the new key reaches the provider, after the recreate")

    def cells_f13_f14(self) -> None:
        key = self.home / PROVIDER_KEY_FILE
        kept = key.read_text()
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        key_in_container = resolved[LITELLM]["entrypoint"][1]  # start.sh's provider key file
        self.harvest(LITELLM)
        self.compose("rm", "--stop", "--force", LITELLM)
        key.unlink()
        refused = self.compose("up", "--detach", "--no-deps", LITELLM, check=False)
        text = refused.stderr + refused.stdout
        expect(refused.returncode != 0, "F13: Compose did not refuse")
        expect(str(key) in text, f"F13: the refusal does not name the secret: {text[-300:]}")
        expect(not self.containers_of(LITELLM), "F13: Compose created a container")
        expect(not (key.exists() or key.is_symlink()), "F13: Compose made the key's path")
        refusal = text.strip().splitlines()[-1].replace(str(self.home), "$HOME")
        self.hold("F13", f"Compose refuses and creates no container and no path: {refusal}")
        write_new(key, b"", 0o600)
        self.compose("up", "--detach", "--no-deps", LITELLM, check=False)
        time.sleep(5)
        (container,) = self.containers_of(LITELLM)
        state = json.loads(self.run(["docker", "inspect", container]).stdout)[0]
        expect(state["State"]["ExitCode"] != 0, "F14: the container did not exit")
        logs = self.run(["docker", "logs", container], check=False)
        named = [line for line in logs.stderr.splitlines() if line.startswith("litellm: ")]
        expect(
            named and all(key_in_container in line for line in named),
            f"F14: the log lines name no path: {named[:2]}",
        )
        self.hold("F14", "the container exits non-zero and its line names the path only")
        key.unlink()
        write_new(key, kept.encode(), 0o600)
        self.recreate_litellm()

    def cell_f20(self) -> None:
        self.steer(mode="hold")
        before = len(self.provider_requests())
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            self.canary_command(), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True, env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(self.canary_input(DEFAULT_APP))
        process.stdin.close()
        deadline = time.monotonic() + 60
        while len(self.provider_requests()) == before:
            expect(time.monotonic() < deadline, "F20: the run never reached the provider")
            time.sleep(1)
        self.recreate_litellm()
        out, err = process.communicate(timeout=CANARY_SECONDS)
        self.record(out, err)
        run = verdicts(out, process.returncode)
        expect(run.get("code") == UNAVAILABLE, f"F20: {run}")
        self.steer()
        again = self.canary(DEFAULT_APP)
        expect(again["exit"] == "0", f"F20: the next run: {again}")
        self.hold("F20", "the run in flight is provider_unavailable, the next one succeeds")

    def cells_f15_f16(self) -> None:
        found = self.values_in_corpus(self.every_value)
        expect(not found, f"F15: {len(found)} secret values found in I, L, R or the output")
        size = sum(len(text) for text in self.corpus)
        self.hold(
            "F15",
            f"{len(self.every_value)} values absent from {size} characters of every command's"
            " output and every container's I and L",
        )
        planted = self.every_value[0]
        plant = self.run([
            "docker", "create", "--network", "none", "--label", LABEL,
            "-e", f"PLANT={planted}", self.image, "true",
        ]).stdout.strip()  # fmt: skip
        try:
            found = self.values_in_corpus([planted])
        finally:
            self.run(["docker", "rm", plant])
        expect(found == [planted], "F16: the planted copy was not found")
        self.hold("F16", "a planted copy in a labelled container is found through the same search")

    def cell_f19(self) -> None:
        container = self.container(LITELLM)
        result = self.run(
            ["docker", "exec", "-i", container, "python3", "-", *SECRET_NAMES],
            stdin=CENSUS_PROGRAM,
        )  # fmt: skip
        rows = {int(pid): row for pid, row in json.loads(result.stdout)["processes"].items()}
        init_children = [pid for pid, row in rows.items() if row["parent"] == 1]
        expect(len(init_children) == 1, f"F19: init has {len(init_children)} children")
        proxy = init_children[0]

        def in_main_tree(pid: int) -> bool:
            while pid not in {1, proxy}:
                pid = rows[pid]["parent"]
            return pid == proxy

        outside = [pid for pid in rows if pid != 1 and not in_main_tree(pid)]
        holders = {pid for pid, row in rows.items() if row["holds"]}
        expect(not outside, f"F19: {len(outside)} processes outside the main tree")
        expect(proxy in holders and 1 not in holders, f"F19: holders {sorted(holders)}")
        expect(set(rows[proxy]["holds"]) == set(SECRET_NAMES), f"F19: proxy {rows[proxy]['holds']}")
        user = self.expect_holders(rows, holders, proxy, container)
        names = sorted(rows[pid]["executable"] for pid in holders)
        self.hold(
            "F19",
            f"init and a main tree of {len(rows) - 1}; holders {names}, all uid {user} with core"
            " size 0",
        )

    def expect_holders(self, rows: dict, holders: set[int], proxy: int, container: str) -> int:
        """The proxy and its one query engine are the only holders, all as the configured user with
        core size 0; returns that user."""
        engines = [pid for pid in holders if self.is_engine(rows[pid], proxy)]
        strays = [rows[pid]["name"] for pid in holders - {proxy, *engines}]
        expect(len(engines) == 1, f"F19: {len(engines)} query engines hold the secrets")
        expect(not strays, f"F19: holders outside the proxy and its query engine: {strays}")
        user = self.configured_user(container)
        expect(
            all(rows[pid]["uid"] == user and rows[pid]["core"] == ["0", "0"] for pid in holders),
            "F19: a holder is not the configured user or has a core size",
        )
        return user

    @staticmethod
    def is_engine(row: dict, proxy: int) -> bool:
        return row["parent"] == proxy and row["executable"].startswith(ENGINE_EXECUTABLE)

    def configured_user(self, container: str) -> int:
        configured = json.loads(self.run(["docker", "inspect", container]).stdout)[0]["Config"]
        return int(configured["User"].split(":")[0])

    def cell_d6(self) -> None:
        """LiteLLM without its database and with a wrong password: it ends non-zero after
        Prisma's retries, never listens, and the provider gets nothing."""
        self.harvest(LITELLM)
        self.compose("stop", LITELLM, DATABASE)
        before = len(self.provider_requests())
        away = self.ended_start("without the database", self.database_password)
        self.hold("D6", f"litellm-db stopped: {away}")
        self.compose("up", "--detach", "--wait", "--no-deps", DATABASE)
        wrong = secrets.token_urlsafe(32)
        self.every_value.append(wrong)
        kept = (self.home / DATABASE_PASSWORD_FILE).read_text()
        self.replace_by_rename(DATABASE_PASSWORD_FILE, wrong + "\n", 0o644)
        mistaken = self.ended_start("with a wrong password", wrong)
        expect(len(self.provider_requests()) == before, "D6: the fake provider got a request")
        self.hold("D6", f"a wrong password: {mistaken}")
        self.replace_by_rename(DATABASE_PASSWORD_FILE, kept, 0o644)
        self.recreate_litellm()

    def ended_start(self, how: str, password: str) -> str:
        """Starts LiteLLM alone and waits for its end: non-zero, never listening, the `password`
        it got not in its log. The text is what the cell holds, with the time measured."""
        self.compose("rm", "--stop", "--force", LITELLM)
        started = time.monotonic()
        self.compose("up", "--detach", "--no-deps", LITELLM)
        (container,) = self.containers_of(LITELLM)
        # The shipped policy restarts it, which would hide its first exit code.
        self.run(["docker", "update", "--restart=no", container])
        while True:
            state = json.loads(self.run(["docker", "inspect", container]).stdout)[0]["State"]
            if not state["Running"]:
                break
            expect(time.monotonic() - started < DATABASE_WAIT_SECONDS, f"D6: still up {how}")
            time.sleep(2)
        seconds = time.monotonic() - started
        self.compose("stop", LITELLM)
        logs = self.run(["docker", "logs", container], check=False)
        text = logs.stdout + logs.stderr
        tail = " | ".join(text.strip().splitlines()[-8:])[-1200:]
        expect(state["ExitCode"] != 0, f"D6: {how}: exit code {state['ExitCode']}: {tail}")
        expect(LISTENING not in text, f"D6: {how}: LiteLLM listened")
        expect(password not in text, f"D6: {how}: the password is in the log")
        return f"exit code {state['ExitCode']} after {seconds:.0f} s, no listening line"


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], FailureProbe)


if __name__ == "__main__":
    sys.exit(main())
