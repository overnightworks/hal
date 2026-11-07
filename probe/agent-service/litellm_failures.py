"""Probe of the API route's failures, keys and rotation (#807 S1b cells F6-F11, F13-F17, F19, D6,
and K10): the stack of litellm.py (the front, LiteLLM, its database and the gateway, against a
fake Anthropic) with the fake steered through its control
file and the caller of litellm.py, a throwaway with an app key. Nothing live and nothing paid: the
probe refuses to start unless `internet` is internal and holds only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_failures.py --scratch DIR

Measured: a run takes about eight minutes (F10 waits for the fake's 120 s hold limit, K10 for
LiteLLM's caches) and its teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: F is the fake provider's request log, A the caller's status and LiteLLM's error type, I
`docker inspect`, L the container logs, LA LiteLLM's access log. The probe differs from production
as litellm.py does, plus the fake's control file and, for F9 only, the fake's certificate from a
second scratch CA. Exit 0: every cell held.
"""

from __future__ import annotations

import contextlib
import json
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))

from litellm import (
    DATABASE,
    DATABASE_PASSWORD_FILE,
    FAKE_PROVIDER,
    LABEL,
    LITELLM,
    PROJECT,
    PROVIDER_HOST,
    PROVIDER_KEY_FILE,
    REPO,
    ROUTE,
    LitellmProbe,
    ProbeFailed,
    error_of,
    expect,
    is_engine,
    person_budget,
    run_scratch_probe,
    wire_body,
)
from litellm_ca import ScratchCa, issue_certificate, write_new, write_scratch_ca

HOLD_END_SECONDS = 150
CACHE_SECONDS = 300
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
            "executable": os.readlink(f"/proc/{entry}/exe"),
            "core": core.split()[-3:-1],
        }
print(json.dumps({"processes": rows}))
"""
SECRET_NAMES = ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "LITELLM_MASTER_KEY", "DATABASE_URL")


class FailureProbe(LitellmProbe):
    """litellm.py's stack, with the provider and the keys made to fail."""

    def __init__(self, scratch: Path) -> None:
        self.corpus: list[str] = []
        super().__init__(scratch)
        self.scratch = scratch
        self.home = Path(self.environment["HOME"])
        self.key = ""
        self.every_value = [
            self.provider_key,
            self.picture_key,
            self.master_key,
            self.database_password,
        ]

    # --- plumbing -----------------------------------------------------------------------------

    def steer(self, **steering: object) -> None:
        self.steer_fake(provider_key=self.provider_key, **steering)

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

    def call_command(self, name: str, bearer: str | None, method: str, path: str,
                     body: dict | None, *, front: bool, network: str | None = None):  # fmt: skip
        """Every caller's argv enters the corpus, the command line its container's Config.Cmd
        comes from, so F15 sees a key that reached it."""
        argv, program = super().call_command(
            name, bearer, method, path, body, front=front, network=network
        )
        self.record(" ".join(argv))
        return argv, program

    def containers_of(self, service: str) -> list[str]:
        """Every container of `service`, stopped ones included."""
        return self.run([
            "docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--filter", f"label=com.docker.compose.service={service}",
        ]).stdout.split()  # fmt: skip

    def every_container(self) -> list[str]:
        """Every container of the probe, stopped ones included: the project's and the ones it
        labels."""
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

    def wait_for_front(self) -> None:
        """The front answers and a request through it reaches LiteLLM: LiteLLM refuses one without a
        bearer. A 401 proves no more: not the keys, the database or the provider."""
        deadline = time.monotonic() + 60
        while True:
            try:
                if self.complete(None, user=self.fingerprint())["status"] == 401:
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

    def failed_answer(self, cell: str) -> str:
        """One request the provider answers with a failure: not 200, F 1; returns its status."""
        before = len(self.provider_requests())
        answer = self.complete(self.key, user=self.fingerprint())
        expect(answer["status"] != 200, f"{cell}: the failure was answered 200")
        sent = len(self.provider_requests()) - before
        expect(sent == 1, f"{cell}: the fake provider got {sent} requests")
        return f"{answer['status']} {error_of(answer)}"

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until_listening()
        self.admin("POST", "/budget/new", person_budget())
        self.key = self.make_key()
        self.steer()
        self.cells_provider_failures()
        self.cell_f20()
        self.cell_f9()
        self.cell_f10()
        self.cell_f11()
        self.cell_f17()
        self.cells_f13_f14()
        self.cell_k10()
        self.cell_d6()
        self.cells_f15_f16()
        self.cell_f19()

    def cells_provider_failures(self) -> None:
        """F6 to F8: one request per answer of the fake, F7 with both answers of a used-up
        balance; the caller's status is recorded for agent-runtime."""
        for cell, steerings, how in (
            ("F6", ({"mode": "reset"},), "connection reset"),
            ("F7", ({"mode": "billing"}, {"mode": "low_credit"}),
             "a used-up balance as 402 billing_error and as 400 credit balance too low"),
            ("F8", ({"mode": "broken"},), "200 with a broken body"),
        ):  # fmt: skip
            statuses = []
            for steering in steerings:
                self.steer(**steering)
                statuses.append(self.failed_answer(cell))
            self.hold(cell, f"{how}: F 1 per answer, the caller got {statuses}")
        self.steer()

    def cell_f20(self) -> None:
        """A call right after a provider 401 reaches the provider and is served: the router
        keeps no cooldown, so no 429 stands in for the provider's answer."""
        self.steer(mode="status", status=401)
        refused = self.failed_answer("F20")
        self.steer()
        before = len(self.provider_requests())
        answer = self.complete(self.key, user=self.fingerprint())
        self.served("F20", answer, self.provider_requests()[before:])
        self.hold("F20", f"after the provider's {refused}, the next call reached F and was served")

    def serve_provider_certificate_of(self, authority: ScratchCa) -> None:
        """The fake provider recreated with a certificate of `authority`, once it listens."""
        folder = self.fake / PROVIDER_HOST
        issue_certificate(authority, PROVIDER_HOST, folder)
        for file in folder.iterdir():
            file.chmod(0o644)
        self.harvest(FAKE_PROVIDER)
        self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", FAKE_PROVIDER)
        connect = "import socket; socket.create_connection(('127.0.0.1', 443), timeout=1)"
        self.wait_for("F9", "the fake provider's listener", lambda: self.run(
            ["docker", "exec", self.container(FAKE_PROVIDER), "python", "-I", "-c", connect],
            check=False,
        ).returncode == 0, seconds=30)  # fmt: skip

    def cell_f9(self) -> None:
        """A provider certificate from a CA LiteLLM does not trust: refused before any request
        reaches F, and served again once the trusted certificate is back."""
        other = write_scratch_ca(self.scratch / "other-ca")
        self.serve_provider_certificate_of(other)
        answer = self.complete(self.key, user=self.fingerprint())
        expect(answer["status"] != 200, "F9: an untrusted certificate was answered 200")
        expect(not self.provider_requests(), "F9: a request reached the untrusted provider")
        self.serve_provider_certificate_of(self.scratch_ca)
        recovered = self.complete(self.key, user=self.fingerprint())
        self.served("F9", recovered, self.provider_requests())
        self.hold("F9", f"a provider certificate of an untrusted CA: {answer['status']} "
                  f"{error_of(answer)}, F 0; the trusted one back, served")  # fmt: skip

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
        """A caller that leaves while its request is held at the provider."""
        self.steer(mode="hold")
        before, already = len(self.provider_requests()), len(self.hold_ends())
        name = f"{PROJECT}-leaving-caller"
        body = wire_body(user=self.fingerprint())
        argv, program = self.call_command(name, self.key, "POST", ROUTE, body, front=True)
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(program)
        process.stdin.close()
        deadline = time.monotonic() + 60
        while len(self.provider_requests()) == before:
            expect(time.monotonic() < deadline, "F10: the request never reached the provider")
            time.sleep(1)
        self.run(["docker", "inspect", name])  # I of a key-bearing caller while it runs, for F15
        self.run(["docker", "rm", "--force", name])
        process.communicate(timeout=60)
        ended = self.wait_for_hold_end("F10", already)
        self.steer()
        after = len(self.provider_requests()) - before
        expect(after == 1, f"F10: the provider got {after} requests by the end of the hold")
        self.hold("F10", f"the caller left: F 1 request and none after; its request ended {ended}")

    def cell_f11(self) -> None:
        malformed = f"not a key {secrets.token_hex(12)}"
        self.every_value.append(malformed)
        before = len(self.provider_requests())
        status = self.complete(malformed, user=self.fingerprint())["status"]
        expect(status == 401, f"F11: a malformed bearer got {status}")
        expect(len(self.provider_requests()) == before, "F11: the provider was reached")
        expect(malformed not in self.log_of(LITELLM), "F11: a log line holds the bearer")
        self.hold("F11", "a malformed bearer: 401, F 0, the value in no line of LiteLLM's log")

    def cell_f17(self) -> None:
        new = secrets.token_urlsafe(32)
        self.every_value.append(new)
        self.replace_by_rename(PROVIDER_KEY_FILE, new + "\n")
        self.provider_key = new
        self.steer()
        before = len(self.provider_requests())
        self.complete(self.key, user=self.fingerprint())
        stale = self.provider_requests()[before:]
        expect([r["key_ok"] for r in stale] == [False], "F17: the old inode did not hold")
        self.recreate_litellm()
        before = len(self.provider_requests())
        status = self.complete(self.key, user=self.fingerprint())["status"]
        sent = [r["key_ok"] for r in self.provider_requests()[before:]]
        expect(status == 200 and sent == [True], f"F17: {status} {sent}")
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

    def cell_k10(self) -> None:
        """The database stopped under a running proxy: a key it has cached passes until the cache
        expires, then every request is refused before the provider."""
        key, served, refused = self.make_key(), [], None
        expect(self.complete(key, user=self.fingerprint())["status"] == 200, "K10: not served")
        self.compose("stop", DATABASE)
        stopped = time.monotonic()
        while refused is None:
            expect(time.monotonic() - stopped < CACHE_SECONDS, f"K10: served {len(served)} times")
            before = len(self.provider_requests())
            answer = self.complete(key, user=self.fingerprint())
            if answer["status"] == 200:
                served.append(time.monotonic() - stopped)
            else:
                expect(len(self.provider_requests()) == before, "K10: the refusal reached F")
                refused = (time.monotonic() - stopped, f"{answer['status']} {error_of(answer)}")
            time.sleep(1)
        expect(self.database_password not in self.log_of(LITELLM), "K10: the password is logged")
        self.compose("up", "--detach", "--wait", "--no-deps", DATABASE)
        self.recreate_litellm()
        last = f"{served[-1]:.0f} s" if served else "none"
        self.hold("K10", f"litellm-db stopped: served {len(served)} times, the last at {last}; "
                  f"refused at {refused[0]:.0f} s with {refused[1]}, F 0; no password in "
                  "L")  # fmt: skip

    def cells_f15_f16(self) -> None:
        self.every_value += self.app_keys
        found = self.values_in_corpus(self.every_value)
        expect(not found, f"F15: {len(found)} secret values found in I, L, R or the output")
        size = sum(len(text) for text in self.corpus)
        self.hold(
            "F15",
            f"{len(self.every_value)} values absent from {size} characters of every command's"
            " output, every caller's argv and every container's I and L",
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
        names = sorted(Path(rows[pid]["executable"]).name for pid in holders)
        self.hold(
            "F19",
            f"init and a main tree of {len(rows) - 1}; holders {names}, all uid {user} with core"
            " size 0",
        )

    def expect_holders(self, rows: dict, holders: set[int], proxy: int, container: str) -> int:
        """The proxy and its one query engine are the only holders, all as the configured user with
        core size 0; returns that user."""
        engines = [pid for pid in holders if is_engine(rows[pid], proxy, self.engine_executable)]
        strays = [rows[pid]["name"] for pid in holders - {proxy, *engines}]
        expect(len(engines) == 1, f"F19: {len(engines)} query engines hold the secrets")
        expect(not strays, f"F19: holders outside the proxy and its query engine: {strays}")
        user = self.configured_user(container)
        expect(
            all(rows[pid]["uid"] == user and rows[pid]["core"] == ["0", "0"] for pid in holders),
            "F19: a holder is not the configured user or has a core size",
        )
        return user

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
        """Starts LiteLLM alone and waits for its end: non-zero, never listening in any snapshot
        while it ran, the `password` it got not in its log. The text is what the cell holds, with
        the time measured."""
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
            listening = False
            with contextlib.suppress(ProbeFailed):  # it may end between inspect and the scan
                listening = self.proxy_snapshot().listening
            expect(not listening, f"D6: {how}: LiteLLM listened")
            expect(time.monotonic() - started < DATABASE_WAIT_SECONDS, f"D6: still up {how}")
            time.sleep(2)
        seconds = time.monotonic() - started
        self.compose("stop", LITELLM)
        logs = self.run(["docker", "logs", container], check=False)
        text = logs.stdout + logs.stderr
        tail = " | ".join(text.strip().splitlines()[-8:])[-1200:]
        expect(state["ExitCode"] != 0, f"D6: {how}: exit code {state['ExitCode']}: {tail}")
        expect(password not in text, f"D6: {how}: the password is in the log")
        return f"exit code {state['ExitCode']} after {seconds:.0f} s, never listening"


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], FailureProbe)


if __name__ == "__main__":
    sys.exit(main())
