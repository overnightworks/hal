"""Probe of the API route's bound on parallel requests (#847 cells B0-B6): the stack of litellm.py
(the real service, the one-route front, LiteLLM and the gateway's second entrypoint, against a
fake Anthropic) with the fake holding requests until the probe releases them. Nothing live and
nothing paid: the probe refuses to start unless `internet` is internal and holds only the fakes.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_admission.py --scratch DIR

Evidence: F is the fake provider's request log, R the canary's verdict lines, C the exit lines of
the throwaway clients. N is the bound the resolved compose environment of `litellm` carries. The
probe waits on observed events only: N new request lines in F, the clients' lines, the canary's
verdicts. Exit 0: every cell held.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))

from litellm import (
    DEFAULT_APP,
    FAKE_PROVIDER,
    LABEL,
    LISTENING,
    LITELLM,
    PROJECT,
    REPO,
    ROUTE,
    SERVICE,
    LitellmProbe,
    expect,
    run_scratch_probe,
)

BOUND = "API_ROUTE_MAX_PARALLEL_REQUESTS"
WORKERS = "NUM_WORKERS"
UNAVAILABLE = "provider_unavailable"
TOO_MANY = 429
REQUEST_SECONDS = 60
HOLDER_SECONDS = 120
UPSTREAM_FAILURE = 529
CLIENT_PROGRAM = """\
import json, socket, sys, time
bearer, body = sys.argv[1:3]
payload = body.encode()
head = (
    "POST " + sys.argv[3] + " HTTP/1.1\\r\\nHost: litellm-front:4000\\r\\nConnection: close\\r\\n"
    f"Authorization: Bearer {bearer}\\r\\nContent-Type: application/json\\r\\n"
    f"Content-Length: {len(payload)}\\r\\n\\r\\n"
)
started = time.monotonic()
with socket.create_connection(("litellm-front", 4000), timeout=120) as raw:
    raw.sendall(head.encode() + payload)
    reply = b""
    while chunk := raw.recv(65536):
        reply += chunk
lines = reply.split(b"\\r\\n\\r\\n", 1)[0].decode().splitlines()
headers = {k.lower(): v for k, _, v in (line.partition(": ") for line in lines[1:])}
print(json.dumps({
    "status": int(lines[0].split(" ", 2)[1]), "retry_after": headers.get("retry-after"),
    "seconds": time.monotonic() - started,
}), flush=True)
"""


class AdmissionProbe(LitellmProbe):
    """litellm.py's stack, with the provider holding requests and the bound read from compose."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.holders: list[subprocess.Popen] = []
        self.client_count = 0
        self.base = 0

    # --- plumbing -----------------------------------------------------------------------------

    def litellm_environment(self) -> dict:
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        return resolved["services"][LITELLM]["environment"]

    def client_command(self, name: str) -> list[str]:
        return [
            "docker", "run", "--rm", "-i", "--name", name, "--label", LABEL,
            f"--network={PROJECT}_litellm-api", "--read-only", "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", self.image,
            "python", "-I", "-", self.credential, json.dumps(self.good_body()), ROUTE,
        ]  # fmt: skip

    def start_client(self) -> subprocess.Popen:
        self.client_count += 1
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            self.client_command(f"{PROJECT}-client-{self.client_count}"),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(CLIENT_PROGRAM)
        process.stdin.close()
        return process

    def finish(self, process: subprocess.Popen) -> dict:
        """The line a client prints when its request is answered."""
        out, err = process.communicate(timeout=HOLDER_SECONDS)
        expect(process.returncode == 0, f"a client failed: {err[-300:]}")
        return json.loads(out.strip().splitlines()[-1])

    def one_request(self) -> dict:
        return self.finish(self.start_client())

    def wait_for_requests(self, cell: str, count: int) -> None:
        deadline = time.monotonic() + REQUEST_SECONDS
        while len(self.provider_requests()) < count:
            expect(time.monotonic() < deadline, f"{cell}: the fake never logged {count} requests")
            time.sleep(1)

    def released(self) -> list[str]:
        return [line for line in self.log_of(FAKE_PROVIDER).splitlines() if line.startswith("held")]

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until(SERVICE, LISTENING)
        self.wait_until(LITELLM, LISTENING)
        environment = self.litellm_environment()
        bound = int(environment[BOUND])
        try:
            self.cell_b0(environment)
            self.cells_b1_to_b4(bound)
            self.cell_b5(bound)
            self.cell_b6(bound)
        finally:
            for process in self.holders:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def cell_b0(self, environment: dict) -> None:
        expect(WORKERS not in environment, f"B0: {WORKERS} is set to {environment.get(WORKERS)!r}")
        self.hold("B0", "workers 1")

    def cells_b1_to_b4(self, bound: int) -> None:
        self.steer_fake(mode="hold")
        self.base = len(self.provider_requests())
        self.holders = [self.start_client() for _ in range(bound)]
        self.wait_for_requests("B1", self.base + bound)
        expect(all(p.poll() is None for p in self.holders), "B1: a held request was answered")
        self.hold("B1", f"the fake logged {bound} new requests, all {bound} held")
        over = self.one_request()
        retry = over["retry_after"]
        expect(over["status"] == TOO_MANY, f"B2: the request over the bound got {over['status']}")
        expect(
            retry is not None and retry.isdigit() and int(retry) >= 1, f"B2: Retry-After {retry!r}"
        )
        expect(
            not self.released() and all(p.poll() is None for p in self.holders),
            "B2: a held request ended before the refusal was received",
        )
        self.hold(
            "B2", f"429, Retry-After {retry}, after {over['seconds']:.2f} s, before any release"
        )
        run = self.canary(DEFAULT_APP)
        expect(run.get("route") == "api" and run.get("code") == UNAVAILABLE, f"B4: {run}")
        expect(run["exit"] != "0", "B4: the failed run exited 0")
        self.hold("B4", "an API-only person's run: failed, provider_unavailable, route api")
        sent = len(self.provider_requests()) - self.base
        expect(sent == bound, f"B3: the fake got {sent} requests, not {bound}")
        self.hold("B3", f"the fake's count is the base plus {bound}")

    def cell_b5(self, bound: int) -> None:
        self.steer_fake()
        answered = [self.finish(process) for process in self.holders]
        expect(all(a["status"] == 200 for a in answered), f"B5: the held ones ended {answered}")
        before = len(self.provider_requests())
        after = self.one_request()
        expect(after["status"] == 200, f"B5: the next request got {after['status']}")
        expect(
            len(self.provider_requests()) == before + 1, "B5: the fake's count did not grow by 1"
        )
        self.hold("B5", f"the {bound} held ones ended 200, the next is 200 and reached the fake")

    def cell_b6(self, bound: int) -> None:
        self.steer_fake(mode="status", status=UPSTREAM_FAILURE)
        before = len(self.provider_requests())
        statuses = [self.one_request()["status"] for _ in range(bound + 1)]
        expect(TOO_MANY not in statuses, f"B6: a failed request kept its slot: {statuses}")
        sent = len(self.provider_requests()) - before
        expect(sent == bound + 1, f"B6: the fake got {sent} of {bound + 1} requests")
        self.steer_fake()
        self.hold("B6", f"{bound + 1} failed requests in a row ({statuses}), none refused")


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], AdmissionProbe)


if __name__ == "__main__":
    sys.exit(main())
