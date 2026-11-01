"""Probe of the API route's retention (#814 S1c cells B1-B11): the stack of litellm.py (the real
service, the one-route front, LiteLLM and the gateway's second entrypoint, against a fake Anthropic)
with a unique canary in each request and answer, searched afterwards in every writable mount and
every log of the front, the gateway, LiteLLM and the service by `agent-service/retention_census.py`.
Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and holds
only the fakes.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_retention.py --scratch DIR

Measured: a run takes about four minutes (B8 waits for the fake's 120 s hold limit) and its
teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: F is the fake provider's request log, R the canary's verdict lines, C the census's verdict
(canaries found per sink, and every sink it could not examine). B2, B3a and B3b are the controls:
each plants a canary where the search must find it (a file by exec into a tmpfs, a LiteLLM debug
log, the front's access log), and they run first on a stack the probe then recreates, so no clean
cell sees their tmpfs. The probe differs from production as the controls say, for B3a and B3b
only: `LITELLM_LOG=DEBUG`, and the front's access log. The fake's control file and the client's
scratch are harness inputs that hold the canaries by design and are no sinks of the route.
Every clean cell sends fresh canaries. B11 prints the configuration of the running
containers; the reviewer judges it against the pinned image's source writers.

Exit 0: every cell held.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "agent-service"))

from litellm import (  # noqa: E402
    CANARY_SECONDS,
    DEFAULT_APP,
    FRONT,
    FRONT_STATIC,
    GATEWAY,
    LISTENING,
    LITELLM,
    REMAPPED_APP,
    ROUTE,
    SERVICE,
    ProbeFailed,
    expect,
    listeners_of,
    mounted_file,
    run_scratch_probe,
)
from litellm_failures import FailureProbe  # noqa: E402
from retention_census import Census, Completed, Sweep, Target  # noqa: E402

from hal.output import write_line  # noqa: E402

HOLD_SECONDS = 45  # B4's hold: below the service's 120 s idle timeout, over a scan of the route
SCAN_DEADLINE_SECONDS = 60
UPSTREAM_ERROR = 400
SETTINGS_SECTIONS = {
    "litellm_settings": {
        "turn_off_message_logging": True,
        "redact_messages_in_exceptions": True,
    },
    "general_settings": {"custom_auth": "auth.user_api_key_auth"},
    "router_settings": {"num_retries": 0},
}
STORE_NAMES = re.compile(
    r"DATABASE|REDIS|CALLBACK|LANGFUSE|VERBOSE|SPEND|S3_|LITELLM_PRINT_STANDARD_LOGGING_PAYLOAD",
    re.I,
)
PYTHON_CONTAINERS = frozenset({LITELLM, SERVICE})


def run_docker(command: Sequence[str], stdin: bytes | None = None) -> Completed:
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        list(command), input=stdin, capture_output=True, timeout=300, check=False
    )
    return Completed(result.returncode, result.stdout, result.stderr)


def canary(label: str) -> str:
    return f"{label}-{secrets.token_hex(10)}"


def settings_of(text: str, section: str) -> object:
    """The whole top-level `section` of a YAML file, so a nested list or block compares as one."""
    return yaml.safe_load(text).get(section)


class RetentionProbe(FailureProbe):
    """litellm.py's stack with the census run over the route's containers, at the log level
    compose.yaml ships."""

    LITELLM_LOG_LEVEL = None

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.census = Census(run_docker, secrets.token_bytes(16))
        self.clean: dict[str, str] = {}
        self.controls = self.write_controls(scratch)

    def write_controls(self, scratch: Path) -> Path:
        """The overlay of B3a and B3b alone: LiteLLM's debug log and the front's access log."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        shipped = mounted_file(resolved[FRONT], FRONT_STATIC).read_text(encoding="utf-8")
        static = scratch / "front-with-access-log.yml"
        static.write_text(shipped + "\naccessLog: {}\n", encoding="utf-8")
        static.chmod(0o644)
        overlay = scratch / "compose.controls.yaml"
        overlay.write_text(
            json.dumps({
                "services": {
                    LITELLM: {"environment": {"LITELLM_LOG": "DEBUG"}},
                    FRONT: {"volumes": [{
                        "type": "bind", "source": str(static), "target": FRONT_STATIC,
                        "read_only": True,
                    }]},
                },
            }),
            encoding="utf-8",
        )  # fmt: skip
        return overlay

    # --- the census ---------------------------------------------------------------------------

    def targets(self) -> list[Target]:
        return [
            Target(self.container_name(service), service in PYTHON_CONTAINERS)
            for service in (FRONT, GATEWAY, LITELLM, SERVICE)
        ]

    def sweep(self, tokens: Mapping[str, str]) -> Sweep:
        """C: the census over the four containers for the canaries `tokens` (label -> value)."""
        result = self.census.sweep(self.targets(), tokens)
        expect(not result.problems, f"C: sinks not examined: {list(result.problems)}")
        return result

    def expect_nothing_retained(self, cell: str, tokens: Mapping[str, str]) -> None:
        found = self.sweep(tokens).found
        expect(not found, f"{cell}: canaries retained: {found}{self.excerpts(tokens, found)}")
        self.clean.update({f"{cell} {label}": value for label, value in tokens.items()})

    def excerpts(self, tokens: Mapping[str, str], found: Mapping[str, tuple[str, ...]]) -> str:
        """The first 200 characters of each log line that holds a canary found in a log, the
        canary shown as its label: what a reviewer needs to see where the content was written."""
        shown = []
        for label, sinks in found.items():
            for sink in (s for s in sinks if s.endswith(" log")):
                log = self.run(["docker", "logs", sink.removesuffix(" log")], check=False)
                lines = (log.stdout + log.stderr).splitlines()
                shown += [
                    f"[{label}] {line.replace(tokens[label], '<canary>')[:200]}"
                    for line in lines if tokens[label] in line
                ]  # fmt: skip
        return "".join(f"\n  {line}" for line in shown)

    def failed_with(self, cell: str, app: str, options: tuple[str, ...]) -> dict[str, str]:
        run = self.canary(app, options)
        expect(run.get("route") == "api" and run["exit"] != "0", f"{cell}: {run}")
        return run

    def request_canary_hits(self, since: int) -> int:
        return sum(request["request_canary_hits"] for request in self.provider_requests()[since:])

    def wait_until(self, service: str, line: str, seconds: int = 60) -> None:
        """LiteLLM at CRITICAL prints no start line, so its listening socket is the signal."""
        if service != LITELLM:
            super().wait_until(service, line, seconds)
            return
        deadline = time.monotonic() + seconds
        while True:
            try:
                if listeners_of(self, LITELLM)["tcp"]:
                    return
            except ProbeFailed:
                pass  # the container is not up yet
            expect(time.monotonic() < deadline, f"LiteLLM did not listen in {seconds} seconds")
            time.sleep(1)

    # --- life cycle ---------------------------------------------------------------------------

    def recreate_route(self) -> None:
        """Every container of the route recreated, so that no tmpfs and no log of an earlier cell
        remains."""
        for service in (GATEWAY, LITELLM, FRONT, SERVICE):
            self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
        self.wait_until(LITELLM, LISTENING)
        self.wait_until(SERVICE, LISTENING)
        self.wait_until_the_gateway_answers()
        self.wait_for_front()

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        """The controls first, then a recreated route for the clean cells, in the order of the
        matrix."""
        for service in (SERVICE, LITELLM):
            self.wait_until(service, LISTENING)
        self.steer()
        failed = []
        for step in (
            self.cell_b2, self.cells_b3, self.recreate_route, self.cell_b1, self.cell_b4,
            self.cell_b5, self.cell_b6, self.cell_b7, self.cell_b8, self.cell_b9, self.cell_b10,
            self.cell_b11,
        ):  # fmt: skip
            try:
                step()
            except ProbeFailed as problem:
                failed.append(step.__name__)
                write_line(f"{step.__name__} FAILED: {problem}", flush=True)
        expect(not failed, f"cells failed: {', '.join(failed)}")

    def cell_b2(self) -> None:
        tokens = {"file in litellm": canary("b2-litellm"), "file in front": canary("b2-front")}
        litellm, front = self.container_name(LITELLM), self.container_name(FRONT)
        self.run([
            "docker", "exec", litellm, "python", "-c",
            f"open('/tmp/planted', 'w').write({tokens['file in litellm']!r})",
        ])  # fmt: skip
        self.run([
            "docker", "exec", front, "sh", "-c",
            f"echo {tokens['file in front']} > /dev/shm/planted",
        ])  # fmt: skip
        found = self.sweep(tokens).found
        expect(set(found) == set(tokens), f"B2: found {found}")
        expect(f"{litellm} /tmp" in found["file in litellm"], f"B2: litellm {found}")
        expect(f"{front} /dev/shm" in found["file in front"], f"B2: front {found}")
        self.hold("B2", "a canary planted by exec in LiteLLM's /tmp and in the front's /dev/shm "
                  "is found, each by the search of its own kind of container")  # fmt: skip

    def cells_b3(self) -> None:
        self.overlays.append(self.controls)
        for service in (LITELLM, FRONT):
            self.compose("up", "--detach", "--wait", "--force-recreate", "--no-deps", service)
        self.wait_until(LITELLM, LISTENING)
        self.wait_for_front()
        litellm_canary, front_canary = canary("b3a-request"), canary("b3b-path")
        run = self.canary(DEFAULT_APP, ("--request-marker", litellm_canary))
        expect(run["exit"] == "0", f"B3a: {run}")
        status = self.http("GET", f"/{front_canary}")
        expect(status == 404, f"B3b: the front answered {status}")
        found = self.sweep({"request in LiteLLM debug log": litellm_canary,
                            "path in front access log": front_canary}).found  # fmt: skip
        expect(
            f"{self.container_name(LITELLM)} log" in found.get("request in LiteLLM debug log", ()),
            f"B3a: found {found}",
        )
        self.hold("B3a", "with LITELLM_LOG=DEBUG the request canary is found in LiteLLM's log")
        expect(
            f"{self.container_name(FRONT)} log" in found.get("path in front access log", ()),
            f"B3b: found {found}",
        )
        self.hold("B3b", "with the access log on, a canary in the path is found in the front's log")
        self.overlays.remove(self.controls)

    def cell_b1(self) -> None:
        result = self.sweep({"probe": canary("b1")})
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        lines = []
        for service in (FRONT, GATEWAY, LITELLM, SERVICE):
            inspected = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[
                0
            ]
            wanted = self.declared_writable(resolved[service])
            seen = {mount["Destination"] for mount in inspected["Mounts"] if mount["RW"]} | set(
                inspected["HostConfig"].get("Tmpfs") or {}
            )
            expect(
                wanted == seen, f"B1: {service} declares {sorted(wanted)}, inspect {sorted(seen)}"
            )
            lines.append(f"{service}: {', '.join(result.inventory[self.container_name(service)])}")
        self.hold("B1", "; ".join(lines))

    @staticmethod
    def declared_writable(service: dict) -> set[str]:
        """The destinations the resolved Compose service declares writable: read-write binds and
        tmpfs."""
        binds = {
            volume["target"]
            for volume in service.get("volumes", [])
            if volume["type"] in {"bind", "volume"} and not volume.get("read_only")
        }
        tmpfs = {entry.split(":")[0] for entry in service.get("tmpfs", [])}
        return (
            binds
            | tmpfs
            | {
                volume["target"]
                for volume in service.get("volumes", [])
                if volume["type"] == "tmpfs"
            }
        )

    def cell_b4(self) -> None:
        request, answer = canary("b4-request"), canary("b4-answer")
        tokens = {"request": request, "answer": answer}
        self.steer(mode="hold", hold_seconds=HOLD_SECONDS, marker=answer, request_canary=request)
        before, already = len(self.provider_requests()), len(self.hold_ends())
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself
            self.canary_command(("--request-marker", request, "--marker", answer)),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=self.environment, cwd=REPO,
        )  # fmt: skip
        process.stdin.write(self.canary_input(DEFAULT_APP))
        process.stdin.close()
        deadline = time.monotonic() + SCAN_DEADLINE_SECONDS
        while len(self.provider_requests()) == before:
            expect(time.monotonic() < deadline, "B4: the run never reached the provider")
            time.sleep(1)
        during = self.sweep(tokens).found
        expect(len(self.hold_ends()) == already, "B4: the hold ended before the scan did")
        out, _ = process.communicate(timeout=CANARY_SECONDS)
        run = self.verdicts(out, process.returncode)
        expect(run["exit"] == "0" and run.get("marker") == "yes", f"B4: {run}")
        expect(self.request_canary_hits(before) >= 1, "B4: the request canary never reached F")
        self.steer()
        after = self.sweep(tokens).found
        expect(not during and not after, f"B4: retained during {during}, after {after}")
        self.clean.update({f"B4 {label}": value for label, value in tokens.items()})
        self.hold("B4", "both canaries in no file and no log while F held the request and after; "
                  "the answer canary reached the client and the request canary F")  # fmt: skip

    def cell_b5(self) -> None:
        request = canary("b5-request")
        self.steer(mode="status", status=500, request_canary=request)
        before = len(self.provider_requests())
        run = self.failed_with("B5", DEFAULT_APP, ("--request-marker", request))
        expect(run.get("code") == "provider_unavailable", f"B5: {run}")
        expect(self.request_canary_hits(before) == 1, "B5: the request canary never reached F")
        self.expect_nothing_retained("B5", {"request": request})
        self.hold(
            "B5", "upstream 500: provider_unavailable, the canary reached F, retained nowhere"
        )

    def cell_b6(self) -> None:
        request = canary("b6-request")
        self.steer(mode="echo", status=UPSTREAM_ERROR, request_canary=request)
        before = len(self.provider_requests())
        run = self.failed_with("B6", DEFAULT_APP, ("--request-marker", request))
        expect(self.request_canary_hits(before) == 1, "B6: the request canary never reached F")
        self.expect_nothing_retained("B6", {"request": request})
        self.hold("B6", f"an upstream {UPSTREAM_ERROR} whose body echoes the request canary: "
                  f"code {run.get('code')}, retained nowhere")  # fmt: skip

    def cell_b7(self) -> None:
        request = canary("b7-request")
        self.steer(request_canary=request)
        before = len(self.provider_requests())
        self.failed_with("B7", REMAPPED_APP, ("--request-marker", request))
        expect(len(self.provider_requests()) == before, "B7: the provider was reached")
        self.expect_nothing_retained("B7", {"request": request})
        self.hold("B7", "a model LiteLLM lacks: refused, F 0, the canary retained nowhere")

    def cell_b8(self) -> None:
        request = canary("b8-request")
        self.steer(mode="hold", request_canary=request)
        before, already = len(self.provider_requests()), len(self.hold_ends())
        run = self.canary(DEFAULT_APP, ("--cancel", "--request-marker", request))
        expect(run.get("status") == "cancelled", f"B8: {run}")
        ended = self.wait_for_hold_end("B8", already)
        self.steer()
        expect(self.request_canary_hits(before) == 1, "B8: the request canary never reached F")
        self.expect_nothing_retained("B8", {"request": request})
        self.hold("B8", f"cancelled: the canary reached F once, its request ended {ended}, "
                  "retained nowhere")  # fmt: skip

    def cell_b9(self) -> None:
        body = canary("b9-body")
        before = len(self.provider_requests())
        status = self.http("POST", ROUTE, self.credential, {**self.good_body(), "api_base": body})
        expect(status == 401, f"B9: the hook answered {status}")
        expect(len(self.provider_requests()) == before, "B9: the provider was reached")
        self.expect_nothing_retained("B9", {"body": body})
        self.hold(
            "B9", "the hook refuses (401) a body key holding the canary: F 0, retained nowhere"
        )

    def cell_b10(self) -> None:
        """Every sink of the route over B4 to B9."""
        found = self.sweep(self.clean).found
        expect(not found, f"B10: retained in {found}")
        self.hold("B10", f"the mounts and logs of the front, the gateway, LiteLLM and the service "
                  f"hold none of {len(self.clean)} canaries of B4 to B9")  # fmt: skip

    def cell_b11(self) -> None:
        litellm, front = self.container_name(LITELLM), self.container_name(FRONT)
        config = self.run(["docker", "exec", litellm, "cat", "/etc/litellm/config.yaml"]).stdout
        for section, wanted in SETTINGS_SECTIONS.items():
            found = settings_of(config, section)
            expect(found == wanted, f"B11: {section} holds {found}, not {wanted}")
        top = set(yaml.safe_load(config))
        expect(top == {"model_list", *SETTINGS_SECTIONS}, f"B11: LiteLLM's sections {sorted(top)}")
        names = self.run(["docker", "exec", litellm, "env"]).stdout
        stores = sorted({n.split("=")[0] for n in names.splitlines() if STORE_NAMES.search(n)})
        expect(not stores, f"B11: LiteLLM's environment names {stores}")
        level = [n for n in names.splitlines() if n.startswith("LITELLM_LOG=")]
        expect(level == ["LITELLM_LOG=CRITICAL"], f"B11: LiteLLM's log level {level}")
        static = self.run(["docker", "exec", front, "cat", FRONT_STATIC]).stdout
        expect("accessLog" not in static and "level: INFO" in static, "B11: the front's log")
        self.hold("B11", "LiteLLM: message logging off, redaction on, custom_auth only, retries 0, "
                  "no callback, cache, database or spend setting, no such environment name, "
                  "log level CRITICAL; the front: INFO and no access log")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], RetentionProbe)


if __name__ == "__main__":
    sys.exit(main())
