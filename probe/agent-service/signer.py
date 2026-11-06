"""The signer cells (`unit.py --cell signer`, #346 P12, P12b, P28 and P26): the real service, with
the scratch signing key, the scratch CA and songmaker's MCP origin from `service.toml`, asked by
the repository's own `agent-smoke --tool` for one tool, in the stand-in issuer's project.

The front is a Traefik on `mcp` under the origin's name, its certificate issued by the scratch CA
(scratch_secrets.py), routing `/mcp` to `songmaker-web` on the project's songmaker MCP network.
Behind it stands `mcp_signer.py` (agent-service/), which judges the capability against the
scratch `public.pem`, or nothing, so that the front answers 502. A cell reads verdicts, counts
and event names, never a token or a capability."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from egress import LABEL, NotDriven, ProbeFailed, expect
from issuer import ISSUER_SERVICE, SERVICE, IssuerProbe
from litellm_ca import issue_certificate
from live_signer import PROOF_TOOL, STANDIN_ALIAS, failed_without_text, mcp_origin
from live_smoke import event_names, other_lines
from mcp_signer import LISTENING_LINE, PUBLIC_KEY_MOUNT, SCRIPT_MOUNT, VERIFIED
from refusals import SMOKE_SERVICE
from service_log import LOGIN_REFUSED

FRONT_SERVICE = "agent-front"
SIGNER_SERVICE = "agent-signer"
FRONT_IMAGE_SERVICE = "agent-egress"  # a Traefik of compose.yaml's own pin
FRONT_DIRECTORY = "/front"
FRONT_ROUTER = "songmaker"
SMOKE_SECONDS = 240
WAIT_SECONDS = 60
RECREATES = 2
ANSWERED = "answered"
BAD_GATEWAY = 502


def static_configuration() -> dict:
    """The front's static and dynamic configuration are JSON, which Traefik reads as YAML."""
    return {
        "global": {"checkNewVersion": False, "sendAnonymousUsage": False},
        "log": {"level": "INFO"},
        "accessLog": {"format": "json"},
        "entryPoints": {"mcp": {"address": ":443"}},
        "providers": {"file": {"filename": f"{FRONT_DIRECTORY}/dynamic.yml"}},
    }


def dynamic_configuration(host: str) -> dict:
    return {
        "http": {
            "routers": {FRONT_ROUTER: {
                "rule": f"Host(`{host}`) && Path(`/mcp`)", "entryPoints": ["mcp"],
                "service": FRONT_ROUTER, "tls": {},
            }},
            "services": {FRONT_ROUTER: {"loadBalancer": {
                "servers": [{
                    "url": f"http://{STANDIN_ALIAS}:8080",  # NOSONAR(S5332) probe network
                }],
            }}},
        },
        "tls": {"certificates": [{
            "certFile": f"{FRONT_DIRECTORY}/tls/cert.pem",
            "keyFile": f"{FRONT_DIRECTORY}/tls/key.pem",
        }]},
    }  # fmt: skip


def access_records(log: str) -> list[dict]:
    """The front's access-log lines (JSON); its other log lines are text."""
    records = []
    for line in log.splitlines():
        if line.startswith("{"):
            record = json.loads(line)
            if "DownstreamStatus" in record:
                records.append(record)
    return records


@dataclass(frozen=True)
class Run:
    """What one run left behind: the signer's verdict, the smoke's events and text, the front's
    new access records and the new CLI starts (refused logins) in the service log."""

    verdict: str
    events: list[str]
    text: str
    front: list[dict]
    cli_starts: int


class SignerProbe(IssuerProbe):
    """The service with the scratch key and CA, and a TLS front for songmaker's origin."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.origin = mcp_origin(self.configuration)
        self.host = urlsplit(self.origin).hostname or ""
        front = scratch / "front"
        tls = front / "tls"
        front.mkdir()
        certificate, key = issue_certificate(self.scratch_secrets, self.host, tls)
        (front / "traefik.yml").write_text(json.dumps(static_configuration()), encoding="utf-8")
        (front / "dynamic.yml").write_text(
            json.dumps(dynamic_configuration(self.host)), encoding="utf-8"
        )
        for directory in (front, tls):
            directory.chmod(0o755)
        for name in (certificate, key, front / "traefik.yml", front / "dynamic.yml"):
            name.chmod(0o644)
        front_image = json.loads(self.compose("config", "--format", "json").stdout)["services"][
            FRONT_IMAGE_SERVICE
        ]["image"]
        script = Path(__file__).resolve().parents[2] / "agent-service" / "mcp_signer.py"
        hardened = {
            "profiles": ["agent-service"], "user": "65534:65534", "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "restart": "no",
        }  # fmt: skip
        overlay = scratch / "compose.signer.yaml"
        overlay.write_text(
            json.dumps({"services": {
                FRONT_SERVICE: {
                    **hardened, "image": front_image,
                    "command": ["--configFile", f"{FRONT_DIRECTORY}/traefik.yml"],
                    "sysctls": {"net.ipv4.ip_unprivileged_port_start": 0},
                    "networks": {"mcp": {"aliases": [self.host]}, "mcp-songmaker": {}},
                    "volumes": [{"type": "bind", "source": str(front), "target": FRONT_DIRECTORY,
                                 "read_only": True}],
                },
                SIGNER_SERVICE: {
                    **hardened, "image": self.image,
                    "networks": {"mcp-songmaker": {"aliases": [STANDIN_ALIAS]}},
                    "entrypoint": ["python", "-I", "-B", SCRIPT_MOUNT, self.origin, PROOF_TOOL],
                    "volumes": [
                        {"type": "bind", "source": str(script), "target": SCRIPT_MOUNT,
                         "read_only": True},
                        {"type": "bind", "source": str(self.scratch_secrets.signing_public),
                         "target": PUBLIC_KEY_MOUNT, "read_only": True},
                    ],
                },
            }}),
            encoding="utf-8",
        )  # fmt: skip
        self.overlays.append(overlay)

    def services_to_start(self) -> tuple[str, ...]:
        return ("agent-egress", ISSUER_SERVICE, FRONT_SERVICE, SERVICE)

    def drive(self) -> None:
        self.wait_until_listening()
        self.cell_p12()
        self.cell_p12b()
        self.cell_p28()
        self.hold("P26", "every compose call resolved only this project's networks")

    # --- the cells ----------------------------------------------------------------------------

    def cell_p12(self) -> None:
        run = self.capability_run(with_signer=True)
        expect(run.verdict == VERIFIED, f"P12: mcp_signer.py {run.verdict}")
        expect(failed_without_text(run.events, run.text), f"P12: the run went {run.events}")
        self.expect_front_reached(run.front, "P12")
        expect(run.cli_starts == 0, f"P12: {run.cli_starts} CLI starts")
        self.hold("P12", f"verified; the run failed without text after {len(run.front)} requests")

    def cell_p12b(self) -> None:
        run = self.capability_run(with_signer=False)
        statuses = {record["DownstreamStatus"] for record in run.front}
        expect(statuses == {BAD_GATEWAY}, f"P12b: the front answered {sorted(statuses)}")
        expect(failed_without_text(run.events, run.text), f"P12b: the run went {run.events}")
        self.expect_front_reached(run.front, "P12b")
        expect(run.cli_starts == 0, f"P12b: {run.cli_starts} CLI starts")
        self.hold("P12b", f"the front answered 502 to {len(run.front)} requests; no CLI start")

    def cell_p28(self) -> None:
        for number in range(1, RECREATES + 1):
            self.compose(
                "up", "--detach", "--wait", "--force-recreate", "--no-deps", SERVICE, timeout=600
            )
            self.wait_until_listening()
            run = self.capability_run(with_signer=True)
            expect(run.verdict == VERIFIED, f"P28: after recreate {number}: {run.verdict}")
        self.hold("P28", f"verified again after each of {RECREATES} recreates of the service")

    def expect_front_reached(self, records: list[dict], cell: str) -> None:
        expect(bool(records), f"{cell}: the front saw no request")
        hosts = {record["RequestHost"] for record in records}
        expect(hosts == {self.host}, f"{cell}: the front saw {len(hosts)} hosts, not only one")

    # --- one run and what it leaves -----------------------------------------------------------

    def capability_run(self, *, with_signer: bool) -> Run:
        """One `agent-smoke --tool` run, with the signer behind the front or with none."""
        self.compose("rm", "--stop", "--force", SIGNER_SERVICE)
        if with_signer:
            self.compose("up", "--detach", "--no-deps", SIGNER_SERVICE)
            self.wait_for_line(lambda log: LISTENING_LINE in log.split())
        front_before = len(access_records(self.container_log(FRONT_SERVICE)))
        refused_before = self.container_log(SERVICE).count(LOGIN_REFUSED)
        tokens = self.tokens()
        smoke = self.run(
            self.compose_command(
                "run", "--rm", "-T", "--no-deps", "--label", LABEL, SMOKE_SERVICE,
                "--timeout", "180", "--tool", f"{PROOF_TOOL}:read_only",
            ),
            stdin=f"{tokens.person}\n{tokens.workload}\n", check=False, timeout=SMOKE_SECONDS,
        )  # fmt: skip
        shown = smoke.stdout + smoke.stderr
        expect(tokens.person not in shown and tokens.workload not in shown, "a token was printed")
        verdict = ANSWERED
        if with_signer:
            verdict = self.signer_verdict()
        return Run(
            verdict=verdict,
            events=event_names(smoke.stdout),
            text=other_lines(smoke.stdout),
            front=access_records(self.container_log(FRONT_SERVICE))[front_before:],
            cli_starts=self.container_log(SERVICE).count(LOGIN_REFUSED) - refused_before,
        )

    def signer_verdict(self) -> str:
        """`verified` or `refused: <reason>`, the one line the signer prints after its start."""
        verdicts: list[str] = []

        def printed(log: str) -> bool:
            verdicts[:] = [
                line for line in log.splitlines()
                if line == VERIFIED or line.startswith("refused: ")
            ]  # fmt: skip
            return bool(verdicts)

        self.wait_for_line(printed)
        return verdicts[0]

    def signer_log(self) -> str:
        """The signer's log, also once it has exited: it ends after its first verdict."""
        container = self.compose("ps", "--all", "-q", SIGNER_SERVICE).stdout.strip()
        expect(bool(container), f"{SIGNER_SERVICE} has no container")
        logs = self.run(["docker", "logs", container], check=False)
        if logs.returncode != 0:
            raise ProbeFailed(f"docker logs {container} exited {logs.returncode}")
        return logs.stdout + logs.stderr

    def wait_for_line(self, found: Callable[[str], bool]) -> None:
        deadline = time.monotonic() + WAIT_SECONDS
        while time.monotonic() < deadline:
            if found(self.signer_log()):
                return
            time.sleep(0.5)
        raise NotDriven(f"{SIGNER_SERVICE} printed nothing awaited in {WAIT_SECONDS} seconds")
