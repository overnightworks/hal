"""Songmaker's MCP origin through traefik-mcp: the cells P14-P27 of #346, driven against a
stand-in for songmaker's web service (compose.probe.yaml) on `hal_mcp_songmaker`'s copy in the
probe's project. A mixin of the step-ca probe (probe.py): it uses the probe's compose, client and
container helpers."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

from edge_copy import DISCARD_OUTPUT, expect
from step_ca_names import (
    BACKEND_URL,
    CA_HEALTH_URL,
    CERTIFICATE_UNVERIFIED,
    CONTAINER_USER,
    COULD_NOT_RESOLVE,
    ORIGIN,
    ORIGIN_ANSWER,
    ORIGIN_URL,
    PROJECT,
    READY_SECONDS,
    ROOT_CERTIFICATE,
    ROOT_IN_CLIENT,
    SONGMAKER_NETWORK,
    SONGMAKER_ORIGIN,
    SONGMAKER_URL,
    STAND_IN,
    STAND_IN_URL,
)

from hal.output import write_line

INCOMPLETE_EXIT_CODE = 2  # a cell was not driven: neither a pass nor a failure


def print_verdict(not_driven: list[str]) -> int:
    """PROBE PASSED only when every cell was driven; a cell that could not run is not held."""
    if not_driven:
        write_line(f"PROBE INCOMPLETE: not driven: {'; '.join(not_driven)}")
        return INCOMPLETE_EXIT_CODE
    write_line("PROBE PASSED: proofs 1-14, #95 P3 and #346 P14-P27 hold")
    return 0


class McpNetworks:
    def client_beside(self, container: str, *curl_arguments: str):
        """curl in the network namespace of `container`: what that container itself can reach."""
        return self.curl(f"container:{container}", curl_arguments, None)

    def curl(self, network: str, curl_arguments: tuple[str, ...], root: Path | None):
        image, _ = self.image_and_volume()
        trust = ["--volume", f"{root}:{ROOT_IN_CLIENT}:ro"] if root else []
        cacert = ["--cacert", ROOT_IN_CLIENT] if root else []
        return self.run(
            ["docker", "run", "--rm", "--network", network, "--read-only",
             "--user", CONTAINER_USER, *trust, "--entrypoint", "curl", image,
             "--silent", "--max-time", "5", *cacert, *curl_arguments],
            check=False,
        )  # fmt: skip

    def proof_7_network_split(self) -> None:
        reachable = {
            ("mcp-backends", BACKEND_URL): True,
            ("mcp-backends", CA_HEALTH_URL): False,
            ("mcp-backends", ORIGIN_URL): False,
            ("mcp", BACKEND_URL): False,
            ("mcp", CA_HEALTH_URL): False,
            ("mcp-ca", BACKEND_URL): False,
        }
        for (network, url), expected in reachable.items():
            result = self.client(network, "--insecure", "--output", DISCARD_OUTPUT, url)
            outcome = "answered" if result.returncode == 0 else f"curl exit {result.returncode}"
            wanted = 0 if expected else COULD_NOT_RESOLVE
            expect(result.returncode == wanted, f"{network} -> {url}: {outcome}")
        write_line(
            f"proof 7 held: {len(reachable)} network pairs as ruled; only the control answers"
        )

    def stand_in_requests(self) -> int:
        """How many requests the stand-in has logged so far; whoami logs one line per request."""
        logs = self.compose("logs", "--no-color", STAND_IN).stdout.decode(errors="replace")
        return sum(1 for line in logs.splitlines() if ' HTTP/1.1"' in line)

    def container_on(self, service: str, network: str) -> tuple[str, str]:
        """The container id and the address of `service` on one of the project's networks."""
        container = self.container_id(service)
        address_of = f'{{{{(index .NetworkSettings.Networks "{PROJECT}_{network}").IPAddress}}}}'
        address = self.run(["docker", "inspect", "--format", address_of, container])
        address = address.stdout.decode().strip()
        expect(bool(address), f"{service} has no address on {network}")
        return container, address

    def wait_until_songmaker_served(self) -> None:
        root = self.secrets_dir / ROOT_CERTIFICATE

        def answers() -> bool:
            result = self.client("mcp", SONGMAKER_URL, root=root)
            return f"Host: {SONGMAKER_ORIGIN}" in result.stdout.decode(errors="replace")

        self.poll_until(f"{SONGMAKER_URL} answering with the stand-in", READY_SECONDS, answers)

    def expect_no_stand_in_request(self, cell: str, requests_before: int, what: str) -> None:
        requests = self.stand_in_requests()
        expect(requests == requests_before, f"{cell}: {what} reached the stand-in")

    def expect_unreachable(self, cell: str, result: subprocess.CompletedProcess, what: str) -> None:
        expect(result.returncode != 0, f"{cell}: {what} answered")

    def wrong_root(self) -> Path:
        wrong = self.scratch / "wrong_ca.crt"
        self.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
             "-nodes", "-keyout", str(self.scratch / "wrong_ca.key"), "-out", str(wrong),
             "-subj", "/CN=probe wrong root", "-days", "1"]
        )  # fmt: skip
        return wrong

    def cell_p14_p15_p17_refused(self, root: Path) -> list[str]:
        before = self.stand_in_requests()
        unverified = self.client("mcp", SONGMAKER_URL)
        wrong = self.client("mcp", SONGMAKER_URL, root=self.wrong_root())
        for outcome, what in ((unverified, "no root"), (wrong, "a wrong root")):
            code = outcome.returncode
            expect(code == CERTIFICATE_UNVERIFIED, f"P14: {what}: curl exit {code}")
        self.expect_no_stand_in_request("P14", before, "an untrusted client")

        plain_url = f"http://{SONGMAKER_ORIGIN}:443/mcp"  # NOSONAR(S5332) P15 sends plain HTTP
        no_port_url = f"http://{SONGMAKER_ORIGIN}/mcp"  # NOSONAR(S5332) P15 sends plain HTTP
        plain = self.client("mcp", "--include", plain_url, root=root)
        no_port = self.client("mcp", no_port_url, root=root)
        expect(
            f"Host: {SONGMAKER_ORIGIN}" not in plain.stdout.decode(errors="replace"),
            "P15: plain http answered",
        )
        self.expect_unreachable("P15", no_port, "port 80")
        self.expect_no_stand_in_request("P15", before, "plain http")

        for path in ("/", "/api"):
            answer = self.client("mcp", "--output", DISCARD_OUTPUT, "--write-out", "%{http_code}",
                                 f"https://{SONGMAKER_ORIGIN}{path}", root=root)  # fmt: skip
            expect(answer.stdout.decode() == "404", f"P17: {path} answered {answer.stdout!r}")
        self.expect_no_stand_in_request("P17", before, "an unrelated path")
        return [
            f"route P14 held: no root and a wrong root: curl exit {unverified.returncode} and "
            f"{wrong.returncode}, no stand-in request",
            f"route P15 held: plain http on 443 exit {plain.returncode}, on 80 exit "
            f"{no_port.returncode}, no stand-in request",
            "route P17 held: / and /api answered 404, no stand-in request",
        ]

    def cell_p16_p18_paths(self, root: Path) -> list[str]:
        base = f"https://{SONGMAKER_ORIGIN}"
        before = self.stand_in_requests()
        for path in ("/mcp/", "/mcpx"):
            answer = self.client("mcp", "--path-as-is", "--output", DISCARD_OUTPUT, "--write-out",
                                 "%{http_code}", f"{base}{path}", root=root)  # fmt: skip
            expect(answer.stdout.decode() == "404", f"P16: {path} answered {answer.stdout!r}")
        self.expect_no_stand_in_request("P16", before, "/mcp/ or /mcpx")
        doubled = self.client("mcp", "--path-as-is", "--include", f"{base}//mcp", root=root)
        reached = self.stand_in_requests() > before
        status = doubled.stdout.decode(errors="replace").splitlines()[:1]
        query = self.client("mcp", f"{base}/mcp?x=1", root=root).stdout.decode(errors="replace")
        expect("GET /mcp?x=1 HTTP/1.1" in query, f"P18: the query was not kept: {query[-200:]}")
        return [
            "route P16 held: /mcp/ and /mcpx answered 404, no stand-in request",
            f"route P16 observed: //mcp -> {status}, reached the stand-in: {reached}",
            "route P18 held: /mcp?x=1 reached the stand-in as GET /mcp?x=1",
        ]

    def cell_p19_other_origin(self, root: Path) -> str:
        before = self.stand_in_requests()
        answer = self.client("mcp", f"https://{ORIGIN}/mcp", root=root).stdout.decode(
            errors="replace"
        )
        expect(
            ORIGIN_ANSWER in answer, f"P19: hello did not answer for its own name: {answer[-120:]}"
        )
        self.expect_no_stand_in_request("P19", before, f"SNI and Host {ORIGIN}")
        return f"route P19 held: {ORIGIN}/mcp answered by hello-mcp, no stand-in request"

    def cell_p20_stand_in_stopped(self, root: Path) -> str:
        self.compose("stop", STAND_IN)
        try:
            answer = self.client(
                "mcp", "--output", "-", "--write-out", "|%{http_code}|%{redirect_url}|",
                SONGMAKER_URL, root=root,
            )  # fmt: skip
        finally:
            self.compose("start", STAND_IN)
        text = answer.stdout.decode(errors="replace")
        expect("|502||" in text, f"P20: the stopped stand-in gave {text[-120:]}")
        expect("Hostname:" not in text, "P20: another origin answered")
        self.wait_until_songmaker_served()
        return (
            "route P20 held: stand-in stopped -> 502, no redirect, no other origin; answers again"
        )

    def cell_p21_gateway_to_stand_in(self) -> str:
        members = json.loads(
            self.run(["docker", "network", "inspect", f"{PROJECT}_{SONGMAKER_NETWORK}"]).stdout
        )[0]["Containers"]
        names = sorted(member["Name"] for member in members.values())
        expect(
            names == [f"{PROJECT}-{service}-1" for service in (STAND_IN, "traefik-mcp")],
            f"P21: the members of the stand-in network are {names}",
        )
        ca = self.directory_status(self.secrets_dir / ROOT_CERTIFICATE)
        expect(ca == 200, f"P21: the CA answered {ca}")
        hello = self.client("mcp", ORIGIN_URL, root=self.secrets_dir / ROOT_CERTIFICATE)
        expect(ORIGIN_ANSWER in hello.stdout.decode(errors="replace"), "P21: hello did not answer")
        return f"route P21 held: members {names}; CA directory 200 and hello answer as controls"

    def cell_p22_mcp_client_isolated(self) -> str:
        _, stand_in_address = self.container_on(STAND_IN, SONGMAKER_NETWORK)
        _, ca_address = self.container_on("step-ca", "mcp-ca")
        before = self.stand_in_requests()
        targets = {
            "the stand-in by name": STAND_IN_URL,
            "the stand-in by address": f"http://{stand_in_address}:8080/",  # NOSONAR(S5332)
            "the CA by name": CA_HEALTH_URL,
            "the CA by address": f"https://{ca_address}:9000/health",
        }
        for what, url in targets.items():
            self.expect_unreachable(
                "P22", self.client("mcp", "--insecure", "--output", DISCARD_OUTPUT, url), what
            )
        self.expect_no_stand_in_request("P22", before, "a client on mcp")
        return f"route P22 held: a client on mcp reaches none of {len(targets)} targets"

    def origin_resolves(self, network: str, origin: str) -> bool:
        answer = self.client(
            network, "--insecure", "--output", DISCARD_OUTPUT, f"https://{origin}/"
        )
        return answer.returncode != COULD_NOT_RESOLVE

    def cell_p23_p24_stand_in_alone(self) -> list[str]:
        stand_in, stand_in_address = self.container_on(STAND_IN, SONGMAKER_NETWORK)
        _, hello_address = self.container_on("hello-mcp", "mcp-backends")
        _, ca_address = self.container_on("step-ca", "mcp-ca")
        from_stand_in = {
            "hello-mcp by name": BACKEND_URL,
            "hello-mcp by address": f"http://{hello_address}/",  # NOSONAR(S5332)
            "the CA by name": CA_HEALTH_URL,
            "the CA by address": f"https://{ca_address}:9000/health",
            "the CA's origin names": f"https://{ORIGIN}/",
            "songmaker's origin name": SONGMAKER_URL,
        }
        for what, url in from_stand_in.items():
            answer = self.client_beside(stand_in, "--insecure", "--output", DISCARD_OUTPUT, url)
            self.expect_unreachable("P23/P24", answer, f"{what} from the stand-in")
        for what, url in {
            "the stand-in by name": STAND_IN_URL,
            "the stand-in by address": f"http://{stand_in_address}:8080/",  # NOSONAR(S5332)
        }.items():
            answer = self.client(
                "mcp-backends", "--insecure", "--output", DISCARD_OUTPUT, url
            )  # fmt: skip
            self.expect_unreachable("P23", answer, f"{what} from mcp-backends")
        resolving = {
            (network, origin): self.origin_resolves(network, origin)
            for network in ("mcp", "mcp-ca", "mcp-backends", SONGMAKER_NETWORK)
            for origin in (ORIGIN, SONGMAKER_ORIGIN)
        }
        resolved_on = {network for (network, _), found in resolving.items() if found}
        expect(
            resolved_on == {"mcp", "mcp-ca"} and all(
                found for (network, _), found in resolving.items() if network in resolved_on
            ),
            f"P24: the origin names resolve on {sorted(resolved_on)}: {resolving}",
        )  # fmt: skip
        return [
            f"route P23 held: no path between the stand-in network and mcp-backends, by name "
            f"and address, both ways ({len(from_stand_in) + 2} attempts)",
            "route P24 held: the stand-in reaches no CA; the origin names resolve on mcp and "
            "mcp-ca alone",
        ]

    def cell_p25_network_shape(self) -> str:
        network = json.loads(
            self.run(["docker", "network", "inspect", f"{PROJECT}_{SONGMAKER_NETWORK}"]).stdout
        )[0]
        gateways = [config.get("Gateway") for config in network["IPAM"]["Config"]]
        mode = network["Options"].get("com.docker.network.bridge.gateway_mode_ipv4")
        expect(network["Internal"] is True, "P25: the network is not internal")
        expect(mode == "isolated" and not any(gateways), f"P25: mode {mode}, gateways {gateways}")
        for service in ("traefik-mcp", STAND_IN):
            inspected = self.run(
                ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}",
                 self.container_id(service)]
            )  # fmt: skip
            ports = json.loads(inspected.stdout)
            expect(not any(ports.values()), f"P25: {service} publishes {ports}")
        return "route P25 held: internal, isolated, no gateway address, no published port"

    def proof_14_songmaker_route(self) -> None:
        """The cells run against a stand-in for songmaker's MCP server on the new network."""
        root = self.secrets_dir / ROOT_CERTIFICATE
        self.compose("up", "--detach", "--no-deps", STAND_IN)
        self.wait_until_songmaker_served()
        lines = self.cell_p14_p15_p17_refused(root)
        lines += self.cell_p16_p18_paths(root)
        lines.extend(
            [
                self.cell_p19_other_origin(root),
                self.cell_p20_stand_in_stopped(root),
                self.cell_p21_gateway_to_stand_in(),
                self.cell_p22_mcp_client_isolated(),
            ]
        )
        lines += self.cell_p23_p24_stand_in_alone()
        lines.append(self.cell_p25_network_shape())
        self.proof_7_network_split()  # P27: hello's route and the existing pairs still hold
        lines.append("route P27 held: hello's route and proof 7's pairs hold with the new network")
        write_line("\n".join(lines))
