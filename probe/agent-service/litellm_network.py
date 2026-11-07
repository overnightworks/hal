"""Probe of the isolation between the API-route networks (#808 S1d cells X1, X6-X12, R3, S1, S2,
G20; D3, S1 and S2 with the database of #937; HAL-2.11's picture host in R3, X7 and X11):
LiteLLM, its front, its database and the gateway reach each other and the outside only along the
declared topology, each exclusion with the control that proves the same observer connects when a
path exists. It runs on the stack of litellm.py: the front, LiteLLM, its database and the gateway
against a fake Anthropic and a fake OpenAI. Nothing live and nothing paid: the probe refuses to
start unless the resolved copy marks `internet` internal and holds only the fake hosts.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_network.py --scratch DIR

Measured: a run takes about six minutes and its teardown a few seconds (K 30 s, CAP 1800 s).

"No connection" is an outcome of `tcp_connect` in `egress_observe.UNREACHABLE`; a timeout, a
refusal or any other error fails the cell. X8 reads the first TLS record the gateway sends back for
a real host no router names: an alert holds it, a ServerHello fails it, and the same reading for
the provider's name is its control. A cell "from a namespace" runs litellm_stack.py's client in a
throwaway that joins that container's namespace, so the front and the gateway (Traefik images
without Python) are observed like the rest.

S1 and S2 need LiteLLM's namespace before LiteLLM starts. This probe's overlay replaces LiteLLM's
entrypoint with a start gate that waits for a file in a bind-mounted scratch directory and then
runs the shipped entrypoint with the shipped arguments; the windows open first, then the file is
dropped. The one name LiteLLM's start may ask the resolver for beside the control's, and the one
address it may open a connection to beside the gateway's entrypoint, is its database, read from
start.sh. S1 and S2 claim LiteLLM's behaviour from the moment `start.sh` runs, not Docker's own
start of the container. G20 is one gateway SYN window over the start and every driving cell, not
over the stack's start. A window that ends before the last cell it covers is NOT DRIVEN.

X13 to X16 are the refusals of no SNI, of plain bytes, and of a suffix and a prefix of the
provider's name.

Exit 0: every cell held, 1: a cell failed or was not driven.
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "agent-service"))

from egress_observe import UNREACHABLE  # noqa: E402
from litellm import (  # noqa: E402
    CA_IN_CLIENT,
    ENTRYPOINT_ADDRESS,
    FAKE_PICTURES,
    FAKE_PROVIDER,
    FRONT,
    GATEWAY,
    LITELLM,
    PICTURE_HOST,
    PROVIDER_HOST,
    START_DATABASE,
    TLS_PROGRAM,
    LitellmProbe,
    mounted_file,
)
from litellm_stack import GATEWAY_PORT, NotDriven, alerted, expect, run_scratch_probe  # noqa: E402

CAPTURE_LITELLM = "capture-litellm"
CAPTURE_TEMPLATE = "capture-egress"
GATE_DIRECTORY = "/gate"
GATE_FILE = "open"
GATE_PROGRAM = f'while [ ! -e {GATE_DIRECTORY}/{GATE_FILE} ]; do sleep 0.2; done; exec "$@"'
START_SECONDS = 120  # LiteLLM's start and the controls around it
SESSION_SECONDS = 300  # the gateway window over the start and every driving cell
WINDOW_MARGIN_SECONDS = 3
LOOPBACK = "lo"
PROVIDER_ON_INTERNET = "fake provider on internet"
PICTURES_ON_INTERNET = "fake OpenAI on internet"
REFUSED_HOST = "auth.hallucinai.de"  # a real host of ours that no router of the gateway names
NOT_FOUND = "HTTP/1.1 404 Not Found"  # Traefik's own answer to a request it has no router for
TLS_HANDSHAKE, TLS_ALERT, SERVER_HELLO = 22, 21, 2  # record content types, handshake type
FIRST_RECORD_PROGRAM = """\
import json, socket, ssl, sys
address, name, port = sys.argv[1:4]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
hello = ssl.MemoryBIO()
client = context.wrap_bio(ssl.MemoryBIO(), hello, server_hostname=name)
try:
    client.do_handshake()
except ssl.SSLWantReadError:
    pass
received = b""
with socket.create_connection((address, int(port)), timeout=8) as raw:
    raw.sendall(hello.read())
    while len(received) < 6 and (chunk := raw.recv(6 - len(received))):
        received += chunk
record = {"content_type": received[0], "first_byte": received[5]} if len(received) == 6 else {}
print(json.dumps({"bytes": len(received), **record}))
"""


@dataclass(frozen=True)
class Reach:
    """One TCP connect from the namespace of `source` and whether it must complete."""

    cell: str
    source: str
    target: str
    address: str
    port: int
    connects: bool


class NetworkProbe(LitellmProbe):
    """The stack of litellm.py with a start gate before LiteLLM and a window in its namespace."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.gate = scratch / "gate"
        self.gate.mkdir()
        self.gate.chmod(0o755)
        resolved = self.resolved()["services"]
        self.litellm_port = int(self.proxy_address.rsplit(":", 1)[1])
        start = mounted_file(resolved[LITELLM], resolved[LITELLM]["entrypoint"][0]).read_text()
        # Its database as start.sh's DATABASE_URL names it: the one other name and address
        # LiteLLM's start may ask for.
        database = START_DATABASE.search(start)
        self.database, self.database_port = database["service"], int(database["port"])
        self.overlays.append(self.write_network_overlay(scratch, resolved))
        self.expect_fake_only()

    def write_network_overlay(self, scratch: Path, resolved: dict) -> Path:
        """The start gate for LiteLLM and the window service in its namespace, derived from the
        shipped entrypoint and from `capture-egress`, so no pin of either is restated."""
        shipped = resolved[LITELLM]["entrypoint"]
        capture = {
            key: value
            for key, value in resolved[CAPTURE_TEMPLATE].items()
            if key not in ("depends_on", "network_mode", "networks")
        }
        overlay = scratch / "compose.network.yaml"
        overlay.write_text(
            json.dumps({"services": {
                LITELLM: {
                    "entrypoint": ["sh", "-c", GATE_PROGRAM, "gate", *shipped],
                    "volumes": [{"type": "bind", "source": str(self.gate),
                                 "target": GATE_DIRECTORY, "read_only": True}],
                },
                CAPTURE_LITELLM: {**capture, "network_mode": f"service:{LITELLM}"},
            }}),
            encoding="utf-8",
        )  # fmt: skip
        return overlay

    # --- what the topology declares -----------------------------------------------------------

    def resolved(self) -> dict:
        return json.loads(self.compose("config", "--format", "json").stdout)

    def address_of(self, service: str, network: str) -> str:
        """The address `service` holds on the network the compose file keys `network`."""
        name = self.resolved()["networks"][network]["name"]
        found = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[0]
        return found["NetworkSettings"]["Networks"][name]["IPAddress"]

    def entrypoint(self) -> str:
        """The gateway's one entrypoint: the address of the probe's copy of its static file."""
        declared = {
            found.rsplit(":", 1)[0]
            for found in ENTRYPOINT_ADDRESS.findall(self.static_file.read_text())
        }
        expect(len(declared) == 1, f"the gateway declares {declared}")
        return declared.pop()

    # --- one observer -------------------------------------------------------------------------

    def connect_result(self, source: str, address: str, port: int) -> str:
        container = self.container(source)
        return self.client_in_namespace_of(container, "connect", address, str(port))["result"]

    def reach(self, step: Reach, intervals: dict[str, tuple[float, float]]) -> None:
        """One connect, judged; its wall-clock interval goes into `intervals`."""
        started = time.time()
        result = self.connect_result(step.source, step.address, step.port)
        intervals[step.cell] = (started, time.time())
        where = f"{step.source} -> {step.target} {step.address}:{step.port}"
        wanted = ("connected",) if step.connects else UNREACHABLE
        expect(result in wanted, f"{step.cell}: {where}: {result}")
        self.hold(step.cell, f"{where}: {result}")

    def handshake(self, name: str) -> dict:
        """R3: LiteLLM's handshake on the gateway's entrypoint for `name`, verified against the
        scratch CA; it is also the control of `refused_without_a_dial`."""
        mount = ["-v", f"{self.scratch_ca.ca_certificate}:{CA_IN_CLIENT}:ro"]
        network = [f"--network=container:{self.container(LITELLM)}", *mount]
        seen = self.throwaway(network, [self.entrypoint(), name], TLS_PROGRAM)
        return {"handshake": True, **seen}

    def first_record(self, name: str) -> dict:
        """The first TLS record the gateway sends back on its entrypoint to LiteLLM's ClientHello
        for `name`, read on the raw socket: its content type and the first byte of its body."""
        network = [f"--network=container:{self.container(LITELLM)}"]
        arguments = [self.entrypoint(), name, str(GATEWAY_PORT)]
        return self.throwaway(network, arguments, FIRST_RECORD_PROGRAM)

    # --- the windows --------------------------------------------------------------------------

    def bounded_window(
        self, service: str, arguments: list[str], seconds: int, during: Callable[[], None]
    ) -> dict:
        """`window` with a bound of `seconds`; `during` ends only once the window has, so the
        wait for its result stays short."""

        def held_open() -> None:
            opened = time.monotonic()
            during()
            time.sleep(max(0.0, opened + seconds + WINDOW_MARGIN_SECONDS - time.monotonic()))

        return self.window(service, ["--seconds", str(seconds), *arguments], held_open)

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        observed: dict[str, dict] = {}

        def session() -> None:
            self.cells_s1_s2_r3(observed)
            self.cells_x(observed)

        observed["g20"] = self.bounded_window("capture-egress", ["syn"], SESSION_SECONDS, session)
        self.cell_g20(observed)

    def cells_s1_s2_r3(self, observed: dict[str, dict]) -> None:
        """LiteLLM's start with the gate dropped inside a DNS and a SYN window of its namespace."""
        asked = secrets.token_hex(8)
        times: dict[str, float] = {}

        def start() -> None:
            (self.gate / GATE_FILE).write_text("", encoding="utf-8")
            (self.gate / GATE_FILE).chmod(0o644)
            self.wait_until_listening()
            answer = self.client_in_namespace_of(
                self.container(LITELLM), "resolve", f"{asked}.example.com"
            )
            expect(answer["addresses"] == [], f"S1: the control resolved: {answer}")
            times["dns"] = time.time()
            for host in (PROVIDER_HOST, PICTURE_HOST):
                seen = self.handshake(host)
                expect(seen == {"handshake": True, "subject": host, "issuer": "probe-ca"},
                       f"R3: {seen}")  # fmt: skip
            times["syn"] = time.time()

        def inside_syn_window() -> None:
            observed["s1"] = self.bounded_window(
                CAPTURE_LITELLM, ["dns", asked, self.database], START_SECONDS, start
            )

        observed["s2"] = self.bounded_window(
            CAPTURE_LITELLM, ["syn"], START_SECONDS, inside_syn_window
        )
        self.cell_s1(observed["s1"], asked, times["dns"])
        self.cell_s2(observed["s2"], times["syn"])
        self.hold("R3", f"LiteLLM's handshakes on the gateway's entrypoint for {PROVIDER_HOST} and "
                  f"{PICTURE_HOST} show each fake's certificate of the scratch CA")  # fmt: skip

    def cell_s1(self, result: dict, asked: str, control_ended: float) -> None:
        """The window must show the control's own query, not only its reply: a window that
        dropped queries would miss an unanswered one from LiteLLM's start."""
        self.complete(result, "S1", control_ended)
        seen, queries = result["one_question"].get(asked, 0), result["queries"].get(asked, 0)
        if not queries:
            raise NotDriven("S1: not driven: the control's query is not in LiteLLM's DNS window")
        database = result["one_question"].get(self.database, 0)
        # `frames` also holds the kernel's IPv6 multicast reports, which are no DNS.
        expect(
            result["dns_messages"] == seen + database,
            f"S1: {result['dns_messages'] - seen - database} DNS messages are neither the "
            f"control's nor for {self.database}",
        )
        self.hold(
            "S1",
            f"LiteLLM's DNS window holds only the control's {seen} messages, {queries} queries, "
            f"and {database} messages for {self.database}",
        )

    def cell_s2(self, result: dict, control_ended: float) -> None:
        """No SYN leaves LiteLLM's namespace but the control's to the gateway; LiteLLM's own
        connects to its loopback address stay inside it and are counted apart."""
        self.complete(result, "S2", control_ended)
        entrypoint = (self.entrypoint(), GATEWAY_PORT)
        database = (self.address_of(self.database, "litellm-db"), self.database_port)
        leaving = [syn for syn in result["syns"] if syn["interface"] != LOOPBACK]
        inside = sorted({
            f"{syn['destination']}:{syn['port']}"
            for syn in result["syns"] if syn["interface"] == LOOPBACK
        })  # fmt: skip
        stray = [(syn["destination"], syn["port"]) for syn in leaving]
        expect(
            all(found in (entrypoint, database) for found in stray),
            f"S2: LiteLLM sent SYNs to {sorted(set(stray) - {entrypoint, database})}",
        )
        if entrypoint not in stray or database not in stray:
            raise NotDriven(
                "S2: not driven: the control's SYN or the database's is not in LiteLLM's SYN window"
            )
        self.hold(
            "S2",
            f"{len(leaving)} SYNs left LiteLLM's namespace, all to "
            f"{entrypoint[0]}:{entrypoint[1]} or {database[0]}:{database[1]}; "
            f"{len(result['syns']) - len(leaving)} stayed on "
            f"{LOOPBACK}, to {', '.join(inside) or 'nothing'}",
        )

    def cells_x(self, observed: dict[str, dict]) -> None:
        front, litellm, port = FRONT, LITELLM, self.litellm_port
        intervals: dict[str, tuple[float, float]] = {}
        litellm_backend = self.address_of(LITELLM, "litellm-backend")
        litellm_egress = self.address_of(LITELLM, "litellm-egress")
        database = self.address_of(self.database, "litellm-db")
        entrypoint = self.entrypoint()
        provider = self.address_of(FAKE_PROVIDER, "internet")
        for step in (
            Reach("X1c", front, "litellm-backend", litellm_backend, port, True),
            Reach("X1d", GATEWAY, "litellm-egress", litellm_egress, port, True),
            Reach("X6b", front, "agent-egress litellm-egress", entrypoint, GATEWAY_PORT, False),
            Reach("X6c", litellm, "agent-egress litellm-egress", entrypoint, GATEWAY_PORT, True),
            Reach("X7a", front, PROVIDER_ON_INTERNET, provider, GATEWAY_PORT, False),
            Reach("X7b", litellm, PROVIDER_ON_INTERNET, provider, GATEWAY_PORT, False),
            Reach("X7d", GATEWAY, PROVIDER_ON_INTERNET, provider, GATEWAY_PORT, True),
            Reach("X12a", litellm, "litellm-db", database, self.database_port, True),
            Reach("X12b", front, "litellm-db", database, self.database_port, False),
        ):
            self.reach(step, intervals)
        self.cells_x8_to_x11(entrypoint, intervals)
        observed["cells_ended"] = {"at": time.time()}
        observed["x1d"] = {"started": intervals["X1d"][0], "ended": intervals["X1d"][1]}

    def sni_ended(self, source: str, address: str, where: str, name: str) -> str:
        """An SNI of `name` from the namespace of `source` to the gateway at `address`, which must
        end in an alert."""
        result = self.client_in_namespace_of(
            self.container(source), "tls", address, name, str(GATEWAY_PORT), "noverify"
        )
        alerted(result, name)
        return f"SNI {name!r} on {where}: the handshake ended ({result['error']})"

    def cells_x8_to_x11(self, entrypoint: str, intervals: dict[str, tuple[float, float]]) -> None:
        def ended(name: str) -> str:
            return self.sni_ended(LITELLM, entrypoint, "the gateway's entrypoint", name)

        def no_server_hello() -> str:
            record = self.first_record(REFUSED_HOST)
            expect(record.get("content_type") == TLS_ALERT, f"X8: the first record is {record}")
            return (
                f"{ended(REFUSED_HOST)}; its first record is an alert, where {PROVIDER_HOST}'s is "
                "a ServerHello"
            )

        control = self.first_record(PROVIDER_HOST)
        expect(
            (control.get("content_type"), control.get("first_byte"))
            == (TLS_HANDSHAKE, SERVER_HELLO),
            f"X8: the control's first record for {PROVIDER_HOST} is no ServerHello: {control}",
        )
        self.refused_without_a_dial("X8", no_server_hello)
        self.refused_without_a_dial("X9", lambda: ended("example.com"))
        self.cells_x13_to_x16(entrypoint, ended)
        container = self.container(LITELLM)
        outside = self.client_in_namespace_of(container, "resolve", "example.com")["addresses"]
        expect(outside == [], f"X10: example.com resolves to {outside}")
        self.hold("X10", "LiteLLM resolves example.com to no address")
        for host in (PROVIDER_HOST, PICTURE_HOST):
            found = self.client_in_namespace_of(container, "resolve", host)["addresses"]
            expect(found == [entrypoint], f"X11: {host} resolves to {found}")
        self.hold("X11", f"LiteLLM resolves {PROVIDER_HOST} and {PICTURE_HOST} to {entrypoint}, "
                  "the gateway's entrypoint")  # fmt: skip
        self.cells_picture_host(intervals)

    def cells_x13_to_x16(self, entrypoint: str, ended: Callable[[str], str]) -> None:
        """No SNI, plain bytes, a suffix and a prefix of the provider name end in the gateway."""

        def without_sni() -> str:
            result = self.client_in_namespace_of(
                self.container(LITELLM), "tls", entrypoint, "-", str(GATEWAY_PORT), "noverify"
            )
            alerted(result, "no SNI")
            return f"no SNI refused ({result['error']})"

        def plain_bytes() -> str:
            result = self.client_in_namespace_of(
                self.container(LITELLM), "plain", entrypoint, str(GATEWAY_PORT)
            )
            refused = not result["connected"] or result["reply"] in ("closed", NOT_FOUND)
            expect(refused, f"plain bytes: {result}")
            return f"plain bytes refused ({result})"

        self.refused_without_a_dial("X13", without_sni)
        self.refused_without_a_dial("X14", plain_bytes)
        self.refused_without_a_dial("X15", lambda: ended(f"{PROVIDER_HOST}.example.com"))
        self.refused_without_a_dial("X16", lambda: ended(f"x{PROVIDER_HOST}"))

    def cells_picture_host(self, intervals: dict[str, tuple[float, float]]) -> None:
        """X7e and X7g: only the gateway reaches the fake OpenAI."""
        pictures = self.address_of(FAKE_PICTURES, "internet")
        for step in (
            Reach("X7e", LITELLM, PICTURES_ON_INTERNET, pictures, GATEWAY_PORT, False),
            Reach("X7g", GATEWAY, PICTURES_ON_INTERNET, pictures, GATEWAY_PORT, True),
        ):
            self.reach(step, intervals)

    def cell_g20(self, observed: dict[str, dict]) -> None:
        """The gateway dials only the fake hosts; X1d's own connect from its namespace to LiteLLM
        is allowed inside X1d's interval alone."""
        result = observed["g20"]
        self.complete(result, "G20", observed["cells_ended"]["at"])
        provider = (self.address_of(FAKE_PROVIDER, "internet"), GATEWAY_PORT)
        pictures = (self.address_of(FAKE_PICTURES, "internet"), GATEWAY_PORT)
        x1d = (self.address_of(LITELLM, "litellm-egress"), self.litellm_port)
        interval = observed["x1d"]

        def of_x1d(syn: dict) -> bool:
            at_x1d = (syn["destination"], syn["port"]) == x1d
            return at_x1d and interval["started"] <= syn["at"] <= interval["ended"]

        controls = [syn for syn in result["syns"] if of_x1d(syn)]
        seen = {(syn["destination"], syn["port"]) for syn in result["syns"] if not of_x1d(syn)}
        stray = seen - {provider, pictures}
        expect(not stray, f"G20: the gateway sent SYNs to {sorted(stray)}")
        if provider not in seen or pictures not in seen or not controls:
            raise NotDriven("G20: not driven: the controls' SYNs are not in the gateway's window")
        self.hold(
            "G20",
            f"the gateway sent SYNs only to the fake hosts {sorted(seen)}, and to LiteLLM within "
            "X1d's interval",
        )


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], NetworkProbe)


if __name__ == "__main__":
    sys.exit(main())
