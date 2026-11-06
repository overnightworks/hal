"""The egress gateway as files, no containers (#189 cell E16): compose.yaml, the gateway's static
and dynamic files and the probe overlay.

The running paths are proven by probe/agent-service/litellm_network.py; these tests hold the static
facts the probe does not see: every network a member of the agent attachments joins is internal and
isolated, and the gateway is the only service with a route out. The packet windows of capture.py
and the SYN verdict of litellm_stack.py are pure logic, checked here on synthetic frames.
"""

import ipaddress
import re
import signal
import socket
import struct
import subprocess
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml
from support.script_module import loaded_script

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "probe" / "agent-service"
GATEWAY = "agent-egress"
SERVICE = "agent-service"
STAND_IN = "agent-probe"
LITELLM_EGRESS = "litellm-egress"
OBSERVER = "realm-observer"
ISOLATED_MODE = {"com.docker.network.bridge.gateway_mode_ipv4": "isolated"}
HOST_SNI = re.compile(r"HostSNI\(`([^`]+)`\)")


def load(path: str):
    return yaml.safe_load((ROOT / path).read_text())


@pytest.fixture(scope="module")
def compose() -> dict:
    return load("compose.yaml")


@pytest.fixture(scope="module")
def overlay() -> dict:
    return load("probe/agent-service/compose.probe.yaml")


@pytest.fixture(scope="module")
def routers() -> dict:
    return load("agent-service/egress/dynamic/allowed.yml")["tcp"]["routers"]


@pytest.fixture(scope="module")
def attachments(compose) -> dict:
    return compose["x-agent-attachments"]


def test_every_network_of_the_agent_attachments_is_internal_and_isolated(compose, attachments):
    """E16: the service and the stand-in join only networks with no route out or host address."""
    joined = {name: compose["networks"][name] for name in attachments["networks"]}

    for network in joined.values():
        assert network["internal"] is True
        assert network["driver_opts"] == ISOLATED_MODE


@pytest.mark.parametrize("member", [STAND_IN, SERVICE])
def test_a_member_carries_the_attachments_and_nothing_else_of_the_network(
    compose, attachments, member
):
    """E16: the stand-in and the service merge the one anchor; neither adds a port, a network
    mode or a network."""
    service = compose["services"][member]
    assert service["networks"] == attachments["networks"]
    assert not {"ports", "network_mode", "expose"} & service.keys()


def test_the_gateway_is_the_only_service_on_internet(compose):
    """E16: one route out, and it is the gateway's."""
    on_internet = [
        name
        for name, service in compose["services"].items()
        if "internet" in (service.get("networks") or [])
    ]

    assert on_internet == [GATEWAY]
    assert compose["networks"]["internet"].get("internal") is not True
    assert "ports" not in compose["services"][GATEWAY]
    assert "network_mode" not in compose["services"][GATEWAY]
    sharing = [
        name
        for name, service in compose["services"].items()
        if GATEWAY in service.get("network_mode", "")
    ]
    assert sharing == []


def test_the_gateway_cannot_reach_the_docker_api_and_adds_nothing_to_its_hardening(compose):
    """E16: no socket, no socket-proxy, a file provider only, no capability, two networks."""
    gateway = compose["services"][GATEWAY]
    static_config = load("agent-service/egress/traefik.yml")

    assert not any(
        "docker.sock" in volume or "socket-proxy" in volume for volume in gateway["volumes"]
    )
    assert "socket-proxy" not in gateway.get("depends_on", {})
    assert set(static_config["providers"]) == {"file"}
    assert "cap_add" not in gateway
    assert set(gateway["networks"]) == {LITELLM_EGRESS, "internet"}


def test_the_gateways_address_stands_in_compose_and_in_its_static_file(compose):
    """E16: the one entrypoint listens on the gateway's address on `litellm-egress`."""
    entrypoints = load("agent-service/egress/traefik.yml")["entryPoints"]
    address = compose["x-litellm-egress-address"]

    assert compose["services"][GATEWAY]["networks"][LITELLM_EGRESS] == {"ipv4_address": address}
    assert ipaddress.ip_address(address) in ipaddress.ip_network(
        compose["networks"][LITELLM_EGRESS]["ipam"]["config"][0]["subnet"]
    )
    assert [entrypoint["address"] for entrypoint in entrypoints.values()] == [f"{address}:443"]


def test_every_router_names_the_one_entrypoint_and_only_the_two_providers_are_open(routers):
    """#768: the text and the picture provider, each from LiteLLM's entrypoint alone."""
    entrypoints = list(load("agent-service/egress/traefik.yml")["entryPoints"])

    assert {name: router["entryPoints"] for name, router in routers.items()} == {
        "provider": entrypoints,
        "pictures": entrypoints,
    }


def test_the_gateway_shares_the_public_traefiks_image_and_hardening(compose):
    """E16: one image digest and one hardening for every Traefik instance."""
    shared = ("image", "user", "read_only", "cap_drop", "security_opt")
    public = compose["services"]["traefik"]

    assert {key: compose["services"][GATEWAY][key] for key in shared} == {
        key: public[key] for key in shared
    }


@pytest.mark.parametrize("member", [GATEWAY, SERVICE, STAND_IN])
def test_no_plain_compose_up_starts_the_gateway_the_service_or_the_stand_in(compose, member):
    """Each sits behind a profile, whichever one."""
    assert compose["services"][member]["profiles"]


def test_the_gateways_static_file_keeps_global_and_log_of_the_public_traefik_and_no_api():
    """E16: version check and telemetry stay off, and api, ping and metrics stay absent."""
    public, gateway = load("traefik.yml"), load("agent-service/egress/traefik.yml")

    assert {key: gateway[key] for key in ("global", "log")} == {
        key: public[key] for key in ("global", "log")
    }
    assert not {"api", "ping", "metrics"} & gateway.keys()


def test_every_router_passes_its_name_through_to_that_name_on_443(routers):
    """The gateway holds no key: each router passes TLS through to the host it matched."""
    services = load("agent-service/egress/dynamic/allowed.yml")["tcp"]["services"]

    assert routers
    for router in routers.values():
        (server,) = services[router["service"]]["loadBalancer"]["servers"]
        assert router["tls"] == {"passthrough": True}
        assert server["address"] == f"{HOST_SNI.fullmatch(router['rule']).group(1)}:443"


def test_an_unmatched_or_missing_sni_is_refused_in_the_gateway():
    """No catch-all router exists, and the default TLS options refuse an unknown name."""
    allowed = load("agent-service/egress/dynamic/allowed.yml")

    assert allowed["tls"]["options"]["default"]["sniStrict"] is True
    assert all(HOST_SNI.fullmatch(router["rule"]) for router in allowed["tcp"]["routers"].values())


@pytest.mark.parametrize("service", ["capture-egress", "capture-host"])
def test_a_capture_service_runs_the_observers_pin_with_net_raw_alone(compose, overlay, service):
    """The packet windows use the realm observer's image and add one capability to none."""
    capture = overlay["services"][service]

    assert capture["image"] == compose["services"][OBSERVER]["image"]
    assert capture["cap_drop"] == ["ALL"]
    assert capture["cap_add"] == ["NET_RAW"]
    assert capture["read_only"] is True
    assert "ports" not in capture
    assert all(volume.endswith(":ro") for volume in capture["volumes"])


# --- the packet windows' pure logic, on synthetic frames --------------------------------------


def probe_module(name: str, *directories: Path) -> Iterator[ModuleType]:
    yield from loaded_script(f"agent_probe_{name}", PROBE / f"{name}.py", *directories)


@pytest.fixture(scope="module")
def capture() -> Iterator[ModuleType]:
    yield from probe_module("capture")


@pytest.fixture(scope="module")
def litellm_stack() -> Iterator[ModuleType]:
    yield from probe_module("litellm_stack")


CONTROL_DESTINATION = "203.0.113.7"
OTHER_DESTINATION = "198.51.100.9"
CONTROL_STARTED = 100.0


def syn(at: float, destination: str, port: int = 443) -> dict:
    return {"at": at, "interface": "eth1", "destination": destination, "port": port}


@pytest.mark.parametrize(
    ("syns", "early", "stray", "control_seen"),
    [
        pytest.param([syn(101.0, CONTROL_DESTINATION)], [], [], True, id="the control alone"),
        pytest.param(
            [syn(99.9, OTHER_DESTINATION), syn(101.0, CONTROL_DESTINATION)],
            [(OTHER_DESTINATION, 443)], [], True,
            id="a forbidden SYN the kernel stamped before the control, read late",
        ),
        pytest.param(
            [syn(101.0, CONTROL_DESTINATION), syn(102.0, OTHER_DESTINATION)],
            [], [(OTHER_DESTINATION, 443)], True,
            id="a SYN to another destination after the control started",
        ),
        pytest.param(
            [syn(101.0, CONTROL_DESTINATION, 80)],
            [], [(CONTROL_DESTINATION, 80)], False,
            id="the control's address on another port",
        ),
        pytest.param([], [], [], False, id="no SYN at all"),
    ],
)  # fmt: skip
def test_the_syn_window_is_judged_by_kernel_time_and_destination(
    litellm_stack, syns, early, stray, control_seen
):
    """E3-E5: only the control's SYN, to the provider's addresses on 443, may follow its start."""
    verdict = litellm_stack.classify_syns(syns, CONTROL_STARTED, {CONTROL_DESTINATION})

    assert verdict == (early, stray, control_seen)


def ethernet(ethertype: int, packet: bytes) -> bytes:
    return bytes(12) + struct.pack("!H", ethertype) + packet


def tcp(source_port: int, destination_port: int, flags: int, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", source_port, destination_port, 0, 0, 5 << 4, flags, 0, 0, 0)
    return header + payload


def ipv6(next_header: int, body: bytes) -> bytes:
    source, destination = socket.inet_pton(socket.AF_INET6, "::1"), bytes(15) + b"\x02"
    header = struct.pack("!IHBB", 6 << 28, len(body), next_header, 64)
    return ethernet(0x86DD, header + source + destination + body)


def ipv4_header(
    protocol: int,
    body: bytes,
    fragment: int = 0,
    destination: str = "0.0.0.0",  # noqa: S104 - the default destination of a scenario packet and no listener
) -> bytes:
    address = socket.inet_aton(destination)
    fields = (0x45, 0, 20 + len(body), 0, fragment, 64, protocol, 0, bytes(4), address)
    return struct.pack("!BBHHHBBH4s4s", *fields) + body


def extension_header(next_header: int, kind: str) -> bytes:
    if kind == "fragment":  # a later fragment: the offset is 8 units
        return struct.pack("!BBHI", next_header, 0, 8 << 3, 1)
    return struct.pack("!BB", next_header, 0) + bytes(6)  # hop-by-hop options


def long_options(next_header: int, length: int) -> bytes:
    """One destination-options header of `length` bytes (a multiple of 8), then `next_header`."""
    return struct.pack("!BB", next_header, length // 8 - 1) + bytes(length - 2)


def udp(source_port: int, destination_port: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload


def tcp_with_options(payload: bytes) -> bytes:
    """A DNS-over-TCP segment whose header declares 60 bytes (data offset 15)."""
    header = struct.pack("!HHIIBBHHH", 40000, 53, 0, 0, 15 << 4, 0x18, 0, 0, 0) + bytes(40)
    return header + struct.pack("!H", len(payload)) + payload


def dns_message(name: str, flags: int = 0x0100) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    return struct.pack("!HHHHHH", 1, flags, 1, 0, 0, 0) + labels + b"\0\0\1\0\1"


def parse(capture, frame: bytes):
    return capture.parse(frame, "eth0", capture.PACKET_OUTGOING, capture.ARPHRD_ETHER, 5.0)


def test_a_syn_behind_ipv6_extension_headers_is_decoded_with_its_kernel_time(capture):
    """E3-E5: a hop-by-hop header in front of the TCP header hides neither the SYN nor its time."""
    body = extension_header(6, "options") + tcp(40000, 443, capture.TCP_SYN)

    segment = parse(capture, ipv6(0, body))

    assert (segment.protocol, segment.destination_port, segment.at) == (6, 443, 5.0)
    assert segment.flags & capture.TCP_SYN
    assert not segment.undecoded


def test_an_ipv6_frame_behind_extension_headers_without_ports_is_no_gap(capture):
    """E10: multicast listener reports (ICMPv6 behind hop-by-hop) are walked, not counted."""
    frame = ipv6(0, extension_header(58, "options") + bytes(8))

    assert parse(capture, frame) is None


MORE_FRAGMENTS = 0x2000
CUT_EXTENSION = struct.pack("!BB", 58, 3) + bytes(6)  # declares 32 bytes, 8 captured


@pytest.mark.parametrize(
    "frame",
    [
        pytest.param(
            ipv6(44, extension_header(6, "fragment") + bytes(20)), id="an IPv6 later fragment"
        ),
        pytest.param(ipv6(0, bytes(3)), id="a chain cut off by the snap length"),
        pytest.param(ipv6(0, CUT_EXTENSION), id="an extension cut short of its declared length"),
        pytest.param(
            ethernet(0x0800, ipv4_header(17, bytes(16), MORE_FRAGMENTS)),
            id="an IPv4 first fragment",
        ),
        pytest.param(ethernet(0x0800, ipv4_header(17, bytes(4))), id="a short UDP header"),
        pytest.param(ethernet(0x0800, ipv4_header(6, bytes(12))), id="a short TCP header"),
        pytest.param(
            ipv6(60, long_options(17, 1528) + udp(40000, 53, dns_message("a.b.c"))),
            id="a UDP DNS message cut by the capture behind a long extension chain",
        ),
        pytest.param(
            ipv6(60, long_options(6, 1520) + tcp_with_options(dns_message("a.b.c"))),
            id="a TCP header whose options run past the captured bytes",
        ),
    ],
)
def test_a_frame_whose_ports_cannot_be_reached_makes_the_dns_window_incomplete(
    capture, litellm_stack, frame
):
    """E10: DNS the window cannot decode is counted, so the control cannot cover for it."""
    segment = parse(capture, frame[: capture.READ_BYTES])
    window = capture.Window()

    window.see(segment, ["label"])

    assert segment.undecoded
    assert window.undecoded == 1
    result = {"drops": 0, "undecoded": window.undecoded, "ended_at": 9.0, "started_at": 0.0}
    with pytest.raises(litellm_stack.NotDriven):
        litellm_stack.StackProbe.complete(
            {**result, "ended_by": "seconds", "frames": 1}, "E10", 5.0
        )


def test_a_frame_the_kernel_truncated_on_port_53_is_undecoded(capture):
    frame = ethernet(0x0800, ipv4_header(17, udp(40000, 53, dns_message("a.b.c"))))

    segment = capture.parse(
        frame, "eth0", capture.PACKET_OUTGOING, capture.ARPHRD_ETHER, 5.0, truncated=True
    )

    assert segment.undecoded


class OneFrameSocket:
    """A packet socket that hands over one outgoing frame with the given message flags."""

    def __init__(self, capture, frame: bytes, flags: int) -> None:
        self.capture, self.frame, self.flags = capture, frame, flags

    def recvmsg(self, size: int, _ancillary_size: int):
        timestamp = struct.pack("@ll", 5, 0)
        ancillary = [(socket.SOL_SOCKET, self.capture.SO_TIMESTAMPNS, timestamp)]
        address = ("eth0", 0, self.capture.PACKET_OUTGOING, self.capture.ARPHRD_ETHER, b"")
        return self.frame[:size], ancillary, self.flags, address


@pytest.mark.parametrize(
    ("flags", "undecoded"),
    [(0, 0), (socket.MSG_TRUNC, 1)],
    ids=["a whole frame", "a frame the kernel cut"],
)
def test_the_watch_loop_counts_a_dns_frame_the_kernel_cut_as_undecoded(
    capture, monkeypatch, flags, undecoded
):
    """E10: the MSG_TRUNC flag of the socket's message reaches the parser through `watch`."""
    monkeypatch.setattr(capture, "FRAME_CAP", 1)
    frame = ethernet(0x0800, ipv4_header(17, udp(40000, 53, dns_message("a.b.c"))))

    window, ended_by = capture.watch(OneFrameSocket(capture, frame, flags), ["label"])

    assert (window.frames, window.undecoded, ended_by) == (1, undecoded, "frames")


class SilentSocket:
    """A packet socket that never sees a frame; its poll times out."""

    def recvmsg(self, _size: int, _ancillary_size: int):
        raise TimeoutError


@pytest.mark.parametrize("bound", [None, 45], ids=["the default bound", "a longer bound"])
def test_a_window_lasts_for_its_bound_in_seconds(capture, monkeypatch, bound):
    seconds = bound or capture.WINDOW_SECONDS
    clock = iter(range(1000))
    now = []
    monkeypatch.setattr(capture.time, "monotonic", lambda: now.append(next(clock)) or now[-1])

    arguments = [] if bound is None else [bound]
    _, ended_by = capture.watch(SilentSocket(), [], *arguments)

    assert ended_by == "seconds"
    assert seconds <= now[-1] - now[0] <= seconds + 1


@pytest.mark.parametrize(
    ("arguments", "parsed"),
    [
        (["syn"], (None, "syn", [])),
        (["--seconds", "90", "syn"], (90, "syn", [])),
        (["--seconds", "90", "dns", "Label"], (90, "dns", ["label"])),
        (["--seconds"], None),
        (["--seconds", "0", "syn"], None),
        (["--seconds", "ten", "syn"], None),
        (["--seconds", "90"], None),
        (["--seconds", "90", "syn", "label"], None),
        (["dns"], None),
        (["dns", "litellm-db"], (None, "dns", ["litellm-db"])),
        (["dns", "-db"], None),
    ],
    ids=[
        "no bound", "a bound on syn", "a bound on dns", "a bound without a number",
        "a bound of zero", "a bound that is no number", "a bound without a mode",
        "syn with a label", "dns without a label", "a label with a hyphen",
        "a label that starts with a hyphen",
    ],
)  # fmt: skip
def test_the_window_arguments_name_the_bound_the_mode_and_the_labels(capture, arguments, parsed):
    if parsed is not None and parsed[0] is None:
        parsed = (capture.WINDOW_SECONDS, *parsed[1:])

    assert capture.parse_arguments(arguments) == parsed


@pytest.mark.parametrize(
    ("cut", "undecoded"),
    [(None, 0), (20, 1)],
    ids=["one whole message", "a message split across segments"],
)
def test_a_tcp_dns_message_split_across_segments_makes_the_dns_window_incomplete(
    capture, cut, undecoded
):
    """E10: the question of a split TCP message is not in its first segment alone."""
    message = dns_message("label.example.com")
    payload = struct.pack("!H", len(message)) + message[:cut]
    frame = ethernet(0x0800, ipv4_header(6, tcp(40000, 53, capture.TCP_ACK, payload)))
    segment = parse(capture, frame)
    dns_window, syn_window = capture.Window(), capture.Window()

    dns_window.see(segment, ["label"])
    syn_window.see(segment, [])

    assert dns_window.undecoded == undecoded
    assert syn_window.undecoded == 0


def filter_passes(capture, frame: bytes) -> bool:
    """The kernel's verdict, replayed: the assembled DNS filter on one Ethernet frame."""
    program = capture.assemble(capture.DNS_FILTER)
    steps = [struct.unpack_from("HBBI", program, at) for at in range(0, len(program), 8)]
    accumulator, index, at = 0, 0, 0
    while True:
        opcode, yes, no, operand = steps[at]
        at += 1
        if opcode == capture.LOAD_WORD:
            accumulator = (
                capture.ARPHRD_ETHER
                if operand == capture.HARDWARE_TYPE_OFFSET
                else struct.unpack_from("!I", frame, operand)[0]
            )
        elif opcode == capture.LOAD_HALF:
            accumulator = struct.unpack_from("!H", frame, operand)[0]
        elif opcode == capture.LOAD_HALF_INDEXED:
            accumulator = struct.unpack_from("!H", frame, index + operand)[0]
        elif opcode == capture.LOAD_BYTE:
            accumulator = frame[operand]
        elif opcode == capture.LOAD_HEADER_LENGTH_INTO_X:
            index = 4 * (frame[operand] & 0x0F)
        elif opcode == capture.JUMP_EQUAL:
            at += yes if accumulator == operand else no
        elif opcode == capture.JUMP_ANY_BIT:
            at += yes if accumulator & operand else no
        else:
            return operand != capture.DROP_FRAME


@pytest.mark.parametrize(
    ("protocol", "body", "passes"),
    [
        pytest.param(6, tcp(40000, 53, 0x10), True, id="TCP port 53"),
        pytest.param(6, tcp(40000, 80, 0x10), False, id="TCP port 80"),
        pytest.param(58, bytes(8), False, id="ICMPv6 without a header chain"),
        pytest.param(0, extension_header(6, "o") + tcp(40000, 53, 0x10), True, id="hop-by-hop"),
        pytest.param(60, extension_header(17, "o") + bytes(8), True, id="destination options"),
    ],
)  # fmt: skip
def test_the_dns_filter_lets_ipv6_extension_header_chains_through_to_be_walked(
    capture, protocol, body, passes
):
    """E10: the filter cannot read ports behind an extension header, so it passes the chain on."""
    assert filter_passes(capture, ipv6(protocol, body)) is passes


@pytest.mark.parametrize(
    ("destination", "passes"),
    [("127.0.0.11", True), ("127.0.0.12", False)],
    ids=["Docker's embedded resolver", "another loopback address"],
)
def test_the_dns_filter_passes_a_query_to_the_embedded_resolver_on_its_rewritten_port(
    capture, destination, passes
):
    """S1: Docker rewrites the port of a container's query to 127.0.0.11 before the frame is
    captured, so the filter cannot wait for port 53 on it."""
    rewritten_port = 46519  # where Docker's rule in a container sends a query to its resolver
    body = udp(40000, rewritten_port, dns_message("label.example.com"))
    frame = ethernet(0x0800, ipv4_header(17, body, destination=destination))

    assert filter_passes(capture, frame) is passes


@pytest.mark.parametrize(
    ("ports", "destination", "flags", "queries"),
    [
        ((40000, 46519), "127.0.0.11", 0x0100, {"label": 1}),  # a rewritten port
        ((53, 40000), "127.0.0.1", 0x8180, {}),  # a reply's flags
    ],
    ids=["a query on the rewritten port", "the reply from port 53"],
)  # fmt: skip
def test_the_dns_window_counts_a_query_to_the_embedded_resolver_apart_from_its_reply(
    capture, ports, destination, flags, queries
):
    """S1: the window names the control's query, not only its reply."""
    body = udp(*ports, dns_message("label.example.com", flags))
    segment = parse(capture, ethernet(0x0800, ipv4_header(17, body, destination=destination)))
    window = capture.Window()

    window.see(segment, ["label"])

    assert (window.label_frames, window.query_frames) == ({"label": 1}, queries)


def with_questions(first: str, *more: str) -> bytes:
    """A DNS query for `first` followed by one more question for each of `more`."""
    extra = b"".join(dns_message(name)[12:] for name in more)
    count = struct.pack("!H", 1 + len(more))
    return dns_message(first)[:4] + count + dns_message(first)[6:] + extra


@pytest.mark.parametrize(
    ("message", "matched"),
    [
        (dns_message("litellm-db.example.com"), {"litellm-db": 1}),
        (dns_message("litellm-db"), {"litellm-db": 1}),
        (dns_message("license.litellm.ai"), {}),
        (dns_message("litellm-dbx.example.com"), {}),
        (dns_message("x.litellm-db.example.com"), {}),
        (with_questions("litellm-db", "license.litellm.ai"), {}),
        (dns_message("litellm-db")[:4] + struct.pack("!H", 0) + dns_message("litellm-db")[6:], {}),
        (dns_message("litellm-db")[:-4], {}),
        (dns_message("litellm-db")[:-5], {}),
        (dns_message("litellm-db")[:12] + b"\x0alitellm-db\xc0\x0c" + bytes(200), {}),
        (dns_message("litellm-db")[:20], {}),
        (dns_message("litellm-db")[:8], {}),
    ],
    ids=["the label with a domain", "the label alone", "another host of litellm",
         "a longer first label", "the label deeper in the name",
         "a second question behind the label", "no question", "a question cut after its name",
         "a name without its root", "a name that ends in a compression pointer",
         "a name cut inside a label", "a header cut short"],
)  # fmt: skip
def test_the_dns_window_matches_one_whole_question_by_its_first_label_and_counts_every_message(
    capture, message, matched
):
    """S1: `litellm-db` is told from other names that contain it, a message with any other question
    count or a cut question matches nothing, and every DNS message still counts."""
    body = udp(40000, 53, message)
    segment = parse(capture, ethernet(0x0800, ipv4_header(17, body, destination="127.0.0.1")))
    window = capture.Window()

    window.see(segment, ["litellm-db"])

    assert (window.one_question_frames, window.dns_messages) == (matched, 1)


# --- the unit probe's refused-start decision, on synthetic state and logs ----------------------

DIAGNOSTIC = "cli.anthropic.token_file"
LISTENING_LINE = "INFO: Uvicorn running on http://0.0.0.0:8080"


@pytest.fixture(scope="module")
def unit() -> Iterator[ModuleType]:
    yield from probe_module("unit")


def stopped(exit_code: int) -> dict:
    return {"Running": False, "Restarting": False, "ExitCode": exit_code}


def test_a_start_that_listened_before_it_crashed_fails_the_cell(unit):
    """U6/U11: a non-zero exit does not excuse a log that shows the service listening."""
    logs = f"{LISTENING_LINE}\n{DIAGNOSTIC} is too open\n"
    assert unit.ended_unsuccessfully(stopped(1))
    with pytest.raises(unit.ProbeFailed):
        unit.refusal_is_complete("U11", logs, [DIAGNOSTIC])


def test_a_clean_exit_is_no_refused_start(unit):
    assert not unit.ended_unsuccessfully(stopped(0))


def test_a_container_that_is_running_is_no_refused_start(unit):
    assert not unit.ended_unsuccessfully({"Running": True, "Restarting": False, "ExitCode": 1})


def test_a_failed_start_that_names_the_field_and_never_listened_passes(unit):
    restarting = {"Running": True, "Restarting": True, "ExitCode": 1}
    assert unit.ended_unsuccessfully(stopped(1))
    assert unit.ended_unsuccessfully(restarting)
    assert unit.refusal_is_complete("U11", f"{DIAGNOSTIC} is too open\n", [DIAGNOSTIC])
    assert not unit.refusal_is_complete("U11", "starting\n", [DIAGNOSTIC])


@pytest.mark.parametrize("failing", ["docker ps", "docker inspect"])
def test_a_failed_listing_or_inspection_fails_the_cell_never_reads_as_down(
    unit, monkeypatch, failing
):
    def answer(command, **_):
        if command[:2] == ["docker", "ps"]:
            code, out = (1, "") if failing == "docker ps" else (0, "abc\n")
        else:
            code, out = 1, ""
        return subprocess.CompletedProcess(command, code, out, "daemon error")

    monkeypatch.setattr(unit.subprocess, "run", answer)
    probe = object.__new__(unit.UnitProbe)
    probe.environment = {}
    with pytest.raises(unit.ProbeFailed):
        probe.service_state()


@pytest.fixture
def agent_networks() -> Iterator[ModuleType]:
    # it imports its sibling modules by name
    yield from probe_module("agent_networks", PROBE, ROOT / "probe", ROOT / "agent-service")


def test_p36_checks_every_ordered_pair_of_the_three_agent_networks(agent_networks):
    target = "agent-service-1"
    refused_pairs = []

    class Probe:
        def __init__(self):
            self.target = SimpleNamespace(compose_service=target)
            self.image = "image"

        def run(self, command):
            return SimpleNamespace(stdout=f"ip-{command[-1]}\n")

        def client_in_namespace_of(self, beside, action, *arguments):
            if action == "resolve":
                return {"addresses": []}
            if arguments[0] == "127.0.0.1":
                return {"result": "connected"}
            if arguments[0] == target:
                return {"result": "connected"}
            refused_pairs.append((beside, arguments[0]))
            return {"result": "ENETUNREACH"}

        def container(self, name):
            return "id"

        def inspect_network(self, network):
            return {"Containers": {"id": {}}}

        def hold(self, cell, text):
            self.held = cell

    probe = Probe()
    agent_networks.cell_p36(probe, project="p", label="l", service_port=80, service_listens=True)
    assert probe.held == "P36"
    callers = {network: f"p-caller-{network}" for network in agent_networks.AGENT_NETWORKS}
    assert set(refused_pairs) == {
        (callers[caller], f"ip-{callers[other]}")
        for caller in callers
        for other in callers
        if caller != other
    }
    assert len(refused_pairs) == 6


def test_a_term_during_the_litellm_probes_stack_removal_is_ignored(litellm_stack):
    seen = {}

    def remove_stack() -> None:
        seen["handler"] = signal.getsignal(signal.SIGTERM)

    stack = SimpleNamespace(
        windows=[],
        remove_stack=remove_stack,
        run=lambda *_, **__: SimpleNamespace(stdout=""),
        guard=SimpleNamespace(expect_clean_teardown=lambda: None),
    )
    before = signal.signal(signal.SIGTERM, signal.default_int_handler)
    try:
        litellm_stack.StackProbe.__exit__(stack)
    finally:
        signal.signal(signal.SIGTERM, before)
    assert seen["handler"] == signal.SIG_IGN
