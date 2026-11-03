"""A bounded packet window for the agent-service probe (#189): standard library only, run in a
container with NET_RAW and nothing else, in the namespace it is asked to watch.

    capture.py [--seconds N] syn                     TCP SYNs that leave this namespace
    capture.py [--seconds N] dns LABEL [LABEL ...]   DNS frames on port 53 or to Docker's
                                                     embedded resolver, UDP or TCP, whose
                                                     question's first label is a LABEL, the
                                                     queries among them and all DNS messages

It opens an `AF_PACKET` socket on every interface, prints `ready`, watches for at most N seconds
(default WINDOW_SECONDS) or FRAME_CAP frames, whichever comes first, and prints one JSON line: the
counts, the addresses and ports named below, and the kernel's own PACKET_STATISTICS for the
socket. Every frame is parsed in memory and dropped. No packet file, and no payload in any output
or diagnostic: the host's window also sees the operator's own traffic. The caller decides whether
the window was complete (no drop, nothing undecoded, still open when its control ended).

Every SYN carries the kernel's receive timestamp of its frame (SO_TIMESTAMPNS), not the time this
script got round to reading it.

The `dns` window attaches a kernel filter that passes only frames with port 53, IPv4 frames to
Docker's embedded resolver on any port (Docker rewrites a container's query to it to another port
before the frame is captured, while its reply leaves with port 53 again) and every frame of an
interface without an Ethernet header, so a busy host does not fill the frame cap with traffic
the window does not look at. IPv6 frames that carry an extension header pass too: the ports lie
behind the chain, which `parse` walks. A frame the window cannot fully decode is counted in
`undecoded` and makes the window incomplete: an IPv4 first fragment, an IPv6 chain or extension
header that is cut, a non-first IPv6 fragment, a TCP or UDP header that is short, a port-53
frame the capture truncated (MSG_TRUNC, or a UDP length or TCP header longer than what was
captured), and a TCP port-53 segment that does not hold exactly one whole DNS message (a message
split across segments). IPv4 non-first fragments carry no port and are not passed.
"""

# ruff: noqa: T201 - this in-container program answers on standard output
from __future__ import annotations

import contextlib
import ctypes
import json
import re
import socket
import struct
import sys
import time
from dataclasses import dataclass
from typing import NamedTuple

WINDOW_SECONDS = 20
FRAME_CAP = 20_000
RECEIVE_BUFFER_BYTES = 16 * 1024 * 1024
READ_BYTES = 1600  # headers and a DNS question fit; the rest of a frame is never kept
POLL_SECONDS = 0.5
ETH_P_ALL = 3
SOL_PACKET = 263
PACKET_STATISTICS = 6
PACKET_OUTGOING = 4
SO_TIMESTAMPNS = 35  # the kernel's receive time of each frame, as a control message
ARPHRD_ETHER = 1
ARPHRD_LOOPBACK = 772  # carries an Ethernet header too
ETHERNET_HEADER_BYTES = 14
VLAN_TAG_BYTES = 4
ETHERTYPE_VLAN = 0x8100
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
IPV6_HEADER_BYTES = 40
UDP_HEADER_BYTES = 8
TCP_HEADER_BYTES = 20
IPV4_FRAGMENT_BITS = 0x3FFF  # More Fragments and the fragment offset
TCP_SYN, TCP_ACK = 0x02, 0x10
PROTOCOL_TCP, PROTOCOL_UDP = 6, 17
IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_FRAGMENT = 0, 43, 44
IPV6_AUTHENTICATION, IPV6_DESTINATION_OPTIONS, IPV6_MOBILITY = 51, 60, 135
IPV6_EXTENSION_HEADERS = (
    IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_FRAGMENT,
    IPV6_AUTHENTICATION, IPV6_DESTINATION_OPTIONS, IPV6_MOBILITY,
)  # fmt: skip
IPV6_FRAGMENT_HEADER_BYTES = 8
IPV6_FRAGMENT_OFFSET_BITS = 0xFFF8
IPV6_CHAIN_LIMIT = 8
DNS_PORT = 53
DNS_HEADER_BYTES = 12
DNS_QUESTION_TAIL_BYTES = 4  # the question type and class behind its name
DNS_POINTER_BITS = 0xC0  # a name length byte with these bits set is no label length
DNS_RESPONSE_BIT = 0x80  # QR, the top bit of the header's third byte
EMBEDDED_RESOLVER = "127.0.0.11"  # Docker's resolver inside every container on a user network
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")

# Classic BPF: opcodes, and the ancillary load of the interface's hardware type (SKF_AD_OFF + 28).
SO_ATTACH_FILTER = 26
LOAD_WORD, LOAD_HALF, LOAD_BYTE = 0x20, 0x28, 0x30  # absolute offset
LOAD_HALF_INDEXED, LOAD_HEADER_LENGTH_INTO_X = 0x48, 0xB1
JUMP_EQUAL, JUMP_ANY_BIT, RETURN = 0x15, 0x45, 0x06
HARDWARE_TYPE_OFFSET = 0xFFFFF01C
PASS_FRAME, DROP_FRAME = 0xFFFF, 0
ETHERTYPE_OFFSET, IPV4_PROTOCOL_OFFSET, IPV4_FRAGMENT_OFFSET, IPV4_HEADER_OFFSET = 12, 23, 20, 14
IPV4_DESTINATION_OFFSET = 30
IPV6_PROTOCOL_OFFSET, IPV6_SOURCE_PORT_OFFSET = 20, 54
FRAGMENT_BITS = 0x1FFF


@dataclass(frozen=True)
class Segment:
    """What the window keeps of one TCP or UDP frame: no payload but the DNS question."""

    outgoing: bool
    interface: str
    protocol: int
    destination: str
    source_port: int
    destination_port: int
    flags: int
    question: str
    at: float  # the kernel's receive time
    query: bool = False  # a DNS message with QR 0
    undecoded: bool = False  # the frame could not be fully decoded
    partial_dns: bool = False  # TCP port 53 with a payload that is not one whole DNS message
    dns: bool = False  # the frame is a DNS message or a segment of one
    one_question: bool = False  # a DNS message of a whole header and exactly one whole question


def kernel_time(ancillary: list[tuple[int, int, bytes]]) -> float:
    for level, kind, data in ancillary:
        if level == socket.SOL_SOCKET and kind == SO_TIMESTAMPNS:
            seconds, nanoseconds = struct.unpack_from("@ll", data)
            return seconds + nanoseconds / 1e9
    raise RuntimeError("a frame came without the kernel's timestamp")


def ipv6_transport(frame: bytes, start: int) -> tuple[int, bytes] | None:
    """The transport protocol of an IPv6 packet behind its extension headers, and what follows
    them; None when the chain is cut, too long or only a later fragment (no ports to read)."""
    protocol, at = frame[start + 6], start + IPV6_HEADER_BYTES
    for _ in range(IPV6_CHAIN_LIMIT):
        if protocol not in IPV6_EXTENSION_HEADERS:
            return protocol, frame[at:]
        if at + IPV6_FRAGMENT_HEADER_BYTES > len(frame):
            return None
        if protocol == IPV6_FRAGMENT:
            if struct.unpack_from("!H", frame, at + 2)[0] & IPV6_FRAGMENT_OFFSET_BITS:
                return None
            length = IPV6_FRAGMENT_HEADER_BYTES
        elif protocol == IPV6_AUTHENTICATION:
            length = (frame[at + 1] + 2) * 4
        else:
            length = (frame[at + 1] + 1) * 8
        if at + length > len(frame):
            return None
        protocol, at = frame[at], at + length
    return None


def link_header_bytes(frame: bytes, hardware_type: int) -> tuple[int, int | None]:
    """The link header's length and the IP version it announces (None: read it from the packet)."""
    if hardware_type not in (ARPHRD_ETHER, ARPHRD_LOOPBACK):
        return 0, None
    length, ethertype = ETHERNET_HEADER_BYTES, struct.unpack_from("!H", frame, 12)[0]
    if ethertype == ETHERTYPE_VLAN:
        length, ethertype = length + VLAN_TAG_BYTES, struct.unpack_from("!H", frame, 16)[0]
    return length, {ETHERTYPE_IPV4: 4, ETHERTYPE_IPV6: 6}.get(ethertype)


class Network(NamedTuple):
    """What the IP header yields: where the packet goes, its protocol, and the bytes behind it."""

    destination: str
    protocol: int
    transport: bytes
    undecoded: bool = False


def network_layer(frame: bytes, offset: int, version: int) -> Network | None:
    """The IP header's reading; None for a packet that is neither IPv4 nor IPv6, or a fragment
    of neither TCP nor UDP."""
    if version == 4:
        protocol = frame[offset + 9]
        destination = socket.inet_ntop(socket.AF_INET, frame[offset + 16 : offset + 20])
        transport = frame[offset + (frame[offset] & 0x0F) * 4 :]
        if struct.unpack_from("!H", frame, offset + 6)[0] & IPV4_FRAGMENT_BITS:
            # Not reassembled: a fragment of a TCP or UDP datagram is a gap, and fails closed.
            if protocol in (PROTOCOL_TCP, PROTOCOL_UDP):
                return Network(destination, 0, b"", undecoded=True)
            return None
        return Network(destination, protocol, transport)
    if version == 6:
        destination = socket.inet_ntop(socket.AF_INET6, frame[offset + 24 : offset + 40])
        if (reached := ipv6_transport(frame, offset)) is None:
            return Network(destination, 0, b"", undecoded=True)
        return Network(destination, *reached)
    return None


def transport_contents(
    protocol: int, transport: bytes, header_bytes: int, carries_dns: bool
) -> tuple[int, bytes, bool]:
    """The TCP flags, the payload, and whether a DNS-over-TCP message is cut short."""
    if protocol != PROTOCOL_TCP:
        return 0, transport[UDP_HEADER_BYTES:], False
    flags, payload = transport[13], transport[header_bytes:]
    if carries_dns and payload:
        # DNS over TCP: a two-byte length comes first, and one whole message follows it.
        declared = int.from_bytes(payload[:2])
        return flags, payload[2:], len(payload) != 2 + declared
    return flags, payload, False


def parse(
    frame: bytes,
    interface: str,
    packet_type: int,
    hardware_type: int,
    at: float,
    truncated: bool = False,
) -> Segment | None:
    outgoing = packet_type == PACKET_OUTGOING
    offset, version = link_header_bytes(frame, hardware_type)
    if len(frame) <= offset:
        return None
    network = network_layer(frame, offset, version or frame[offset] >> 4)
    if network is None:
        return None
    destination, protocol, transport, undecoded = network
    gap = Segment(outgoing, interface, 0, destination, 0, 0, 0, "", at, undecoded=True)
    if undecoded:
        return gap
    if protocol not in (PROTOCOL_TCP, PROTOCOL_UDP):
        return None
    if len(transport) < (TCP_HEADER_BYTES if protocol == PROTOCOL_TCP else UDP_HEADER_BYTES):
        return gap
    source_port, destination_port = struct.unpack_from("!HH", transport)
    header_bytes = (transport[12] >> 4) * 4 if protocol == PROTOCOL_TCP else UDP_HEADER_BYTES
    declared_bytes = (
        header_bytes if protocol == PROTOCOL_TCP else struct.unpack_from("!H", transport, 4)[0]
    )
    carries_dns = is_dns(destination, source_port, destination_port)
    if carries_dns and (truncated or declared_bytes > len(transport)):
        # The capture cut the DNS message (or its TCP options): the question is not all here.
        return gap
    flags, payload, partial = transport_contents(protocol, transport, header_bytes, carries_dns)
    question, query = dns_reading(payload) if carries_dns else ("", False)
    one_question = carries_dns and has_one_question(payload)
    return Segment(
        outgoing, interface, protocol, destination, source_port, destination_port, flags,
        question, at, query=query, partial_dns=partial, dns=carries_dns,
        one_question=one_question,
    )  # fmt: skip


def is_dns(destination: str, source_port: int, destination_port: int) -> bool:
    """Port 53 either way, or any port to Docker's embedded resolver, which rewrites it."""
    return DNS_PORT in (source_port, destination_port) or destination == EMBEDDED_RESOLVER


def dns_reading(message: bytes) -> tuple[str, bool]:
    """The first question's name, and whether the message is a query (QR 0)."""
    return dns_question(message), len(message) > 2 and not message[2] & DNS_RESPONSE_BIT


def dns_question(message: bytes) -> str:
    """The first question's name, lower-cased and dotted; empty for anything else."""
    return question_name(message)[0]


def has_one_question(message: bytes) -> bool:
    """A whole header that declares one question, and that question whole: its name ends inside the
    message with no compression pointer, and its type and class follow."""
    if len(message) < DNS_HEADER_BYTES or struct.unpack_from("!H", message, 4)[0] != 1:
        return False
    root = question_name(message)[1]
    return root is not None and root + 1 + DNS_QUESTION_TAIL_BYTES <= len(message)


def question_name(message: bytes) -> tuple[str, int | None]:
    """The first question's name, lower-cased and dotted, and the offset of its root byte: None when
    the name runs past the message or reaches a compression pointer, where its labels stop."""
    labels, at = [], DNS_HEADER_BYTES
    while at < len(message) and message[at]:
        if message[at] & DNS_POINTER_BITS:
            return ".".join(labels).lower(), None
        length = message[at]
        labels.append(message[at + 1 : at + 1 + length].decode("ascii", errors="replace"))
        at += 1 + length
    return ".".join(labels).lower(), at if at < len(message) else None


# (label, opcode, operand, jump to this label if true, if false); no label: the next instruction.
Step = tuple[str | None, int, int, str | None, str | None]
IPV4_PORTS = "ipv4 ports"
IPV6_PORTS = "ipv6 ports"
DNS_FILTER: list[Step] = [
    (None, LOAD_WORD, HARDWARE_TYPE_OFFSET, None, None),
    (None, JUMP_EQUAL, ARPHRD_ETHER, "ethernet", None),
    (None, JUMP_EQUAL, ARPHRD_LOOPBACK, "ethernet", "pass"),
    ("ethernet", LOAD_HALF, ETHERTYPE_OFFSET, None, None),
    (None, JUMP_EQUAL, ETHERTYPE_IPV4, "ipv4", None),
    (None, JUMP_EQUAL, ETHERTYPE_IPV6, "ipv6", None),
    (None, JUMP_EQUAL, ETHERTYPE_VLAN, "pass", "drop"),
    ("ipv4", LOAD_BYTE, IPV4_PROTOCOL_OFFSET, None, None),
    (None, JUMP_EQUAL, PROTOCOL_TCP, IPV4_PORTS, None),
    (None, JUMP_EQUAL, PROTOCOL_UDP, IPV4_PORTS, "drop"),
    (IPV4_PORTS, LOAD_HALF, IPV4_FRAGMENT_OFFSET, None, None),
    (None, JUMP_ANY_BIT, FRAGMENT_BITS, "drop", None),
    (None, LOAD_WORD, IPV4_DESTINATION_OFFSET, None, None),
    (None, JUMP_EQUAL, int.from_bytes(socket.inet_aton(EMBEDDED_RESOLVER)), "pass", None),
    (None, LOAD_HEADER_LENGTH_INTO_X, IPV4_HEADER_OFFSET, None, None),
    (None, LOAD_HALF_INDEXED, IPV4_HEADER_OFFSET, None, None),
    (None, JUMP_EQUAL, DNS_PORT, "pass", None),
    (None, LOAD_HALF_INDEXED, IPV4_HEADER_OFFSET + 2, None, None),
    (None, JUMP_EQUAL, DNS_PORT, "pass", "drop"),
    ("ipv6", LOAD_BYTE, IPV6_PROTOCOL_OFFSET, None, None),
    (None, JUMP_EQUAL, PROTOCOL_TCP, IPV6_PORTS, None),
    (None, JUMP_EQUAL, PROTOCOL_UDP, IPV6_PORTS, None),
    # The ports lie behind an extension header chain, which the filter cannot walk.
    *[(None, JUMP_EQUAL, header, "pass", None) for header in IPV6_EXTENSION_HEADERS],
    (None, RETURN, DROP_FRAME, None, None),
    (IPV6_PORTS, LOAD_HALF, IPV6_SOURCE_PORT_OFFSET, None, None),
    (None, JUMP_EQUAL, DNS_PORT, "pass", None),
    (None, LOAD_HALF, IPV6_SOURCE_PORT_OFFSET + 2, None, None),
    (None, JUMP_EQUAL, DNS_PORT, "pass", "drop"),
    ("pass", RETURN, PASS_FRAME, None, None),
    ("drop", RETURN, DROP_FRAME, None, None),
]


def assemble(steps: list[Step]) -> bytes:
    """The classic-BPF program (one struct sock_filter per step) of steps with labelled jumps."""
    at = {label: index for index, (label, *_) in enumerate(steps) if label}
    return b"".join(
        struct.pack(
            "HBBI",
            opcode,
            at[yes] - index - 1 if yes else 0,
            at[no] - index - 1 if no else 0,
            operand,
        )
        for index, (_, opcode, operand, yes, no) in enumerate(steps)
    )


def attach_filter(watcher: socket.socket, steps: list[Step]) -> None:
    """The kernel's classic-BPF filter for the socket."""
    program = assemble(steps)
    instructions = ctypes.create_string_buffer(program, len(program))
    address = ctypes.cast(instructions, ctypes.c_void_p).value
    descriptor = struct.pack("@HL", len(steps), address)
    watcher.setsockopt(socket.SOL_SOCKET, SO_ATTACH_FILTER, descriptor)


class Window:
    def __init__(self) -> None:
        self.frames = 0
        self.syns: list[dict] = []
        self.label_frames: dict[str, int] = {}
        self.query_frames: dict[str, int] = {}
        self.undecoded = 0
        self.one_question_frames: dict[str, int] = {}
        self.dns_messages = 0

    def see(self, segment: Segment, labels: list[str]) -> None:
        # Only a DNS window (it has labels) reads TCP port 53 for its question.
        if segment.undecoded or (labels and segment.partial_dns):
            self.undecoded += 1
        opens_a_connection = segment.protocol == PROTOCOL_TCP and (
            segment.flags & (TCP_SYN | TCP_ACK) == TCP_SYN
        )
        if segment.outgoing and opens_a_connection:
            self.syns.append(
                {
                    "at": segment.at,
                    "interface": segment.interface,
                    "destination": segment.destination,
                    "port": segment.destination_port,
                }
            )
        self.dns_messages += segment.dns
        for label in labels:
            if segment.question.split(".")[0] == label:
                # `litellm-db.<other>` matches too: the first label alone is the limit.
                if segment.one_question:
                    self.one_question_frames[label] = self.one_question_frames.get(label, 0) + 1
                self.label_frames[label] = self.label_frames.get(label, 0) + 1
                if segment.query:
                    self.query_frames[label] = self.query_frames.get(label, 0) + 1


def open_socket(steps: list[Step] | None) -> socket.socket:
    watcher = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    watcher.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, RECEIVE_BUFFER_BYTES)
    watcher.setsockopt(socket.SOL_SOCKET, SO_TIMESTAMPNS, 1)
    if steps:
        attach_filter(watcher, steps)
        # What queued before the filter was attached is not the window's.
        watcher.setblocking(False)
        with contextlib.suppress(BlockingIOError):
            while True:
                watcher.recv(READ_BYTES)
        read_statistics(watcher)
    watcher.settimeout(POLL_SECONDS)
    return watcher


def read_statistics(watcher: socket.socket) -> tuple[int, int]:
    """The kernel's counts for the socket since the last read: (packets seen, packets dropped)."""
    return struct.unpack("II", watcher.getsockopt(SOL_PACKET, PACKET_STATISTICS, 8))


def watch(
    watcher: socket.socket, labels: list[str], seconds: int = WINDOW_SECONDS
) -> tuple[Window, str]:
    window, deadline = Window(), time.monotonic() + seconds
    while window.frames < FRAME_CAP:
        if time.monotonic() >= deadline:
            return window, "seconds"
        try:
            frame, ancillary, flags, address = watcher.recvmsg(READ_BYTES, socket.CMSG_SPACE(16))
        except TimeoutError:
            continue
        window.frames += 1
        interface, _, packet_type, hardware_type, _ = address
        truncated = bool(flags & socket.MSG_TRUNC)
        if segment := parse(
            frame, interface, packet_type, hardware_type, kernel_time(ancillary), truncated
        ):
            window.see(segment, labels)
    return window, "frames"


def run(mode: str, labels: list[str], seconds: int = WINDOW_SECONDS) -> dict:
    watcher = open_socket(DNS_FILTER if mode == "dns" else None)
    print("ready", flush=True)
    started = time.time()
    window, ended_by = watch(watcher, labels, seconds)
    packets, drops = read_statistics(watcher)
    result = {
        "started_at": started,
        "ended_at": time.time(),
        "ended_by": ended_by,
        "frames": window.frames,
        "packets": packets,
        "drops": drops,
        "undecoded": window.undecoded,
    }
    if mode == "syn":
        return result | {"syns": window.syns}
    return result | {
        "labels": window.label_frames,
        "queries": window.query_frames,
        "one_question": window.one_question_frames,
        "dns_messages": window.dns_messages,
    }


def parse_arguments(arguments: list[str]) -> tuple[int, str, list[str]] | None:
    """The window's length in seconds, its mode and its labels; None for arguments that are none
    of the usages."""
    seconds = WINDOW_SECONDS
    if arguments[:1] == ["--seconds"]:
        if len(arguments) < 2 or not re.fullmatch(r"[1-9]\d{0,5}", arguments[1]):
            return None
        seconds, arguments = int(arguments[1]), arguments[2:]
    mode, labels = (arguments[0] if arguments else ""), [label.lower() for label in arguments[1:]]
    valid = (mode == "syn" and not labels) or (
        mode == "dns" and labels and all(LABEL.fullmatch(label) for label in labels)
    )
    return (seconds, mode, labels) if valid else None


def main(arguments: list[str]) -> int:
    if (parsed := parse_arguments(arguments)) is None:
        print(
            "usage: capture.py [--seconds N] syn | capture.py [--seconds N] dns LABEL [LABEL ...]",
            file=sys.stderr,
        )
        return 2
    seconds, mode, labels = parsed
    print(json.dumps(run(mode, labels, seconds)), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
