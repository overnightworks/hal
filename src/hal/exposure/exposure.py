"""What counts as exposed, and the findings that say so."""

import ipaddress
from dataclasses import dataclass
from enum import StrEnum

WILDCARD_ADDRESS = "*"


class UnreadableOutputError(ValueError):
    """`docker` or `ss` printed something the parser cannot read; the message names it."""


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"
    SCTP = "sctp"


class Problem(StrEnum):
    PUBLICATION_BEYOND_LOOPBACK = "publication-beyond-loopback"
    PUBLICATION_WITHOUT_HOST_IP = "publication-without-host-ip"
    LISTENER_BEYOND_LOOPBACK = "listener-beyond-loopback"
    ROUTED_WITHOUT_EDGE_NAME = "routed-without-edge-name"
    INVALID_EDGE_NAME = "invalid-edge-name"
    DUPLICATE_EDGE_NAME = "duplicate-edge-name"


@dataclass(frozen=True, order=True)
class PortRange:
    """A host port, or the range Docker may pick one from (`-p 127.0.0.1:8000-8010:80`)."""

    first: int
    last: int

    @classmethod
    def single(cls, port: int) -> PortRange:
        return cls(port, port)

    def contains(self, port: int) -> bool:
        return self.first <= port <= self.last

    def as_json(self) -> int | str:
        return self.first if self.first == self.last else f"{self.first}-{self.last}"


@dataclass(frozen=True)
class Finding:
    """A socket finding names protocol, address and port; an edge-name finding names neither."""

    problem: Problem
    subject: str
    protocol: Protocol | None = None
    address: str = ""
    port: PortRange | None = None
    edge_name: str | None = None

    def as_json(self) -> dict[str, str | int | None]:
        return {
            "problem": self.problem.value,
            "subject": self.subject,
            "protocol": None if self.protocol is None else self.protocol.value,
            "address": self.address,
            "port": None if self.port is None else self.port.as_json(),
            "edge_name": self.edge_name,
        }


def checked_address(address: str) -> str:
    """The address unchanged, once it is known to be an IP address or ss's `*` wildcard."""
    if address != WILDCARD_ADDRESS:
        ipaddress.ip_address(address)
    return address


def is_loopback(address: str) -> bool:
    if address == WILDCARD_ADDRESS:
        return False
    return ipaddress.ip_address(address).is_loopback


def ordered(findings: list[Finding]) -> list[Finding]:
    """Drop duplicates and sort, so two runs on the same state print the same list."""

    def sort_key(finding: Finding) -> tuple[str, str, str, str, PortRange, str]:
        port = PortRange.single(-1) if finding.port is None else finding.port
        return (
            finding.problem,
            finding.subject,
            finding.protocol or "",
            finding.address,
            port,
            finding.edge_name or "",
        )

    return sorted(set(findings), key=sort_key)
