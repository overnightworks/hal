"""The agent networks of compose.yaml in the LiteLLM probes: one caller per app's network."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from edge_copy import expect

if TYPE_CHECKING:
    from litellm_stack import StackProbe

# `hal_agent_<app>` of compose.yaml, as the probe's copy names them: `<project>_agent_<app>`.
# The probes drive only these, which keep one app from another.
AGENT_NETWORKS = ("agent_songmaker", "agent_presentator", "agent_hopin")
CALLER_PORT = 8000
READY_SECONDS = 90
EMBEDDED_RESOLVER = "127.0.0.11"


def listeners_of(probe: StackProbe, service: str) -> dict[str, list[str]]:
    """The TCP and UDP sockets `service` has open in its own namespace."""
    found = probe.client_in_namespace_of(probe.container(service), "listeners")
    # Docker's embedded resolver listens on this loopback address in every container's own
    # namespace; no other container can reach it.
    return {
        protocol: [name for name in names if not name.startswith(EMBEDDED_RESOLVER + ":")]
        for protocol, names in found.items()
    }


def gateway_listeners(probe: StackProbe, gateway: str, expected_addresses: list[str]) -> None:
    """The gateway listens on exactly `expected_addresses` (each `address:port`) over TCP and holds
    no UDP socket. The probe copy's static file names the addresses."""
    found = listeners_of(probe, gateway)
    expect(sorted(found["tcp"]) == sorted(expected_addresses), f"listeners: TCP {found['tcp']}")
    expect(found["udp"] == [], f"listeners: UDP sockets {found['udp']}")


def start_caller(probe: StackProbe, project: str, label: str, network: str, name: str) -> str:
    """A container that listens on CALLER_PORT on one agent network, removed with the stack (its
    label); its address there."""
    probe.run(
        ["docker", "run", "--detach", "--name", name, "--label", label,
         f"--network={project}_{network}", "--read-only", "--user", "65534:65534",
         "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--entrypoint",
         "python", probe.image, "-I", "-m", "http.server", str(CALLER_PORT)]
    )  # fmt: skip
    deadline = time.monotonic() + READY_SECONDS
    while (
        probe.client_in_namespace_of(name, "connect", "127.0.0.1", str(CALLER_PORT))["result"]
        != "connected"
    ):
        expect(time.monotonic() < deadline, f"{name} does not listen")
        time.sleep(1)
    address_of = f'{{{{(index .NetworkSettings.Networks "{project}_{network}").IPAddress}}}}'
    return probe.run(["docker", "inspect", "--format", address_of, name]).stdout.strip()
