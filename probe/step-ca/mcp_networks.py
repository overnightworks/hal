"""The MCP networks' split (proof 7) and the probe's verdict. A mixin of the step-ca probe
(probe.py): it uses the probe's client and image helpers."""

from __future__ import annotations

from pathlib import Path

from edge_copy import DISCARD_OUTPUT, expect
from step_ca_names import (
    BACKEND_URL,
    CA_HEALTH_URL,
    CONTAINER_USER,
    COULD_NOT_RESOLVE,
    ORIGIN_URL,
    ROOT_IN_CLIENT,
)

from hal.output import write_line

INCOMPLETE_EXIT_CODE = 2  # a cell was not driven: neither a pass nor a failure


def print_verdict(not_driven: list[str]) -> int:
    """PROBE PASSED only when every cell was driven; a cell that could not run is not held."""
    if not_driven:
        write_line(f"PROBE INCOMPLETE: not driven: {'; '.join(not_driven)}")
        return INCOMPLETE_EXIT_CODE
    write_line("PROBE PASSED: proofs 1-13 and #95 P3 hold")
    return 0


class McpNetworks:
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
