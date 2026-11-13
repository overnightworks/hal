"""Probe of the apps' way to LiteLLM (#962 cells N2, Y1-Y5): the stack of litellm.py, its callers on
the three app networks of the probe's copy (`<project>_agent_<app>`), each with an app key of its
own. Nothing live and nothing paid: the probe refuses to start unless `internet` is internal and
holds only the fakes.

    probe-run -k 50 1780 \\
        python3 probe/agent-service/litellm_apps.py --scratch DIR

Evidence: F is the fake provider's request log, S `/key/info`, I `docker inspect`. "No
connection" is an outcome of `tcp_connect` in `egress_observe.UNREACHABLE`. A fake app is a
container that listens on one app network (agent_networks.start_caller); a request of an app is a
throwaway on its network that posts agent-runtime's wire body to `litellm-front:4000` by name.
Y5's holder claims the network alias `litellm` on HopIn's network and listens on LiteLLM's port;
the front, restarted so that its first dial resolves the name afresh, has its embedded resolver
hand the holder that name: the control that only the front's
`extra_hosts` keeps the route on LiteLLM. Exit 0: every cell held.
"""

from __future__ import annotations

import itertools
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "agent-service"))

from agent_networks import AGENT_NETWORKS, CALLER_PORT, start_caller  # noqa: E402
from egress_observe import UNREACHABLE  # noqa: E402
from litellm import (  # noqa: E402
    DATABASE,
    FRONT,
    FRONT_PORT,
    LABEL,
    LITELLM,
    PROJECT,
    ROUTE,
    START_DATABASE,
    LitellmProbe,
    ProbeFailed,
    expect,
    mounted_file,
    person_budget,
    run_scratch_probe,
)

SONGMAKER, _, HOPIN = AGENT_NETWORKS
FRONT_NETWORKS = (*AGENT_NETWORKS, "litellm-backend")
HOLDER = f"{PROJECT}-holder"
HOLDER_SECONDS = 60
# A listener that prints one line per connection it accepts. argv: port.
HOLDER_PROGRAM = """\
import socket, sys
server = socket.create_server(("0.0.0.0", int(sys.argv[1])))
while True:
    connection, _ = server.accept()
    print("accepted", flush=True)
    connection.close()
"""
# One A query to Docker's embedded resolver, never /etc/hosts. argv: name; prints {"addresses"}.
RESOLVER_PROGRAM = """\
import json, socket, struct, sys
labels = b"".join(bytes([len(part)]) + part.encode() for part in sys.argv[1].split("."))
query = struct.pack("!HHHHHH", 0x5EED, 0x0100, 1, 0, 0, 0) + labels + b"\\0\\0\\1\\0\\1"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as asking:
    asking.settimeout(4)
    asking.sendto(query, ("127.0.0.11", 53))
    reply = asking.recv(512)
index, addresses = 12 + len(labels) + 1 + 4, []
for _ in range(struct.unpack("!H", reply[6:8])[0]):
    if reply[index] & 0xC0 == 0xC0:
        index += 2
    else:
        while reply[index]:
            index += reply[index] + 1
        index += 1
    kind, _, _, length = struct.unpack("!HHIH", reply[index:index + 10])
    index += 10
    if kind == 1 and length == 4:
        addresses.append(socket.inet_ntoa(reply[index:index + 4]))
    index += length
print(json.dumps({"addresses": addresses}))
"""


class AppsProbe(LitellmProbe):
    """The stack of litellm.py, driven by one fake app per app network."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        start = mounted_file(resolved[LITELLM], resolved[LITELLM]["entrypoint"][0]).read_text()
        self.database_port = START_DATABASE.search(start)["port"]
        self.litellm_port = self.proxy_address.rsplit(":", 1)[1]

    def inspected(self, container: str) -> dict:
        return json.loads(self.run(["docker", "inspect", container]).stdout)[0]

    def address_of(self, container: str, network: str) -> str:
        """The address `container` holds on `<project>_<network>`."""
        networks = self.inspected(container)["NetworkSettings"]["Networks"]
        return networks[f"{PROJECT}_{network}"]["IPAddress"]

    def from_app(self, network: str, key: str) -> dict:
        """A: one request of the app on `network` through the front, with its key."""
        return self.complete(key, user=self.fingerprint(), network=network)

    def reached(self, container: str, address: str, port: str) -> str:
        return self.client_in_namespace_of(container, "connect", address, port)["result"]

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until_listening()
        self.cell_n2()
        self.admin("POST", "/budget/new", person_budget())
        keys = {network: self.make_key() for network in AGENT_NETWORKS}
        self.cells_y1_y2(keys)
        apps = {network: f"{PROJECT}-app-{network}" for network in AGENT_NETWORKS}
        addresses = {
            network: start_caller(self, PROJECT, LABEL, network, name)
            for network, name in apps.items()
        }
        self.cell_y3(apps)
        self.cell_y4(apps, addresses)
        self.cell_y5(keys)

    def cell_n2(self) -> None:
        front = self.inspected(self.container(FRONT))
        joined = set(front["NetworkSettings"]["Networks"])
        wanted = {f"{PROJECT}_{network}" for network in FRONT_NETWORKS}
        expect(joined == wanted, f"N2: the front is on {sorted(joined)}, not {sorted(wanted)}")
        apps = {f"{PROJECT}_{network}" for network in AGENT_NETWORKS}
        for service in (FRONT, LITELLM, DATABASE):
            container = self.inspected(self.container(service))
            expect(not container["HostConfig"]["PortBindings"], f"N2: {service} publishes a port")
            if service != FRONT:
                on = set(container["NetworkSettings"]["Networks"]) & apps
                expect(not on, f"N2: {service} is on the app networks {sorted(on)}")
        self.hold("N2", f"the front is on {', '.join(sorted(wanted))} and nothing else; LiteLLM "
                  "and its database on no app network; no published port")  # fmt: skip

    def cells_y1_y2(self, keys: dict[str, str]) -> None:
        spends = []
        for network, key in keys.items():
            before = {other: self.key_info(other)["spend"] for other in keys.values()}
            sent = len(self.provider_requests())
            answer = self.from_app(network, key)
            self.served("Y1", answer, self.provider_requests()[sent:])
            self.wait_for("Y2", f"the spend of {network}'s key",
                          lambda key=key: self.key_info(key)["spend"] > 0)  # fmt: skip
            after = {other: self.key_info(other)["spend"] for other in keys.values()}
            others = {other: spend for other, spend in after.items() if other != key}
            expect(
                others == {other: before[other] for other in others},
                f"Y2: {network}'s request moved another key's spend",
            )
            spends.append(f"{network} {before[key]} -> {after[key]}")
        self.hold("Y1", f"each of {', '.join(keys)} through litellm-front:4000 with its own key: "
                  "200 with the marker, F one request with the mapped id")  # fmt: skip
        self.hold("Y2", f"each request counts on its own key alone: {'; '.join(spends)}")

    def cell_y3(self, apps: dict[str, str]) -> None:
        litellm, front = self.container(LITELLM), self.container(FRONT)
        upstream = self.address_of(litellm, "litellm-backend")
        database = self.address_of(self.container(DATABASE), "litellm-db")
        for network, app in apps.items():
            for name in (LITELLM, DATABASE):
                found = self.client_in_namespace_of(app, "resolve", name)["addresses"]
                expect(not found, f"Y3: {network} resolves {name} to {found}")
            for address, port in ((upstream, self.litellm_port), (database, self.database_port)):
                seen = self.reached(app, address, port)
                expect(seen in UNREACHABLE, f"Y3: {network} reaches {address}:{port}: {seen}")
        controls = {
            "the front to LiteLLM": self.reached(front, upstream, self.litellm_port),
            "LiteLLM to its database": self.reached(litellm, database, self.database_port),
        }
        expect(set(controls.values()) == {"connected"}, f"Y3: controls {controls}")
        self.hold("Y3", f"no app resolves {LITELLM} or {DATABASE} or connects to {upstream}:"
                  f"{self.litellm_port} or {database}:{self.database_port}; controls: "
                  f"{', '.join(controls)} connected")  # fmt: skip

    def cell_y4(self, apps: dict[str, str], addresses: dict[str, str]) -> None:
        for caller, other in itertools.permutations(AGENT_NETWORKS, 2):
            seen = self.reached(apps[caller], addresses[other], str(CALLER_PORT))
            expect(seen in UNREACHABLE, f"Y4: {caller} reaches {other}'s port: {seen}")
            found = self.client_in_namespace_of(apps[caller], "resolve", apps[other])["addresses"]
            expect(not found, f"Y4: {caller} resolves {apps[other]} to {found}")
        for network, app in apps.items():
            seen = self.reached(app, FRONT, str(FRONT_PORT))
            expect(seen == "connected", f"Y4: {network} -> {FRONT}:{FRONT_PORT}: {seen}")
        self.hold("Y4", f"the fake apps on {', '.join(AGENT_NETWORKS)} reach neither another's "
                  f"port nor its name; each reaches {FRONT}:{FRONT_PORT}")  # fmt: skip

    def cell_y5(self, keys: dict[str, str]) -> None:
        front = self.container(FRONT)
        self.run(
            ["docker", "run", "--detach", "--name", HOLDER, "--label", LABEL,
             f"--network={PROJECT}_{HOPIN}", "--network-alias", LITELLM, "--read-only",
             "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt",
             "no-new-privileges:true", "--entrypoint", "python", self.image, "-I", "-c",
             HOLDER_PROGRAM, self.litellm_port]
        )  # fmt: skip
        self.wait_for("Y5", "the holder listening", lambda: self.reached(
            HOLDER, "127.0.0.1", self.litellm_port) == "connected", HOLDER_SECONDS)  # fmt: skip
        holder = self.address_of(HOLDER, HOPIN)
        # A fresh front has no pooled connection to LiteLLM, so its first dial resolves the name.
        self.run(["docker", "restart", front])
        self.wait_for("Y5", "the restarted front routing", self.front_routes, HOLDER_SECONDS)
        answered = self.throwaway([f"--network=container:{front}"], [LITELLM], RESOLVER_PROGRAM)[
            "addresses"
        ]
        expect(holder in answered, f"Y5: the front's resolver answers {LITELLM} with {answered}")
        upstream = self.address_of(self.container(LITELLM), "litellm-backend")
        extra_hosts = self.inspected(front)["HostConfig"]["ExtraHosts"]
        mapped = [entry.replace("=", ":", 1) for entry in extra_hosts]  # either form Docker takes
        expect(mapped == [f"{LITELLM}:{upstream}"], f"Y5: the front maps {extra_hosts}")
        accepted = self.holder_connections()
        sent = len(self.provider_requests())
        answer = self.from_app(SONGMAKER, keys[SONGMAKER])
        self.served("Y5", answer, self.provider_requests()[sent:])
        expect(self.holder_connections() == accepted, "Y5: the holder received a connection")
        self.hold("Y5", f"the front's resolver answers {LITELLM} with the holder's {holder}; the "
                  f"front maps {LITELLM} to {upstream}; {SONGMAKER}'s request served by LiteLLM, F "
                  "one request; the holder received no connection")  # fmt: skip

    def front_routes(self) -> bool:
        """True once the front refuses a query string itself, which no connection to LiteLLM
        precedes: its route is loaded and nothing is pooled."""
        try:
            return self.complete(None, network=SONGMAKER, path=f"{ROUTE}?probe")["status"] == 400
        except ProbeFailed:
            return False

    def holder_connections(self) -> int:
        return self.run(["docker", "logs", HOLDER]).stdout.count("accepted")


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], AppsProbe)


if __name__ == "__main__":
    sys.exit(main())
