"""Probe of the agent service's API route through LiteLLM (#768 S1a cells G1-G15, N1, L1-L3, R1,
R2): the real service, its one-route front, LiteLLM and the gateway's second entrypoint, in a
throwaway compose project, against a fake Anthropic. Nothing live and nothing paid: the probe
refuses to start unless the resolved copy marks `internet` internal and holds only the two fake
hosts, and it never calls `egress.py`'s live cells.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm.py --scratch DIR

Measured: a run takes about a minute and its teardown a few seconds (K 30 s, CAP 1800 s).

The scratch HOME holds the throwaway secrets (random values, never printed): the provider key,
the service credential, the CA and the signing pair. The fake provider (alias api.anthropic.com)
and the fake issuer (alias auth.hallucinai.de) hold certificates of the scratch CA, which
LiteLLM's SSL_CERT_FILE trusts. The scratch HOME also holds LiteLLM's master key file.

Evidence: F is the fake provider's request log, R the canary's verdict lines, I `docker inspect`,
LA LiteLLM's access log. The probe differs from production in LiteLLM's log level: compose.yaml sets
`CRITICAL`, which prints no access line, so this probe sets `INFO` for LA (LITELLM_LOG_LEVEL;
litellm_retention.py leaves the shipped level). Exit 0: every cell held.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "agent-service"))

from agent_networks import EMBEDDED_RESOLVER, gateway_listeners, listeners_of  # noqa: E402
from api_canary import verdicts  # noqa: E402
from egress import LABEL, PROJECT, ProbeFailed, expect, run_scratch_probe  # noqa: E402
from egress_observe import socket_name  # noqa: E402
from issuer import ISSUER_ORIGIN, ISSUER_SERVICE, SERVICE, IssuerProbe  # noqa: E402
from refusals import API_GROUP  # noqa: E402
from retention_census import DATABASE, FRONT, GATEWAY, LITELLM  # noqa: E402
from scratch_secrets import issue_certificate, write_new  # noqa: E402

FAKE_PROVIDER, FAKE_ISSUER, CANARY = "fake-anthropic", "fake-issuer", "agent-canary"
PROVIDER_HOST, ISSUER_HOST = "api.anthropic.com", "auth.hallucinai.de"
NEW_NETWORKS = ("litellm-api", "litellm-backend", "litellm-egress", "litellm-db")
ISOLATED = "isolated"
LISTEN_SECONDS = 60
CANARY_SECONDS = 240
FAKE_DIRECTORY = "/fake"
DEFAULT_APP, REMAPPED_APP, REMAPPED_MODEL = "songmaker", "hopin", "nonesuch"
ACCESS_LINE = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP/\d(?:\.\d)?"')
ADMITTED_LINE = re.compile(r'"POST /v1/chat/completions HTTP/\d(?:\.\d)?" 200')
ROUTE = "/v1/chat/completions"
LISTENING = "Uvicorn running"
FRONT_STATIC = "/etc/traefik/traefik.yml"
ENTRYPOINT_ADDRESS = re.compile(r'address:\s*"([^"]+)"')
START_LISTENER = re.compile(r"--host (\S+) --port (\d+)")
# The database service and port as start.sh's DATABASE_URL names them.
START_DATABASE = re.compile(r"@(?P<service>[\w-]+):(?P<port>\d+)/")
WILDCARD_SOCKETS = ("0.0.0.0", "[::]")  # noqa: S104 - names the listener addresses the probe accepts and binds none
LOOPBACK_ADDRESS = "127.0.0.1"
# The secret files under the scratch HOME, where compose.yaml's `secrets` read them.
PROVIDER_KEY_FILE = Path(".secrets/litellm/anthropic")
MASTER_KEY_FILE = Path(".secrets/litellm/master-key")
DATABASE_PASSWORD_FILE = Path(".secrets/litellm/db-password")
CREDENTIAL_FILE = Path(".secrets/agent-service/api/credential.json")
# The processes of the container and its listening TCP sockets in one snapshot: argv: none; prints
# {"processes": {pid: {parent, executable}}, "listeners": [{address, version, owners: [pid]}]}, the
# address in /proc/net's hexadecimal. A process or descriptor that vanishes mid-scan repeats the
# scan; a scan that never completes ends non-zero.
SNAPSHOT_PROGRAM = """\
import json, os, sys, time
def scan():
    processes, held = {}, {}
    for entry in filter(str.isdigit, os.listdir("/proc")):
        if int(entry) == os.getpid():
            continue
        fields = open(f"/proc/{entry}/stat").read().rpartition(")")[2].split()
        processes[entry] = {
            "parent": int(fields[1]), "executable": os.readlink(f"/proc/{entry}/exe"),
        }
        for fd in os.listdir(f"/proc/{entry}/fd"):
            target = os.readlink(f"/proc/{entry}/fd/{fd}")
            if target.startswith("socket:["):
                held.setdefault(target[8:-1], []).append(int(entry))
    listeners = []
    for table, version in (("tcp", 4), ("tcp6", 6)):
        for row in (line.split() for line in open(f"/proc/net/{table}").read().splitlines()[1:]):
            if row[3] == "0A":
                owners = held.get(row[9], [])
                listeners.append({"address": row[1], "version": version, "owners": owners})
    return {"processes": processes, "listeners": listeners}
for _ in range(50):
    try:
        print(json.dumps(scan()))
        break
    except OSError:
        time.sleep(0.1)
else:
    sys.exit("the processes of the container never stood still for one scan")
"""
# The query engine path Prisma's client resolves for the proxy, from the image and not from a
# running process: prints the version check of the binary, then the path on the last line.
ENGINE_PATH_PROGRAM = """\
import os
from prisma.client import BINARY_PATHS
from prisma.engine import utils
print(os.path.realpath(utils.ensure(BINARY_PATHS.query_engine)))
"""
HTTP_PROGRAM = """\
import json, socket, sys
method, path, bearer, body = sys.argv[1:5]
head = f"{method} {path} HTTP/1.1\\r\\nHost: litellm-front:4000\\r\\nConnection: close\\r\\n"
if bearer != "-":
    head += f"Authorization: Bearer {bearer}\\r\\n"
payload = b"" if body == "-" else body.encode()
head += f"Content-Type: application/json\\r\\nContent-Length: {len(payload)}\\r\\n\\r\\n"
with socket.create_connection(("litellm-front", 4000), timeout=60) as raw:
    raw.sendall(head.encode() + payload)
    reply = b""
    while chunk := raw.recv(65536):
        reply += chunk
print(json.dumps({"status": int(reply.split(b" ", 2)[1])}))
"""
# The step-ca root inside a client container, at the path of compose.yaml's secret mount.
CA_IN_CLIENT = "/run/secrets/step_ca_root_certificate"
TLS_PROGRAM = f"""\
import json, socket, ssl, sys
address, name = sys.argv[1:3]
context = ssl.create_default_context(cafile="{CA_IN_CLIENT}")
with socket.create_connection((address, 443), timeout=10) as raw:
    with context.wrap_socket(raw, server_hostname=name) as secured:
        certificate = secured.getpeercert()
subject = dict(pair[0] for pair in certificate["subject"])
issuer = dict(pair[0] for pair in certificate["issuer"])
print(json.dumps({{"subject": subject["commonName"], "issuer": issuer["commonName"]}}))
"""


def mounted_file(service: dict, target: str) -> Path:
    """The host file the resolved compose `service` binds at `target`."""
    (source,) = [m["source"] for m in service["volumes"] if m["target"] == target]
    return Path(source)


def bound_names(declared: str) -> list[list[str]]:
    """The TCP listener lists that bind the declared `host:port`, as `listeners_of` names them: the
    declared address exactly, or for an unspecified host (`:port`) one IPv4 or IPv6 wildcard."""
    host, port = declared.rsplit(":", 1)
    if host:
        return [[declared]]
    return [[f"{wildcard}:{port}"] for wildcard in WILDCARD_SOCKETS]


def named_sockets(listeners: list[dict]) -> list[tuple[str, list[int]]]:
    """Each listening socket as `listeners_of` names it with the pids that hold it, without Docker's
    embedded resolver, which listens in every container's namespace."""
    named = [
        (socket_name(entry["address"], entry["version"]), entry["owners"]) for entry in listeners
    ]
    resolver = EMBEDDED_RESOLVER + ":"
    return [(name, owners) for name, owners in named if not name.startswith(resolver)]


@dataclass(frozen=True)
class ProxySnapshot:
    """LiteLLM's listening TCP sockets as one scan of the container saw them."""

    proxies: frozenset[int]  # the owners of the declared proxy address
    engines: dict[int, list[str]]  # each query engine child of a proxy, with its socket names
    outside: list[str]  # the sockets no query engine owns

    @property
    def listening(self) -> bool:
        return bool(self.proxies)


class LitellmProbe(IssuerProbe):
    """The service with an API-only person, the front, LiteLLM and a fake Anthropic."""

    LITELLM_LOG_LEVEL: str | None = "INFO"  # None keeps the level compose.yaml ships

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.profiles = (*self.profiles, "litellm")
        # The throwaway clients and the fakes run the stand-in's plain Python, not the service image
        # IssuerProbe resolved (whose entrypoint is the service).
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        self.image = resolved["services"]["agent-probe"]["image"]
        home = Path(self.environment["HOME"])
        self.provider_key = secrets.token_urlsafe(32)
        self.credential = secrets.token_urlsafe(32)
        self.marker = secrets.token_hex(8)
        self.identity = {
            name: f"{name}-{secrets.token_hex(6)}" for name in ("sub", "username", "email")
        }
        self.database_password = secrets.token_urlsafe(32)
        self.write_secrets(home)
        self.fake = scratch / "fake"
        self.write_fakes(self.fake)
        self.litellm_config = scratch / "litellm.yaml"
        shipped = (REPO / "agent-service" / "litellm" / "config.yaml").read_text(encoding="utf-8")
        self.litellm_config.write_text(shipped, encoding="utf-8")
        self.litellm_config.chmod(0o644)
        self.write_service_configuration()
        self.overlays.append(self.write_overlay(scratch))
        self.expect_fake_only()

    # --- the scratch files --------------------------------------------------------------------

    def write_secrets(self, home: Path) -> None:
        for relative, text in (
            (PROVIDER_KEY_FILE, self.provider_key + "\n"),
            (MASTER_KEY_FILE, f"sk-{secrets.token_hex(32)}\n"),
            (CREDENTIAL_FILE, json.dumps({"shared_key": self.credential})),
            (DATABASE_PASSWORD_FILE, self.database_password + "\n"),
        ):
            folder = home
            for part in relative.parent.parts:
                folder /= part
                folder.mkdir(exist_ok=True)
                folder.chmod(0o700)
            # The database user is not the probe's: it reads the password as the live file's
            # loosest_mode allows, inside the 0700 folder.
            mode = 0o644 if relative == DATABASE_PASSWORD_FILE else 0o600
            write_new(home / relative, text.encode(), mode)

    def write_fakes(self, directory: Path) -> None:
        """One directory per fake host: its certificate and key, what it checks and its program."""
        directory.mkdir()
        expectations = json.dumps({
            "provider_key": self.provider_key, "credential": self.credential,
            "identity": [*self.identity.values(), DEFAULT_APP, REMAPPED_APP],
            "marker": self.marker,
        })  # fmt: skip
        program = (Path(__file__).resolve().parent / "fake_anthropic.py").read_text(
            encoding="utf-8"
        )
        for host in (PROVIDER_HOST, ISSUER_HOST):
            issue_certificate(self.scratch_secrets, host, directory / host)
            (directory / host / "expect.json").write_text(expectations, encoding="utf-8")
            (directory / host / "fake_anthropic.py").write_text(program, encoding="utf-8")
            (directory / host).chmod(0o755)
            for file in (directory / host).iterdir():
                file.chmod(0o644)
        directory.chmod(0o755)

    def write_service_configuration(self) -> None:
        """The issuer's scratch service.toml, with the API route and a model LiteLLM lacks for one
        app."""
        text = self.configuration.read_text(encoding="utf-8")
        text = text.replace(
            "[cli.anthropic]",
            "[cli.anthropic]\n# probe: a name the service lists and LiteLLM lacks",
        ).replace(
            'models = ["opus", "sonnet", "haiku"]',
            'models = ["opus", "sonnet", "haiku", "nonesuch"]',
        )
        text = text.replace(
            'group_claim = "groups"', f'group_claim = "groups"\napi_groups = ["{API_GROUP}"]'
        )
        text = text.replace(
            "[apps.hopin]\n", f'[apps.hopin]\nmodel = "anthropic/{REMAPPED_MODEL}"\n'
        )
        text += (
            '\n[api]\ncompletion_url = "http://litellm-front:4000/v1/chat/completions"\n'
            'credential_file = "/run/secrets/agent_service_api_credential"\n'
        )
        self.configuration.write_text(text, encoding="utf-8")

    def write_overlay(self, scratch: Path) -> Path:
        hardened = {
            "profiles": ["litellm"], "user": "65534:65534", "read_only": True,
            "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"], "restart": "no",
        }  # fmt: skip

        def fake(role: str, host: str) -> dict:
            return {
                **hardened, "image": self.image,
                "sysctls": {"net.ipv4.ip_unprivileged_port_start": 0},
                "networks": {"internet": {"aliases": [host]}},
                "entrypoint": ["python", "-I", "-B", f"{FAKE_DIRECTORY}/fake_anthropic.py", role],
                "volumes": [
                    {"type": "bind", "source": str(self.fake / host), "target": FAKE_DIRECTORY,
                     "read_only": True},
                ],
            }  # fmt: skip

        level = self.LITELLM_LOG_LEVEL
        log_level = {"LITELLM_LOG": level} if level else {}
        overlay = scratch / "compose.litellm.yaml"
        overlay.write_text(
            json.dumps({
                "services": {
                    SERVICE: {"secrets": ["agent_service_api_credential"]},
                    LITELLM: {
                        "environment": {
                            "SSL_CERT_FILE": "/probe/ca.crt",
                            **log_level,
                        },
                        "volumes": [
                            {"type": "bind", "source": str(self.litellm_config),
                             "target": "/etc/litellm/config.yaml", "read_only": True},
                            {"type": "bind", "source": str(self.scratch_secrets.ca_certificate),
                             "target": "/probe/ca.crt", "read_only": True},
                        ],
                    },
                    FAKE_PROVIDER: fake("provider", PROVIDER_HOST),
                    FAKE_ISSUER: fake("issuer", ISSUER_HOST),
                },
                "networks": {"internet": {"internal": True}},
            }),
            encoding="utf-8",
        )  # fmt: skip
        return overlay

    def expect_fake_only(self) -> None:
        """Refuses to go on unless `internet` is internal and only the gateway and the two fake
        hosts are on it."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        on_internet = {
            name for name, service in resolved["services"].items()
            if "internet" in service.get("networks", {})
        }  # fmt: skip
        expect(resolved["networks"]["internet"].get("internal") is True, "internet is not internal")
        expect(
            on_internet == {GATEWAY, FAKE_PROVIDER, FAKE_ISSUER},
            f"internet holds {sorted(on_internet)}, not the gateway and the two fake hosts",
        )

    # --- life cycle ---------------------------------------------------------------------------

    def services_to_start(self) -> tuple[str, ...]:
        return (
            GATEWAY,
            SERVICE,
            ISSUER_SERVICE,
            FAKE_PROVIDER,
            FAKE_ISSUER,
            FRONT,
            DATABASE,
            LITELLM,
        )

    def log_of(self, service: str) -> str:
        return self.container_log(service, container=self.container(service))

    def wait_until(self, service: str, line: str, seconds: int = LISTEN_SECONDS) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if line in self.log_of(service):
                return
            time.sleep(1)
        last = " | ".join(self.log_of(service).strip().splitlines()[-3:])
        raise ProbeFailed(f"{service} did not print {line!r} in {seconds} seconds: {last[-600:]}")

    # --- evidence -----------------------------------------------------------------------------

    def provider_requests(self) -> list[dict]:
        lines = self.log_of(FAKE_PROVIDER).splitlines()
        return [json.loads(line) for line in lines if line.startswith("{")]

    def access_lines(self) -> list[str]:
        return [line for line in self.log_of(LITELLM).splitlines() if ACCESS_LINE.search(line)]

    def canary_input(self, app: str) -> str:
        """The two tokens of a person of the API group alone, as the canary reads them."""
        claims = {
            "sub": self.identity["sub"], "preferred_username": self.identity["username"],
            "email": self.identity["email"], "azp": app, "groups": [f"/apps/{app}", API_GROUP],
        }  # fmt: skip
        issuer = f"{ISSUER_ORIGIN}/realms/hallucinai"
        person = self.issuer.token(issuer, claims)
        workload = self.issuer.token(
            issuer,
            {"sub": "workload", "azp": app, "client_id": app,
             "realm_access": {"roles": ["agent-workload"]}},
        )  # fmt: skip
        return f"{person}\n{workload}\n"

    def canary_command(self, options: tuple[str, ...] = ()) -> list[str]:
        return self.compose_command(
            "run", "--rm", "-T", "--no-deps", "--label", LABEL, CANARY,
            "--marker", self.marker, *options,
        )  # fmt: skip

    def canary(self, app: str, options: tuple[str, ...] = ()) -> dict[str, str]:
        """R: the canary's verdict lines of one run of `app` by a person of the API group alone."""
        result = self.run(
            self.canary_command(options), stdin=self.canary_input(app), check=False,
            timeout=CANARY_SECONDS,
        )  # fmt: skip
        return verdicts(result.stdout, result.returncode)

    def steer_fake(self, **steering: object) -> None:
        """Writes the provider fake's control file; the fake re-reads it on every request."""
        folder = self.fake / PROVIDER_HOST
        draft = folder / "control.json.new"
        draft.write_text(json.dumps(steering), encoding="utf-8")
        draft.chmod(0o644)
        draft.replace(folder / "control.json")

    def recreate_litellm(self) -> None:
        self.compose(
            "up", "--detach", "--wait", "--force-recreate", "--no-deps", LITELLM, timeout=300
        )
        self.wait_until(LITELLM, LISTENING)

    def http(self, method: str, path: str, bearer: str | None = None, body: dict | None = None):
        """The status of one raw request from a throwaway on `litellm-api`, through the front."""
        arguments = [method, path, bearer or "-", "-" if body is None else json.dumps(body)]
        network = f"--network={PROJECT}_litellm-api"
        return self.throwaway([network], arguments, HTTP_PROGRAM)["status"]

    def good_body(self) -> dict:
        return {"model": "anthropic/opus", "messages": [], "tools": []}

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until(SERVICE, LISTENING)
        self.wait_until(LITELLM, LISTENING)
        self.cell_d1()
        self.cell_n1()
        self.cells_listeners()
        self.cells_r1_r2()
        self.cells_g1_to_g3_g10()
        for cell, method, path in (
            ("G6", "GET", ROUTE), ("G7", "POST", "/key/generate"),
            ("G8", "POST", "/mcp/"), ("G9", "POST", "/register"),
        ):  # fmt: skip
            self.cell_unreachable(cell, method, path)
        self.cells_g11_to_g15()
        self.cell_g5()
        self.cell_g4()

    def model_id(self, text: str, name: str = "anthropic/opus") -> str:
        found = re.search(
            rf"model_name: {re.escape(name)}\n\s+litellm_params:\n\s+model: \S+/(\S+)", text
        )
        expect(found is not None, f"config.yaml names no model {name}")
        return found[1]

    def cells_g1_to_g3_g10(self) -> None:
        before_f, before_la = len(self.provider_requests()), len(self.access_lines())
        run = self.canary(DEFAULT_APP)
        expect(run.get("exit") == "0" and run.get("marker") == "yes", f"G1: {run}")
        sent = self.provider_requests()[before_f:]
        expect(len(sent) == 1, f"G1: the fake provider got {len(sent)} requests")
        shipped = (REPO / "agent-service" / "litellm" / "config.yaml").read_text(encoding="utf-8")
        expect(sent[0]["model"] == self.model_id(shipped), f"G1: model {sent[0]['model']}")
        expect(sent[0]["key_ok"], "G1: the provider key did not arrive")
        self.hold("G1", "succeeded, marker in the answer, one request, mapped id, key equal")
        expect(sent[0]["identity_hits"] == 0, f"G2: {sent[0]['identity_hits']} identity matches")
        expect(sent[0]["jwt_hits"] == 0 and sent[0]["uuid_hits"] == 0, "G2: a token or id arrived")
        self.hold("G2", "no identity string, token or run id at the fake provider")
        expect(not sent[0]["authorization"] and not sent[0]["credential_bytes"], "G3: credential")
        self.hold("G3", "no Authorization header and no credential bytes at the fake provider")
        admitted = [line for line in self.access_lines()[before_la:] if ADMITTED_LINE.search(line)]
        expect(len(admitted) == 1, f"G10: {len(admitted)} admitted lines in LiteLLM's log")
        self.hold("G10", "the admitted request shows once as POST /v1/chat/completions 200")

    def cell_unreachable(self, cell: str, method: str, path: str) -> None:
        before = len(self.access_lines())
        status = self.http(method, path, self.credential, self.good_body())
        expect(status == 404, f"{cell}: status {status}")
        expect(len(self.access_lines()) == before, f"{cell}: LiteLLM's log grew")
        self.hold(cell, f"{method} {path} through the front: 404, LiteLLM saw nothing")

    def cells_g11_to_g15(self) -> None:
        wrong = secrets.token_urlsafe(24)
        cases = (
            ("G11", f"{ROUTE}?model=x", self.credential, self.good_body(), 401),
            ("G12", ROUTE, None, self.good_body(), 401),
            ("G13", ROUTE, wrong, self.good_body(), 401),
            ("G14", ROUTE, self.credential, {**self.good_body(), "api_base": "x"}, 401),
            ("G15", ROUTE, self.credential, {**self.good_body(), "fallbacks": ["x"]}, 401),
        )  # fmt: skip
        for cell, path, bearer, body, wanted in cases:
            before = len(self.provider_requests())
            status = self.http("POST", path, bearer, body)
            expect(status == wanted, f"{cell}: status {status}, wanted {wanted}")
            expect(len(self.provider_requests()) == before, f"{cell}: the provider was reached")
            self.hold(cell, f"{wanted} and the fake provider saw nothing")

    def cell_g5(self) -> None:
        before = len(self.provider_requests())
        run = self.canary(REMAPPED_APP)
        expect(run.get("code") == "provider_unavailable", f"G5: {run}")
        expect(len(self.provider_requests()) == before, "G5: the provider was reached")
        self.hold("G5", "a model LiteLLM lacks ends failed: provider_unavailable, provider 0")

    def cell_g4(self) -> None:
        text = self.litellm_config.read_text(encoding="utf-8")
        old = self.model_id(text)
        new = self.model_id(text, "anthropic/sonnet")
        expect(old != new, "G4: the two families share an id")
        self.litellm_config.write_text(text.replace(f"anthropic/{old}", f"anthropic/{new}", 1))
        self.recreate_litellm()
        before = len(self.provider_requests())
        run = self.canary(DEFAULT_APP)
        sent = self.provider_requests()[before:]
        expect(run.get("exit") == "0" and [r["model"] for r in sent] == [new], f"G4: {run} {sent}")
        self.hold("G4", "a remapped config reaches LiteLLM after its recreate")

    def cell_d1(self) -> None:
        """LiteLLM runs as its configured user on a read-only root, and its migrations are done."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        container = json.loads(self.run(["docker", "inspect", self.container(LITELLM)]).stdout)[0]
        user = resolved[LITELLM]["user"]
        expect(
            container["Config"]["User"] == user,
            f"D1: LiteLLM runs as {container['Config']['User']}",
        )
        expect(container["HostConfig"]["ReadonlyRootfs"] is True, "D1: the root is writable")
        counted = self.sql(
            "SELECT count(finished_at), count(*) FROM _prisma_migrations",
            "--tuples-only", "--no-align",
        ).stdout.strip()  # fmt: skip
        finished, total = (int(number) for number in counted.split("|"))
        expect(total > 0 and finished == total, f"D1: {finished} of {total} migrations finished")
        self.hold("D1", f"LiteLLM runs as {user} on a read-only root; {finished} of {total} "
                  "migrations finished")  # fmt: skip

    def database_options(self) -> list[str]:
        """The user and database `compose.yaml` gives `litellm-db`, as the options of psql and
        pg_dump."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        environment = resolved[DATABASE]["environment"]
        return [
            f"--username={environment['POSTGRES_USER']}",
            f"--dbname={environment['POSTGRES_DB']}",
        ]

    def sql(self, statement: str, *options: str) -> subprocess.CompletedProcess:
        return self.run([
            "docker", "exec", self.container(DATABASE), "psql", *self.database_options(),
            *options, "--command", statement,
        ])  # fmt: skip

    def cell_n1(self) -> None:
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        members = (SERVICE, FRONT, LITELLM, GATEWAY, DATABASE)
        for service in members:
            container = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[
                0
            ]
            joined = set(container["NetworkSettings"]["Networks"])
            wanted = {
                resolved["networks"][key]["name"]
                for key in resolved["services"][service]["networks"]
            }
            expect(joined == wanted, f"N1: {service} is on {sorted(joined)}, not {sorted(wanted)}")
            expect(not container["HostConfig"]["PortBindings"], f"N1: {service} publishes a port")
        declared = {
            service: {n for n in resolved["services"][service]["networks"] if n in NEW_NETWORKS}
            for service in members
        }
        expect(
            declared[FRONT] == {"litellm-api", "litellm-backend"}, f"N1: front {declared[FRONT]}"
        )
        expect(
            declared[LITELLM] == {"litellm-backend", "litellm-egress", "litellm-db"},
            f"N1: {declared[LITELLM]}",
        )
        expect(declared[DATABASE] == {"litellm-db"}, f"N1: database {declared[DATABASE]}")
        for network in NEW_NETWORKS:
            inspected = self.inspect_network(network)
            expect(inspected["Internal"] is True, f"N1: {network} is not internal")
            expect(
                inspected["Options"].get("com.docker.network.bridge.gateway_mode_ipv4") == ISOLATED,
                f"N1: {network} is not isolated",
            )
            members = {c["Name"] for c in inspected["Containers"].values()}
            wanted = {self.container_name(s) for s, n in declared.items() if network in n}
            expect(members == wanted, f"N1: {network} holds {sorted(members)}")
        self.hold("N1", "members as declared; the four new networks internal and isolated; no port")

    def container_name(self, service: str) -> str:
        found = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[0]
        return found["Name"].removeprefix("/")

    def cells_listeners(self) -> None:
        addresses = ENTRYPOINT_ADDRESS.findall(self.static_file.read_text())
        gateway_listeners(self, GATEWAY, addresses)
        self.hold(
            "L1", f"the gateway listens on {', '.join(addresses)}/tcp and holds no UDP socket"
        )
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        front_static = mounted_file(resolved[FRONT], FRONT_STATIC).read_text()
        (front_address,) = ENTRYPOINT_ADDRESS.findall(front_static)
        declared = {FRONT: front_address, LITELLM: self.proxy_address}
        for cell, service in (("L2", FRONT), ("L3", LITELLM)):
            found = listeners_of(self, service)
            tcp, engines = found["tcp"], {}
            if service == LITELLM:
                snapshot = self.proxy_snapshot()
                tcp, engines = snapshot.outside, snapshot.engines
                expect(snapshot.listening, f"{cell}: nothing listens on {self.proxy_address}")
            engine = [name for names in engines.values() for name in names]
            expect(
                tcp in bound_names(declared[service]) and found["udp"] == [],
                f"{cell}: {service} declares {declared[service]} and listens on {found}",
            )
            expect(
                service != LITELLM or (len(engines) == 1 and len(engine) == 1),
                f"{cell}: {len(engines)} query engines with sockets {engine}",
            )
            expect(
                all(name.startswith(f"{LOOPBACK_ADDRESS}:") for name in engine),
                f"{cell}: the query engine listens beyond loopback: {engine}",
            )
            self.hold(
                cell,
                f"{service} declares {declared[service]} and listens on {tcp}"
                + (f"; its Prisma engine on {engine}" if engine else ""),
            )

    @cached_property
    def proxy_address(self) -> str:
        """The `host:port` start.sh gives LiteLLM, from the resolved configuration."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        start = mounted_file(resolved[LITELLM], resolved[LITELLM]["entrypoint"][0]).read_text()
        return ":".join(START_LISTENER.search(start).groups())

    @cached_property
    def engine_executable(self) -> str:
        """The one query engine binary the image ships for the proxy, read from the image."""
        shown = self.run(
            ["docker", "exec", "-i", self.container(LITELLM), "python3", "-"],
            stdin=ENGINE_PATH_PROGRAM,
        ).stdout
        return shown.strip().splitlines()[-1]

    def is_engine(self, row: dict, proxy: int) -> bool:
        """The process is the query engine: the image's engine binary, a child of the proxy."""
        return row["parent"] == proxy and row["executable"] == self.engine_executable

    def proxy_snapshot(self) -> ProxySnapshot:
        """LiteLLM's listeners from one scan: the proxy owns the declared address, and the engine
        sockets are those of the processes `is_engine` accepts."""
        scan = json.loads(
            self.run(
                ["docker", "exec", "-i", self.container(LITELLM), "python3", "-"],
                stdin=SNAPSHOT_PROGRAM,
            ).stdout
        )
        sockets = named_sockets(scan["listeners"])
        declared = {name for names in bound_names(self.proxy_address) for name in names}
        proxies = {pid for name, owners in sockets if name in declared for pid in owners}
        engines = {
            int(pid): [name for name, owners in sockets if int(pid) in owners]
            for pid, row in scan["processes"].items()
            if any(self.is_engine(row, proxy) for proxy in proxies)
        }
        outside = [name for name, owners in sockets if not set(owners) & engines.keys()]
        return ProxySnapshot(frozenset(proxies), engines, outside)

    def cells_r1_r2(self) -> None:
        for cell, name in (("R1", PROVIDER_HOST), ("R2", ISSUER_HOST)):
            container = self.container(SERVICE)
            seen = self.client_with(["exec", "-i", container], [self.address, name], TLS_PROGRAM)
            expect(seen == {"subject": name, "issuer": "probe-ca"}, f"{cell}: {seen}")
            self.hold(
                cell, f"the handshake on entrypoint 1 for {name} shows the fake's certificate"
            )


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LitellmProbe)


if __name__ == "__main__":
    sys.exit(main())
