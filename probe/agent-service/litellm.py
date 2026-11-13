"""Probe of LiteLLM's own keys on the API route (cells K1, K2, K4, and #768 S1a's G6-G9, N1, L1-L3,
D1): the front, LiteLLM, its database and the gateway, in the throwaway compose project of
litellm_stack.py, against a fake Anthropic. The caller is a
throwaway on HopIn's network that posts agent-runtime's wire body (`model`, `messages`, `user`,
`tools`) through the front with an app key the probe made through the master key from a throwaway
on `litellm-backend`. Nothing live and nothing paid: the probe refuses to start unless the resolved
copy marks `internet` internal and holds only the fake hosts.

    probe-run \\
        python3 probe/agent-service/litellm.py --scratch DIR

Measured: a run takes about two minutes and its teardown a few seconds (K 30 s, CAP 1800 s).

The scratch HOME holds the throwaway secrets (random values, never printed): the two provider keys,
the master key and the database password; the scratch CA lies beside it. The fake providers
(aliases api.anthropic.com and api.openai.com, fake_anthropic.py's roles `provider` and
`pictures`) hold certificates of the scratch CA, which LiteLLM's SSL_CERT_FILE trusts. Keys,
budgets and fingerprints are the probe's scenario data; a key reaches a throwaway inside the
program on its standard input, never in argv, and only its hash is printed or persists.

Evidence: F is the fake provider's request log, A the caller's status and LiteLLM's error type, I
`docker inspect`, LA LiteLLM's access log. The probe differs from production in LiteLLM's log
level: compose.yaml sets `CRITICAL`, which prints no access line, so this probe sets `INFO` for LA
(LITELLM_LOG_LEVEL; litellm_retention.py leaves the shipped level). Its scratch copy of
config.yaml differs in one setting: the budget rescheduler runs every few seconds
(RESCHEDULER_SECONDS), so a budget moved due resets at once. Exit 0: every cell held.
"""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "agent-service"))

from agent_networks import AGENT_NETWORKS, EMBEDDED_RESOLVER, gateway_listeners, listeners_of  # noqa: E402
from egress_observe import socket_name  # noqa: E402
from litellm_ca import issue_certificate, write_new  # noqa: E402
from litellm_caller import CALL_PROGRAM, caller_input  # noqa: E402
from litellm_stack import (  # noqa: E402
    LABEL,
    PROJECT,
    ProbeFailed,
    StackProbe,
    expect,
    run_scratch_probe,
)
from retention_census import DATABASE, FRONT, GATEWAY, LITELLM, DatabaseLogin  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import litellm_keys  # noqa: E402

FAKE_PROVIDER, FAKE_PICTURES = "fake-anthropic", "fake-openai"
PROVIDER_HOST, PICTURE_HOST = "api.anthropic.com", "api.openai.com"
NEW_NETWORKS = ("litellm-backend", "litellm-egress", "litellm-db")
ISOLATED = "isolated"
LISTEN_SECONDS = 60
FAKE_DIRECTORY = "/fake"
ACCESS_LINE = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) \S+ HTTP/\d(?:\.\d)?"')
ADMITTED_LINE = re.compile(r'"POST /v1/chat/completions HTTP/\d(?:\.\d)?" 200')
ROUTE, PICTURE_ROUTE = litellm_keys.COMPLETION_ROUTE, litellm_keys.PICTURE_ROUTE
MODELS_ROUTE = litellm_keys.MODELS_ROUTE
LISTENING = "Uvicorn running"  # Uvicorn's start line, which LiteLLM prints too
FRONT_PORT = 4000
# The scenario of an app key and a person (docs/agent-service.md, "The API route"): each app key
# has a money budget per month and a parallel bound, each person a budget per month.
APP_BUDGET, PERSON_BUDGET, PERIOD, PARALLEL = 10.0, 2.0, "1mo", 5
PERSON_PUSH = {"input_tokens": 600_000, "output_tokens": 1}  # on text/opus, past PERSON_BUDGET
OPERATOR_BUDGET = "probe-operator"  # a budget with no max_budget, linked to the operator's row
RESCHEDULER_SECONDS = 3
SPEND_SECONDS = 90
TOO_MANY = 429
FRONT_STATIC = "/etc/traefik/traefik.yml"
ENTRYPOINT_ADDRESS = re.compile(r'address:\s*"([^"]+)"')
START_LISTENER = re.compile(r"--host (\S+) --port (\d+)")
# The database service and port as start.sh's DATABASE_URL names them.
START_DATABASE = re.compile(r"@(?P<service>[\w-]+):(?P<port>\d+)/")
WILDCARD_SOCKETS = ("0.0.0.0", "[::]")  # noqa: S104 - names the listener addresses the probe accepts and binds none
LOOPBACK_ADDRESS = "127.0.0.1"
# The secret files under the scratch HOME, where compose.yaml's `secrets` read them.
PROVIDER_KEY_FILE = Path(".secrets/litellm/anthropic")
PICTURE_KEY_FILE = Path(".secrets/litellm/openai")
MASTER_KEY_FILE = Path(".secrets/litellm/master-key")
DATABASE_PASSWORD_FILE = Path(".secrets/litellm/db-password")
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


def is_engine(row: dict, proxy: int, engine_executable: str) -> bool:
    """The process is the query engine: the image's engine binary, a child of the proxy."""
    return row["parent"] == proxy and row["executable"] == engine_executable


def snapshot_of(scan: dict, proxy_address: str, engine_executable: str) -> ProxySnapshot:
    """LiteLLM's listeners from one scan of SNAPSHOT_PROGRAM: the proxy owns the declared address,
    and the engine sockets are those of the processes `is_engine` accepts."""
    sockets = named_sockets(scan["listeners"])
    declared = {name for names in bound_names(proxy_address) for name in names}
    proxies = {pid for name, owners in sockets if name in declared for pid in owners}
    engines = {
        int(pid): [name for name, owners in sockets if int(pid) in owners]
        for pid, row in scan["processes"].items()
        if any(is_engine(row, proxy, engine_executable) for proxy in proxies)
    }
    outside = [name for name, owners in sockets if not set(owners) & engines.keys()]
    return ProxySnapshot(frozenset(proxies), engines, outside)


def shipped_config() -> dict:
    return yaml.safe_load(
        (REPO / "agent-service" / "litellm" / "config.yaml").read_text(encoding="utf-8")
    )


def shipped_models() -> dict[str, dict]:
    """Each model name of the shipped config.yaml with its `litellm_params`."""
    return {
        entry["model_name"]: entry["litellm_params"] for entry in shipped_config()["model_list"]
    }


DEFAULT_MODEL = next(iter(shipped_models()))


def person_budget() -> dict:
    """The scenario's person budget, under the id config.yaml names."""
    budget_id = shipped_config()["litellm_settings"]["max_end_user_budget_id"]
    return {"budget_id": budget_id, "max_budget": PERSON_BUDGET, "budget_duration": PERIOD}


def hashed(key: str) -> str:
    """A key as LiteLLM stores and accepts it on its admin routes: its SHA-256 in hex."""
    return hashlib.sha256(key.encode()).hexdigest()


def error_of(answer: dict) -> str:
    """LiteLLM's error type and code of an answer, never its message, which may quote a request."""
    document = answer["document"]
    error = document.get("error") if isinstance(document, dict) else None
    return f"{error.get('type')}/{error.get('code')}" if isinstance(error, dict) else "-"


def wire_body(model: str = DEFAULT_MODEL, user: str | None = None, **extra: object) -> dict:
    """agent-runtime's wire body for `model` and `user` (none when None), with `extra`."""
    asked = {"model": model, "messages": [{"role": "user", "content": "probe"}]}
    return {**asked, **({"user": user} if user else {}), "tools": [], **extra}


def answer_text(answer: dict) -> str | None:
    try:
        return answer["document"]["choices"][0]["message"]["content"]
    except KeyError, IndexError, TypeError:
        return None


class LitellmProbe(StackProbe):
    """The front, LiteLLM, its database, the gateway and a fake Anthropic and OpenAI."""

    LITELLM_LOG_LEVEL: str | None = "INFO"  # None keeps the level compose.yaml ships
    caller_network = AGENT_NETWORKS[-1]  # the app network a request comes from unless it names one

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        home = Path(self.environment["HOME"])
        self.provider_key, self.picture_key = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self.master_key = f"sk-{secrets.token_hex(32)}"
        self.app_keys: list[str] = []
        self.marker = secrets.token_hex(8)
        self.identity = {
            name: f"{name}-{secrets.token_hex(6)}" for name in ("sub", "username", "email")
        }
        self.database_password = secrets.token_urlsafe(32)
        self.write_secrets(home)
        self.fake = scratch / "fake"
        self.write_fakes(self.fake)
        self.litellm_config = scratch / "litellm.yaml"
        self.write_litellm_config(shipped_config())
        self.overlays.append(self.write_overlay(scratch))
        self.expect_fake_only()

    # --- the scratch files --------------------------------------------------------------------

    def write_secrets(self, home: Path) -> None:
        for relative, text in (
            (PROVIDER_KEY_FILE, self.provider_key + "\n"),
            (PICTURE_KEY_FILE, self.picture_key + "\n"),
            (MASTER_KEY_FILE, self.master_key + "\n"),
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

    def write_litellm_config(self, config: dict) -> None:
        """The scratch config.yaml: the given one with the rescheduler's short period."""
        rescheduled = {**config["general_settings"],
                       "proxy_budget_rescheduler_min_time": RESCHEDULER_SECONDS,
                       "proxy_budget_rescheduler_max_time": RESCHEDULER_SECONDS + 1}  # fmt: skip
        text = yaml.safe_dump({**config, "general_settings": rescheduled}, sort_keys=False)
        self.litellm_config.write_text(text, encoding="utf-8")
        self.litellm_config.chmod(0o644)

    def write_fakes(self, directory: Path) -> None:
        """One directory per fake host: its certificate and key, what it checks and its program."""
        directory.mkdir()
        expectations = {"identity": list(self.identity.values()), "marker": self.marker}
        program = (Path(__file__).resolve().parent / "fake_anthropic.py").read_text(
            encoding="utf-8"
        )
        keys = {PROVIDER_HOST: self.provider_key, PICTURE_HOST: self.picture_key}
        for host in (PROVIDER_HOST, PICTURE_HOST):
            issue_certificate(self.scratch_ca, host, directory / host)
            expected = json.dumps({**expectations, "provider_key": keys.get(host, "")})
            (directory / host / "expect.json").write_text(expected, encoding="utf-8")
            (directory / host / "fake_anthropic.py").write_text(program, encoding="utf-8")
            (directory / host).chmod(0o755)
            for file in (directory / host).iterdir():
                file.chmod(0o644)
        directory.chmod(0o755)

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
                    LITELLM: {
                        "environment": {
                            "SSL_CERT_FILE": "/probe/ca.crt",
                            **log_level,
                        },
                        "volumes": [
                            {"type": "bind", "source": str(self.litellm_config),
                             "target": "/etc/litellm/config.yaml", "read_only": True},
                            {"type": "bind", "source": str(self.scratch_ca.ca_certificate),
                             "target": "/probe/ca.crt", "read_only": True},
                        ],
                    },
                    FAKE_PROVIDER: fake("provider", PROVIDER_HOST),
                    FAKE_PICTURES: fake("pictures", PICTURE_HOST),
                },
                "networks": {"internet": {"internal": True}},
            }),
            encoding="utf-8",
        )  # fmt: skip
        return overlay

    def expect_fake_only(self) -> None:
        """Refuses to go on unless `internet` is internal and only the gateway and the fake hosts
        are on it."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        on_internet = {
            name for name, service in resolved["services"].items()
            if "internet" in service.get("networks", {})
        }  # fmt: skip
        expect(resolved["networks"]["internet"].get("internal") is True, "internet is not internal")
        expect(
            on_internet == {GATEWAY, FAKE_PROVIDER, FAKE_PICTURES},
            f"internet holds {sorted(on_internet)}, not the gateway and the fake hosts",
        )

    # --- life cycle ---------------------------------------------------------------------------

    def services_to_start(self) -> tuple[str, ...]:
        return (GATEWAY, FAKE_PROVIDER, FAKE_PICTURES, FRONT, DATABASE, LITELLM)

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

    def steer_fake(self, host: str = PROVIDER_HOST, **steering: object) -> None:
        """Writes the control file of the fake provider at `host`; the fake re-reads it on every
        request. The app keys and the master key are always among the values it counts."""
        folder = self.fake / host
        draft = folder / "control.json.new"
        counted = {"secrets": [*self.app_keys, self.master_key], **steering}
        draft.write_text(json.dumps(counted), encoding="utf-8")
        draft.chmod(0o644)
        draft.replace(folder / "control.json")

    def recreate_litellm(self) -> None:
        self.compose(
            "up", "--detach", "--wait", "--force-recreate", "--no-deps", LITELLM, timeout=300
        )
        self.wait_until_listening()

    def wait_until_listening(self, seconds: int = LISTEN_SECONDS) -> None:
        """Until a snapshot shows the declared address listening; a scan that fails (the container
        not up yet) is tried again, and the last failure ends up in the deadline's message."""
        deadline, last = time.monotonic() + seconds, "nothing listens"
        while time.monotonic() < deadline:
            try:
                if self.proxy_snapshot().listening:
                    return
            except ProbeFailed as problem:
                last = str(problem)
            time.sleep(1)
        raise ProbeFailed(f"LiteLLM did not listen in {seconds} seconds: {last}")

    # --- the caller ---------------------------------------------------------------------------

    def call_command(self, name: str, bearer: str | None, method: str, path: str,
                     body: dict | None, *, front: bool, network: str | None = None):  # fmt: skip
        """The argv and standard input of one throwaway's request: through the front from an app's
        network (`network`, else `caller_network`), or straight at LiteLLM from `litellm-backend`.
        Bearer and body go on standard input, since a body may carry a key."""
        network, host, port = (
            (network or self.caller_network, FRONT, str(FRONT_PORT)) if front
            else ("litellm-backend", LITELLM, self.proxy_address.rsplit(":", 1)[1])
        )  # fmt: skip
        argv = [
            "docker", "run", "--rm", "-i", "--name", name, "--label", LABEL,
            f"--network={PROJECT}_{network}", "--read-only", "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", self.image,
            "python", "-I", "-", host, port, method, path,
        ]  # fmt: skip
        return argv, caller_input(CALL_PROGRAM, bearer, body, self.hidden_keys())

    def hidden_keys(self) -> list[str]:
        """The keys a caller's output shows as `<key>`."""
        return [*self.app_keys, self.master_key]

    def call(
        self, bearer: str | None, method: str, path: str, body: dict | None = None,
        *, front: bool = True, network: str | None = None,
    ) -> dict:  # fmt: skip
        """A: one request's status, Retry-After, seconds and answer document."""
        self.throwaways += 1
        name = f"{PROJECT}-caller-{self.throwaways}"
        argv, program = self.call_command(
            name, bearer, method, path, body, front=front, network=network
        )
        return json.loads(
            self.run(argv, stdin=program, timeout=240).stdout.strip().splitlines()[-1]
        )

    def listed(self, key: str) -> list[str]:
        """The names `key` lists on the model list through the front, sorted."""
        answer = self.call(key, "GET", MODELS_ROUTE)
        expect(answer["status"] == 200, f"the list: {answer['status']} {error_of(answer)}")
        return sorted(entry["id"] for entry in answer["document"]["data"])

    def admin(self, method: str, path: str, body: dict | None = None) -> dict:
        """The answer document of one admin request with the master key, straight at LiteLLM."""
        answer = self.call(self.master_key, method, path, body, front=False)
        expect(answer["status"] == 200, f"{method} {path}: {answer['status']} {error_of(answer)}")
        return answer["document"]

    def make_key(self, **settings: object) -> str:
        """A new app key of the scenario, its settings overridden by `settings`."""
        scenario = {
            "models": list(shipped_models()), "max_budget": APP_BUDGET, "budget_duration": PERIOD,
            "allowed_routes": list(litellm_keys.ROUTES), "max_parallel_requests": PARALLEL,
        }  # fmt: skip
        key = f"sk-{secrets.token_urlsafe(32)}"
        self.app_keys.append(key)
        self.admin("POST", "/key/generate", {**scenario, **settings, "key": key})
        self.steer_fake()
        return key

    def key_info(self, key: str) -> dict:
        return self.admin("GET", f"/key/info?key={hashed(key)}")["info"]

    def customer_row(self, user: str) -> dict | None:
        """The person's row; None while LiteLLM's batched write has not made it yet."""
        path = f"/customer/info?end_user_id={user}"
        answer = self.call(self.master_key, "GET", path, front=False)
        expect(answer["status"] in {200, 404}, f"/customer/info: {answer['status']}")
        return answer["document"] if answer["status"] == 200 else None

    def customer_spend(self, user: str) -> float:
        return (self.customer_row(user) or {"spend": 0.0})["spend"]

    def push(self, key: str, user: str, usage: dict) -> None:
        """One served request whose steered usage LiteLLM prices."""
        self.steer_fake(usage=usage)
        answer = self.complete(key, user=user)
        self.steer_fake()
        expect(answer["status"] == 200, f"the push was refused: {answer['status']}")

    def push_person(self, cell: str, key: str, user: str) -> float:
        self.push(key, user, PERSON_PUSH)
        self.wait_for(cell, "the person's spend past the budget",
                      lambda: self.customer_spend(user) > PERSON_BUDGET)  # fmt: skip
        return self.customer_spend(user)

    def move_due(self, table: str, column: str, value: str) -> None:
        """Moves a budget's reset into the past in LiteLLM's database."""
        moved = "budget_reset_at = now() - interval '1 minute'"
        self.sql(f"UPDATE \"{table}\" SET {moved} WHERE {column} = '{value}'")  # noqa: S608 - the probe names the table and the value

    def complete(self, key: str | None, model: str = DEFAULT_MODEL, user: str | None = None,
                 path: str = ROUTE, front: bool = True, network: str | None = None,
                 **extra: object) -> dict:  # fmt: skip
        """A: one request of agent-runtime's wire body."""
        body = wire_body(model, user, **extra)
        return self.call(key, "POST", path, body, front=front, network=network)

    def fingerprint(self) -> str:
        return f"fp-{secrets.token_hex(8)}"

    def wait_for(self, cell: str, what: str, holds, seconds: int = SPEND_SECONDS) -> float:
        """Polls `holds()` until it is true and returns the seconds it took."""
        started = time.monotonic()
        while not holds():
            expect(time.monotonic() - started < seconds, f"{cell}: {what} not within {seconds} s")
            time.sleep(1)
        return time.monotonic() - started

    def served(self, cell: str, answer: dict, sent: list[dict], model: str = DEFAULT_MODEL) -> None:
        expect(answer["status"] == 200, f"{cell}: {answer['status']} {error_of(answer)}")
        expect(answer_text(answer) == self.marker, f"{cell}: the marker is not in the answer")
        wanted = shipped_models()[model]["model"].split("/", 1)[1]
        expect([request["model"] for request in sent] == [wanted], f"{cell}: F saw {sent}")

    def refused(self, cell: str, answer: dict, before: int) -> None:
        """Refused before the provider: a 4xx that is not 429, and F saw nothing new."""
        status = answer["status"]
        expect(400 <= status < 500 and status != TOO_MANY, f"{cell}: status {status}")
        expect(len(self.provider_requests()) == before, f"{cell}: the provider was reached")

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until_listening()
        self.cell_d1()
        self.cell_n1()
        self.cells_listeners()
        self.admin("POST", "/budget/new", person_budget())
        key = self.make_key()
        self.cell_k1(key)
        for cell, method, path in (
            ("G6", "GET", ROUTE), ("G7", "POST", "/key/generate"),
            ("G8", "POST", "/mcp/"), ("G9", "POST", "/register"),
        ):  # fmt: skip
            self.cell_unreachable(cell, method, path, key)
        self.cell_k2(key)
        self.cell_k4(key)

    def cell_k1(self, key: str) -> None:
        before_f, before_la = len(self.provider_requests()), len(self.access_lines())
        answer = self.complete(key, user=self.fingerprint())
        sent = self.provider_requests()[before_f:]
        self.served("K1", answer, sent)
        expect(sent[0]["key_ok"], "K1: the provider key did not arrive")
        expect(sent[0]["secret_hits"] == 0 and not sent[0]["authorization"], "K1: a key at F")
        expect(sent[0]["identity_hits"] == 0, f"K1: {sent[0]['identity_hits']} identity matches")
        expect(sent[0]["jwt_hits"] == 0 and sent[0]["uuid_hits"] == 0, "K1: a token or id at F")
        admitted = [line for line in self.access_lines()[before_la:] if ADMITTED_LINE.search(line)]
        expect(len(admitted) == 1, f"K1: {len(admitted)} admitted lines in LiteLLM's log")
        self.hold("K1", "200 with the marker; F 1 with the mapped id and the provider key, no app "
                  "or master key, no identity string; one admitted line in LA")  # fmt: skip

    def cell_unreachable(self, cell: str, method: str, path: str, key: str) -> None:
        before = len(self.access_lines())
        status = self.call(key, method, path, {"model": DEFAULT_MODEL})["status"]
        expect(status == 404, f"{cell}: status {status}")
        expect(len(self.access_lines()) == before, f"{cell}: LiteLLM's log grew")
        self.hold(cell, f"{method} {path} through the front: 404, LiteLLM saw nothing")

    def cell_k2(self, key: str) -> None:
        user, stored = self.fingerprint(), hashed(key)
        for how, bearer, front in (
            ("no bearer", None, True), ("a wrong one", secrets.token_urlsafe(24), True),
            ("the key's stored hash through the front", stored, True),
            ("the key's stored hash straight at LiteLLM", stored, False),
        ):  # fmt: skip
            before = len(self.provider_requests())
            answer = self.call(bearer, "POST", ROUTE, wire_body(user=user), front=front)
            served = answer["status"] == 200 or len(self.provider_requests()) != before
            if bearer == stored and served:
                write_line("K2 measured: the stored hash is accepted as a bearer", flush=True)
            expect(answer["status"] == 401, f"K2: {how}: {answer['status']} {error_of(answer)}")
            expect(len(self.provider_requests()) == before, f"K2: {how}: the provider was reached")
        self.hold("K2", "no bearer, a wrong one and the key's stored "
                  "hash, through the front and straight at LiteLLM: 401 each, F 0")  # fmt: skip

    def cell_k4(self, key: str) -> None:
        user, results = self.fingerprint(), []
        url = "https://x.invalid"
        for how, extra in (
            ("api_base", {"api_base": url}),
            ("a fallback URL", {"fallbacks": [url]}),
        ):
            before = len(self.provider_requests())
            answer = self.complete(key, user=user, **extra)
            self.refused(f"K4: {how}", answer, before)
            results.append(f"{how}: {answer['status']} {error_of(answer)}")
        before = len(self.provider_requests())
        second = list(shipped_models())[1]
        answer = self.complete(key, user=user, fallbacks=[second])
        self.served("K4", answer, self.provider_requests()[before:])
        self.hold("K4", f"{'; '.join(results)}, F 0; fallbacks naming {second}: served by "
                  f"{DEFAULT_MODEL}")  # fmt: skip

    def cell_d1(self) -> None:
        """LiteLLM runs as its configured user on a read-only root, and its migrations are done."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        container = json.loads(self.run(["docker", "inspect", self.container(LITELLM)]).stdout)[0]
        user = resolved[LITELLM]["user"]
        expect(container["Config"]["User"] == user, f"D1: runs as {container['Config']['User']}")
        expect(container["HostConfig"]["ReadonlyRootfs"] is True, "D1: the root is writable")
        counted = self.sql(
            "SELECT count(finished_at), count(*) FROM _prisma_migrations",
            "--tuples-only", "--no-align",
        ).stdout.strip()  # fmt: skip
        finished, total = (int(number) for number in counted.split("|"))
        expect(total > 0 and finished == total, f"D1: {finished} of {total} migrations finished")
        self.hold("D1", f"LiteLLM runs as {user} on a read-only root; {finished} of {total} "
                  "migrations finished")  # fmt: skip

    def database_login(self) -> DatabaseLogin:
        """The user and database `compose.yaml` gives `litellm-db`."""
        resolved = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        return DatabaseLogin.of(resolved[DATABASE])

    def database_options(self) -> list[str]:
        return self.database_login().options()

    def sql(self, statement: str, *options: str) -> subprocess.CompletedProcess:
        return self.run([
            "docker", "exec", self.container(DATABASE), "psql", *self.database_options(),
            *options, "--command", statement,
        ])  # fmt: skip

    def cell_n1(self) -> None:
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        members = (FRONT, LITELLM, GATEWAY, DATABASE)
        for service in members:
            inspected = self.run(["docker", "inspect", self.container(service)]).stdout
            (container,) = json.loads(inspected)
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
        expect(declared[FRONT] == {"litellm-backend"}, f"N1: {declared[FRONT]}")
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
        self.hold(
            "N1", "members as declared; the three new networks internal and isolated; no port"
        )

    def container_name(self, service: str) -> str:
        found = json.loads(self.run(["docker", "inspect", self.container(service)]).stdout)[0]
        return found["Name"].removeprefix("/")

    def cells_listeners(self) -> None:
        addresses = ENTRYPOINT_ADDRESS.findall(self.static_file.read_text())
        gateway_listeners(self, GATEWAY, addresses)
        listened = ", ".join(addresses)
        self.hold("L1", f"the gateway listens on {listened}/tcp and holds no UDP socket")
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
                f"{cell}: {service} declares {declared[service]} and listens on tcp {tcp}, "
                f"udp {found['udp']}",
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

    def proxy_snapshot(self) -> ProxySnapshot:
        scan = json.loads(
            self.run(
                ["docker", "exec", "-i", self.container(LITELLM), "python3", "-"],
                stdin=SNAPSHOT_PROGRAM,
            ).stdout
        )
        return snapshot_of(scan, self.proxy_address, self.engine_executable)


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LitellmProbe)


if __name__ == "__main__":
    sys.exit(main())
