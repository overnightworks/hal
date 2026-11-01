"""Keycloak probe: proves the edge's Keycloak service on a throwaway stack (docs/keycloak.md).

It starts its own compose project from this checkout with throwaway secrets in the scratch
directory, stands in for Cloudflare by sending `Host: auth.<domain>` and
`X-Forwarded-Proto: https` to its edge entrypoint, prints one line per proof, and always tears
the stack down, volumes included. Its Traefik entrypoints listen on free loopback ports it picks
and its keycloak network takes a free /24, so it runs beside the live edge, which stays up.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 720 \
        python3 probe/keycloak/probe.py --scratch DIR  # teardown measured 11 s (K 50 s, CAP 720 s)

`hold --scratch DIR` instead brings the same stack up without the proofs, prints one READY line
and keeps it until SIGTERM, SIGINT or EOF on stdin (see probe/keycloak/README.md).
"""

from __future__ import annotations

import argparse
import base64
import grp
import hashlib
import hmac
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import re
import secrets
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from html.parser import HTMLParser
from http.cookiejar import Cookie, CookieJar, DefaultCookiePolicy, parse_ns_headers
from pathlib import Path
from types import ModuleType
from typing import Any, ClassVar
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    OpenerDirector,
    Request,
    build_opener,
)

REPO = Path(__file__).resolve().parents[2]
# The probe runs from a bare checkout with system python; hal.stack.realm is standard library only.
sys.path[:0] = [str(REPO / "src"), str(REPO / "probe/keycloak")]
import backchannel_cell  # noqa: E402
import device_grant_cell  # noqa: E402
import logout_actions_cell  # noqa: E402
import service_audience_cell  # noqa: E402
import terms_cell  # noqa: E402
from admin import AdminToken  # noqa: E402
from service_audience_cell import (  # noqa: E402
    AGENT_SERVICE,
    SPEECH_SERVICE,
    WORKLOAD_ROLES,
    audience_of,
    is_workload_identity_of,
)
from test_rp import token_claims as claims  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import checkout, compose, core, switches  # noqa: E402
from hal.stack.realm import OBSERVER_SERVICE, change_lines, new_digest_key, reconcile  # noqa: E402
from hal.stack.realm.observe import CLIENT, FLOW, GROUP, IMPORT_CHECKSUM, Inventory  # noqa: E402
from hal.stack.result_rows import SNAPSHOT_SHORT_ID, result_rows  # noqa: E402

PROJECT = "edge-kc-probe"
KEYCLOAK_PROFILE = "keycloak"
PROJECT_LABEL = f"com.docker.compose.project={PROJECT}"
DOMAIN = "hallucinai.de"
REALM = "hallucinai"
THEME = "hallucinai"
REALM_FILE = "realm.yaml"
CONFIG_FILES = ("master.yaml", REALM_FILE)
ENTRYPOINT_FILE = "entrypoint.sh"
UNDEFINED_VARIABLE_LINE = (
    "displayName: $(env:PROBE_UNDEFINED_VARIABLE)\n"  # a realm.yaml line config-cli cannot resolve
)
PUBLIC_HOST = f"auth.{DOMAIN}"
REALM_PATH = f"/realms/{REALM}"
PUBLIC_TOKEN_PATH = f"{REALM_PATH}/protocol/openid-connect/token"
PUBLIC_ISSUER = f"https://{PUBLIC_HOST}{REALM_PATH}"
LOOPBACK_ADDRESS = "127.0.0.1"
# The live entrypoint addresses in traefik.yml, which the probe's copy of it replaces.
LIVE_EDGE_ADDRESS = f"{LOOPBACK_ADDRESS}:8081"
LIVE_ADMIN_ADDRESS = f"{LOOPBACK_ADDRESS}:8090"
# What keycloak/go-live pins for the live edge, which no step over the probe's stack may reach.
LIVE_GO_LIVE_ADDRESSES = ("localhost:8090", "localhost:8081", LIVE_ADMIN_ADDRESS, LIVE_EDGE_ADDRESS)
TRAEFIK_CONFIG = "traefik.yml"
NETWORK_OVERLAY = "network.compose.yaml"
# Which containers the Docker provider routes: the live one takes any `edge.name` label that
# matches; the probe's takes its own project only, and its keycloak carries an `edge.name` the
# live provider refuses (compose.probe.yaml), so neither Traefik sees the other's containers.
LIVE_CONSTRAINTS = "LabelRegex(`edge.name`, `^[a-z0-9-]{1,63}$`)"
PROBE_CONSTRAINTS = f"Label(`com.docker.compose.project`, `{PROJECT}`)"
# The /24s a probe's keycloak network may take, clear of the live one (172.31.253.0/24).
SUBNET_CANDIDATES = tuple(f"172.31.{third}.0/24" for third in range(200, 250))
TRAEFIK_NOT_FOUND = b"404 page not found\n"


# `roles` carries the workload role, `service_account` the client_id and the audience is the
# service's; hopin reads no email, web origin or acr, so it has none of the three.
HOPIN_CLIENT_SCOPES = frozenset(
    {"basic", "profile", "groups", "roles", "service_account", "agent-service-audience"}
)
SONGMAKER_PRESENTATOR_CLIENT_SCOPES = HOPIN_CLIENT_SCOPES | {"email", "web-origins", "acr"}


@dataclass(frozen=True)
class AppClient:
    """An app's relying party in realm.yaml as #11 lists it (#108, #161)."""

    client_id: str
    group: str  # the group of the user who signs in; its full path is in the ID token
    callbacks: tuple[str, ...]
    logout_redirect: str
    default_scopes: frozenset[str]  # exactly the client's default scopes in realm.yaml
    optional_scopes: frozenset[str] = frozenset()  # and its optional ones

    @property
    def secret_file(self) -> str:
        return f"clients/{self.client_id}"

    @property
    def callback(self) -> str:
        return self.callbacks[0]

    @property
    def origin(self) -> str:
        return f"https://{self.client_id}.{DOMAIN}"


SONGMAKER = AppClient(
    "songmaker",
    "/apps/songmaker/admin",
    (f"https://songmaker.{DOMAIN}/auth/callback",),
    f"https://songmaker.{DOMAIN}/login",
    default_scopes=SONGMAKER_PRESENTATOR_CLIENT_SCOPES,
)
HOPIN = AppClient(
    "hopin",
    "/apps/hopin",
    (f"https://hopin.{DOMAIN}/auth/callback",),
    f"https://hopin.{DOMAIN}/login",
    default_scopes=HOPIN_CLIENT_SCOPES,
    optional_scopes=frozenset({service_audience_cell.SPEECH_SCOPE}),
)
PRESENTATOR = AppClient(
    "presentator",
    "/apps/presentator/admin",
    (
        f"https://presentator.{DOMAIN}/auth/callback",
        f"https://presentator-talk.{DOMAIN}/auth/callback",
    ),
    f"https://presentator.{DOMAIN}/login",
    default_scopes=SONGMAKER_PRESENTATOR_CLIENT_SCOPES,
)
APP_CLIENTS = (SONGMAKER, HOPIN, PRESENTATOR)
AGENT_WORKLOAD_ROLE = WORKLOAD_ROLES[AGENT_SERVICE]
SECRET_FILES = (
    "db-password",
    "config-cli-secret",
    "bootstrap-admin-password",
    *(client.secret_file for client in APP_CLIENTS),
)
READY_TIMEOUT_SECONDS = 240
CHANGED_ACCESS_TOKEN_LIFESPAN = 360
CHANGED_GROUP = "probe-changed"
MEMBER_GROUP = "/apps/songmaker"
SUBSCRIPTION_GROUP = "/services/agent-service/subscription"
PUBLIC_AUTH_PATH = f"{REALM_PATH}/protocol/openid-connect/auth"
PUBLIC_LOGOUT_PATH = f"{REALM_PATH}/protocol/openid-connect/logout"
CLIENT_ADDRESS = "198.51.100.23"  # the person signing in, as Cloudflare saw it
CLIENT_ADDRESS_IPV6 = "2001:db8::23"  # the same, for a person on IPv6
FORGED_FORWARDED_FOR = "203.0.113.9, 192.0.2.7"  # a forged first value, then a proxy's
CONSOLE_PARENT = "/apps"
CONSOLE_SUBGROUP_NAME = "probe-console"
CONSOLE_SUBGROUP = f"{CONSOLE_PARENT}/{CONSOLE_SUBGROUP_NAME}"
# What an operator adds in the admin console before an apply (#66, the U1 measurement). The apply
# deletes no undeclared top-level object and no person; a console addition inside a declared object
# is reset with it. So of these only the residue below goes: the observer names exactly it.
CONSOLE_NAME = "probe-console"
CONSOLE_FLOW = "console-flow"
FORMS_FLOW = "browser-mfa-forms"
SUBFLOW_PARENT = "direct-grant-mfa-totp"
CONSOLE_SUBFLOW = f"{CONSOLE_NAME}-subflow"
CONSOLE_SCOPE = f"{CONSOLE_NAME}-scope"
CONSOLE_CLIENT_ROLE = f"{CONSOLE_NAME}-client-role"
SCOPED_CLIENT = "songmaker"  # lists its default scopes, as do hopin and presentator
SERVICE_ACCOUNT_CLIENT = "songmaker"  # a listed service account
ENABLED_SERVICE_ACCOUNT_CLIENT = "hopin"  # its service account, which the console turns off
BACKUP_ASKED = ["backup", "keycloak", "--pre-apply", "--json"]  # what hal was asked first
RESTORE_TEST_ASKED = ["restore", "--test", "keycloak", "--snapshot"]  # then the snapshot just made
LIFESPAN_SETTING = "accessTokenLifespan: 300 "  # as realm.yaml sets it
CHANGED_LIFESPAN_SETTING = f"accessTokenLifespan: {CHANGED_ACCESS_TOKEN_LIFESPAN} "
STEP_GROUP = "probe-realm-step"  # a group proof 12 adds to realm.yaml
STEP_CONSOLE_MAPPER = "probe-step-mapper"  # a console change proof 12's step resets
STEP_CONSOLE_GROUP = "probe-step-console-group"  # console objects proof 12's step leaves alone
STEP_CONSOLE_CLIENT = "probe-step-console-client"
STEP_CONSOLE_FLOW = "probe-step-console-flow"
ONLY_IN_KEYCLOAK = "only in Keycloak: "
COMPOSE_PREFIX_LENGTH = 6  # docker compose --project-directory D --file F
RESIDUE_OF_THE_APPLY = [
    # the service account a console turned off and the apply turns back on: Keycloak drops its
    # scope with the flag and the apply restores it
    f"hallucinai: change client {ENABLED_SERVICE_ACCOUNT_CLIENT} defaultClientScopes: "
    '["agent-service-audience", "basic", "groups", "profile", "roles"] → '
    '["agent-service-audience", "basic", "groups", "profile", "roles", "service_account"]',
    f"hallucinai: change client {ENABLED_SERVICE_ACCOUNT_CLIENT} serviceAccountsEnabled: false → "
    "true",
    f'hallucinai: change client {SCOPED_CLIENT} defaultClientScopes: ["acr", '
    '"agent-service-audience", "basic", "email", "groups", "probe-console-scope", "profile", '
    '"roles", "service_account", "web-origins"] → ["acr", "agent-service-audience", "basic", '
    '"email", "groups", "profile", "roles", "service_account", "web-origins"]',
    f"hallucinai: change client {SCOPED_CLIENT} authenticationFlowBindingOverrides: changed",
    f"hallucinai: removal protocol mapper scope groups/{CONSOLE_NAME}-mapper",
    f"hallucinai: removal service-account client role service-account-{SERVICE_ACCOUNT_CLIENT}/"
    f"{AGENT_SERVICE}/{CONSOLE_CLIENT_ROLE}",
    # the user and the role mappings the apply recreates with the service account
    "hallucinai: addition service-account realm role service-account-"
    f"{ENABLED_SERVICE_ACCOUNT_CLIENT}/{AGENT_WORKLOAD_ROLE}",
    "hallucinai: addition service-account realm role service-account-"
    f"{ENABLED_SERVICE_ACCOUNT_CLIENT}/default-roles-hallucinai",
    "hallucinai: addition service-account realm role service-account-"
    f"{service_audience_cell.SPEECH_CALLER}/{WORKLOAD_ROLES[SPEECH_SERVICE]}",
    f"hallucinai: addition service-account user service-account-{ENABLED_SERVICE_ACCOUNT_CLIENT}",
    f"master: removal flow {CONSOLE_SUBFLOW}",
    f"master: removal flow step {FORMS_FLOW}/auth-otp-form#1",
    f"master: removal flow step {SUBFLOW_PARENT}/{CONSOLE_SUBFLOW}#1",
]
DROPPED_CLIENT = "hopin"
DROPPED_GROUP = "services"
ROLE_HOLDERS = {  # the realm roles earlier applies created, with the service accounts holding each
    AGENT_WORKLOAD_ROLE: [f"service-account-{client.client_id}" for client in APP_CLIENTS],
    WORKLOAD_ROLES[SPEECH_SERVICE]: [f"service-account-{service_audience_cell.SPEECH_CALLER}"],
}
CHANGED_CONFIG = "browser-mfa-without-passkey"
# 6.5.1 reads the managed-role switch only when the file has a roles section, so an empty
# list stays in it.
EMPTY_REALM_ROLES = "roles:\n  realm: []\n"
ESCAPING_GROUP = "probe\x1b[31mconsole\nname"
OBSERVER_SECRET = "/run/secrets/config_cli_secret"  # noqa: S105 - the path of a mounted secret file and no secret
OBSERVER_SCRIPT = "/opt/observer/observe.py"
OBSERVER_START_SECONDS = 60
GO_LIVE_ADMIN = "probe-owner"
ADMIN_REQUIRED_ACTIONS = ("CONFIGURE_TOTP", "webauthn-register")


class ProbeFailure(Exception):
    """A proof did not hold; the message names what was expected and what came back."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeFailure(message)


# --- HTTP -----------------------------------------------------------------------------------


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)

    @property
    def text(self) -> str:
        return self.body.decode(errors="replace")


LOOPBACK_HOSTS = ("localhost", "127.0.0.1")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


class LocalhostIsSecure(DefaultCookiePolicy):
    """Sends Secure cookies to a loopback origin (http://localhost, or the edge entrypoint on
    127.0.0.1). The edge entrypoint with `X-Forwarded-Proto: https` stands in for the https
    origin auth.hallucinai.de, where a browser does send them."""

    def return_ok_secure(self, cookie: Cookie, request: Request) -> bool:
        return urlsplit(request.full_url).hostname in LOOPBACK_HOSTS or super().return_ok_secure(
            cookie, request
        )


class ReceivedCookies(CookieJar):
    """A browser's cookie jar that hands every nonempty value a response sets to `keep` as it
    arrives, so proof 7 looks for it even after a later response replaces or expires it."""

    def __init__(self, keep: Callable[[str, str], object]) -> None:
        super().__init__(policy=LocalhostIsSecure())
        self.keep = keep
        self.received = 0

    def extract_cookies(self, response: Any, request: Request) -> None:
        for name_and_value, *_attributes in parse_ns_headers(
            response.info().get_all("Set-Cookie", [])
        ):
            name, value = name_and_value
            if value:
                self.received += 1
                self.keep(f"cookie {name} #{self.received}", value)
        super().extract_cookies(response, request)


def new_opener(cookies: CookieJar | None = None) -> OpenerDirector:
    handlers: list[Any] = [NoRedirect()]
    if cookies is not None:
        handlers.append(HTTPCookieProcessor(cookies))
    return build_opener(*handlers)


PLAIN = new_opener()


def http(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    form: dict[str, str] | None = None,
    json_body: Any = None,
    bearer: str | None = None,
    opener: OpenerDirector = PLAIN,
) -> Response:
    request_headers = dict(headers or {})
    data = None
    if form is not None:
        data = urlencode(form).encode()
        request_headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif json_body is not None:
        data = json.dumps(json_body).encode()
        request_headers["Content-Type"] = "application/json"
    if bearer:
        request_headers["Authorization"] = f"Bearer {bearer}"
    request = Request(url, data=data, method=method, headers=request_headers)  # noqa: S310 - the URL is an address of the probe stack
    try:
        with opener.open(request, timeout=15) as reply:
            return Response(reply.status, dict(reply.headers), reply.read())
    except HTTPError as error:
        return Response(error.code, dict(error.headers), error.read())


def tunnel_request(
    edge_url: str,
    method: str,
    path: str,
    *,
    host: str = PUBLIC_HOST,
    headers: dict[str, str] | None = None,
    **kwargs: Any,
) -> Response:
    """What cloudflared sends to the edge entrypoint at `edge_url` for a public request: the
    public host and the original scheme."""
    sent = {"Host": host, "X-Forwarded-Proto": "https", **(headers or {})}
    return http(method, edge_url + path, headers=sent, **kwargs)


def tunnel_request_url(edge_url: str, method: str, url: str, **kwargs: Any) -> Response:
    """Follows an absolute URL Keycloak gave out on the public host, through the tunnel."""
    target = urlsplit(url)
    expect(
        target.scheme == "https" and target.hostname == PUBLIC_HOST,
        f"{url} is not https on {PUBLIC_HOST}",
    )
    return tunnel_request(
        edge_url, method, urlunsplit(("", "", target.path, target.query, "")), **kwargs
    )


def cloudflare_forwarded(address: str) -> str:
    """The `Forwarded` value external/cloudflare.tf sets: RFC 7239 brackets and quotes IPv6."""
    node = f'"[{address}]"' if ipaddress.ip_address(address).version == 6 else address
    return f"for={node};proto=https"


def stored_event_types(events: list[dict[str, Any]], request_address: str) -> list[str]:
    """The sorted types of stored user events, each proven to carry `request_address`.

    The address is the one Cloudflare put in `Forwarded`, which Traefik and Keycloak pass on and
    read; a dropped link would store Traefik's address on the keycloak network instead.
    """
    for event in events:
        address = event.get("ipAddress")
        expect(
            address == request_address,
            f"the stored {event['type']} event carries the IP address {address}, "
            f"not the request's {request_address}",
        )
    return sorted(event["type"] for event in events)


# --- The throwaway stack --------------------------------------------------------------------


def write_appkit_files() -> None:
    """The themes bind appkit's files from this checkout, where no apply runs. The repository's own
    `uv run` writes them, because the interpreter this probe runs under may lack appkit."""
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["uv", "run", "--project", str(REPO), "python", "-m", "hal.stack.appkit_step", str(REPO)],  # noqa: S607 - uv is found on PATH by design
        capture_output=True,
        text=True,
        check=False,
    )
    expect(result.returncode == 0, f"appkit step failed:\n{tail(result.stderr)}")


@dataclass
class Stack:
    scratch: Path
    admin_url: str = ""  # a test's stand-in; empty, the admin entrypoint's own free port
    write_appkit: Callable[[], None] = write_appkit_files  # a test's stand-in writes nothing
    edge_url: str = field(init=False)
    edge_port: int = field(init=False)
    admin_port: int = field(init=False)
    traefik_config: Path = field(init=False)
    network_overlay: Path = field(init=False)
    keycloak_subnet: str = field(init=False)
    secrets_dir: Path = field(init=False)
    config_dir: Path = field(init=False)
    # Everything a secret could leak into, for proof 7: each container's Config.Env as it was
    # seen, and the output of every compose command (applies and service logs included).
    seen_env: list[tuple[str, list[str]]] = field(init=False, default_factory=list)
    outputs: list[str] = field(init=False, default_factory=list)

    def __post_init__(self) -> None:
        self.secrets_dir = self.scratch / "secrets"
        self.config_dir = self.scratch / "config"
        self.traefik_config = self.scratch / TRAEFIK_CONFIG
        self.edge_port, self.admin_port = free_loopback_ports(2)
        self.edge_url = f"http://127.0.0.1:{self.edge_port}"
        self.admin_url = self.admin_url or f"http://localhost:{self.admin_port}"
        self.keycloak_subnet = free_subnet()
        self.network_overlay = self.scratch / NETWORK_OVERLAY
        self.write_network_overlay()

    @property
    def master_issuer(self) -> str:
        return f"{self.admin_url}/realms/master"

    @property
    def master_token_url(self) -> str:
        return f"{self.master_issuer}/protocol/openid-connect/token"

    @property
    def admin_console_redirect(self) -> str:
        return f"{self.admin_url}/admin/master/console/"

    def environment(self, config_dir: Path) -> dict[str, str]:
        return {
            **os.environ,
            "EDGE_DOMAIN": DOMAIN,
            "DOCKER_GID": os.environ.get("DOCKER_GID") or str(grp.getgrnam("docker").gr_gid),
            "PROBE_SECRETS_DIR": str(self.secrets_dir),
            "PROBE_CONFIG_DIR": str(config_dir),
            "PROBE_TRAEFIK_CONFIG": str(self.traefik_config),
            "PROBE_ADMIN_URL": self.admin_url,
            "PROBE_KEYCLOAK_SUBNET": self.keycloak_subnet,
        }

    def write_network_overlay(self) -> None:
        """The keycloak network on this stack's free subnet instead of the live one. A compose
        file cannot replace the base file's list of subnets, so the base file's is dropped with
        compose's own `!override` tag here, which the repository's YAML checks never read."""
        self.scratch.mkdir(parents=True, exist_ok=True)
        self.network_overlay.write_text(
            "networks:\n  keycloak:\n    ipam:\n      config: !override\n"
            f"        - subnet: {self.keycloak_subnet}\n"
        )

    def write_traefik_config(self) -> None:
        """The repository's traefik.yml with the entrypoints on the probe's free ports and the
        Docker provider limited to the probe's own project, so the probe runs beside the live
        edge (which holds 8081 and 8090) and neither Traefik routes to the other's containers."""
        text = (REPO / TRAEFIK_CONFIG).read_text()
        for live, probe in {
            LIVE_EDGE_ADDRESS: f"{LOOPBACK_ADDRESS}:{self.edge_port}",
            LIVE_ADMIN_ADDRESS: f"{LOOPBACK_ADDRESS}:{self.admin_port}",
            LIVE_CONSTRAINTS: PROBE_CONSTRAINTS,
        }.items():
            expect(live in text, f"{TRAEFIK_CONFIG} no longer holds {live}")
            text = text.replace(live, probe)
        self.traefik_config.write_text(text)

    def compose(
        self,
        *args: str,
        bootstrap: bool = False,
        config_dir: Path | None = None,
        stdin: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            [*self.compose_command(bootstrap), *args],
            env=self.environment(config_dir or self.config_dir),
            input=stdin,
            capture_output=True,
            text=True,
            check=False,
        )
        self.outputs.append(result.stdout + result.stderr)
        return result

    def compose_command(self, bootstrap: bool = False) -> list[str]:
        files = ["compose.yaml"]
        if bootstrap:
            files.append("keycloak/bootstrap.compose.yaml")
        files.append("probe/keycloak/compose.probe.yaml")
        command = ["docker", "compose", "--project-name", PROJECT, "--project-directory", str(REPO)]
        command += ["--profile", KEYCLOAK_PROFILE]
        for compose_file in files:
            command += ["--file", str(REPO / compose_file)]
        return [*command, "--file", str(self.network_overlay)]

    def write_secrets(self) -> dict[str, str]:
        self.secrets_dir.mkdir(mode=0o700, parents=True)
        values = {}
        for name in SECRET_FILES:
            values[name] = secrets.token_urlsafe(32)
            path = self.secrets_dir / name
            path.parent.mkdir(mode=0o700, exist_ok=True)
            path.write_text(values[name])
            # Readable by the container users (postgres, keycloak-config-cli); the directory
            # stays 0700, so no other host user reaches the file.
            path.chmod(0o644)
        return values

    def copy_config(self, target: Path) -> Path:
        target.mkdir(parents=True)
        for name in CONFIG_FILES:
            shutil.copy(REPO / "keycloak" / name, target / name)
        return target

    def apply(
        self, *, bootstrap: bool = False, config_dir: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        # Kept until inspected, so proof 7 sees the one-off container's Config.Env too.
        container = f"{PROJECT}-apply-{secrets.token_hex(4)}"
        result = self.compose(
            "run",
            "--no-deps",
            "--name",
            container,
            "keycloak-config-cli",
            bootstrap=bootstrap,
            config_dir=config_dir,
        )
        self.see_env(container)
        subprocess.run(["docker", "rm", container], capture_output=True, check=True)  # noqa: S603, S607 - argv is built by the program itself and docker is found on PATH by design
        return result

    def observe(self, digest_key: str, *, keep_as: str = "") -> subprocess.CompletedProcess[str]:
        """One observe as `hal apply` runs it; `keep_as` names and keeps the container, so its
        Config.Env and hardening can be inspected, instead of `--rm`."""
        options = ["--name", keep_as] if keep_as else ["--rm"]
        return self.compose("run", "-T", *options, OBSERVER_SERVICE, stdin=digest_key + "\n")

    def observe_stopped_by(
        self, digest_key: str, stop_signal: signal.Signals, moment: Callable[[Observing], bool]
    ) -> list[str]:
        """Sends `stop_signal` to an observe once `moment` holds; names the containers left."""
        observing = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            [*self.compose_command(), "run", "-T", "--rm", OBSERVER_SERVICE],
            env=self.environment(self.config_dir),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert observing.stdin is not None  # noqa: S101 - narrows the type after stdin is a pipe
        observing.stdin.write(digest_key + "\n")
        observing.stdin.flush()
        deadline = time.monotonic() + OBSERVER_START_SECONDS
        while not moment(observing) and observing.poll() is None:
            expect(time.monotonic() < deadline, f"the observe never reached {moment.__name__}")
            time.sleep(0.05)
        observing.send_signal(stop_signal)
        stdout, stderr = observing.communicate(timeout=OBSERVER_START_SECONDS)
        self.outputs.append(stdout + stderr)
        # A stopped compose stops relaying at once, so stdout may hold part of an inventory and
        # only the exit tells it from one; a signal compose takes this early may be lost, and the
        # observe completes. The inventory is one JSON object on one line
        # (json.dump escapes every newline), so it is whole exactly when it ends in "}\n".
        expect(
            observing.returncode != 0 or stdout.endswith("}\n"),
            f"the observe stopped by {stop_signal.name} {moment.__name__} exited 0 with "
            f"{len(stdout)} bytes of a cut inventory",
        )
        deadline = time.monotonic() + OBSERVER_START_SECONDS
        while observer_containers() and time.monotonic() < deadline:
            time.sleep(0.5)
        return observer_containers()

    def must_apply(self, label: str, **kwargs: Any) -> str:
        result = self.apply(**kwargs)
        output = result.stdout + result.stderr
        expect(result.returncode == 0, f"{label} exited {result.returncode}:\n{tail(output)}")
        return output

    def move_master_to_admin_entrypoint(self) -> None:
        result = self.compose(
            "exec", "-T", "keycloak", "/opt/edge/admin-frontend.sh", bootstrap=True
        )
        output = result.stdout + result.stderr
        expect(
            result.returncode == 0, f"admin-frontend.sh exited {result.returncode}:\n{tail(output)}"
        )

    def up(self, *services: str, bootstrap: bool = False) -> None:
        self.write_appkit()
        result = self.compose("up", "--detach", "--wait", *services, bootstrap=bootstrap)
        expect(result.returncode == 0, f"compose up failed:\n{tail(result.stderr)}")

    def down(self) -> bool:
        """Removes the stack, volumes included, and says whether nothing of it is left."""
        remove_one_offs()
        result = self.compose("down", "--volumes", "--remove-orphans", bootstrap=True)
        left = leftovers()
        removed = result.returncode == 0 and not left
        if removed:
            status = "removed"
        elif result.returncode != 0:
            status = f"FAILED ({tail(result.stderr)})"
        else:
            status = f"FAILED (still there: {', '.join(left)})"
        write_line(f"teardown: stack {PROJECT} {status}", flush=True)
        return removed

    def see_env(self, container: str) -> None:
        inspected = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", "inspect", "--format", "{{.Name}} {{json .Config.Env}}", container],  # noqa: S607 - docker is found on PATH by design
            capture_output=True,
            text=True,
            check=True,
        )
        name, environment = inspected.stdout.split(" ", 1)
        self.seen_env.append((name.lstrip("/"), json.loads(environment)))

    def see_running(self) -> None:
        """Records the Config.Env and the logs of every container the stack runs right now."""
        listed = self.compose("ps", "--quiet")
        expect(listed.returncode == 0, f"compose ps failed:\n{tail(listed.stderr)}")
        container_ids = listed.stdout.split()
        expect(bool(container_ids), "compose ps lists no running container")
        for container_id in container_ids:
            self.see_env(container_id)
        self.logs()

    def logs(self, *services: str) -> str:
        logs = self.compose("logs", "--no-log-prefix", *services)
        expect(logs.returncode == 0, f"compose logs failed:\n{tail(logs.stderr)}")
        return logs.stdout


def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, check=False)  # noqa: S603, S607 - argv is built by the program itself and docker is found on PATH by design


def observer_containers(*states: str) -> list[str]:
    """The observer's containers, of any state unless `states` names some."""
    listed = docker(
        "container",
        "ls",
        "--all",
        "--quiet",
        "--filter",
        f"label={PROJECT_LABEL}",
        "--filter",
        f"label=com.docker.compose.service={OBSERVER_SERVICE}",
        *(option for state in states for option in ("--filter", f"status={state}")),
    )
    return listed.stdout.split()


Observing = subprocess.Popen[str]


# Not as soon as the container exists: a signal compose takes while it still creates the
# container can leave that container behind.
def as_its_container_runs(_observing: Observing) -> bool:
    return bool(observer_containers("running"))


def as_the_inventory_arrives(observing: Observing) -> bool:
    return bool(select.select([observing.stdout], [], [], 0)[0])


def remove_one_offs() -> None:
    # `compose down` skips a one-off `compose run` container that is still running, as an apply
    # is when a SIGTERM kills its compose client.
    listed = docker(
        *("container", "ls", "--all", "--quiet", "--filter", f"label={PROJECT_LABEL}"),
        *("--filter", "label=com.docker.compose.oneoff=True"),
    )
    one_offs = listed.stdout.split()
    if one_offs:
        docker("container", "rm", "--force", *one_offs)


def leftovers() -> list[str]:
    """Names every container, network and volume of the probe's project that still exists."""
    left = []
    for kind, all_flag, name in (
        ("container", ["--all"], "{{.Names}}"),
        ("network", [], "{{.Name}}"),
        ("volume", [], "{{.Name}}"),
    ):
        listed = docker(
            kind, "ls", *all_flag, "--filter", f"label={PROJECT_LABEL}", "--format", name
        )
        if listed.returncode != 0:
            left.append(f"{kind}s unlisted ({tail(listed.stderr)})")
        left += [f"{kind} {found}" for found in listed.stdout.split()]
    return left


def tail(output: str, lines: int = 15) -> str:
    """The last lines of a command's output, without Java stack frames."""
    meaningful = [line for line in output.strip().splitlines() if not line.startswith("\tat ")]
    return "\n".join(meaningful[-lines:])


def free_loopback_ports(count: int) -> list[int]:
    """`count` distinct loopback ports nothing listens on, which the kernel handed out together."""
    sockets = [socket.socket() for _ in range(count)]
    try:
        for held in sockets:
            held.bind((LOOPBACK_ADDRESS, 0))
        return [held.getsockname()[1] for held in sockets]
    finally:
        for held in sockets:
            held.close()


def free_subnet() -> str:
    """The first of SUBNET_CANDIDATES that no Docker network on this host overlaps."""
    listed = docker("network", "ls", "--quiet")
    expect(listed.returncode == 0, f"docker network ls failed:\n{tail(listed.stderr)}")
    ids = listed.stdout.split()
    taken: list[ipaddress.IPv4Network] = []
    if ids:
        inspected = docker(
            "network", "inspect", "--format", "{{range .IPAM.Config}}{{.Subnet}} {{end}}", *ids
        )
        expect(
            inspected.returncode == 0, f"docker network inspect failed:\n{tail(inspected.stderr)}"
        )
        taken = [
            network
            for network in map(ipaddress.ip_network, inspected.stdout.split())
            if isinstance(network, ipaddress.IPv4Network)
        ]
    for candidate in SUBNET_CANDIDATES:
        if not any(ipaddress.ip_network(candidate).overlaps(network) for network in taken):
            return candidate
    raise ProbeFailure(f"no free /24 among {SUBNET_CANDIDATES[0]} ... {SUBNET_CANDIDATES[-1]}")


def wait_until_ready(admin_url: str) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        try:
            if http("GET", f"{admin_url}/realms/master").status == 200:
                return
        except OSError:
            pass
        time.sleep(2)
    raise ProbeFailure(f"Keycloak was not ready on {admin_url} after {READY_TIMEOUT_SECONDS}s")


# --- Admin API --------------------------------------------------------------------------------


@dataclass(frozen=True)
class Admin:
    token: AdminToken
    admin_url: str

    def call(self, method: str, path: str, json_body: Any = None) -> Response:
        url = f"{self.admin_url}/admin/realms{path}"
        return self.token.send(lambda bearer: http(method, url, json_body=json_body, bearer=bearer))

    def get(self, path: str) -> Any:
        response = self.call("GET", path)
        expect(response.status == 200, f"GET {path} answered {response.status}")
        return response.json()

    def create(self, path: str, representation: dict[str, Any]) -> str:
        response = self.call("POST", path, representation)
        expect(response.status == 201, f"POST {path} answered {response.status}: {response.text}")
        return response.headers["Location"].rsplit("/", 1)[-1]

    def must(self, method: str, path: str, json_body: Any = None) -> None:
        response = self.call(method, path, json_body)
        expect(response.status in (200, 204), f"{method} {path} answered {response.status}")

    def create_user(self, realm: str, username: str, password: str) -> str:
        user_id = self.create(
            f"/{realm}/users",
            {
                "username": username,
                "enabled": True,
                "email": f"{username}@probe.invalid",
                "emailVerified": True,
                "firstName": "Probe",
                "lastName": username,
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
        )
        return terms_cell.without_pending_terms(self, user_id) if realm == REALM else user_id

    def join_group(self, user_id: str, group_path: str) -> None:
        group = self.get(f"/{REALM}/group-by-path{group_path}")
        self.must("PUT", f"/{REALM}/users/{user_id}/groups/{group['id']}")

    def group_paths(self, user_id: str) -> list[str]:
        return sorted(group["path"] for group in self.get(f"/{REALM}/users/{user_id}/groups"))

    def admin_event_count(self, realm: str) -> int:
        return len(self.get(f"/{realm}/admin-events?first=0&max=100000"))

    def find(self, path: str, key: str, value: str) -> dict[str, Any]:
        found = [item for item in self.get(path) if item.get(key) == value]
        expect(len(found) == 1, f"GET {path} holds {len(found)} items with {key} {value}")
        return found[0]

    def client(self, client_id: str, realm: str = REALM) -> dict[str, Any]:
        return self.find(f"/{realm}/clients?clientId={client_id}", "clientId", client_id)

    def service_account_user(self, client_id: str, realm: str = REALM) -> dict[str, Any]:
        return self.get(
            f"/{realm}/clients/{self.client(client_id, realm)['id']}/service-account-user"
        )


def hardcoded_claim(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": "oidc-hardcoded-claim-mapper",
        "config": {"claim.name": name, "claim.value": "console", "access.token.claim": "true"},
    }


# --- Browser login (admin console) ------------------------------------------------------------


class FormCollector(HTMLParser):
    """Collects each form's action and its named input values from a Keycloak page."""

    def __init__(self) -> None:
        super().__init__()
        self.forms: list[tuple[str, dict[str, str]]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name: value or "" for name, value in attrs}
        if tag == "form":
            self.forms.append((attributes.get("action", ""), {}))
        elif tag == "input" and self.forms and attributes.get("name"):
            self.forms[-1][1][attributes["name"]] = attributes.get("value", "")


def form_with(page: Response, field_name: str) -> tuple[str, dict[str, str]]:
    collector = FormCollector()
    collector.feed(page.text)
    for action, inputs in collector.forms:
        if field_name in inputs:
            return action, inputs
    raise ProbeFailure(f"page {page.status} has no form with a '{field_name}' field")


def has_field(page: Response, field_name: str) -> bool:
    collector = FormCollector()
    collector.feed(page.text)
    return any(field_name in inputs for _action, inputs in collector.forms)


def load_go_live() -> ModuleType:
    """keycloak/go-live as a module (it has no .py suffix), as the unit tests load it."""
    loader = importlib.machinery.SourceFileLoader(
        "keycloak_go_live", str(REPO / "keycloak/go-live")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None  # noqa: S101 - narrows the type after the loader is built
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # its dataclasses resolve their annotations through it
    loader.exec_module(module)
    return module


def page_message(page: Response) -> str:
    """The feedback a Keycloak page shows the user, for a failure message."""
    found = re.search(
        r'(?:kc-feedback-text|kc-error-message|class="instruction")[^>]*>\s*(?:<[^>]+>\s*)*'
        r"([^<]{3,200})",
        page.text,
    )
    return found.group(1).strip() if found else f"no feedback text ({len(page.body)} bytes)"


def totp(secret: str, period_offset: int = 0) -> str:
    """RFC 6238 code for Keycloak's default policy: HmacSHA1, 6 digits, 30 s, the raw secret."""
    counter = int(time.time()) // 30 + period_offset
    # Keycloak's default OTP policy (RFC 6238's default) is HmacSHA1; the probe answers it and
    # chooses no hash.
    digest = hmac.new(
        secret.encode(),
        struct.pack(">Q", counter),
        hashlib.sha1,  # NOSONAR(S4790)
    ).digest()
    offset = digest[-1] & 0x0F
    number = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1_000_000:06d}"


def within_keycloak(
    response: Response, opener: OpenerDirector, admin_console_redirect: str
) -> Response:
    """Follows Keycloak's own redirects (a required action, say) as a browser would, and stops
    at the redirect back to the admin console."""
    while response.status in (302, 303):
        location = response.headers["Location"]
        if location.startswith(admin_console_redirect):
            break
        response = http("GET", location, opener=opener)
    return response


@dataclass
class RealmStepStand:
    """What proof 12 drives `hal.stack.realm.reconcile` with: this stack's Compose (its project and
    overlays), a repository of the realm files the stack's config-cli mounts, and hal
    under a scratch HOME that backs up this stack's Keycloak database and no other."""

    stack: Stack
    root: Path
    backup_command: tuple[str, ...]
    kinds: Mapping[str, checkout.EntryKind]  # what HEAD tracks of the files the stand copies
    asked: list[list[str]] = field(default_factory=list)

    @classmethod
    def at(cls, stack: Stack) -> RealmStepStand:
        root = stack.scratch / "realm-step"
        password_file = root / "home" / ".secrets" / "restic" / "password"
        password_file.parent.mkdir(mode=0o700, parents=True)
        password_file.write_text(secrets.token_urlsafe(32))
        password_file.chmod(0o600)
        config_dir = stack.copy_config(root / "repository" / "keycloak")
        shutil.copy(REPO / "keycloak" / ENTRYPOINT_FILE, config_dir / ENTRYPOINT_FILE)
        apps = root / "apps.toml"
        apps.write_text(
            "[app.keycloak]\n"
            f'compose_project = "{PROJECT}"\n'
            'db_service = "keycloak-db"\ndump = "pg_dump_custom"\n'
            'db_user = "keycloak"\ndb_name = "keycloak"\npostgres_major = 17\n'
            '[app.keycloak.restore_test]\ncount_table = "realm"\nrequire_rows = true\n'
        )
        executable = shutil.which(
            "hal", path=f"{REPO / '.venv' / 'bin'}{os.pathsep}{os.environ['PATH']}"
        )
        expect(executable is not None, "no hal in the checkout's .venv or on the PATH")
        kinds = checkout.Git(REPO).entry_kinds(("keycloak", f"keycloak/{ENTRYPOINT_FILE}"))
        return cls(stack, root, (executable,), kinds)

    @property
    def repository(self) -> Path:
        return self.root / "repository"

    @property
    def realm_file(self) -> Path:
        return self.repository / "keycloak" / REALM_FILE

    def edit_realm(self, *replacements: tuple[str, str], append: str = "") -> None:
        text = self.realm_file.read_text()
        for old, new in replacements:
            expect(old in text, f"realm.yaml no longer holds {old!r}")
            text = text.replace(old, new)
        # The file lies in the probe's own --scratch directory, which only the operator names.
        self.realm_file.write_text(text + append)  # NOSONAR(S2083)

    def hal(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        command = [*self.backup_command, *arguments, "--apps", str(self.root / "apps.toml")]
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            command,
            env={**os.environ, "HOME": str(self.root / "home")},
            capture_output=True,
            text=True,
            check=False,
            timeout=900,
        )
        self.stack.outputs.append(result.stdout + result.stderr)
        return result

    def run_backup(self, command: list[str], _timeout: int, _stdin: str | None = None):
        self.asked.append(command[len(self.backup_command) :])
        return self.hal(*command[len(self.backup_command) :])

    def run_compose(self, command: list[str], _timeout: int, stdin: str | None = None):
        return self.stack.compose(
            *command[COMPOSE_PREFIX_LENGTH:], stdin=stdin, config_dir=self.repository / "keycloak"
        )

    @property
    def engine(self) -> compose.Compose:
        return compose.Compose(self.run_compose, self.repository)

    @property
    def configuration(self) -> dict[str, Any]:
        """As Compose resolves it, but config-cli's entrypoint is the stand's copy, not REPO's."""
        config = self.engine.resolved_configuration()
        for mount in config["services"][reconcile.CONFIG_CLI]["volumes"]:
            if mount["target"] == "/opt/edge/entrypoint.sh":
                mount["source"] = str(self.repository / "keycloak" / ENTRYPOINT_FILE)
        return config

    def plan(self) -> reconcile.RealmPlan:
        return reconcile.plan_realm(
            reconcile.Observer(self.engine),
            core.Record(self.root / "state"),
            self.configuration,
            core.Checkout(self.repository, self.kinds),
            core.Gate.ON,
            None,
        )

    @property
    def realm(self) -> reconcile.Realm:
        engine, state = self.engine, self.root / "state"
        return reconcile.Realm(
            engine,
            reconcile.Observer(engine),
            reconcile.Backup(self.backup_command, self.run_backup),
            core.Record(state),
            self.configuration,
            core.Checkout(self.repository, self.kinds),
            switches.Switches(state),
            None,
        )

    def apply(self) -> reconcile.StepResult:
        return self.realm.run(self.plan())


# --- Proofs -------------------------------------------------------------------------------------


@dataclass
class Probe:
    stack: Stack
    secret_values: dict[str, str] = field(default_factory=dict)
    member_password: str = field(default_factory=lambda: secrets.token_urlsafe(16))
    evidence: list[str] = field(default_factory=list)
    admin: Admin = field(init=False)
    logout_timeout_seconds: ClassVar[int] = 20

    def say(self, line: str) -> None:
        """Prints a line of evidence and keeps it, so proof 7 can check it for secrets."""
        self.evidence.append(line)
        write_line(line, flush=True)

    def held(self, proof: str, detail: str) -> None:
        self.say(f"PROOF {proof} held: {detail}")

    def through_tunnel(self, method: str, path: str, **kwargs: Any) -> Response:
        return tunnel_request(self.stack.edge_url, method, path, **kwargs)

    def through_tunnel_url(self, method: str, url: str, **kwargs: Any) -> Response:
        return tunnel_request_url(self.stack.edge_url, method, url, **kwargs)

    def keep_secret(self, name: str, value: str) -> str:
        """Registers a credential the probe made or received, so proof 7 looks for it too."""
        self.secret_values[name] = value
        return value

    def tokens_from(self, holder: str, response: Response) -> dict[str, Any]:
        """Reads a token response and registers every token in it, so proof 7 looks for each."""
        expect(
            response.status == 200,
            f"the token request for {holder} answered {response.status}: {response.text}",
        )
        tokens = response.json()
        for kind, value in tokens.items():
            if kind.endswith("_token"):
                self.keep_secret(f"{holder} {kind}", value)
        return tokens

    def admin_minting(self, holder: str, form: dict[str, str]) -> Admin:
        def mint(count: int) -> str:
            response = http("POST", self.stack.master_token_url, form=form)
            name = holder if count == 1 else f"{holder} {count}"
            return self.tokens_from(name, response)["access_token"]

        return Admin(AdminToken(mint), self.stack.admin_url)

    def admin_with_password(self, username: str, password: str) -> Admin:
        form = {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        }
        return self.admin_minting(username, form)

    def admin_with_client(self, secret: str) -> Admin:
        form = {
            "grant_type": "client_credentials",
            "client_id": "config-cli",
            "client_secret": secret,
        }
        return self.admin_minting("config-cli", form)

    def start_with_bootstrap_admin(self) -> Admin:
        self.secret_values = self.stack.write_secrets()
        self.stack.copy_config(self.stack.config_dir)
        self.stack.write_traefik_config()
        self.stack.up(bootstrap=True)
        wait_until_ready(self.stack.admin_url)
        self.stack.move_master_to_admin_entrypoint()
        self.say("stack: up with the temporary bootstrap admin, master on the admin entrypoint")
        return self.admin_with_password(
            "temp-admin", self.secret_values["bootstrap-admin-password"]
        )

    def apply_and_restart(self) -> None:
        self.stack.must_apply("fresh apply", bootstrap=True)
        # The bootstrap keycloak container and its logs disappear when it is recreated below.
        self.stack.see_running()
        self.stack.up("keycloak")
        wait_until_ready(self.stack.admin_url)
        # The config-cli client exists only if the fresh apply created the master configuration.
        self.admin = self.admin_with_client(self.secret_values["config-cli-secret"])
        expect(self.admin.get(f"/{REALM}")["realm"] == REALM, f"no {REALM} realm")

    def run(self) -> None:
        bootstrap_admin = self.start_with_bootstrap_admin()
        self.missing_variable_fails_loudly(bootstrap_admin)
        self.apply_and_restart()
        admin = self.admin
        stand = self.fresh_realm_has_nothing_only_in_keycloak()
        self.held(
            "3a",
            "a fresh apply created the master configuration (the config-cli client signs in "
            "after a restart without the bootstrap overlay) and the hallucinai realm; both "
            "realms hold nothing only in Keycloak: only declared objects and Keycloak's own",
        )

        member_id = self.seed_member(admin)
        self.apply_removes_what_the_observer_names(admin, member_id)
        self.public_issuer_and_paths()
        self.go_live_creates_the_admin(admin)
        self.admin_console_only_on_loopback(admin)
        self.changed_yaml_applies(admin, member_id)
        rp_secret = self.create_probe_rp(admin)
        self.member_token_carries_groups_and_audience(rp_secret)
        self.disabled_user_refused_on_refresh(admin, rp_secret)
        self.backchannel_logout_reaches_rp(admin, rp_secret)
        logout_actions_cell.prove(self, expect, MEMBER_GROUP)
        self.only_logins_and_failed_logins_are_stored(admin, rp_secret)
        for client in APP_CLIENTS:
            self.app_client(admin, client)
        self.the_realm_step(stand)
        self.the_observer_door(admin)
        self.no_secret_leaked()

    def hold(self) -> None:
        """Brings the stack up as `run` does, runs no proof and keeps it until told to stop."""
        self.start_with_bootstrap_admin()
        self.apply_and_restart()
        keep_stack_until_told_to_stop(self.ready_line())

    def ready_line(self) -> str:
        details = {
            "admin_url": self.stack.admin_url,
            "edge_url": self.stack.edge_url,
            "realm": REALM,
            "public_issuer": PUBLIC_ISSUER,
            "admin_client_id": "config-cli",
            "admin_client_secret_file": str(self.stack.secrets_dir / "config-cli-secret"),
        }
        return f"{READY_MARK} {json.dumps(details)}"

    def missing_variable_fails_loudly(self, admin: Admin) -> None:
        broken = self.stack.copy_config(self.stack.scratch / "config-missing-variable")
        realm_file = broken / REALM_FILE
        realm_file.write_text(realm_file.read_text() + UNDEFINED_VARIABLE_LINE)
        result = self.stack.apply(bootstrap=True, config_dir=broken)
        output = result.stdout + result.stderr
        expect(result.returncode != 0, "an apply with an undefined variable exited 0")
        expect("PROBE_UNDEFINED_VARIABLE" in output, "the failure does not name the variable")
        expect(admin.call("GET", f"/{REALM}").status == 404, "the failed apply left a realm")
        self.held(
            "3b",
            f"an undefined variable fails the apply (exit {result.returncode}, names "
            "PROBE_UNDEFINED_VARIABLE) and creates no realm",
        )

    def seed_member(self, admin: Admin) -> str:
        """Stands in for a person and a membership the operator manages in the admin console."""
        password = self.keep_secret("probe-member password", self.member_password)
        member_id = admin.create_user(REALM, "probe-member", password)
        admin.join_group(member_id, MEMBER_GROUP)
        self.say(f"seed: probe-member in {MEMBER_GROUP} through the admin API")
        return member_id

    def observe(self, digest_key: str) -> Inventory:
        result = self.stack.observe(digest_key)
        expect(
            result.returncode == 0, f"an observe exited {result.returncode}: {tail(result.stderr)}"
        )
        return json.loads(result.stdout)

    def apply_removes_what_the_observer_names(self, admin: Admin, member_id: str) -> None:
        digest_key = self.keep_secret("the observer's digest key", new_digest_key())
        events = admin.admin_event_count(REALM)
        first, second = self.observe(digest_key), self.observe(digest_key)
        expect(change_lines(first, second) == [], "two observes of an unchanged Keycloak differ")
        expect(admin.admin_event_count(REALM) == events, f"an observe left admin events in {REALM}")

        self.make_console_changes(admin)
        before = self.observe(digest_key)
        output = self.stack.must_apply("second apply")
        expect("checksum" not in output.lower(), "the second apply consulted the checksum cache")
        after = self.observe(digest_key)
        removed = change_lines(before, after)
        expect(
            removed == RESIDUE_OF_THE_APPLY,
            f"the observer lists {removed}, not the residue the apply removes",
        )
        self.console_changes_survive(admin, member_id)
        self.service_account_is_back_with_its_role_and_no_group(admin)
        self.stack.must_apply("third apply")
        reapplied = self.observe(digest_key)
        again = change_lines(after, reapplied)
        expect(again == [], f"a re-apply changed {again}")
        self.leave_console_subgroup(admin)
        for line in removed:
            self.say(f"observer: {line}")
        self.held(
            "3c",
            "two observes are equal and leave no admin event; a second apply (cache off, nothing "
            f"managed in full) resets the {len(removed)} console changes the observer lists above, "
            "all inside objects the file declares, and keeps the console subgroup with its member, "
            "the console flows, the console role on config-cli's service account and the console "
            f"group on {SERVICE_ACCOUNT_CLIENT}'s, the console default scope on agent-service, the "
            "console client, identity provider, component, realm roles and the agent-service "
            f"mapper, and probe-member in {MEMBER_GROUP}; a third apply lists nothing",
        )
        self.realm_settings_as_decided(admin, reapplied)

    def leave_console_subgroup(self, admin: Admin) -> None:
        """A workload token carries no group (W1), so the listed service account leaves again."""
        account = admin.service_account_user(SERVICE_ACCOUNT_CLIENT)
        group = admin.get(f"/{REALM}/group-by-path{CONSOLE_SUBGROUP}")
        admin.must("DELETE", f"/{REALM}/users/{account['id']}/groups/{group['id']}")

    def service_account_is_back_with_its_role_and_no_group(self, admin: Admin) -> None:
        account = admin.service_account_user(ENABLED_SERVICE_ACCOUNT_CLIENT)
        roles = admin.get(f"/{REALM}/users/{account['id']}/role-mappings/realm")
        names, groups = [role["name"] for role in roles], admin.group_paths(account["id"])
        expect(
            set(WORKLOAD_ROLES.values()) <= set(names) and groups == [],
            f"{ENABLED_SERVICE_ACCOUNT_CLIENT}'s service account has roles {names} and groups "
            f"{groups} after the apply",
        )

    def console_changes_survive(self, admin: Admin, member_id: str) -> None:
        expect(admin.group_paths(member_id) == [MEMBER_GROUP], "the seeded membership changed")
        member = admin.find(
            f"/{REALM}/users?username=probe-console-member", "username", "probe-console-member"
        )
        expect(
            admin.group_paths(member["id"]) == [CONSOLE_SUBGROUP],
            f"the console subgroup {CONSOLE_SUBGROUP} or its member did not survive the apply",
        )
        expect(
            CONSOLE_FLOW in [flow["alias"] for flow in admin.get("/master/authentication/flows")],
            f"the console flow {CONSOLE_FLOW} did not survive the apply",
        )
        agent = admin.find(f"/{REALM}/clients?clientId=agent-service", "clientId", "agent-service")
        scopes = admin.get(f"/{REALM}/clients/{agent['id']}/default-client-scopes")
        expect(
            CONSOLE_SCOPE in [scope["name"] for scope in scopes],
            f"agent-service lost the default scope {CONSOLE_SCOPE} the console added",
        )
        account = admin.service_account_user("config-cli", "master")
        roles = admin.get(f"/master/users/{account['id']}/role-mappings/realm")
        expect(
            f"{CONSOLE_NAME}-role" in [role["name"] for role in roles],
            "the service account lost the console's extra role",
        )
        expect(
            admin.group_paths(admin.service_account_user(SERVICE_ACCOUNT_CLIENT)["id"])
            == [CONSOLE_SUBGROUP],
            f"the listed service account lost the console group {CONSOLE_SUBGROUP}",
        )

    def make_console_changes(self, admin: Admin) -> None:
        """What an operator does in the admin console: additions inside declared objects (the
        residue loses two of them), and further additions of their own."""
        groups_scope = admin.find(f"/{REALM}/client-scopes", "name", "groups")
        admin.create(
            f"/{REALM}/client-scopes/{groups_scope['id']}/protocol-mappers/models",
            hardcoded_claim(f"{CONSOLE_NAME}-mapper"),
        )
        for realm in ("master", REALM):
            admin.create(f"/{realm}/roles", {"name": f"{CONSOLE_NAME}-role"})
        account = admin.service_account_user("config-cli", "master")
        console_role = admin.get(f"/master/roles/{CONSOLE_NAME}-role")
        admin.must("POST", f"/master/users/{account['id']}/role-mappings/realm", [console_role])
        admin.create(
            f"/master/authentication/flows/{FORMS_FLOW}/executions/execution",
            {"provider": "auth-otp-form"},
        )
        admin.create(
            "/master/authentication/flows",
            {"alias": CONSOLE_FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False},
        )
        parent = admin.get(f"/{REALM}/group-by-path{CONSOLE_PARENT}")
        admin.create(f"/{REALM}/groups/{parent['id']}/children", {"name": CONSOLE_SUBGROUP_NAME})
        password = self.keep_secret("probe-console-member password", secrets.token_urlsafe(16))
        admin.join_group(
            admin.create_user(REALM, "probe-console-member", password), CONSOLE_SUBGROUP
        )
        scope_id = admin.create(
            f"/{REALM}/client-scopes", {"name": CONSOLE_SCOPE, "protocol": "openid-connect"}
        )
        agent = admin.find(f"/{REALM}/clients?clientId=agent-service", "clientId", "agent-service")
        admin.must("PUT", f"/{REALM}/clients/{agent['id']}/default-client-scopes/{scope_id}")
        self.make_changes_to_declared_objects(admin, scope_id)
        self.make_survivors(admin)

    def make_changes_to_declared_objects(self, admin: Admin, scope_id: str) -> None:
        """The rest of the class: what hangs off an object the file declares goes with the next
        apply, except a listed user's roles and groups the merge switches keep."""
        admin.create(
            f"/master/authentication/flows/{SUBFLOW_PARENT}/executions/flow",
            {"alias": CONSOLE_SUBFLOW, "type": "basic-flow", "provider": "registration-page-form"},
        )
        role_client = admin.find(
            f"/{REALM}/clients?clientId={AGENT_SERVICE}", "clientId", AGENT_SERVICE
        )
        admin.create(f"/{REALM}/clients/{role_client['id']}/roles", {"name": CONSOLE_CLIENT_ROLE})
        client_role = admin.get(f"/{REALM}/clients/{role_client['id']}/roles/{CONSOLE_CLIENT_ROLE}")
        account = admin.service_account_user(SERVICE_ACCOUNT_CLIENT)
        admin.must(
            "POST",
            f"/{REALM}/users/{account['id']}/role-mappings/clients/{role_client['id']}",
            [client_role],
        )
        admin.join_group(account["id"], CONSOLE_SUBGROUP)
        scoped = admin.client(SCOPED_CLIENT)
        admin.must("PUT", f"/{REALM}/clients/{scoped['id']}/default-client-scopes/{scope_id}")
        flow_id = admin.create(
            f"/{REALM}/authentication/flows",
            {"alias": CONSOLE_FLOW, "providerId": "basic-flow", "topLevel": True, "builtIn": False},
        )
        admin.must(
            "PUT",
            f"/{REALM}/clients/{scoped['id']}",
            {**scoped, "authenticationFlowBindingOverrides": {"browser": flow_id}},
        )
        enabled = admin.client(ENABLED_SERVICE_ACCOUNT_CLIENT)
        admin.must(
            "PUT",
            f"/{REALM}/clients/{enabled['id']}",
            {**enabled, "serviceAccountsEnabled": False},
        )

    def make_survivors(self, admin: Admin) -> None:
        attribute = self.keep_secret("probe-console client attribute", secrets.token_urlsafe(24))
        client_id = admin.create(
            f"/{REALM}/clients",
            {
                "clientId": f"{CONSOLE_NAME}-client",
                "publicClient": False,
                "serviceAccountsEnabled": False,
                "attributes": {"probe.console.secret": attribute},
            },
        )
        secret = admin.get(f"/{REALM}/clients/{client_id}/client-secret")["value"]
        self.keep_secret("probe-console client secret", secret)
        idp_secret = self.keep_secret("console-idp clientSecret", secrets.token_urlsafe(24))
        admin.create(
            f"/{REALM}/identity-provider/instances",
            {
                "alias": "console-idp",
                "providerId": "oidc",
                "enabled": True,
                "trustEmail": False,
                "config": {
                    "clientId": "console",
                    "clientSecret": idp_secret,
                    "clientAuthMethod": "client_secret_post",
                    "authorizationUrl": "https://idp.probe.invalid/auth",
                    "tokenUrl": "https://idp.probe.invalid/token",
                },
            },
        )
        admin.create(
            f"/{REALM}/components",
            {
                "name": f"{CONSOLE_NAME}-component",
                "providerId": "max-clients",
                "providerType": (
                    "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy"
                ),
                "subType": "anonymous",
                "parentId": admin.get(f"/{REALM}")["id"],
                "config": {"max-clients": ["50"]},
            },
        )
        agent = admin.find(f"/{REALM}/clients?clientId=agent-service", "clientId", "agent-service")
        admin.create(
            f"/{REALM}/clients/{agent['id']}/protocol-mappers/models",
            hardcoded_claim(f"{CONSOLE_NAME}-agent-mapper"),
        )

    def realm_settings_as_decided(self, admin: Admin, inventory: Inventory) -> None:
        realm = admin.get(f"/{REALM}")
        master = admin.get("/master")
        expected = {
            "webAuthnPolicyRpId": DOMAIN,
            "webAuthnPolicyPasswordlessRpId": DOMAIN,
            "accessTokenLifespan": 300,
            "ssoSessionMaxLifespan": 2592000,
            "ssoSessionIdleTimeout": 604800,
            "bruteForceProtected": True,
            "eventsEnabled": True,
            "eventsExpiration": 7776000,
            "adminEventsEnabled": True,
            "loginTheme": THEME,
            "accountTheme": THEME,
            "internationalizationEnabled": True,
            "defaultLocale": "en",
        }
        wrong = {key: realm.get(key) for key, value in expected.items() if realm.get(key) != value}
        if sorted(realm.get("supportedLocales", [])) != ["de", "en"]:
            wrong["supportedLocales"] = realm.get("supportedLocales")
        admin_expiry = realm.get("attributes", {}).get("adminEventsExpiration")
        if admin_expiry != "31536000":
            wrong["attributes.adminEventsExpiration"] = admin_expiry
        if sorted(realm.get("enabledEventTypes", [])) != ["LOGIN", "LOGIN_ERROR"]:
            wrong["enabledEventTypes"] = realm.get("enabledEventTypes")
        if realm.get("adminEventsDetailsEnabled"):
            wrong["adminEventsDetailsEnabled"] = True
        providers = inventory[REALM].get("identity provider", {}).values()
        if any(provider["fields"]["trustEmail"] for provider in providers):
            wrong["identityProviders.trustEmail"] = True
        master_expected = {
            "bruteForceProtected": True,
            "browserFlow": "browser-mfa",
            "directGrantFlow": "direct-grant-mfa",
            "webAuthnPolicyRpId": "localhost",
            "loginTheme": None,
            "accountTheme": None,
            "internationalizationEnabled": False,
        }
        for key, value in master_expected.items():
            if master.get(key) != value:
                wrong[f"master.{key}"] = master.get(key)
        expect(not wrong, f"realm settings differ from the decisions: {wrong}")
        self.held(
            "8",
            "rpId hallucinai.de, access token 300 s, SSO max 30 d / idle 7 d, login events "
            "90 d (LOGIN and LOGIN_ERROR only), admin events 1 y without details (no client "
            "representation in them), "
            "brute force on in both realms, "
            f"{len(providers)} identity providers (so no trustEmail=true), master browser flow "
            "browser-mfa, direct grant direct-grant-mfa, rpId localhost, "
            "master theme and language untouched; hallucinai themes and de/en as decided",
        )

    def public_issuer_and_paths(self) -> None:
        discovery = self.through_tunnel("GET", f"{REALM_PATH}/.well-known/openid-configuration")
        expect(discovery.status == 200, f"public discovery answered {discovery.status}")
        issuer = discovery.json()["issuer"]
        expect(issuer == PUBLIC_ISSUER, f"public issuer is {issuer}")
        login_path = f"{REALM_PATH}/protocol/openid-connect/auth?" + urlencode(
            {
                "client_id": "account-console",
                "redirect_uri": f"https://{PUBLIC_HOST}{REALM_PATH}/account/",
                "response_type": "code",
                "scope": "openid",
                "code_challenge": "x" * 43,
                "code_challenge_method": "S256",
            }
        )
        login_page = self.through_tunnel("GET", login_path)
        expect(login_page.status == 200, f"public login page answered {login_page.status}")
        expect("HTTPS required" not in login_page.text, "the login page demands HTTPS")
        login_resource = self.themed_resource(login_page, "login")
        german = self.through_tunnel("GET", login_path, headers={"Accept-Language": "de"})
        expect(
            "Passwort" in german.text and 'lang="de"' in german.text,
            "the login page does not speak German for Accept-Language: de",
        )
        expect(self.has_language_switcher(german), "the German login page has no language switcher")
        for asked in ({"Accept-Language": "fr"}, {}):
            english = self.through_tunnel("GET", login_path, headers=asked)
            expect(
                'lang="en"' in english.text and "Password" in english.text,
                f"the login page does not speak English for {asked or 'no language'}",
            )
        account_page = self.through_tunnel("GET", f"{REALM_PATH}/account/")
        expect(account_page.status == 200, f"the account console answered {account_page.status}")
        account_resource = self.themed_resource(account_page, "account")
        self.held(
            "1",
            f"public discovery issuer {issuer}; the login page renders without HTTPS error, "
            f"links {login_resource} and the account console links {account_resource} "
            "(both 200); German for Accept-Language de with a language switcher, English for "
            "fr and for none",
        )

        localization = self.through_tunnel("GET", f"/resources/{REALM}/account/en")
        expect(localization.status == 200, f"account localization answered {localization.status}")

        refused = [
            (PUBLIC_HOST, "/realms/master/.well-known/openid-configuration"),
            (PUBLIC_HOST, "/realms/master/protocol/openid-connect/token"),
            (PUBLIC_HOST, "/resources/master/login/en"),
            (PUBLIC_HOST, "/resources/master/admin/en"),
            (PUBLIC_HOST, "/admin/"),
            (PUBLIC_HOST, "/admin/master/console/"),
            (PUBLIC_HOST, "/metrics"),
            (PUBLIC_HOST, "/health"),
            (PUBLIC_HOST, "/realms/hallucinai/../master/.well-known/openid-configuration"),
            ("localhost", f"{REALM_PATH}/.well-known/openid-configuration"),
            ("localhost", "/admin/master/console/"),
        ]
        for host, path in refused:
            answer = self.through_tunnel("GET", path, host=host)
            expect(
                answer.status == 404 and answer.body == TRAEFIK_NOT_FOUND,
                f"the edge entrypoint {host}{path} answered {answer.status}, not Traefik's 404",
            )
        account_page = f"https://{PUBLIC_HOST}{REALM_PATH}/account"
        for bare_address in ("/", "/?x=1"):
            redirect = self.through_tunnel("GET", bare_address)
            expect(
                (redirect.status, redirect.headers.get("Location")) == (302, account_page),
                f"the edge entrypoint {PUBLIC_HOST}{bare_address} answered {redirect.status} "
                f"to {redirect.headers.get('Location')}, not 302 to {account_page}",
            )
        # Inside the admitted prefix, so only the entrypoint's encoded-character rule stops it.
        encoded = self.through_tunnel("GET", "/realms/hallucinai/..%2Fmaster/")
        expect(
            encoded.status == 400,
            f"an encoded slash on the edge entrypoint answered {encoded.status}",
        )
        self.held(
            "2a",
            "the edge entrypoint answers /realms/hallucinai/, its localization and the versioned "
            f"static resources; Traefik refuses {len(refused)} master realm and master resources, "
            "admin, metrics, health, traversal and Host: localhost requests (404), redirects the "
            "bare / and /?x=1 to the account page (302) "
            "and refuses an encoded slash inside the admitted prefix (400)",
        )

    @staticmethod
    def has_language_switcher(page: Response) -> bool:
        return "login-select-toggle" in page.text

    def themed_resource(self, page: Response, area: str) -> str:
        """The first /resources/<version>/<area>/hallucinai/ link of a page, fetched and 200."""
        link = re.search(
            rf'(?:href|src)="([^"]*/resources/[a-z0-9]{{5}}/{area}/{THEME}/[^"]+)"', page.text
        )
        expect(link is not None, f"the {area} page links nothing under {area}/{THEME}/")
        path = link.group(1)
        resource = self.through_tunnel("GET", path[path.index("/resources/") :])
        expect(resource.status == 200, f"{path} answered {resource.status}")
        self.say(f"{path} Cache-Control: {resource.headers.get('Cache-Control')}")
        return path

    def admin_console_password_step(
        self, holder: str, username: str, password: str
    ) -> tuple[OpenerDirector, str, Response]:
        """Opens the admin console's login and posts the password like a browser does; returns the
        session's opener, the PKCE verifier and the page that follows the password. The verifier
        and the session cookies are credentials as well, so proof 7 looks for them too."""
        opener = new_opener(
            ReceivedCookies(lambda name, value: self.keep_secret(f"{holder} {name}", value))
        )
        verifier = self.keep_secret(f"{holder} PKCE verifier", secrets.token_urlsafe(48))
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        query = urlencode(
            {
                "client_id": "security-admin-console",
                "redirect_uri": self.stack.admin_console_redirect,
                "response_type": "code",
                "scope": "openid",
                "state": secrets.token_urlsafe(8),
                "nonce": secrets.token_urlsafe(8),
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            }
        )
        login_page = http(
            "GET", f"{self.stack.master_issuer}/protocol/openid-connect/auth?{query}", opener=opener
        )
        expect(login_page.status == 200, f"admin login page answered {login_page.status}")
        action, fields = form_with(login_page, "username")
        fields |= {"username": username, "password": password}
        factor_page = within_keycloak(
            http("POST", action, form=fields, opener=opener),
            opener,
            self.stack.admin_console_redirect,
        )
        expect(
            factor_page.status == 200,
            f"password step answered {factor_page.status}: {page_message(factor_page)}",
        )
        return opener, verifier, factor_page

    def admin_console_login(
        self, holder: str, username: str, password: str, second_factor: Any
    ) -> dict[str, Any]:
        """Signs in to the admin console like a browser does and returns the token response.

        `second_factor(page)` answers the page that follows the password: it returns the form
        action and the fields to post. The authorization code is a credential too.
        """
        opener, verifier, factor_page = self.admin_console_password_step(holder, username, password)
        action, fields = second_factor(factor_page)
        done = within_keycloak(
            http("POST", action, form=fields, opener=opener),
            opener,
            self.stack.admin_console_redirect,
        )
        location = done.headers.get("Location", "")
        expect(
            done.status == 302 and location.startswith(self.stack.admin_console_redirect),
            f"second factor answered {done.status} without the console redirect: "
            f"{page_message(done)}",
        )
        code = parse_qs(urlsplit(location).query)["code"][0]
        self.keep_secret(f"{holder} authorization code", code)
        token_form = {
            "grant_type": "authorization_code",
            "client_id": "security-admin-console",
            "redirect_uri": self.stack.admin_console_redirect,
            "code": code,
            "code_verifier": verifier,
        }
        return self.tokens_from(
            holder, http("POST", self.stack.master_token_url, form=token_form, opener=opener)
        )

    def go_live_creates_the_admin(self, admin: Admin) -> None:
        """Proof 11 (#129): go-live's admin step, driven as its own steps (never `run()`, whose
        compose calls would reach the operator's project), makes an admin a real Keycloak accepts.
        Runs before proof 2b, whose probe-admin would make the step's done-state true."""
        listed = admin.get("/master/authentication/required-actions")
        enabled = {action["alias"]: action["enabled"] for action in listed}
        expect(
            all(enabled.get(alias) is True for alias in ADMIN_REQUIRED_ACTIONS),
            f"required actions enabled in master: "
            f"{ {alias: enabled.get(alias) for alias in ADMIN_REQUIRED_ACTIONS} }",
        )
        password = self.keep_secret("go-live admin password", secrets.token_urlsafe(16))
        step = self.go_live_admin_step(password, typed_answers=True)
        expect(
            not step.is_done(),
            "go-live's admin step is done before it ran: config-cli's service account is no admin",
        )
        step.do()
        expect(step.is_done(), "go-live's admin step is not done after it ran")

        user = admin.find(
            f"/master/users?username={GO_LIVE_ADMIN}&exact=true", "username", GO_LIVE_ADMIN
        )
        roles = [
            role["name"] for role in admin.get(f"/master/users/{user['id']}/role-mappings/realm")
        ]
        expect(
            user["enabled"] and "admin" in roles,
            f"go-live's admin: enabled {user['enabled']}, roles {roles}",
        )
        expect(
            sorted(user["requiredActions"]) == sorted(ADMIN_REQUIRED_ACTIONS),
            f"go-live's admin has the required actions {user['requiredActions']}",
        )
        grant = http(
            "POST",
            self.stack.master_token_url,
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": GO_LIVE_ADMIN,
                "password": password,
            },
        )
        expect(
            grant.status == 401 and b"access_token" not in grant.body,
            f"a password grant of go-live's admin without TOTP answered {grant.status}",
        )

        opener, _verifier, first_page = self.admin_console_password_step(
            "go-live admin console", GO_LIVE_ADMIN, password
        )
        action, fields = form_with(first_page, "totpSecret")
        self.keep_secret("go-live admin TOTP seed", fields["totpSecret"])
        after_totp = within_keycloak(
            http(
                "POST",
                action,
                form=fields | {"totp": totp(fields["totpSecret"]), "userLabel": "probe"},
                opener=opener,
            ),
            opener,
            self.stack.admin_console_redirect,
        )
        expect(
            after_totp.status == 200 and has_field(after_totp, "attestationObject"),
            f"after the TOTP the next page was not the passkey page: {after_totp.status}, "
            f"{page_message(after_totp)}",
        )
        expect(
            not has_field(after_totp, "password-new"),
            "the sign-in asks for a new password although the password is permanent",
        )

        rerun = self.go_live_admin_step(password, typed_answers=False)
        expect(rerun.is_done(), "go-live's admin step is not done on its second run")
        again = self.admin_console_password_step(
            "go-live admin second console", GO_LIVE_ADMIN, password
        )[2]
        expect(
            not has_field(again, "password"), "the typed password is refused on the second sign-in"
        )
        expect(
            len(admin.get(f"/master/users?username={GO_LIVE_ADMIN}")) == 1,
            "the second run made another user",
        )

        master = admin.get("/master")
        expect(
            not master.get("adminEventsEnabled") and not master.get("adminEventsDetailsEnabled"),
            "master stores admin events, so the create body could be kept",
        )
        stored = json.dumps(admin.get("/master/admin-events?first=0&max=100000"))
        expect(password not in stored, "the typed password is in master's admin events")
        self.held(
            "11",
            f"go-live's admin step (step 6, driven on its own) created {GO_LIVE_ADMIN} with the "
            "realm role admin and CONFIGURE_TOTP and webauthn-register pending (both enabled in "
            "master); the password grant without TOTP is refused (401); the browser sign-in with "
            "the typed password shows the TOTP enrolment, then the passkey page and no password "
            "update; a second run asks nothing, adds no user and the password still signs in; "
            "master's admin events are off and hold no password. Passkey registration itself is "
            "not driven (no authenticator): the operator's go-live is its proof",
        )

    def go_live_admin_step(self, password: str, *, typed_answers: bool) -> Any:
        """Step 6 of keycloak/go-live over the probe's stack. Its `run` raises on any call: no
        compose command may run, because go-live's compose targets the operator's project. A
        step that must not ask makes any prompt a failure."""
        go_live = load_go_live()
        # go-live pins the live entrypoint addresses; this stack's are its own.
        go_live.ADMIN_URL = self.stack.admin_url
        go_live.EDGE_URL = self.stack.edge_url
        go_live.MASTER_ISSUER = self.stack.master_issuer
        go_live.MASTER_TOKEN_URL = self.stack.master_token_url
        go_live.ADMIN_REALMS = f"{self.stack.admin_url}/admin/realms"
        for name, value in vars(go_live).items():
            expect(
                not isinstance(value, str)
                or not any(live in value for live in LIVE_GO_LIVE_ADDRESSES),
                f"go-live's {name} still names the live edge: {value}",
            )

        def no_command(*_args: object, **_kwargs: object) -> object:
            raise ProbeFailure("go-live's admin step ran a command")

        def answer(prompt: str) -> str:
            expect(typed_answers, f"go-live's admin step asked: {prompt}")
            return ""

        def answer_hidden(prompt: str) -> str:
            expect(typed_answers, "go-live's admin step asked for a password")
            return password

        tools = go_live.Tools(
            run=no_command,
            ask=answer,
            ask_hidden=answer_hidden,
            default_user=lambda: GO_LIVE_ADMIN,
            say=self.say,
        )
        marks = go_live.switches.Switches(self.stack.scratch / "switches")
        steps = go_live.GoLive(tools, self.stack.secrets_dir, marks).steps()
        return next(step for step in steps if step.number == "6")

    def admin_console_only_on_loopback(self, admin: Admin) -> None:
        master_discovery = http(
            "GET", f"{self.stack.master_issuer}/.well-known/openid-configuration"
        )
        expect(
            master_discovery.status == 200, f"master discovery answered {master_discovery.status}"
        )
        issuer = master_discovery.json()["issuer"]
        expect(issuer == self.stack.master_issuer, f"master issuer is {issuer}")
        foreign_host = http(
            "GET", f"{self.stack.admin_url}/realms/hallucinai/", headers={"Host": PUBLIC_HOST}
        )
        expect(
            foreign_host.status == 404,
            f"the admin entrypoint with the public host answered {foreign_host.status}",
        )
        encoded = http("GET", f"{self.stack.admin_url}/admin%2Fmaster/console/")
        expect(
            encoded.status == 400,
            f"an encoded slash on the admin entrypoint answered {encoded.status}",
        )

        password = self.keep_secret("probe-admin password", secrets.token_urlsafe(16))
        admin_id = admin.create_user("master", "probe-admin", password)
        admin_role = admin.get("/master/roles/admin")
        admin.must("POST", f"/master/users/{admin_id}/role-mappings/realm", [admin_role])
        password_only = http(
            "POST",
            self.stack.master_token_url,
            form={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": "probe-admin",
                "password": password,
            },
        )
        expect(
            password_only.status == 401 and b"access_token" not in password_only.body,
            f"an admin-cli password grant without TOTP answered {password_only.status}",
        )
        enrolled: dict[str, str] = {}

        def enrol_totp(page: Response) -> tuple[str, dict[str, str]]:
            action, fields = form_with(page, "totpSecret")
            enrolled["secret"] = self.keep_secret("probe-admin TOTP seed", fields["totpSecret"])
            return action, fields | {"totp": totp(fields["totpSecret"]), "userLabel": "probe"}

        first_login = self.admin_console_login(
            "probe-admin console", "probe-admin", password, enrol_totp
        )
        first = claims(first_login["access_token"])
        expect(first["iss"] == self.stack.master_issuer, f"admin token issuer is {first['iss']}")

        def answer_otp(page: Response) -> tuple[str, dict[str, str]]:
            action, fields = form_with(page, "otp")
            # The next period's code: the first one was spent, and Keycloak's look-around
            # window of one period accepts the next.
            return action, fields | {"otp": totp(enrolled["secret"], period_offset=1)}

        second_login = self.admin_console_login(
            "probe-admin second console", "probe-admin", password, answer_otp
        )
        second = claims(second_login["access_token"])
        expect(
            second["iss"] == self.stack.master_issuer,
            f"second admin token issuer is {second['iss']}",
        )
        self.held(
            "2b",
            f"on the admin entrypoint the master issuer is {issuer}; a new admin's admin-cli "
            "password grant without TOTP is refused (401), the admin must enrol TOTP before the "
            "console login completes, the next login demands the code; it refuses the public host "
            "(404) and an encoded slash (400)",
        )

    @staticmethod
    def changed_realm_text(text: str) -> str:
        expect(LIFESPAN_SETTING in text, "realm.yaml no longer sets 300 s as expected")
        text = text.replace(LIFESPAN_SETTING, CHANGED_LIFESPAN_SETTING)
        # The change swaps one group tree for another group and drops a client: the apply adds the
        # new group and, deleting nothing, keeps the dropped groups and client.
        group_start = text.find(f"  - name: {DROPPED_GROUP}\n")
        group_end = text.find("clientScopes:\n")
        expect(0 <= group_start < group_end, f"realm.yaml no longer lists group {DROPPED_GROUP}")
        text = text[:group_start] + f"  - name: {CHANGED_GROUP}\n" + text[group_end:]
        client_start = text.find(f"  - clientId: {DROPPED_CLIENT}\n")
        client_end = text.find("  # One client for presentator")
        expect(
            0 <= client_start < client_end,
            f"realm.yaml no longer lists the client {DROPPED_CLIENT}",
        )
        text = text[:client_start] + text[client_end:]
        roles_start, roles_end = text.find("\nroles:\n  realm:\n"), text.find("\ngroups:\n")
        expect(0 <= roles_start < roles_end, "realm.yaml no longer lists the realm roles")
        return text[: roles_start + 1] + EMPTY_REALM_ROLES + text[roles_end + 1 :]

    def changed_yaml_applies(self, admin: Admin, member_id: str) -> None:
        changed = self.stack.copy_config(self.stack.scratch / "config-changed")
        realm_file = changed / REALM_FILE
        realm_file.write_text(self.changed_realm_text(realm_file.read_text()))
        self.stack.must_apply("changed apply", config_dir=changed)
        realm = admin.get(f"/{REALM}")
        expect(
            realm["accessTokenLifespan"] == CHANGED_ACCESS_TOKEN_LIFESPAN,
            f"access token lifespan is {realm['accessTokenLifespan']} after the change",
        )
        expect(
            admin.call("GET", f"/{REALM}/group-by-path/{CHANGED_GROUP}").status == 200,
            f"group {CHANGED_GROUP} was not created",
        )
        for path in (SUBSCRIPTION_GROUP, CONSOLE_SUBGROUP):
            expect(
                admin.call("GET", f"/{REALM}/group-by-path{path}").status == 200,
                f"the group {path} did not survive the changed apply",
            )
        expect(
            bool(admin.get(f"/{REALM}/clients?clientId={DROPPED_CLIENT}")),
            f"the client {DROPPED_CLIENT}, dropped from realm.yaml, did not survive the apply",
        )
        expect(admin.group_paths(member_id) == [MEMBER_GROUP], "the seeded membership changed")
        for role, holders in ROLE_HOLDERS.items():
            found = sorted(user["username"] for user in admin.get(f"/{REALM}/roles/{role}/users"))
            expect(
                found == sorted(holders),
                f"the role {role}, dropped from realm.yaml, or its service accounts did not "
                f"survive the apply: {found}",
            )
        self.held(
            "3d",
            f"a changed realm.yaml applies (access token {CHANGED_ACCESS_TOKEN_LIFESPAN} s, "
            f"group /{CHANGED_GROUP}) and deletes nothing it dropped: "
            f"the group /{DROPPED_GROUP} tree and the client {DROPPED_CLIENT} and the roles "
            f"{sorted(ROLE_HOLDERS)} with their service-account "
            f"holders, all dropped from realm.yaml, and the console-made {CONSOLE_SUBGROUP} stay; "
            f"probe-member is still in {MEMBER_GROUP}",
        )

    def create_probe_rp(self, admin: Admin) -> str:
        representation = json.loads((REPO / "probe/keycloak/probe-rp-client.json").read_text())
        client_id = admin.create(f"/{REALM}/clients", representation)
        secret = admin.get(f"/{REALM}/clients/{client_id}/client-secret")["value"]
        return self.keep_secret("probe-rp client secret", secret)

    def password_grant(
        self,
        username: str,
        password: str,
        rp_secret: str,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        response = self.through_tunnel(
            "POST",
            PUBLIC_TOKEN_PATH,
            headers=headers,
            form={
                "grant_type": "password",
                "client_id": "probe-rp",
                "client_secret": rp_secret,
                "username": username,
                "password": password,
                "scope": "openid",
            },
        )
        return self.tokens_from(username, response)

    def member_token_carries_groups_and_audience(self, rp_secret: str) -> None:
        tokens = self.password_grant("probe-member", self.member_password, rp_secret)
        access = claims(tokens["access_token"])
        audience = audience_of(access)
        expect(access.get("iss") == PUBLIC_ISSUER, f"access token issuer is {access.get('iss')}")
        expect(MEMBER_GROUP in access.get("groups", []), f"groups claim is {access.get('groups')}")
        expect("agent-service" in audience, f"audience is {audience}")
        self.held(
            "4",
            f"probe-member's access token: iss {access['iss']}, groups {access['groups']}, "
            f"aud {audience}",
        )

    def disabled_user_refused_on_refresh(self, admin: Admin, rp_secret: str) -> None:
        password = self.keep_secret("probe-disabled password", secrets.token_urlsafe(16))
        user_id = admin.create_user(REALM, "probe-disabled", password)
        tokens = self.password_grant("probe-disabled", password, rp_secret)
        admin.must("PUT", f"/{REALM}/users/{user_id}", {"enabled": False})
        refresh = self.through_tunnel(
            "POST",
            PUBLIC_TOKEN_PATH,
            form={
                "grant_type": "refresh_token",
                "client_id": "probe-rp",
                "client_secret": rp_secret,
                "refresh_token": tokens["refresh_token"],
            },
        )
        error = refresh.json().get("error") if refresh.status == 400 else None
        expect(error == "invalid_grant", f"refresh after disabling answered {refresh.status}")
        self.held("5", "a disabled user's refresh is refused (400 invalid_grant)")

    def backchannel_logout_reaches_rp(self, admin: Admin, rp_secret: str) -> None:
        password = self.keep_secret("probe-logout password", secrets.token_urlsafe(16))
        user_id = admin.create_user(REALM, "probe-logout", password)
        self.password_grant("probe-logout", password, rp_secret)
        admin.must("POST", f"/{REALM}/users/{user_id}/logout")
        record = self.logout_record(user_id)
        expect(record is not None, f"probe-rp saw no logout within {self.logout_timeout_seconds}s")
        expect((iss := record["iss"]) == PUBLIC_ISSUER, f"logout iss is {iss}")
        self.held("6", f"admin logout reached probe-rp (iss {iss}, sid {bool(record['sid'])})")
        self.held("BC1", backchannel_cell.prove(self, admin, rp_secret, expect))

    def logout_record(self, user_id: str) -> dict[str, Any] | None:
        deadline = time.monotonic() + self.logout_timeout_seconds
        while time.monotonic() < deadline:
            for line in re.findall(r"^backchannel-logout (.*)$", self.stack.logs("probe-rp"), re.M):
                if (record := json.loads(line))["sub"] == user_id and time.monotonic() < deadline:
                    return record
            time.sleep(1)

    def only_logins_and_failed_logins_are_stored(self, admin: Admin, rp_secret: str) -> None:
        password = self.keep_secret("probe-events password", secrets.token_urlsafe(16))
        user_id = admin.create_user(REALM, "probe-events", password)
        forwarded = {
            "Forwarded": cloudflare_forwarded(CLIENT_ADDRESS),
            "X-Forwarded-For": FORGED_FORWARDED_FOR,
        }

        def wrong_password(headers: dict[str, str]) -> Response:
            return self.through_tunnel(
                "POST",
                PUBLIC_TOKEN_PATH,
                headers=headers,
                form={
                    "grant_type": "password",
                    "client_id": "probe-rp",
                    "client_secret": rp_secret,
                    "username": "probe-events",
                    "password": "not-the-password",
                },
            )

        tokens = self.password_grant("probe-events", password, rp_secret, forwarded)
        refused = wrong_password(forwarded)
        expect(refused.status == 400, f"a wrong password answered {refused.status}")
        logout = self.through_tunnel(
            "POST",
            PUBLIC_LOGOUT_PATH,
            form={
                "client_id": "probe-rp",
                "client_secret": rp_secret,
                "refresh_token": tokens["refresh_token"],
            },
        )
        expect(logout.status == 204, f"the logout answered {logout.status}")
        events_path = f"/{REALM}/events?user={user_id}"
        stored = stored_event_types(admin.get(events_path), CLIENT_ADDRESS)
        expect(
            stored == ["LOGIN", "LOGIN_ERROR"],
            f"probe-events has the stored events {stored}, not one LOGIN and one LOGIN_ERROR",
        )
        forwarded_ipv6 = {**forwarded, "Forwarded": cloudflare_forwarded(CLIENT_ADDRESS_IPV6)}
        refused_ipv6 = wrong_password(forwarded_ipv6)
        expect(refused_ipv6.status == 400, f"a wrong password answered {refused_ipv6.status}")
        events_after_ipv6 = admin.get(events_path)
        types_after_ipv6 = sorted(event["type"] for event in events_after_ipv6)
        expect(
            types_after_ipv6 == ["LOGIN", "LOGIN_ERROR", "LOGIN_ERROR"],
            f"probe-events has the stored events {types_after_ipv6} after the IPv6 wrong password, "
            "not one LOGIN and two LOGIN_ERROR",
        )
        newest = max(events_after_ipv6, key=lambda event: event["time"])
        stored_ipv6 = f"[{CLIENT_ADDRESS_IPV6}]"  # Keycloak keeps RFC 7239's brackets
        expect(
            newest["type"] == "LOGIN_ERROR" and newest.get("ipAddress") == stored_ipv6,
            f"the newest {newest['type']} event carries the IP address {newest.get('ipAddress')}, "
            f"not {stored_ipv6}",
        )
        self.held(
            "EV2",
            "a sign-in stored one LOGIN, a wrong password one LOGIN_ERROR, both with the "
            f"Forwarded client address {CLIENT_ADDRESS} and not the forged X-Forwarded-For "
            f"{FORGED_FORWARDED_FOR!r}, a wrong password from {CLIENT_ADDRESS_IPV6} one more "
            "LOGIN_ERROR with that IPv6 address in brackets, a logout none",
        )

    def app_client(self, admin: Admin, client: AppClient) -> None:
        """Proof 10 (#108, #161): an app's client does what #11 lists, through the public tunnel."""
        name = client.client_id
        username = f"probe-{name}-member"
        password = self.keep_secret(f"{username} password", secrets.token_urlsafe(16))
        member_id = admin.create_user(REALM, username, password)
        admin.join_group(member_id, client.group)
        admin.join_group(member_id, SUBSCRIPTION_GROUP)
        client_secret = self.secret_values[client.secret_file]
        browser = self.browser(name)
        tokens = self.app_client_sign_in(client, browser, username, password, client_secret)
        groups = claims(tokens["id_token"]).get("groups", [])
        expect(client.group in groups, f"{name}'s ID token groups are {groups}")
        backchannel_cell.refresh_token_follows_the_ruling(name, tokens, expect)
        self.person_token_is_no_workload(client, tokens["access_token"])
        self.app_client_refuses_what_it_does_not_use(client, client_secret)
        self.app_client_logout_pages(client, browser)
        self.app_client_representation(admin, client)
        self.workload_token_carries_the_role(admin, client_secret, client)
        terms_cell.prove(self, expect, form_with, client)
        service_audience_cell.prove(self, expect, client, tokens["access_token"])
        self.held(
            "10",
            f"a member of {client.group} signs in to {name} with PKCE and gets a code "
            f"at exactly {client.callback}, exchanged with the scratch secret for an ID token "
            f"with groups {groups}, and an access token with {SUBSCRIPTION_GROUP} and the "
            f"{AGENT_SERVICE} audience; no code challenge, a suffixed callback, http, the password "
            "grant and the offline_access scope are refused; the end-session page asks before "
            f"logging out for {client.logout_redirect} and refuses an unregistered address and "
            "the origin root; the client's logout, optional scopes, base URL, console listing and "
            "refresh token are as ruled; a person's token has the "
            f"{AGENT_SERVICE} audience and no {AGENT_WORKLOAD_ROLE} role, and its "
            f"client_credentials token has {AGENT_WORKLOAD_ROLE}, client_id and azp {name}, no "
            "group and the realm's lifespan or 1 s more to live (W1 to W3)",
        )

    def browser(self, name: str) -> OpenerDirector:
        return new_opener(ReceivedCookies(lambda c, v: self.keep_secret(f"{name} {c}", v)))

    @staticmethod
    def app_client_authorization_query(client: AppClient, **changes: str) -> str:
        parameters = {
            "client_id": client.client_id,
            "redirect_uri": client.callback,
            "response_type": "code",
            "scope": "openid",
            "state": secrets.token_urlsafe(8),
            "nonce": secrets.token_urlsafe(8),
        }
        return urlencode({**parameters, **changes})

    def app_client_sign_in(
        self,
        client: AppClient,
        opener: OpenerDirector,
        username: str,
        password: str,
        client_secret: str,
        scope: str = "openid",
    ) -> dict[str, Any]:
        """The authorization-code flow with S256 up to the ID token (cells T1, T2)."""
        name = client.client_id
        verifier = self.keep_secret(f"{name} PKCE verifier", secrets.token_urlsafe(48))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        query = self.app_client_authorization_query(
            client,
            scope=scope,
            code_challenge=challenge.rstrip(b"=").decode(),
            code_challenge_method="S256",
        )
        login_page = self.through_tunnel("GET", f"{PUBLIC_AUTH_PATH}?{query}", opener=opener)
        expect(login_page.status == 200, f"{name}'s login page answered {login_page.status}")
        action, fields = form_with(login_page, "username")
        signed_in = self.through_tunnel_url(
            "POST",
            action,
            form=fields | {"username": username, "password": password},
            opener=opener,
        )
        location = signed_in.headers.get("Location", "")
        callback = urlsplit(location)
        expect(
            signed_in.status == 302 and location.startswith(f"{client.callback}?"),
            f"sign-in answered {signed_in.status} with {callback._replace(query='').geturl()!r}, "
            f"not a code at {client.callback}: {page_message(signed_in)}",
        )
        code = self.keep_secret(f"{name} authorization code", parse_qs(callback.query)["code"][0])
        return self.tokens_from(
            username,
            self.through_tunnel(
                "POST",
                PUBLIC_TOKEN_PATH,
                form={
                    "grant_type": "authorization_code",
                    "client_id": name,
                    "client_secret": client_secret,
                    "redirect_uri": client.callback,
                    "code": code,
                    "code_verifier": verifier,
                },
            ),
        )

    def app_client_refuses_what_it_does_not_use(
        self, client: AppClient, client_secret: str
    ) -> None:
        """Cells T3-T5, DG1: PKCE required, exact callback, only songmaker's device grant."""
        without_challenge = self.through_tunnel(
            "GET", f"{PUBLIC_AUTH_PATH}?{self.app_client_authorization_query(client)}"
        )
        error = parse_qs(urlsplit(without_challenge.headers.get("Location", "")).query)
        expect(
            without_challenge.status == 302 and error.get("error") == ["invalid_request"],
            f"an auth request without code_challenge answered {without_challenge.status} "
            f"with {error}",
        )
        for redirect_uri in (
            f"{client.callback}/x",
            client.callback.replace("https", "http"),
        ):
            query = self.app_client_authorization_query(
                client, redirect_uri=redirect_uri, **device_grant_cell.PKCE
            )
            page = self.through_tunnel("GET", f"{PUBLIC_AUTH_PATH}?{query}")
            expect(
                page.status == 400 and "Invalid parameter: redirect_uri" in page.text,
                f"redirect_uri {redirect_uri} answered {page.status}: {page_message(page)}",
            )
        self.app_client_refuses_offline_access(client)
        grant = self.password_grant_of_the_member()
        refused = self.through_tunnel(
            "POST",
            PUBLIC_TOKEN_PATH,
            form={"client_id": client.client_id, "client_secret": client_secret, **grant},
        )
        error = refused.json().get("error") if refused.status in (400, 401) else None
        expect(
            error == "unauthorized_client",
            f"{grant['grant_type']} on {client.client_id} answered {refused.status}",
        )
        device_grant_cell.prove(self, client.client_id, client_secret, expect)

    @staticmethod
    def person_token_is_no_workload(client: AppClient, access_token: str) -> None:
        """Cell W3: a person's token from the app's login has the audience and groups (the app's
        group and the subscription group in full path), never the workload role."""
        access = claims(access_token)
        roles = access.get("realm_access", {}).get("roles", [])
        expect(
            AGENT_SERVICE in audience_of(access)
            and {client.group, SUBSCRIPTION_GROUP} <= set(access.get("groups", []))
            and AGENT_WORKLOAD_ROLE not in roles,
            f"a person's access token from {client.client_id} has aud {audience_of(access)}, "
            f"groups {access.get('groups')}, realm roles {roles}",
        )

    def workload_token_carries_the_role(
        self, admin: Admin, client_secret: str, client: AppClient
    ) -> None:
        """Cells W1, W2: the client-credentials token is the app's workload identity and lives the
        realm's 300 s (proof 8) or 1 s more: Keycloak reads the clock twice."""
        name = client.client_id
        override = admin.find(f"/{REALM}/clients", "clientId", name)["attributes"].get(
            "access.token.lifespan"
        )
        realm_lifespan = admin.get(f"/{REALM}")["accessTokenLifespan"]
        tokens = self.tokens_from(
            f"{name} workload",
            self.through_tunnel(
                "POST",
                PUBLIC_TOKEN_PATH,
                form={
                    "grant_type": "client_credentials",
                    "client_id": name,
                    "client_secret": client_secret,
                },
            ),
        )
        access = claims(tokens["access_token"])
        roles = access.get("realm_access", {}).get("roles", [])
        extra_seconds = access["exp"] - access["iat"] - realm_lifespan
        expect(
            is_workload_identity_of(access, name) and not override and extra_seconds in (0, 1),
            f"{name}'s workload token has realm roles {roles}, aud {audience_of(access)}, "
            f"client_id {access.get('client_id')}, azp {access.get('azp')}, groups "
            f"{access.get('groups')}, lifespan {realm_lifespan + extra_seconds}s (realm "
            f"{realm_lifespan}s, 0 or 1 s more accepted, client override {override})",
        )

    def app_client_refuses_offline_access(self, client: AppClient) -> None:
        """Cell T13: offline_access is no scope of the client, so no offline token is issued."""
        query = self.app_client_authorization_query(
            client, scope="openid offline_access", **device_grant_cell.PKCE
        )
        refused = self.through_tunnel("GET", f"{PUBLIC_AUTH_PATH}?{query}")
        location = refused.headers.get("Location", "")
        error = parse_qs(urlsplit(location).query)
        expect(
            refused.status == 302
            and error.get("error") == ["invalid_scope"]
            and "code" not in error,
            f"scope offline_access answered {refused.status} with {error}: {page_message(refused)}",
        )

    def password_grant_of_the_member(self) -> dict[str, str]:
        return {
            "grant_type": "password",
            "username": "probe-member",
            "password": self.member_password,
        }

    def app_client_logout_pages(self, client: AppClient, browser: OpenerDirector) -> None:
        """Cells T6, T7: with a session, the registered logout address asks before logging out and
        others fail."""

        def end_session(post_logout_redirect_uri: str) -> Response:
            query = urlencode(
                {
                    "client_id": client.client_id,
                    "post_logout_redirect_uri": post_logout_redirect_uri,
                }
            )
            return self.through_tunnel("GET", f"{PUBLIC_LOGOUT_PATH}?{query}", opener=browser)

        registered = end_session(client.logout_redirect)
        expect(
            registered.status == 200 and "Do you want to log out?" in registered.text,
            f"end session with {client.logout_redirect} answered {registered.status} to "
            f"{registered.headers.get('Location')}: {page_message(registered)}",
        )
        for unregistered_address in (f"{client.origin}/elsewhere", f"{client.origin}/"):
            unregistered = end_session(unregistered_address)
            expect(
                unregistered.status == 400,
                f"end session with unregistered {unregistered_address} answered "
                f"{unregistered.status}",
            )

    @staticmethod
    def app_client_representation(admin: Admin, client: AppClient) -> None:
        """Cell T8, #161 SA3-1: flags, callbacks, logout, base URL and console listing."""
        found = admin.find(f"/{REALM}/clients", "clientId", client.client_id)
        wrong = {
            key: found.get(key)
            for key, value in {
                "publicClient": False,
                "standardFlowEnabled": True,
                "implicitFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "serviceAccountsEnabled": True,
                "frontchannelLogout": False,
                "baseUrl": f"{client.origin}/",
                "alwaysDisplayInConsole": False,
            }.items()
            if found.get(key) != value
        } | {
            key: found.get(key)
            for key, value in {
                "redirectUris": set(client.callbacks),
                "defaultClientScopes": client.default_scopes,
                "optionalClientScopes": client.optional_scopes,
            }.items()
            if set(found.get(key) or ()) != value
        }
        wrong |= backchannel_cell.wrong_logout_settings(client.client_id, found["attributes"])
        expect(not wrong, f"{client.client_id}'s representation differs: {wrong}")

    def fresh_realm_has_nothing_only_in_keycloak(self) -> RealmStepStand:
        """Proof 3a's end (#248, cell 2): the realms the files just made hold only what they
        declare and Keycloak 26.8.1 brings itself, so a Keycloak upgrade that adds a built-in
        fails here loudly. Returns the stand proof 12 drives."""
        import gzip_cache

        gzip_cache.prove_survives_a_restart(self, expect, wait_until_ready)
        stand = RealmStepStand.at(self.stack)
        realm = stand.realm
        inventory = realm.observer.inventory()
        leftovers = realm.leftovers(inventory)
        expect(
            leftovers.files_read and not leftovers.found and not leftovers.absent,
            f"a fresh import lists {leftovers.found} and misses {leftovers.absent}",
        )
        missing = [
            f"{realm_name} {kind} {identity}"
            for realm_name, kinds in reconcile.BUILT_IN.items()
            for kind, identities in kinds.items()
            for identity in sorted(identities - inventory[realm_name].get(kind, {}).keys())
        ]
        expect(not missing, f"pinned built-ins a fresh import does not hold: {missing}")
        return stand

    def the_realm_step(self, stand: RealmStepStand) -> None:
        """Proof 12 (#242): the realm step of `hal apply` against this stack, with hal
        under a scratch HOME and its own apps.toml. The same Keycloak, its database and its
        config-cli answer; only the repository, the HOME and the project are the probe's."""
        expect(stand.hal("backup", "--init").returncode == 0, "hal backup --init failed")

        baseline = stand.apply()
        expect(baseline.failure is None, f"the first realm step failed: {baseline.failure}")
        snapshots = stand.hal("restore", "--list").stdout
        expect(
            [call[: len(BACKUP_ASKED)] for call in stand.asked]
            == [BACKUP_ASKED, RESTORE_TEST_ASKED],
            f"it asked {stand.asked}",
        )
        expect(
            stand.asked[-1] == [*RESTORE_TEST_ASKED, baseline.applied.snapshot],
            f"the restore test was asked {stand.asked[-1]}, not for the snapshot just made",
        )
        expect(stand.plan().settled, "the step is planned again right after it finished")
        expect(stand.plan().action is reconcile.RealmAction.NOTHING, "a settled realm plans work")
        asked = len(stand.asked)
        expect(stand.apply() == reconcile.StepResult(), "a settled realm's step did something")
        expect(stand.asked == stand.asked[:asked], "a settled realm's step called hal")
        expect(stand.hal("restore", "--list").stdout == snapshots, "a quiet step made a snapshot")
        self.held(
            "12a",
            "a first step backs up, proves that snapshot's restore and applies; a second "
            "plan right after it is quiet, and running its step makes no snapshot (cells 1, 4)",
        )

        stand.edit_realm(
            (LIFESPAN_SETTING, CHANGED_LIFESPAN_SETTING),
            (
                f"  - name: {DROPPED_GROUP}\n",
                f"  - name: {STEP_GROUP}\n  - name: {DROPPED_GROUP}\n",
            ),
        )
        plan = stand.plan()
        expect("keycloak/realm.yaml changed" in plan.why, f"the plan says {plan.why!r}")
        console_made = self.make_console_objects()
        applied = stand.apply()
        expect(applied.failure is None, f"the changed realm step failed: {applied.failure}")
        (row,) = result_rows(applied)
        for line in (row.fact, *row.details):
            self.say(f"realm step: {line}")
        self.step_lists_what_is_only_in_keycloak(applied, row.details, console_made)
        changes = [line for line in row.details if not line.startswith(ONLY_IN_KEYCLOAK)]
        expected = [
            f"{REALM}: addition group /{STEP_GROUP} (0 members)",
            f"{REALM}: change realm {REALM} accessTokenLifespan: "
            f"300 → {CHANGED_ACCESS_TOKEN_LIFESPAN}",
        ]
        expect(sorted(changes) == sorted(expected), f"the lines are {changes}")
        expect(
            self.admin.get(f"/{REALM}")["accessTokenLifespan"] == CHANGED_ACCESS_TOKEN_LIFESPAN,
            "the realm does not hold the changed lifespan",
        )
        expect(stand.plan().action is reconcile.RealmAction.NOTHING, "the next plan is not quiet")
        self.held(
            "12b",
            "a changed realm.yaml is applied after a Keycloak-only backup and "
            "restore test, and the lines equal the YAML diff: "
            + "; ".join(expected)
            + " (cell 3); a "
            "group, a client and a top-level flow made in the console survive it, are listed as "
            "only in Keycloak with no removal line, and one line names the unread kinds",
        )

        realm = self.admin.get(f"/{REALM}")
        checksum = next(key for key in realm["attributes"] if key.startswith(IMPORT_CHECKSUM))
        self.admin.must(
            "PUT",
            f"/{REALM}",
            {**realm, "attributes": {**realm["attributes"], checksum: "restored"}},
        )
        plan = stand.plan()
        expect("import checksum is not the recorded one" in plan.why, f"the plan says {plan.why!r}")
        expect(stand.apply().failure is None, "the step after a restored database failed")
        expect(stand.plan().settled, "the checksum was not recorded again")
        self.held(
            "12c",
            "a tampered import-checksum attribute (what a restored database would show) is "
            "applied again, and the next plan is quiet (cell 7)",
        )

        groups_scope = self.admin.find(f"/{REALM}/client-scopes", "name", "groups")
        self.admin.create(
            f"/{REALM}/client-scopes/{groups_scope['id']}/protocol-mappers/models",
            hardcoded_claim(STEP_CONSOLE_MAPPER),
        )
        stand.edit_realm((CHANGED_LIFESPAN_SETTING, LIFESPAN_SETTING))
        reset = stand.apply()
        expect(
            reset.failure is None, f"the step that resets a console change failed: {reset.failure}"
        )
        removal = (
            f"{REALM}: removal protocol mapper scope groups/{STEP_CONSOLE_MAPPER}: "
            f"reset to the file, pre-apply snapshot {reset.applied.snapshot[:SNAPSHOT_SHORT_ID]}"
        )
        expect(removal in result_rows(reset)[0].details, "the reset is not listed as such")
        self.held(
            "12d",
            "a console mapper on the scope groups is listed as reset to the file with "
            "the snapshot, exit 0 (cell 13)",
        )

        stand.edit_realm(append=UNDEFINED_VARIABLE_LINE)
        asked = len(stand.asked)
        failed = stand.apply()
        named = re.search(r"pre-apply snapshot (\S+),", failed.failure or "")
        expect(
            named is not None and "Restore Keycloak" in failed.failure,
            f"a failed config-cli ends as {failed.failure!r}",
        )
        expect(
            stand.asked[asked:] == [BACKUP_ASKED, [*RESTORE_TEST_ASKED, named[1]]],
            f"the failed step asked hal {stand.asked[asked:]}",
        )
        expect(
            stand.plan().action is reconcile.RealmAction.RUN, "the failed step is not planned again"
        )
        self.held(
            "12e",
            "a config-cli that fails (an undefined variable) ends the step partial, "
            'names the snapshot and "Restore Keycloak", and the next plan repeats it (cell 11)',
        )

        stand.edit_realm((UNDEFINED_VARIABLE_LINE, ""))
        expect(stand.apply().failure is None, "the step after the repaired realm failed")
        expect(stand.plan().settled, "the repaired realm is not recorded")
        entrypoint = stand.repository / "keycloak" / ENTRYPOINT_FILE
        original = entrypoint.read_text()
        entrypoint.write_text(original + "# changed\n")
        plan = stand.plan()
        expect("keycloak/entrypoint.sh changed" in plan.why, f"the plan says {plan.why!r}")
        entrypoint.write_text(original)
        expect(stand.plan().settled, "the plan is not quiet with the entrypoint as it was")
        self.held(
            "12f",
            "proves the entrypoint trigger: a changed entrypoint.sh that config-cli binds "
            "plans the step",
        )

    def make_console_objects(self) -> list[str]:
        """A group, a client and a top-level flow made in the console; returns the lines the
        step is to list for them."""
        admin = self.admin
        admin.create(f"/{REALM}/groups", {"name": STEP_CONSOLE_GROUP})
        admin.create(f"/{REALM}/clients", {"clientId": STEP_CONSOLE_CLIENT, "enabled": True})
        admin.create(
            f"/{REALM}/authentication/flows",
            {
                "alias": STEP_CONSOLE_FLOW,
                "providerId": "basic-flow",
                "topLevel": True,
                "builtIn": False,
            },
        )
        return [
            f"{ONLY_IN_KEYCLOAK}{REALM} {GROUP.name} /{STEP_CONSOLE_GROUP}",
            f"{ONLY_IN_KEYCLOAK}{REALM} {CLIENT.name} {STEP_CONSOLE_CLIENT}",
            f"{ONLY_IN_KEYCLOAK}{REALM} {FLOW.name} {STEP_CONSOLE_FLOW}",
        ]

    def step_lists_what_is_only_in_keycloak(
        self, step: reconcile.StepResult, lines: tuple[str, ...], made: list[str]
    ) -> None:
        """#248, cells 1 and 3: the console objects survive the step, are listed and have no
        removal line; the step carries the kinds that cannot be read."""
        missing = [line for line in made if line not in lines]
        expect(not missing, f"the step does not list {missing}")
        made_names = (STEP_CONSOLE_GROUP, STEP_CONSOLE_CLIENT, STEP_CONSOLE_FLOW)
        removed = [x for x in lines if "removal" in x and any(name in x for name in made_names)]
        expect(not removed, f"the step resets a console object: {removed}")
        admin = self.admin
        expect(
            admin.get(f"/{REALM}/group-by-path/{STEP_CONSOLE_GROUP}")["name"] == STEP_CONSOLE_GROUP
            and admin.client(STEP_CONSOLE_CLIENT)["clientId"] == STEP_CONSOLE_CLIENT
            and any(
                flow["alias"] == STEP_CONSOLE_FLOW
                for flow in admin.get(f"/{REALM}/authentication/flows")
            ),
            "a console object did not survive the step",
        )
        unread = step.applied.leftovers.unread
        expect(
            "defaultGroups" in unread and "workflows" in unread,
            f"the unread kinds are {unread}",
        )

    def the_observer_door(self, admin: Admin) -> None:
        """Proof 9 (#66): the observer's container, its console-change lines and its stops. Runs
        last but for proof 7, when every credential proof 7 looks for exists."""
        password = self.keep_secret("smtp password", secrets.token_urlsafe(16))
        smtp = {
            "host": "smtp.probe.invalid",
            "port": "587",
            "from": "probe@probe.invalid",
            "auth": "true",
            "user": "probe",
        }
        admin.must("PUT", f"/{REALM}", {"smtpServer": smtp | {"password": password}})
        digest_key = self.keep_secret("the observer's second digest key", new_digest_key())
        kept = f"{PROJECT}-observe-{secrets.token_hex(4)}"
        result = self.stack.observe(digest_key, keep_as=kept)
        expect(result.returncode == 0, f"the kept observe exited {result.returncode}")
        before = json.loads(result.stdout)
        door = self.observer_container(kept)

        original = self.change_config_in_console(admin)
        group_id = admin.create(f"/{REALM}/groups", {"name": ESCAPING_GROUP})
        lines = change_lines(before, self.observe(digest_key))
        admin.must("PUT", f"/master/authentication/config/{original['id']}", original)
        admin.must("DELETE", f"/{REALM}/groups/{group_id}")
        expected = [
            f"{REALM}: addition group /probe\\x1b[31mconsole\\nname (0 members)",
            f"master: change authenticator config {CHANGED_CONFIG} config.check_result: "
            '"not-executed" → "executed"',
        ]
        expect(lines == expected, f"the console changes are listed as {lines}")

        left = {
            f"{stop.name} {moment.__name__}": self.stack.observe_stopped_by(
                digest_key, stop, moment
            )
            for stop in (signal.SIGINT, signal.SIGTERM)
            for moment in (as_its_container_runs, as_the_inventory_arrives)
        }
        expect(not any(left.values()), f"a stopped observe left containers: {left}")

        self.stack.see_running()
        stopped = self.stack.compose("stop", "keycloak")
        expect(stopped.returncode == 0, f"compose stop keycloak failed: {tail(stopped.stderr)}")
        refused = self.stack.observe(digest_key)
        running = self.stack.compose("ps", "--status", "running", "--services").stdout.split()
        expect(
            refused.returncode != 0 and "does not answer" in refused.stderr,
            f"an observe without Keycloak exited {refused.returncode}: {tail(refused.stderr)}",
        )
        expect("keycloak" not in running, "an observe started Keycloak")
        self.held(
            "9",
            f"the observer runs as {door}; a console change of {CHANGED_CONFIG} is one change "
            "line and a group named with ESC and a newline one escaped line; SIGINT and SIGTERM "
            "as its container runs and as the inventory arrives leave no container, and an exit "
            "0 carries the whole inventory; with Keycloak stopped it says 'does not answer', exits "
            f"{refused.returncode} and starts nothing",
        )

    def observer_container(self, name: str) -> str:
        """Checks the kept observer container's door, records its Config.Env, removes it."""
        self.stack.see_env(name)
        inspected = docker("inspect", name)
        docker("rm", name)
        expect(inspected.returncode == 0, f"docker inspect {name} failed")
        container = json.loads(inspected.stdout)[0]
        host, config = container["HostConfig"], container["Config"]
        mounts = {mount["Destination"]: mount["RW"] for mount in container["Mounts"]}
        door = {
            "user": config["User"],
            "read-only": host["ReadonlyRootfs"],
            "cap_drop": host["CapDrop"],
            "no-new-privileges": "no-new-privileges:true" in (host["SecurityOpt"] or []),
            "ports": host["PortBindings"] or {},
            "networks": sorted(container["NetworkSettings"]["Networks"]),
            "mounts": mounts,
        }
        wanted = {
            "user": "65534:65534",
            "read-only": True,
            "cap_drop": ["ALL"],
            "no-new-privileges": True,
            "ports": {},
            "networks": [f"{PROJECT}_keycloak"],
            "mounts": {OBSERVER_SECRET: False, OBSERVER_SCRIPT: False},
        }
        expect(door == wanted, f"the observer container is {door}")
        return (
            "65534, read-only, cap_drop ALL, no-new-privileges, no port, the keycloak network "
            "alone, its secret a read-only file"
        )

    def change_config_in_console(self, admin: Admin) -> dict[str, Any]:
        """Changes one authenticator config as an operator would; returns it as it was."""
        steps = admin.get("/master/authentication/flows/browser-mfa/executions")
        config_id = next(
            step["authenticationConfig"] for step in steps if step.get("alias") == CHANGED_CONFIG
        )
        original = admin.get(f"/master/authentication/config/{config_id}")
        changed = {**original, "config": {**original["config"], "check_result": "executed"}}
        admin.must("PUT", f"/master/authentication/config/{config_id}", changed)
        return original

    def no_secret_leaked(self) -> None:
        self.stack.see_running()
        places = [(f"Config.Env of {name}", "\n".join(env)) for name, env in self.stack.seen_env]
        places += [
            ("the compose, apply and service log output", "\n".join(self.stack.outputs)),
            ("the probe's own output", "\n".join(self.evidence)),
        ]
        leaks = [
            f"{secret_name} in {place}"
            for place, text in places
            for secret_name, value in self.secret_values.items()
            if value in text
        ]
        expect(not leaks, f"credentials leaked: {leaks}")
        containers = sorted({name for name, _ in self.stack.seen_env})
        self.held(
            "7",
            f"none of the {len(self.secret_values)} credentials (secret files, passwords, the "
            "TOTP seed, the RP secret, access, refresh, ID and admin tokens, the admin console's "
            "PKCE verifiers, authorization codes and session cookies) is in the Config.Env of the "
            f"{len(containers)} containers seen ({', '.join(containers)}), in any "
            "compose, apply or service log output, or in the probe's own output",
        )


READY_MARK = "READY"
STOP_SIGNALS = (signal.SIGTERM, signal.SIGINT)
# Per mode: the Probe method that runs it and the line that reports it ended well.
MODES = {
    "run": ("run", "PROBE PASSED: proofs 1-12 hold"),
    "hold": ("hold", "HOLD ENDED"),
}


class StopHolding(Exception):
    """A held stack was told to stop; unlike ProbeFailure this is the normal end."""


def stop_as_failure(signum: int, _frame: object) -> None:
    ignore_stop_signals()
    raise ProbeFailure(f"stopped by {signal.Signals(signum).name}")


def stop_holding(_signum: int, _frame: object) -> None:
    ignore_stop_signals()
    raise StopHolding


def ignore_stop_signals() -> None:
    """Ends the stop signals' effect; blocked meanwhile, so none can raise between the two.

    The stop handlers call it before they raise and main calls it as the run ends, inside the
    try that catches their raise, so only the first stop signal acts and the teardown that
    follows cannot be interrupted by a second one."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        for stopping in STOP_SIGNALS:
            signal.signal(stopping, signal.SIG_IGN)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def keep_stack_until_told_to_stop(ready_line: str) -> None:
    """Prints the READY line, then blocks until SIGTERM, SIGINT or EOF on stdin."""
    # A signal that arrives while the handler is swapped waits until READY is out, so one
    # before READY is a failure and one after it is a stop, never the other way round.
    # Unblocking delivers a pending signal inside pthread_sigmask; main ends the hold on it.
    signal.pthread_sigmask(signal.SIG_BLOCK, STOP_SIGNALS)
    try:
        for stopping in STOP_SIGNALS:
            signal.signal(stopping, stop_holding)
        write_line(ready_line, flush=True)
    finally:
        signal.pthread_sigmask(signal.SIG_UNBLOCK, STOP_SIGNALS)
    sys.stdin.read()


def main(make_stack: Callable[[Path], Stack] = Stack) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "mode",
        nargs="?",
        choices=tuple(MODES),
        default="run",
        help="run: the proofs (default); hold: keep the stack up for another repository's proof",
    )
    parser.add_argument("--scratch", type=Path, required=True, help="an empty or new directory")
    arguments = parser.parse_args()
    scratch = arguments.scratch.resolve()
    if scratch.exists() and (not scratch.is_dir() or any(scratch.iterdir())):
        parser.error(f"{scratch} is not an empty directory")
    # `timeout` sends SIGTERM and Ctrl-C sends SIGINT; turn both into a failure so even a stop
    # while the stack is being built ends with the one FAILED line, and the teardown below still
    # runs for a stack that exists.
    for stopping in STOP_SIGNALS:
        signal.signal(stopping, stop_as_failure)
    failures = []
    stack = None
    method_name, success_line = MODES[arguments.mode]
    try:
        try:
            try:
                stack = make_stack(scratch)
            except OSError as failure:
                raise ProbeFailure(str(failure)) from failure
            getattr(Probe(stack), method_name)()
        finally:
            # Inside the try whose handlers take a stop signal: one landing while this swaps
            # the handlers still ends the run as a stop or a failure, never as a skipped teardown.
            ignore_stop_signals()
    except StopHolding:
        pass  # any stop signal after READY, however late, is the normal end of a hold
    except ProbeFailure as failure:
        failures.append(str(failure))
        # A stop signal landing in the inner finally replaced the error it interrupted; name both.
        # The same replacement turns a non-ProbeFailure raised after READY into a StopHolding,
        # which ends the hold quietly; that error is not reported.
        if isinstance(failure.__context__, ProbeFailure):
            failures.append(str(failure.__context__))
    finally:
        # The teardown must finish and say so; the SIGKILL of `timeout --kill-after` bounds it.
        if stack is not None and not stack.down():
            failures.append(f"stack {PROJECT} is left behind; see probe/keycloak/README.md")
    if failures:
        write_line(f"PROBE FAILED: {'; '.join(failures)}", flush=True)
        return 1
    write_line(success_line, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
