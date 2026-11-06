"""The stand-in issuer of a probe run: the realm's side (signing key, certificate, JWKS, tokens)
and the service of the compose project that serves it on the `agent-songmaker` network, all
throwaway."""

from __future__ import annotations

import base64
import json
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

from egress import (
    COMPOSE_FILE,
    SERVICE_CONFIGURATION,
    SERVICE_PORT,
    Probe,
    ProbeFailed,
    Target,
    expect,
)
from refusals import MEMBER_GROUPS
from scratch_secrets import LOGIN_DIRECTORY
from smoke import Tokens

SERVICE = Target.SERVICE.compose_service

ISSUER_SERVICE = "agent-issuer"
ISSUER_PORT = 8443
ISSUER_ORIGIN = f"https://{ISSUER_SERVICE}:{ISSUER_PORT}"
REAL_ISSUER_ORIGIN = "https://auth.hallucinai.de"
KEY_ID = "probe-key"
WORKLOAD_CLIENT = "songmaker"
LISTEN_SECONDS = 90
LISTENING = f"Uvicorn running on http://0.0.0.0:{SERVICE_PORT}"
TOKEN_SECONDS = 240  # the service refuses a workload token that lives longer than 300
ISSUER_PROGRAM = (
    f"ISSUER_PORT = {ISSUER_PORT}\n"
    + """\
import http.server, ssl
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = open("/issuer/jwks.json", "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain("/issuer/cert.pem", "/issuer/key.pem")
server = http.server.HTTPServer(("0.0.0.0", ISSUER_PORT), Handler)
server.socket = context.wrap_socket(server.socket, server_side=True)
server.serve_forever()
"""
)


def openssl(*arguments: str, stdin: bytes | None = None) -> bytes:
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["openssl", *arguments],  # noqa: S607 - openssl is found on PATH by design
        input=stdin,
        capture_output=True,
        check=False,
        timeout=60,
    )
    expect(result.returncode == 0, f"openssl {arguments[0]} failed: {result.stderr[-200:]!r}")
    return result.stdout


def base64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class StandInIssuer:
    """A signing key, its certificate for `host`, the JWKS it serves and the tokens it
    signs: the realm's side of a run, all of it throwaway."""

    def __init__(self, directory: Path, host: str = ISSUER_SERVICE) -> None:
        self.directory = directory
        directory.mkdir()
        self.key = directory / "key.pem"
        openssl("genrsa", "-out", str(self.key), "2048")
        openssl(
            "req", "-x509", "-new", "-key", str(self.key), "-out", str(directory / "cert.pem"),
            "-days", "1", "-subj", f"/CN={host}",
            "-addext", f"subjectAltName=DNS:{host}",
        )  # fmt: skip
        modulus = openssl("rsa", "-in", str(self.key), "-noout", "-modulus").decode()
        keys = {"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": KEY_ID, "e": "AQAB",
            "n": base64url(bytes.fromhex(modulus.strip().removeprefix("Modulus="))),
        }]}  # fmt: skip
        (directory / "jwks.json").write_text(json.dumps(keys), encoding="utf-8")
        for name in ("key.pem", "cert.pem", "jwks.json"):
            (directory / name).chmod(0o644)
        directory.chmod(0o755)

    def token(self, issuer: str, claims: dict) -> str:
        now = int(time.time())
        payload = {"iss": issuer, "aud": "agent-service", "iat": now, "exp": now + TOKEN_SECONDS}
        header = {"alg": "RS256", "kid": KEY_ID, "typ": "JWT"}
        signing_input = ".".join(
            base64url(json.dumps(part).encode()) for part in (header, {**payload, **claims})
        )
        signature = openssl("dgst", "-sha256", "-sign", str(self.key), stdin=signing_input.encode())
        return f"{signing_input}.{base64url(signature)}"


def wait_for_listening(read_log: Callable[[], str], failure: str) -> None:
    """Poll the service log until it says the service listens, or fail with `failure`."""
    deadline = time.monotonic() + LISTEN_SECONDS
    while time.monotonic() < deadline:
        if LISTENING in read_log():
            return
        time.sleep(0.5)
    raise ProbeFailed(f"{failure} in time")


class IssuerProbe(Probe):
    """The service with a stand-in issuer on the `agent-songmaker` network."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch, Target.SERVICE)
        self.issuer = StandInIssuer(scratch / "issuer")
        self.image = self.service_image()
        configuration = self.configuration = scratch / "service.toml"
        configuration.write_text(
            SERVICE_CONFIGURATION.read_text(encoding="utf-8").replace(
                REAL_ISSUER_ORIGIN, ISSUER_ORIGIN
            ),
            encoding="utf-8",
        )
        configuration.chmod(0o644)
        program = scratch / "issuer.py"
        program.write_text(ISSUER_PROGRAM, encoding="utf-8")
        overlay = scratch / "compose.smoke.yaml"
        overlay.write_text(
            json.dumps({"services": {
                "agent-service": {
                    "environment": {"SSL_CERT_FILE": "/issuer/cert.pem"},
                    "volumes": [
                        {"type": "bind", "source": str(configuration), "read_only": True,
                         "target": "/etc/agent-service/service.toml"},
                        {"type": "bind", "source": str(self.issuer.directory), "read_only": True,
                         "target": "/issuer"},
                    ],
                },
                ISSUER_SERVICE: {
                    "image": self.image,
                    "profiles": ["agent-service"],
                    "user": "65534:65534", "read_only": True, "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"], "networks": ["agent-songmaker"],
                    "entrypoint": ["python", "-I", "-B", "/issuer.py"],
                    "volumes": [
                        {"type": "bind", "source": str(program), "target": "/issuer.py",
                         "read_only": True},
                        {"type": "bind", "source": str(self.issuer.directory),
                         "target": "/issuer", "read_only": True},
                    ],
                },
            }}),
            encoding="utf-8",
        )  # fmt: skip
        self.overlays.append(overlay)

    def service_image(self) -> str:
        """The issuer is a python script, and the service image is the python already on the PC;
        compose resolves the image as it does for the service."""
        self.write_on_probe_subnet(COMPOSE_FILE, self.compose_file)  # the project's names (P26)
        resolved = self.compose("config", "--format", "json")
        return json.loads(resolved.stdout)["services"][SERVICE]["image"]

    def wait_until_listening(self, since: int | None = None) -> None:
        wait_for_listening(lambda: self.container_log(SERVICE, since), "the service did not listen")

    @property
    def token_path(self) -> Path:
        return Path(self.environment["HOME"]) / LOGIN_DIRECTORY

    def tokens(self, groups: tuple[str, ...] = MEMBER_GROUPS) -> Tokens:
        issuer = f"{ISSUER_ORIGIN}/realms/hallucinai"
        person = self.issuer.token(
            issuer, {"sub": "person", "azp": WORKLOAD_CLIENT, "groups": list(groups)})  # fmt: skip
        workload = self.issuer.token(
            issuer,
            {"sub": "workload", "azp": WORKLOAD_CLIENT, "client_id": WORKLOAD_CLIENT,
             "realm_access": {"roles": ["agent-workload"]}},
        )  # fmt: skip
        return Tokens(person=person, workload=workload)
