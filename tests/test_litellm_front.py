"""The CI job `front` (#768): litellm-front, as shipped, against a stand-in for LiteLLM, driven by
a table of raw requests. Only the one completion route without a query string reaches the
backend, with one constant `User-Agent` and no tag header; every other method, path form, encoded
character and query string stops in the front itself. The job re-runs on every Traefik bump.

It starts containers, so it runs only where EDGE_FRONT_CASES is set (the job `front`; locally under
the probe lock). The stand-in and client images are compose.yaml's pins.
"""

import base64
import json
import os
import subprocess
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PROJECT = "edge-litellm-front-ci"
COMPOSE_FILES = [ROOT / "compose.yaml", ROOT / "tests" / "support" / "front.compose.yaml"]
# Compose's own tags, which no YAML check of the repository reads, so the file is written per run.
TAGGED_OVERLAY = """\
services:
  litellm-front:
    networks: !override [litellm-api, litellm-backend]
    extra_hosts: !reset []
networks:
  litellm-backend:
    ipam: !reset {}
"""
FRONT, STAND_IN, CLIENT = "litellm-front", "stand-in", "client"
ROUTE = "/v1/chat/completions"
ROUTE_FILE = ROOT / "agent-service" / "litellm" / "front" / "dynamic" / "route.yml"
TAG_HEADER = "x-litellm-tags"  # lower case, `-` for `_`: every spelling LiteLLM could read
FRONT_ORIGIN = "litellm-front:4000"
BACKEND_MARK = "Hostname:"  # the stand-in's (whoami's) answer begins with it; the front's never
H2C_PRIOR_KNOWLEDGE_BODY = b"{}"

pytestmark = pytest.mark.skipif(
    "EDGE_FRONT_CASES" not in os.environ, reason="starts containers; the CI job `front` runs it"
)

# The program the client container runs with `python -I -`: standard library only. It sends the
# raw bytes of one case and prints the status and the body's first line. `h2c` sends HTTP/2 with
# prior knowledge: the preface, empty settings and one HEADERS frame with HPACK indexed or
# literal fields, and prints the :status of the reply (the static-table index 8 to 14).
CLIENT_PROGRAM = """
import json, socket, sys

def exchange(payload, wait=3.0):
    with socket.create_connection(("litellm-front", 4000), timeout=wait) as raw:
        raw.sendall(payload)
        received = b""
        try:
            while chunk := raw.recv(65536):
                received += chunk
        except TimeoutError:
            pass
    return received

def literal(name, value):
    return b"\\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value

def h2c(path):
    authority = literal(b":authority", b"litellm-front:4000")
    block = b"\\x83\\x86" + literal(b":path", path.encode()) + authority
    frame = len(block).to_bytes(3, "big") + b"\\x01\\x05" + (1).to_bytes(4, "big") + block
    settings = b"\\x00\\x00\\x00\\x04\\x00\\x00\\x00\\x00\\x00"
    reply = exchange(b"PRI * HTTP/2.0\\r\\n\\r\\nSM\\r\\n\\r\\n" + settings + frame)
    index = 0
    while index + 9 <= len(reply):
        length = int.from_bytes(reply[index:index + 3], "big")
        kind = reply[index + 3]
        payload = reply[index + 9:index + 9 + length]
        if kind == 1 and payload:
            statuses = {0x88: 200, 0x8d: 404, 0x8c: 400}
            return {"status": statuses.get(payload[0], payload[0])}
        index += 9 + length
    return {"status": None}

def http(raw_hex):
    reply = exchange(bytes.fromhex(raw_hex))
    head, _, body = reply.partition(b"\\r\\n\\r\\n")
    first, *fields = head.decode("latin-1").split("\\r\\n")
    names = [field.partition(":")[0].strip().lower() for field in fields]
    return {"status": int(first.split()[1]) if first else None,
            "location": "location" in names, "body": body.decode("latin-1")[:2000]}

kind, argument = sys.argv[1], sys.argv[2]
print(json.dumps(h2c(argument) if kind == "h2c" else http(argument)))
"""


@dataclass(frozen=True)
class Case:
    name: str
    status: int
    reaches_backend: bool = False
    backend_sees: str | None = None  # the request line the stand-in echoes
    method: str = "POST"
    target: str = ROUTE
    headers: tuple[str, ...] = ()
    kind: str = "http"  # http, h2c
    forwarded: tuple[str, ...] = ()  # header lines the stand-in must echo unchanged


def reaches(name: str, target: str, sees: str, **changes) -> Case:
    return Case(name, 200, True, sees, target=target, **changes)


def stops(name: str, status: int, **changes) -> Case:
    return Case(name, status, **changes)


POSITIVE_CONTROL = reaches("C32 positive control", ROUTE, f"POST {ROUTE} HTTP/1.1")

# The committed outcomes are what the pinned image measured. C11 to C13: Traefik cleans the path
# (`sanitizePath`) and the backend sees the route itself. C14 to C20: an encoded character inside
# the route's path never matches the router, so the front answers 404 itself; the encoded-character
# options of the entrypoint (the 400 answer) do not fire before routing.
CASES = [
    stops("C1 GET", 404, method="GET"),
    stops("C2 PUT", 404, method="PUT"),
    stops("C3 DELETE", 404, method="DELETE"),
    stops("C4 PATCH", 404, method="PATCH"),
    stops("C5 OPTIONS", 404, method="OPTIONS"),
    stops("C6 HEAD", 404, method="HEAD"),
    stops("C7 no version", 404, target="/chat/completions"),
    stops("C8 trailing slash", 404, target=ROUTE + "/"),
    stops("C9 upper case", 404, target=ROUTE.upper()),
    stops("C10 deeper path", 404, target=ROUTE + "/x"),
    reaches("C11 double slash", "//v1/chat/completions", f"POST {ROUTE} HTTP/1.1"),
    reaches("C12 dot segment", "/v1/./chat/completions", f"POST {ROUTE} HTTP/1.1"),
    reaches("C13 dot-dot segment", "/a/../v1/chat/completions", f"POST {ROUTE} HTTP/1.1"),
    stops("C14 encoded slash", 404, target="/v1/chat%2Fcompletions"),
    stops("C15 encoded backslash", 404, target="/v1/chat%5Ccompletions"),
    stops("C16 encoded null", 404, target="/v1/chat%00completions"),
    stops("C17 encoded semicolon", 404, target="/v1/chat%3Bcompletions"),
    stops("C18 encoded percent", 404, target="/v1/chat%25completions"),
    stops("C19 encoded question mark", 404, target="/v1/chat%3Fcompletions"),
    stops("C20 encoded hash", 404, target="/v1/chat%23completions"),
    stops("C21 query", 400, target=ROUTE + "?model=x"),
    reaches(
        "C22 arbitrary host", ROUTE, f"POST {ROUTE} HTTP/1.1", headers=("Host: anything.invalid",)
    ),
    stops("C23 key generation", 404, target="/key/generate"),
    stops("C24 token", 404, target="/token"),
    stops("C25 register", 404, target="/register"),
    stops("C26 mcp sse", 404, method="GET", target="/mcp/sse"),
    stops("C27 mcp", 404, target="/mcp/"),
    stops("C28 cost map", 404, method="GET", target="/public/litellm_model_cost_map"),
    stops("C29 readiness", 404, method="GET", target="/health/readiness"),
    stops("C30 h2c key generation", 404, target="/key/generate", kind="h2c"),
    stops(
        "C31 websocket",
        404,
        method="GET",
        target="/v1/realtime",
        headers=(
            "Upgrade: websocket",
            "Connection: Upgrade",
            "Sec-WebSocket-Version: 13",
            f"Sec-WebSocket-Key: {base64.b64encode(os.urandom(16)).decode()}",
        ),
    ),
    POSITIVE_CONTROL,
    stops("C33 empty query", 400, target=ROUTE + "?"),
    stops("C34 api version", 400, target=ROUTE + "?api-version=x"),
    stops("C35 semicolon pair", 400, target=ROUTE + "?a=1;model=text/opus"),
    stops("C36 absolute form", 400, target=f"http://{FRONT_ORIGIN}{ROUTE}?model=x"),
    stops("C37 h2c query", 400, target=ROUTE + "?model=x", kind="h2c"),
    reaches(
        "C38 own user agent", ROUTE, f"POST {ROUTE} HTTP/1.1", headers=("User-Agent: probe/1.0",)
    ),
    reaches("C39 no user agent", ROUTE, f"POST {ROUTE} HTTP/1.1"),
    reaches(
        "C40 tag headers",
        ROUTE,
        f"POST {ROUTE} HTTP/1.1",
        headers=(
            "x-litellm-tags: a",
            "X-LiteLLM-Tags: b",
            "x_litellm_tags: c",
            "X-Litellm-Tags: d",
        ),
    ),
    reaches(
        "C41 authorization and content type",
        ROUTE,
        f"POST {ROUTE} HTTP/1.1",
        headers=("Authorization: Bearer probe-token", "Content-Type: application/json"),
        forwarded=("Authorization: Bearer probe-token", "Content-Type: application/json"),
    ),
    stops("C42 path parameter", 404, target=ROUTE + ";model=x"),
]


def constant_user_agent() -> str:
    """The `User-Agent` the front's headers middleware sets, from route.yml."""
    middlewares = yaml.safe_load(ROUTE_FILE.read_text())["http"]["middlewares"].values()
    (headers,) = [middleware["headers"] for middleware in middlewares if "headers" in middleware]
    return headers["customRequestHeaders"]["User-Agent"]


def echoed_headers(body: str) -> list[tuple[str, str]]:
    """The header lines of the stand-in's echo, after its request line."""
    _, _, after = body.partition(" HTTP/1.1")
    return [
        (name, value.strip())
        for name, separator, value in (line.partition(":") for line in after.splitlines())
        if separator
    ]


def raw_request(case: Case) -> bytes:
    headers = [f"Host: {FRONT_ORIGIN}", "Connection: close", "Content-Length: 2", *case.headers]
    if any(header.startswith("Host:") for header in case.headers):
        headers.remove(f"Host: {FRONT_ORIGIN}")
    return (
        f"{case.method} {case.target} HTTP/1.1\r\n" + "\r\n".join(headers) + "\r\n\r\n{}"
    ).encode()


class Stack:
    def __init__(self, tagged_overlay: Path) -> None:
        compose = yaml.safe_load(COMPOSE_FILES[0].read_text())["services"]
        self.files = [*COMPOSE_FILES, tagged_overlay]
        self.environment = {
            **os.environ,
            "DOCKER_GID": "0",
            "EDGE_DOMAIN": "front.invalid",
            "STAND_IN_IMAGE": compose["hello"]["image"],
            "CLIENT_IMAGE": compose["agent-probe"]["image"],
        }

    def compose(self, *arguments: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        files = [argument for file in self.files for argument in ("--file", str(file))]
        return subprocess.run(
            ["docker", "compose", "-p", PROJECT, *files, "--profile", "litellm", *arguments],
            input=stdin, capture_output=True, text=True, env=self.environment, check=True,
            timeout=300,
        )  # fmt: skip

    def drive(self, case: Case) -> dict:
        argument = case.target if case.kind == "h2c" else raw_request(case).hex()
        result = self.compose("exec", "-T", CLIENT, "python", "-I", "-", case.kind, argument,
                              stdin=CLIENT_PROGRAM)  # fmt: skip
        return json.loads(result.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def stack(tmp_path_factory) -> Iterator[Stack]:
    tagged_overlay = tmp_path_factory.mktemp("front") / "tagged.compose.yaml"
    tagged_overlay.write_text(TAGGED_OVERLAY)
    running = Stack(tagged_overlay)
    try:
        running.compose("up", "--detach", "--wait", "--no-deps", FRONT, STAND_IN, CLIENT)
        deadline = time.monotonic() + 30
        while running.drive(POSITIVE_CONTROL)["status"] != 200:  # the front has loaded its file
            assert time.monotonic() < deadline, "the front never routed the positive control"
            time.sleep(1)
        yield running
    finally:
        running.compose("down", "--volumes", "--remove-orphans", "--timeout", "10")


@pytest.mark.parametrize("case", CASES, ids=[case.name for case in CASES])
def test_the_front_forwards_only_the_one_route_and_answers_the_rest_itself(stack, case):
    answer = stack.drive(case)
    assert answer["status"] == case.status
    assert not answer.get("location")  # the front never sends a client elsewhere
    body = answer.get("body", "")
    assert (BACKEND_MARK in body) == case.reaches_backend
    if case.backend_sees:
        assert case.backend_sees in body
    for line in case.forwarded:
        assert line in body.splitlines()


@pytest.mark.parametrize(
    "case", [case for case in CASES if case.reaches_backend], ids=lambda case: case.name
)
def test_litellm_sees_one_constant_user_agent_and_no_tag_header(stack, case):
    echoed = echoed_headers(stack.drive(case)["body"])

    assert [value for name, value in echoed if name.lower() == "user-agent"] == [
        constant_user_agent()
    ]
    assert not [name for name, _ in echoed if name.lower().replace("_", "-") == TAG_HEADER]
