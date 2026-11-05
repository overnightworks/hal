"""What the speech probe asks the daemon: containers and networks of the copy and its app by their
Compose labels, and curl in a throwaway container on a network or in a container's namespace.

The curl client is the copy's step-ca image (it ships curl), read-only, as the probe's own uid, with
the copy's project label so every label sweep of the copy removes a stray one. A token never enters
an argument or the environment: headers come on stdin (`--header @-`).
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import edge_copy
from edge_copy import expect

from hal.backup.docker import PROJECT_LABEL, SERVICE_LABEL

SHORT_SECONDS = 120
CURL_SECONDS = "4"
ROOT_IN_CLIENT = "/run/probe/root_ca.crt"
STATUS_MARK = b"\n#status "  # what --write-out appends after the body
# A server answering every GET and POST with the fixed body argv[2] on argv[1]:argv[3]; it serves no
# file. Run by the host's and by a container's python.
FIXED_RESPONSE_SERVER = """\
import http.server, sys
bind, body, port = sys.argv[1], sys.argv[2].encode(), int(sys.argv[3])
class Fixed(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    do_POST = do_GET
    def log_message(self, *_):
        pass
http.server.HTTPServer((bind, port), Fixed).serve_forever()
"""


PLAIN_HTTP = "http://"  # NOSONAR(S5332) the copy's internal networks; speech has no TLS by design


def plain_http(host: str, port: int, path: str = "/") -> str:
    """The URL of `path` at `host`:`port` over plain HTTP: every one the probe sends."""
    return f"{PLAIN_HTTP}{host}:{port}{path}"


def docker(*arguments: str, check: bool = True, stdin: bytes | None = None) -> bytes:
    result = edge_copy.run_command(
        ["docker", *arguments], input=stdin, env=os.environ, timeout=SHORT_SECONDS
    )
    if check:
        tail = result.stderr.decode(errors="replace").strip()[-200:]
        expect(result.returncode == 0, f"docker {' '.join(arguments[:3])} exited: {tail}")
    return result.stdout


def containers_of(project: str, service: str, *, every: bool = True) -> list[str]:
    """The ids of `service`'s containers in `project`, stopped ones too when `every`."""
    labels = ["--filter", f"label={PROJECT_LABEL}={project}"]
    labels += ["--filter", f"label={SERVICE_LABEL}={service}"]
    listed = docker("ps", *(["--all"] if every else []), "--quiet", "--no-trunc", *labels)
    return listed.decode().split()


def one_container(project: str, service: str) -> str:
    found = containers_of(project, service)
    expect(len(found) == 1, f"{project} has {len(found)} containers of {service}")
    return found[0]


def inspected(kind: str, name: str) -> dict[str, Any]:
    return json.loads(docker(kind, "inspect", name))[0]


def networks_of(project: str) -> dict[str, str]:
    """Each network carrying `project`'s label, by name: its id."""
    listed = docker(
        "network",
        "ls",
        "--filter",
        f"label={PROJECT_LABEL}={project}",
        "--format",
        "{{.Name}} {{.ID}}",
    )
    return {name: network_id for name, network_id in map(str.split, listed.decode().splitlines())}


def addresses_of(container: str) -> dict[str, str]:
    """The container's IPv4 address on each network it joins, by network name."""
    networks = inspected("container", container)["NetworkSettings"]["Networks"]
    return {name: one["IPAddress"] for name, one in networks.items() if one.get("IPAddress")}


@dataclass(frozen=True)
class Answer:
    exit_code: int  # curl's: 0 answered, 6 not resolved, 7 refused or unreachable, 28 timed out
    status: int  # 0 when nothing answered
    body: bytes

    def json(self) -> Any:
        return json.loads(self.body)


@dataclass(frozen=True)
class Curl:
    """curl from the copy's step-ca image, labelled with the copy's project."""

    image: str
    project: str
    root: Path  # the copy's step-ca root, readable by the probe's uid

    def at(
        self,
        network: str,
        arguments: Sequence[str],
        *,
        headers: str = "",
        trusted: bool = True,
        mounts: Sequence[tuple[Path, str]] = (),
    ) -> Answer:
        """curl on `network` (or `container:<id>`), its headers from stdin, each file of `mounts`
        read-only at its path."""
        files = [*([(self.root, ROOT_IN_CLIENT)] if trusted else []), *mounts]
        trust = [word for path, at in files for word in ("--volume", f"{path}:{at}:ro")]
        command = [
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--network",
            network,
            "--read-only",
            "--label",
            f"{PROJECT_LABEL}={self.project}",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            *trust,
            "--entrypoint",
            "curl",
            self.image,
            "--silent",
            "--max-time",
            CURL_SECONDS,
            "--header",
            "@-",
            "--write-out",
            f"{STATUS_MARK.decode()}%{{http_code}}",
            *(["--cacert", ROOT_IN_CLIENT] if trusted else []),
            *arguments,
        ]
        result = edge_copy.run_command(
            command, input=headers.encode(), env=os.environ, timeout=SHORT_SECONDS
        )
        body, _, status = result.stdout.rpartition(STATUS_MARK)
        return Answer(result.returncode, int(status or b"0"), body)


def container_log(container: str) -> str:
    """Everything the container wrote, stdout and stderr."""
    result = edge_copy.run_command(["docker", "logs", container], env=os.environ, timeout=60)
    expect(result.returncode == 0, f"docker logs {container[:12]} exited {result.returncode}")
    return (result.stdout + result.stderr).decode(errors="replace")


def wait_healthy(container: str, seconds: int) -> None:
    """Waits until the container's health check reports healthy."""
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        state = docker("inspect", "--format", "{{.State.Health.Status}}", container, check=False)
        if state.decode().strip() == "healthy":
            return
        time.sleep(2)
    raise edge_copy.ProbeFailed(f"{container[:12]} is not healthy after {seconds} s")


@contextmanager
def fixed_server(
    image: str, project: str, networks: Sequence[str], body: str, *, port: int, alias: str = ""
) -> Iterator[str]:
    """A container of `image` (its `python`) on `networks`, as `alias` too when given, answering
    every request on `port` with `body`, read-only, as nobody, labelled with `project`: its id,
    removed on leaving."""
    first, *more = networks
    aliased = ["--network-alias", alias] if alias else []
    started = docker(
        "run", "--detach", "--rm", "--network", first, *aliased,
        "--label", f"{PROJECT_LABEL}={project}", "--read-only", "--user", "65534",
        "--entrypoint", "python", image, "-c", FIXED_RESPONSE_SERVER, "", body, str(port),
    )  # fmt: skip
    container = started.decode().strip()
    try:
        for network in more:
            docker("network", "connect", *(["--alias", alias] if alias else []), network, container)
        yield container
    finally:
        docker("rm", "--force", container, check=False)
