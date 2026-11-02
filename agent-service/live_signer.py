#!/usr/bin/env python3
"""The live signer proof of the agent service (docs/agent-service.md, "Proofs").

    cd ~/srv/hal && python3 agent-service/live_signer.py

It proves what the service signs for one tool, through songmaker's own client and the real
gateway, with no paid turn: both runs fail before any CLI starts. You sign in as for
`live_smoke.py`. The command recreates the service and judges the recreate (L3): the service's
networks are the resolved ones and each is internal and isolated, and its two secret mounts come
from the files `compose.yaml` names. It then removes the shared `hal_agent` network once it is
empty, and refuses while it has a member. Then it runs `agent-smoke` with one tool:
L4a with no backend behind the gateway (the run must end `failed` with no text, the gateway
having refused), L4b with the capture verifier `mcp_signer.py` at songmaker-web's place on the MCP
network (the received capability must verify against the live public.pem). Only the verdict is
printed, never the capability. The stand-in is always removed, and the command refuses while
anything but traefik-mcp is on the network: from then on songmaker's own call is the proof.
It needs `[apps.songmaker] mcp_origin` in agent-service/service.toml.
Exit 1 when a cell prints FAILED. Only the standard library is used.
"""

from __future__ import annotations

import argparse
import json
import queue
import subprocess
import sys
import threading
import time
import tomllib
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from pathlib import Path

from device_sign_in import SignInFailed, sign_in
from live_smoke import (
    CLIENT_SECRET_FILE,
    LOGIN_TOKEN_FILE,
    RECREATE_REASON_CHARACTERS,
    REFUSAL_LINE,
    SECRETS_DIRECTORY,
    SERVICE,
    SERVICE_TOML,
    TIME_FORMAT,
    Cell,
    LiveSmokeFailed,
    Report,
    Secrets,
    Stack,
    Verdict,
    cleanup_cell,
    end_child,
    event_names,
    inspect_network,
    last_line,
    network_ids,
    other_lines,
    paid_turn,
    project_network,
    read_secret,
    recreate_service,
    service_network_names,
)
from mcp_signer import LISTENING_LINE, PUBLIC_KEY_MOUNT, SCRIPT_MOUNT, VERIFIED
from signing_key import PRIVATE_FILE, PUBLIC_FILE, SIGNING_DIRECTORY
from smoke import Tokens

PUBLIC_KEY = SECRETS_DIRECTORY / SERVICE / SIGNING_DIRECTORY / PUBLIC_FILE
SIGNING_KEY_SECRET = "agent_service_signing_key"  # noqa: S105 - the name of a docker secret and no credential
CA_ROOT_SECRET = "step_ca_root_certificate"  # noqa: S105 - the name of a docker secret and no credential
SECRET_SOURCES = {
    SIGNING_KEY_SECRET: SECRETS_DIRECTORY / SERVICE / SIGNING_DIRECTORY / PRIVATE_FILE,
    CA_ROOT_SECRET: SECRETS_DIRECTORY / "step-ca/root_ca.crt",
}
SECRET_TARGET_DIRECTORY = "/run/secrets"  # noqa: S105 - a mount directory and no credential
GATEWAY_MODE_OPTION = "com.docker.network.bridge.gateway_mode_ipv4"
SHARED_NETWORK_KEY = "agent"
STANDIN_SCRIPT = Path(__file__).resolve().with_name("mcp_signer.py")
PROOF_TOOL = "capability_check"
SMOKE_ARGUMENTS = ("--tool", f"{PROOF_TOOL}:read_only")
GATEWAY_SERVICE = "traefik-mcp"
GATEWAY_PROFILE = "step-ca"
MCP_NETWORK = "mcp-songmaker"
STANDIN_ALIAS = "songmaker-web"
LISTEN_SECONDS = 60
VERDICT_SECONDS = 15
REFUSED_BY_GATEWAY = "UpstreamRefused"
UNREACHABLE_GATEWAY = "UpstreamUnreachable"
NO_TEXT_FAILURE = "provider_error"
NO_BACKEND_CELL = "L4a no backend"
CAPABILITY_CELL = "L4b the capability"


def mcp_origin(service_toml: Path) -> str:
    songmaker = tomllib.loads(service_toml.read_text(encoding="utf-8"))["apps"]["songmaker"]
    if "mcp_origin" not in songmaker:
        raise LiveSmokeFailed(
            "service.toml has no [apps.songmaker] mcp_origin, so there is nothing to prove"
        )
    return songmaker["mcp_origin"]


def standin_name(project: str) -> str:
    return f"{project}-mcp-signer"


def standin_command(
    project: str, network: str, image: str, origin: str, tool: str = PROOF_TOOL
) -> list[str]:
    """Hardened like the listeners' container; only the key's public half goes in, read-only."""
    return [
        "docker", "run", "--rm", "--name", standin_name(project), "--read-only",
        "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
        "--network", network, "--network-alias", STANDIN_ALIAS,
        "-v", f"{STANDIN_SCRIPT}:{SCRIPT_MOUNT}:ro", "-v", f"{PUBLIC_KEY}:{PUBLIC_KEY_MOUNT}:ro",
        "--entrypoint", "python", image, "-I", "-B", SCRIPT_MOUNT, origin, tool,
    ]  # fmt: skip


def service_container(stack: Stack) -> dict:
    listed = stack.compose("ps", "-q", SERVICE)
    identifiers = listed.stdout.split()
    if listed.returncode != 0 or len(identifiers) != 1:
        raise LiveSmokeFailed(f"docker compose ps {SERVICE} did not name one container")
    answer = stack.run(["docker", "inspect", identifiers[0]])
    try:
        return json.loads(answer.stdout)[0]
    except ValueError, IndexError:
        raise LiveSmokeFailed(f"docker inspect {SERVICE} gave no container") from None


def internal_and_isolated(network: dict) -> bool:
    options = network.get("Options") or {}
    return bool(network.get("Internal")) and options.get(GATEWAY_MODE_OPTION) == "isolated"


def l3_networks_cell(stack: Stack, container: dict) -> Cell:
    """The service sits on exactly the networks the resolved configuration names, each of them
    internal and isolated."""
    keys = service_network_names(stack)
    resolved = {stack.configuration["networks"][key]["name"] for key in keys}
    joined = set(container["NetworkSettings"]["Networks"])
    leaky = [key for key in keys if not internal_and_isolated(project_network(stack, key))]
    held = joined == resolved and not leaky
    return Cell(
        "L3 networks", Verdict.HELD if held else Verdict.FAILED,
        f"joined {sorted(joined)}, resolved {sorted(resolved)}, "
        f"not internal and isolated {sorted(leaky)}",
    )  # fmt: skip


def l3_mounts_cell(stack: Stack, container: dict) -> Cell:
    """Each secret is mounted from the file the resolved configuration names, and that file is
    the one SECRET_SOURCES names: the private file alone, never its folder."""
    declared = stack.configuration["secrets"]
    seen = {
        mount["Destination"]: mount["Source"]
        for mount in container["Mounts"]
        if mount["Destination"].startswith(f"{SECRET_TARGET_DIRECTORY}/")
    }
    wanted = {
        f"{SECRET_TARGET_DIRECTORY}/{name}": str(path) for name, path in SECRET_SOURCES.items()
    }
    resolved = {
        f"{SECRET_TARGET_DIRECTORY}/{name}": declared[name]["file"] for name in SECRET_SOURCES
    }
    held = seen == wanted == resolved
    return Cell(
        "L3 mounts", Verdict.HELD if held else Verdict.FAILED,
        f"mounted {sorted(seen.values())}, resolved {sorted(resolved.values())}",
    )  # fmt: skip


def shared_network_cell(stack: Stack) -> Cell:
    """The shared `hal_agent` is found by its compose labels. Empty means removed, a member means
    it stays, absent means held."""
    name = "L3 shared network"
    found = network_ids(stack, SHARED_NETWORK_KEY)
    if not found:
        return Cell(name, Verdict.HELD, "the shared agent network is gone")
    if len(found) != 1:
        return Cell(name, Verdict.FAILED, f"{len(found)} networks carry the shared labels")
    members = inspect_network(stack, found[0]).get("Containers") or {}
    if members:
        return Cell(
            name, Verdict.FAILED, f"{len(members)} container(s) are still on it; nothing removed"
        )
    removed = stack.run(["docker", "network", "rm", found[0]])
    if removed.returncode != 0:
        return Cell(name, Verdict.FAILED, f"docker network rm exited {removed.returncode}")
    return Cell(name, Verdict.HELD, "the empty shared agent network was removed")


def occupied_network_cell(stack: Stack) -> Cell | None:
    """FAILED while any container but traefik-mcp's is on songmaker's MCP network."""
    listed = stack.compose("--profile", GATEWAY_PROFILE, "ps", "-q", GATEWAY_SERVICE)
    if listed.returncode != 0:
        return Cell(
            "L4 the MCP network", Verdict.FAILED, f"docker compose ps {GATEWAY_SERVICE} failed"
        )
    gateway = listed.stdout.split()
    members = project_network(stack, MCP_NETWORK).get("Containers") or {}
    others = [member for member in members if member not in gateway]
    if not others:
        return None
    return Cell(
        "L4 the MCP network", Verdict.FAILED,
        f"{len(others)} container(s) besides {GATEWAY_SERVICE} are on it; songmaker's own "
        "call is the proof now",
    )  # fmt: skip


def failed_without_text(events: list[str], text: str) -> bool:
    return events == ["run_started", "failed"] and text.startswith(NO_TEXT_FAILURE)


def l4a_cell(output: str, service_log: str, known: Secrets) -> Cell:
    output = known.redact(output)
    events, text = event_names(output), other_lines(output)
    said = f"events {events}; {text}"
    refusal = None if events else REFUSAL_LINE.search(output)
    if refusal and refusal["code"] == "forbidden":
        return Cell(
            NO_BACKEND_CELL, Verdict.FAILED, f"forbidden: the service lacks the origin; {said}"
        )
    if {"succeeded", "assistant_text"} & set(events):
        return Cell(NO_BACKEND_CELL, Verdict.FAILED, f"a fallback answered; {said}")
    if UNREACHABLE_GATEWAY in service_log:
        return Cell(
            NO_BACKEND_CELL, Verdict.FAILED, f"the gateway was unreachable (TLS or route); {said}"
        )
    held = failed_without_text(events, text) and REFUSED_BY_GATEWAY in service_log
    return Cell(
        NO_BACKEND_CELL, Verdict.HELD if held else Verdict.FAILED,
        f"the gateway refused and the run failed without text; {said}" if held
        else f"no {REFUSED_BY_GATEWAY} with a failed run; {said}",
    )  # fmt: skip


def l4b_cell(verdict: str | None, output: str, known: Secrets) -> Cell:
    output = known.redact(output)
    events, text = event_names(output), other_lines(output)
    if verdict is None:
        return Cell(CAPABILITY_CELL, Verdict.FAILED, "no verdict from the stand-in")
    if verdict != VERIFIED:
        return Cell(CAPABILITY_CELL, Verdict.FAILED, f"the stand-in {verdict}")
    if not failed_without_text(events, text):
        return Cell(CAPABILITY_CELL, Verdict.FAILED, f"verified, but the run went events {events}")
    return Cell(
        CAPABILITY_CELL,
        Verdict.HELD,
        "verified against public.pem; the run failed without text",
    )


def read_line(process: subprocess.Popen[str], seconds: float) -> str | None:
    """The next line of the child, or None at its end or after `seconds`."""
    lines: queue.Queue[str] = queue.Queue()
    threading.Thread(target=lambda: lines.put(process.stdout.readline()), daemon=True).start()
    try:
        return lines.get(timeout=seconds).strip() or None
    except queue.Empty:
        return None


def run_smoke(stack: Stack, known: Secrets) -> tuple[str, str, list[Cell]]:
    """The smoke's output, the service log since it began, and its clean-up cell."""
    since = datetime.now(UTC).strftime(TIME_FORMAT)
    turn = paid_turn(stack, known.tokens, smoke_arguments=SMOKE_ARGUMENTS)
    logs = stack.compose("logs", "--since", since, SERVICE)
    log = logs.stdout + logs.stderr if logs.returncode == 0 else "SAMPLE FAILED"
    return turn.process.stdout, log, cleanup_cell(turn.cleanup, known)


def standin_is_gone(stack: Stack, name: str) -> bool:
    """`--rm` may have removed the stand-in already; only a confirmed absence counts."""
    listed = stack.run(["docker", "ps", "-a", "-q", "--filter", f"name=^{name}$"])
    return listed.returncode == 0 and not listed.stdout.strip()


def remove_standin(stack: Stack, name: str, known: Secrets) -> list[Cell]:
    removed = stack.run(["docker", "rm", "-f", name])
    if removed.returncode == 0 or standin_is_gone(stack, name):
        return []
    reason = known.redact(last_line(removed.stderr))[:RECREATE_REASON_CHARACTERS]
    return [
        Cell(
            "cleanup of the stand-in",
            Verdict.FAILED,
            f"docker rm exited {removed.returncode}: {reason}",
        )
    ]


def standin_cells(stack: Stack, known: Secrets, report: Report, origin: str) -> None:
    if busy := occupied_network_cell(stack):
        return report.add(busy)
    network = project_network(stack, MCP_NETWORK)["Name"]
    image = stack.configuration["services"][SERVICE]["image"]
    process = stack.start(standin_command(stack.project, network, image, origin))
    try:
        if read_line(process, LISTEN_SECONDS) != LISTENING_LINE:
            report.add(
                Cell(CAPABILITY_CELL, Verdict.FAILED, "the stand-in printed no listening line")
            )
            return
        output, _, cleanup = run_smoke(stack, known)
        report.add(l4b_cell(read_line(process, VERDICT_SECONDS), output, known), *cleanup)
    finally:
        end_child(process)
        report.add(*remove_standin(stack, standin_name(stack.project), known))


def live_signer(
    stack: Stack, known: Secrets, report: Report, origin: str,
    pause: Callable[[float], None] = time.sleep,
) -> int:  # fmt: skip
    if busy := occupied_network_cell(stack):
        report.add(busy)
        return 1
    recreated = recreate_service(stack, known, pause)
    report.add(recreated)
    if recreated.verdict is Verdict.FAILED:
        return 1
    container = service_container(stack)
    report.add(l3_networks_cell(stack, container), l3_mounts_cell(stack, container))
    if report.failed():
        return 1
    report.add(shared_network_cell(stack))
    output, log, cleanup = run_smoke(stack, known)
    report.add(l4a_cell(output, log, known), *cleanup)
    standin_cells(stack, known, report, origin)
    return 1 if report.failed() else 0


def main(
    argv: Sequence[str],
    service_toml: Path = SERVICE_TOML,
    sign_in_with: Callable[[str], Tokens] = sign_in,
    stack_of: Callable[[], Stack] = Stack,
) -> int:
    argparse.ArgumentParser(description=__doc__.splitlines()[0]).parse_args(argv)
    try:
        origin = mcp_origin(service_toml)
        stack = stack_of()
        if busy := occupied_network_cell(stack):
            Report([]).add(busy)  # before the sign-in, so that nothing secret exists yet
            return 1
        client_secret = read_secret(CLIENT_SECRET_FILE, "the client secret")
        login_token = read_secret(LOGIN_TOKEN_FILE, "the login token")
        known = Secrets(sign_in_with(client_secret), login_token, client_secret)
        return live_signer(stack, known, Report(known.values()), origin)
    except (LiveSmokeFailed, SignInFailed) as failure:
        print(f"live signer: {failure}", file=sys.stderr)  # noqa: T201 - the failure line of the live run on standard error
        return 1
    except subprocess.TimeoutExpired:
        print("live signer: a docker command ran out of time", file=sys.stderr)  # noqa: T201 - the failure line of the live run on standard error
        return 1
    except KeyboardInterrupt:
        print("live signer: interrupted", file=sys.stderr)  # noqa: T201 - the failure line of the live run on standard error
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
