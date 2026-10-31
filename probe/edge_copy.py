"""What the live-stack probes share: a copy of the repository with its own venv, and `hal` run in
it, at a pty or without a terminal (#52 proof 10, #60 proof 11, #61 probe c).

A probe works in the copy so that it flips `fleet.yaml` and lets `hal` write `dynamic/` and the
state under its throwaway HOME without ever touching the checkout it runs from. The copy is the
live checkout of that HOME, `<HOME>/srv/hal` with a `.git` directory, so that its `hal apply`
runs there and never against the operator's HOME (#79 rule 3). It is a clean `main` with a bare
remote `<scratch>/origin.git`, as `hal apply --local` requires (its ignored `.env` is written by
that apply, #136); a probe publishes every edit it makes there (commit and push) before it
applies (#95 rule 10). To put the copy behind origin, as a pull request merged elsewhere does, a
probe advances origin from a work clone `<scratch>/work` (#98 P1). A probe adds this directory and
the repository's `src` to `sys.path` before importing it, which also works when the probe is
loaded by path.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from hal.backup.docker import PROJECT_LABEL
from hal.stack import catalog, checkout, compose, deploy_checkout

APPLY_SECONDS = 600
NOT_RUNNABLE = 3  # a probe's exit when its preconditions fail, before it touches anything
HAL_OK, HAL_FAILURE = 0, 3  # hal's exits: 3 is every outcome of the stack that is not "done"
DISCARD_OUTPUT = "/dev/null"
ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")  # hal colours its rows at a pty
REMOTE = "origin.git"
WORK_CLONE = "work"
# The probe's own identity, in the copy's config: its git reads no global one (checkout's local
# profile).
PROBE_IDENTITY = {"user.name": "edge probe", "user.email": "probe@edge.invalid"}
# The fixed network names of compose.yaml (`name: hal_<suffix>`) that apps join as external
# networks; they survive the project's rename, so a probe must never create or remove one.
LIVE_NETWORK_PREFIX = "hal_"
LIVE_NETWORK_NAME = re.compile(
    rf"^(\s+name:\s+){re.escape(LIVE_NETWORK_PREFIX)}(\w+)\s*$", re.MULTILINE
)
GUARDED_COMPOSE_VERBS = {"up", "run", "down"}  # what creates or removes networks
# The networks of compose.yaml that pin a /24 so agent-egress has one address on each; a probe
# moves each to a free /24 of its own, so it never collides with the live stack's.
GATEWAY_NETWORKS = ("egress", "litellm-egress")
GATEWAY_SUBNET = re.compile(r"^ {2}(?P<network>[\w-]+):\n(?P<block>(?: {4}.*\n)+)", re.MULTILINE)
PINNED_PREFIX = re.compile(r"subnet:\s+(\d+\.\d+\.\d+\.)0/24")
# The loopback address a probe's Traefik listens on beside the live one: `lo` routes all of
# 127.0.0.0/8, and the live listeners are bound to 127.0.0.1 only.
PROBE_HOST = "127.0.0.2"
# The hosts of an entrypoint that listens on every address, the probe host's included.
WILDCARD_HOSTS = {"", "0.0.0.0", "[::]"}


class ProbeFailed(Exception):
    """A proof did not hold; the message names what was expected and what came back."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeFailed(message)


def namespaced_compose(text: str, project: str) -> str:
    """`text` of compose.yaml with every fixed network name `hal_<suffix>` moved to
    `<project>_<suffix>`, so a probe's stack shares no network with the live one. Refuses a text
    with no such name, and one in which a `hal_` name remains."""
    namespaced, renamed = LIVE_NETWORK_NAME.subn(rf"\g<1>{project}_\g<2>", text)
    expect(renamed > 0, "compose.yaml names no fixed hal_ network to move")
    remaining = re.findall(rf"name:\s+{LIVE_NETWORK_PREFIX}\S*", namespaced)
    expect(not remaining, f"a hal_ network name remains after the rewrite: {remaining}")
    return namespaced


def beside_the_live_edge(text: str, project: str) -> str:
    """`text` of traefik.yml with every entrypoint address moved to `PROBE_HOST` (its own port
    kept) and the Docker provider's constraint narrowed to `<live constraint> &&
    Label(<PROJECT_LABEL>, <project>)`, so a Traefik started from it listens beside the live one
    and routes only the probe's project. Every other byte stays. Refuses a text with no
    entrypoint address or no Docker constraint, an address already on `PROBE_HOST` or on every
    address (it would hold the probe host's port too), and a value found other than once."""
    try:
        document = yaml.safe_load(text)
        addresses = [entry["address"] for entry in document["entryPoints"].values()]
        constraint = document["providers"]["docker"]["constraints"]
    except (yaml.YAMLError, KeyError, TypeError, AttributeError) as error:
        raise ProbeFailed(
            f"traefik.yml names no entrypoint address or Docker constraint: {error!r}"
        ) from error
    expect(bool(addresses), "traefik.yml names no entrypoint")
    wildcard = [address for address in addresses if address.rpartition(":")[0] in WILDCARD_HOSTS]
    expect(not wildcard, f"{wildcard} listen on every address, {PROBE_HOST} among them")
    narrowed = f"{constraint} && Label(`{PROJECT_LABEL}`, `{project}`)"
    moved = {address: f"{PROBE_HOST}:{address.rpartition(':')[2]}" for address in addresses}
    moved[constraint] = narrowed
    for live, replacement in moved.items():
        expect(not live.startswith(f"{PROBE_HOST}:"), f"{live} is already on {PROBE_HOST}")
        expect(text.count(live) == 1, f"traefik.yml holds {live!r} {text.count(live)} times")
        text = text.replace(live, replacement)
    return text


def live_gateway_prefixes(text: str) -> dict[str, str]:
    """The first three octets (with the trailing dot) of the /24 each of `GATEWAY_NETWORKS` pins in
    `text` of compose.yaml. Refuses a text in which one pins none."""
    blocks = {m["network"]: m["block"] for m in GATEWAY_SUBNET.finditer(text)}
    prefixes = {
        network: found[1]
        for network in GATEWAY_NETWORKS
        if (found := PINNED_PREFIX.search(blocks.get(network, "")))
    }
    expect(
        set(prefixes) == set(GATEWAY_NETWORKS), f"compose.yaml pins no /24 on {GATEWAY_NETWORKS}"
    )
    return prefixes


def free_gateway_prefixes(
    live: Mapping[str, str], candidates: Sequence[str], occupied: Sequence[str]
) -> dict[str, str]:
    """For each live prefix of `live` a free /24 of `candidates`, none of them twice."""
    taken, moved = list(occupied), {}
    for prefix in live.values():
        subnet = free_subnet(candidates, taken)
        taken.append(str(subnet))
        moved[prefix] = str(subnet.network_address).removesuffix("0")
    return moved


def moved_to_probe_subnets(text: str, moved: Mapping[str, str]) -> str:
    """`text` with every live prefix of `moved` replaced by its probe prefix, in one pass; refuses a
    text that names one of them nowhere."""
    for live in moved:
        expect(live in text, f"the file does not name {live}")
    return re.sub("|".join(map(re.escape, moved)), lambda found: moved[found[0]], text)


def without_inherited_apps(text: str) -> str:
    """`text` of fleet.yaml without the entries `catalog.is_app` names (the lane's real apps, whose
    projects a probe on the shared daemon must never plan or start). It drops each app's key line,
    its deeper non-blank lines and its deeper comments. Every blank line and every comment at or
    above the entry indent stays, as does every other line, byte-identical and in order. Refuses a
    text that does not parse or has no `services` mapping, and one whose result does not parse to
    the original minus its apps, outside `services` as well as within."""
    apps = {key for key, entry in _services(text).items() if catalog.is_app(entry)}
    filtered = _without_app_lines(text, apps)
    expect(
        _without_services(filtered, set()) == _without_services(text, apps),
        "the filtered fleet.yaml differs from the original minus its apps",
    )
    return filtered


def _without_app_lines(text: str, apps: set[str]) -> str:
    kept: list[str] = []
    in_services, entry_indent, dropping = False, None, False
    for line in text.splitlines(keepends=True):
        content = line.strip()
        indent = len(line) - len(line.lstrip())
        if line.startswith("services:"):
            in_services = True
        elif in_services and _is_code(content):
            if indent == 0:
                in_services = dropping = False
            else:
                entry_indent = entry_indent or indent
                dropping = _dropping_at(content, indent, entry_indent, dropping, apps)
        if not _is_removed(in_services and dropping, content, indent, entry_indent):
            kept.append(line)
    return "".join(kept)


def _is_code(content: str) -> bool:
    """Whether the stripped line is neither blank nor a comment."""
    return bool(content) and not content.startswith("#")


def _dropping_at(
    content: str, indent: int, entry_indent: int, dropping: bool, apps: set[str]
) -> bool:
    """Whether the entry the stripped code line sits in is dropped: a line at `entry_indent` opens
    an entry, which goes when it is one of `apps`; a deeper line stays in the entry before it."""
    if indent != entry_indent:
        return dropping
    return content.split(":")[0].strip("'\"") in apps


def _is_removed(
    in_dropped_entry: bool, content: str, indent: int, entry_indent: int | None
) -> bool:
    """Whether a line goes: inside a dropped entry, code, or a comment deeper than the entry."""
    return in_dropped_entry and bool(content) and (_is_code(content) or indent > entry_indent)


def _document(text: str) -> dict:
    try:
        document = catalog.parse(text.encode())
    except catalog.CatalogError as error:
        raise ProbeFailed(f"fleet.yaml does not parse: {error}") from error
    expect(isinstance(document, dict), "fleet.yaml has no services mapping")
    return document


def _services(text: str) -> dict:
    services = _document(text).get("services")
    expect(isinstance(services, dict), "fleet.yaml has no services mapping")
    return services


def _without_services(text: str, apps: set[str]) -> dict:
    """The parsed `text` with the entries named `apps` taken out of its `services`."""
    services = {key: entry for key, entry in _services(text).items() if key not in apps}
    return {**_document(text), "services": services}


def expect_project_networks(resolved: dict, project: str) -> None:
    """Raises `ProbeFailed` when a network of a resolved compose configuration (`config --format
    json`) is not named `<project>_...`: a call that resolves one would touch a live network."""
    foreign = {
        key: network["name"]
        for key, network in (resolved.get("networks") or {}).items()
        if not network["name"].startswith(f"{project}_")
    }
    expect(not foreign, f"networks outside the project {project}: {foreign}")


def copy_compose_prefix(copy: Path) -> list[str]:
    """Compose as edge calls it in `copy`: its project directory and file, named so that no
    inherited `COMPOSE_FILE` selects another."""
    compose_file = copy / deploy_checkout.COMPOSE_FILE
    return ["docker", "compose", "--project-directory", str(copy), "--file", str(compose_file)]


def copy_compose_command(copy: Path) -> list[str]:
    """`copy_compose_prefix` with every profile."""
    return [*copy_compose_prefix(copy), "--profile", "*"]


def daemon_subnets() -> list[str]:
    """The subnets of every network the daemon has."""
    listing = subprocess.run(
        ["docker", "network", "ls", "-q"], capture_output=True, text=True, check=True
    ).stdout.split()
    if not listing:
        return []
    inspected = subprocess.run(
        ["docker", "network", "inspect", *listing], capture_output=True, text=True, check=True
    ).stdout
    return [
        config["Subnet"]
        for network in json.loads(inspected)
        for config in (network.get("IPAM") or {}).get("Config") or []
        if config.get("Subnet")
    ]


def free_subnet(candidates: Sequence[str], occupied: Sequence[str]) -> ipaddress.IPv4Network:
    """The first candidate /24 that overlaps none of the `occupied` subnets (`daemon_subnets()`)."""
    used = [ipaddress.ip_network(subnet) for subnet in occupied]
    for candidate in map(ipaddress.IPv4Network, candidates):
        if not any(candidate.overlaps(other) for other in used if other.version == 4):
            return candidate
    raise ProbeFailed(f"no free /24 among {candidates[0]} ... {candidates[-1]}")


class NetworkGuard:
    """Checks, before a compose call that starts or removes something, that what the call's files
    and profiles resolve is the probe's project and names only networks of it (P26). `run` returns
    the stdout of a command. A command is resolved once unless `once` is false, for a file that
    changes between calls."""

    def __init__(self, project: str, run: Callable[[list[str]], str | bytes]) -> None:
        self.project, self.run = project, run
        self.checked: set[tuple[str, ...]] = set()
        self.live_before = live_networks()

    def expect(self, prefix: list[str], *, once: bool = True) -> None:
        key = tuple(prefix)
        if not once or key not in self.checked:
            resolved = json.loads(self.run([*prefix, "config", "--format", "json"]))
            name = resolved.get("name")
            expect(name is not None, f"the resolved configuration names no project: {prefix}")
            expect(name == self.project, f"the project is {name!r}, not {self.project}")
            expect_project_networks(resolved, self.project)
            self.checked.add(key)

    def expect_call(self, command: list[str]) -> None:
        """Checks a compose `command` that starts or removes something with its own files and
        profiles, everything before its verb, so the guard resolves what the call runs."""
        verbs = [index for index, word in enumerate(command) if word in GUARDED_COMPOSE_VERBS]
        if verbs:
            self.expect(command[: verbs[0]], once=False)

    def expect_clean_teardown(self) -> None:
        """No network of the project is left, and the live `hal_*` networks are the same as when
        the guard was made."""
        left = subprocess.run(
            ["docker", "network", "ls", "-q", "--filter", f"name={self.project}_"],
            capture_output=True, check=True, text=True, timeout=APPLY_SECONDS,
        ).stdout.split()  # fmt: skip
        expect(not left, f"the teardown left networks {left}")
        after = live_networks()
        expect(after == self.live_before, f"the hal_ networks changed: {self.live_before ^ after}")


def guarded_compose(copy: Path, guard: NetworkGuard | None, arguments: Sequence[str]) -> list[str]:
    """The arguments of `docker` for the compose `arguments` in `copy` (`copy_compose_prefix`),
    once `guard`, when there is one yet, has checked what they start or remove."""
    command = [*copy_compose_prefix(copy), *arguments]
    if guard is not None:
        guard.expect_call(command)
    return command[1:]


def live_networks() -> set[str]:
    """The names of the fixed `hal_*` networks the daemon has now."""
    listing = subprocess.run(
        ["docker", "network", "ls", "--format", "{{.Name}}"],
        capture_output=True, check=True, text=True, timeout=APPLY_SECONDS,
    )  # fmt: skip
    return {name for name in listing.stdout.split() if name.startswith(LIVE_NETWORK_PREFIX)}


@dataclass(frozen=True)
class LiveProject:
    """What a read-only look at the live Compose project saw: each container's name, id and start
    time, and its volumes' names."""

    name: str
    containers: frozenset[tuple[str, str, str]]
    volumes: frozenset[str]

    def counts(self) -> str:
        return f"{len(self.containers)} containers, {len(self.volumes)} volumes"


def live_project(repository: Path) -> LiveProject:
    """The live project of `repository`'s compose.yaml (its top-level `name`) as the daemon has it
    now; empty when the live stack is down."""

    def docker(*arguments: str) -> list[str]:
        return subprocess.run(
            ["docker", *arguments], capture_output=True, check=True, text=True,
            timeout=APPLY_SECONDS,
        ).stdout.splitlines()  # fmt: skip

    name = yaml.safe_load((repository / deploy_checkout.COMPOSE_FILE).read_text())["name"]
    selector = f"label={PROJECT_LABEL}={name}"
    identifiers = docker("container", "ls", "--all", "--quiet", "--no-trunc", "--filter", selector)
    inspected = docker(
        "container", "inspect", "--format", "{{.Name}} {{.Id}} {{.State.StartedAt}}", *identifiers
    ) if identifiers else []  # fmt: skip
    return LiveProject(
        name,
        frozenset(tuple(line.split(" ", 2)) for line in inspected),
        frozenset(docker("volume", "ls", "--quiet", "--filter", selector)),
    )


def expect_live_project_unchanged(before: LiveProject, repository: Path) -> str:
    """The line that shows the live project is as `before` saw it; refuses any container started,
    replaced or gone, and any volume added or removed."""
    after = live_project(repository)
    expect(
        after == before,
        f"the live project {before.name} changed: containers "
        f"{sorted(before.containers ^ after.containers)}, volumes "
        f"{sorted(before.volumes ^ after.volumes)}",
    )
    return f"the live project {before.name} is untouched: {after.counts()}"


def repository_copy(
    repository: Path, home: Path, scratch: Path, project: str | None = None
) -> Path:
    """The files of `repository` that git tracks or would track, as the live checkout of `home`: a
    `main` pushed to the bare remote `<scratch>/origin.git`, with its ignored `.env` written by the
    first `hal apply --local` and its own venv from `uv sync`. With a `project`, the copy's
    compose.yaml names its fixed networks `<project>_...` (namespaced_compose), so the copy's
    `hal apply` touches no live network. Its fleet.yaml has no app entry (without_inherited_apps),
    with or without a `project`: a probe adds its own fixture apps.
    Copying again over an existing copy publishes what differs."""
    copy = checkout.live_checkout(home)
    listing = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        capture_output=True, cwd=repository, check=True, timeout=APPLY_SECONDS,
    )  # fmt: skip
    for name in filter(None, listing.stdout.decode().split("\0")):
        if (repository / name).is_file():
            (copy / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(repository / name, copy / name)
    fleet_file = copy / catalog.FLEET_FILE
    fleet_file.write_text(without_inherited_apps(fleet_file.read_text()))
    if project:
        compose_file = copy / deploy_checkout.COMPOSE_FILE
        compose_file.write_text(namespaced_compose(compose_file.read_text(), project))
    if not (copy / ".git").is_dir():
        remote = scratch / REMOTE
        git(scratch, "init", "--quiet", "--bare", "--initial-branch", checkout.MAIN, str(remote))
        git(copy, "init", "--quiet", "--initial-branch", checkout.MAIN)
        git(copy, "remote", "add", "origin", str(remote))
        for key, value in PROBE_IDENTITY.items():
            git(copy, "config", key, value)
    synced = subprocess.run(
        ["uv", "sync", "--quiet"], capture_output=True, cwd=copy, check=False,
        timeout=APPLY_SECONDS,
    )  # fmt: skip
    if synced.returncode != 0:
        tail = synced.stderr.decode(errors="replace").strip().splitlines()
        raise ProbeFailed(f"uv sync exited {synced.returncode}: {tail[-1] if tail else ''}")
    publish(copy, "the lane's files")
    return copy


def publish(copy: Path, message: str) -> None:
    """Commit every change of the copy and push it to its remote, as a merged pull request and its
    pull would bring it; the copy is a clean `main` again."""
    git(copy, "add", "--all")
    git(copy, "commit", "--quiet", "--allow-empty", "--message", message)
    git(copy, "push", "--quiet", "origin", checkout.MAIN)


def advance_origin(
    scratch: Path,
    message: str,
    appended: Mapping[str, str],
    replaced: Mapping[str, tuple[str, str]] | None = None,
) -> str:
    """One commit pushed to the bare remote from the work clone `<scratch>/work`, appending each
    text to its file there and replacing, in each file of `replaced`, the one occurrence of the
    first text by the second, so the copy is behind origin's `main` until it merges; the commit's
    short sha."""
    work = scratch / WORK_CLONE
    if (work / ".git").is_dir():
        git(work, "pull", "--quiet", "--ff-only", "origin", checkout.MAIN)
    else:
        git(scratch, "clone", "--quiet", str(scratch / REMOTE), str(work))
        for key, value in PROBE_IDENTITY.items():
            git(work, "config", key, value)
    for name, text in appended.items():
        with (work / name).open("a") as file:
            file.write(text)
    for name, (old, new) in (replaced or {}).items():
        content = (work / name).read_text()
        expect(
            content.count(old) == 1, f"{name} holds {old!r} {content.count(old)} times, not once"
        )
        (work / name).write_text(content.replace(old, new))
    publish(work, message)
    return checkout.Git(work).short()


def git(tree: Path, *arguments: str) -> None:
    """Git through edge's own isolated runner: no hook, no global config, no prompt."""
    result = checkout.run_git(tree, arguments, checkout.Profile.LOCAL)
    tail = compose.last_line(result.stderr.decode("utf-8", "backslashreplace"))
    expect(result.returncode == 0, f"git {arguments[0]} exited {result.returncode}: {tail}")


def run_hal(
    copy: Path,
    environment: Mapping[str, str],
    *arguments: str,
    terminal: bool,
    exit_code: int = 0,
    typed: bytes = b"yes\n",
    launcher: bool = False,
) -> str:
    """`hal <arguments>` in the copy: at a pty with the operator typing `typed`, or with stdin and
    stdout that are no terminal. The whitespace-normalised output of a run that exits
    `exit_code`. With `launcher` it runs the copy's `bin/hal`, which syncs the dependencies first,
    where the default runs the copy's venv program as it is."""
    program = copy / "bin" / "hal" if launcher else copy / ".venv" / "bin" / "hal"
    command = [str(program), *arguments]
    if terminal:
        result = subprocess.run(
            ["script", "-qec", shlex.join(command), DISCARD_OUTPUT],
            input=typed, capture_output=True, env=environment, cwd=copy, check=False,
            timeout=APPLY_SECONDS,
        )  # fmt: skip
    else:
        result = subprocess.run(
            command, stdin=subprocess.DEVNULL, capture_output=True, env=environment,
            cwd=copy, check=False, timeout=APPLY_SECONDS,
        )  # fmt: skip
    text = (result.stdout + result.stderr).decode(errors="replace")
    output = " ".join(ANSI_ESCAPE.sub("", text).split())
    expect(
        result.returncode == exit_code,
        f"hal {' '.join(arguments)} exited {result.returncode}, wanted {exit_code}: "
        f"{output[-200:]}",
    )
    return output


def scratch_directory(text: str) -> Path:
    """The `--scratch` argument as an absolute path of an existing directory the operator can
    write to; anything else is refused where the command line is read."""
    path = Path(text).resolve()
    if not path.is_dir() or not os.access(path, os.W_OK):
        raise argparse.ArgumentTypeError(f"{text} is not a writable directory")
    return path


def compose_engine(environment: Mapping[str, str], copy: Path) -> compose.Compose:
    """edge's own Compose reader, over the copy and the probe's environment."""

    def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command, capture_output=True, text=True, env=environment, cwd=copy,
            check=False, timeout=timeout,
        )  # fmt: skip

    return compose.Compose(run, copy)


def _raise_interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def begin_teardown() -> None:
    """From here an alarm or a SIGTERM cannot abort the teardown and leave the stack, and with it
    the operator's login bind, standing."""
    signal.alarm(0)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)


def run_probe(
    scratch: Path,
    create: Callable[[Path], Any],
    prove: Callable[[Any], int],
    passed: str,
) -> int:
    """A probe's run in `scratch`: refuse a scratch that is not empty, create the probe, prove it,
    and tear it down even when `timeout` ends the proof with SIGTERM. The exit code is the
    proof's, or 1 when the teardown fails; `passed` is printed on success."""
    if any(scratch.iterdir()):
        print("PROBE FAILED: --scratch is not empty")
        return NOT_RUNNABLE
    probe = create(scratch)
    signal.signal(signal.SIGTERM, _raise_interrupt)
    exit_code = prove(probe)
    begin_teardown()
    try:
        probe.teardown()
    except (ProbeFailed, subprocess.TimeoutExpired) as failure:
        print(f"PROBE FAILED: teardown, {failure}")
        exit_code = 1
    if exit_code == 0:
        print(passed)
    return exit_code


def run_main(
    description: str,
    argv: Sequence[str] | None,
    create: Callable[[Path], Any],
    prove: Callable[[Any], int],
    passed: str,
) -> int:
    """A probe's command line, `--scratch DIR`, and its `run_probe`."""
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    return run_probe(parser.parse_args(argv).scratch, create, prove, passed)
