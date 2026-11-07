"""The retention census of a container set (#814, S1c of #299): whether a unique canary is in any
sink of the containers, on the paths a run exercised.

The host asks `docker` for each container's inspection, its complete mount table and its log, and
for a database target a plain `pg_dump`, searched in memory and never kept. A
container with Python is searched by `tree_census.py`'s retention mode, which walks each writable
mount by descriptor and reads the table before any filter. A container without Python has its
writable points streamed out as a tar archive and searched here. Every writable entry of the table
is accounted for by exactly one of: a destination of `docker inspect`'s Mounts or Tmpfs, one of
Docker's own mounts (DOCKER_OWN), a path `docker inspect` lists as masked, or a filesystem that
holds no content (`tree_census.EXCLUDED_FILESYSTEMS`). Anything else, any skip the census did not
resolve and any sink that could not be read completely, a failed or unreadable dump included, is a
problem; the verdict is never "clean" over a sink it did not examine.

Only the verdict leaves this module: labels, container names, mount points and closed phrases, never
a canary, a log line or a file name from a container.
"""

from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import NamedTuple

import tree_census
from tree_census import Skip

MAXIMUM_ARCHIVED_FILE = 1 << 26  # a larger file is not read, so it is an unexamined sink
# Docker's per-container writable mounts: the three files it binds in, /dev and /dev/shm.
DOCKER_OWN = frozenset({
    "/etc/hosts", "/etc/hostname", "/etc/resolv.conf", "/dev",
    "/dev/shm",  # NOSONAR(S5443) inspected, never written; a split literal would only hide it  # noqa: S108 - docker mounts it in every container and it is only compared
})  # fmt: skip
HANDED_OVER = frozenset({Skip.NESTED_MOUNT.value, Skip.FILE_MOUNT.value})
COMMAND_NOT_FOUND = frozenset({126, 127})
MOUNT_TABLE = "/proc/1/mountinfo"
DOCKER_SECONDS = 300
FRONT, GATEWAY, LITELLM = "litellm-front", "agent-egress", "litellm"
DATABASE = "litellm-db"
# The compose services of the direct route an app request takes, each with whether its container
# holds Python. LiteLLM cannot run without its database, so the database is searched with the rest.
ROUTE_SERVICES = {FRONT: False, GATEWAY: False, LITELLM: True, DATABASE: False}
COPY_HEADER = re.compile(r'^COPY public\."?(\w+)"? ')
COPY_END = "\\."
DUMP = "dump"

Entry = tuple[str, str, bool]  # mount point, filesystem type, writable


class Completed(NamedTuple):
    returncode: int
    stdout: bytes
    stderr: bytes = b""  # only a log is read from it: a container's standard error


Run = Callable[[Sequence[str], bytes | None], Completed]


def run_docker(command: Sequence[str], stdin: bytes | None = None) -> Completed:
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        list(command), input=stdin, capture_output=True, timeout=DOCKER_SECONDS, check=False
    )
    return Completed(result.returncode, result.stdout, result.stderr)


@dataclass(frozen=True)
class DatabaseLogin:
    """The user and database a `pg_dump` of a PostgreSQL container logs in as."""

    user: str
    database: str

    @classmethod
    def of(cls, service: Mapping) -> DatabaseLogin:
        """The login a resolved compose service's environment gives its database."""
        environment = service["environment"]
        return cls(environment["POSTGRES_USER"], environment["POSTGRES_DB"])

    def options(self) -> list[str]:
        return [f"--username={self.user}", f"--dbname={self.database}"]


@dataclass(frozen=True)
class Target:
    name: str
    has_python: bool
    login: DatabaseLogin | None = None  # a database whose dump is one more sink


def route_target(service: str, name: str, services: Mapping[str, Mapping]) -> Target:
    """The census target of a route service's container: the database comes with the login the
    resolved compose services give it, so that its dump is searched."""
    login = DatabaseLogin.of(services[DATABASE]) if service == DATABASE else None
    return Target(name, ROUTE_SERVICES[service], login)


@dataclass
class Sweep:
    """The verdict over every sink of the targets for the canaries asked."""

    hits: dict[str, list[str]] = field(default_factory=dict)
    problems: tuple[str, ...] = ()
    inventory: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @property
    def found(self) -> dict[str, tuple[str, ...]]:
        """Each canary label that is somewhere, with the sinks that hold it."""
        return {label: tuple(sinks) for label, sinks in self.hits.items()}

    def hit(self, labels: set[str], sink: str) -> None:
        for label in sorted(labels):
            self.hits.setdefault(label, []).append(sink)

    def problem(self, sink: str, phrase: str) -> None:
        self.problems = (*self.problems, f"{sink}: {phrase}")


def mounted_path(destination: str) -> str:
    """The path the mount table shows for a destination: `/var/run` is a link to `/run` in the
    images of the route, and the kernel lists the mount under its target."""
    if destination == "/var/run" or destination.startswith("/var/run/"):
        return "/run" + destination.removeprefix("/var/run")
    return destination


def writable_destinations(document: dict) -> frozenset[str]:
    """The destinations `docker inspect` lists as writable: read-write mounts and tmpfs."""
    mounts = {mount["Destination"] for mount in document["Mounts"] if mount["RW"]}
    return frozenset(map(mounted_path, mounts | set(document["HostConfig"].get("Tmpfs") or {})))


def searched_points(table: Sequence[Entry], masked: frozenset[str]) -> list[tuple[str, str]]:
    """The writable entries that can hold content: not masked, not a filesystem without any."""
    return [
        (point, filesystem)
        for point, filesystem, writable in table
        if writable and filesystem not in tree_census.EXCLUDED_FILESYSTEMS and point not in masked
    ]


def unaccounted(
    table: Sequence[Entry], declared: frozenset[str], masked: frozenset[str]
) -> list[str]:
    """The phrases for every writable entry no rule accounts for, and every inspected writable
    mount the table lacks."""
    allowed = declared | DOCKER_OWN | masked
    problems = [
        f"a writable {filesystem} mount at {point} is not accounted for"
        for point, filesystem, writable in table
        if writable and point not in allowed and filesystem not in tree_census.EXCLUDED_FILESYSTEMS
    ]
    present = {point for point, _, writable in table if writable}
    return problems + [
        f"the inspected writable mount {point} is not in the mount table"
        for point in sorted(declared - present)
    ]


def search_archive(archive: bytes, tokens: Mapping[str, str]) -> tuple[set[str], list[str]]:
    """The labels whose canary a tar archive's regular files hold, and why the search was not
    complete. Special files are listed by the archive and never read."""
    found: set[str] = set()
    problems: list[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
            for member in bundle:
                if not member.isreg():
                    continue
                if member.size > MAXIMUM_ARCHIVED_FILE:
                    problems.append("a file over the size bound")
                    continue
                content = bundle.extractfile(member).read()  # type: ignore[union-attr]
                found |= {label for label, text in tokens.items() if text.encode() in content}
    except tarfile.TarError:
        problems.append("an archive that could not be read completely")
    return found, problems


def contains(data: bytes, tokens: Mapping[str, str]) -> set[str]:
    return {label for label, text in tokens.items() if text.encode() in data}


def dump_sinks(dump: str, tokens: Mapping[str, str]) -> dict[str, set[str]]:
    """Each label whose canary a plain-format dump holds, with where: `dump <table>` for a row of a
    table's COPY block, `dump` for any other line."""
    found: dict[str, set[str]] = {}
    table = None
    for line in dump.splitlines():
        if header := COPY_HEADER.match(line):
            table = header[1]
        elif line == COPY_END:
            table = None
        for label, text in tokens.items():
            if text in line:
                found.setdefault(label, set()).add(f"{DUMP} {table}" if table else DUMP)
    return found


class Census:
    def __init__(self, run: Run, key: bytes) -> None:
        self.run = run
        self.key = key

    def sweep(self, targets: Sequence[Target], tokens: Mapping[str, str]) -> Sweep:
        sweep = Sweep()
        for target in targets:
            self._container(target, tokens, sweep)
        return sweep

    def _container(self, target: Target, tokens: Mapping[str, str], sweep: Sweep) -> None:
        name = target.name
        document = self._inspection(name)
        if document is None:
            sweep.problem(name, "the container could not be inspected")
            return
        declared = writable_destinations(document)
        masked = frozenset(document["HostConfig"].get("MaskedPaths") or ())
        known = declared | DOCKER_OWN | masked
        inside = self._inside(name, tokens, known, masked, sweep) if target.has_python else None
        table = self._table_of(name, sweep) if not target.has_python else inside and inside[0]
        if table is not None:
            for phrase in unaccounted(table, declared, masked):
                sweep.problem(name, phrase)
            points = searched_points(table, masked)
            driver = document["HostConfig"]["LogConfig"]["Type"]
            sweep.inventory[name] = (*(f"{p} {f}" for p, f in points), f"log {driver}")
            for point, _ in points:
                if inside is None:
                    self._archive(name, point, tokens, sweep)
                elif point not in inside[1]:
                    sweep.problem(f"{name} {point}", "the census did not walk the mount")
        self._log(name, tokens, sweep)
        if target.login is not None:
            self._dump(name, target.login, tokens, sweep)

    def _inspection(self, name: str) -> dict | None:
        result = self.run(["docker", "inspect", name], None)
        try:
            document = json.loads(result.stdout)[0] if result.returncode == 0 else None
        except ValueError, IndexError:
            return None
        return document if isinstance(document, dict) else None

    def _table_of(self, name: str, sweep: Sweep) -> list[Entry] | None:
        result = self.run(["docker", "exec", name, "cat", MOUNT_TABLE], None)
        if result.returncode != 0:
            sweep.problem(name, "the mount table could not be read")
            return None
        entries = tree_census.mount_entries(result.stdout)
        return [(entry.point, entry.filesystem, entry.writable) for entry in entries]

    def _inside(
        self,
        name: str,
        tokens: Mapping[str, str],
        known: frozenset[str],
        masked: frozenset[str],
        sweep: Sweep,
    ) -> tuple[list[Entry], set[str]] | None:
        """The table and the walked points of a container the census searched itself."""
        settings = {
            "key": self.key.hex(), "mode": "retention", "known": sorted(known),
            "tokens": dict(tokens),
        }  # fmt: skip
        result = self.run(
            ["docker", "exec", "-i", name, "python", "-I", "-"],
            tree_census.program(settings).encode(),
        )
        report = _last_line(result)
        if report is None:
            sweep.problem(name, "the census could not search the mounts")
            return None
        for mount in report["mounts"]:
            self._mount(name, mount, tokens, masked, sweep)
        table = [(point, filesystem, writable) for point, filesystem, writable in report["table"]]
        return table, {mount["mount"] for mount in report["mounts"]}

    def _mount(
        self,
        name: str,
        mount: dict,
        tokens: Mapping[str, str],
        masked: frozenset[str],
        sweep: Sweep,
    ) -> None:
        point, sink = mount["mount"], f"{name} {mount['mount']}"
        sweep.hit({label for label, count in mount["found"].items() if count}, sink)
        for reason, count in sorted(mount["skips"].items()):
            if reason not in HANDED_OVER:
                sweep.problem(sink, f"{reason} x{count} was not resolved")
        if Skip.FILE_MOUNT.value in mount["skips"] and point not in masked:
            self._search(name, point, self._copy(name, point), tokens, sweep)

    def _archive(self, name: str, point: str, tokens: Mapping[str, str], sweep: Sweep) -> None:
        result = self.run(["docker", "exec", name, "tar", "-c", point], None)
        if result.returncode in COMMAND_NOT_FOUND:
            result = self._copy(name, point)
        self._search(name, point, result, tokens, sweep)

    def _copy(self, name: str, point: str) -> Completed:
        return self.run(["docker", "cp", f"{name}:{point}", "-"], None)

    def _search(
        self, name: str, point: str, result: Completed, tokens: Mapping[str, str], sweep: Sweep
    ) -> None:
        sink = f"{name} {point}"
        if result.returncode != 0:
            sweep.problem(sink, "the archive command failed")
            return
        found, problems = search_archive(result.stdout, tokens)
        sweep.hit(found, sink)
        for phrase in problems:
            sweep.problem(sink, phrase)

    def _log(self, name: str, tokens: Mapping[str, str], sweep: Sweep) -> None:
        result = self.run(["docker", "logs", name], None)
        if result.returncode != 0:
            sweep.problem(name, "the log could not be read")
            return
        sweep.hit(contains(result.stdout + result.stderr, tokens), f"{name} log")

    def _dump(
        self, name: str, login: DatabaseLogin, tokens: Mapping[str, str], sweep: Sweep
    ) -> None:
        """The plain dump of the database, searched here; no text of it leaves this method."""
        sink = f"{name} {DUMP}"
        result = self.run(["docker", "exec", name, "pg_dump", *login.options()], None)
        if result.returncode != 0:
            sweep.problem(sink, "the dump failed")
            return
        try:
            dump = result.stdout.decode()
        except UnicodeDecodeError:
            sweep.problem(sink, "the dump could not be read")
            return
        sweep.inventory[name] = (*sweep.inventory.get(name, ()), DUMP)
        for label, sinks in dump_sinks(dump, tokens).items():
            for where in sorted(sinks):
                sweep.hit({label}, f"{name} {where}")


def _last_line(result: Completed) -> dict | None:
    """The census's one JSON line, or None for a failed or errored run."""
    if result.returncode != 0:
        return None
    try:
        report = json.loads(result.stdout.strip().splitlines()[-1])
    except ValueError, IndexError:
        return None
    return None if "error" in report else report
