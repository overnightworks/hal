"""The in-container census of the agent service's writable trees (#339 lane C3, agent-runtime#440).

Standard library only. The host sends this file's text followed by one line,
`f"emit({settings_text!r})"` (the settings as one Python string literal, never a hand-quoted
one), on the stdin of `python3 -`; nothing is copied into the container, and the HMAC key and the
settings never reach an argv or the environment. `emit` prints exactly one JSON line.

Nothing leaves memory before `Names`: every path component and every process name is shown as an
allowlisted structural name or as an opaque id. The output holds counts, type letters, opaque ids
and closed skip reasons, never an exception message, a raw name or a `repr`. The walk anchors at a
mount point reached component by component from `/` with O_NOFOLLOW, checked against the mount
table's device, and goes down by descriptor: each directory is opened from its parent's
descriptor with O_NOFOLLOW, checked against the listing by (st_dev, st_ino), and never resolved
by path. Special files and links are listed by type letter and never opened or read; a regular
file is opened only to count a token, after the same identity check.
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import os
import re
import stat
import sys
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field, replace
from enum import StrEnum
from pathlib import Path
from typing import cast

Identity = tuple[int, int]  # (st_dev, st_ino)

ALLOWED_NAMES = frozenset(
    {
        "system-prompt",
        "relay-mcp.json",
        ".claude",
        "home",
        "work",
    }
)
# Mount points the report shows as the path itself; named without the leading slash.
SHOWN_MOUNT_POINTS = frozenset({"tmp"})
RUN_TREE = re.compile(r"agent-run-[A-Za-z0-9_-]{8}")
OPAQUE_HEX_DIGITS = 8

EXCLUDED_FILESYSTEMS = frozenset({"proc", "sysfs", "cgroup", "cgroup2", "devpts", "mqueue"})
START_UP_CHILDREN = frozenset({b"rg", b"git", b"sh", b"uname"})

MAXIMUM_DEPTH = 64
CHUNK_SIZE = 1 << 16
MAXIMUM_SMALL_FILE = 1 << 22
READ_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
DIRECTORY_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | os.O_CLOEXEC


class Skip(StrEnum):
    REPLACED = "replaced"
    FILE_MOUNT = "file mount"
    NESTED_MOUNT = "nested mount skipped"
    LOGIN = "login excluded"
    REFUSED = "refused"
    TOO_DEEP = "too deep"
    NOT_REGULAR = "not regular"
    VANISHED = "vanished"


class Names:
    """The sanitizer: the one way a name from the container's tree is shown."""

    def __init__(self, key: bytes, socks_uid: int) -> None:
        self._key = key
        self._allowed = ALLOWED_NAMES | {f"cc-socks-{socks_uid}"}

    def show(self, component: str | bytes) -> str:
        raw = os.fsencode(component)
        text = os.fsdecode(raw)
        if text in self._allowed:
            return text
        if RUN_TREE.fullmatch(text):
            return "agent-run-<8>"
        digest = hmac.new(self._key, raw, hashlib.sha256).hexdigest()
        return f"n-{digest[:OPAQUE_HEX_DIGITS]}"

    def show_mount(self, point: str) -> str:
        return point if point.removeprefix("/") in SHOWN_MOUNT_POINTS else self.show(point)


@dataclass(frozen=True)
class WritableMount:
    point: str
    nested: frozenset[tuple[str, ...]]  # every other mount point below it, relative
    device: tuple[int, int]  # major, minor


def _decode_escapes(field_text: bytes) -> str:
    return os.fsdecode(re.sub(rb"\\([0-7]{3})", lambda m: bytes([int(m[1], 8)]), field_text))


def _device(field_text: bytes) -> tuple[int, int]:
    major, _, minor = field_text.partition(b":")
    return (int(major), int(minor)) if major.isdigit() and minor.isdigit() else (-1, -1)


def _relative(point: str, below: str) -> tuple[str, ...] | None:
    prefix = point.rstrip("/") + "/"
    if point == below or not below.startswith(prefix):
        return None
    return tuple(part for part in below[len(prefix) :].split("/") if part)


@dataclass(frozen=True)
class MountEntry:
    point: str
    filesystem: str
    writable: bool  # the mount's own options (field 6) hold `rw`
    device: tuple[int, int]  # major, minor


def mount_entries(mountinfo_text: bytes) -> tuple[MountEntry, ...]:
    """Every line of the mount table, before any filter."""
    entries = []
    for line in mountinfo_text.split(b"\n"):
        head, separator, tail = line.partition(b" - ")
        fields = head.split(b" ")
        if not separator or len(fields) < 6 or not tail:
            continue
        filesystem = tail.split(b" ")[0].decode("ascii", "replace")
        writable = b"rw" in fields[5].split(b",")
        entries.append(
            MountEntry(_decode_escapes(fields[4]), filesystem, writable, _device(fields[2]))
        )
    return tuple(entries)


def writable_mounts(mountinfo_text: bytes) -> tuple[WritableMount, ...]:
    """Mounts whose own options (field 6) hold `rw`; the superblock options after ` - ` do not
    count. Pseudo filesystems are left out."""
    entries = mount_entries(mountinfo_text)
    return tuple(
        WritableMount(
            entry.point,
            frozenset(
                rel for other in entries if (rel := _relative(entry.point, other.point)) is not None
            ),
            entry.device,
        )
        for entry in entries
        if entry.writable and entry.filesystem not in EXCLUDED_FILESYSTEMS
    )


class TokenRead(StrEnum):
    FOUND = "found"
    ABSENT = "absent"
    NOT_REGULAR = "not regular"
    VANISHED = "vanished"
    REFUSED = "refused"
    REPLACED = "replaced"


def count_token(
    directory_fd: int, name: str, listed: Identity, token: bytes, chunk_size: int = CHUNK_SIZE
) -> TokenRead:
    """One content read: does the file the listing saw (`listed`) hold the token's bytes? The
    overlap between chunks is the token's length minus one, compared in memory."""
    if not token:
        raise ValueError
    try:
        descriptor = os.open(name, READ_FLAGS, dir_fd=directory_fd)
    except FileNotFoundError:
        return TokenRead.VANISHED
    except OSError:
        return TokenRead.REFUSED
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != listed:
            return TokenRead.REPLACED
        if not stat.S_ISREG(opened.st_mode):
            return TokenRead.NOT_REGULAR
        overlap = len(token) - 1
        carried = b""
        while chunk := os.read(descriptor, chunk_size):
            window = carried + chunk
            if token in window:
                return TokenRead.FOUND
            carried = window[max(0, len(window) - overlap) :]
        return TokenRead.ABSENT
    except OSError:
        return TokenRead.REFUSED
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class Listing:
    path: str
    kind: str
    harness_owned: bool = False


@dataclass
class Census:
    listings: list[Listing] = field(default_factory=list)
    skips: dict[str, int] = field(default_factory=dict)
    token_files: int = 0

    def skip(self, reason: Skip) -> None:
        self.skips[reason.value] = self.skips.get(reason.value, 0) + 1


@dataclass(frozen=True)
class WalkRules:
    excluded: frozenset[Identity] = frozenset()
    nested: frozenset[tuple[str, ...]] = frozenset()
    harness_owned: frozenset[Identity] = frozenset()
    token: bytes | None = None
    root_device: int | None = None  # st_dev of the walked mount; another one is a nested mount

    def for_mount(self, nested: frozenset[tuple[str, ...]], root_device: int) -> WalkRules:
        return cast(WalkRules, replace(self, nested=nested, root_device=root_device))


def kind_letter(mode: int) -> str:
    for test, letter in (
        (stat.S_ISDIR, "d"),
        (stat.S_ISREG, "f"),
        (stat.S_ISLNK, "l"),
        (stat.S_ISFIFO, "p"),
        (stat.S_ISSOCK, "s"),
        (stat.S_ISBLK, "b"),
        (stat.S_ISCHR, "c"),
    ):
        if test(mode):
            return letter
    return "?"


def _open_child(name: str, parent_fd: int) -> int:
    return os.open(name, DIRECTORY_FLAGS, dir_fd=parent_fd)


def _identity(info: os.stat_result) -> Identity:
    return (info.st_dev, info.st_ino)


def _open_verified(name: str, parent_fd: int, listed: os.stat_result) -> int:
    """Open a directory below `parent_fd`; what was opened must be what `listed` saw."""
    child_fd = _open_child(name, parent_fd)
    if _identity(os.fstat(child_fd)) != _identity(listed):
        os.close(child_fd)
        raise OSError(errno.ESTALE, "replaced between listing and open")
    return child_fd


def _listing_names(directory_fd: int) -> Iterator[str] | None:
    try:
        with os.scandir(directory_fd) as entries:
            return iter(sorted(entry.name for entry in entries))
    except OSError:
        return None


def _walk(
    directory_fd: int,
    trail: tuple[str, ...],
    names: Names,
    rules: WalkRules,
    census: Census,
) -> None:
    listed = _listing_names(directory_fd)
    if listed is None:
        census.skip(Skip.REFUSED)
        return
    for name in listed:
        shown = "/".join(names.show(part) for part in (*trail, name))
        try:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            census.skip(Skip.VANISHED)
            continue
        kind = kind_letter(info.st_mode)
        census.listings.append(Listing(shown, kind, _identity(info) in rules.harness_owned))
        if (*trail, name) in rules.nested:
            census.skip(Skip.NESTED_MOUNT)
            continue
        if kind == "f" and rules.token is not None:
            _count_file(directory_fd, name, _identity(info), rules.token, census)
        if kind != "d":
            continue
        skip = _directory_skip(trail, info, rules)
        if skip is not None:
            census.skip(skip)
            continue
        _descend(directory_fd, trail, name, info, names, rules, census)


def _directory_skip(trail: tuple[str, ...], info: os.stat_result, rules: WalkRules) -> Skip | None:
    if _identity(info) in rules.excluded:
        return Skip.LOGIN
    if info.st_dev != rules.root_device:
        return Skip.NESTED_MOUNT
    if len(trail) + 1 >= MAXIMUM_DEPTH:
        return Skip.TOO_DEEP
    return None


def _count_file(
    directory_fd: int, name: str, listed: Identity, token: bytes, census: Census
) -> None:
    outcome = count_token(directory_fd, name, listed, token)
    if outcome is TokenRead.FOUND:
        census.token_files += 1
    elif outcome is not TokenRead.ABSENT:
        census.skip(Skip(outcome.value))


def _descend(
    parent_fd: int,
    trail: tuple[str, ...],
    name: str,
    listed: os.stat_result,
    names: Names,
    rules: WalkRules,
    census: Census,
) -> None:
    try:
        child_fd = _open_verified(name, parent_fd, listed)
    except OSError:
        census.skip(Skip.REPLACED)
        return
    try:
        _walk(child_fd, (*trail, name), names, rules, census)
    finally:
        os.close(child_fd)


def _open_root(point: str) -> int:
    """The mount point, opened one component at a time from `/` so that no ancestor is followed."""
    descriptor = os.open("/", DIRECTORY_FLAGS)
    try:
        for part in point.split("/"):
            if part:
                listed = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                parent, descriptor = descriptor, _open_verified(part, descriptor, listed)
                os.close(parent)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


def _is_directory(point: str) -> bool:
    """False for a single-file mount such as /etc/hosts; a missing point is left to the open."""
    try:
        return stat.S_ISDIR(os.stat(point).st_mode)
    except OSError:
        return True


def census_mount(mount: WritableMount, names: Names, rules: WalkRules) -> Census:
    """Walk one mount from its mount point. Root and every level below are opened without
    following links; the root must be the mount table's device and not the login directory."""
    census = Census()
    if not _is_directory(mount.point):
        census.skip(Skip.FILE_MOUNT)
        return census
    try:
        root_fd = _open_root(mount.point)
    except OSError as failure:
        replaced = failure.errno in (errno.ELOOP, errno.ENOTDIR, errno.ESTALE)
        census.skip(Skip.REPLACED if replaced else Skip.REFUSED)
        return census
    try:
        root = os.fstat(root_fd)
        if (os.major(root.st_dev), os.minor(root.st_dev)) != mount.device:
            census.skip(Skip.REPLACED)
        elif _identity(root) in rules.excluded:
            census.skip(Skip.LOGIN)
        else:
            walked = rules.for_mount(mount.nested, root.st_dev)
            _walk(root_fd, (), names, walked, census)
    finally:
        os.close(root_fd)
    return census


def _read_small(path: str, directory_fd: int | None = None) -> bytes:
    descriptor = os.open(path, READ_FLAGS, dir_fd=directory_fd)
    try:
        return os.read(descriptor, MAXIMUM_SMALL_FILE)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class ProcessRecord:
    pid: int
    ppid: int
    pgid: int
    sid: int
    name: str
    start_up_child: bool


def _process_record(data: bytes, pid: int, names: Names) -> ProcessRecord | None:
    opening, closing = data.find(b"("), data.rfind(b")")
    fields = data[closing + 2 :].split()
    if opening < 0 or closing < opening or len(fields) < 4:
        return None
    command = data[opening + 1 : closing]
    ppid, pgid, sid = (int(value) for value in fields[1:4])
    return ProcessRecord(pid, ppid, pgid, sid, names.show(command), command in START_UP_CHILDREN)


def sample_processes(proc_fd: int, names: Names) -> list[ProcessRecord]:
    records = []
    for entry in os.listdir(proc_fd):
        if not (entry.isascii() and entry.isdigit()):
            continue
        try:
            data = _read_small(f"{entry}/stat", proc_fd)
        except OSError:
            continue
        record = _process_record(data, int(entry), names)
        if record is not None:
            records.append(record)
    return records


def sample_for(
    proc_path: str,
    names: Names,
    duration: float,
    interval: float,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
) -> list[ProcessRecord]:
    """Every distinct process seen while the window lasts, sampled every `interval` seconds."""
    proc_fd = os.open(proc_path, DIRECTORY_FLAGS)
    seen: dict[ProcessRecord, None] = {}
    try:
        deadline = clock() + duration
        while True:
            seen.update(dict.fromkeys(sample_processes(proc_fd, names)))
            if clock() >= deadline:
                return list(seen)
            sleep(interval)
    finally:
        os.close(proc_fd)


INIT_PID = 1


@dataclass
class Disappearance:
    """Whether something was seen, and the wall time it was first seen gone afterwards."""

    seen: bool = False
    gone_at: float | None = None

    def observe(self, present: bool, moment: float) -> None:
        if present:
            self.seen = True
        elif self.seen and self.gone_at is None:
            self.gone_at = moment

    @property
    def settled(self) -> bool:
        return self.gone_at is not None


def cli_group_leader(records: list[ProcessRecord]) -> int | None:
    """The service is the lowest process below init; the CLI is its child that leads a group."""
    service = min(
        (r.pid for r in records if r.ppid == INIT_PID and r.pid != INIT_PID), default=None
    )
    return next((r.pid for r in records if r.ppid == service and r.pgid == r.pid), None)


def watch_for(
    proc_path: str,
    root_path: str,
    names: Names,
    deadline: float,
    interval: float,
    stop_path: str,
    clock: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    wall: Callable[[], float] = time.time,
) -> dict:
    """Samples the processes and the working root's entries until the CLI group and the run tree
    were each seen and then seen gone, the stop file appears, or `deadline` seconds have passed.
    Only booleans, wall times and the number of samples leave."""
    proc_fd = os.open(proc_path, DIRECTORY_FLAGS)
    root_fd = _open_root(root_path)
    group, tree = Disappearance(), Disappearance()
    leader: int | None = None
    samples = 0
    try:
        end = clock() + deadline
        while True:
            records = sample_processes(proc_fd, names)
            moment = wall()
            leader = leader if leader is not None else cli_group_leader(records)
            group.observe(any(r.pgid == leader for r in records), moment)
            tree.observe(bool(list(_listing_names(root_fd) or ())), moment)
            samples += 1
            if (group.settled and tree.settled) or clock() >= end or os.path.exists(stop_path):
                break
            sleep(interval)
    finally:
        os.close(proc_fd)
        os.close(root_fd)
    return {
        "group_seen": group.seen, "group_gone_at": group.gone_at,
        "tree_seen": tree.seen, "tree_gone_at": tree.gone_at, "samples": samples,
    }  # fmt: skip


def start_up_children_only(records: list[ProcessRecord], group_leader: int) -> tuple[bool, int]:
    """The B7 verdict: whether every other process of the leader's group is an expected
    start-up child, and how many there were. No executable name is part of it."""
    children = [r for r in records if r.pgid == group_leader and r.pid != group_leader]
    return all(child.start_up_child for child in children), len(children)


def _identities(paths: list[str]) -> frozenset[Identity]:
    identities = set()
    for path in paths:
        try:
            identities.add(_identity(os.stat(path, follow_symlinks=False)))
        except OSError:
            continue
    return frozenset(identities)


def _census_report(settings: dict, names: Names) -> dict:
    token_file = settings["token_file"]
    token = _read_small(token_file).strip()
    rules = WalkRules(
        excluded=frozenset({_identity(os.stat(os.path.dirname(token_file)))}),
        harness_owned=_identities(settings["harness_owned"]),
        token=token,
    )
    mounts = []
    for mount in writable_mounts(_read_small(f"/proc/{os.getpid()}/mountinfo")):
        census = census_mount(mount, names, rules)
        mounts.append(
            {
                "mount": names.show_mount(mount.point),
                "listings": [
                    [item.path, item.kind, item.harness_owned] for item in census.listings
                ],
                "skips": census.skips,
                "token_files": census.token_files,
            }
        )
    return {"mounts": mounts}


def _shown(entry_point: str, plain: bool, names: Names) -> str:
    return entry_point if plain else names.show_mount(entry_point)


def _every_skip(walks: Iterable[Census]) -> dict[str, int]:
    """The skips of all walks of one mount, each reason at its highest count: an entry can refuse
    one walk and not the next, and the walk it refused did not search it for that token."""
    skips: dict[str, int] = {}
    for walk in walks:
        for reason, count in walk.skips.items():
            skips[reason] = max(skips.get(reason, 0), count)
    return skips


def retention_report(settings: dict, names: Names, mountinfo_text: bytes) -> dict:
    """The retention mode (#814): every writable mount is walked once per token, with no login
    exclusion, and the whole mount table leaves with the filesystem types, before any filter. A
    point shows as itself when the host named it in `known` or its filesystem holds no content,
    else as an opaque id. The host decides what an unresolved skip or an unaccounted mount means."""
    known = frozenset(settings["known"])
    tokens = {label: text.encode() for label, text in settings["tokens"].items()}
    table = [
        [
            _shown(
                entry.point, entry.point in known or entry.filesystem in EXCLUDED_FILESYSTEMS, names
            ),
            entry.filesystem,
            entry.writable,
        ]
        for entry in mount_entries(mountinfo_text)
    ]
    mounts = []
    for mount in writable_mounts(mountinfo_text):
        walks = {
            label: census_mount(mount, names, WalkRules(token=token))
            for label, token in tokens.items()
        }
        mounts.append(
            {
                "mount": _shown(mount.point, mount.point in known, names),
                "listings": len(next(iter(walks.values())).listings),
                "skips": _every_skip(walks.values()),
                "found": {label: walk.token_files for label, walk in walks.items()},
            }
        )
    return {"table": table, "mounts": mounts}


def _sample_report(settings: dict, names: Names) -> dict:
    records = sample_for(settings["proc"], names, settings["duration"], settings["interval"])
    only_expected, children = start_up_children_only(records, settings["group_leader"])
    return {
        "processes": [
            [r.pid, r.ppid, r.pgid, r.sid, r.name] for r in sorted(records, key=lambda r: r.pid)
        ],
        "only_expected_start_up_children": only_expected,
        "start_up_children": children,
    }


def _watch_report(settings: dict, names: Names) -> dict:
    return watch_for(
        settings["proc"], settings["working_root"], names, settings["deadline"],
        settings["interval"], settings["stop_path"],
    )  # fmt: skip


def run(settings_text: str) -> dict:
    settings = json.loads(settings_text)
    names = Names(bytes.fromhex(settings["key"]), os.getuid())
    if settings["mode"] == "census":
        return _census_report(settings, names)
    if settings["mode"] == "watch":
        return _watch_report(settings, names)
    if settings["mode"] == "retention":
        return retention_report(settings, names, _read_small(f"/proc/{os.getpid()}/mountinfo"))
    return _sample_report(settings, names)


def program(settings: dict) -> str:
    """What the host sends on the stdin of `python -I -`: this file and the call of `emit`."""
    return Path(__file__).read_text(encoding="utf-8") + f"\nemit({json.dumps(settings)!r})\n"


def emit(settings_text: str) -> None:
    try:
        report = run(settings_text)
    except Exception:  # the text of an exception may carry a name or the token
        report = {"error": "failed"}
    sys.stdout.write(json.dumps(report) + "\n")
