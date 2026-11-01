"""The host side of `tree_census.py` (#339): sends its source and one settings line to
`python -I -` inside the service container and returns the parsed records. The HMAC key is made
once per client, so one opaque name means the same thing in every answer; a raw name never leaves
the container."""

from __future__ import annotations

import json
import secrets
import sys
import tomllib
from pathlib import Path
from typing import NamedTuple

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))  # tree_census.py

import tree_census
from egress import Probe, ProbeFailed, expect

SERVICE_UID = 1000  # `user: "1000:1000"` of the service in compose.yaml
SAMPLE_INTERVAL = 0.25
WATCH_INTERVAL = 0.01
WATCH_STOP_PATH = "/probe-watch/stop"  # the file the host's overlay lets it create to end a watch


class Process(NamedTuple):
    pid: int
    ppid: int
    pgid: int
    sid: int
    name: str  # as `tree_census.Names` shows it


class Watched(NamedTuple):
    """What a watch saw of the CLI's process group and the run tree: whether each was seen, the
    wall time (unix seconds) it was first seen gone afterwards, and how many samples it took."""

    group_seen: bool
    group_gone_at: float | None
    tree_seen: bool
    tree_gone_at: float | None
    samples: int


class Mount(NamedTuple):
    """What the census shows of one writable mount: its entries as (shown path, kind), why it
    skipped some as (reason, count) pairs, and how many files outside the login hold the token."""

    listings: tuple[tuple[str, str], ...]
    skips: tuple[tuple[str, int], ...]
    token_files: int = 0

    @property
    def listed(self) -> bool:
        """False when the census listed nothing and skipped something: the walk lists every entry
        before it decides a skip, so that is a root it could not read, never an empty one."""
        return bool(self.listings) or not self.skips


class CensusClient:
    def __init__(self, probe: Probe, container: str, configuration: Path) -> None:
        settings = tomllib.loads(configuration.read_text(encoding="utf-8"))
        self.working_root = settings["cli"]["working_root"]
        self.token_file = settings["cli"]["anthropic"]["token_file"]
        self.probe = probe
        self.container = container
        self.key = secrets.token_bytes(16)
        self.names = tree_census.Names(self.key, SERVICE_UID)

    @property
    def sleep(self) -> str:
        """The opaque name the census shows for `sleep`."""
        return self.names.show("sleep")

    def processes(self, duration: float = 0) -> tuple[Process, ...]:
        """Every distinct process seen in a window of `duration` seconds; 0 is one pass."""
        report = self.ask({
            "mode": "sample", "proc": "/proc", "duration": duration,
            "interval": SAMPLE_INTERVAL, "group_leader": 0,
        })  # fmt: skip
        return tuple(Process(*record) for record in report["processes"])

    def watch(self, deadline_seconds: float) -> Watched:
        """Samples the processes and the working root every 10 ms until the group and the tree
        were each seen and then gone, the stop file appears, or the deadline passes."""
        return Watched(**self.ask({
            "mode": "watch", "proc": "/proc", "working_root": self.working_root,
            "deadline": deadline_seconds, "interval": WATCH_INTERVAL, "stop_path": WATCH_STOP_PATH,
        }))  # fmt: skip

    def mounts(self) -> dict[str, Mount]:
        """Every writable mount the census shows, by its shown name."""
        report = self.ask({"mode": "census", "token_file": self.token_file, "harness_owned": []})
        shown = {
            entry["mount"]: Mount(
                tuple((path, kind) for path, kind, _ in entry["listings"]),
                tuple(sorted(entry["skips"].items())),
                entry["token_files"],
            )
            for entry in report["mounts"]
        }
        expect(len(shown) == len(report["mounts"]), "the census shows one writable mount twice")
        return shown

    def listed(self, *mounts: str) -> tuple[int, ...]:
        """How many entries the census lists below each writable mount (a path), in order."""
        seen = self.mounts()
        counts = []
        for mount in mounts:
            shown = self.names.show_mount(mount)
            expect(shown in seen, "the census shows no writable mount for one asked")
            counts.append(len(seen[shown].listings))
        return tuple(counts)

    def ask(self, settings: dict) -> dict:
        program = tree_census.program({"key": self.key.hex(), **settings})
        command = ["docker", "exec", "-i", self.container, "python", "-I", "-"]
        result = self.probe.run(command, stdin=program, check=False, timeout=240)
        mode = settings["mode"]
        if result.returncode != 0:
            raise ProbeFailed(f"the census exited {result.returncode} in {mode} mode")
        report = json.loads(result.stdout.strip().splitlines()[-1])
        if "error" in report:
            raise ProbeFailed(f"the census failed in {mode} mode")
        return report
