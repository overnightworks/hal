"""Probe of the backup's retention bound and its per-home restore server (#969 cells P1-P8): the
checkout's `hal backup`, `hal backup <app> --pre-apply` and `hal restore --test` under two scratch
HOMEs, each with its own restic repository, against two Postgres apps the probe starts itself.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/backup/retention.py --scratch DIR

The apps `alpha` and `bravo` (bravo with an audio volume) run in `docker run` containers without
network that carry the compose labels hal finds them by and the probe's own label, by which the
teardown removes them. The probe plants back-dated snapshots with `restic backup --time` in the
pinned restic image and reads what is left with `restic snapshots --json`; it never forgets one
itself. Every age derives from `PRE_APPLY_MAX_AGE`. The restic password is a scratch value it
generates and never prints. No live container, volume, network, repository or HOME is named. It
leaves --scratch empty, passed or failed (`edge_copy`). Exit 0: every cell held.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(REPO / "src"))  # hal's own facts

import edge_copy  # noqa: E402
from edge_copy import ProbeFailed, expect  # noqa: E402

from hal.backup.apps import PRE_APPLY_TAG, PostgresMajor  # noqa: E402
from hal.backup.docker import (  # noqa: E402
    ONEOFF_LABEL,
    PROJECT_LABEL,
    RESTORE_OWNER_LABEL,
    RESTORE_OWNER_ROLE,
    SERVICE_LABEL,
    VOLUME_LABEL,
    restore_server_name,
)
from hal.backup.restic import (  # noqa: E402
    KEEP_PRE_APPLY,
    PRE_APPLY_MAX_AGE,
    Mount,
    MountKind,
    app_source,
    restic_argv,
)
from hal.backup.settings import RESTIC_HOSTNAME, RESTORE_IMAGES, Settings  # noqa: E402
from hal.output import write_line  # noqa: E402

HAL = REPO / ".venv" / "bin" / "hal"
HAL_SECONDS = 600
DOCKER_SECONDS = 120
READY_SECONDS = 60
POSTGRES_MAJOR = PostgresMajor.SIXTEEN
POSTGRES_IMAGE = RESTORE_IMAGES[POSTGRES_MAJOR]
ALPHA, BRAVO = "alpha", "bravo"
DB_SERVICE = "postgres"
AUDIO_VOLUME = "audiofiles"
TABLE = "probe_rows"
OTHER_HOST = "retention-probe-other-host"
DAY, HOUR, MINUTE = timedelta(days=1), timedelta(hours=1), timedelta(minutes=1)
# P1's recent pre-apply snapshots: more than a pre-apply run keeps, so only the weekly policy's
# `--keep-tag` keeps them all.
P1_RECENT = KEEP_PRE_APPLY + 2
LOCKED_FILE = "locked.mp3"


def now() -> datetime:
    return datetime.now(UTC).replace(microsecond=0)


def past_the_bound() -> datetime:
    return now() - PRE_APPLY_MAX_AGE - DAY


@dataclass(frozen=True)
class Snapshot:
    snapshot_id: str
    taken: datetime
    app: str
    pre_apply: bool
    host: str


def selected(
    snapshots: list[Snapshot], app: str, *, pre_apply: bool, host: str = RESTIC_HOSTNAME
) -> dict[str, Snapshot]:
    return {
        s.snapshot_id: s
        for s in snapshots
        if (s.app, s.pre_apply, s.host) == (app, pre_apply, host)
    }


@dataclass(frozen=True)
class Home:
    """A scratch HOME: its own password, restic repository, status, lock and work directory."""

    path: Path
    apps_file: Path

    @property
    def settings(self) -> Settings:
        return Settings.for_home(self.path, os.getuid(), os.getgid())

    def hal(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = {
            key: value for key, value in os.environ.items() if key not in {"LOG_FORMAT", "NO_COLOR"}
        }
        return subprocess.run(  # noqa: S603 - argv is built by the probe itself and no shell runs
            [str(HAL), *arguments, "--apps", str(self.apps_file)],
            env={**environment, "HOME": str(self.path)},
            capture_output=True,
            text=True,
            check=False,
            timeout=HAL_SECONDS,
        )

    def status(self) -> dict:
        return json.loads(self.settings.status_file.read_text())


class RetentionProbe:
    def __init__(self, scratch: Path) -> None:
        self.prefix = f"retention-probe-{secrets.token_hex(4)}"
        self.label = f"hal-retention-probe={self.prefix}"
        self.apps_file = scratch / "apps.toml"
        self.apps_file.write_text(self.apps_toml())
        self.source = scratch / "planted"
        self.source.mkdir()
        (self.source / "file").write_text("planted\n")
        self.first = Home(scratch / "h1", self.apps_file)
        self.second = Home(scratch / "h2", self.apps_file)
        self.controls: dict[str, str] = {}

    def apps_toml(self) -> str:
        """Two Postgres records; bravo keeps an audio volume beside its database."""
        return "\n".join(self.app_record(app, audio=app == BRAVO) for app in (ALPHA, BRAVO))

    def app_record(self, app: str, *, audio: bool) -> str:
        lines = [
            f"[app.{app}]",
            f'compose_project = "{self.project(app)}"',
            f'db_service = "{DB_SERVICE}"',
            'dump = "pg_dump_custom"',
            'db_user = "postgres"',
            'db_name = "postgres"',
            f"postgres_major = {int(POSTGRES_MAJOR)}",
            *([f'volume = "{AUDIO_VOLUME}"'] if audio else []),
            f"[app.{app}.restore_test]",
            f'count_table = "{TABLE}"',
            *(
                [f'audio_reference_table = "{TABLE}"', 'audio_reference_column = "path"']
                if audio
                else []
            ),
        ]
        return "\n".join(lines) + "\n"

    def project(self, app: str) -> str:
        return f"{self.prefix}-{app}"

    # --- plumbing -----------------------------------------------------------------------------

    def docker(self, *arguments: str) -> str:
        result = subprocess.run(  # noqa: S603 - argv is built by the probe itself and no shell runs
            ["docker", *arguments],  # noqa: S607 - docker is found on PATH by design
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_SECONDS,
        )
        expect(
            result.returncode == 0,
            f"docker {arguments[0]} exited {result.returncode}: {result.stderr.strip()[-300:]}",
        )
        return result.stdout

    def restic(self, home: Home, command: list[str], *mounts: Mount) -> str:
        result = subprocess.run(  # noqa: S603 - argv is built by hal's own restic module and no shell runs
            restic_argv(home.settings, command, *mounts),
            capture_output=True,
            text=True,
            check=False,
            timeout=DOCKER_SECONDS,
        )
        expect(
            result.returncode == 0,
            f"restic {command[0]} exited {result.returncode}: {result.stderr.strip()[-300:]}",
        )
        return result.stdout

    def hal_ran(
        self, home: Home, cell: str, *arguments: str, exit_code: int = 0
    ) -> subprocess.CompletedProcess[str]:
        result = home.hal(*arguments)
        expect(
            result.returncode == exit_code,
            f"{cell}: hal {' '.join(arguments)} exited {result.returncode}, not {exit_code}: "
            f"{result.stdout.strip()[-400:]} {result.stderr.strip()[-400:]}",
        )
        return result

    def plant(
        self,
        home: Home,
        app: str,
        taken: datetime,
        *,
        pre_apply: bool = True,
        host: str = RESTIC_HOSTNAME,
    ) -> str:
        """A snapshot of the app as a run at `taken` would have left it; returns its full ID."""
        tags = f"{app},{PRE_APPLY_TAG}" if pre_apply else app
        output = self.restic(
            home,
            ["backup", "--json", "--time", f"{taken.astimezone(UTC):%Y-%m-%d %H:%M:%S}",
             "--host", host, "--tag", tags, app_source(app)],
            Mount(MountKind.BIND, str(self.source), app_source(app)),
        )  # fmt: skip
        messages = [json.loads(line) for line in output.splitlines() if line.strip()]
        [summary] = [m for m in messages if m.get("message_type") == "summary"]
        return summary["snapshot_id"]

    def snapshots(self, home: Home) -> list[Snapshot]:
        listed = json.loads(self.restic(home, ["snapshots", "--json"]))
        return [
            Snapshot(
                s["id"],
                datetime.fromisoformat(s["time"]),
                next(tag for tag in s["tags"] if tag != PRE_APPLY_TAG),
                PRE_APPLY_TAG in s["tags"],
                s["hostname"],
            )
            for s in listed
        ]

    def pre_apply_run(self, home: Home, cell: str) -> str:
        """`hal backup alpha --pre-apply --json`, as `hal apply` calls it; the new snapshot."""
        result = self.hal_ran(home, cell, "backup", ALPHA, "--pre-apply", "--json")
        return json.loads(result.stdout)["snapshot"]

    def controls_kept(self, cell: str, snapshots: list[Snapshot]) -> None:
        listed = {s.snapshot_id for s in snapshots}
        lost = [name for name, snapshot_id in self.controls.items() if snapshot_id not in listed]
        expect(not lost, f"{cell}: controls forgotten: {lost}")

    def held(self, cell: str, what: str) -> None:
        write_line(f"#969 {cell} held: {what}")

    # --- the stand ----------------------------------------------------------------------------

    def start(self) -> None:
        for home in (self.first, self.second):
            password = home.settings.password_file
            password.parent.mkdir(mode=0o700, parents=True)
            password.touch(mode=0o600, exist_ok=False)
            password.write_text(secrets.token_urlsafe(32))
            self.hal_ran(home, "stand", "backup", "--init")
        self.docker(
            "volume", "create", "--label", self.label,
            "--label", f"{PROJECT_LABEL}={self.project(BRAVO)}",
            "--label", f"{VOLUME_LABEL}={AUDIO_VOLUME}",
            self.audio_volume,
        )  # fmt: skip
        self.in_audio_volume("echo audio > /audio/one.mp3")
        for app in (ALPHA, BRAVO):
            self.docker(
                "run", "--detach", "--name", self.project(app), "--network", "none",
                "--label", self.label,
                "--label", f"{PROJECT_LABEL}={self.project(app)}",
                "--label", f"{SERVICE_LABEL}={DB_SERVICE}",
                "--label", f"{ONEOFF_LABEL}=False",
                "--env", "POSTGRES_HOST_AUTH_METHOD=trust",
                POSTGRES_IMAGE,
            )  # fmt: skip
        for app in (ALPHA, BRAVO):
            self.wait_until_accepting(app)
            self.docker(
                "exec", self.project(app), "psql", "--username", "postgres", "--host", "127.0.0.1",
                "--set", "ON_ERROR_STOP=1",
                "--command", f"CREATE TABLE {TABLE} (path text); "  # noqa: S608 - the table name is this probe's own literal
                f"INSERT INTO {TABLE} VALUES ('one.mp3');",
            )  # fmt: skip

    @property
    def audio_volume(self) -> str:
        return f"{self.project(BRAVO)}_{AUDIO_VOLUME}"

    def in_audio_volume(self, script: str) -> None:
        """A root shell over bravo's audio volume: what an app writing as root would leave."""
        self.docker(
            "run", "--rm", "--network", "none", "--label", self.label, "--user", "0",
            "--mount", f"type=volume,source={self.audio_volume},target=/audio",
            "--entrypoint", "sh", POSTGRES_IMAGE, "-c", script,
        )  # fmt: skip

    def wait_until_accepting(self, app: str) -> None:
        """Over TCP: the image's init server listens on the socket only, then restarts."""
        deadline = time.monotonic() + READY_SECONDS
        while True:
            ready = subprocess.run(  # noqa: S603 - argv is built by the probe itself and no shell runs
                ["docker", "exec", self.project(app), "pg_isready", "--host", "127.0.0.1"],  # noqa: S607 - docker is found on PATH by design
                capture_output=True,
                check=False,
                timeout=DOCKER_SECONDS,
            )
            if ready.returncode == 0:
                return
            expect(time.monotonic() < deadline, f"{app}'s database did not start")
            time.sleep(1)

    # --- the cells ----------------------------------------------------------------------------

    def cell_p3(self) -> None:
        """P4's controls, then P3: every pre-apply snapshot of alpha past the bound."""
        home = self.first
        self.controls = {
            "alpha's own weekly snapshot past the bound": self.plant(
                home, ALPHA, past_the_bound(), pre_apply=False
            ),
            "alpha's pre-apply snapshot of another host past the bound": self.plant(
                home, ALPHA, past_the_bound(), host=OTHER_HOST
            ),
            "bravo's pre-apply snapshot past the bound": self.plant(home, BRAVO, past_the_bound()),
        }
        past = {self.plant(home, ALPHA, past_the_bound() - days * DAY) for days in (0, 4, 29)}
        self.controls_kept("P4 before", self.snapshots(home))
        self.hal_ran(home, "P3", "backup", ALPHA)
        after = self.snapshots(home)
        expect(
            not selected(after, ALPHA, pre_apply=True), "P3: a pre-apply snapshot of alpha stays"
        )
        weekly = selected(after, ALPHA, pre_apply=False)
        expect(len(weekly) == 2, f"P3: alpha keeps {len(weekly)} weekly snapshots, not 2")
        self.controls_kept("P3", after)
        self.held(
            "P3",
            f"all {len(past)} pre-apply snapshots of alpha past the bound, the newest included, "
            "forgotten by a weekly `hal backup alpha`; alpha's 2 weekly snapshots stay",
        )

    def cell_p2b(self) -> None:
        home = self.first
        self.plant(home, ALPHA, past_the_bound())
        recent = {self.plant(home, ALPHA, now() - hours * HOUR) for hours in (3, 2, 1)}
        new = self.pre_apply_run(home, "P2b")
        after = self.snapshots(home)
        kept = set(selected(after, ALPHA, pre_apply=True))
        expect(kept == {*recent, new}, f"P2b: alpha keeps {len(kept)} pre-apply snapshots")
        self.controls_kept("P2b", after)
        self.held(
            "P2b",
            "`hal backup alpha --pre-apply` forgot the one pre-apply snapshot past the bound and "
            "kept the 3 recent ones and its new one",
        )

    def cell_p2a(self) -> None:
        home = self.first
        before = selected(self.snapshots(home), ALPHA, pre_apply=True)
        missing = KEEP_PRE_APPLY + 1 - len(before)
        for minutes in range(missing, 0, -1):
            self.plant(home, ALPHA, now() - minutes * MINUTE)
        planted = selected(self.snapshots(home), ALPHA, pre_apply=True)
        expect(len(planted) == KEEP_PRE_APPLY + 1, f"P2a: {len(planted)} recent pre-apply")
        new = self.pre_apply_run(home, "P2a")
        after = self.snapshots(home)
        kept = selected(after, ALPHA, pre_apply=True)
        expect(new in kept, "P2a: its new snapshot was forgotten")
        everything = sorted([*planted.values(), kept[new]], key=lambda s: s.taken)
        newest = {s.snapshot_id for s in everything[-KEEP_PRE_APPLY:]}
        expect(set(kept) == newest, f"P2a: alpha keeps {len(kept)}, not its newest ten")
        self.controls_kept("P2a", after)
        self.held(
            "P2a",
            f"`hal backup alpha --pre-apply` over {len(planted)} recent pre-apply snapshots keeps "
            f"the newest {len(kept)}, its new one included",
        )

    def cell_p1_and_p4b(self) -> None:
        home = self.first
        older = self.plant(home, ALPHA, now() - PRE_APPLY_MAX_AGE - DAY)
        younger = self.plant(home, ALPHA, now() - PRE_APPLY_MAX_AGE + DAY)
        recent = set(selected(self.snapshots(home), ALPHA, pre_apply=True)) - {older, younger}
        for minutes in range(P1_RECENT - len(recent), 0, -1):
            recent.add(self.plant(home, ALPHA, now() - minutes * MINUTE))
        bravo_control = self.controls.pop("bravo's pre-apply snapshot past the bound")
        self.hal_ran(home, "P1", "backup")
        after = self.snapshots(home)
        kept = set(selected(after, ALPHA, pre_apply=True))
        expect(kept == {*recent, younger}, f"P1: alpha keeps {len(kept)} pre-apply snapshots")
        self.controls_kept("P1", after)
        self.held(
            "P1",
            "a weekly `hal backup` forgot alpha's pre-apply snapshot a day past the bound and kept "
            f"the one a day inside it and all {len(recent)} recent ones",
        )
        self.held(
            "P4",
            f"through P3, P2b, P2a and P1: {', '.join(self.controls)} kept; bravo's pre-apply "
            "snapshot past the bound kept through P3, P2b and P2a",
        )
        expect(bravo_control not in {s.snapshot_id for s in after}, "P4b: bravo's stays")
        self.held(
            "P4b", "the weekly run in which bravo backed up forgot its old pre-apply snapshot"
        )

    def cell_p5(self) -> None:
        home = self.first
        alpha_past = self.plant(home, ALPHA, past_the_bound())
        self.plant(home, BRAVO, past_the_bound())
        bravo_before = self.bravo_snapshots(home)
        self.in_audio_volume(f"echo held > /audio/{LOCKED_FILE} && chmod 600 /audio/{LOCKED_FILE}")
        result = self.hal_ran(home, "P5", "backup", exit_code=3)
        self.in_audio_volume(f"rm /audio/{LOCKED_FILE}")
        rows = result.stdout.splitlines()
        expected = [
            r"  ✓ alpha\s+backed up\s+\w{8} · .+",
            r"  ✗ bravo\s+not backed up  backup: restic backup ended with exit 3",
            r"  · bravo\s+not pruned     its backup failed",
            r"  ✓ repository\s+pruned\s+checked · .+",
        ]
        expect(
            len(rows) == len(expected) and all(map(re.fullmatch, expected, rows, strict=True)),
            f"P5: the rows are {rows}",
        )
        status = home.status()
        expect(
            (status["failing_app"], status["failing_phase"]) == (BRAVO, "backup"),
            f"P5: the status names {status['failing_app']} in {status['failing_phase']}",
        )
        after = self.snapshots(home)
        expect(alpha_past not in {s.snapshot_id for s in after}, "P5: alpha was not forgotten")
        bravo_after = self.bravo_snapshots(home)
        expect(bravo_before < bravo_after, "P5: one of bravo's snapshots was forgotten")
        expect(len(bravo_after - bravo_before) == 1, "P5: bravo's partial snapshot is missing")
        self.held(
            "P5",
            "with bravo's restic exit 3 (a root-owned unreadable file in its volume) and its "
            f"partial snapshot, `hal backup` exit 3, rows {' | '.join(r.strip() for r in rows)}; "
            f"alpha's pre-apply snapshot past the bound forgotten, all {len(bravo_before)} of "
            "bravo's earlier snapshots kept, its old pre-apply one included",
        )

    def bravo_snapshots(self, home: Home) -> set[str]:
        return {s.snapshot_id for s in self.snapshots(home) if s.app == BRAVO}

    def cell_p6(self) -> None:
        home = self.first
        bound = now() - PRE_APPLY_MAX_AGE
        pre_apply = selected(self.snapshots(home), ALPHA, pre_apply=True).values()
        expect(all(s.taken >= bound for s in pre_apply), "P6: a snapshot is past the bound")
        self.pre_apply_run(home, "P6")
        self.hal_ran(home, "P6", "backup", ALPHA)
        self.held(
            "P6",
            "with no pre-apply snapshot past the bound, `hal backup alpha --pre-apply` and "
            "`hal backup alpha` exit 0",
        )

    def cell_p7(self) -> None:
        home = self.first
        future = self.plant(home, ALPHA, now() + DAY)
        self.hal_ran(home, "P7", "backup", ALPHA)
        expect(future in {s.snapshot_id for s in self.snapshots(home)}, "P7: it was forgotten")
        self.held("P7", "a pre-apply snapshot a day after the host clock outlives a weekly run")

    def cell_p8(self) -> None:
        first, second = (
            restore_server_name(h.settings.lock_file) for h in (self.first, self.second)
        )
        expect(first != second, "P8: both homes name their server alike")
        self.hal_ran(self.second, "P8", "backup", ALPHA)
        standing = self.docker(
            "run", "--detach", "--name", first, "--network", "none", "--label", self.label,
            "--label", f"{RESTORE_OWNER_LABEL}={RESTORE_OWNER_ROLE}",
            "--entrypoint", "sleep", POSTGRES_IMAGE, "3600",
        ).strip()  # fmt: skip
        self.hal_ran(self.second, "P8", "restore", "--test", ALPHA)
        expect(self.containers(standing) == [standing], "P8: H2's restore test removed H1's")
        self.hal_ran(self.first, "P8", "restore", "--test", ALPHA)
        expect(not self.containers(standing), "P8: H1's restore test left its own leftover")
        expect(not self.servers(), "P8: a throwaway server is left")
        self.held(
            "P8",
            f"H1's server {first} and H2's {second} differ; H1's leftover with its name and the "
            "owner label stood through H2's `hal restore --test alpha`, and H1's next one swept it",
        )

    def containers(self, container_id: str) -> list[str]:
        return self.docker(
            "ps", "--all", "--quiet", "--no-trunc", "--filter", f"id={container_id}"
        ).split()

    def servers(self) -> list[str]:
        """The containers under either home's server name: none outlives a run."""
        return [
            found
            for home in (self.first, self.second)
            for found in self.docker(
                "ps", "--all", "--quiet", "--no-trunc",
                "--filter", f"name=^{restore_server_name(home.settings.lock_file)}$",
            ).split()
        ]  # fmt: skip

    # --- teardown ------------------------------------------------------------------------------

    def teardown(self) -> None:
        """Removes what carries the probe's label and either home's server; no other container."""
        containers = [
            *self.docker("ps", "--all", "--quiet", "--filter", f"label={self.label}").split(),
            *self.servers(),
        ]
        if containers:
            self.docker("rm", "--force", "--volumes", *containers)
        volumes = self.docker("volume", "ls", "--quiet", "--filter", f"label={self.label}").split()
        if volumes:
            self.docker("volume", "rm", *volumes)
        left = self.docker("ps", "--all", "--quiet", "--filter", f"label={self.label}").split()
        expect(not left and not self.servers(), f"teardown left {len(left)} containers")


def prove(probe: RetentionProbe) -> int:
    """The stand, then the cells in an order that keeps each one's premise: P3 first, while alpha
    has no pre-apply snapshot, and P1 after P2's single-app runs, since bravo backs up in it."""
    steps = (
        probe.start,
        probe.cell_p3,
        probe.cell_p2b,
        probe.cell_p2a,
        probe.cell_p1_and_p4b,
        probe.cell_p5,
        probe.cell_p6,
        probe.cell_p7,
        probe.cell_p8,
    )
    try:
        for step in steps:
            step()
    except (ProbeFailed, subprocess.TimeoutExpired, OSError, ValueError, KeyError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


def verdict(_probe: RetentionProbe) -> int:
    return edge_copy.passed_line("PROBE PASSED: #969 P1-P8 (P4b)")


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(__doc__.splitlines()[0], argv, RetentionProbe, prove, verdict)


if __name__ == "__main__":
    sys.exit(main())
