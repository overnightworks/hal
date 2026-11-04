"""restic, run from its pinned image: the repository and the password file are mounted, never read.

The password reaches restic only as a read-only file behind `--password-file`.
"""

import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path

from hal.backup import host
from hal.backup.apps import DB_FOLDER, PRE_APPLY_TAG
from hal.backup.settings import RESTIC_HOSTNAME, RESTIC_IMAGE, Settings

REPOSITORY = "/repo"
PASSWORD_FILE = "/run/secrets/restic-password"  # noqa: S105 - the path of a mounted secret file and no secret
RESTORE_TARGET = "/restore"
SCRATCH = "/scratch"
RETRY_LOCK = "5m"
KEEP_WEEKLY = 4
KEEP_MONTHLY = 3
# A snapshot taken right before a change is applied carries this tag besides its app's name.
KEEP_PRE_APPLY = 10
# The longest any pre-apply snapshot stays, measured on the host clock: the privacy text states it.
PRE_APPLY_MAX_AGE = timedelta(days=90)
# A snapshot's full ID, the only form a forget is ever named: never a prefix or an option.
_FULL_ID = re.compile(r"[0-9a-f]{64}")
CHECK_READ_DATA_SUBSET = "10%"
# Every prune repacks each pack that holds an unused blob, so a forgotten snapshot's bytes leave
# the repository at that prune: the privacy text's bound on backups depends on it.
PRUNE = ("--prune", "--max-unused", "0")
_SNAPSHOTS_LABEL = "restic snapshots"
# The snapshot layout under an app's source path: the dump and manifest (DB_FOLDER), the audio,
# and a SQLite app's files volume under its compose volume name.
AUDIO_FOLDER = "audio"


@dataclass(frozen=True)
class BackupSummary:
    snapshot_id: str
    source_bytes: int
    """restic's `total_bytes_processed`: the size of what the backup read, not what it added."""


class MountKind(StrEnum):
    BIND = "bind"
    VOLUME = "volume"


@dataclass(frozen=True)
class Mount:
    kind: MountKind
    source: str
    """A host path for a bind mount (it must exist; Docker never creates it), else a volume."""
    target: str
    readonly: bool = True

    def as_argument(self) -> str:
        argument = f"type={self.kind},source={self.source},target={self.target}"
        return f"{argument},readonly" if self.readonly else argument


@dataclass(frozen=True)
class KeptVolume:
    """A compose volume the snapshot holds read-only beside the dump, in its own folder."""

    folder: str
    volume: str
    skip: str | None
    """A name glob left out at every depth below the folder."""


def app_source(app: str) -> str:
    """The fixed in-container path an app's snapshot holds: DB_FOLDER and the kept volume."""
    return f"/backup/{app}"


def container_argv(
    settings: Settings,
    *mounts: Mount,
    entrypoint: str | None = None,
    image: str = RESTIC_IMAGE,
    user: str | None = None,
) -> list[str]:
    """`docker run` with no network, no privileges and a read-only root, as the operator's user
    unless the run names another."""
    argv = [
        "docker", "run", "--rm",
        "--log-driver", "none",
        "--network", "none",
        "--hostname", RESTIC_HOSTNAME,
        "--user", user or f"{settings.uid}:{settings.gid}",
        "--read-only",
        # restic stages pack files in TMPDIR: a tmpfs only this container's user can enter.
        "--tmpfs", f"{SCRATCH}:mode=0700,uid={settings.uid},gid={settings.gid}",
        "--env", f"TMPDIR={SCRATCH}",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
    ]  # fmt: skip
    argv += [argument for mount in mounts for argument in ("--mount", mount.as_argument())]
    if entrypoint is not None:
        argv += ["--entrypoint", entrypoint]
    return [*argv, image]


def restic_argv(settings: Settings, command: list[str], *mounts: Mount) -> list[str]:
    repository = Mount(MountKind.BIND, str(settings.repository), REPOSITORY, readonly=False)
    password = Mount(MountKind.BIND, str(settings.password_file), PASSWORD_FILE)
    return [
        *container_argv(settings, repository, password, *mounts),
        "--repo", REPOSITORY,
        "--password-file", PASSWORD_FILE,
        "--no-cache",
        "--retry-lock", RETRY_LOCK,
        *command,
    ]  # fmt: skip


def init(settings: Settings) -> None:
    _restic(settings, "restic init", ["init"])


def backup(
    settings: Settings,
    app: str,
    staging: Path,
    kept: KeptVolume | None,
    *,
    pre_apply: bool = False,
) -> BackupSummary:
    """One snapshot holding dump, manifest and the kept volume (none for a DB-only app); any
    non-zero exit (3 too) is a failure. The skip is anchored under the volume's folder."""
    mounts = [Mount(MountKind.BIND, str(staging), f"{app_source(app)}/{DB_FOLDER}")]
    excludes: list[str] = []
    if kept is not None:
        target = f"{app_source(app)}/{kept.folder}"
        mounts.append(Mount(MountKind.VOLUME, kept.volume, target))
        if kept.skip is not None:
            excludes = ["--exclude", f"{target}/**/{kept.skip}"]
    output = _restic(
        settings,
        "restic backup",
        ["backup", "--json", *excludes, *_tag(app, pre_apply=pre_apply), app_source(app)],
        *mounts,
    )
    return _backup_summary(output)


def forget(settings: Settings, app: str, *, pre_apply: bool = False) -> None:
    """The weekly policy never deletes a pre-apply snapshot; a pre-apply run thins only those.

    Either then forgets the app's pre-apply snapshots past PRE_APPLY_MAX_AGE by ID: restic applies
    no host or tag to an ID, so the listing alone scopes the delete, and it prunes only what the
    same call forgot. A forget with neither IDs nor a policy is refused, so none runs empty.
    """
    _restic(
        settings,
        "restic forget",
        [
            "forget", *_scope(app, pre_apply=pre_apply), "--group-by", "host,tags",
            *(_pre_apply_policy() if pre_apply else _weekly_policy()),
            *PRUNE,
        ],
    )  # fmt: skip
    if expired := _pre_apply_older_than(settings, app, host.now() - PRE_APPLY_MAX_AGE):
        _restic(settings, "restic forget", ["forget", *expired, *PRUNE])


def _pre_apply_older_than(settings: Settings, app: str, bound: datetime) -> list[str]:
    """The full IDs of the app's pre-apply snapshots of this host taken before the bound."""
    listing = _restic(
        settings, _SNAPSHOTS_LABEL, ["snapshots", "--json", *_scope(app, pre_apply=True)]
    )
    return [snapshot_id for snapshot_id, taken in _taken(listing) if taken < bound]


def _taken(listing: bytes) -> list[tuple[str, datetime]]:
    """Each listed snapshot's full ID and the instant it was taken; anything else fails loud."""
    try:
        snapshots = json.loads(listing)
        if not isinstance(snapshots, list):
            raise ValueError("a listing that is no array")
        return [_id_and_time(snapshot) for snapshot in snapshots]
    except (ValueError, KeyError, TypeError) as error:
        raise host.UnreadableOutputError("restic snapshots output is unreadable") from error


def _id_and_time(snapshot: dict[str, str]) -> tuple[str, datetime]:
    snapshot_id, taken = snapshot["id"], datetime.fromisoformat(snapshot["time"])
    if not _FULL_ID.fullmatch(snapshot_id) or taken.utcoffset() is None:
        raise ValueError("a snapshot without its full ID or an instant")
    return snapshot_id, taken


def _pre_apply_policy() -> list[str]:
    return ["--keep-last", str(KEEP_PRE_APPLY)]


def _weekly_policy() -> list[str]:
    return [
        "--keep-weekly", str(KEEP_WEEKLY), "--keep-monthly", str(KEEP_MONTHLY),
        "--keep-tag", PRE_APPLY_TAG,
    ]  # fmt: skip


def check(settings: Settings, *, read_data: bool) -> None:
    subset = [f"--read-data-subset={CHECK_READ_DATA_SUBSET}"] if read_data else []
    _restic(settings, "restic check", ["check", *subset])


def latest_snapshot(settings: Settings, app: str) -> str | None:
    ids = snapshot_ids(settings, app, "--latest", "1")
    return ids[-1] if ids else None


def has_snapshot(settings: Settings, app: str, snapshot_id: str) -> bool:
    return snapshot_id in snapshot_ids(settings, app)


def snapshot_ids(settings: Settings, app: str, *options: str) -> list[str]:
    output = _restic(settings, _SNAPSHOTS_LABEL, ["snapshots", "--json", *options, *_scope(app)])
    try:
        return [snapshot["id"] for snapshot in json.loads(output)]
    except (ValueError, KeyError, TypeError) as error:
        raise host.UnreadableOutputError("restic snapshots output is unreadable") from error


def restore(settings: Settings, app: str, snapshot_id: str, target: Path) -> None:
    """The app's source path lands directly in target: DB_FOLDER and the kept folder below it."""
    _restic(
        settings,
        "restic restore",
        ["restore", f"{snapshot_id}:{app_source(app)}", "--target", RESTORE_TARGET],
        Mount(MountKind.BIND, str(target), RESTORE_TARGET, readonly=False),
    )


def snapshots(settings: Settings) -> str:
    return _restic(settings, _SNAPSHOTS_LABEL, ["snapshots", "--host", RESTIC_HOSTNAME]).decode()


def unlock(settings: Settings) -> None:
    """Removes only stale restic locks; a live run's lock stays."""
    _restic(settings, "restic unlock", ["unlock"])


# restic's own exit codes for a repository that does not exist, is locked, or rejects the password.
REPOSITORY_EXIT_CODES = frozenset({10, 11, 12})


class RepositoryUnusableError(host.HostCommandError):
    """restic says the repository, not the app being worked on, is why it failed."""


def _restic(settings: Settings, label: str, command: list[str], *mounts: Mount) -> bytes:
    try:
        return host.run(restic_argv(settings, command, *mounts), label=label)
    except host.HostCommandError as error:
        if error.exit_code in REPOSITORY_EXIT_CODES:
            raise RepositoryUnusableError(
                label, str(error).removeprefix(f"{label} "), error.exit_code
            ) from error
        raise


def _scope(app: str, *, pre_apply: bool = False) -> list[str]:
    return ["--host", RESTIC_HOSTNAME, *_tag(app, pre_apply=pre_apply)]


def _tag(app: str, *, pre_apply: bool = False) -> list[str]:
    """Each app's snapshots carry its name as their tag; restic reads a comma list as all of them
    when it selects and as the whole set when it tags."""
    return ["--tag", f"{app},{PRE_APPLY_TAG}" if pre_apply else app]


def _backup_summary(backup_output: bytes) -> BackupSummary:
    try:
        messages = [json.loads(line) for line in backup_output.splitlines() if line.strip()]
        summary = next(m for m in messages if m.get("message_type") == "summary")
        snapshot_id, source_bytes = summary["snapshot_id"], summary["total_bytes_processed"]
    except (ValueError, KeyError, AttributeError, StopIteration) as error:
        raise host.UnreadableOutputError("restic backup summary is unreadable") from error
    if not isinstance(snapshot_id, str) or not _is_size(source_bytes):
        raise host.UnreadableOutputError("restic backup summary is unreadable")
    return BackupSummary(snapshot_id, source_bytes)


def _is_size(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0
