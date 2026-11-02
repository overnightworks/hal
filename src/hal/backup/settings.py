"""Where `hal backup` keeps things on this PC, and the pinned images it runs."""

import re
from dataclasses import dataclass
from datetime import timedelta
from importlib import resources
from pathlib import Path

from hal.backup.apps import PostgresMajor

IMAGE_STAGE = re.compile(r"^FROM (\S+) AS (\S+)$", re.MULTILINE)


def _stage_references() -> dict[str, str]:
    dockerfile = resources.files("hal.backup").joinpath("images", "Dockerfile").read_text()
    return {stage: reference for reference, stage in IMAGE_STAGE.findall(dockerfile)}


_STAGES = _stage_references()
RESTIC_IMAGE = _STAGES["restic"]
SQLITE_IMAGE = _STAGES["sqlite"]
# The restore test loads a dump into a throwaway server of the app's own major, so it proves the
# version the app really runs; an older server cannot read a newer archive.
RESTORE_IMAGES = {
    PostgresMajor.SIXTEEN: _STAGES["restore-16"],
    PostgresMajor.SEVENTEEN: _STAGES["restore-17"],
}

# Fixed so restic sees one host and the same source paths every run (parent snapshots, forget).
RESTIC_HOSTNAME = "hal"
READINESS_TIMEOUT = timedelta(minutes=10)
READINESS_POLL_SECONDS = 15
# One readiness probe (docker info/ps/inspect, pg_isready); a hung daemon must not outlast the wait.
PROBE_TIMEOUT = timedelta(seconds=30)
RESTORE_SERVER_TIMEOUT = timedelta(minutes=2)
RESTORE_SERVER_POLL_SECONDS = 1


@dataclass(frozen=True)
class Settings:
    repository: Path
    password_file: Path
    status_file: Path
    lock_file: Path
    work_dir: Path
    """Private staging and restore directories; on the home disk, not a possible tmpfs."""
    uid: int
    gid: int

    @classmethod
    def for_home(cls, home: Path, uid: int, gid: int) -> Settings:
        state = home / ".local/state/edge"
        return cls(
            repository=home / "backups/restic",
            password_file=home / ".secrets/restic/password",
            status_file=state / "backup-status.json",
            lock_file=state / "backup.lock",
            work_dir=home / ".cache/edge-backup",
            uid=uid,
            gid=gid,
        )
