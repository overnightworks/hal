"""The backup's own manifest, and what a restored copy must show to count as good."""

import json
from dataclasses import dataclass
from pathlib import Path

MANIFEST_SCHEMA = 1
MANIFEST_NAME = "manifest.json"
DUMP_NAME = "db.dump"
SQLITE_COPY_NAME = "db.sqlite3"


class VerificationError(RuntimeError):
    """The restored copy is not what was backed up; the message says how."""


@dataclass(frozen=True)
class Manifest:
    app: str
    audio_files: int | None
    """None for a DB-only app."""
    rows: int | None = None
    """The restore test's table count in the staged copy; only a SQLite app has one."""
    files: int | None = None
    """The files in a SQLite app's kept volume; absent when it declares none."""

    def as_json(self) -> str:
        document = {"schema": MANIFEST_SCHEMA, "app": self.app, "audio_files": self.audio_files}
        if self.rows is not None:
            document["rows"] = self.rows
        if self.files is not None:
            document["files"] = self.files
        return json.dumps(document) + "\n"

    @classmethod
    def from_json(cls, text: str) -> Manifest:
        try:
            document = json.loads(text)
            if document["schema"] != MANIFEST_SCHEMA:
                raise ValueError(document["schema"])
            audio_files, rows = document["audio_files"], document.get("rows")
            files = document.get("files")
            return cls(
                app=document["app"],
                audio_files=None if audio_files is None else int(audio_files),
                rows=None if rows is None else int(rows),
                files=None if files is None else int(files),
            )
        except (ValueError, KeyError, TypeError) as error:
            raise VerificationError("the snapshot's manifest is unreadable") from error


def _manifest_count(expected: int | None) -> str:
    return "no number" if expected is None else str(expected)


def check_file_count(expected: int | None, restored: int, noun: str) -> None:
    """The restored kept volume holds exactly the files the manifest counted."""
    if restored != expected:
        raise VerificationError(
            f"{restored} {noun} restored, the manifest names {_manifest_count(expected)}"
        )


def check_rows(manifest: Manifest, restored: int) -> None:
    """A SQLite app's restored table holds exactly the rows its staged copy held."""
    if restored != manifest.rows:
        raise VerificationError(
            f"{restored} rows restored, the manifest names {_manifest_count(manifest.rows)}"
        )


def check_row_count(table: str, rows: int, *, require_rows: bool) -> None:
    if require_rows and rows == 0:
        raise VerificationError(f"the restored table {table} is empty")


def check_audio_references(references: list[str], restored_audio: Path) -> None:
    """Every audio file the restored database names exists in the copy with a size above zero."""
    if missing := sum(1 for reference in references if not _present(restored_audio, reference)):
        raise VerificationError(
            f"{missing} of {len(references)} referenced audio files are missing or empty"
        )


def _present(root: Path, reference: str) -> bool:
    candidate = (root / reference).resolve()
    return (
        candidate.is_relative_to(root.resolve())
        and candidate.is_file()
        and candidate.stat().st_size > 0
    )
