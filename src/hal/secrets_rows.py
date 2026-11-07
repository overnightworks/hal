"""What `hal secrets` prints: one row for each finding (the findings of one folder share a row once
they are many), one row for everything healthy, optional or revoked, and the verdict; with `-v` a
table of every entry first. The facts name entries, paths and kinds, never a value."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath

from hal.output import (
    HEADING_THRESHOLD,
    Glyph,
    Noun,
    Row,
    Verdict,
    counted,
    write_row,
    write_table,
    write_verdict,
)
from hal.output.command import Verb, command
from hal.workstation.layout import Layout
from hal.workstation.secrets_setup import as_command
from hal.workstation.secrets_view import (
    HOME_PREFIX,
    FindingRule,
    Presence,
    SecretEntry,
    SecretFinding,
    SecretStatus,
    SecretsView,
    Verification,
    status_row,
)

MAX_NAMED_PATHS = 3
TABLE_HEADERS = ("name", "kind", "file", "check", "place", "renew")


class Event(StrEnum):
    MISSING = "missing"
    NOT_CHECKED = "not checked"
    INVALID = "invalid"
    RETIRED = "retired"
    UNKNOWN = "unknown"
    TOO_OPEN = "too open"
    CLOSED = "closed"
    SYMLINK = "symlink"
    NOT_A_FOLDER = "not a folder"
    PRESENT = "present"
    NOT_SET_UP = "not set up"
    REVOKED = "revoked"


class Label(Noun):
    FINDING = "finding"
    ENTRY = "entry"
    PATH = "path"


EVENTS = {
    FindingRule.MISSING: Event.MISSING,
    FindingRule.PRESENCE_UNKNOWN: Event.NOT_CHECKED,
    FindingRule.UNKNOWN_FILE: Event.UNKNOWN,
    FindingRule.LOOSE_MODE: Event.TOO_OPEN,
    FindingRule.SYMLINKED_FOLDER: Event.SYMLINK,
    FindingRule.SYMLINKED_FILE: Event.SYMLINK,
    FindingRule.NOT_A_FOLDER: Event.NOT_A_FOLDER,
    FindingRule.CLOSED_FOLDER: Event.CLOSED,
    FindingRule.REVOCATION_UNCONFIRMED: Event.RETIRED,
    FindingRule.VERIFICATION_FAILED: Event.INVALID,
    FindingRule.VERIFICATION_UNREACHABLE: Event.NOT_CHECKED,
}
TREE_RULES = frozenset(
    {
        FindingRule.UNKNOWN_FILE,
        FindingRule.LOOSE_MODE,
        FindingRule.SYMLINKED_FOLDER,
        FindingRule.SYMLINKED_FILE,
        FindingRule.NOT_A_FOLDER,
        FindingRule.CLOSED_FOLDER,
    }
)
FACTS = {
    FindingRule.MISSING: "{kind}",
    FindingRule.PRESENCE_UNKNOWN: "its folder cannot be read",
    FindingRule.UNKNOWN_FILE: "not in the manifest",
    FindingRule.REVOCATION_UNCONFIRMED: "revocation not confirmed",
    FindingRule.VERIFICATION_FAILED: "{detail} failed",
    FindingRule.VERIFICATION_UNREACHABLE: "{detail} hung or is missing",
}
STEPLESS_RULES = frozenset({FindingRule.PRESENCE_UNKNOWN, FindingRule.VERIFICATION_UNREACHABLE})
ENTRY_STEP_RULES = frozenset({FindingRule.MISSING, FindingRule.REVOCATION_UNCONFIRMED})


@dataclass(frozen=True)
class _Folders:
    """Where the secrets live and in which folders below them the manifest names a file."""

    secrets: PurePosixPath
    with_manifest_places: frozenset[PurePosixPath]

    def path_of(self, finding: SecretFinding) -> PurePosixPath:
        return PurePosixPath(finding.subject.removeprefix(HOME_PREFIX)).relative_to(self.secrets)

    def holding(self, path: PurePosixPath) -> PurePosixPath:
        """The nearest folder above `path` holding a manifest place, else the secrets folder."""
        return next(
            (folder for folder in path.parents if folder in self.with_manifest_places),
            PurePosixPath(),
        )

    def shown(self, path: PurePosixPath) -> str:
        return str(path) if path.parts else f"{HOME_PREFIX}{self.secrets}"


def _fact(finding: SecretFinding) -> str:
    kind = finding.kind.label if finding.kind else ""
    return FACTS.get(finding.rule, "{detail}").format(kind=kind, detail=finding.detail)


def _entry_step(entry: SecretEntry) -> str:
    if entry.retired:
        return f"revoke: {entry.revoke_url}"
    return command(Verb.SETUP) if entry.written_by_setup else as_command(entry.recreate)


def _step(finding: SecretFinding, entries: Mapping[str, SecretEntry]) -> str:
    if finding.rule in STEPLESS_RULES:
        return ""
    if finding.rule in ENTRY_STEP_RULES:
        return _entry_step(entries[finding.subject])
    if finding.rule is FindingRule.VERIFICATION_FAILED:
        return as_command(entries[finding.subject].recreate)
    return as_command(finding.fix)


def _finding_row(
    finding: SecretFinding, entries: Mapping[str, SecretEntry], folders: _Folders
) -> Row:
    subject = (
        folders.shown(folders.path_of(finding)) if finding.rule in TREE_RULES else finding.subject
    )
    step = _step(finding, entries)
    return Row(
        Glyph.NEEDS_YOU,
        subject,
        EVENTS[finding.rule],
        _fact(finding),
        details=(step,) if step else (),
    )


def _group_row(findings: Sequence[SecretFinding], folder: PurePosixPath, folders: _Folders) -> Row:
    names = [str(folders.path_of(finding).relative_to(folder)) for finding in findings]
    paths = ", ".join(names) if len(names) <= MAX_NAMED_PATHS else counted(len(names), Label.PATH)
    first = findings[0]
    return Row(
        Glyph.NEEDS_YOU, folders.shown(folder), EVENTS[first.rule], f"{paths} · {_fact(first)}"
    )


def _finding_rows(
    view: SecretsView, entries: Mapping[str, SecretEntry], folders: _Folders, *, grouped: bool
) -> list[Row]:
    """Entry findings stay one row each; with `grouped`, tree findings sharing rule, folder and
    detail share one row, a group of one finding being that finding's own row."""
    rows = []
    groups: dict[tuple[FindingRule, PurePosixPath, str], list[SecretFinding]] = {}
    for finding in view.findings:
        if grouped and finding.rule in TREE_RULES:
            key = (finding.rule, folders.holding(folders.path_of(finding)), _fact(finding))
            groups.setdefault(key, []).append(finding)
        else:
            rows.append(_finding_row(finding, entries, folders))
    for (_rule, folder, _fact_text), found in groups.items():
        single = len(found) == 1
        rows.append(
            _finding_row(found[0], entries, folders)
            if single
            else _group_row(found, folder, folders)
        )
    return rows


def _healthy_row(view: SecretsView) -> list[Row]:
    with_finding = {finding.subject for finding in view.findings if finding.rule not in TREE_RULES}
    healthy = [
        status
        for status in view.statuses
        if not status.entry.retired
        and status.presence is Presence.PRESENT
        and status.entry.name not in with_finding
    ]
    verified = [s.entry.name for s in healthy if s.verification is Verification.PASSED]
    if not verified:
        fact = "not checked"
    else:
        rest = "; the rest not checked" if len(verified) < len(healthy) else ""
        fact = f"{', '.join(verified)} checked: valid{rest}"
    return (
        [Row(Glyph.DONE, counted(len(healthy), Label.ENTRY), Event.PRESENT, fact)]
        if healthy
        else []
    )


def _dim_row(names: list[str], label: str, event: Event) -> list[Row]:
    return [Row(Glyph.UNCHANGED, f"{len(names)} {label}", event, ", ".join(names))] if names else []


def _summary_rows(view: SecretsView) -> list[Row]:
    optional = [
        s.entry.name
        for s in view.statuses
        if s.entry.optional and not s.entry.retired and s.presence is Presence.MISSING
    ]
    revoked = [
        s.entry.name for s in view.statuses if s.entry.retired and s.entry.revocation_confirmed
    ]
    return [
        *_healthy_row(view),
        *_dim_row(optional, "optional", Event.NOT_SET_UP),
        *_dim_row(revoked, "retired", Event.REVOKED),
    ]


def _verdict(view: SecretsView, *, verbose: bool) -> Verdict:
    hint = "" if verbose else f"{command(Verb.SECRETS, '-v')} lists every entry"
    if view.findings:
        return Verdict(Glyph.NEEDS_YOU, counted(len(view.findings), Label.FINDING), (), hint=hint)
    return Verdict(Glyph.DONE, "no findings", ((len(view.statuses), Label.ENTRY),), hint=hint)


def _table_row(status: SecretStatus) -> tuple[str, ...]:
    name, kind, file, check, _expiry, place, _recreate = status_row(status)
    return name, kind, file, check, place, _entry_step(status.entry)


def _folders_of(view: SecretsView, layout: Layout) -> _Folders:
    secrets = PurePosixPath(layout.secrets_dir.relative_to(layout.home))
    return _Folders(
        secrets,
        frozenset(
            pattern.parent.relative_to(secrets)
            for status in view.statuses
            for pattern in status.entry.paths
            if secrets in pattern.parents
        ),
    )


def write(view: SecretsView, layout: Layout, *, verbose: bool) -> None:
    entries = {status.entry.name: status.entry for status in view.statuses}
    if verbose:
        write_table(TABLE_HEADERS, [_table_row(status) for status in view.statuses])
    grouped = not verbose and len(view.findings) >= HEADING_THRESHOLD
    rows = _finding_rows(view, entries, _folders_of(view, layout), grouped=grouped)
    for row in rows if verbose else [*rows, *_summary_rows(view)]:
        write_row(row)
    write_verdict(_verdict(view, verbose=verbose))
