"""`hal check` runs every read-only check of `home` and says in plain words whether all is well and what to do.

It writes one report and sends at most one desktop notification and one e-mail, and only when an action appears or
goes: every finding has one level (OK, Note, Action needed), notes alone and findings that merely persist
never nag. A check that breaks or recovers is an action that appears or goes, because its failure is remembered as one; the mail and the popup
name it. The desktop counts as a channel only while a graphical session
exists, the mail only while `~/.secrets/smtp/account.toml` exists; the news is remembered once every such channel delivered it and at least one exists. Exit code: 0 when
every check is clean, 1 when any finding exists, 2 when the configuration file
or the secrets manifest is invalid, 3 when a check broke on an unexpected error. A broken check leaves the other checks' findings
in the report.
"""

from __future__ import annotations

import json
import re
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from enum import StrEnum

from hal.output import Glyph, Noun, Row, Verdict, printable, write_error, write_row, write_verdict
from hal.output.command import Verb, command
from hal.workstation import backup_check, exposure_check, hook_check, logs_check, mail, platform_check, secrets_view
from hal.workstation.exposure_check import ExposureReader, ExposureRule
from hal.workstation.logs_check import LOG_DIRECTORY
from hal.workstation.platform_check import MINIMUM_FREE_SHARE, REBOOT_REQUIRED_FILE, DiskSpaceReader
from hal.workstation.report import Level, findings_count, read_state_file, write_state_file
from hal.workstation.secrets_view import ExitCodeProbe, FindingRule, SecretKind
from hal.workstation.layout import CommandRunner, Layout

MINIMUM_FREE_PERCENT = round(MINIMUM_FREE_SHARE * 100)


@dataclass(frozen=True)
class CheckSettings:
    notify: bool = True


@dataclass(frozen=True)
class CheckContext:
    layout: Layout
    settings: CheckSettings
    run: CommandRunner
    probe: ExitCodeProbe
    now: datetime
    disk_space: DiskSpaceReader
    read_exposure: ExposureReader


@dataclass(frozen=True)
class CheckResult:
    name: str
    report: str
    finding_identities: frozenset[str]
    error: Exception | None = None


def _failure_line(name: str, error: Exception) -> str:
    return f"check {name} failed ({type(error).__name__}): {error}"


CheckFindings = tuple[str, frozenset[str]]
"""What one check returns: its report section and the identities of its findings."""


MISSING_PASSWORD_RULE = "missing-password"  # noqa: S105 - a rule name and no credential


def _secret_rule(finding: secrets_view.SecretFinding) -> str:
    """A missing human password is its own rule: the one missing secret that needs action."""
    if (finding.rule, finding.kind) == (FindingRule.MISSING, SecretKind.HUMAN_PASSWORD):
        return MISSING_PASSWORD_RULE
    return finding.rule.value


def _secrets_check(ctx: CheckContext) -> CheckFindings:
    view, report = secrets_view.inspect(ctx.layout, ctx.probe, ctx.now)
    return report, frozenset(f"{_secret_rule(finding)}\t{finding.subject}" for finding in view.findings)


def _hook_check(ctx: CheckContext) -> CheckFindings:
    findings, report = hook_check.inspect(ctx.layout, ctx.run, ctx.now)
    return report, frozenset(finding.identity for finding in findings)


def _logs_check(ctx: CheckContext) -> CheckFindings:
    findings, report = logs_check.inspect(ctx.run, ctx.now, LOG_DIRECTORY)
    return report, frozenset(finding.identity for finding in findings)


def _platform_check(ctx: CheckContext) -> CheckFindings:
    findings, report = platform_check.inspect(ctx.run, ctx.now, REBOOT_REQUIRED_FILE, ctx.disk_space, platform_check.read_switched_off(ctx.layout.home))
    return report, frozenset(finding.identity for finding in findings)


def _backup_check(ctx: CheckContext) -> CheckFindings:
    findings, report = backup_check.inspect(ctx.layout.home, ctx.now)
    return report, frozenset(finding.identity for finding in findings)


def _exposure_check(ctx: CheckContext) -> CheckFindings:
    findings, report = exposure_check.inspect(ctx.read_exposure, ctx.now)
    return report, frozenset(finding.identity for finding in findings)


# The one place a check gets its name; the name prefixes every remembered finding identity.
CHECKS: tuple[tuple[str, Callable[[CheckContext], CheckFindings]], ...] = (
    ("secrets", _secrets_check),
    ("hook", _hook_check),
    ("logs", _logs_check),
    ("backup", _backup_check),
    ("platform", _platform_check),
    ("exposure", _exposure_check),
)
CHECK_FAILED_IDENTITY = "check-failed"


def _run_isolated(name: str, run_check: Callable[[CheckContext], CheckFindings], ctx: CheckContext) -> CheckResult:
    """A check that breaks becomes one line in the report, so the other checks' findings stay visible."""
    try:
        report, identities = run_check(ctx)
    except Exception as error:
        return CheckResult(name, f"# {name}\n\n{_failure_line(name, error)}\n", frozenset(), error)
    return CheckResult(name, report, identities)


def run_areas(ctx: CheckContext, names: frozenset[str]) -> tuple[CheckResult, ...]:
    """The named checks, each isolated, in the order of `CHECKS`."""
    return tuple(_run_isolated(name, run_check, ctx) for name, run_check in CHECKS if name in names)


def _failure_marker(name: str) -> str:
    return f"{name}\t{CHECK_FAILED_IDENTITY}"


CHECK_NAMES = frozenset(name for name, _ in CHECKS)
FAILURE_MARKERS = frozenset(_failure_marker(name) for name in CHECK_NAMES)


def remembered_identities(results: tuple[CheckResult, ...], previous: frozenset[str] | None) -> frozenset[str]:
    """What the run found, whatever order the checks report it in.

    A broken check is remembered as one failure marker, so its breaking is news; the findings it could not
    observe are carried over from the previous run, because unobserved is neither new nor gone.
    """
    before = previous or frozenset()
    identities: set[str] = set()
    for result in results:
        if result.error:
            identities.add(_failure_marker(result.name))
            identities.update(identity for identity in before if identity.startswith(f"{result.name}\t"))
        else:
            identities.update(f"{result.name}\t{identity}" for identity in result.finding_identities)
    return frozenset(identities)


def render_report(results: tuple[CheckResult, ...], now: datetime) -> str:
    total = sum(len(result.finding_identities) for result in results)
    failed = [result.name for result in results if result.error]
    failed_clause = f" | failed: {', '.join(failed)}" if failed else ""
    header = f"# {command(Verb.CHECK)} {now:%d.%m.%Y %H:%M} | {findings_count(total)}{failed_clause}"
    return "\n".join([header, *("\n" + result.report.rstrip() for result in results)]) + "\n"


def previous_identities(layout: Layout) -> frozenset[str] | None:
    text = read_state_file(layout.home, layout.check_findings_file)
    return None if text is None else _parse_identities(text)


REMOVED_CHECK_NAME = "tidy"


def _is_of_the_removed_check(identity: object) -> bool:
    return isinstance(identity, str) and identity.partition("\t")[0] == REMOVED_CHECK_NAME


def _parse_identities(text: str) -> frozenset[str]:
    """Only identities `hal check` itself remembers pass, so nothing else is ever carried into the state file.

    The findings of the removed tidy check are dropped unseen: they are neither news nor recovered.
    """
    identities = json.loads(text)
    if isinstance(identities, list):
        identities = [identity for identity in identities if not _is_of_the_removed_check(identity)]
    if not isinstance(identities, list) or not all(isinstance(identity, str) and _is_remembered(identity) for identity in identities):
        raise ValueError("remembered findings invalid: expected a list of check, rule and subject")
    return frozenset(identities)


def _is_remembered(identity: str) -> bool:
    """Check name, then either the failure marker or the rule and subject of a finding with a level, each separated by a tab; the subject may be empty."""
    name, _, finding = identity.partition("\t")
    rule, separator, _ = finding.partition("\t")
    return name in CHECK_NAMES and (finding == CHECK_FAILED_IDENTITY or bool(separator and rule != CHECK_FAILED_IDENTITY and _rule_report(name, rule)))


def remember(layout: Layout, identities: frozenset[str]) -> None:
    write_state_file(layout.home, layout.check_findings_file, json.dumps(sorted(identities), indent=0) + "\n")


NOTIFY_FAILED = "popup failed: notify-send did not run; the next run reports again"
NOTIFY_FAILED_NOT_RETRIED = "popup failed: notify-send did not run; the mail was delivered, so the popup is not sent again"


@dataclass(frozen=True)
class RuleReport:
    """What the mail says of one rule: its level, the plain sentence, and the one step that clears it (for an action)."""

    level: Level
    sentence: str
    next_step: str = ""
    area_note: str = ""
    """What the area line says after the level when the rule is a note; the sentence without its final period when empty."""
    resolved: str = ""
    """What the mail says once an action is gone, as a sentence that reads true on its own."""
    describes_shared_state: bool = False
    """Whether the sentence describes one state however many subjects or rules show it, so a current action with the same sentence still denies a recovery."""
    hides_state: bool = False
    """Whether the rule means its check cannot read the state it checks, so no other action of that check may be reported as done."""


AGENT_STEP = "Tell an agent: \"{area}: please look\"."


def _container_report(sentence: str, problem: str, resolved: str) -> RuleReport:
    return RuleReport(Level.ACTION, sentence, f"Tell an agent: \"{{subject}} {problem}, please look\".", resolved=resolved)


ACTION, NOTE = Level.ACTION, Level.NOTE
SECRETS_VIEW = f"Run `{command(Verb.SECRETS)}`."
BACKUP_NOW = f"Run `{command(Verb.BACKUP)}`."
SETUP_APPLY = f"Run `{command(Verb.SETUP)}`."
HOOK_BROKEN = RuleReport(
    ACTION, "The protection that checks every commit for secrets is not working.", SETUP_APPLY,
    resolved="The protection that checks every commit for secrets is working again.",
    describes_shared_state=True,
)
LOGS_UNSEEN = RuleReport(ACTION, "The check cannot see all the logs.", AGENT_STEP, resolved="The check can see all the logs again.", hides_state=True)
LOGS_NOT_ROTATED = RuleReport(NOTE, "Logs are not yet deleted everywhere after 30 days.", area_note="not yet deleted everywhere after 30 days")
SECRET_UNFIT_FOLDER = RuleReport(NOTE, "A folder among the secrets is not in shape.", area_note="a folder among the secrets is not in shape")
# The sentence of a rule names only what the mail may carry: a Compose project or an app by name, never a secret, a path or a home file (#415 Z6).
RULE_REPORTS: dict[tuple[str, str], RuleReport] = {
    ("platform", "container-restarting"): _container_report("{subject} keeps restarting and is therefore unreachable.", "keeps restarting", "{subject} no longer keeps restarting."),
    ("platform", "container-dead"): _container_report("{subject} has crashed.", "has crashed", "{subject} no longer reports a crash."),
    ("platform", "container-unhealthy"): _container_report("{subject} is running but reports being unwell.", "reports being unwell", "{subject} no longer reports being unwell."),
    ("platform", "container-exited"): _container_report("{subject} stopped with an error.", "stopped with an error", "{subject} no longer reports an error exit."),
    ("platform", "docker-unreadable"): RuleReport(ACTION, "The check cannot read Docker; whether the services run is unknown.", AGENT_STEP, resolved="The check can read Docker again.", hides_state=True),
    ("platform", "job-failed"): RuleReport(
        ACTION, "{subject} failed on its last run.", "Tell an agent: \"{subject} failed, please look\".", resolved="{subject} no longer reports a failure.",
    ),
    ("platform", "systemd-unreadable"): RuleReport(ACTION, "The check cannot read systemd; whether the jobs ran is unknown.", AGENT_STEP, resolved="The check can read systemd again.", hides_state=True),
    ("platform", "disk-low"): RuleReport(
        ACTION, f"The disk has less than {MINIMUM_FREE_PERCENT} % free.", "Tell an agent: \"The disk is nearly full, please look\".",
        resolved=f"The disk has at least {MINIMUM_FREE_PERCENT} % free again.", describes_shared_state=True,
    ),
    ("platform", "reboot-pending"): RuleReport(NOTE, "A restart of the PC is pending.", area_note="a restart of the PC is pending"),
    ("backup", "backup-stale"): RuleReport(ACTION, "{subject} was not backed up for too long.", BACKUP_NOW, resolved="{subject} was backed up again."),
    ("backup", "backup-failed"): RuleReport(ACTION, "The last backup failed.", BACKUP_NOW, resolved="The backup reports no error any more.", describes_shared_state=True),
    ("backup", "backup-status-unreadable"): RuleReport(ACTION, "Whether the backup runs is unknown.", BACKUP_NOW, resolved="Whether the backup runs is known again.", hides_state=True),
    ("backup", "backup-crashed"): RuleReport(ACTION, "The backup is stuck.", AGENT_STEP, resolved="The backup is no longer stuck.", describes_shared_state=True),
    ("hook", "hooks-path"): HOOK_BROKEN,
    ("hook", "hook-file"): HOOK_BROKEN,
    ("hook", "quality"): HOOK_BROKEN,
    ("hook", "engines"): HOOK_BROKEN,
    ("hook", "mise"): RuleReport(
        ACTION, "mise is missing or not the pinned one; the quality gate cannot install its scanners.", SETUP_APPLY,
        resolved="mise is the pinned one again.", describes_shared_state=True,
    ),
    ("hook", "hidden-hook"): RuleReport(NOTE, "A repo's own commit step is hidden.", area_note="a repo's own commit step is hidden"),
    ("secrets", FindingRule.LOOSE_MODE.value): RuleReport(ACTION, "A secret is readable by others.", SECRETS_VIEW, resolved="A secret is no longer readable by others."),
    ("secrets", FindingRule.SYMLINKED_FOLDER.value): RuleReport(ACTION, "A secret sits behind a link.", SECRETS_VIEW, resolved="A secret no longer sits behind a link."),
    ("secrets", FindingRule.SYMLINKED_FILE.value): RuleReport(ACTION, "A secret file is a link.", SECRETS_VIEW, resolved="A secret file is no longer a link."),
    ("secrets", FindingRule.REVOCATION_UNCONFIRMED.value): RuleReport(
        ACTION, "A retired key is not yet confirmed as revoked.", SECRETS_VIEW, resolved="A retired key is confirmed as revoked."
    ),
    ("secrets", FindingRule.VERIFICATION_FAILED.value): RuleReport(ACTION, "A login is no longer valid; what uses it fails.", SECRETS_VIEW, resolved="The check of a login reports no error any more."),
    ("secrets", MISSING_PASSWORD_RULE): RuleReport(ACTION, "The backup password is missing; without it nothing can be restored.", SECRETS_VIEW, resolved="The backup password is no longer reported missing."),
    ("secrets", FindingRule.MISSING.value): RuleReport(NOTE, "Credentials{readers} are still missing."),
    ("secrets", FindingRule.NOT_A_FOLDER.value): SECRET_UNFIT_FOLDER,
    ("secrets", FindingRule.CLOSED_FOLDER.value): SECRET_UNFIT_FOLDER,
    ("secrets", FindingRule.PRESENCE_UNKNOWN.value): RuleReport(NOTE, "Whether a secret is there cannot be seen.", area_note="whether a secret is there cannot be seen"),
    ("secrets", FindingRule.VERIFICATION_UNREACHABLE.value): RuleReport(NOTE, "A login could not be checked just now.", area_note="a login could not be checked just now"),
    ("secrets", FindingRule.UNKNOWN_FILE.value): RuleReport(NOTE, "There are unknown files among the secrets.", area_note="there are unknown files among the secrets"),
    ("logs", "container-json-file"): LOGS_NOT_ROTATED,
    ("logs", "docker-default-driver"): LOGS_NOT_ROTATED,
    ("logs", "rsyslog-file"): LOGS_NOT_ROTATED,
    ("logs", "journal-age"): RuleReport(ACTION, "There are logs older than 30 days.", SETUP_APPLY, resolved="There are no logs older than 30 days any more.", describes_shared_state=True),
    ("logs", "journal-unreadable"): LOGS_UNSEEN,
    ("logs", "docker-unreadable"): LOGS_UNSEEN,
    ("exposure", ExposureRule.REACHABLE_BEYOND_LOOPBACK.value): RuleReport(
        ACTION, "{subject} can be reached from beyond this PC.", 'Tell an agent: "{subject} can be reached from beyond this PC, please look".',
        resolved="{subject} can no longer be reached from beyond this PC.",
    ),
    ("exposure", ExposureRule.ROUTING_NAME_UNUSABLE.value): RuleReport(
        ACTION, "The routing name of {subject} cannot be used.", 'Tell an agent: "The routing name of {subject} cannot be used, please look".',
        resolved="The routing name of {subject} can be used again.",
    ),
}
BROKEN_CHECK_REPORT = RuleReport(ACTION, "The {area} check did not run.", f"Run `{command(Verb.CHECK)}`.", resolved="The {area} check runs again.")
# The areas in the order the mail names them, by the check that owns each.
AREAS = (
    ("platform", "Services"),
    ("backup", "Backup"),
    ("hook", "Commit protection"),
    ("secrets", "Secrets"),
    ("logs", "Server logs"),
    ("exposure", "Exposure"),
)
AREA_LABELS = dict(AREAS)
TERMINAL_LABELS = {"platform": "services", "backup": "backup", "hook": "commit hook", "secrets": "secrets", "logs": "server logs", "exposure": "exposure"}


@dataclass(frozen=True)
class Item:
    """One remembered identity, told what it says and how much it matters."""

    identity: str
    check: str
    report: RuleReport
    sentence: str
    next_step: str
    area_note: str
    resolved: str

    @property
    def level(self) -> Level:
        return self.report.level


def _rule_report(check_name: str, rule: str) -> RuleReport | None:
    if rule == CHECK_FAILED_IDENTITY:
        return BROKEN_CHECK_REPORT
    return RULE_REPORTS.get((check_name, rule))


APP_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
NO_READERS: Mapping[str, str] = MappingProxyType({})


def _split(identity: str) -> tuple[str, str, str]:
    """The check, the rule and the subject of a remembered identity."""
    check_name, rule, subject = [*identity.split("\t", 2), "", ""][:3]
    return check_name, rule, subject


def _item(identity: str, readers: Mapping[str, str]) -> Item:
    check_name, rule, subject = _split(identity)
    report = _rule_report(check_name, rule)
    assert report is not None, identity  # noqa: S101 - the identity names a rule that exists
    words = {"subject": subject, "area": AREA_LABELS[check_name], "readers": f" for {readers[subject]}" if readers.get(subject) else ""}
    note = (report.area_note or report.sentence).removesuffix(".")
    return Item(identity, check_name, report, report.sentence.format(**words), report.next_step.format(**words), note.format(**words), report.resolved.format(**words))


def _items(identities: frozenset[str], readers: Mapping[str, str] = NO_READERS) -> list[Item]:
    """In the order of the mail: area, then the rule and subject the identity starts with."""
    area_order = {name: position for position, (name, _) in enumerate(AREAS)}
    return sorted((_item(identity, readers) for identity in identities), key=lambda item: (area_order[item.check], item.identity))


def _actions(identities: frozenset[str] | None) -> frozenset[str]:
    return frozenset(item.identity for item in _items(identities or frozenset()) if item.level is Level.ACTION)


def _is_news(current: frozenset[str], previous: frozenset[str] | None) -> bool:
    """An action that appeared or went is news, a broken or recovered check included; notes alone never are."""
    return _actions(current) != _actions(previous)


def _area_level(items: list[Item], check_name: str) -> Level:
    return max((item.level for item in items if item.check == check_name), default=Level.OK)


class Finding(Noun):
    ACTION = "action"
    NOTE = "note"


class AreaState(StrEnum):
    OK = "ok"
    NOT_CHECKED = "not checked"


class AreaChecked(Noun):
    AREA = "area checked"


LEVEL_FINDINGS = {Level.ACTION: Finding.ACTION, Level.NOTE: Finding.NOTE}
LEVEL_GLYPHS = {Level.OK: Glyph.DONE, Level.NOTE: Glyph.UNCHANGED, Level.ACTION: Glyph.NEEDS_YOU}
BROKEN_AREA_FACT = "the check did not run · details in the report"
MORE_FINDINGS = " · +{count} more"
BARE_COMMAND_STEP = re.compile(r"Run `(.+)`\.")


@dataclass(frozen=True)
class AreaSummary:
    """What the terminal says of one area: its level, how many findings are at that level, the first one's sentence and how many other findings the area has."""

    check: str
    level: Level
    count: int
    sentence: str
    others: int


def area_summaries(items: list[Item]) -> list[AreaSummary]:
    """One summary per area in the mail's order, from the items the mail is made of."""
    summaries = []
    for name, _ in AREAS:
        level = _area_level(items, name)
        in_area = [item for item in items if item.check == name]
        at_level = [item for item in in_area if item.level is level and level is not Level.OK]
        sentence = at_level[0].sentence.removesuffix(".") if at_level else ""
        summaries.append(AreaSummary(name, level, len(at_level), sentence, len(in_area) - len(at_level) if at_level else 0))
    return summaries


def _terminal_step(step: str) -> str:
    """A command bare, any other step as the mail writes it without its final period."""
    command = BARE_COMMAND_STEP.fullmatch(step)
    return command.group(1) if command else step.removesuffix(".")


def _area_row(summary: AreaSummary, broken: bool) -> Row:
    label = TERMINAL_LABELS[summary.check]
    if broken:
        return Row(Glyph.FAILED, label, AreaState.NOT_CHECKED, BROKEN_AREA_FACT)
    if summary.level is Level.OK:
        return Row(Glyph.DONE, label, AreaState.OK)
    more = MORE_FINDINGS.format(count=summary.count - 1 + summary.others) if summary.count + summary.others > 1 else ""
    return Row(LEVEL_GLYPHS[summary.level], label, LEVEL_FINDINGS[summary.level], summary.sentence + more, summary.count)


def title(current: frozenset[str]) -> str:
    """The state of the PC in one phrase; at action it names the areas."""
    items = _items(current)
    levels = {name: _area_level(items, name) for name, _ in AREAS}
    action_areas = [label for name, label in AREAS if levels[name] is Level.ACTION]
    if action_areas:
        return f"PC check: {Level.ACTION.label.lower()} – {', '.join(action_areas)}"
    return "PC check: all well – notes only" if Level.NOTE in levels.values() else "PC check: all well"


MAX_ITEM_LINES = 20
MORE_ITEMS = "… and {count} more, see report"


def _capped(lines: list[str]) -> list[str]:
    if len(lines) <= MAX_ITEM_LINES:
        return lines
    return [*lines[:MAX_ITEM_LINES], MORE_ITEMS.format(count=len(lines) - MAX_ITEM_LINES)]


def _action_lines(current: frozenset[str], previous: frozenset[str] | None) -> list[str]:
    before = _actions(previous)
    lines = [
        f"{number}. {item.sentence}{'' if item.identity in before else ' (new)'}\n   Next step: {item.next_step}"
        for number, item in enumerate((item for item in _items(current) if item.level is Level.ACTION), start=1)
    ]
    return _capped(lines)


def _gone_lines(current: frozenset[str], previous: frozenset[str] | None) -> list[str]:
    """An action is reported as done only when nothing now contradicts it: no current action on the same subject or, for a shared state, with the same sentence, and no current action of its check that cannot be read."""
    current_actions = _items(_actions(current))
    held_back = {(item.check, _split(item.identity)[2]) for item in current_actions}
    held_sentences = {item.sentence for item in current_actions if item.report.describes_shared_state}
    unreadable_checks = {item.check for item in current_actions if item.report.hides_state}
    gone = [
        item
        for item in _items(_actions(previous) - current)
        if (item.check, _split(item.identity)[2]) not in held_back and item.sentence not in held_sentences and item.check not in unreadable_checks
    ]
    return _capped([f"- {sentence}" for sentence in dict.fromkeys(item.resolved for item in gone)])


@dataclass(frozen=True)
class MailFacts:
    """What the mail says beyond the findings: who reads each secret (a manifest fact) and when the last backup succeeded."""

    readers: Mapping[str, str] = NO_READERS
    last_backup: datetime | None = None


def _when(moment: datetime, now: datetime) -> str:
    local, today = moment.astimezone(), now.astimezone().date()
    day = {today: "today", today - timedelta(days=1): "yesterday"}.get(local.date(), f"{local:%Y-%m-%d}")
    return f"{day} {local:%H:%M}"


def _area_line(items: list[Item], check_name: str, facts: MailFacts, now: datetime) -> str:
    level = _area_level(items, check_name)
    notes = [item.area_note for item in items if item.check == check_name and item.level is Level.NOTE]
    detail = f" – {notes[0]}" if level is Level.NOTE else ""
    if check_name == "backup" and level is Level.OK and facts.last_backup:
        detail = f", last backup {_when(facts.last_backup, now)}"
    return f"{AREA_LABELS[check_name]}: {level.label}{detail}"


def notification_body(current: frozenset[str], report_file: str) -> str:
    """The sentences of the actions without their steps, and where the report is."""
    sentences = _capped([item.sentence for item in _items(current) if item.level is Level.ACTION])
    return "\n".join([*sentences, f"Everything in detail: {report_file}"])


def mail_body(current: frozenset[str], previous: frozenset[str] | None, report_file: str, now: datetime, facts: MailFacts) -> str:
    """The actions with one step each, what is no longer an action, and one line per area; no number, no secret, no home file."""
    items = _items(current, facts.readers)
    sections = []
    if actions := _action_lines(current, previous):
        sections.append("Action needed\n\n" + "\n\n".join(actions))
    if gone := _gone_lines(current, previous):
        sections.append("Done\n\n" + "\n".join(gone))
    area_lines = "\n".join(_area_line(items, name, facts, now) for name, _ in AREAS)
    sections.append(f"How the PC stands ({now:%Y-%m-%d %H:%M})\n\n{area_lines}")
    hint = "Notes are not urgent.\n" if any(item.level is Level.NOTE for item in items) else ""
    sections.append(f"{hint}Everything in detail: {report_file}")
    return "\n\n".join(sections) + "\n"


MAIL_FAILED = "mail failed: msmtp could not deliver via {host}:{port}; the next run reports again\n"
MAIL_ACCOUNT_INVALID = "mail not sent: {problem}; the next run reports again\n"
GRAPHICAL_SESSION_PROBE = ["systemctl", "--user", "is-active", "--quiet", "graphical-session.target"]


def _mail_delivered(ctx: CheckContext, subject: str, body: str) -> bool | None:
    """None while mail is not set up; False (after one stderr line) when the account is invalid or msmtp did not deliver."""
    try:
        account = mail.load_account(ctx.layout)
    except mail.AccountInvalid as error:
        sys.stderr.write(MAIL_ACCOUNT_INVALID.format(problem=printable(str(error))))
        return False
    if account is None:
        return None
    delivered = ctx.run(mail.sendmail_command(account, ctx.layout.secrets_dir, mail.compose(account, subject, body))) is not None
    if not delivered:
        sys.stderr.write(MAIL_FAILED.format(host=printable(str(account.host)), port=account.port))
    return delivered


def _desktop_delivered(ctx: CheckContext, summary: str, body: str) -> bool | None:
    """None without a graphical session; False when the notification was not delivered."""
    if ctx.run(GRAPHICAL_SESSION_PROBE) is None:
        return None
    return _notify(ctx.run, summary, body, ctx.layout.check_report_file)


def _mail_facts(ctx: CheckContext) -> MailFacts:
    """A manifest that cannot be read leaves the app names out; the secrets check reports that failure itself.

    `read_by` is free text, so only a reader that is a bare app or service name reaches the mail (no file, path or secret name).
    """
    try:
        manifest = secrets_view.load_manifest(secrets_view.MANIFEST_PATH)
    except secrets_view.ManifestError:
        manifest = ()
    readers = {entry.name: ", ".join(reader for reader in entry.read_by if APP_NAME.fullmatch(reader)) for entry in manifest}
    return MailFacts(readers, backup_check.last_successful_backup(ctx.layout.home))


class Delivery(StrEnum):
    """What the run says happened to the news."""

    MAIL_SENT = "mail sent"
    NEWS_SENT = "news sent"
    MAIL_FAILED = "mail failed, retries next run"
    NO_MAIL = "no mail set up"
    POPUP_FAILED = "popup failed, retries next run"
    NOTHING_NEW = "nothing new, no mail"
    NOTIFICATIONS_OFF = "notifications off"


def delivery_glyph(delivery: Delivery) -> Glyph:
    match delivery:
        case Delivery.MAIL_FAILED | Delivery.POPUP_FAILED:
            return Glyph.NEEDS_YOU
        case _:
            return Glyph.DONE


@dataclass(frozen=True)
class NewsOutcome:
    delivery: Delivery
    settled: bool
    """Whether the run counts as having told the operator, so the remembered findings may advance."""
    told: bool
    """Whether the news reached the operator once: the mail was delivered, or with no mail set up the popup was delivered. A failed popup beside a delivered mail does not make a caller resend the mail."""


def _delivery_of(desktop: bool | None, mail_outcome: bool | None) -> Delivery:
    if mail_outcome is not None:
        return Delivery.MAIL_SENT if mail_outcome else Delivery.MAIL_FAILED
    if desktop is False:
        return Delivery.POPUP_FAILED
    return Delivery.NEWS_SENT if desktop else Delivery.NO_MAIL


def _news_delivered(ctx: CheckContext, current: frozenset[str], previous: frozenset[str] | None, facts: MailFacts, *, mail_settles: bool) -> NewsOutcome:
    """Every set-up channel is attempted; the news counts as delivered when at least one is set up and all of those delivered.

    With `mail_settles`, a delivered mail ends the news, so a failed popup beside it is not tried again.
    """
    home = ctx.layout.home
    report_file = f"~/{ctx.layout.check_report_file.relative_to(home)}"
    summary = title(current)
    desktop = _desktop_delivered(ctx, summary, notification_body(current, report_file))
    mail_outcome = _mail_delivered(ctx, summary, mail_body(current, previous, report_file, ctx.now, facts))
    set_up = [outcome for outcome in (desktop, mail_outcome) if outcome is not None]
    settled = bool(set_up) and all(set_up)
    told = mail_outcome if mail_outcome is not None else desktop is True
    if desktop is False:
        retried = not (told if mail_settles else settled)
        sys.stderr.write(printable(NOTIFY_FAILED if retried else NOTIFY_FAILED_NOT_RETRIED) + "\n")
    return NewsOutcome(_delivery_of(desktop, mail_outcome), settled, told)


def _news_outcome(ctx: CheckContext, current: frozenset[str], previous: frozenset[str] | None, facts: MailFacts, *, mail_settles: bool = False) -> NewsOutcome:
    if not ctx.settings.notify:
        return NewsOutcome(Delivery.NOTIFICATIONS_OFF, True, True)
    if not _is_news(current, previous):
        return NewsOutcome(Delivery.NOTHING_NEW, True, True)
    return _news_delivered(ctx, current, previous, facts, mail_settles=mail_settles)


OPEN_REPORT_ACTION = "open=Open report"
# Runs inside the detached unit. A printed notification ID above 0 proves delivery (0 is what a failed show prints),
# so only then is the unit ready and systemd-run succeeds; afterwards the click is awaited and opens the report, a dismissal ends quietly.
# notify-send holds its ID in a block buffer until it exits, which --action delays to the click, so it runs line-buffered.
WAIT_FOR_CLICK_SCRIPT = (
    f'stdbuf -oL notify-send --print-id --action="{OPEN_REPORT_ACTION}" "$1" "$2" | '
    '{ read -r id && [ "$id" -gt 0 ] 2>/dev/null || exit 1; systemd-notify --ready; '
    'read -r action; if [ "$action" = open ]; then exec xdg-open "$3"; fi; }'
)
DETACHED_UNIT_OPTIONS = ["systemd-run", "--user", "--collect", "-p", "Type=notify", "-p", "NotifyAccess=all"]


def notification_command(summary: str, body: str, report_file: Path) -> list[str]:
    """systemd-run returns once the unit reported the notification as delivered; the click is awaited by the unit, never by the check."""
    return [*DETACHED_UNIT_OPTIONS, "sh", "-c", WAIT_FOR_CLICK_SCRIPT, "sh", summary, body, str(report_file)]


def _notify(run: CommandRunner, summary: str, body: str, report_file: Path) -> bool:
    """True once the notification was delivered and its click-waiting unit runs detached."""
    return run(notification_command(summary, body, report_file)) is not None


A_CHECK_BROKE_EXIT = 3


def _manifest_error(failed: list[CheckResult]) -> secrets_view.ManifestError | None:
    """An invalid manifest keeps its own exit code 2, whatever else broke."""
    manifest_errors = [result.error for result in failed if isinstance(result.error, secrets_view.ManifestError)]
    return manifest_errors[0] if len(manifest_errors) == len(failed) else None


def _write_verdict(items: list[Item], area_count: int, outcome: NewsOutcome, report_file: str) -> None:
    levels = [item.level for item in items]
    action = next((item for item in items if item.level is Level.ACTION), None)
    if not items:
        shown = () if outcome.delivery is Delivery.NOTHING_NEW else (outcome.delivery,)
        write_verdict(Verdict(Glyph.DONE, "all well", ((area_count, AreaChecked.AREA),), details=shown))
        return
    counts = ((levels.count(Level.ACTION), Finding.ACTION), (levels.count(Level.NOTE), Finding.NOTE))
    write_verdict(
        Verdict(
            LEVEL_GLYPHS[max(levels)],
            "",
            counts,
            details=(outcome.delivery, f"report {report_file}"),
            next_step=_terminal_step(action.next_step) if action else "",
        )
    )


def deliver_news(ctx: CheckContext, current: frozenset[str], previous: frozenset[str] | None) -> NewsOutcome:
    """The news of `current` against `previous` through every set-up channel, with a delivered mail ending the news; the caller remembers `current` when the outcome is told."""
    return _news_outcome(ctx, current, previous, _mail_facts(ctx), mail_settles=True)


def check(ctx: CheckContext) -> int:
    layout = ctx.layout
    results = run_areas(ctx, CHECK_NAMES)
    report = render_report(results, ctx.now)
    write_state_file(layout.home, layout.check_report_file, report)
    previous = previous_identities(layout)
    current = remembered_identities(results, previous)
    facts = _mail_facts(ctx)
    outcome = _news_outcome(ctx, current, previous, facts)
    # The remembered set stays at the last delivered one, so the next run sends this news again.
    if outcome.settled:
        remember(layout, current)
    failed = [result for result in results if result.error]
    items = _items(current, facts.readers)
    broken = {result.name for result in failed}
    for summary in area_summaries(items):
        write_row(_area_row(summary, summary.check in broken))
    if failed:
        if manifest_error := _manifest_error(failed):
            raise manifest_error
        write_error(f"{len(failed)} of {len(AREAS)} areas could not check · {outcome.delivery}", _terminal_step(BROKEN_CHECK_REPORT.next_step))
        return A_CHECK_BROKE_EXIT
    _write_verdict(items, len(AREAS), outcome, f"~/{layout.check_report_file.relative_to(layout.home)}")
    return 1 if current else 0
