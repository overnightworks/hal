"""The finished run as rows: each step's typed result is mapped to the rows `hal.output` prints.
Nothing here parses a string or prints; `plan_rows` is the planned run's twin."""

from enum import StrEnum

from hal.output import Glyph, Noun, Row, counted, format_duration, printable
from hal.output.command import Verb, command
from hal.stack import realm as realm_lines
from hal.stack.apps import (
    AppFailed,
    AppHeldOff,
    AppKind,
    AppOn,
    AppPlan,
    AppResult,
    AppSwitchedOff,
    OffPlan,
)
from hal.stack.plan_rows import ChangeNoun, PlanEvent
from hal.stack.realm import Kind
from hal.stack.realm.reconcile import (
    REALM_UNIT,
    Leftovers,
    NotRecorded,
    RealmApplied,
    RealmFailed,
    RealmSkipped,
    Stage,
    StepResult,
)

# restic's short ID, which `hal restore --snapshot` takes as a prefix (`hal.backup.runner`'s
# MIN_SNAPSHOT_PREFIX); `hal.stack` may not import `hal.backup`, so the length is repeated.
SNAPSHOT_SHORT_ID = 8
_SEPARATOR = " · "
_ONLY_IN_KEYCLOAK = "only in Keycloak: "
RESTORE_GUIDE = 'docs/backup.md "Restore Keycloak"'
_STATE_OF_THE_REALM = {
    Stage.BEFORE: "nothing applied",
    Stage.APPLYING: "may be partly applied",
    Stage.APPLIED: "applied, not observed",
}


class ResultEvent(StrEnum):
    REALM_APPLIED = "realm applied"
    REALM_FAILED = "realm failed"
    WAITING = "waiting"
    APP_SWITCHED_ON = "switched on"
    APP_STARTED_AGAIN = "started again"
    APP_UPDATED = "updated"
    APP_FAILED = "failed"
    APP_SWITCHED_OFF = "switched off"
    APP_SWITCH_OFF_FAILED = "switch off failed"
    APP_HELD_OFF = "switched off meanwhile"


_APP_ON_EVENT = {
    AppKind.ON: ResultEvent.APP_SWITCHED_ON,
    AppKind.START_AGAIN: ResultEvent.APP_STARTED_AGAIN,
    AppKind.UPDATE: ResultEvent.APP_UPDATED,
}


class UnreadNoun(Noun):
    KIND = "kind not read"


class UnobservedNoun(Noun):
    REALM = "realm not observed"


def result_rows(result: StepResult) -> tuple[Row, ...]:
    """The rows of one step's result: none when the plan was settled."""
    return () if result is None else (_row(result),)


def _row(result: RealmSkipped | RealmFailed | RealmApplied) -> Row:
    match result:
        case RealmSkipped(reason):
            return Row(Glyph.NEEDS_YOU, REALM_UNIT, PlanEvent.REALM_SKIPPED, reason)
        case RealmFailed():
            return _failed_row(result)
        case RealmApplied():
            return _applied_row(result)


def partial_error(result: StepResult) -> str | None:
    """What the run's `error: partial, ...` line says of this step, None when it did not end
    partial."""
    match result:
        case RealmSkipped():
            return f"{REALM_UNIT} {PlanEvent.REALM_SKIPPED}"
        case RealmFailed():
            return f"{REALM_UNIT} {ResultEvent.REALM_FAILED}"
        case RealmApplied(leftovers=NotRecorded(error)):
            return (
                "realm: applied and observed, but the record could not be written "
                f"({error}); the next run repeats the step"
            )
        case _:
            return None


def app_row(result: AppResult) -> Row:
    """The row of one app's run; every cause is escaped."""
    match result:
        case AppOn(plan, seconds):
            facts = (plan.release.tag, "running", format_duration(seconds))
            event = _APP_ON_EVENT[plan.kind]
            return Row(Glyph.DONE, plan.app.key, event, _SEPARATOR.join(facts))
        case AppSwitchedOff(off):
            key = off.app.key
            return Row(
                Glyph.DONE, key, ResultEvent.APP_SWITCHED_OFF, f"volumes and ~/srv/{key} kept"
            )
        case AppFailed(subject, cause):
            return Row(Glyph.FAILED, subject.app.key, _failed_event(subject), printable(cause))
        case AppHeldOff(plan, cause):
            return Row(Glyph.FAILED, plan.app.key, ResultEvent.APP_HELD_OFF, printable(cause))


def app_partial(result: AppFailed | AppHeldOff) -> tuple[str, str]:
    """The run's `partial, ...` text for a failed app and the command that ends it: a stop that
    won is ended only by start."""
    match result:
        case AppFailed(subject):
            return f"partial, {subject.app.key} {_failed_event(subject)}", command(Verb.APPLY)
        case AppHeldOff(plan):
            key = plan.app.key
            return f"partial, {key} {ResultEvent.APP_HELD_OFF}", command(Verb.START, key)


def _failed_event(subject: AppPlan | OffPlan) -> ResultEvent:
    if isinstance(subject, OffPlan):
        return ResultEvent.APP_SWITCH_OFF_FAILED
    return ResultEvent.APP_FAILED


def waiting_row(grace_seconds: float) -> Row:
    """The line said while a stopped `hal` is given its grace to clean up."""
    fact = f"up to {format_duration(grace_seconds)} for hal to clean up"
    return Row(Glyph.ANNOUNCE, REALM_UNIT, ResultEvent.WAITING, fact)


def _failed_row(failed: RealmFailed) -> Row:
    fact = f"{printable(failed.cause)}{_SEPARATOR}{_STATE_OF_THE_REALM[failed.stage]}"
    details: tuple[str, ...] = ()
    if failed.snapshot:
        short = printable(failed.snapshot[:SNAPSHOT_SHORT_ID])
        proof = "proven" if failed.proven else "unproven"
        details = (f"pre-apply snapshot {short}{_SEPARATOR}{proof}",)
    if failed.stage is not Stage.BEFORE:
        details += (f"way back: {RESTORE_GUIDE}{_SEPARATOR}the next apply repeats the step",)
    return Row(Glyph.FAILED, REALM_UNIT, ResultEvent.REALM_FAILED, fact, details=details)


def _applied_row(applied: RealmApplied) -> Row:
    short = applied.snapshot[:SNAPSHOT_SHORT_ID]
    changes = counted(len(applied.changes), ChangeNoun.CHANGE) if applied.changes else "no changes"
    facts = (changes, f"snapshot {short} proven", format_duration(applied.seconds))
    details = (
        *(_change_detail(change, short) for change in applied.changes),
        *(
            _leftovers_details(applied.leftovers)
            if isinstance(applied.leftovers, Leftovers)
            else ()
        ),
    )
    return Row(Glyph.DONE, REALM_UNIT, ResultEvent.REALM_APPLIED, _SEPARATOR.join(facts),
               details=details)  # fmt: skip


def _change_detail(change: realm_lines.Change, short_snapshot: str) -> str:
    """A removal is config-cli resetting a console change to the file."""
    shown = realm_lines.line(change)
    if change.kind is Kind.REMOVAL:
        shown += f": reset to the file, pre-apply snapshot {short_snapshot}"
    return shown


def _leftovers_details(leftovers: Leftovers) -> tuple[str, ...]:
    if not leftovers.files_read:
        return (f"{_ONLY_IN_KEYCLOAK}not listed, the realm files could not be read",)
    found = tuple(
        f"{_ONLY_IN_KEYCLOAK}{printable(item.realm)} {item.kind} {printable(item.identity)}"
        for item in leftovers.found
    )
    absent = tuple(
        f"{_ONLY_IN_KEYCLOAK}{printable(realm)} not listed, it was not observed"
        for realm in leftovers.absent
    )
    seen = f"{len(leftovers.found)} found" if leftovers.found else "nothing"
    unobserved = (counted(len(leftovers.absent), UnobservedNoun.REALM),) if leftovers.absent else ()
    unread = counted(len(leftovers.unread), UnreadNoun.KIND)
    summary = f"{_ONLY_IN_KEYCLOAK}{_SEPARATOR.join((seen, *unobserved, unread))}"
    return (*found, *absent, summary)
