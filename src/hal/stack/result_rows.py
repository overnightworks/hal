"""The finished run as rows: each step's typed result is mapped to the rows `hal.output` prints.
Nothing here parses a string or prints; `plan_rows` is the planned run's twin."""

from collections import Counter
from enum import StrEnum

from hal.output import Glyph, Noun, Row, counted, format_duration, printable
from hal.output.command import Verb, command
from hal.stack import realm as realm_lines
from hal.stack.appkit_step import AppkitPlan
from hal.stack.apps import (
    AppFailed,
    AppFailure,
    AppHeldOff,
    AppKind,
    AppOn,
    AppPlan,
    AppResult,
    AppSwitchedOff,
    OffPlan,
)
from hal.stack.barrier import BarriersUnproven
from hal.stack.legal_step import LEGAL_UNIT, LegalPlan, PageChange
from hal.stack.litellm_keys import (
    ADMIN_BUDGET_ID,
    LITELLM_SERVICE,
    AdminState,
    Change,
    KeysDone,
    KeysFailed,
    KeysResult,
    KeysSkipped,
    RowChange,
    StepChange,
)
from hal.stack.plan_rows import (
    ChangeNoun,
    KeysEvent,
    PlanEvent,
    RowNoun,
    admin_rows,
    appkit_row,
    change_event,
    customer_rows,
    key_change_row,
    name_taken_row,
    shown_subject,
)
from hal.stack.pre_apply import SNAPSHOT_SHORT_ID
from hal.stack.realm import Kind
from hal.stack.realm.reconcile import (
    REALM_UNIT,
    Leftovers,
    MembersNotRead,
    NotRecorded,
    RealmApplied,
    RealmFailed,
    RealmSkipped,
    Stage,
    StepResult,
)
from hal.stack.service_recreate import Recreated, short_snapshot
from hal.stack.switches import describe_since
from hal.stack.unit_plans import (
    Action,
    CoreFailure,
    Interrupted,
    NotOff,
    NotWritten,
    SeenDown,
    StepFailed,
    StoppedMeanwhile,
    SwitchedOffMeanwhile,
    SwitchFailure,
    UnitPlan,
)

type RowFailure = SwitchFailure | StoppedMeanwhile

_SEPARATOR = " · "
_PARTIAL_STATE = "its state may be partial"
_LOG_LINES = 50
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
    SWITCHED_ON = "switched on"
    APP_STARTED_AGAIN = "started again"
    APP_UPDATED = "updated"
    FAILED = "failed"
    SWITCHED_OFF = "switched off"
    APP_SWITCH_OFF_FAILED = "switch off failed"
    APP_HELD_OFF = "switched off meanwhile"
    RECREATED = "recreated"
    NOT_RUNNING = "not running"
    NOT_OFF = "not off"
    STOPPED_MEANWHILE = "stopped meanwhile"
    NOT_PROVEN = "not proven"
    FILES_WRITTEN = "files written"
    FILES_REMOVED = "files removed"
    PAGES_WRITTEN = "pages written"
    RECORD_WRITTEN = "record written"
    NOT_WRITTEN = "not written"
    NOT_MADE = "not made"
    KEYS_SKIPPED = "keys skipped"
    KEYS_FAILED = "keys failed"
    INTERRUPTED = "interrupted"


_APP_ON_EVENT = {
    AppKind.ON: ResultEvent.SWITCHED_ON,
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


def keys_rows(result: KeysResult) -> tuple[Row, ...]:
    """The key step's rows: each change done, the failed one with its cause and each one not made
    after it, then each app whose name another key holds and why the admin rows wait; row changes
    as counts per budget."""
    rows: list[Row] = []
    match result:
        case KeysSkipped(reason):
            rows.append(
                Row(Glyph.NEEDS_YOU, LITELLM_SERVICE, ResultEvent.KEYS_SKIPPED, printable(reason))
            )
        case KeysDone(done, name_taken, admin):
            rows += [*_done_rows(done), *map(name_taken_row, name_taken), *admin_rows(admin)]
        case KeysFailed(done, failed, cause, not_made, name_taken, admin):
            rows += [
                *_done_rows(done),
                _failed_keys_row(failed, cause),
                *_not_made_rows(not_made),
                *map(name_taken_row, name_taken),
                *admin_rows(admin),
            ]
    return tuple(rows)


def keys_partial(result: KeysResult) -> tuple[str, str | None] | None:
    """The run's `partial, ...` text for the key step and the command that ends it, None when it
    did not end partial; a taken name no hal command resolves, members not read the next apply."""
    match result:
        case KeysSkipped():
            return f"partial, {LITELLM_SERVICE} {ResultEvent.KEYS_SKIPPED}", command(Verb.APPLY)
        case KeysDone(name_taken=name_taken, admin=admin) if unsettled := _unsettled(
            name_taken, admin
        ):
            next_step = command(Verb.APPLY) if isinstance(admin, MembersNotRead) else None
            return f"partial, {'; '.join(unsettled)}", next_step
        case KeysFailed(failed=failed, name_taken=name_taken, admin=admin):
            what = (
                f"{LITELLM_SERVICE} {ResultEvent.KEYS_FAILED}"
                if failed is None
                else f"{shown_subject(failed)} {change_event(failed)} failed"
            )
            text = "; ".join((what, *_unsettled(name_taken, admin)))
            return f"partial, {text}", command(Verb.APPLY)
        case _:
            return None


def _unsettled(name_taken: tuple[str, ...], admin: AdminState) -> tuple[str, ...]:
    """What the step left unsettled beside its writes: taken names, members not read."""
    taken = (f"{', '.join(name_taken)} {KeysEvent.NAME_TAKEN}",) if name_taken else ()
    not_read = isinstance(admin, MembersNotRead)
    return (*taken, *((f"{ADMIN_BUDGET_ID} members not read from Keycloak",) if not_read else ()))


def _done_rows(done: tuple[StepChange, ...]) -> tuple[Row, ...]:
    changes = (change for change in done if isinstance(change, Change))
    return (
        *(key_change_row(change, Glyph.DONE) for change in changes),
        *customer_rows(done, Glyph.DONE),
    )


def _failed_keys_row(failed: StepChange | None, cause: str) -> Row:
    if failed is None:
        return Row(Glyph.FAILED, LITELLM_SERVICE, ResultEvent.KEYS_FAILED, printable(cause))
    return Row(Glyph.FAILED, shown_subject(failed), change_event(failed), printable(cause))


def _not_made_rows(not_made: tuple[StepChange, ...]) -> tuple[Row, ...]:
    """Each change not made; the row changes counted by budget."""
    rows = [
        Row(Glyph.UNCHANGED, change.subject, ResultEvent.NOT_MADE, str(change_event(change)))
        for change in not_made
        if isinstance(change, Change)
    ]
    rows_by_budget = Counter(change.budget for change in not_made if isinstance(change, RowChange))
    rows += [
        Row(Glyph.UNCHANGED, budget, ResultEvent.NOT_MADE, counted(count, RowNoun.CUSTOMER_ROW))
        for budget, count in rows_by_budget.items()
    ]
    return tuple(rows)


def app_row(result: AppResult) -> Row:
    """The row of one app's run; every cause is escaped."""
    glyph = Glyph.FAILED if isinstance(result, AppFailure) else Glyph.DONE
    match result:
        case AppOn(plan, seconds):
            facts = (plan.release.tag, "running", format_duration(seconds))
            event = _APP_ON_EVENT[plan.kind]
            return Row(glyph, plan.app.key, event, _SEPARATOR.join(facts))
        case AppSwitchedOff(off):
            key = off.app.key
            return Row(glyph, key, ResultEvent.SWITCHED_OFF, f"volumes and ~/srv/{key} kept")
        case AppFailed(subject, cause):
            return Row(glyph, subject.app.key, _failed_event(subject), printable(cause))
        case AppHeldOff(plan, cause):
            return Row(glyph, plan.app.key, ResultEvent.APP_HELD_OFF, printable(cause))


def app_partial(result: AppFailure) -> tuple[str, str]:
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
    return ResultEvent.FAILED


def unit_row(plan: UnitPlan, snapshot: str | None) -> Row:
    """A unit switched on and observed up, or switched off with the volumes an off never touches;
    a switch-on that proved a pre-apply snapshot names it dim under the row.

    A switched-on unit is `up` once observed because compose up waits for its one-shots, which
    share the profile of the service that waits for them."""
    if plan.action is Action.OFF:
        fact = f"volumes {', '.join(plan.volumes)} kept" if plan.volumes else ""
        return Row(Glyph.DONE, plan.unit.key, ResultEvent.SWITCHED_OFF, fact)
    details = (_snapshot_detail(snapshot, "proven"),) if snapshot else ()
    fact = _SEPARATOR.join((", ".join(plan.services), "up"))
    return Row(Glyph.DONE, plan.unit.key, ResultEvent.SWITCHED_ON, fact, details=details)


def _snapshot_detail(snapshot: str, proof: str) -> str:
    return f"pre-apply snapshot {short_snapshot(snapshot)}{_SEPARATOR}{proof}"


def recreated_row(recreated: Recreated) -> Row:
    """A service recreated and observed running, with the time it took; a core service whose
    barriers were proven says so, and a database unit's first recreate names the snapshot it
    proved before."""
    facts = (
        *(("barriers proven",) if recreated.barriers_proven else ()),
        *((f"snapshot {short_snapshot(recreated.snapshot)} proven",) if recreated.snapshot else ()),
        format_duration(recreated.seconds),
    )
    return Row(Glyph.DONE, recreated.service, ResultEvent.RECREATED, _SEPARATOR.join(facts))


def unproven_row(failure: BarriersUnproven) -> Row:
    """The barriers that are not proven after a core recreate: each key, its cause dim under the
    row, and the way on last."""
    keys = ", ".join(printable(proof.unit) for proof in failure.proofs)
    causes = tuple(
        f"{printable(proof.unit)}: {printable(proof.failure)}" for proof in failure.proofs
    )
    then = (
        f"then: {command(Verb.APPLY)} repeats the proof{_SEPARATOR}"
        f"{command(Verb.ONLINE)} reopens only once every barrier is proven"
    )
    return Row(
        Glyph.FAILED,
        "barriers",
        ResultEvent.NOT_PROVEN,
        f"{keys}{_SEPARATOR}may be reachable through Traefik",
        details=(*causes, then),
    )


def unproven_partial() -> tuple[str, str]:
    """The run's `partial, ...` text for unproven barriers and the command that closes the
    tunnel."""
    return f"partial, barriers {ResultEvent.NOT_PROVEN}{_SEPARATOR}no unit switched", command(
        Verb.OFFLINE
    )


def appkit_rows(plan: AppkitPlan) -> tuple[Row, ...]:
    """The rows of a finished appkit write, none when nothing was planned: a write ends with the
    whole plan done or with a failure, so the plan is what was written."""
    return appkit_row(
        plan,
        (Glyph.DONE, ResultEvent.FILES_WRITTEN),
        (Glyph.DONE, ResultEvent.FILES_REMOVED),
        "removed",
    )


def legal_rows(plan: LegalPlan) -> tuple[Row, ...]:
    """The rows of a finished legal write: the pages whose bytes were written, then the pages that
    gained only their record."""
    written = [page for page, change in plan.changed.items() if change is not PageChange.UNRECORDED]
    recorded = [page for page, change in plan.changed.items() if change is PageChange.UNRECORDED]
    rows = []
    if written:
        rows.append(Row(Glyph.DONE, LEGAL_UNIT, ResultEvent.PAGES_WRITTEN, ", ".join(written)))
    if recorded:
        rows.append(Row(Glyph.DONE, LEGAL_UNIT, ResultEvent.RECORD_WRITTEN, ", ".join(recorded)))
    return tuple(rows)


def not_written_row(failure: NotWritten) -> Row:
    """A step that could not write; the path and the reason are escaped."""
    return Row(Glyph.FAILED, failure.subject, ResultEvent.NOT_WRITTEN, printable(failure.fact))


def not_written_partial(failure: NotWritten) -> tuple[str, str]:
    """The run's `partial, ...` text for a failed write and the command that ends it."""
    text = f"partial, {failure.subject} {ResultEvent.NOT_WRITTEN}{_SEPARATOR}no unit switched"
    return text, command(Verb.APPLY)


def stopped_rows(failure: NotWritten | CoreFailure) -> tuple[Row, ...]:
    """The ✗ rows of a run stopped before any unit was switched, one per service seen down."""
    match failure:
        case NotWritten():
            return (not_written_row(failure),)
        case BarriersUnproven():
            return (unproven_row(failure),)
        case _:
            return failure_rows(failure)


def failure_rows(failure: RowFailure) -> tuple[Row, ...]:
    """The ✗ rows of a failed recreate or switch, one per service seen down; a cause is
    escaped."""
    match failure:
        case SeenDown(services, watch_seconds, recreated, way_back):
            of = f"the {recreated} recreate" if recreated else "the start"
            seen = f"seen down within {format_duration(watch_seconds)} of {of}"
            return tuple(
                Row(
                    Glyph.FAILED,
                    down.service,
                    ResultEvent.NOT_RUNNING,
                    seen,
                    details=_way(way_back),
                )
                for down in services
            )
        case StoppedMeanwhile(service):
            return (Row(Glyph.FAILED, service, ResultEvent.STOPPED_MEANWHILE, "not started"),)
        case SwitchedOffMeanwhile(unit, since, service, way_back, left):
            fact = f"since {describe_since(since)}{_SEPARATOR}{service} not {left}"
            return (
                Row(Glyph.FAILED, unit, ResultEvent.APP_HELD_OFF, fact, details=_way(way_back)),
            )
        case NotOff(unit, way_back):
            fact = "a container of it remains"
            return (Row(Glyph.FAILED, unit, ResultEvent.NOT_OFF, fact, details=_way(way_back)),)
        case StepFailed(subject, step, cause, way_back):
            fact = f"could not {step}{_SEPARATOR}{printable(cause)}"
            return (Row(Glyph.FAILED, subject, ResultEvent.FAILED, fact, details=_way(way_back)),)


def interrupted_row(interrupted: Interrupted) -> Row:
    """The ✗ row of a Ctrl-C: each note, then the snapshots' way back, as a detail line."""
    facts = (printable(interrupted.step), _PARTIAL_STATE) if interrupted.step else (_PARTIAL_STATE,)
    return Row(
        Glyph.FAILED,
        interrupted.subject,
        ResultEvent.INTERRUPTED,
        _SEPARATOR.join(facts),
        details=(*(printable(note) for note in interrupted.notes), *_way(interrupted.way_back)),
    )


def interrupted_error(interrupted: Interrupted) -> tuple[str, str]:
    """The run's `error: ...` text for `interrupted_row` and the command that ends it."""
    return f"{ResultEvent.INTERRUPTED} at {interrupted.subject}", command(Verb.APPLY)


def stopped_partial(failure: NotWritten | CoreFailure) -> tuple[str, str]:
    """The run's `partial, ...` text for the first row of `stopped_rows` and the command that
    ends it."""
    match failure:
        case NotWritten():
            return not_written_partial(failure)
        case BarriersUnproven():
            return unproven_partial()
        case _:
            text, next_step = switch_partial(failure)
            return f"{text}{_SEPARATOR}no unit switched", next_step


def switch_partial(failure: RowFailure) -> tuple[str, str]:
    """The `partial, ...` text for the first row of `failure_rows` and the command that ends it:
    a stop that won is ended only by start, a container seen down is read in its log."""
    match failure:
        case SeenDown(services):
            service, container = services[0]
            next_step = (
                f"docker logs --tail {_LOG_LINES} {container}" if container else command(Verb.APPLY)
            )
            return f"partial, {service} {ResultEvent.NOT_RUNNING}", next_step
        case StoppedMeanwhile(service):
            return f"partial, {service} {ResultEvent.STOPPED_MEANWHILE}", command(Verb.APPLY)
        case SwitchedOffMeanwhile(unit):
            return f"partial, {unit} {ResultEvent.APP_HELD_OFF}", command(Verb.START, unit)
        case NotOff(unit):
            return f"partial, {unit} {ResultEvent.NOT_OFF}", command(Verb.APPLY)
        case StepFailed(subject):
            return f"partial, {subject} {ResultEvent.FAILED}", command(Verb.APPLY)


def _way(way_back: str | None) -> tuple[str, ...]:
    return (way_back,) if way_back else ()


def waiting_row(grace_seconds: float) -> Row:
    """The line said while a stopped `hal` is given its grace to clean up."""
    fact = f"up to {format_duration(grace_seconds)} for hal to clean up"
    return Row(Glyph.ANNOUNCE, REALM_UNIT, ResultEvent.WAITING, fact)


def _failed_row(failed: RealmFailed) -> Row:
    fact = f"{printable(failed.cause)}{_SEPARATOR}{_STATE_OF_THE_REALM[failed.stage]}"
    details: tuple[str, ...] = ()
    if failed.snapshot:
        details = (_snapshot_detail(failed.snapshot, "proven" if failed.proven else "unproven"),)
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
