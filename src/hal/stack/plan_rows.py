"""The planned run as rows: each part of a `Plan` is mapped from its typed fields to the rows
`hal.output` prints, in the order hal works. Nothing here parses a string or prints."""

from collections.abc import Mapping, Sequence
from dataclasses import replace
from enum import StrEnum

from hal.output import Glyph, Group, Noun, Row, TrailingNoun, counted
from hal.output.command import Verb, command
from hal.stack import checkout, core, environment, switches
from hal.stack.appkit_step import APPKIT_UNIT, TARGETS, AppkitPlan
from hal.stack.apps import AppKind, AppPlan, AppsPlan, OffPlan, SkippedNote, StaysStoppedNote
from hal.stack.built_image import ENDS_RUNS, BuiltRecreate
from hal.stack.legal_step import BlockChange, LegalPlan, PageChange
from hal.stack.plan import Plan
from hal.stack.realm.reconcile import REALM_UNIT, RealmAction, RealmPlan
from hal.stack.unit_plans import Action, ImageReference, KeptImage, Recreate, UnitPlan

_SEPARATOR = " · "
_DIGEST_SHOWN = 4
_DEFINITION_CHANGED = "definition changed"
CHECKOUT = "checkout"


class PlanEvent(StrEnum):
    RECREATE = "recreate"
    NOT_STARTED = "not started"
    STARTS_LATER = "starts later"
    SWITCH_ON = "switch on"
    START_AGAIN = "start again"
    UPDATE = "update"
    SWITCH_OFF = "switch off"
    STAYS_STOPPED = "stays stopped"
    TAG_SKIPPED = "tag skipped"
    OLD_IMAGE = "old image"
    REALM_APPLY = "realm apply"
    REALM_HELD = "realm held"
    REALM_LATER = "realm later"
    REALM_SKIPPED = "realm skipped"
    NEW_FILES = "new files"
    OLD_FILES = "old files"


class LegalEvent(TrailingNoun):
    NEW_PAGE = "new page"
    EDITED_PAGE = "edited page"
    NEW_RECORD = "new record"


class CheckoutEvent(StrEnum):
    CURRENT = "current"
    BEHIND = "behind"


class GuardEvent(StrEnum):
    """What a guard of the apply found or did before any plan."""

    LOCAL_CHANGES = "local changes"
    WRITTEN = "written"
    STILL_RUNS = "still runs"


class ChangeNoun(Noun):
    CHANGE = "change"


class FileNoun(Noun):
    FILE = "file"


class PlanGroup(StrEnum):
    CORE = "core"
    UNITS = "units"
    APPS = "apps"


def checkout_row(origin: checkout.Origin) -> Row:
    """The live checkout against origin's `main`: current, or behind by the commits waiting on
    origin."""
    if origin.standing is checkout.Standing.BEHIND:
        return Row(
            Glyph.NEEDS_YOU,
            CHECKOUT,
            CheckoutEvent.BEHIND,
            f"origin/{checkout.MAIN} {origin.short}",
            count=origin.behind,
        )
    return Row(
        Glyph.DONE, CHECKOUT, CheckoutEvent.CURRENT, f"{origin.short} · origin/{checkout.MAIN}"
    )


class CommitNoun(Noun):
    COMMIT = "commit"


def waiting_text(count: int) -> str:
    """`3 commits wait on origin`: the commits origin's `main` has that this checkout lacks."""
    return f"{counted(count, CommitNoun.COMMIT)} {'waits' if count == 1 else 'wait'} on origin"


class Effect(StrEnum):
    """What a file that waits on origin changes, by where it is read; the value is the row's
    subject."""

    CODE = "hal code"
    DIRECTORY_BIND = "directory bind"
    PLANNED = "planned"
    OTHER = "other"


_EFFECT_FACTS = {
    Effect.CODE: "hal's code and dependencies: the next hal command runs them",
    Effect.DIRECTORY_BIND: (
        "under a directory bind: the merge changes them in place, a container that mounts the "
        "directory sees them at once, and whether its service uses them before its next restart "
        "depends on the service"
    ),
    Effect.PLANNED: (
        f"the next `{command(Verb.APPLY)}` plans them; a container that binds such a file alone "
        "keeps the old one until it is recreated"
    ),
    Effect.OTHER: "",
}


class UpdateEvent(StrEnum):
    NOT_CLASSIFIED = "not classified"


def update_rows(
    origin: checkout.Origin,
    commits: Sequence[checkout.Commit],
    by_effect: Mapping[Effect, Sequence[str]] | None,
    reason: str = "",
) -> list[Row]:
    """What `hal update` shows before it asks: the behind row with every waiting commit under it,
    then the changed files by effect; `by_effect` None is one row saying why they are not
    classified. Each line is conditional on the checkout's configuration, never on a container."""
    behind = replace(
        checkout_row(origin),
        details=tuple(f"{commit.short} {commit.subject}" for commit in commits),
    )
    if by_effect is None:
        return [behind, Row(Glyph.NEEDS_YOU, "files", UpdateEvent.NOT_CLASSIFIED, reason)]
    return [
        behind,
        *(
            Row(
                Glyph.CHANGE,
                effect.value,
                FileNoun.FILE,
                _EFFECT_FACTS[effect],
                count=len(by_effect[effect]),
                details=tuple(by_effect[effect]),
            )
            for effect in Effect
            if by_effect.get(effect)
        ),
    ]


def local_changes_row(paths: tuple[str, ...]) -> Row:
    """The live checkout refused for local changes, each changed path under it."""
    return Row(
        Glyph.FAILED, CHECKOUT, GuardEvent.LOCAL_CHANGES, counted(len(paths), FileNoun.FILE),
        details=paths,
    )  # fmt: skip


def environment_row(written: environment.Settings) -> Row:
    """The `.env` the guard wrote, with the values it derived."""
    facts = _SEPARATOR.join(f"{key}={value}" for key, value in written.assignments)
    return Row(Glyph.DONE, environment.ENVIRONMENT_FILE, GuardEvent.WRITTEN, facts)


def still_runs_row(key: str, fact: str) -> Row:
    """A unit or app that is switched off and whose containers still run."""
    return Row(Glyph.FAILED, key, GuardEvent.STILL_RUNS, fact)


_CHANGING_GLYPHS = frozenset({Glyph.ADD, Glyph.CHANGE, Glyph.REMOVE})


def changes_in(plan: Plan) -> int:
    """The number of printed `+ ~ -` rows: what the plan's yes counts."""
    return sum(row.glyph in _CHANGING_GLYPHS for group in plan_groups(plan) for row in group.rows)


def plan_groups(plan: Plan) -> tuple[Group, ...]:
    return (
        Group(None, (*_appkit_rows(plan.appkit), *_legal_rows(plan.legal))),
        Group(PlanGroup.CORE, _core_rows(plan)),
        Group(PlanGroup.UNITS, _unit_rows(plan)),
        Group(PlanGroup.APPS, _app_rows(plan.app_plans)),
    )


def _appkit_rows(plan: AppkitPlan) -> tuple[Row, ...]:
    old_names = ", ".join(sorted({path.name for path in plan.stale}))
    rows = []
    if plan.changed:
        facts = [plan.version]
        labels = plan.changed_labels
        if len(labels) < len(TARGETS):
            facts.append(f"only {', '.join(labels)}")
        if old_names:
            facts.append(f"removes {old_names}")
        rows.append(Row(Glyph.ADD, APPKIT_UNIT, PlanEvent.NEW_FILES, _SEPARATOR.join(facts)))
    elif old_names:
        rows.append(Row(Glyph.REMOVE, APPKIT_UNIT, PlanEvent.OLD_FILES, old_names))
    return tuple(rows)


_PAGE_ROWS = (
    (PageChange.NEW, Glyph.ADD, LegalEvent.NEW_PAGE),
    (PageChange.CHANGED, Glyph.CHANGE, LegalEvent.EDITED_PAGE),
    (PageChange.UNRECORDED, Glyph.CHANGE, LegalEvent.NEW_RECORD),
)


def _legal_rows(plan: LegalPlan) -> tuple[Row, ...]:
    rows = []
    for kind, glyph, event in _PAGE_ROWS:
        pages = [page for page, change in plan.changed.items() if change is kind]
        if pages:
            details = (
                tuple(
                    _block_change_line(change)
                    for page in pages
                    for change in plan.changed_blocks[page]
                )
                if kind is PageChange.CHANGED
                else ()
            )
            rows.append(Row(glyph, "legal", event, ", ".join(pages), len(pages), details))
    return tuple(rows)


def _block_change_line(change: BlockChange) -> str:
    anchor = f"#{change.anchor}" if change.anchor else ""
    return f"{change.path}{anchor} {change.change}"


def _core_rows(plan: Plan) -> tuple[Row, ...]:
    return (
        *(_core_plan_row(core_plan) for core_plan in plan.core),
        *(_follower_row(follower) for follower in plan.followers),
    )


def _core_plan_row(plan: core.CorePlan) -> Row:
    facts = [_cause_fact(cause, plan.service) for cause in plan.why]
    if plan.action is core.CoreAction.NOT_STARTED:
        return Row(
            Glyph.UNCHANGED,
            plan.service,
            PlanEvent.NOT_STARTED,
            _SEPARATOR.join((*facts, "not running")),
        )
    return Row(Glyph.CHANGE, plan.service, PlanEvent.RECREATE, _SEPARATOR.join(facts))


def _follower_row(plan: core.FollowerPlan) -> Row:
    facts = [_cause_fact(cause, plan.service) for cause in plan.why]
    match plan.action:
        case core.FollowerAction.HELD:
            facts.append(f"{plan.unit} is {plan.gate}")
            return Row(Glyph.UNCHANGED, plan.service, PlanEvent.NOT_STARTED, _SEPARATOR.join(facts))
        case core.FollowerAction.STARTS_WITH_UNIT:
            facts.append(f"with {plan.unit}")
            return Row(Glyph.CHANGE, plan.service, PlanEvent.STARTS_LATER, _SEPARATOR.join(facts))
        case core.FollowerAction.RECREATE:
            return Row(Glyph.CHANGE, plan.service, PlanEvent.RECREATE, _SEPARATOR.join(facts))


def _cause_fact(cause: core.Cause, service: str) -> str:
    subject = cause.subject
    match cause.kind:
        case core.CauseKind.DEFINITION_CHANGED:
            return _DEFINITION_CHANGED
        case core.CauseKind.FILE_CHANGED:
            return f"{subject} changed"
        case core.CauseKind.FILE_UNRECORDED:
            return f"{subject} has no applied record"
        case core.CauseKind.UNFINISHED:
            return "the last recreate did not finish"
        case core.CauseKind.RECORD_UNTRUSTED:
            return subject
        case core.CauseKind.RECORD_NAMES_OTHERS:
            return f"{core.APPLIED_FILE} names {subject}, which {service} does not mount"
        case core.CauseKind.PULLED_IN:
            return f"{subject} is recreated"


def _unit_rows(plan: Plan) -> tuple[Row, ...]:
    realm_row = _realm_row(plan.realm)
    return (
        *(_built_row(built) for built in plan.built),
        *(_recreate_row(recreate) for recreate in plan.recreates),
        *(_unit_plan_row(unit_plan) for unit_plan in plan.plans),
        *(_old_image_row(image) for image in plan.images),
        *(() if realm_row is None else (realm_row,)),
    )


def _built_row(built: BuiltRecreate) -> Row:
    facts = (
        *(
            f"image {running} \N{RIGHTWARDS ARROW} {built.reference}"
            for running in built.moved_from
        ),
        *((_DEFINITION_CHANGED,) if built.definition_changed else ()),
        *((f"image {built.reference} rebuilt",) if built.rebuilt else ()),
        ENDS_RUNS,
    )
    return Row(Glyph.CHANGE, built.service, PlanEvent.RECREATE, _SEPARATOR.join(facts))


def _recreate_row(recreate: Recreate) -> Row:
    return Row(Glyph.CHANGE, recreate.service, PlanEvent.RECREATE, _DEFINITION_CHANGED)


def _unit_plan_row(plan: UnitPlan) -> Row:
    key, services = plan.unit.key, ", ".join(plan.services)
    match plan.action:
        case Action.ON:
            return Row(Glyph.ADD, key, PlanEvent.SWITCH_ON, services)
        case Action.OFF:
            facts = (
                services,
                *((f"volumes {', '.join(plan.volumes)} kept",) if plan.volumes else ()),
                *(
                    (f"its switch since {switches.describe_since(plan.switched_off_since)} stays",)
                    if plan.switched_off_since
                    else ()
                ),
            )
            return Row(Glyph.REMOVE, key, PlanEvent.SWITCH_OFF, _SEPARATOR.join(facts))
        case Action.STAYS_STOPPED:
            fact = _stays_stopped_fact(plan.switched_off_since)
            return Row(Glyph.UNCHANGED, key, PlanEvent.STAYS_STOPPED, fact)


def _old_image_row(image: KeptImage) -> Row:
    running, configured = image.running, image.configured
    shows_name = configured.name != running.name or configured.digest is None
    fact = f"{_image_text(running)}{_SEPARATOR}compose.yaml {_image_text(configured, shows_name)}"
    return Row(Glyph.NEEDS_YOU, image.service, PlanEvent.OLD_IMAGE, fact)


def _image_text(image: ImageReference, shows_name: bool = True) -> str:
    digest = "" if image.digest is None else f"@{image.digest[:_DIGEST_SHOWN]}…"
    return f"{image.name if shows_name else ''}{digest}"


def _realm_row(realm: RealmPlan) -> Row | None:
    match realm.action:
        case RealmAction.RUN:
            fact = f"keycloak/*.yaml{_SEPARATOR}{realm.why}"
            return Row(Glyph.CHANGE, REALM_UNIT, PlanEvent.REALM_APPLY, fact)
        case RealmAction.HELD:
            fact = f"{realm.why}{_SEPARATOR}Keycloak is {realm.gate}"
            return Row(Glyph.UNCHANGED, REALM_UNIT, PlanEvent.REALM_HELD, fact)
        case RealmAction.NOT_CHECKED:
            fact = f"{realm.restart}{_SEPARATOR}next apply checks it"
            return Row(Glyph.UNCHANGED, REALM_UNIT, PlanEvent.REALM_LATER, fact)
        case RealmAction.UNREADABLE:
            return Row(Glyph.NEEDS_YOU, REALM_UNIT, PlanEvent.REALM_SKIPPED, realm.error)
        case _:
            return None


def _app_rows(apps: AppsPlan) -> tuple[Row, ...]:
    return (
        *(_kept_row(note) for note in apps.kept),
        *(_off_row(off) for off in apps.offs),
        *(_app_row(plan) for plan in apps.plans),
    )


def _kept_row(note: StaysStoppedNote | SkippedNote) -> Row:
    if isinstance(note, SkippedNote):
        fact = f"{note.skipped.tag}{_SEPARATOR}{note.skipped.reason}"
        return Row(Glyph.UNCHANGED, note.key, PlanEvent.TAG_SKIPPED, fact)
    return Row(Glyph.UNCHANGED, note.key, PlanEvent.STAYS_STOPPED, _stays_stopped_fact(note.since))


def _stays_stopped_fact(since: str | None) -> str:
    if since is None:
        return "barrier stands"
    return f"switched off since {switches.describe_since(since)}"


def _off_row(off: OffPlan) -> Row:
    fact = f"volumes kept{_SEPARATOR}~/srv/{off.app.key} kept"
    return Row(Glyph.REMOVE, off.app.key, PlanEvent.SWITCH_OFF, fact)


def _app_row(plan: AppPlan) -> Row:
    key, tag = plan.app.key, plan.release.tag
    if plan.kind is AppKind.ON:
        return Row(Glyph.ADD, key, PlanEvent.SWITCH_ON, f"{tag}{_SEPARATOR}into ~/srv/{key}")
    if plan.kind is AppKind.START_AGAIN:
        return Row(Glyph.ADD, key, PlanEvent.START_AGAIN, f"{tag}{_SEPARATOR}recorded")
    fact = f"{plan.recorded_tag} → {tag}"
    if plan.unfinished:
        fact += f"{_SEPARATOR}update to {plan.unfinished} did not finish"
    return Row(Glyph.CHANGE, key, PlanEvent.UPDATE, fact)
