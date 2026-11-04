"""The key step of `hal apply`: each app's LiteLLM key, the person budget and the admin budget
with its customer rows, from the code defaults below, through the one-off `litellm-keys`
(`hal.stack.litellm_admin`).

At plan time the one-off reads what LiteLLM holds; the diff of desired and found is the step's
plan rows, part of the one question. After the yes, past the realm step and before the apps, the
one-off makes the changes: the person budget first, then the apps in name order, then the admin
budget and its rows, and the first failed write stops the rest. A key is found by the SHA-256 of
its file, so a retry after a lost answer makes no second key, and an unchanged row changes
nothing. Only changed fields are sent: a pure limit change sends no period, so LiteLLM keeps its
reset. The apps are the key files compose mounts into the one-off. hal's own process never opens
a key file or the master key; the step's stdin and stdout carry names, numbers, model names and
the admin group's fingerprints, and no printed line carries a fingerprint or a member.

The admin budget has no limit and the person budget's period, so LiteLLM resets its rows' spend
each month and no person budget binds them. Its rows are exactly those of the members of the
Keycloak group ADMIN_GROUP, read through the realm observer at each plan, each fingerprint the
agent-runtime client's `person_fingerprint` of the realm's issuer and the member's id: a member's
row is made or linked, and a row on the admin budget that is no member's is unlinked. Other rows
are never touched. With Keycloak held the admin rows are held; with its members not read they
stay as they are, and the run ends partial.

The step reads while the `litellm` container runs and is absent otherwise; nothing in `hal apply`
starts or stops LiteLLM yet.
"""

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import yaml

from hal.stack import compose, core
from hal.stack.realm import reconcile
from hal.stack.realm.reconcile import MembersNotRead
from hal.stack.unit_plans import Restart

KEYS_SERVICE = "litellm-keys"
LITELLM_SERVICE = "litellm"
CONFIG_FILE = Path("agent-service") / "litellm" / "config.yaml"
BUDGET_ID_SETTING = "max_end_user_budget_id"
# The code defaults until `config.toml` carries the operator's numbers.
APP_BUDGET_DOLLARS = 10.0
PERSON_BUDGET_DOLLARS = 2.0
MAX_PARALLEL_REQUESTS = 5
BUDGET_DURATION = "1mo"
ROUTE = "/v1/chat/completions"  # the one path litellm-front serves
ADMIN_GROUP = "/services/litellm/admin"
ADMIN_BUDGET_ID = "litellm-admin"  # hal's own; LiteLLM never reads it by name
FINGERPRINT = re.compile(r"fp-[0-9a-f]{64}")

type Value = str | float | int | tuple[str, ...] | None
type Settings = Mapping[str, Value]


class KeysError(Exception):
    """The key step's one-off failed or answered nonsense; the message is one line."""


class Target(StrEnum):
    BUDGET = "budget"
    KEY = "key"
    CUSTOMER = "customer"


class Outcome(StrEnum):
    DONE = "done"
    FAILED = "failed"
    NOT_MADE = "not made"


@dataclass(frozen=True)
class FieldChange:
    name: str
    old: Value  # None for a new row
    new: Value


@dataclass(frozen=True)
class Change:
    """One row to make or update: the person budget by its id, or an app's key by the app."""

    target: Target
    subject: str
    new: bool
    fields: tuple[FieldChange, ...]

    def wire(self) -> dict[str, Any]:
        """The change as the one-off's `--write` reads it: the fields to send, a cleared one as
        null."""
        fields = {
            change.name: list(change.new) if isinstance(change.new, tuple) else change.new
            for change in self.fields
        }
        return {"target": self.target, "subject": self.subject, "new": self.new, "fields": fields}


@dataclass(frozen=True)
class RowChange:
    """A customer row linked to `budget`, made for it when `new`, or unlinked from it. Its
    fingerprint travels to the one-off and is never printed."""

    fingerprint: str = field(repr=False)
    budget: str
    link: bool
    new: bool

    def wire(self) -> dict[str, Any]:
        """The change as the one-off's `--write` reads it: an unlink is a null budget and names
        the budget it leaves, so a row moved off it meanwhile stays as it is."""
        named = {"target": Target.CUSTOMER, "subject": self.fingerprint, "new": self.new}
        if self.link:
            return named | {"fields": {"budget_id": self.budget}}
        return named | {"fields": {"budget_id": None}, "leaves": self.budget}


type StepChange = Change | RowChange
type Fingerprints = tuple[str, ...]


@dataclass(frozen=True)
class CustomerRow:
    budget_id: str | None  # the budget the row is linked to, None when unlinked


@dataclass(frozen=True)
class AdminFound:
    """The admin budget's row (None when absent), each member's customer row by fingerprint in
    the order asked (None when it has none), and the fingerprints of the rows on the admin budget
    that are no member's."""

    budget: Mapping[str, Any] | None
    members: Mapping[str, CustomerRow | None] = field(repr=False)
    others: Fingerprints = field(repr=False)


@dataclass(frozen=True)
class AdminHeld:
    """Keycloak's unit is held, so no member is read and the admin rows wait with it."""

    gate: core.Gate


type AdminState = AdminHeld | MembersNotRead | None  # None: the members were read


@dataclass(frozen=True)
class Found:
    """What the one-off read: each app's live key by its hash (None when absent), the apps whose
    name another live key holds, the person budget (None when absent), LiteLLM's models and the
    admin rows, or why they were not asked for."""

    keys: Mapping[str, Mapping[str, Any] | None]
    name_taken: frozenset[str]
    budget: Mapping[str, Any] | None
    models: tuple[str, ...]
    admin: AdminFound | AdminHeld | MembersNotRead


@dataclass(frozen=True)
class KeysPlan:
    """The step as planned; the empty plan is a step that does not act."""

    changes: tuple[StepChange, ...] = ()
    name_taken: tuple[str, ...] = ()
    not_read: str | None = None  # why the keys could not be read while LiteLLM runs
    admin: AdminState = None


@dataclass(frozen=True)
class KeysDone:
    done: tuple[StepChange, ...]
    name_taken: tuple[str, ...]
    admin: AdminState = None


@dataclass(frozen=True)
class KeysFailed:
    """A write that failed: `failed` is None when the one-off ended before it could say which."""

    done: tuple[StepChange, ...]
    failed: StepChange | None
    cause: str
    not_made: tuple[StepChange, ...]
    name_taken: tuple[str, ...]
    admin: AdminState = None


@dataclass(frozen=True)
class KeysSkipped:
    reason: str


type KeysResult = KeysDone | KeysFailed | KeysSkipped | None  # None: nothing to do


def desired_key(app: str, models: tuple[str, ...]) -> Settings:
    return {
        "key_alias": app,
        "max_budget": APP_BUDGET_DOLLARS,
        "budget_duration": BUDGET_DURATION,
        "models": models,
        "allowed_routes": (ROUTE,),
        "max_parallel_requests": MAX_PARALLEL_REQUESTS,
        "rpm_limit": None,
        "tpm_limit": None,
    }


def desired_budget() -> Settings:
    return {"max_budget": PERSON_BUDGET_DOLLARS, "budget_duration": BUDGET_DURATION}


def desired_admin_budget() -> Settings:
    """No limit, so no person budget binds its rows; the person budget's period, so LiteLLM's
    reset job resets their spend as it resets a person's."""
    return {"max_budget": None, "budget_duration": BUDGET_DURATION}


def _comparable(value: object) -> Value:
    """A list compares as a set: LiteLLM keeps the order it was sent, which means nothing."""
    if isinstance(value, list | tuple):
        return tuple(sorted(str(item) for item in value))
    return cast(Value, value)


def diff(
    target: Target, subject: str, desired: Settings, found: Mapping[str, Any] | None
) -> Change | None:
    """The change that makes `found` the desired row, None when it already is; an absent row is
    new and gets every field that is set."""
    if found is None:
        fields = tuple(
            FieldChange(name, None, value) for name, value in desired.items() if value is not None
        )
        return Change(target, subject, True, fields)
    fields = tuple(
        FieldChange(name, _comparable(found.get(name)), value)
        for name, value in desired.items()
        if _comparable(found.get(name)) != _comparable(value)
    )
    return Change(target, subject, False, fields) if fields else None


def planned(found: Found, budget_id: str) -> KeysPlan:
    """The person budget first, then each app in name order, then the admin budget and its rows;
    an app whose name another key holds gets no change."""
    budget = diff(Target.BUDGET, budget_id, desired_budget(), found.budget)
    keys = (
        diff(Target.KEY, app, desired_key(app, found.models), found.keys[app])
        for app in sorted(found.keys)
        if app not in found.name_taken
    )
    changes = tuple(change for change in (budget, *keys) if change is not None)
    taken = tuple(sorted(found.name_taken))
    if not isinstance(found.admin, AdminFound):
        return KeysPlan(changes, taken, admin=found.admin)
    return KeysPlan((*changes, *admin_changes(found.admin)), taken)


def admin_changes(found: AdminFound) -> tuple[StepChange, ...]:
    """The admin budget, then each row on it that is no member's unlinked, then each member's row
    made or linked; unlinks come first, so a write that stops lifts no budget it meant to drop."""
    budget = diff(Target.BUDGET, ADMIN_BUDGET_ID, desired_admin_budget(), found.budget)
    unlinks = (RowChange(other, ADMIN_BUDGET_ID, False, False) for other in found.others)
    links = (
        RowChange(fingerprint, ADMIN_BUDGET_ID, True, row is None)
        for fingerprint, row in found.members.items()
        if row is None or row.budget_id != ADMIN_BUDGET_ID
    )
    return tuple(change for change in (budget, *unlinks, *links) if change is not None)


def plan_keys(
    engine: compose.Compose,
    states: Mapping[str, set[str]],
    repository: Path,
    keycloak_gate: core.Gate | None,
    keycloak_restart: Restart | None,
) -> KeysPlan:
    """Reads while the `litellm` container runs; a read that fails is a step not read. Keycloak's
    gate and restart are those `hal apply` hands the realm step; a gate of None, Keycloak outside
    the catalog, counts as on, as the realm step reads it."""
    if not compose.has_running_container(states, (LITELLM_SERVICE,)):
        return KeysPlan()
    try:
        budget_id = read_budget_id(repository)
        members = admin_members(engine, states, keycloak_gate, keycloak_restart)
        return planned(read(engine, budget_id, members), budget_id)
    except KeysError as error:
        return KeysPlan(not_read=str(error))


def admin_members(
    engine: compose.Compose,
    states: Mapping[str, set[str]],
    gate: core.Gate | None,
    restart: Restart | None,
) -> Fingerprints | AdminHeld | MembersNotRead:
    """The admin group's members as fingerprints: held while Keycloak's gate is not on, and not
    read while Keycloak does not run at plan time; a restart in this run changes no member."""
    if reconcile.keycloak_held(gate):
        return AdminHeld(gate)
    if not compose.has_running_container(states, (reconcile.KEYCLOAK_SERVICE,)):
        starts = restart is Restart.SERVICE
        return MembersNotRead(
            "Keycloak starts in this run" if starts else "Keycloak is not running"
        )
    members = reconcile.Observer(engine).members(ADMIN_GROUP)
    return fingerprints(members) if isinstance(members, reconcile.Members) else members


def fingerprints(members: reconcile.Members) -> Fingerprints:
    """Each member's fingerprint by the client's one recipe, once each and sorted; a value that
    fails a check fails the read, naming the check alone."""
    # Imported here alone: the probes that import this module run on a Python without the
    # client, and no other hal command pays for pydantic's import.
    from agent_runtime_client.turn import Principal, person_fingerprint

    try:
        computed = {
            person_fingerprint(Principal(iss=members.issuer, sub=subject))
            for subject in members.subjects
        }
    except ValueError:  # the client's validation error, whose text quotes the value
        raise KeysError("a member's subject fails the client's check") from None
    if not all(FINGERPRINT.fullmatch(value) for value in computed):
        raise KeysError("a member's fingerprint is not fp- and 64 lowercase hex")
    return tuple(sorted(computed))


def read_budget_id(repository: Path) -> str:
    """The person budget id LiteLLM's configuration names."""
    try:
        settings = yaml.safe_load((repository / CONFIG_FILE).read_text())["litellm_settings"]
        budget_id = settings[BUDGET_ID_SETTING]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as error:
        raise KeysError(f"{CONFIG_FILE} names no {BUDGET_ID_SETTING}") from error
    if not isinstance(budget_id, str) or not budget_id:
        raise KeysError(f"{CONFIG_FILE} names no {BUDGET_ID_SETTING}")
    return budget_id


def read(
    engine: compose.Compose, budget_id: str, members: Fingerprints | AdminHeld | MembersNotRead
) -> Found:
    """What LiteLLM holds; the admin rows only for members read, their fingerprints on stdin."""
    asked = None
    if isinstance(members, tuple):
        asked = {"budget": ADMIN_BUDGET_ID, "members": list(members)}
    document = _one_off(engine, ["--read", budget_id], json.dumps(asked))
    try:
        apps = document["apps"]
        return Found(
            keys={str(app): _row(entry["key"]) for app, entry in apps.items()},
            name_taken=frozenset(
                str(app) for app, entry in apps.items() if entry["name_taken"] is True
            ),
            budget=_row(document["budget"]),
            models=tuple(str(model) for model in document["models"]),
            admin=_admin(document["admin"], members) if isinstance(members, tuple) else members,
        )
    except (KeyError, TypeError, AttributeError, ValueError) as error:
        raise KeysError("the key step answered an unexpected shape") from error


def _admin(answer: Any, members: Fingerprints) -> AdminFound:
    """The admin rows as read; a row for each member asked, in order, else no answer."""
    rows = zip(members, answer["members"], strict=True)
    return AdminFound(
        budget=_row(answer["budget"]),
        members={fingerprint: _customer(row) for fingerprint, row in rows},
        others=tuple(_text(entry["fingerprint"]) for entry in answer["others"]),
    )


def _customer(value: Any) -> CustomerRow | None:
    if value is None:
        return None
    budget_id = value["budget_id"]
    return CustomerRow(None if budget_id is None else _text(budget_id))


def _text(value: object) -> str:
    if isinstance(value, str):
        return value
    raise TypeError("no text")


def _row(value: object) -> Mapping[str, Any] | None:
    if value is None or isinstance(value, dict):
        return value
    raise TypeError(value)


def _one_off(engine: compose.Compose, arguments: list[str], stdin: str) -> Any:
    try:
        output = engine.run_once(KEYS_SERVICE, arguments, stdin)
    except compose.ComposeError as error:
        raise KeysError(error.one_off_cause(KEYS_SERVICE)) from error
    try:
        return json.loads(output)
    except ValueError as error:
        raise KeysError("the key step answered no JSON") from error


def run_keys(plan: KeysPlan, engine: compose.Compose) -> KeysResult:
    """Alone decides whether the step acts: a step not read is skipped, and an empty plan has no
    effect."""
    if plan.not_read is not None:
        return KeysSkipped(plan.not_read)
    if not plan.changes:
        unsettled = bool(plan.name_taken) or plan.admin is not None
        return KeysDone((), plan.name_taken, plan.admin) if unsettled else None
    wired = [change.wire() for change in plan.changes]
    try:
        made, cause = _made(_one_off(engine, ["--write"], json.dumps(wired)), wired)
    except KeysError as error:
        return KeysFailed((), None, str(error), (), plan.name_taken, plan.admin)
    done, rest = plan.changes[:made], plan.changes[made:]
    if cause is None:
        return KeysDone(done, plan.name_taken, plan.admin)
    return KeysFailed(done, rest[0], cause, rest[1:], plan.name_taken, plan.admin)


def _made(document: object, changes: list[dict[str, Any]]) -> tuple[int, str | None]:
    """How many changes were made, in the order sent, and the cause of the one that failed after
    them, None when all were made. An answer that is not one outcome per change, done ones first,
    then at most one failure and the rest not made, is no answer."""
    try:
        answered = [(Target(entry["target"]), entry["subject"]) for entry in document]
        outcomes = [Outcome(entry["outcome"]) for entry in document]
        made = outcomes.count(Outcome.DONE)
        cause = None if made == len(changes) else str(document[made]["cause"])
    except (KeyError, TypeError, ValueError, AttributeError, IndexError) as error:
        raise KeysError("the key step answered an unexpected shape") from error
    expected = [Outcome.DONE] * made + ([] if cause is None else [Outcome.FAILED])
    expected += [Outcome.NOT_MADE] * (len(changes) - len(expected))
    sent = [(Target(change["target"]), change["subject"]) for change in changes]
    if answered != sent or outcomes != expected:
        raise KeysError("the key step answered for other changes than it was given")
    return made, cause
