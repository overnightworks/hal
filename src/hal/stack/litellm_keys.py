"""The key step of `hal apply`: each app's LiteLLM key and the person budget, from the code
defaults below, through the one-off `litellm-keys` (`hal.stack.litellm_admin`).

At plan time the one-off reads what LiteLLM holds; the diff of desired and found is the step's
plan rows, part of the one question. After the yes, past the realm step and before the apps, the
one-off makes the changes: the person budget first, then the apps in name order, and the first
failed write stops the rest. A key is found by the SHA-256 of its file, so a retry after a lost
answer makes no second key, and an unchanged row changes nothing. Only changed fields are sent:
a pure limit change sends no period, so LiteLLM keeps its reset. The apps are the key files
compose mounts into the one-off. hal's own process never opens a key file or the master key; the
step's stdin and stdout carry names, numbers and model names only.

The step reads while the `litellm` container runs and is absent otherwise; nothing in `hal apply`
starts or stops LiteLLM yet.
"""

import json
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, cast

import yaml

from hal.stack import compose

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

type Value = str | float | int | tuple[str, ...] | None
type Settings = Mapping[str, Value]


class KeysError(Exception):
    """The key step's one-off failed or answered nonsense; the message is one line."""


class Target(StrEnum):
    BUDGET = "budget"
    KEY = "key"


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
class Found:
    """What the one-off read: each app's live key by its hash (None when absent), the apps whose
    name another live key holds, the person budget (None when absent) and LiteLLM's models."""

    keys: Mapping[str, Mapping[str, Any] | None]
    name_taken: frozenset[str]
    budget: Mapping[str, Any] | None
    models: tuple[str, ...]


@dataclass(frozen=True)
class KeysPlan:
    """The step as planned; the empty plan is a step that does not act."""

    changes: tuple[Change, ...] = ()
    name_taken: tuple[str, ...] = ()
    not_read: str | None = None  # why the keys could not be read while LiteLLM runs


@dataclass(frozen=True)
class KeysDone:
    done: tuple[Change, ...]
    name_taken: tuple[str, ...]


@dataclass(frozen=True)
class KeysFailed:
    """A write that failed: `failed` is None when the one-off ended before it could say which."""

    done: tuple[Change, ...]
    failed: Change | None
    cause: str
    not_made: tuple[Change, ...]
    name_taken: tuple[str, ...]


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
    """The person budget first, then each app in name order; an app whose name another key holds
    gets no change."""
    budget = diff(Target.BUDGET, budget_id, desired_budget(), found.budget)
    keys = (
        diff(Target.KEY, app, desired_key(app, found.models), found.keys[app])
        for app in sorted(found.keys)
        if app not in found.name_taken
    )
    changes = tuple(change for change in (budget, *keys) if change is not None)
    return KeysPlan(changes, tuple(sorted(found.name_taken)))


def plan_keys(
    engine: compose.Compose, states: Mapping[str, set[str]], repository: Path
) -> KeysPlan:
    """Reads while the `litellm` container runs; a read that fails is a step not read."""
    if not compose.has_running_container(states, (LITELLM_SERVICE,)):
        return KeysPlan()
    try:
        budget_id = read_budget_id(repository)
        return planned(read(engine, budget_id), budget_id)
    except KeysError as error:
        return KeysPlan(not_read=str(error))


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


def read(engine: compose.Compose, budget_id: str) -> Found:
    document = _one_off(engine, ["--read", budget_id], "")
    try:
        apps = document["apps"]
        return Found(
            keys={str(app): _row(entry["key"]) for app, entry in apps.items()},
            name_taken=frozenset(
                str(app) for app, entry in apps.items() if entry["name_taken"] is True
            ),
            budget=_row(document["budget"]),
            models=tuple(str(model) for model in document["models"]),
        )
    except (KeyError, TypeError, AttributeError) as error:
        raise KeysError("the key step answered an unexpected shape") from error


def _row(value: object) -> Mapping[str, Any] | None:
    if value is None or isinstance(value, dict):
        return value
    raise TypeError(value)


def _one_off(engine: compose.Compose, arguments: list[str], stdin: str) -> Any:
    try:
        output = engine.run_once(KEYS_SERVICE, arguments, stdin)
    except compose.ComposeError as error:
        raise KeysError(str(error)) from error
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
        return KeysDone((), plan.name_taken) if plan.name_taken else None
    stdin = json.dumps([change.wire() for change in plan.changes])
    try:
        made, cause = _made(_one_off(engine, ["--write"], stdin), plan.changes)
    except KeysError as error:
        return KeysFailed((), None, str(error), (), plan.name_taken)
    done = plan.changes[:made]
    if cause is None:
        return KeysDone(done, plan.name_taken)
    return KeysFailed(done, plan.changes[made], cause, plan.changes[made + 1 :], plan.name_taken)


def _made(document: object, changes: tuple[Change, ...]) -> tuple[int, str | None]:
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
    if answered != [(change.target, change.subject) for change in changes] or outcomes != expected:
        raise KeysError("the key step answered for other changes than it was given")
    return made, cause
