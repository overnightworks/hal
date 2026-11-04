"""The key step's rows as the one-off reports them, shared by the host-side tests of the step."""

from hal.stack import core, litellm_keys
from hal.stack.api_limits import NONE_SET
from hal.stack.litellm_keys import AdminFound, AdminHeld, Change, Found
from hal.stack.realm.reconcile import MembersNotRead

APPS = ("hopin", "presentator", "songmaker")
MODELS = ("text/haiku", "text/opus", "text/sonnet")
BUDGET_ID = "scenario-budget"


def found_key(app: str, models: tuple[str, ...] = MODELS, **overrides: object) -> dict:
    """The live row of `app` as the one-off reports it: the desired settings at the code
    defaults, overridden."""
    desired = litellm_keys.desired_key(app, models, NONE_SET.limits_of(app))
    return {
        name: list(value) if isinstance(value, tuple) else value for name, value in desired.items()
    } | overrides


def found_budget(**overrides: object) -> dict:
    return dict(litellm_keys.desired_budget(NONE_SET.person_budget())) | overrides


HELD = AdminHeld(core.Gate.OFF)


def found(
    keys: dict | None = None,
    taken: tuple[str, ...] = (),
    budget: dict | None = None,
    models: tuple[str, ...] = MODELS,
    admin: AdminFound | AdminHeld | MembersNotRead = HELD,
) -> Found:
    keys = {app: found_key(app) for app in APPS} if keys is None else keys
    return Found(
        keys={app: keys.get(app) for app in APPS},
        name_taken=frozenset(taken),
        budget=found_budget() if budget is None else budget,
        models=models,
        admin=admin,
    )


def changed_fields(change: Change | None) -> dict[str, object]:
    assert change is not None
    return {field_change.name: field_change.new for field_change in change.fields}
