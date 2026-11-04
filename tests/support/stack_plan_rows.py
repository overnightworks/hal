"""What the `test_stack_plan_rows` tests share with other test modules."""

import re
from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from hal.output import DETAIL_INDENT, Group
from hal.stack import releases
from hal.stack.appkit_step import AppkitPlan
from hal.stack.apps import (
    AppKind,
    AppPlan,
    AppRuntime,
    AppsPlan,
)
from hal.stack.catalog import App, Unit
from hal.stack.legal_step import LegalPlan
from hal.stack.litellm_keys import KeysStep
from hal.stack.plan import Plan
from hal.stack.plan_rows import (
    plan_groups,
)
from hal.stack.realm.reconcile import RealmPlan
from hal.stack.unit_plans import Action, ImageReference, KeptImage, UnitPlan

APP = App("hopin", True, "master")


OLD, NEW = "v2026.10.26.1", "v2026.10.27.1"


def app_plan(kind: AppKind, **overrides: object) -> AppPlan:
    fields: dict[str, object] = {
        "app": APP,
        "release": releases.parse(NEW),
        "sha": "a" * 40,
        "services": ("hopin",),
        "url": "https://github.com/org/hopin.git",
        "ingress": None,
        "kind": kind,
        "recorded_tag": None,
        "unfinished": None,
    }
    return AppPlan(**{**fields, **overrides})  # type: ignore[arg-type]


NO_REALM = RealmPlan()


NO_LEGAL = LegalPlan(Path(), Path(), {}, {})


REPOSITORY = Path("/repository")


NO_APPKIT = AppkitPlan("0.5.0", Path(), REPOSITORY, (), ())


def plan_of(
    images: tuple[KeptImage, ...] = (),
    realm: RealmPlan = NO_REALM,
    legal: LegalPlan = NO_LEGAL,
    appkit: AppkitPlan = NO_APPKIT,
    keys: KeysStep = None,
    **parts: Any,
) -> Plan:
    units = {
        key: parts.pop(key)
        for key in ("built", "recreates", "unit_plans", "core", "followers")
        if key in parts
    }
    apps = AppsPlan(cast(AppRuntime, None), **parts)  # type: ignore[arg-type]
    plan = SimpleNamespace(
        app_plans=apps,
        images=list(images),
        realm=realm,
        keys=keys,
        legal=legal,
        appkit=appkit,
        built=list(units.pop("built", ())),
        recreates=list(units.pop("recreates", ())),
        plans=list(units.pop("unit_plans", ())),
        core=list(units.pop("core", ())),
        followers=list(units.pop("followers", ())),
    )
    return cast(Plan, plan)


def groups_of(**parts: Any) -> tuple[Group, ...]:
    return plan_groups(plan_of(**parts))


def plain(out: str) -> str:
    """The output without colour."""
    return re.sub(r"\x1b\[[0-9;]*m", "", out)


def find_row(out: str, subject: str, event: StrEnum, fact: str = "") -> re.Match[str] | None:
    pattern = (
        rf"^  \S {re.escape(subject)} +(?:\d+ )?{re.escape(str(event))}s?\b.*{re.escape(fact)}"
    )
    return re.search(pattern, plain(out), re.MULTILINE)


def detail_lines(out: str) -> list[str]:
    """The lines indented under a row, without colour."""
    return [
        line[len(DETAIL_INDENT) :]
        for line in plain(out).splitlines()
        if line.startswith(DETAIL_INDENT)
    ]


def row_at(out: str, subject: str, event: StrEnum, fact: str = "") -> int:
    row = find_row(out, subject, event, fact)
    assert row, out
    return row.start()


DIGEST_A, DIGEST_B = "79c6" + "0" * 60, "a78d" + "0" * 60


KEYCLOAK = "quay.io/keycloak/keycloak:26.8.1"


def kept(running: ImageReference, configured: ImageReference) -> KeptImage:
    return KeptImage("keycloak", running, configured)


STEP_CA = Unit("step-ca", True, None)


SERVICES = ("step-ca", "traefik-mcp")


def unit_plan(action: Action, **overrides: Any) -> UnitPlan:
    fields: dict[str, Any] = {"unit": STEP_CA, "services": SERVICES, "volumes": ("step-ca",)}
    return UnitPlan(action=action, **{**fields, **overrides})
