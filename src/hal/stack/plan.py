"""The planned run as a value: what `hal apply` would do, before it does any of it."""

from collections.abc import Mapping
from dataclasses import dataclass

from hal.stack import core, litellm_keys, switches
from hal.stack.appkit_step import AppkitPlan
from hal.stack.apps import AppsPlan
from hal.stack.built_image import BuiltRecreate
from hal.stack.legal_step import LegalPlan
from hal.stack.realm import reconcile
from hal.stack.unit_plans import Action, Fleet, KeptImage, Recreate, UnitPlan


@dataclass(frozen=True)
class Plan:
    fleet: Fleet
    checkout: core.Checkout
    read: Mapping[str, switches.Mark | None]
    core: list[core.CorePlan]
    followers: list[core.FollowerPlan]
    built: list[BuiltRecreate]
    recreates: list[Recreate]
    plans: list[UnitPlan]
    images: list[KeptImage]
    realm: reconcile.RealmPlan
    keys: litellm_keys.KeysStep
    app_plans: AppsPlan
    appkit: AppkitPlan
    legal: LegalPlan

    @property
    def created_services(self) -> tuple[str, ...]:
        """Every service this run creates a container for or names to start (a running one is left
        alone by `--no-recreate`), once each, and the key step's one-off when the step reads."""
        services = (
            *(
                service
                for plan in self.plans
                if plan.action is Action.ON
                for service in plan.services
            ),
            *(plan.service for plan in self.core if plan.action is core.CoreAction.RECREATE),
            *(
                plan.service
                for plan in self.followers
                if plan.action is core.FollowerAction.RECREATE
            ),
            *(built.service for built in self.built),
            *(recreate.service for recreate in self.recreates),
            *((litellm_keys.KEYS_SERVICE,) if litellm_keys.reads(self.keys) else ()),
        )
        return tuple(dict.fromkeys(services))

    @property
    def changes_nothing(self) -> bool:
        return (
            self.realm.action is not reconcile.RealmAction.RUN
            and not (isinstance(self.keys, litellm_keys.KeysPlan) and self.keys.changes)
            and all(plan.action is Action.STAYS_STOPPED for plan in self.plans)
            and all(plan.action is core.CoreAction.NOT_STARTED for plan in self.core)
            and all(plan.action is core.FollowerAction.HELD for plan in self.followers)
            and not self.built
            and not self.recreates
            and self.app_plans.changes_nothing
            and self.appkit.changes_nothing
            and self.legal.changes_nothing
        )
