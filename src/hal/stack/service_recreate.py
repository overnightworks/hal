"""The recreate of a service that is not a core service, alone and under the switch lock:
a follower whose file or definition changed, a live service of a unit that runs on whose
definition changed, the built service whose image or definition changed in whatever state its
container is (#89, #376)."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from hal.stack import built_image, compose, core, switches
from hal.stack.unit_plans import Progress, Recreate, since_of


@dataclass(frozen=True)
class Recreated:
    """A service recreated and observed running, after `seconds` of the lock, the recreate and
    the watch."""

    service: str
    seconds: float


@dataclass(frozen=True)
class ServiceRecreator:
    """One apply run's means to recreate a service alone: `--no-deps`, so the unit's other
    services are never touched (C6), under the switch lock, so a marker that appeared since the
    plan read its marks (`read`) holds it (P7)."""

    engine: compose.Compose
    marks: switches.Switches
    read: Mapping[str, switches.Mark | None]
    config: Mapping[str, Any]
    watch: compose.Watch
    progress: Progress
    tell: Callable[[Recreated], None]

    def followers(
        self,
        recreates: Sequence[core.FollowerPlan],
        record: core.Record,
        followed: Callable[[], frozenset[str]],
    ) -> str | None:
        """Recreate each changed follower whose unit is on. Its entry is emptied first and its
        plan-time digests written once it is observed running (#89 rule 3). No barrier is proven
        again: a follower serves no barrier."""
        if not recreates:
            return None
        try:
            followed_services = followed()
            for plan in recreates:
                self.progress.unit = plan.service
                started = self.watch.clock()
                if failure := self.alone(
                    plan.unit,
                    plan.service,
                    lambda plan=plan: self._mark_unfinished(plan, record, followed_services),
                ):
                    return failure
                self.progress.step = f"record {plan.service} in {core.APPLIED_FILE}"
                record.write(plan.service, plan.digests, followed_services)
                self.tell(Recreated(plan.service, self.watch.clock() - started))
        except (compose.ComposeError, core.CoreError, switches.SwitchError) as error:
            return f"could not {self.progress.step}, {error}"
        return None

    def _mark_unfinished(
        self, plan: core.FollowerPlan, record: core.Record, followed: frozenset[str]
    ) -> None:
        self.progress.step = f"mark {plan.service} unfinished in {core.APPLIED_FILE}"
        record.mark_unfinished([plan.service], followed)

    def unit_services(
        self, recreates: Sequence[Recreate | built_image.BuiltRecreate]
    ) -> str | None:
        """Recreate each live service of a unit that runs on whose definition changed, and each
        built service, in the order planned. A volume is kept; the image is the container's own
        except for the built service, which runs the image its tag names (#376)."""
        try:
            for plan in recreates:
                self.progress.unit = plan.service
                started = self.watch.clock()
                if failure := self.alone(plan.unit, plan.service):
                    return failure
                self.tell(Recreated(plan.service, self.watch.clock() - started))
        except (compose.ComposeError, switches.SwitchError) as error:
            return f"could not {self.progress.step}, {error}"
        return None

    def alone(
        self, unit: str, service: str, before: Callable[[], None] = lambda: None
    ) -> str | None:
        """Recreate one service of `unit` under the switch lock and observe it running; the
        failure line of the first step that fails."""
        with self.marks.lock():
            if changed := self.marks.changed(unit, self.read[unit]):
                since = switches.describe_since(since_of(changed))
                return (
                    f"{unit} was switched off meanwhile (since {since}); {service} is not recreated"
                )
            before()
            self.progress.step = f"recreate {service}"
            self.engine.recreate(service)
        self.progress.step = f"observe {service} running"
        if self.engine.down_while_watched(self.config, (service,), self.watch):
            return f"{service} is not running after the {service} recreate"
        return None
