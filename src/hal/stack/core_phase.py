"""The core phase of `hal apply --local`: the changed core services and followers are recreated
before any unit is touched, and the followers a switch-on started are recorded.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from hal.output import write_row
from hal.output.command import Verb, command
from hal.stack import barrier, compose, core, switches
from hal.stack.plan import Plan
from hal.stack.result_rows import recreated_row
from hal.stack.service_recreate import Recreated, ServiceRecreator
from hal.stack.unit_plans import Progress, UnitPlan


def _say_recreated(recreated: Recreated) -> None:
    write_row(recreated_row(recreated))


@dataclass(frozen=True)
class CorePhase:
    """Recreate each changed core service with a live container, then each changed follower whose
    unit is on, before any unit is touched; record the followers a switch-on started."""

    record: core.Record
    repository: Path
    verifier: barrier.Verifier
    watch: compose.Watch

    def run(
        self,
        engine: compose.Compose,
        planned: Plan,
        marks: switches.Switches,
        progress: Progress,
    ) -> str | None:
        """The core, the followers, then the services to recreate (a live service of a unit that
        runs on, the built service in any container state); the failure line of the first step
        that fails."""
        return self._recreate_core(engine, planned, marks, progress) or self._recreate_services(
            engine, planned, marks, progress
        )

    def _recreate_services(
        self,
        engine: compose.Compose,
        planned: Plan,
        marks: switches.Switches,
        progress: Progress,
    ) -> str | None:
        config = planned.fleet.config
        recreator = ServiceRecreator(
            engine, marks, planned.read, config, self.watch, progress, _say_recreated
        )
        followers = [
            plan for plan in planned.followers if plan.action is core.FollowerAction.RECREATE
        ]
        return recreator.followers(
            followers, self.record, lambda: self._followed(planned, progress)
        ) or recreator.unit_services([*planned.built, *planned.recreates])

    def _recreate_core(
        self,
        engine: compose.Compose,
        planned: Plan,
        marks: switches.Switches,
        progress: Progress,
    ) -> str | None:
        """In start order, look again whether each still has a live container; before the
        set's first recreate mark every recorded service of the set unfinished, whatever its
        liveness then; recreate each, observe it running with the core services it depends on,
        prove every active barrier, and only then record it with its plan-time digests (#85 rule
        3, #87 rule 4). The failure line of the first step that fails, whose set is left marked
        unfinished once its first recreate began, so the next run recreates it (#85 rule 5). One
        stopped since the plan is not started; where it is the set's first, no recreate began
        and no entry changes (C3, #93 rule 2)."""
        recreates = [plan for plan in planned.core if plan.action is core.CoreAction.RECREATE]
        try:
            followed = self._followed(planned, progress) if recreates else frozenset()
            for index, plan in enumerate(recreates):
                progress.unit = plan.service
                if stopped := self._stopped_meanwhile(engine, plan, progress):
                    return stopped
                if index == 0:
                    self._mark_unfinished(recreates, followed, progress)
                if failure := self._recreate_one(engine, planned, marks, plan, followed, progress):
                    return failure
        except (compose.ComposeError, core.CoreError) as error:
            return f"could not {progress.step}, {error}"
        if recreates and len(recreates) == len(planned.core):
            print("the core is current")
        return None

    def _stopped_meanwhile(
        self, engine: compose.Compose, plan: core.CorePlan, progress: Progress
    ) -> str | None:
        """The failure line when the service has no live container now (#93 rules 1, 2)."""
        progress.step = f"look whether {plan.service} still runs"
        if _stopped_since_the_plan(engine.states(), plan):
            return f"{plan.service} was stopped meanwhile; it is not started"
        return None

    def _mark_unfinished(
        self, recreates: Sequence[core.CorePlan], followed: frozenset[str], progress: Progress
    ) -> None:
        """Empty the entry of every recorded service of the set, so a recreate that does not
        finish, or a dependent stopped before its own, is recreated by the next run (#85 rule 5,
        #93 rule 2)."""
        if recorded := [plan.service for plan in recreates if plan.service in followed]:
            progress.step = f"mark {', '.join(recorded)} unfinished in {core.APPLIED_FILE}"
            self.record.mark_unfinished(recorded, followed)

    def _recreate_one(
        self,
        engine: compose.Compose,
        planned: Plan,
        marks: switches.Switches,
        plan: core.CorePlan,
        followed: frozenset[str],
        progress: Progress,
    ) -> str | None:
        """Recreate the service, observe it running with the core services it depends on, prove
        every active barrier, and only then record it; the failure line of the first step that
        fails."""
        config = planned.fleet.config
        progress.step = f"recreate {plan.service}"
        engine.recreate(plan.service)
        progress.step = f"observe {plan.service} running"
        observed = _in_start_order(config, {plan.service, *core.dependencies(config, plan.service)})
        if down := engine.down_while_watched(config, observed, self.watch):
            verb = "is" if len(down) == 1 else "are"
            return f"{' and '.join(down)} {verb} not running after the {plan.service} recreate"
        progress.step = "prove the barriers"
        if unproven := self._unproven_barrier(planned, marks, plan.service):
            return unproven
        if plan.service in followed:
            progress.step = f"record {plan.service} in {core.APPLIED_FILE}"
            self.record.write(plan.service, plan.digests, followed)
        print(plan.recreated(followed))
        return None

    def record_switched_on(
        self, planned: Plan, switched_on: Sequence[UnitPlan], progress: Progress
    ) -> None:
        """Write the plan-time digests of each follower that started with a unit observed on, so
        the next run does not recreate it (#89, P15)."""
        units = {plan.unit.key for plan in switched_on}
        started = [
            plan
            for plan in planned.followers
            if plan.action is core.FollowerAction.STARTS_WITH_UNIT and plan.unit in units
        ]
        if not started:
            return
        followed = self._followed(planned, progress)
        for plan in started:
            progress.unit = plan.unit
            progress.step = f"record {plan.service} in {core.APPLIED_FILE}"
            self.record.write(plan.service, plan.digests, followed)

    def _followed(self, planned: Plan, progress: Progress) -> frozenset[str]:
        progress.step = "find the services edge follows"
        return core.followed_services(planned.fleet.config, planned.checkout)

    def _unproven_barrier(
        self, planned: Plan, marks: switches.Switches, service: str
    ) -> str | None:
        """Say each proven barrier; the failure line naming every one that is not, after all
        active barriers were tried (S9)."""
        unproven: list[barrier.Unproven] = []
        for proof in barrier.prove_active(
            planned.fleet.units, planned.fleet.profile_services, planned.fleet.config, marks,
            self.repository, self.verifier, planned.app_plans.catalogued,
        ):  # fmt: skip
            match proof:
                case barrier.Proven(unit):
                    print(f"the barrier of {unit} is proven")
                case barrier.NoHost(unit):
                    print(f"{unit}: no host behind Traefik, so no barrier")
                case barrier.Unproven():
                    unproven.append(proof)
        if not unproven:
            return None
        units = ", ".join(proof.unit for proof in unproven)
        if len(unproven) == 1:
            barriers, failures = f"the barrier of {units} is", unproven[0].failure
        else:
            barriers = f"the barriers of {units} are"
            failures = "; ".join(f"{proof.unit}: {proof.failure}" for proof in unproven)
        return (
            f"{barriers} not proven after the {service} recreate ({failures}): {units} may be "
            f"reachable through Traefik; to close the tunnel now: {command(Verb.OFFLINE)}"
        )


def _stopped_since_the_plan(states: Mapping[str, set[str]], plan: core.CorePlan) -> bool:
    """The core service planned for a recreate has no live container now; one created and never
    started counts as live only where the plan found edge's unfinished recreate left it so (#87
    rule 4): any other was put there since the plan and is not started (#93 rule 1)."""
    recovering = plan.left_unstarted and compose.never_started(states, plan.service)
    return not (recovering or compose.has_running_container(states, (plan.service,)))


def _in_start_order(config: Mapping[str, Any], services: set[str]) -> tuple[str, ...]:
    return tuple(service for service in core.start_order(config) if service in services)
