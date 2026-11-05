"""The recreate of a service that is not a core service, alone and under the switch lock:
a follower whose file or definition changed, a live service of a unit that runs on whose
definition changed, the built service whose image or definition changed in whatever state its
container is, and a database unit's service whose image moved, after the unit's proven pre-apply
snapshot (#89, #376, #995); and the snapshot before a switch-on starts a database unit over its
data."""

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from hal.output import printable
from hal.output.command import Verb, command
from hal.stack import built_image, compose, core, switches
from hal.stack.pre_apply import SNAPSHOT_SHORT_ID, Backup, PreApplyError
from hal.stack.unit_plans import Begin, DatabaseUnit, Progress, Recreate, since_of


@dataclass(frozen=True)
class Recreated:
    """A service recreated and observed running, after `seconds` of the recreate and the watch
    (for a core service also the proof and the record); `barriers_proven` says a core recreate
    proved at least one barrier and none failed, `snapshot` names the pre-apply snapshot proven
    before it."""

    service: str
    seconds: float
    barriers_proven: bool = False
    snapshot: str | None = None


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
    backup: Backup

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
        built service, in the order planned; the failure line of the first that fails. A volume
        is kept; the image is the container's own except for the built service, which runs the
        image its tag names (#376), and a database unit's moved service, which runs the image
        compose.yaml names (#995)."""
        snapshots: dict[str, str] = {}  # unit -> its pre-apply snapshot of this run
        began: set[str] = set()  # the units one of whose services is being or was recreated
        for plan in recreates:
            if failure := self._unit_service(plan, snapshots, began):
                return failure
        return None

    def _unit_service(
        self,
        plan: Recreate | built_image.BuiltRecreate,
        snapshots: dict[str, str],
        began: set[str],
    ) -> str | None:
        """Recreate one, after its unit's proven snapshot when it is the unit's first; a snapshot
        that fails leaves the unit as it runs, and a failure after it names the snapshot, and the
        way back once the unit's recreate has begun."""
        self.progress.unit = plan.service
        started = self.watch.clock()
        taken = None

        def begin() -> None:
            began.add(plan.unit)

        try:
            if isinstance(plan, Recreate) and plan.snapshot:
                taken = snapshots[plan.unit] = proven_snapshot(
                    self.backup, self.progress, plan.snapshot
                )
            failure = self.alone(plan.unit, plan.service, begin)
        except PreApplyError as error:
            return f"{error}; {plan.unit} is not recreated"
        except (compose.ComposeError, switches.SwitchError) as error:
            failure = f"could not {self.progress.step}, {error}"
        except KeyboardInterrupt as interruption:
            if way_back := _way_back(plan.unit, snapshots.get(plan.unit), plan.unit in began):
                interruption.add_note(way_back)
            raise
        if failure:
            way_back = _way_back(plan.unit, snapshots.get(plan.unit), plan.unit in began)
            return f"{failure}; {way_back}" if way_back else failure
        self.tell(Recreated(plan.service, self.watch.clock() - started, snapshot=taken))
        return None

    def alone(
        self, unit: str, service: str, before: Callable[[], None] = lambda: None
    ) -> str | None:
        """Recreate one service of `unit` under the switch lock and observe it running; the
        failure line of the first step that fails."""
        self.progress.step = f"lock the {unit} switch"
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


def proven_snapshot(backup: Backup, progress: Progress, unit: DatabaseUnit) -> str:
    """The unit's new pre-apply snapshot, once its restore test passed."""
    progress.step = f"take the {unit.key} pre-apply snapshot"
    snapshot = backup.pre_apply(unit)
    short = short_snapshot(snapshot)
    progress.step = f"prove pre-apply snapshot {short}"
    try:
        backup.restore_test(unit, snapshot)
    except PreApplyError as error:
        raise PreApplyError(f"{error}, pre-apply snapshot {short} not proven") from error
    return snapshot


def short_snapshot(snapshot: str) -> str:
    return printable(snapshot[:SNAPSHOT_SHORT_ID])


@dataclass
class SwitchOnSnapshots:
    """The pre-apply snapshots one apply run takes before a switch-on starts a database unit over
    its data, and each unit's way back. Its database, started alone for the backup, is not counted
    as started over the data: the snapshot is taken from it, so loading it would undo nothing that
    start did."""

    backup: Backup
    progress: Progress
    taken: dict[str, str] = field(default_factory=dict)  # unit -> its proven snapshot
    began: set[str] = field(default_factory=set)  # the units whose start over the data began

    def first(self, unit: DatabaseUnit, start: Callable[[Begin], str | None]) -> str | None:
        """The proven snapshot, then `start`; a snapshot that fails starts nothing more."""
        try:
            self.taken[unit.key] = proven_snapshot(self.backup, self.progress, unit)
        except PreApplyError as error:
            raise PreApplyError(f"{error}; {unit.key} is not started") from error
        return start(lambda: self.began.add(unit.key))

    def proven(self, unit: str) -> str | None:
        """What the unit's result line says of its snapshot, once one was proven."""
        return f"snapshot {short_snapshot(self.taken[unit])} proven" if unit in self.taken else None

    def way_back(self) -> str | None:
        """The way back of every unit of the run that holds a snapshot."""
        lines = (
            _way_back(unit, snapshot, unit in self.began) for unit, snapshot in self.taken.items()
        )
        return "; ".join(filter(None, lines)) or None


def _way_back(unit: str, snapshot: str | None, recreating: bool) -> str | None:
    """Once the unit's snapshot was proven, it by name; once its recreate has begun, also how its
    database goes back to it. Before that nothing was changed, and loading it would lose what the
    database took since."""
    if snapshot is None:
        return None
    short = short_snapshot(snapshot)
    if not recreating:
        return f"{unit}: pre-apply snapshot {short} taken"
    restore = f"{command(Verb.RESTORE)} {unit} --live --snapshot {short}"
    return f"pre-apply snapshot {short}, `{restore}` loads it"
