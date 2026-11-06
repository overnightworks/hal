"""What each unit needs to become what the catalog says, and how one unit is switched."""

import dataclasses
import shutil
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple, Protocol

from hal.stack import barrier, built_image, catalog, compose, core, switches


class Action(StrEnum):
    ON = "on"
    OFF = "off"
    STAYS_STOPPED = "stays stopped"


@dataclass(frozen=True)
class UnitPlan:
    unit: catalog.Unit
    action: Action
    services: tuple[str, ...]
    volumes: tuple[str, ...]
    switched_off_since: str | None = None
    running: bool = False
    snapshot: DatabaseUnit | None = None  # a switch-on that takes this unit's snapshot first
    creates_app: bool = False  # ... and whose start then creates the app, which has no container


@dataclass(frozen=True)
class Fleet:
    """What `fleet.yaml` and Compose say about this repository's units."""

    config: Mapping[str, Any]
    profile_services: Mapping[str, tuple[str, ...]]
    units: tuple[catalog.Unit, ...]


def read_fleet(engine: compose.Compose, repository: Path) -> Fleet:
    config = engine.resolved_configuration()
    profile_services = compose.profile_services(config)
    return Fleet(config, profile_services, catalog.load(repository, profile_services))


def plan_switches(
    units: Sequence[catalog.Unit],
    profile_services: Mapping[str, tuple[str, ...]],
    config: Mapping[str, Any],
    states: Mapping[str, set[str]],
    switched_off: Mapping[str, str | None],
) -> list[UnitPlan]:
    """What each unit needs to become what the catalog says; a unit already so is left out.

    `switched_off` maps a switched-off unit to the time of its switch, None when only its barrier
    stands: that unit is never started, and an enabled one is listed as staying stopped.
    """
    plans = []
    for unit in units:
        services = profile_services[unit.key]
        since = switched_off.get(unit.key)
        if unit.enabled and unit.key in switched_off:
            action = Action.STAYS_STOPPED
        elif unit.enabled and not compose.is_up(states, config, services):
            action = Action.ON
        elif not unit.enabled and not compose.is_gone(states, services):
            action = Action.OFF
        else:
            continue
        volumes = unit_volumes(config, services)
        running = compose.has_running_container(states, services)
        plans.append(UnitPlan(unit, action, services, volumes, since, running))
    return plans


def unit_volumes(config: Mapping[str, Any], services: Sequence[str]) -> tuple[str, ...]:
    """The compose volume keys the unit's services mount, sorted."""
    return tuple(
        sorted({v for name in services for v in compose.named_volumes(config["services"][name])})
    )


def plan_switch_on_snapshots(
    plans: Sequence[UnitPlan],
    fleet: Fleet,
    states: Mapping[str, set[str]],
    engine: compose.Compose,
    database_units: Collection[DatabaseUnit],
) -> list[UnitPlan]:
    """The plans, each switch-on that starts a database unit over its data with the unit's
    snapshot first (`snapshot_before_start`), and whether its start then creates the app."""
    planned = []
    for plan in plans:
        unit = (
            snapshot_before_start(fleet, plan.unit.key, states, engine, database_units)
            if plan.action is Action.ON
            else None
        )
        creates_app = unit is not None and unit.service not in states
        planned.append(dataclasses.replace(plan, snapshot=unit, creates_app=creates_app))
    return planned


def snapshot_before_start(
    fleet: Fleet,
    key: str,
    states: Mapping[str, set[str]],
    engine: compose.Compose,
    database_units: Collection[DatabaseUnit],
) -> DatabaseUnit | None:
    """The database unit `key` when its start would create its app or database service, which
    has no container, while a volume of the unit (for Keycloak and LiteLLM their database's)
    exists: the image that last read that data is unknown then, so the unit's pre-apply snapshot
    comes before the app starts. A unit with all its containers, or with no volume yet, has
    nothing to protect from a new image."""
    unit = next((unit for unit in database_units if unit.key == key), None)
    if unit is None or {unit.service, unit.database} <= states.keys():
        return None
    volumes = unit_volumes(fleet.config, fleet.profile_services[key])
    names = (compose.volume_name(fleet.config, volume) for volume in volumes)
    return unit if any(map(engine.volume_exists, names)) else None


def services_to_start(
    fleet: Fleet,
    key: str,
    engine: compose.Compose,
    database_units: Collection[DatabaseUnit],
) -> tuple[tuple[str, ...], DatabaseUnit | None]:
    """The services `hal start` starts for the unit `key`, and the database unit whose data they
    would be created over; then none start, since a switch-on over data is `hal apply`'s, after
    its snapshot."""
    over = snapshot_before_start(fleet, key, engine.states(), engine, database_units)
    return ((), over) if over else (fleet.profile_services[key], None)


DIGEST_SEPARATOR = "@"


def unit_gates(
    units: Sequence[catalog.Unit], switched_off: Mapping[str, str | None]
) -> dict[str, core.Gate]:
    """Each catalogued unit's gate for its followers: on while enabled and not switched off,
    whether or not it is up (#89)."""
    return {unit.key: _gate(unit, switched_off) for unit in units}


def _gate(unit: catalog.Unit, switched_off: Mapping[str, str | None]) -> core.Gate:
    if unit.key in switched_off:
        return core.Gate.SWITCHED_OFF
    if not unit.enabled:
        return core.Gate.OFF
    return core.Gate.ON


def switched_off_units(
    fleet: Fleet, read: Mapping[str, switches.Mark | None], repository: Path
) -> dict[str, str | None]:
    """Each unit switched off by its marker (its time) or by a barrier a stop left (None)."""
    switched_off = {}
    for unit in fleet.units:
        mark = read[unit.key]
        services = fleet.profile_services[unit.key]
        ingress = barrier.Barrier.of_unit(fleet.config, services, repository, unit)
        if barrier.switched_off(mark, ingress):
            switched_off[unit.key] = mark.since if mark else None
    return switched_off


@dataclass(frozen=True)
class ImageReference:
    """An image as the plan names it: its name and tag, and the digest hex that tells two
    builds of one tag apart when it is known."""

    name: str
    digest: str | None

    @classmethod
    def parse(cls, reference: str) -> ImageReference:
        name, separator, digest = reference.partition(DIGEST_SEPARATOR)
        return cls(name, cls.digest_hex(digest) if separator else None)

    @staticmethod
    def digest_hex(digest: str) -> str:
        return digest.rpartition(":")[2]


@dataclass(frozen=True)
class KeptImage:
    """A live service of a unit that runs another image than compose.yaml names now."""

    service: str
    running: ImageReference
    configured: ImageReference


def plan_kept_images(
    units: Sequence[catalog.Unit],
    profile_services: Mapping[str, tuple[str, ...]],
    config: Mapping[str, Any],
    containers: Sequence[compose.Container],
    plans: Sequence[UnitPlan],
    planned_elsewhere: Collection[str],
) -> list[KeptImage]:
    """Each live service of a unit whose container's image is not the exact reference its
    resolved definition names, in catalog and file order (#91 rules 2, 3). The core has no
    profile, the services in `planned_elsewhere` (the followers and the built services) have their
    own plan, a unit planned off loses its containers, a built unit that stays stopped is edge's to
    build and only shown as stopped, and a service whose definition names no image has no pin to
    compare. `plan_recreates` moves those of a database unit's app or database service (#995)."""
    planned_off = {plan.unit.key for plan in plans if plan.action is Action.OFF}
    built_and_stopped = {
        plan.unit.key
        for plan in plans
        if plan.action is Action.STAYS_STOPPED and plan.unit.build is not None
    }
    live = [container for container in containers if container.live]
    kept: dict[KeptImage, None] = {}
    for unit in units:
        if unit.key not in planned_off | built_and_stopped:
            services = [
                service
                for service in profile_services[unit.key]
                if service not in planned_elsewhere
            ]
            kept.update(dict.fromkeys(_kept_images_of(services, config, live)))
    return list(kept)


def _kept_images_of(
    services: Sequence[str], config: Mapping[str, Any], live: Sequence[compose.Container]
) -> Iterator[KeptImage]:
    for service in services:
        configured = config["services"][service].get("image")
        if configured is None:
            continue
        for running in _running_images(service, live):
            if running != configured:
                yield KeptImage(
                    service, ImageReference.parse(running), ImageReference.parse(configured)
                )


def _running_images(service: str, live: Sequence[compose.Container]) -> list[str]:
    """The images the service's live containers were created from; a ps line naming none cannot
    be compared, so it cannot be planned, as a missing label is (#87)."""
    images = []
    for container in live:
        if container.service != service:
            continue
        if container.image is None:
            raise compose.ComposeError(
                f"a live {service} container's `docker compose ps` line names no Image"
            )
        images.append(container.image)
    return images


@dataclass(frozen=True)
class Recreate:
    """A live service of a unit that runs on whose compose definition changed, or the app or
    database service of a database unit whose container runs another image than compose.yaml
    names (`moved`). `snapshot` is set on the first recreate of a unit with a move: the unit's
    pre-apply snapshot is taken and proven before it."""

    unit: str
    service: str
    moved: KeptImage | None = None
    snapshot: DatabaseUnit | None = None


@dataclass(frozen=True)
class DatabaseUnit:
    """A unit whose service reads its own database; `name` is the service as a line says it."""

    key: str
    service: str
    database: str
    name: str


class Restart(StrEnum):
    SERVICE = "service"
    DATABASE = "database"


def restart_of(
    plans: Iterable[UnitPlan], recreates: Iterable[Recreate], unit: DatabaseUnit
) -> Restart | None:
    """What this run starts of `unit`, None when nothing: its service when the unit is switched
    on or the service recreated, else its database when only that is recreated. Any other service
    of the unit counts as neither."""
    if any(plan.unit.key == unit.key and plan.action is Action.ON for plan in plans):
        return Restart.SERVICE
    services = {recreate.service for recreate in recreates if recreate.unit == unit.key}
    if unit.service in services:
        return Restart.SERVICE
    if unit.database in services:
        return Restart.DATABASE
    return None


class RecreatePlans(NamedTuple):
    recreates: list[Recreate]
    moved: list[KeptImage]


def plan_recreates(
    units: Sequence[catalog.Unit],
    profile_services: Mapping[str, tuple[str, ...]],
    config: Mapping[str, Any],
    containers: Sequence[compose.Container],
    hashes: Mapping[str, str],
    plans: Sequence[UnitPlan],
    planned_elsewhere: Collection[str],
    kept: Sequence[KeptImage],
    image_id: Callable[[str], str],
    database_units: Collection[DatabaseUnit],
) -> RecreatePlans:
    """Each live service of an enabled unit that is not switched on, off or kept stopped by a
    plan, whose container is labelled with another definition hash than `hashes` (from
    `docker compose config --hash`), in catalog order and, within a unit, after the services it
    depends on. The services in `planned_elsewhere` have their own plan, a service whose image
    differs is only named (#91), and a container without the label cannot be planned (#376). A
    reference that is not pinned by digest may name another image than the container runs (a
    rebuilt local tag), which a recreate would swap in: that service is named, not recreated.
    The app or database service of one of `database_units` whose image differs is recreated onto
    it instead, after the unit's pre-apply snapshot (#995)."""
    planned = {plan.unit.key for plan in plans}
    databases = {unit.key: unit for unit in database_units}
    live = [container for container in containers if container.live]
    recreates: list[Recreate] = []
    moved: list[KeptImage] = []
    for unit in units:
        if unit.enabled and unit.key not in planned:
            planner = _UnitRecreates(config, live, hashes, image_id, databases.get(unit.key))
            recreates.extend(
                planner.of(unit.key, profile_services[unit.key], planned_elsewhere, kept, moved)
            )
    return RecreatePlans(recreates, moved)


@dataclass(frozen=True)
class _UnitRecreates:
    """The recreates of one unit; `database` is the unit when it is a database unit."""

    config: Mapping[str, Any]
    live: Sequence[compose.Container]
    hashes: Mapping[str, str]
    image_id: Callable[[str], str]
    database: DatabaseUnit | None

    def of(
        self,
        unit: str,
        profile: Sequence[str],
        planned_elsewhere: Collection[str],
        kept: Sequence[KeptImage],
        moved: list[KeptImage],
    ) -> list[Recreate]:
        """Its recreates in dependency order, the first after its snapshot when an image moves;
        each named image swap of an unpinned tag joins `moved`."""
        moves = self._moves(kept)
        kept_services = {image.service for image in kept}
        services = [
            service
            for service in profile
            if service not in planned_elsewhere
            and (service in moves or service not in kept_services)
        ]
        changed = core.changed_definitions(self.live, services, self.hashes)
        recreates: list[Recreate] = []
        for service in core.dependency_order(self.config, services):
            if service in moves:
                recreates.append(Recreate(unit, service, moves[service]))
            elif service in changed:
                swapped = _swapped_image(service, self.config, self.live, self.image_id)
                if swapped is None:
                    recreates.append(Recreate(unit, service))
                elif swapped not in moved:
                    moved.append(swapped)
        if moves:
            recreates[0] = dataclasses.replace(recreates[0], snapshot=self.database)
        return recreates

    def _moves(self, kept: Sequence[KeptImage]) -> dict[str, KeptImage]:
        """The app and database service whose image differs, each with its first kept image."""
        if self.database is None:
            return {}
        movable = (self.database.service, self.database.database)
        moves: dict[str, KeptImage] = {}
        for image in kept:
            if image.service in movable:
                moves.setdefault(image.service, image)
        return moves


def _swapped_image(
    service: str,
    config: Mapping[str, Any],
    live: Sequence[compose.Container],
    image_id: Callable[[str], str],
) -> KeptImage | None:
    """The service when a recreate would run another image than its container runs now: its
    reference is not pinned by digest and names another image id than the container was created
    from."""
    reference = config["services"][service].get("image")
    if reference is None or DIGEST_SEPARATOR in reference:
        return None
    current = image_id(reference)
    for container in live:
        if container.service != service:
            continue
        if container.image_id is None:
            raise compose.ComposeError(
                f"a live {service} container has no {compose.IMAGE_ID_LABEL} label"
            )
        if container.image_id != current:
            return KeptImage(
                service,
                ImageReference(reference, ImageReference.digest_hex(container.image_id)),
                ImageReference(reference, ImageReference.digest_hex(current)),
            )
    return None


class UnitServicePlans(NamedTuple):
    built: list[built_image.BuiltRecreate]
    recreates: list[Recreate]
    images: list[KeptImage]


def plan_unit_services(
    fleet: Fleet,
    containers: Sequence[compose.Container],
    hashes: Mapping[str, str],
    plans: Sequence[UnitPlan],
    followers: Collection[str],
    gates: Mapping[str, core.Gate],
    engine: compose.Compose,
    database_units: Collection[DatabaseUnit],
) -> UnitServicePlans:
    """What the services of the units need besides their switch: the built service is recreated
    onto its image, every other live service whose definition changed is recreated, the app or
    database service of a database unit whose image differs is recreated onto it after the
    unit's snapshot, and every other whose image differs is named (#91, #995)."""
    built_services = built_image.built_services(
        fleet.units, fleet.profile_services, fleet.config, gates
    )
    built = built_image.plan_built_images(
        built_services, fleet.config, containers, hashes, engine.built_image_id
    )
    planned_elsewhere = {*followers, *built_services.values()}
    images = plan_kept_images(
        fleet.units, fleet.profile_services, fleet.config, containers, plans, planned_elsewhere
    )
    recreates, moved = plan_recreates(
        fleet.units,
        fleet.profile_services,
        fleet.config,
        containers,
        hashes,
        plans,
        planned_elsewhere,
        images,
        engine.image_id,
        database_units,
    )
    moving = {recreate.service for recreate in recreates if recreate.moved}
    named = [image for image in images if image.service not in moving]
    return UnitServicePlans(built, recreates, [*named, *moved])


type Show = Callable[[str, str], None]  # the live line's `show(subject, text)`


def _shows_nothing(_subject: str, _text: str) -> None:
    """The live line of a run that draws none."""


@dataclass
class Progress:
    unit: str = ""
    show: Show = _shows_nothing
    _step: str = field(default="", init=False)

    def begin(self, step: str) -> None:
        """The only way to set the step the Ctrl-C row names; it shows the step under the subject
        on the live line, with the same words."""
        self._step = step
        self.show(self.subject, step)

    @property
    def step(self) -> str:
        return self._step

    @property
    def subject(self) -> str:
        return self.unit or CORE_SUBJECT


@dataclass(frozen=True)
class NotWritten:
    """A file step that could not write `path`, and why."""

    subject: str
    path: Path
    reason: str

    @classmethod
    def from_error(cls, subject: str, path: Path, error: OSError) -> NotWritten:
        """A `shutil.Error` has no `strerror` and carries the failed entries as (source,
        destination, reason): a full disk fails them all alike, so the first reason is the
        cause."""
        entries = error.args[0] if isinstance(error, shutil.Error) and error.args else None
        if isinstance(entries, list) and entries:
            return cls(subject, path, entries[0][2])
        return cls(subject, path, error.strerror or str(error))

    @property
    def fact(self) -> str:
        return f"could not write {self.path} ({self.reason})"


CORE_SUBJECT = "core"


@dataclass(frozen=True)
class SeenDown:
    """Services found not running within the watch of the recreate of `recreated`, or of the
    unit's start when that is None, in start order; `way_back` is the unit snapshot's way back
    once one was proven."""

    services: tuple[compose.DownService, ...]
    watch_seconds: float
    recreated: str | None
    way_back: str | None = None


@dataclass(frozen=True)
class StoppedMeanwhile:
    """A core service planned for a recreate that has no live container now."""

    service: str


class NotDone(StrEnum):
    RECREATED = "recreated"
    STARTED = "started"


@dataclass(frozen=True)
class SwitchedOffMeanwhile:
    """`unit` was switched off since the plan was read (`since`), so `service` is `left` undone."""

    unit: str
    since: str
    service: str
    way_back: str | None = None
    left: NotDone = NotDone.RECREATED


@dataclass(frozen=True)
class NotOff:
    """A unit switched off that still has a container of its services."""

    unit: str
    way_back: str | None = None


@dataclass(frozen=True)
class StepFailed:
    """A step of the apply that failed with `cause`; `subject` is the service or unit it worked
    on, `core` while none is set."""

    subject: str
    step: str
    cause: str
    way_back: str | None = None

    @classmethod
    def at(cls, progress: Progress, error: Exception) -> StepFailed:
        return cls(progress.subject, progress.step, str(error))


@dataclass(frozen=True)
class Interrupted:
    """A Ctrl-C while the apply worked on `subject` (`core` while none is set) at `step`; the
    notes are those the interrupt carried."""

    subject: str
    step: str
    notes: tuple[str, ...]
    way_back: str | None = None

    @classmethod
    def at(
        cls, progress: Progress, interruption: KeyboardInterrupt, *, way_back: str | None = None
    ) -> Interrupted:
        notes = tuple(getattr(interruption, "__notes__", ()))
        return cls(progress.subject, progress.step, notes, way_back)


type RecreateFailure = SeenDown | SwitchedOffMeanwhile | StepFailed
type CoreFailure = RecreateFailure | StoppedMeanwhile | barrier.BarriersUnproven
type SwitchFailure = RecreateFailure | NotOff


type Begin = Callable[[], None]  # told under the switch lock, right before the start


class SnapshotFirst(Protocol):
    """Takes and proves `unit`'s pre-apply snapshot, then runs `start` with what it is told
    when the start over the data begins; what `start` returns."""

    def __call__(self, unit: DatabaseUnit, start: Callable[[Begin], str | None]) -> str | None: ...


def switch(
    engine: compose.Compose,
    plan: UnitPlan,
    progress: Progress,
    marks: switches.Switches,
    read: Mapping[str, switches.Mark | None],
    snapshot_first: SnapshotFirst,
) -> SwitchedOffMeanwhile | None:
    """Switch one unit; the services of a switch-on that a switch appeared meanwhile withheld,
    with its time, when the unit stays down. A switch-on with a snapshot starts the unit's
    database alone for it, then the rest."""
    progress.unit = plan.unit.key
    if plan.action is Action.ON:
        starter = _Starter(engine, plan, progress, marks, read[plan.unit.key])
        if plan.snapshot is None:
            return _withheld(plan, starter.start(plan.services, "start"), plan.services)
        database = plan.snapshot.database
        if since := starter.start((database,), f"start {database} alone"):
            return _withheld(plan, since, plan.services)
        rest = tuple(service for service in plan.services if service != database)
        since = snapshot_first(
            plan.snapshot,
            lambda begin: starter.start(
                plan.services, "start", begin if plan.creates_app else None
            ),
        )
        return _withheld(plan, since, rest)
    progress.begin("stop")
    engine.stop(plan.unit.key, plan.services)
    progress.begin("remove the containers")
    engine.remove_containers(plan.unit.key, plan.services)
    return None


def _withheld(
    plan: UnitPlan, since: str | None, not_started: tuple[str, ...]
) -> SwitchedOffMeanwhile | None:
    if since is None:
        return None
    return SwitchedOffMeanwhile(plan.unit.key, since, ", ".join(not_started), left=NotDone.STARTED)


@dataclass(frozen=True)
class _Starter:
    engine: compose.Compose
    plan: UnitPlan
    progress: Progress
    marks: switches.Switches
    read: switches.Mark | None

    def start(self, services: tuple[str, ...], step: str, begin: Begin | None = None) -> str | None:
        """Start `services` of the unit under the switch lock; the time of a switch that
        appeared since the plan read its mark, and nothing started then."""
        self.progress.begin(step)
        with self.marks.lock():
            if changed := self.marks.changed(self.plan.unit.key, self.read):
                return since_of(changed)
            if begin:
                begin()
            self.engine.start(self.plan.unit.key, services)
        return None


def since_of(changed: switches.Changed) -> str:
    """The time of a switch that appeared after the plan was read."""
    return changed.current.since if changed.current else switches.UNKNOWN_SWITCH_TIME


def unobserved(
    engine: compose.Compose,
    plans: Sequence[UnitPlan],
    config: Mapping[str, Any],
    watch: compose.Watch,
) -> dict[str, SeenDown | NotOff]:
    """The plans whose result is not observed, by unit, in plan order: a unit switched on counts
    only when its services stay up through the watch, the way a recreated core service does."""
    switched_on = [plan for plan in plans if plan.action is Action.ON]
    watched = tuple(dict.fromkeys(service for plan in switched_on for service in plan.services))
    down = engine.containers_down_while_watched(config, watched, watch) if watched else ()
    states = engine.states()
    failures: dict[str, SeenDown | NotOff] = {}
    for plan in plans:
        if plan.action is Action.ON:
            if seen := tuple(found for found in down if found.service in plan.services):
                failures[plan.unit.key] = SeenDown(seen, watch.seconds, None)
        elif not compose.is_gone(states, plan.services):
            failures[plan.unit.key] = NotOff(plan.unit.key)
    return failures
