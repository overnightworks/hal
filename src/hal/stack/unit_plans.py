"""What each unit needs to become what the catalog says, and how one unit is switched."""

from collections.abc import Callable, Collection, Iterator, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, NamedTuple

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
        volumes = sorted(
            {v for name in services for v in compose.named_volumes(config["services"][name])}
        )
        running = compose.has_running_container(states, services)
        plans.append(UnitPlan(unit, action, services, tuple(volumes), since, running))
    return plans


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
    def parse(cls, reference: str) -> "ImageReference":
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
    compare."""
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
    """A live service of a unit that runs on whose compose definition changed."""

    unit: str
    service: str


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
) -> RecreatePlans:
    """Each live service of an enabled unit that is not switched on, off or kept stopped by a
    plan, whose container is labelled with another definition hash than `hashes` (from
    `docker compose config --hash`), in catalog order and, within a unit, after the services it
    depends on. The services in `planned_elsewhere` have their own plan, a service whose image
    differs is only named (#91), and a container without the label cannot be planned (#376). A
    reference that is not pinned by digest may name another image than the container runs (a
    rebuilt local tag), which a recreate would swap in: that service is named, not recreated."""
    planned = {plan.unit.key for plan in plans}
    kept_services = {image.service for image in kept}
    live = [container for container in containers if container.live]
    recreates: list[Recreate] = []
    moved: list[KeptImage] = []
    for unit in units:
        if not unit.enabled or unit.key in planned:
            continue
        services = [
            service
            for service in profile_services[unit.key]
            if service not in planned_elsewhere and service not in kept_services
        ]
        changed = core.changed_definitions(live, services, hashes)
        for service in core.dependency_order(config, services):
            if service not in changed:
                continue
            swapped = _swapped_image(service, config, live, image_id)
            if swapped is None:
                recreates.append(Recreate(unit.key, service))
            elif swapped not in moved:
                moved.append(swapped)
    return RecreatePlans(recreates, moved)


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
) -> UnitServicePlans:
    """What the services of the units need besides their switch: the built service is recreated
    onto its image, every other live service whose definition changed is recreated, and every
    other whose image differs is named (#91)."""
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
    )
    return UnitServicePlans(built, recreates, [*images, *moved])


@dataclass
class Progress:
    unit: str = ""
    step: str = ""


@dataclass(frozen=True)
class NotWritten:
    """A file step that could not write `path`, and why."""

    subject: str
    path: Path
    reason: str

    @classmethod
    def from_error(cls, subject: str, path: Path, error: OSError) -> "NotWritten":
        """A `shutil.Error` has no `strerror`; its text is the reason then."""
        return cls(subject, path, error.strerror or str(error))

    @property
    def fact(self) -> str:
        return f"could not write {self.path} ({self.reason})"


def switch(
    engine: compose.Compose,
    plan: UnitPlan,
    progress: Progress,
    marks: switches.Switches,
    read: Mapping[str, switches.Mark | None],
) -> str | None:
    """Switch one unit; the time of a switch that appeared meanwhile when the unit stays down."""
    progress.unit = plan.unit.key
    if plan.action is Action.ON:
        progress.step = "start"
        with marks.lock():
            if changed := marks.changed(plan.unit.key, read[plan.unit.key]):
                return since_of(changed)
            engine.start(plan.unit.key, plan.services)
        return None
    progress.step = "stop"
    engine.stop(plan.unit.key, plan.services)
    progress.step = "remove the containers"
    engine.remove_containers(plan.unit.key, plan.services)
    return None


def since_of(changed: switches.Changed) -> str:
    """The time of a switch that appeared after the plan was read."""
    return changed.current.since if changed.current else switches.UNKNOWN_SWITCH_TIME


def unobserved(
    engine: compose.Compose,
    plans: Sequence[UnitPlan],
    config: Mapping[str, Any],
    watch: compose.Watch,
) -> list[UnitPlan]:
    """The plans whose result is not observed: a unit switched on counts only when its services
    stay up through the watch, the way a recreated core service does."""
    switched_on = [plan for plan in plans if plan.action is Action.ON]
    watched = tuple(dict.fromkeys(service for plan in switched_on for service in plan.services))
    down = set(engine.down_while_watched(config, watched, watch)) if watched else set()
    states = engine.states()
    return [
        plan
        for plan in plans
        if (
            down.intersection(plan.services)
            if plan.action is Action.ON
            else not compose.is_gone(states, plan.services)
        )
    ]
