"""The apps of the catalog: what `hal apply` plans for them and how it runs the plan (#255).

An app is switched on at the newest release of its repository: a `vYYYY.MM.DD.N` tag on origin's
default branch (`releases.py`), checked out in `~/srv/<key>` (`deploy_checkout.py`) and run by
Compose as project `<key>` (`app_compose.py`). The plan shows the tag and waits for the
operator's `yes`, which is the gate: whoever can put a tag on a merged commit offers code to run
here (E1). Nothing of an app is read, created or printed that is a secret, and no output of
Compose is printed (E7).

What was last deployed is the record `<state>/deployed/<key>` (tag, sha, time), written only once
every container is observed settled: running, and healthy where it has a healthcheck. What runs is
observed separately, file-free, from the project's containers. "Nothing to change" holds only when
the record, the newest release and the checkout's HEAD agree and every service has exactly one
settled container.

The compose file of the release is held to the contract of `app_contract.py` before anything is
built, and the images' volumes are checked after build and pull, before `create`. A one-shot service
and a `depends_on` that waits for health or completion are refused. A new tag that fails stays: the
run is partial and the fix is a newer tag.

An app that `hal stop` switched off (its marker, or the barrier a stop left) is never planned: no
fetch, no checkout, no build; one file-free `ps` asks whether it still runs, and apply refuses the
whole run while it does. A stop that comes in after the plan wins: the marker and the barrier
are looked at again before the checkout, under the switch lock around `create` and `start`
together, and under it once more after the health wait; from `create` on, the off step removes
whatever started. A stop that comes in while the lock is held waits for it, then stops what
started. The health wait runs outside the lock, so a stop never waits for it.

An app the catalog disables while containers of its project exist is switched off: file-free
`stop` and `rm -f` of project `<key>`, which reaches every container, whatever the checkout's
compose file says. The named volumes, the checkout and the record are never touched (E4).
"""

import json
from collections import Counter
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
from pathlib import Path

from hal.stack import (
    app_compose,
    app_contract,
    barrier,
    catalog,
    checkout,
    compose,
    deploy_checkout,
    releases,
    switches,
)
from hal.stack.unit_plans import Fleet, Progress

HEALTH_SECONDS = 300.0
HEALTH_POLL_SECONDS = 2.0
_SHA = 40


class AppError(Exception):
    """An app cannot be planned; the message is one line that names the entry."""


@dataclass(frozen=True)
class Deployment:
    """The last successful deployment of an app."""

    tag: str
    sha: str
    at: str


@dataclass(frozen=True)
class DeploymentRecord:
    directory: Path

    def read(self, key: str) -> Deployment | None:
        path = self.directory / key
        try:
            raw = path.read_text()
        except FileNotFoundError:
            return None
        except OSError as error:
            raise AppError(f"services.{key}: cannot read {path} ({error.strerror})") from error
        try:
            fields = json.loads(raw)
            deployment = Deployment(fields["tag"], fields["sha"], fields["time"])
            valid = releases.parse(deployment.tag) and _is_sha(deployment.sha)
        except (ValueError, KeyError, TypeError):
            valid = False
        if not valid:
            raise AppError(f"services.{key}: {path} is not a record of a deployment")
        return deployment

    def write(self, key: str, deployment: Deployment) -> None:
        """Atomically, mode 0600; raises OSError."""
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        fields = {"tag": deployment.tag, "sha": deployment.sha, "time": deployment.at}
        switches.write_atomically(self.directory / key, json.dumps(fields), keep_existing=False)


def _now() -> datetime:
    return datetime.now().astimezone()


@dataclass(frozen=True)
class AppRuntime:
    """Where apps are checked out and how git, docker and the clock are reached."""

    srv: Path
    record: DeploymentRecord
    git: checkout.Runner = checkout.run_git
    docker: compose.Runner = compose.run_docker
    health: compose.Watch = field(default_factory=lambda: compose.Watch(seconds=HEALTH_SECONDS))
    now: Callable[[], datetime] = _now

    @classmethod
    def of(cls, home: Path, state_directory: Path) -> "AppRuntime":
        return cls(home / "srv", DeploymentRecord(state_directory / "deployed"))


class AppKind(StrEnum):
    ON = "on"  # no deployment is recorded
    START_AGAIN = "start again"  # the recorded commit is the planned one
    UPDATE = "update"  # the recorded commit is another one


@dataclass(frozen=True)
class AppPlan:
    app: catalog.App
    release: releases.Release
    sha: str
    services: tuple[str, ...]
    url: str
    ingress: barrier.Barrier
    kind: AppKind
    recorded_tag: str | None  # None on the first deployment
    unfinished: str | None  # the tag or head an update did not reach, None when none


@dataclass(frozen=True)
class OffPlan:
    """An app the catalog disables while containers of its project exist."""

    app: catalog.App


@dataclass(frozen=True)
class StaysStoppedNote:
    key: str
    since: str | None  # None when only the barrier stands


@dataclass(frozen=True)
class SkippedNote:
    key: str
    skipped: releases.SkippedTag


@dataclass(frozen=True)
class AppOn:
    """The app is on and recorded; `seconds` is the run, from checkout to record."""

    plan: AppPlan
    seconds: float


@dataclass(frozen=True)
class AppFailed:
    subject: AppPlan | OffPlan
    cause: str


@dataclass(frozen=True)
class AppHeldOff:
    """A stop won: running apply again would change nothing, only `hal start` ends it."""

    plan: AppPlan
    cause: str


type AppResult = AppOn | AppFailed | AppHeldOff


@dataclass(frozen=True)
class AppsPlan:
    runtime: AppRuntime
    plans: tuple[AppPlan, ...] = ()
    kept: tuple[StaysStoppedNote | SkippedNote, ...] = ()
    offs: tuple[OffPlan, ...] = ()
    catalogued: tuple[catalog.App, ...] = ()  # every app of the catalog, for its barriers
    switched_off_still_running: tuple[str, ...] = ()  # the keys apply refuses to go on with

    @property
    def changes_nothing(self) -> bool:
        return not self.plans and not self.offs

    def run(self, marks: switches.Switches, progress: Progress) -> Iterator[AppResult]:
        """Each app in turn, the ones switched off first, with the result of its run. An app
        switched off yields only a failure."""
        for off in self.offs:
            if failure := _switch_off(off.app.key, self.runtime, progress):
                yield AppFailed(off, failure)
        for plan in self.plans:
            yield _run(plan, self.runtime, marks, progress)


def plan_apps(
    repository: Path, fleet: Fleet, runtime: AppRuntime, marks: switches.Switches
) -> AppsPlan:
    """The plan of every enabled app: it fetches each app's origin and writes only `.git`. An
    app that is on as it should be is left out; one that cannot be planned raises AppError. A
    disabled app is asked file-free for its containers and fetches nothing, and so is an app its
    marker or its barrier keeps off: it is named and left alone, unless its containers still run,
    which apply refuses."""
    document = catalog.read(repository / catalog.FLEET_FILE)
    every = catalog.apps(document, fleet.profile_services, fleet.config["name"])
    offs = [off for app in every if not app.enabled if (off := _plan_off(app, runtime))]
    enabled = [app for app in every if app.enabled]
    if not enabled:
        return AppsPlan(runtime, offs=tuple(offs), catalogued=every)
    organisation = catalog.github_org(document)
    plans, notes, still_running = [], [], []
    for app in enabled:
        ingress = _ingress_of(app, fleet, repository)
        if stopped := _stays_stopped_note(app.key, marks, ingress):
            notes.append(stopped)
            if _runs(app, runtime):
                still_running.append(app.key)
            continue
        planned, skipped = _plan_one(app, organisation, runtime, ingress)
        notes += [SkippedNote(app.key, one) for one in skipped]
        if planned:
            plans.append(planned)
    return AppsPlan(runtime, tuple(plans), tuple(notes), tuple(offs), every, tuple(still_running))


def _ingress_of(app: catalog.App, fleet: Fleet, repository: Path) -> barrier.Barrier:
    try:
        return barrier.Barrier.of_app(fleet.config, repository, app)
    except barrier.BarrierError as error:
        raise AppError(f"services.{app.key}: {error}") from error


def _stays_stopped_note(
    key: str, marks: switches.Switches, ingress: barrier.Barrier
) -> StaysStoppedNote | None:
    """The note for an app its marker or its standing barrier keeps off; None when it is on."""
    mark = marks.mark(key)
    if not barrier.switched_off(mark, ingress):
        return None
    return StaysStoppedNote(key, mark.since if mark else None)


def _runs(app: catalog.App, runtime: AppRuntime) -> bool:
    """Whether a container of the app's project runs, asked file-free."""
    engine = app_compose.AppCompose(app.key, runtime.srv / app.key, runtime.docker)
    return any(compose.is_live(container.state) for container in engine.containers())


def _plan_off(app: catalog.App, runtime: AppRuntime) -> OffPlan | None:
    """None when no container of the project exists."""
    engine = app_compose.AppCompose(app.key, runtime.srv / app.key, runtime.docker)
    if not engine.containers():
        return None
    return OffPlan(app)


def _plan_one(
    app: catalog.App, organisation: str, runtime: AppRuntime, ingress: barrier.Barrier
) -> tuple[AppPlan | None, tuple[releases.SkippedTag, ...]]:
    url = f"https://github.com/{organisation}/{app.key}.git"
    app_checkout = deploy_checkout.AppCheckout(
        checkout.Git(runtime.srv / app.key, runtime.git), url, app.default_branch
    )
    try:
        app_checkout.prepare()
    except deploy_checkout.CheckoutRefused as error:
        raise AppError(f"services.{app.key}: ~/srv/{app.key} {error}") from error
    except checkout.GitError as error:
        raise AppError(f"services.{app.key}: {error}") from error
    try:
        app_checkout.fetch()
        tags = app_checkout.tags()
        choice = releases.choose(tags.mirrored, tags.on_branch, app.default_branch)
        if choice.newest is None:
            raise AppError(
                f"services.{app.key}: no {releases.GRAMMAR} release on origin "
                f"{app.default_branch}; the app's head cuts the first one"
            )
        release = choice.newest
        sha = app_checkout.commit_of(release.tag)
        recorded = runtime.record.read(app.key)
        _refuse_moved_tag(app_checkout, tags.mirrored, app.key, recorded)
        services = _contract_services(app, release.tag, app_checkout.compose_file(sha))
        engine = app_compose.AppCompose(app.key, runtime.srv / app.key, runtime.docker)
        containers = engine.containers()
        head = app_checkout.head()
    except (checkout.GitError, deploy_checkout.CheckoutRefused) as error:
        raise AppError(f"services.{app.key}: {error}") from error
    if recorded and recorded.sha == sha and head == sha and _settled(containers, services):
        return None, choice.skipped
    plan = AppPlan(
        app=app,
        release=release,
        sha=sha,
        services=services,
        url=url,
        ingress=ingress,
        kind=_kind_of(recorded, sha),
        recorded_tag=recorded.tag if recorded else None,
        unfinished=_unfinished_update(recorded, sha, release.tag, head),
    )
    return plan, choice.skipped


def _refuse_moved_tag(
    app_checkout: deploy_checkout.AppCheckout,
    mirrored: Sequence[str],
    key: str,
    recorded: Deployment | None,
) -> None:
    """A tag cannot be planned that names another commit on origin than when it was deployed."""
    if recorded is None or recorded.tag not in mirrored:
        return
    now = app_checkout.commit_of(recorded.tag)
    if now != recorded.sha:
        raise AppError(
            f"services.{key}: tag {recorded.tag} moved on origin; deployed {recorded.sha}, "
            f"origin now {now}"
        )


def _kind_of(recorded: Deployment | None, sha: str) -> AppKind:
    if recorded is None:
        return AppKind.ON
    return AppKind.START_AGAIN if recorded.sha == sha else AppKind.UPDATE


def _unfinished_update(
    recorded: Deployment | None, sha: str, tag: str, head: str | None
) -> str | None:
    """The tag or head an interrupted update was heading for, None when none was interrupted."""
    if recorded is None or recorded.sha == sha or head is None or head == recorded.sha:
        return None
    return tag if head == sha else head


def _settled(containers: Sequence[app_compose.AppContainer], services: Sequence[str]) -> bool:
    """Every service has exactly one container, settled, and no other container exists."""
    per_service = Counter(container.service for container in containers)
    return per_service == Counter(services) and all(c.settled for c in containers)


def _is_sha(text: str) -> bool:
    return len(text) == _SHA and all(digit in "0123456789abcdef" for digit in text)


def _contract_services(app: catalog.App, tag: str, text: str | None) -> tuple[str, ...]:
    try:
        return app_contract.check(text, app.key, tag, app.hosts)
    except app_contract.ContractError as error:
        raise AppError(str(error)) from error


class _SwitchedOffMeanwhile(Exception):
    """A stop, or a barrier, came in after the plan; the message is the line to report."""


def _require_on(plan: AppPlan, marks: switches.Switches) -> None:
    """Raises _SwitchedOffMeanwhile when the app's marker or its barrier stands now ."""
    mark = marks.mark(plan.app.key)
    if barrier.switched_off(mark, plan.ingress):
        since = f"since {switches.describe_since(mark.since)}; " if mark else ""
        raise _SwitchedOffMeanwhile(f"{since}not started")


def _run(
    plan: AppPlan, runtime: AppRuntime, marks: switches.Switches, progress: Progress
) -> AppResult:
    """Check out the release, build, create and start under the switch lock, wait for health
    outside it, record: the failure of the first step that fails, AppOn when the app is on and
    recorded. A stop that comes in meanwhile wins, wherever it comes in: the marker and the
    barrier are looked at before the checkout, under the lock around `create` and `start`, and
    under it again after the health wait; from `create` on, the off step removes what started,
    under the lock of that look, so a start that came in after it is never undone. `progress`
    names the step, so an interrupt can say where the containers may be partly replaced."""
    key, tag = plan.app.key, plan.release.tag
    progress.unit = key
    started = runtime.health.clock()
    engine = app_compose.AppCompose(key, runtime.srv / key, runtime.docker)
    try:
        progress.step = f"look whether {key} was switched off"
        _require_on(plan, marks)
        _build(plan, runtime, engine, progress)
        with marks.lock():
            _require_on(plan, marks)
            progress.step = f"create the containers at {tag}; they may be partly replaced"
            engine.create(tag)
            _start(plan, engine, runtime, marks, progress)
        failure = _wait_until_healthy(plan, runtime, engine, marks, progress)
        progress.step = f"record the deployment of {tag}"
        with marks.lock():
            _require_on_else_switch_off(plan, runtime, marks, progress)
            if failure is None:
                runtime.record.write(
                    key, Deployment(tag, plan.sha, runtime.now().isoformat(timespec="seconds"))
                )
        if failure:
            return AppFailed(plan, failure)
        return AppOn(plan, runtime.health.clock() - started)
    except _SwitchedOffMeanwhile as meanwhile:
        return AppHeldOff(plan, str(meanwhile))
    except app_contract.ContractError as error:
        return AppFailed(plan, str(error))
    except (checkout.GitError, compose.ComposeError, switches.SwitchError) as error:
        return AppFailed(plan, f"could not {progress.step}, {error}")
    except OSError as error:
        return AppFailed(plan, f"could not {progress.step} ({error.strerror})")


def _build(
    plan: AppPlan, runtime: AppRuntime, engine: app_compose.AppCompose, progress: Progress
) -> None:
    """Check out the release, build and pull, and hold the images' volumes to the contract."""
    key, tag = plan.app.key, plan.release.tag
    app_checkout = deploy_checkout.AppCheckout(
        checkout.Git(runtime.srv / key, runtime.git), plan.url, plan.app.default_branch
    )
    progress.step = f"check out {tag}"
    app_checkout.check_out(plan.sha)
    progress.step = f"build at {tag}"
    engine.build(tag)
    progress.step = f"pull at {tag}"
    engine.pull(tag)
    progress.step = f"check the volumes of the images at {tag}"
    app_contract.check_image_volumes(
        app_checkout.compose_file(plan.sha) or "", key, tag,
        engine.image_volumes(plan.services, tag),
    )  # fmt: skip


def _start(
    plan: AppPlan,
    engine: app_compose.AppCompose,
    runtime: AppRuntime,
    marks: switches.Switches,
    progress: Progress,
) -> None:
    """Start the created containers, under the switch lock; a failure is reported as a stop when
    one came in meanwhile."""
    progress.step = f"start at {plan.release.tag}; the containers may be partly replaced"
    try:
        engine.start(plan.release.tag)
    except compose.ComposeError:
        _require_on_else_switch_off(plan, runtime, marks, progress)
        raise


def _wait_until_healthy(
    plan: AppPlan,
    runtime: AppRuntime,
    engine: app_compose.AppCompose,
    marks: switches.Switches,
    progress: Progress,
) -> str | None:
    """Wait for the started containers to be settled, outside the switch lock; the failure line,
    None when all are settled. A stop that is seen ends the wait early; the look under the lock
    after it decides what the stop leaves."""
    key, tag = plan.app.key, plan.release.tag
    try:
        progress.step = f"wait for {key} to be healthy"
        unhealthy = unhealthy_after_waiting(
            engine, plan.services, runtime.health, lambda: _require_on(plan, marks)
        )
    except _SwitchedOffMeanwhile:
        return "was switched off and on again during the health wait; not recorded"
    except compose.ComposeError as error:
        return f"could not {progress.step}, {error}"
    if unhealthy:
        return (
            f"not healthy at {tag} after {runtime.health.seconds:g}s ({unhealthy}); "
            "the record stays, the fix is a newer tag"
        )
    return None


def _require_on_else_switch_off(
    plan: AppPlan, runtime: AppRuntime, marks: switches.Switches, progress: Progress
) -> None:
    """Under the switch lock, once containers were created: a stop that came in wins, and the off
    step removes whatever started before _SwitchedOffMeanwhile is raised, its own failure added."""
    try:
        _require_on(plan, marks)
    except _SwitchedOffMeanwhile as meanwhile:
        off_failure = _switch_off(plan.app.key, runtime, progress)
        line = f"{meanwhile}; {off_failure}" if off_failure else str(meanwhile)
        raise _SwitchedOffMeanwhile(line) from None


def _switch_off(key: str, runtime: AppRuntime, progress: Progress) -> str | None:
    """Stop, then remove, every container of the app's project: the failure line of the step that
    fails, None when none is left. The checkout, the record and every volume stay."""
    progress.unit = key
    engine = app_compose.AppCompose(key, runtime.srv / key, runtime.docker)
    try:
        progress.step = f"stop the containers of {key}"
        engine.stop()
        progress.step = f"remove the containers of {key}"
        engine.remove()
        progress.step = f"remove the one-off containers of {key}"
        removal_failure: compose.ComposeError | None = None
        if left := engine.containers():
            try:
                engine.remove_by_identifier([container.identifier for container in left])
            except compose.ComposeError as error:
                removal_failure = error
            left = engine.containers()
    except compose.ComposeError as error:
        return f"could not {progress.step}, {error}"
    if left:
        shown = ", ".join(container.describe() for container in left)
        reason = f" ({removal_failure})" if removal_failure else ""
        return f"could not remove every container of {key}, left: {shown}{reason}"
    return None


def unhealthy_after_waiting(
    engine: app_compose.AppCompose,
    services: Sequence[str],
    watch: compose.Watch,
    still_on: Callable[[], None],
) -> str | None:
    """The containers as last seen when they are not all settled by the deadline; None when
    they are. `still_on` is asked before every look and raises to end the wait early."""
    deadline = watch.clock() + watch.seconds
    while True:
        still_on()
        containers = engine.containers()
        if _settled(containers, services):
            return None
        if watch.clock() >= deadline:
            return ", ".join(c.describe() for c in containers) or "no container"
        watch.sleep(HEALTH_POLL_SECONDS)
