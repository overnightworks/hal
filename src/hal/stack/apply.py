"""`hal apply --local`: switches the units of this repository on or off from `fleet.yaml` and its
apps on at their newest release (`apps.py`).

Exit 0 applied and observed, or nothing to change; 1 refused, aborted, failed or partial;
2 cannot plan. The core (socket-proxy and traefik) comes first: a core service whose compose
definition changed (Compose's `config --hash` against its container's label) or whose recorded
file, today `traefik.yml`, changed since it was last applied is recreated together with the core
services that depend on it, socket-proxy first; each is observed running with what it depends on
and every active barrier proven again before its record is written and its success is said; one
without a live container is named and never started (#85, #87). After the core, a follower
(today traefik-mcp, a profile service binding a file at Traefik's static-config path) whose file or
definition changed is recreated alone while its unit is on, under the switch lock so a marker
stops it, and recorded once observed running; while its unit is off or switched off it is named
and nothing starts, and one that starts with its unit is recorded once the unit is on (#89).
A unit is a compose profile: on starts its services, off removes their containers. A live service of
a unit that is enabled and not switched off or on whose compose definition changed is recreated
alone after the followers, under the switch lock, one plan line each (#376). Volumes are never
touched. The built service of a unit with `run.build` (agent-service) whose container, in any
state, runs another image or definition than compose.yaml and its tag name now is recreated alone
after the followers, one plan line, and its running requests end (#482). A live service of any
other unit not planned off whose container runs another image than compose.yaml now names is named
after the unit lines and keeps running: its image is never swapped here, and the line alone asks
nothing (#91). A unit that would be switched on, or is enabled and
already runs, and is not set up is asked about separately; on `yes` its own setup command runs in
the operator's terminal (key material is made there, never here) and `--check` must then pass
before a fresh plan is shown. A unit with an emergency switch (`hal stop`) or a barrier a stop
left is never started and its switch is never cleared here: only `hal start` ends it. If it is
enabled in the catalog, declares a setup, and its containers still run while it is not set up,
the run is refused: nothing is asked or published.
An app (an entry with `repo`) is planned last, in the same plan and under the same `yes`: its
newest release tag is checked out, built, started and recorded once its containers are settled
(`apps.py`).
While `services.legal` is enabled the three legal pages are built from `legal/frame` and
`legal/sections` through the validator (`legal_step.py`); a refused section is exit 2, and the
plan names each page that is new or changes. After `yes` the pages are written to `legal/built/`
before any unit switches, which the legal unit serves. The appkit step (`appkit_step.py`) comes
first and runs with or without the legal unit: it writes the installed appkit's tokens and fonts
to `appkit-<version>/` in `legal/assets/` and in both Keycloak themes; a missing appkit is exit 2.

Before any of that it guards, in this order, each refusing with its own lines and nothing else
(#95): a terminal (exit 1); the live checkout `~/srv/hal`, since from any other tree it would bind
the live compose project to that tree (#79, exit 2); `apply.lock` in the state directory, held
non-blocking for the whole run, so a second apply or a `hal update` is refused (exit 1) while
`hal stop` and `hal start` never wait for it; HEAD on `main` (exit 2); a clean tree, every changed
path named (exit 2), since a change reaches the live checkout through a pull request.

Then it fetches origin's `main` through the operator's credential helper and pins its sha (#98): a
failed fetch is exit 2 with git's last error line; a checkout ahead of or beside it is exit 2,
nothing reset; a checkout behind it is exit 2 too, with the waiting commits counted and
`hal update` named, since the apply plans nothing with code that is about to be replaced. Only then
its `.env` is written when missing and otherwise named and left alone when it differs (exit 2,
#136). The checkout stands as one row, current; the plan that follows applies HEAD. Nothing in the
checkout changes: only `.git` gains the fetched objects, FETCH_HEAD and `origin/main`.
"""

import fcntl
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

from hal.output import (
    Glyph,
    Verdict,
    confirmed,
    counted,
    write_error,
    write_groups,
    write_row,
    write_verdict,
)
from hal.output.command import Verb, command
from hal.stack import barrier, catalog, checkout, compose, core, environment, setup, switches
from hal.stack.appkit_step import AppkitError, Rename, plan_appkit
from hal.stack.apps import AppError, AppRuntime, plan_apps, retry_command
from hal.stack.core_phase import CorePhase
from hal.stack.legal_section import LegalError
from hal.stack.legal_step import RECORD_FILE, plan_legal
from hal.stack.plan import Plan
from hal.stack.plan_rows import (
    ChangeNoun,
    PlanEvent,
    changes_in,
    checkout_row,
    environment_row,
    local_changes_row,
    plan_groups,
    still_runs_row,
    waiting_text,
)
from hal.stack.realm import reconcile
from hal.stack.result_rows import result_rows
from hal.stack.terminal import NEEDS_TERMINAL, at_terminal
from hal.stack.unit_plans import (
    Action,
    Progress,
    UnitPlan,
    plan_switches,
    plan_unit_services,
    read_fleet,
    switch,
    switched_off_units,
    unit_gates,
    unobserved,
)
from hal.stack.waiting import fetched

EnsureEnvironment = Callable[[Path], environment.Settings | None]
APPLY_LOCK = "apply.lock"
APPLY_RUNNING = (
    f"another `{command(Verb.APPLY)}` or `{command(Verb.UPDATE)}` is running; nothing changed"
)
_PRIVATE_DIRECTORY = 0o700
_PRIVATE_FILE = 0o600


class ApplyExit(IntEnum):
    APPLIED_OR_NOTHING = 0
    REFUSED = 1
    CANNOT_PLAN = 2


CANNOT_PLAN_ERRORS = (
    compose.ComposeError,
    catalog.CatalogError,
    barrier.BarrierError,
    core.CoreError,
    setup.SetupUnclear,
    switches.SwitchError,
    AppError,
    checkout.GitError,
    LegalError,
    AppkitError,
)


@dataclass(frozen=True)
class MissingSetup:
    unit: catalog.Unit
    check_line: str
    kept_stopped: bool = False


def _plan(
    engine: compose.Compose,
    marks: switches.Switches,
    record: core.Record,
    live: checkout.Git,
    app_runtime: AppRuntime,
    rename: Rename = os.rename,
) -> Plan:
    repository = live.tree
    fleet = read_fleet(engine, repository)
    tracked = core.Checkout.read(fleet.config, live)
    read = {unit.key: marks.mark(unit.key) for unit in fleet.units}
    switched_off = switched_off_units(fleet, read, repository)
    gates = unit_gates(fleet.units, switched_off)
    followers = core.follower_units(fleet.config, gates)
    running_services = (
        service
        for unit in fleet.units
        if gates[unit.key] is core.Gate.ON
        for service in fleet.profile_services[unit.key]
    )
    hashes = engine.config_hashes(
        tuple(dict.fromkeys((*core.core_services(fleet.config), *followers, *running_services)))
    )
    containers = engine.containers()
    states = compose.states_of(containers)
    plans = plan_switches(fleet.units, fleet.profile_services, fleet.config, states, switched_off)
    core_plans = core.plan_core(fleet.config, containers, hashes, tracked, record)
    follower_plans = core.plan_followers(fleet.config, containers, hashes, tracked, record, gates)
    unit_services = plan_unit_services(fleet, containers, hashes, plans, followers, gates, engine)
    realm = reconcile.plan_realm(
        reconcile.Observer(engine),
        record,
        fleet.config,
        tracked,
        gates.get(reconcile.REALM_UNIT),
        reconcile.restart_of(plans, unit_services.recreates),
    )
    app_plans = plan_apps(repository, fleet, app_runtime, marks)
    appkit = plan_appkit(repository, rename=rename)
    legal = plan_legal(repository, record.directory / RECORD_FILE, fleet)
    return Plan(
        fleet,
        tracked,
        read,
        core_plans,
        follower_plans,
        unit_services.built,
        unit_services.recreates,
        plans,
        unit_services.images,
        realm,
        app_plans,
        appkit,
        legal,
    )


def apply_local(
    state_directory: Path,
    engine: compose.Compose | None = None,
    repository: Path = compose.REPOSITORY,
    check: setup.SetupCheck = setup.run_setup_check,
    run_setup: setup.SetupRunner = setup.run_setup,
    home: Path | None = None,
    verifier: barrier.Verifier = barrier.PROVEN_OVER_HTTP,
    watch: compose.Watch = compose.SETTLED,
    git: checkout.Runner = checkout.run_git,
    ensure_environment: EnsureEnvironment = environment.ensure,
    realm_backup: reconcile.Backup | None = None,
    app_runtime: AppRuntime | None = None,
    rename: Rename = os.rename,
) -> int:
    started = verifier.clock()
    if not at_terminal():
        write_error(NEEDS_TERMINAL)
        return ApplyExit.REFUSED
    if refusal := checkout.not_live_checkout_line(repository, home or Path.home()):
        write_error(refusal)
        return ApplyExit.CANNOT_PLAN
    try:
        lock = take_apply_lock(state_directory)
    except OSError as error:
        write_error(f"cannot take {state_directory / APPLY_LOCK} ({error.strerror})")
        return ApplyExit.CANNOT_PLAN
    if lock is None:
        write_error(APPLY_RUNNING)
        return ApplyExit.REFUSED
    try:
        live = checkout.Git(repository, git)
        if not on_clean_main(live):
            return ApplyExit.CANNOT_PLAN
        if (origin := fetched(live, write_error)) is None or _waits_on_origin(origin):
            return ApplyExit.CANNOT_PLAN
        if not _environment_ready(repository, ensure_environment):
            return ApplyExit.CANNOT_PLAN
        write_row(checkout_row(origin))
        return _plan_and_apply(
            state_directory,
            engine,
            live,
            check,
            run_setup,
            verifier,
            watch,
            realm_backup or reconcile.Backup.installed(repository, _tell),
            app_runtime or AppRuntime.of(home or Path.home(), state_directory),
            rename,
            lambda: verifier.clock() - started,
        )
    finally:
        os.close(lock)


def _tell(line: str) -> None:
    print(line, flush=True)


def take_apply_lock(state_directory: Path) -> int | None:
    """The descriptor holding `apply.lock`, or None while another apply holds it; raises OSError.

    The file is private and never unlinked, so every apply locks the same inode; the descriptor
    is not inherited, so no child outlives the lock with it (#95 rule 4).
    """
    state_directory.mkdir(mode=_PRIVATE_DIRECTORY, parents=True, exist_ok=True)
    descriptor = os.open(
        state_directory / APPLY_LOCK, os.O_CREAT | os.O_WRONLY | os.O_CLOEXEC, _PRIVATE_FILE
    )
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    except BaseException:
        os.close(descriptor)
        raise
    return descriptor


def on_clean_main(git: checkout.Git) -> bool:
    """True on a born `main` with nothing changed; else False, after saying why (#95 rules 5, 6)."""
    if (refusal := checkout.not_clean_main(git)) is None:
        return True
    if refusal.paths:
        write_row(local_changes_row(refusal.paths))
        write_error(refusal.message, f"git -C {checkout.LIVE_CHECKOUT} status")
    else:
        write_error(refusal.message)
    return False


def _waits_on_origin(origin: checkout.Origin) -> bool:
    """True, after saying so, when origin's `main` has commits this checkout lacks: the apply
    plans nothing with code that is about to be replaced."""
    if origin.standing is not checkout.Standing.BEHIND:
        return False
    write_row(checkout_row(origin))
    write_error(
        f"{waiting_text(origin.behind)} {checkout.MAIN}; nothing changed", command(Verb.UPDATE)
    )
    return True


def _environment_ready(repository: Path, ensure_environment: EnsureEnvironment) -> bool:
    """True when `.env` holds the derived settings, written now or before; else False, after
    saying why (#136)."""
    try:
        written = ensure_environment(repository)
    except environment.EnvironmentRefused as refusal:
        write_error(str(refusal))
        return False
    if written:
        write_row(environment_row(written))
    return True


def _plan_and_apply(
    state_directory: Path,
    engine: compose.Compose | None,
    live: checkout.Git,
    check: setup.SetupCheck,
    run_setup: setup.SetupRunner,
    verifier: barrier.Verifier,
    watch: compose.Watch,
    realm_backup: reconcile.Backup,
    app_runtime: AppRuntime,
    rename: Rename,
    elapsed: Callable[[], float],
) -> int:
    repository = live.tree
    engine = engine or compose.Compose(repository=repository)
    marks = switches.Switches(state_directory)
    record = core.Record(state_directory)
    try:
        completed: list[str] = []
        while True:  # the plan made after the setups ran is held to the same refusals
            planned = _plan(engine, marks, record, live, app_runtime, rename)
            missing = _missing_setups(planned, repository, check)
            exit_code = _refusal(missing, planned, bool(completed))
            if exit_code is None:
                exit_code = _ask_and_run_setups(missing, repository, check, run_setup)
            if exit_code is not None:
                return exit_code
            if not missing:
                break
            completed = [m.unit.key for m in missing]
    except CANNOT_PLAN_ERRORS as error:
        write_error(f"cannot plan, {error}")
        return ApplyExit.CANNOT_PLAN
    if planned.changes_nothing:
        _write_plan(planned)
        if (realm := planned.realm).action is reconcile.RealmAction.UNREADABLE:
            write_error(
                f"realm: Keycloak could not be read; not checked ({realm.error})",
                command(Verb.APPLY),
            )
            return ApplyExit.REFUSED
        write_verdict(
            Verdict(
                Glyph.DONE,
                "nothing to change",
                (),
                details=("units and apps checked",),
                elapsed_seconds=elapsed(),
            )
        )
        return ApplyExit.APPLIED_OR_NOTHING
    return _confirm_and_switch(
        engine,
        planned,
        marks,
        CorePhase(record, repository, verifier, watch),
        completed,
        realm_backup,
    )


def _missing_setups(planned: Plan, repository: Path, check: setup.SetupCheck) -> list[MissingSetup]:
    """The enabled units whose `--check` says not set up, in catalog order.

    A unit whose containers already run is checked too: an interrupted setup leaves them up, and
    the publish must not follow before the setup is done. A unit kept stopped is checked only
    while its containers still run."""
    stopped = {p.unit.key: p.running for p in planned.plans if p.action is Action.STAYS_STOPPED}
    missing = []
    for unit in planned.fleet.units:
        if not unit.enabled or not stopped.get(unit.key, True):
            continue
        if line := setup.not_set_up_line(unit, repository, check):
            missing.append(MissingSetup(unit, line, kept_stopped=unit.key in stopped))
    return missing


def _refusal(missing: Sequence[MissingSetup], planned: Plan, setups_ran: bool) -> int | None:
    """REFUSED when a unit or app a stop keeps off still runs, or, after the setups ran, a unit
    is still not set up: none is started."""
    still_running = [
        *(still_runs_row(item.unit.key, item.check_line) for item in missing if item.kept_stopped),
        *(still_runs_row(key, "") for key in planned.app_plans.switched_off_still_running),
    ]
    if still_running:
        for row in still_running:
            write_row(row)
        write_error(
            "switched off but still running, nothing switched",
            command(Verb.STOP, still_running[0].subject),
        )
        return ApplyExit.REFUSED
    if setups_ran and missing:
        write_error(
            "; ".join(
                f"{item.unit.key} is not set up after the setups ran; nothing switched; "
                f"run `{item.unit.setup}` first; {item.check_line}"
                for item in missing
            ),
            command(Verb.APPLY),
        )
        return ApplyExit.REFUSED
    return None


def _ask_and_run_setups(
    missing: Sequence[MissingSetup],
    repository: Path,
    check: setup.SetupCheck,
    run_setup: setup.SetupRunner,
) -> int | None:
    """Ask for every setup first, then run them in turn; an exit code when the run ends here."""
    for item in missing:
        print(f"{item.unit.key} is not set up: {item.check_line}")
        if not confirmed(f"run `{item.unit.setup}` now"):
            write_error(f"aborted, nothing changed; run `{item.unit.setup}` yourself or answer yes")
            return ApplyExit.REFUSED
    for item in missing:
        if (exit_code := _run_one_setup(item, repository, check, run_setup)) is not None:
            return exit_code
    return None


def _run_one_setup(
    item: MissingSetup,
    repository: Path,
    check: setup.SetupCheck,
    run_setup: setup.SetupRunner,
) -> int | None:
    setup_command = item.unit.setup
    try:
        ran = run_setup(repository / str(setup_command), repository)
    except OSError as error:
        write_error(f"cannot start `{setup_command}`, {error}")
        return ApplyExit.CANNOT_PLAN
    if ran.interrupted:
        write_error(
            f"interrupted during `{setup_command}`; nothing switched; keys may already exist",
            command(Verb.APPLY),
            fresh_line=True,
        )
        return ApplyExit.REFUSED
    if ran.exit_code:
        write_error(
            f"`{setup_command}` failed (exit {ran.exit_code}); nothing switched; keys may "
            "already exist",
            command(Verb.APPLY),
        )
        return ApplyExit.REFUSED
    if line := setup.not_set_up_line(item.unit, repository, check):
        write_error(f"`{setup_command}` ran, still not set up: {line}")
        return ApplyExit.REFUSED
    return None


def _observe_and_record(
    engine: compose.Compose,
    planned: Plan,
    core_phase: CorePhase,
    started: Sequence[UnitPlan],
    progress: Progress,
) -> list[UnitPlan]:
    """The started plans not observed as planned; each unit observed on records the followers
    that started with it (#89, P15)."""
    progress.step = "observe the result"
    mismatched = unobserved(engine, started, planned.fleet.config, core_phase.watch)
    switched_on = [plan for plan in started if plan.action is Action.ON and plan not in mismatched]
    core_phase.record_switched_on(planned, switched_on, progress)
    return mismatched


def _realm_step(
    engine: compose.Compose,
    planned: Plan,
    marks: switches.Switches,
    core_phase: CorePhase,
    backup: reconcile.Backup,
) -> reconcile.Realm:
    return reconcile.Realm(
        engine,
        reconcile.Observer(engine),
        backup,
        core_phase.record,
        planned.fleet.config,
        planned.checkout,
        marks,
        planned.read.get(reconcile.REALM_UNIT),
        clock=core_phase.verifier.clock,
    )


def _apply_realm(
    engine: compose.Compose,
    planned: Plan,
    marks: switches.Switches,
    core_phase: CorePhase,
    backup: reconcile.Backup,
) -> bool:
    """The realm step after the unit switches; says its lines and whether it ended partial."""
    result = _realm_step(engine, planned, marks, core_phase, backup).run(planned.realm)
    for row in result_rows(result):
        write_row(row)
    failure = result.failure
    if result.skipped is not None:
        failure = f"{reconcile.REALM_UNIT} {PlanEvent.REALM_SKIPPED}"
    if failure:
        write_error(f"partial, {failure}", command(Verb.APPLY))
    return bool(failure)


def _apply_apps(planned: Plan, marks: switches.Switches, progress: Progress) -> bool:
    """The app step after the realm step; says its lines and whether it ended partial."""
    failed = False
    for plan, failure in planned.app_plans.run(marks, progress):
        if failure:
            write_error(f"partial, {failure}", retry_command(plan.app.key, failure))
            failed = True
        else:
            print(f"{plan.app.key} is on at {plan.release.tag}")
    return failed


def _say_aborted(completed_setups: Sequence[str]) -> None:
    write_error(
        f"aborted, setup of {', '.join(completed_setups)} completed; nothing switched"
        if completed_setups
        else "aborted, nothing changed"
    )


def _say_interrupted(progress: Progress, interruption: KeyboardInterrupt) -> None:
    notes = getattr(interruption, "__notes__", ())
    write_error(
        "; ".join(
            (
                f"interrupted while changing {progress.unit} ({progress.step}); "
                "its state may be partial",
                *notes,
            )
        ),
        command(Verb.APPLY),
        fresh_line=True,
    )


def _write_plan(planned: Plan) -> None:
    """The plan as it stands: all rows."""
    write_groups(plan_groups(planned))


def _confirm_and_switch(
    engine: compose.Compose,
    planned: Plan,
    marks: switches.Switches,
    core_phase: CorePhase,
    completed_setups: Sequence[str],
    realm_backup: reconcile.Backup,
) -> int:
    print("the plan")
    _write_plan(planned)
    if not confirmed(f"apply {counted(changes_in(planned), ChangeNoun.CHANGE)}"):
        _say_aborted(completed_setups)
        return ApplyExit.REFUSED
    changes = [plan for plan in planned.plans if plan.action is not Action.STAYS_STOPPED]
    progress = Progress()
    withheld: dict[str, str] = {}
    try:
        if failure := (
            planned.appkit.write(progress)
            or planned.legal.write(progress)
            or core_phase.run(engine, planned, marks, progress)
        ):
            write_error(f"partial, {failure}; no unit switched", command(Verb.APPLY))
            return ApplyExit.REFUSED
        for plan in changes:
            if since := switch(engine, plan, progress, marks, planned.read):
                withheld[plan.unit.key] = since
        started = [plan for plan in changes if plan.unit.key not in withheld]
        mismatched = _observe_and_record(engine, planned, core_phase, started, progress)
        progress.unit, progress.step = reconcile.REALM_UNIT, "apply the realm step"
        realm_failed = _apply_realm(engine, planned, marks, core_phase, realm_backup)
        apps_failed = _apply_apps(planned, marks, progress)
    except (compose.ComposeError, switches.SwitchError, core.CoreError) as error:
        write_error(f"partial, {progress.unit}: could not {progress.step}, {error}")
        return ApplyExit.REFUSED
    except KeyboardInterrupt as interruption:
        _say_interrupted(progress, interruption)
        return ApplyExit.REFUSED
    return _report_switched(changes, withheld, mismatched, realm_failed or apps_failed)


def _report_switched(
    changes: Sequence[UnitPlan],
    withheld: Mapping[str, str],
    mismatched: Sequence[UnitPlan],
    later_steps_failed: bool,
) -> int:
    for unit, since in withheld.items():
        write_error(
            f"partial, {unit} was switched off meanwhile "
            f"(since {switches.describe_since(since)}); not started"
        )
    for plan in mismatched:
        write_error(f"partial, {plan.unit.key} is not {plan.action} after the change")
    if mismatched or withheld or later_steps_failed:
        return ApplyExit.REFUSED
    for plan in changes:
        print(f"{plan.unit.key} is {plan.action}")
    return ApplyExit.APPLIED_OR_NOTHING
