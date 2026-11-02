"""The realm step of `hal apply --local`: applies a changed `keycloak/realm.yaml` or
`keycloak/master.yaml` to the running Keycloak after a Keycloak-only backup (#242, #235 rulings
R2-R4).

The step runs only when Keycloak is on, set up and running, and an input changed: the step's entry
in `applied.json` (under `keycloak-config-cli`) is missing, unfinished, or differs from the digests
of the checkout files config-cli reads and hal's digest of its resolved service, or Keycloak's own
import-checksum attributes differ from the ones the entry saw after the last apply. The digest
makes each bind source inside the checkout relative to it, so moving the checkout is no realm
change. A rotated client secret alone does not trigger it: the digest covers the secret
attachments, not their content.

An apply that runs takes `hal backup keycloak --pre-apply --json`, proves that snapshot with
`hal restore --test keycloak --snapshot`, observes both realms, runs config-cli, observes again and
lists what changed, then what exists only in Keycloak: the objects of the kinds the operator
creates that the files do not declare, which the step never deletes. The entry is emptied before
config-cli and filled only after the observe, so a step that did not finish is planned again.
Nothing is deleted but what config-cli resets to the file; those removals say so.
"""

import contextlib
import hashlib
import json
import os
import re
import signal
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from functools import partial
from pathlib import Path
from typing import Any

from hal.output import printable
from hal.output.command import PROGRAM, Verb, command
from hal.stack import compose, core, switches
from hal.stack import realm as realm_lines
from hal.stack.realm import OBSERVER_SERVICE, new_digest_key
from hal.stack.realm import declared as declared_identities
from hal.stack.realm.observe import (
    CLIENT,
    CLIENT_SCOPE,
    COVERAGE,
    FLOW,
    REALM_ROLE,
    Entity,
    Gap,
    Inventory,
    keys,
)
from hal.stack.unit_plans import Action, Recreate, UnitPlan

REALM_UNIT = "keycloak"
KEYCLOAK_SERVICE = "keycloak"
CONFIG_CLI = "keycloak-config-cli"
# config-cli imports these from its directory bind of keycloak/, which `core.file_binds` skips.
REALM_FILES = ("keycloak/master.yaml", "keycloak/realm.yaml")
DEFINITION_KEY = "definition"  # the entry's key for `definition_digest` of config-cli
BACKUP_SECONDS = 1800
STOP_GRACE_SECONDS = 120  # what hal backup gets to remove its staging and restore container
COLLECT_SECONDS = 5  # what the output of a killed hal backup gets before its pipes are closed
_ERROR_LINE = re.compile(r"^error: (.+)$", re.MULTILINE)

type Checksums = dict[str, dict[str, str]]  # realm -> import-checksum attribute -> value
type Waiting = Callable[[float], None]  # told the seconds a stopped hal is given to clean up


class RealmError(Exception):
    """A part of the step failed; the message is one line without a secret."""


# --- What the plan decides ---------------------------------------------------------------------


@dataclass(frozen=True)
class Inputs:
    """What the realm files and config-cli's definition are now."""

    files: core.Digests
    definition: str

    @property
    def entry(self) -> dict[str, str]:
        return {**self.files, DEFINITION_KEY: self.definition}

    def changed_since(self, recorded: Mapping[str, str]) -> str | None:
        for name, digest in self.entry.items():
            if recorded.get(name) != digest:
                return (
                    "config-cli's definition changed"
                    if name == DEFINITION_KEY
                    else f"{name} changed"
                )
        return None


def bound_files(config: Mapping[str, Any], checkout: core.Checkout) -> tuple[Path, ...]:
    """The checkout files config-cli reads: the realm files and every file it binds (its
    entrypoint)."""
    realm_files = tuple(checkout.path / name for name in REALM_FILES)
    return (*realm_files, *core.file_binds(config["services"].get(CONFIG_CLI, {}), checkout))


def definition_digest(service: Mapping[str, Any], repository: Path) -> str:
    """The sha256 of the resolved service in canonical JSON, each bind source inside the checkout
    as its path relative to it, so a checkout elsewhere is the same definition. Compose's own hash
    names the checkout, which the recreate decisions need and this record must not."""
    mounts = [
        {**mount, "source": Path(mount["source"]).relative_to(repository).as_posix()}
        if mount.get("type") == "bind" and Path(mount["source"]).is_relative_to(repository)
        else mount
        for mount in service.get("volumes", [])
    ]
    canonical = json.dumps({**service, "volumes": mounts}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def read_inputs(config: Mapping[str, Any], checkout: core.Checkout) -> Inputs:
    files = core.digests(bound_files(config, checkout), checkout.path)
    return Inputs(files, definition_digest(config["services"][CONFIG_CLI], checkout.path))


def _flat(checksums: Checksums) -> dict[str, str]:
    return {
        f"{realm} {attribute}": value
        for realm, attributes in checksums.items()
        for attribute, value in attributes.items()
    }


class RealmAction(StrEnum):
    NOTHING = "nothing"
    RUN = "run"
    HELD = "held"  # Keycloak is off or switched off: the changed files wait
    NOT_CHECKED = "not checked"  # Keycloak starts in this run
    UNREADABLE = "unreadable"  # Keycloak should run and cannot be read


class RealmRestart(StrEnum):
    KEYCLOAK = "Keycloak starts now"
    DATABASE = "its database restarts now"


@dataclass(frozen=True)
class RealmPlan:
    action: RealmAction = RealmAction.NOTHING
    why: str = ""  # why the realm is applied or held, for RUN and HELD
    error: str = ""  # why Keycloak could not be read, for UNREADABLE
    restart: RealmRestart | None = None  # the Keycloak unit start of this run, for NOT_CHECKED
    gate: core.Gate | None = None  # the Keycloak unit's gate, for HELD
    entry: dict[str, str] = field(default_factory=dict)  # the inputs as planned, for the record

    @property
    def settled(self) -> bool:
        return self.action not in (RealmAction.RUN, RealmAction.UNREADABLE)


class Observer:
    """The realm observer through its compose service (`hal.stack.realm.observe`). One observer
    holds one digest key, so the inventories it reads before and after an apply can be compared."""

    def __init__(self, engine: compose.Compose) -> None:
        self.engine = engine
        self.digest_key = new_digest_key()

    def inventory(self) -> Inventory:
        return self._read([], self.digest_key + "\n")

    def checksums(self) -> Checksums:
        return self._read(["--import-checksums"], "")

    def _read(self, arguments: list[str], stdin: str) -> dict:
        try:
            return json.loads(self.engine.run_once(OBSERVER_SERVICE, arguments, stdin))
        except compose.ComposeError as error:
            raise RealmError(f"the realm observer failed ({error})") from error
        except ValueError as error:
            raise RealmError("the realm observer answered no JSON") from error


def restart_of(plans: Iterable[UnitPlan], recreates: Iterable[Recreate]) -> RealmRestart | None:
    """What this run starts of the Keycloak unit, None when nothing: Keycloak itself when its
    unit is switched on or its service recreated, else only another service of the unit."""
    realm_recreates = [recreate for recreate in recreates if recreate.unit == REALM_UNIT]
    switched_on = any(plan.unit.key == REALM_UNIT and plan.action is Action.ON for plan in plans)
    if switched_on or any(recreate.service == KEYCLOAK_SERVICE for recreate in realm_recreates):
        return RealmRestart.KEYCLOAK
    if realm_recreates:
        return RealmRestart.DATABASE
    return None


def plan_realm(
    observer: Observer,
    record: core.Record,
    config: Mapping[str, Any],
    checkout: core.Checkout,
    gate: core.Gate | None,
    restart: RealmRestart | None,
) -> RealmPlan:
    """What the step does: `gate` is the Keycloak unit's, None when the catalog has none, and
    `restart` says what this run starts of its unit, None when nothing."""
    if gate is None:
        return RealmPlan()
    if restart:
        return RealmPlan(RealmAction.NOT_CHECKED, restart=restart)
    inputs = read_inputs(config, checkout)
    reading = record.read()
    if gate is not core.Gate.ON:
        if why := _why(reading, inputs, None):
            return RealmPlan(RealmAction.HELD, why=why, gate=gate)
        return RealmPlan()
    try:
        observed = observer.checksums()
    except RealmError as error:
        return RealmPlan(RealmAction.UNREADABLE, error=str(error))
    if why := _why(reading, inputs, observed):
        return RealmPlan(RealmAction.RUN, why=why, entry=inputs.entry)
    return RealmPlan()


def _why(reading: core.Reading, inputs: Inputs, observed: Checksums | None) -> str | None:
    """Why the realm has to be applied; `observed` is None while Keycloak is not read."""
    if reading.problem:
        return reading.problem
    if (recorded := reading.entries.get(CONFIG_CLI)) is None:
        return "no realm apply is recorded"
    if reading.unfinished(CONFIG_CLI):
        return "the last realm apply did not finish"
    if why := inputs.changed_since(recorded):
        return why
    saw = {name: value for name, value in recorded.items() if name not in inputs.entry}
    if observed is not None and saw != _flat(observed):
        return "Keycloak's import checksum is not the recorded one"
    return None


# --- The step ----------------------------------------------------------------------------------


def run_edge_backup(
    command: list[str], timeout: int, stdin: str | None = None, *, waiting: Waiting
) -> subprocess.CompletedProcess[str]:
    """Run hal backup or hal restore to its end, in a session of its own, so the terminal's Ctrl-C
    reaches only this step. On the timeout or the first Ctrl-C it is stopped as the `hal-backup`
    systemd unit is (`KillMode=control-group` default): SIGTERM to its whole group, then
    `STOP_GRACE_SECONDS` to remove its staging and restore container."""
    try:
        with subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=compose.REPOSITORY,
            start_new_session=True,
        ) as process:
            try:
                stdout, stderr = process.communicate(stdin, timeout)
            except subprocess.TimeoutExpired as error:
                _stop(process, waiting)
                raise compose.ComposeError(
                    f"`{' '.join(command[:3])}` took longer than {timeout}s"
                ) from error
            except KeyboardInterrupt:
                _stop(process, waiting)
                raise
    except OSError as error:
        raise compose.ComposeError(f"cannot run {command[0]}: {error.strerror}") from error
    return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)


def _stop(process: subprocess.Popen[str], waiting: Waiting) -> None:
    """SIGTERM to the group and a grace that no further Ctrl-C shortens; then the group is killed
    and the output collected for a bounded time, so a grandchild holding a pipe cannot hang."""
    waiting(STOP_GRACE_SECONDS)
    _signal_group(process, signal.SIGTERM)
    deadline = time.monotonic() + STOP_GRACE_SECONDS
    while (remaining := deadline - time.monotonic()) > 0:
        try:
            process.communicate(timeout=remaining)
            break
        except subprocess.TimeoutExpired:
            break
        except KeyboardInterrupt:
            continue  # hal was told once; only its exit or the grace ends the wait
    _signal_group(process, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired, KeyboardInterrupt):
        process.communicate(timeout=COLLECT_SECONDS)  # leaving the `with` closes the pipes


def _signal_group(process: subprocess.Popen[str], sent: signal.Signals) -> None:
    with contextlib.suppress(ProcessLookupError):  # the group is gone already
        os.killpg(process.pid, sent)


@dataclass(frozen=True)
class Backup:
    """`hal backup` and `hal restore` as the timers run them, for Keycloak alone."""

    command: tuple[str, ...]
    run: compose.Runner

    @classmethod
    def installed(cls, repository: Path, waiting: Waiting) -> "Backup":
        """`waiting` is told when a stopped hal is waited for."""
        return cls(
            (str(repository / ".venv" / "bin" / PROGRAM),),
            partial(run_edge_backup, waiting=waiting),
        )

    def pre_apply(self) -> str:
        """The new snapshot's ID."""
        arguments = ["backup", REALM_UNIT, "--pre-apply", "--json"]
        result = self._run(arguments, "the Keycloak backup failed")
        try:
            snapshot = json.loads(result.stdout)["snapshot"]
        except (ValueError, KeyError, TypeError):
            snapshot = None
        if not isinstance(snapshot, str):
            raise RealmError(f"{command(Verb.BACKUP)} named no pre-apply snapshot")
        return snapshot

    def restore_test(self, snapshot: str) -> None:
        """Proves the snapshot just made, whatever a timer backs up in between."""
        arguments = ["restore", "--test", REALM_UNIT, "--snapshot", snapshot]
        self._run(arguments, "the restore test failed")

    def _run(self, arguments: list[str], failure: str) -> subprocess.CompletedProcess[str]:
        try:
            result = self.run([*self.command, *arguments], BACKUP_SECONDS)
        except compose.ComposeError as error:
            raise RealmError(f"{failure} ({error})") from error
        if result.returncode != 0:
            raise RealmError(f"{failure} ({_cause(result)})")
        return result


def _cause(result: subprocess.CompletedProcess[str]) -> str:
    """The `error:` line hal wrote, never its `next:` line; the last line of a failure that is not
    hal's own."""
    output = result.stderr + result.stdout
    errors = _ERROR_LINE.findall(output)
    return printable(errors[-1].strip()) if errors else compose.last_line(output)


class Stage(StrEnum):
    BEFORE = "before"  # nothing is applied yet
    APPLYING = "applying"  # config-cli started
    APPLIED = "applied"  # config-cli ended well; its result is not recorded yet


@dataclass
class _Progress:
    stage: Stage = Stage.BEFORE
    snapshot: str | None = None
    proven: bool = False


@dataclass(frozen=True)
class OnlyInKeycloak:
    """One object of a kind the operator creates that the realm files do not declare."""

    realm: str
    kind: str
    identity: str


@dataclass(frozen=True)
class Leftovers:
    """What the step leaves alone: the objects only in Keycloak, the declared realms it did not
    observe, whether the realm files could be read to compare, and the kinds it cannot see."""

    found: tuple[OnlyInKeycloak, ...]
    absent: tuple[str, ...]
    files_read: bool
    unread: tuple[str, ...]


@dataclass(frozen=True)
class NotRecorded:
    """The record of an applied and observed step could not be written, so nothing is listed."""

    error: str


@dataclass(frozen=True)
class RealmApplied:
    """A step that ran config-cli and observed the result; `seconds` is the whole step."""

    snapshot: str
    seconds: float
    changes: tuple[realm_lines.Change, ...]
    leftovers: Leftovers | NotRecorded


@dataclass(frozen=True)
class RealmFailed:
    """A step that ended partial: how far it got, the pre-apply snapshot once there is one, and
    whether its restore test passed."""

    cause: str
    stage: Stage
    snapshot: str | None
    proven: bool


@dataclass(frozen=True)
class RealmSkipped:
    """Keycloak could not be read, so the step did not act."""

    reason: str


type StepResult = RealmApplied | RealmFailed | RealmSkipped | None  # None: a settled plan


@dataclass(frozen=True)
class Realm:
    """The step, with what it drives injected: Compose, the observer, the backup and the record."""

    engine: compose.Compose
    observer: Observer
    backup: Backup
    record: core.Record
    config: Mapping[str, Any]
    checkout: core.Checkout
    marks: switches.Switches
    mark: switches.Mark | None  # Keycloak's marker as the plan read it
    clock: Callable[[], float] = time.monotonic

    def run(self, plan: RealmPlan) -> StepResult:
        """Alone decides whether the step acts: a settled plan has no effect."""
        if plan.settled:
            return None
        if plan.action is RealmAction.UNREADABLE:
            return RealmSkipped(plan.error)
        progress = _Progress()
        try:
            return self._apply(plan, progress)
        except (RealmError, compose.ComposeError, core.CoreError, switches.SwitchError) as error:
            return _failed(progress, str(error))
        except KeyboardInterrupt:
            return _failed(progress, "interrupted")

    def _apply(self, plan: RealmPlan, progress: _Progress) -> RealmApplied:
        started = self.clock()
        followed = core.followed_services(self.config, self.checkout)
        self._refuse_while_config_cli_runs()
        progress.snapshot = self.backup.pre_apply()
        self.backup.restore_test(progress.snapshot)
        progress.proven = True
        before = self.observer.inventory()
        self._run_config_cli(progress, followed)
        after = self.observer.inventory()
        checksums = self.observer.checksums()
        changes = tuple(realm_lines.diff(before, after))
        try:
            self.record.write(CONFIG_CLI, {**plan.entry, **_flat(checksums)}, followed)
        except core.CoreError as error:
            return RealmApplied(
                progress.snapshot, self.clock() - started, changes, NotRecorded(str(error))
            )
        seconds = self.clock() - started
        return RealmApplied(progress.snapshot, seconds, changes, self.leftovers(after))

    def leftovers(self, after: Inventory) -> Leftovers:
        """What the step leaves alone, said only once the step has succeeded. A realm file that
        cannot be read as a declaration shortens the list and nothing else."""
        unread = tuple(
            name
            for name, coverage in COVERAGE.items()
            if isinstance(coverage, Gap) and "." not in name
        )
        try:
            files = [(self.checkout.path / name).read_text() for name in REALM_FILES]
            declared = [declared_identities.declared_realm(text) for text in files]
        except (OSError, UnicodeDecodeError, declared_identities.DeclaredError):
            return Leftovers((), (), False, unread)
        absent = tuple(realm.realm for realm in declared if realm.realm not in after)
        return Leftovers(tuple(only_in_keycloak(after, declared)), absent, True, unread)

    def _refuse_while_config_cli_runs(self) -> None:
        if compose.has_running_container(self.engine.states(), (CONFIG_CLI,)):
            raise RealmError("a config-cli container is still running")

    def _run_config_cli(self, progress: _Progress, followed: frozenset[str]) -> None:
        """Under the switch lock, so a marker set since the plan stops it before Keycloak could
        be touched; config-cli never starts Keycloak (`--no-deps`)."""
        with self.marks.lock():
            if self.marks.changed(REALM_UNIT, self.mark):
                raise RealmError(f"{REALM_UNIT} was switched off meanwhile; config-cli is not run")
            self.record.mark_unfinished([CONFIG_CLI], followed)
            progress.stage = Stage.APPLYING
            self.engine.run_once(CONFIG_CLI, [])
        progress.stage = Stage.APPLIED


def _failed(progress: _Progress, cause: str) -> RealmFailed:
    return RealmFailed(cause, progress.stage, progress.snapshot, progress.proven)


# --- What exists only in Keycloak ---------------------------------------------------------------

# Keycloak 26.8.1's own objects of the kinds the list compares (`compose.yaml` pins the version),
# read from a fresh import of the realm files by the probe's proof 3a; a Keycloak upgrade that
# adds one fails that proof. A flow carries its own `builtIn` flag instead.
_BUILT_IN_CLIENTS = keys("account account-console admin-cli broker security-admin-console")
_BUILT_IN_SCOPES = keys(
    """AuthnContextClassRef acr address basic email microprofile-jwt offline_access organization
    phone profile role_list roles saml_organization service_account web-origins"""
)
_BUILT_IN_ROLES = keys("offline_access uma_authorization")
BUILT_IN: Mapping[str, declared_identities.Identities] = {
    "master": {
        CLIENT.name: _BUILT_IN_CLIENTS | {"master-realm", "hallucinai-realm"},
        CLIENT_SCOPE.name: _BUILT_IN_SCOPES,
        REALM_ROLE: _BUILT_IN_ROLES | {"admin", "create-realm", "default-roles-master"},
    },
    "hallucinai": {
        CLIENT.name: _BUILT_IN_CLIENTS | {"realm-management"},
        CLIENT_SCOPE.name: _BUILT_IN_SCOPES,
        REALM_ROLE: _BUILT_IN_ROLES | {"default-roles-hallucinai"},
    },
}


def only_in_keycloak(
    inventory: Inventory, declared: Iterable[declared_identities.DeclaredRealm]
) -> list[OnlyInKeycloak]:
    """What `inventory` holds of the declared kinds beyond the files and Keycloak's own, in the
    realms it holds."""
    found = []
    for realm in (realm for realm in declared if realm.realm in inventory):
        for kind, declared_names in realm.identities.items():
            built_in = BUILT_IN.get(realm.realm, {}).get(kind, frozenset())
            objects = inventory[realm.realm].get(kind, {})
            found += [
                OnlyInKeycloak(realm.realm, kind, identity)
                for identity in sorted(objects.keys() - declared_names - built_in)
                if _made_by_the_operator(kind, objects[identity])
            ]
    return found


def _made_by_the_operator(kind: str, entity: Entity) -> bool:
    """A flow is the operator's when it is top-level and Keycloak does not flag it built in."""
    if kind != FLOW.name:
        return True
    return bool(entity["fields"]["topLevel"]) and not entity["fields"]["builtIn"]
