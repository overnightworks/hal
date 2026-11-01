"""The realm step of `hal apply --local` (#242): when it runs (the plan) and what it does (the
step), with Compose, the observer and hal backup faked. Each test names its cell of the item's
scenario matrix."""

import contextlib
import json
import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import pytest
from support.stack_core import tracked

from hal.stack import compose, core, switches
from hal.stack import realm as realm_lines
from hal.stack.realm import observe, reconcile
from hal.stack.realm.reconcile import RealmAction, RealmPlan, RealmRestart, Stage

REPOSITORY = Path(__file__).resolve().parents[1]
SNAPSHOT = "ab12cd34"
ATTRIBUTE = "de.adorsys.keycloak.config.import-checksum-default"
GROUP = observe.GROUP.name


def applied(result: reconcile.StepResult) -> reconcile.RealmApplied:
    assert isinstance(result, reconcile.RealmApplied)
    return result


def failed(result: reconcile.StepResult) -> reconcile.RealmFailed:
    assert isinstance(result, reconcile.RealmFailed)
    return result


def change_lines(result: reconcile.StepResult) -> list[str]:
    return [realm_lines.line(change) for change in applied(result).changes]


def leftovers(result: reconcile.StepResult) -> reconcile.Leftovers:
    found = applied(result).leftovers
    assert isinstance(found, reconcile.Leftovers)
    return found


def listed(result: reconcile.StepResult) -> list[str]:
    """What the step left alone, as `kind identity` of each object."""
    return [f"{item.kind} {item.identity}" for item in leftovers(result).found]


def group(name: str, members: int = 0) -> dict:
    return {"fields": {"name": name, "members": members}, "digests": {}}


def inventory(*groups: dict, **kinds: dict[str, dict]) -> dict:
    """Both realms as the observer reads them: the groups, and other kinds by identity."""
    entries = {GROUP: {entry["fields"]["name"]: entry for entry in groups}}
    return {"master": {}, "hallucinai": {**entries, **kinds}}


def entity(**fields: object) -> dict:
    return {"fields": fields, "digests": {}}


def flow(*, top_level: bool = True, built_in: bool | None = None) -> dict:
    return entity(topLevel=top_level, builtIn=built_in)


@dataclass
class World:
    """The repository, the record, the switches and every fake the step drives, in one event log."""

    root: Path
    events: list[str] = field(default_factory=list)
    checksum: str = "checksum one"
    config_cli_running: bool = False
    failing: set[str] = field(default_factory=set)
    interrupted: set[str] = field(default_factory=set)
    before: dict = field(default_factory=lambda: inventory(group("/apps")))
    after: dict = field(default_factory=lambda: inventory(group("/apps")))
    meanwhile: Callable[[], None] | None = None  # what changes right before config-cli runs

    def __post_init__(self) -> None:
        (self.root / "keycloak").mkdir(parents=True)
        self.write_file("realm.yaml", "realm: hallucinai\ngroups:\n  - name: apps\n")
        self.write_file("master.yaml", "realm: master\n")
        self.write_file("entrypoint.sh", "#!/bin/sh\n")
        self.record = core.Record(self.root / "state")
        self.marks = switches.Switches(self.root / "state")
        self.checkout = tracked(self.config, self.root)

    def write_file(self, name: str, text: str) -> None:
        (self.root / "keycloak" / name).write_text(text)

    @property
    def config(self) -> dict:
        """config-cli as compose.yaml resolves it: an entrypoint file bind, a `keycloak/` tree."""
        binds = [
            {"type": "bind", "source": str(self.root / "keycloak/entrypoint.sh")},
            {"type": "bind", "source": str(self.root / "keycloak")},
        ]
        return {"services": {reconcile.CONFIG_CLI: {"volumes": binds}}}

    # the fakes ---------------------------------------------------------------------------------

    def states(self) -> dict[str, set[str]]:
        return {reconcile.CONFIG_CLI: {"running"}} if self.config_cli_running else {}

    def run_once(self, service: str, arguments: list[str], stdin: str = "") -> str:
        assert service == reconcile.CONFIG_CLI
        assert not arguments
        assert not stdin
        self.act("config-cli")
        if self.meanwhile:
            self.meanwhile()
        return ""

    def act(self, name: str) -> None:
        self.events.append(name)
        if name in self.interrupted:
            raise KeyboardInterrupt
        if name in self.failing:
            raise reconcile.RealmError(f"{name} broke")

    def pre_apply(self) -> str:
        self.act("backup")
        return SNAPSHOT

    def restore_test(self, snapshot: str) -> None:
        assert snapshot == SNAPSHOT
        self.act("restore test")

    def inventory(self) -> dict:
        self.act("observe")
        done = "config-cli" in self.events
        return self.after if done else self.before

    def checksums(self) -> dict:
        self.act("checksums")
        return {"master": {}, "hallucinai": {ATTRIBUTE: self.checksum}}

    # the step ----------------------------------------------------------------------------------

    def plan(
        self, gate: core.Gate | None = core.Gate.ON, restart: RealmRestart | None = None
    ) -> RealmPlan:
        return reconcile.plan_realm(self, self.record, self.config, self.checkout, gate, restart)

    def run(self, plan: RealmPlan, mark: switches.Mark | None = None) -> reconcile.StepResult:
        realm = reconcile.Realm(
            self,
            self,
            self,
            self.record,
            self.config,
            self.checkout,
            self.marks,
            mark,
            clock=lambda: 0.0,
        )
        return realm.run(plan)

    def step(self, mark: switches.Mark | None = None) -> reconcile.StepResult:
        """Plan with every fault disarmed, then run the step with them armed."""
        faults = self.failing, self.interrupted
        self.failing, self.interrupted = set(), set()
        plan = self.plan()
        self.events.clear()
        self.failing, self.interrupted = faults
        return self.run(plan, mark)

    def applied_once(self) -> reconcile.StepResult:
        result = self.step()
        self.events.clear()
        return result


@pytest.fixture
def world(tmp_path: Path) -> World:
    return World(tmp_path / "repository")


# --- When the step runs ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("moved", "gate"),
    [(False, core.Gate.ON), (True, core.Gate.ON), (False, core.Gate.OFF)],
    ids=["same checkout root", "another root", "keycloak off"],
)
def test_nothing_changed_since_the_last_apply_plans_no_step_and_no_line(
    world: World, tmp_path: Path, moved: bool, gate: core.Gate
) -> None:
    """Cells 1 and 4: a second apply does nothing, wherever it is checked out."""
    assert isinstance(world.applied_once(), reconcile.RealmApplied)
    if moved:
        record, world = world.record, World(tmp_path / "moved")
        world.record = record
    plan = world.plan(gate)

    assert (plan.action, plan.settled) == (RealmAction.NOTHING, True)


def test_no_recorded_apply_plans_the_step(world: World) -> None:
    plan = world.plan()

    assert (plan.action, plan.settled) == (RealmAction.RUN, False)
    assert plan.why == "no realm apply is recorded"


@pytest.mark.parametrize(
    ("change", "why"),
    [
        (
            lambda world: world.write_file("realm.yaml", "realm: two\n"),
            "keycloak/realm.yaml changed",
        ),
        (
            lambda world: world.write_file("master.yaml", "master: two\n"),
            "keycloak/master.yaml changed",
        ),
        (
            lambda world: world.write_file("entrypoint.sh", "#!/bin/sh\nexit 1\n"),
            "keycloak/entrypoint.sh changed",
        ),
        (
            lambda world: setattr(world, "checksum", "restored from an older snapshot"),
            "Keycloak's import checksum is not the recorded one",
        ),
    ],
    ids=["realm file", "master file", "entrypoint", "database restored"],
)
def test_each_input_that_changed_plans_the_step_and_names_it(
    world: World, change: Callable[[World], None], why: str
) -> None:
    """Cells 3, 5, 6 and 7, and the entrypoint config-cli binds."""
    world.applied_once()

    change(world)

    assert world.plan().why == why


def test_an_apply_that_did_not_finish_is_planned_again(world: World) -> None:
    world.record.mark_unfinished([reconcile.CONFIG_CLI], {reconcile.CONFIG_CLI})

    assert "the last realm apply did not finish" in world.plan().why


def test_an_unreadable_record_plans_the_step(world: World) -> None:
    world.record.path.parent.mkdir(parents=True)
    world.record.path.write_text("not json")

    assert "is malformed" in world.plan().why


@pytest.mark.parametrize("gate", [core.Gate.OFF, core.Gate.SWITCHED_OFF])
def test_a_changed_file_while_keycloak_is_off_is_one_line_and_reads_nothing(
    world: World, gate: core.Gate
) -> None:
    """Cells 14 and 15: no step, Keycloak is not asked."""
    plan = world.plan(gate)

    assert plan.action is RealmAction.HELD
    assert plan.settled
    assert (plan.why, plan.gate) == ("no realm apply is recorded", gate)
    assert world.events == []


def test_keycloak_starting_in_this_run_is_not_checked_and_one_line_says_so(world: World) -> None:
    plan = world.plan(restart=RealmRestart.KEYCLOAK)

    assert (plan.action, plan.settled) == (RealmAction.NOT_CHECKED, True)
    assert plan.restart is RealmRestart.KEYCLOAK


def test_a_catalog_without_keycloak_plans_nothing(world: World) -> None:
    assert world.plan(None) == RealmPlan()


def test_a_keycloak_that_cannot_be_read_is_planned_as_a_skipped_step(world: World) -> None:
    world.failing.add("checksums")
    plan = world.plan()
    result = world.run(plan)

    assert (plan.action, plan.settled) == (RealmAction.UNREADABLE, False)
    assert plan.error == "checksums broke"
    assert result == reconcile.RealmSkipped("checksums broke")
    assert "backup" not in world.events


# --- What the step does ------------------------------------------------------------------------


def test_the_step_backs_up_proves_observes_applies_observes_and_lists_the_changes(
    world: World,
) -> None:
    """Cell 3: the order, and the lines equal what changed."""
    world.after = inventory(group("/apps"), group("operators", members=2))

    result = world.step()

    assert world.events == [
        "backup", "restore test", "observe", "config-cli", "observe", "checksums",
    ]  # fmt: skip
    assert (applied(result).snapshot, applied(result).seconds) == (SNAPSHOT, 0.0)
    assert change_lines(result) == ["hallucinai: addition group operators (2 members)"]


def test_an_apply_that_changes_nothing_says_so(world: World) -> None:
    assert applied(world.step()).changes == ()


def test_a_removal_is_printed_as_reset_to_the_file_with_the_snapshot(world: World) -> None:
    """Cell 13 (R4): a console change under a declared object, reset by the apply."""
    world.before = inventory(group("/apps"), group("console-made"))

    result = world.step()

    assert [(change.kind, change.identity) for change in applied(result).changes] == [
        (realm_lines.Kind.REMOVAL, "console-made")
    ]


def test_a_failed_backup_applies_nothing(world: World) -> None:
    """Cell 8."""
    world.failing.add("backup")

    result = world.step()

    assert world.events == ["backup"]
    assert failed(result) == reconcile.RealmFailed("backup broke", Stage.BEFORE, None, False)


def test_a_failed_restore_test_applies_nothing_and_names_the_snapshot_as_unproven(
    world: World,
) -> None:
    """Cell 9."""
    world.failing.add("restore test")

    result = world.step()

    assert "config-cli" not in world.events
    assert failed(result) == reconcile.RealmFailed(
        "restore test broke", Stage.BEFORE, SNAPSHOT, False
    )


def test_an_observer_that_fails_before_applies_nothing(world: World) -> None:
    """Cell 10."""
    world.failing.add("observe")

    result = world.step()

    assert "config-cli" not in world.events
    assert failed(result) == reconcile.RealmFailed("observe broke", Stage.BEFORE, SNAPSHOT, True)


def test_a_failed_config_cli_is_partial_names_the_way_back_and_is_planned_again(
    world: World,
) -> None:
    """Cell 11."""
    world.failing.add("config-cli")

    result = world.step()

    assert failed(result) == reconcile.RealmFailed(
        "config-cli broke", Stage.APPLYING, SNAPSHOT, True
    )
    assert world.plan().action is RealmAction.RUN


def test_a_checksum_read_that_fails_after_config_cli_is_partial_and_not_recorded(
    world: World,
) -> None:
    """Cell 12."""
    world.failing.add("checksums")

    result = world.step()

    assert failed(result) == reconcile.RealmFailed("checksums broke", Stage.APPLIED, SNAPSHOT, True)
    world.failing.clear()
    assert world.plan().action is RealmAction.RUN


def test_a_marker_set_since_the_plan_keeps_config_cli_from_running(world: World) -> None:
    """Cell 16: Keycloak is switched off between the plan and the step."""
    plan = world.plan()
    world.marks.record(reconcile.REALM_UNIT, datetime(2026, 10, 21, tzinfo=UTC))

    result = world.run(plan, mark=None)

    assert "config-cli" not in world.events
    assert failed(result) == reconcile.RealmFailed(
        f"{reconcile.REALM_UNIT} was switched off meanwhile; config-cli is not run",
        Stage.BEFORE,
        SNAPSHOT,
        True,
    )


def test_an_interrupt_during_the_backup_applies_nothing(world: World) -> None:
    """Cell 19."""
    world.interrupted.add("backup")

    result = world.step()

    assert failed(result) == reconcile.RealmFailed("interrupted", Stage.BEFORE, None, False)
    assert "config-cli" not in world.events


def test_an_interrupt_during_config_cli_names_the_snapshot_and_the_realm_may_be_partial(
    world: World,
) -> None:
    """Cell 20."""
    world.interrupted.add("config-cli")

    result = world.step()

    assert failed(result) == reconcile.RealmFailed("interrupted", Stage.APPLYING, SNAPSHOT, True)
    assert world.plan().action is RealmAction.RUN


def test_a_config_cli_container_still_running_refuses_the_step_before_the_backup(
    world: World,
) -> None:
    """Cell 20: the one-off container of an interrupted run."""
    world.config_cli_running = True

    result = world.step()

    assert world.events == []
    assert failed(result).cause == "a config-cli container is still running"


def test_the_record_is_emptied_before_config_cli_and_filled_after_the_observe(
    world: World,
) -> None:
    def while_config_cli_runs() -> None:
        assert world.record.read().entries == {reconcile.CONFIG_CLI: {}}

    world.meanwhile = while_config_cli_runs

    world.step()

    entry = world.record.read().entries[reconcile.CONFIG_CLI]
    assert entry["keycloak/realm.yaml"]
    assert entry["definition"]
    assert entry[f"hallucinai {ATTRIBUTE}"] == "checksum one"


# --- The observer and hal as the step calls them ---------------------------------------


@dataclass
class RecordedCompose:
    answer: str
    calls: list[tuple[str, list[str], str]] = field(default_factory=list)
    error: compose.ComposeError | None = None

    def run_once(self, service: str, arguments: list[str], stdin: str = "") -> str:
        self.calls.append((service, arguments, stdin))
        if self.error:
            raise self.error
        return self.answer


def test_the_observer_reads_checksums_with_no_key_and_inventories_under_one_key() -> None:
    """The two inventories a step compares are digested under the same key; the checksums need
    none."""
    engine = RecordedCompose('{"master": {}}')
    observer = reconcile.Observer(engine)

    observer.checksums()
    observer.inventory()
    observer.inventory()

    (_, checksum_arguments, checksum_input), (_, arguments, first_key), (_, _, second_key) = (
        engine.calls
    )
    assert (checksum_arguments, checksum_input) == (["--import-checksums"], "")
    assert arguments == []
    assert len(first_key.strip()) >= 64
    assert first_key == second_key


@pytest.mark.parametrize(
    ("engine", "message"),
    [
        (
            RecordedCompose("", error=compose.ComposeError("exited 1: realm-observer: a/b")),
            "the realm observer failed (exited 1: realm-observer: a/b)",
        ),
        (RecordedCompose("<html>"), "the realm observer answered no JSON"),
    ],
    ids=["compose failure", "not JSON"],
)
def test_an_observer_that_fails_or_answers_nonsense_is_one_line(
    engine: RecordedCompose, message: str
) -> None:
    observer = reconcile.Observer(engine)

    with pytest.raises(reconcile.RealmError) as raised:
        observer.checksums()

    assert str(raised.value) == message


@dataclass
class Commands:
    """hal as a fake process: the commands asked, and what it answers."""

    stdout: str = f'{{"snapshot": "{SNAPSHOT}"}}\n'
    stderr: str = ""
    code: int = 0
    asked: list[list[str]] = field(default_factory=list)

    def __call__(
        self, command: list[str], _timeout: int, _stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        self.asked.append(command)
        return subprocess.CompletedProcess(command, self.code, self.stdout, self.stderr)


def test_the_backup_asks_for_keycloak_alone_and_reads_the_snapshot_id() -> None:
    commands = Commands()
    backup = reconcile.Backup(("hal",), commands)

    snapshot = backup.pre_apply()
    backup.restore_test(snapshot)

    assert snapshot == SNAPSHOT
    assert commands.asked == [
        ["hal", "backup", "keycloak", "--pre-apply", "--json"],
        ["hal", "restore", "--test", "keycloak", "--snapshot", SNAPSHOT],
    ]


def test_a_failing_backup_says_the_error_line_hal_wrote() -> None:
    failing = Commands(stdout="", stderr="error: hal backup: kein Passwort\n", code=3)
    backup = reconcile.Backup(("hal",), failing)

    with pytest.raises(reconcile.RealmError) as raised:
        backup.pre_apply()
    assert str(raised.value) == "the Keycloak backup failed (hal backup: kein Passwort)"


def test_a_backup_that_names_no_snapshot_is_a_failure() -> None:
    backup = reconcile.Backup(("hal",), Commands(stdout="hal backup: fertig\n"))

    with pytest.raises(reconcile.RealmError, match="named no pre-apply snapshot"):
        backup.pre_apply()


def test_the_installed_backup_is_the_checkouts_own_hal(tmp_path: Path) -> None:
    backup = reconcile.Backup.installed(tmp_path, lambda _grace: None)

    assert backup.command == (str(tmp_path / ".venv" / "bin" / "hal"),)


def test_the_installed_backup_says_the_waiting_line_through_the_line_it_was_given(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cell 7: the waiting line leaves through the channel that carries the step's prefix."""
    monkeypatch.setattr(reconcile, "STOP_GRACE_SECONDS", 0.2)
    said: list[float] = []
    backup = reconcile.Backup.installed(tmp_path, said.append)

    with pytest.raises(compose.ComposeError, match="took longer than 1s"):
        backup.run(["sh", "-c", WAITS], 1)

    assert said == [0.2]


def test_the_entry_of_a_finished_step_survives_a_json_round_trip(world: World) -> None:
    world.step()

    on_disk = json.loads(world.record.path.read_text())

    assert set(on_disk[reconcile.CONFIG_CLI]) == {
        "keycloak/entrypoint.sh",
        "keycloak/master.yaml",
        "keycloak/realm.yaml",
        "definition",
        f"hallucinai {ATTRIBUTE}",
    }


# --- What the step leaves alone, and what it says when a part breaks ---------------------------


@pytest.mark.parametrize("old_hash", [False, True], ids=["after an apply", "after Compose's hash"])
def test_a_settled_plan_runs_nothing_and_keeps_the_record(world: World, old_hash: bool) -> None:
    """An old hash plans RUN; the successful apply replaces it, so the next plan is quiet."""
    world.applied_once()
    if old_hash:
        name = reconcile.CONFIG_CLI
        old = world.record.read().entries[name] | {reconcile.DEFINITION_KEY: "Compose's hash"}
        world.record.write(name, old, {name})
        plan = world.plan()
        assert (plan.action, plan.why) == (RealmAction.RUN, "config-cli's definition changed")
        assert isinstance(world.run(plan), reconcile.RealmApplied)
    recorded = world.record.path.read_bytes()
    plan = world.plan()
    world.events.clear()
    result = world.run(plan)

    assert (plan.action, result, world.events) == (RealmAction.NOTHING, None, [])
    assert world.record.path.read_bytes() == recorded


def test_a_bind_resolution_that_fails_is_a_partial_line_not_a_traceback(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan = world.plan()
    world.events.clear()

    def refuse(*_: object) -> frozenset[str]:
        raise core.CoreError("cannot read keycloak (Permission denied)")

    monkeypatch.setattr(core, "followed_services", refuse)

    result = world.run(plan)

    assert failed(result).cause == "cannot read keycloak (Permission denied)"
    assert world.events == []


def test_a_record_that_cannot_be_written_keeps_the_changes_and_says_it_repeats(
    world: World, monkeypatch: pytest.MonkeyPatch
) -> None:
    world.after = inventory(group("/apps"), group("operators", members=2))

    def refuse(*_: object) -> None:
        raise core.CoreError("cannot write applied.json (Permission denied)")

    monkeypatch.setattr(core.Record, "write", refuse)

    result = world.step()

    assert change_lines(result) == ["hallucinai: addition group operators (2 members)"]
    assert applied(result).leftovers == reconcile.NotRecorded(
        "cannot write applied.json (Permission denied)"
    )


# --- What exists only in Keycloak --------------------------------------------------------------


@pytest.mark.parametrize(
    ("kind", "identity", "made"),
    [
        (observe.CLIENT.name, "console-client", entity(clientId="console-client", enabled=True)),
        (observe.CLIENT_SCOPE.name, "console-scope", entity(name="console-scope")),
        (observe.REALM_ROLE, "console-role", entity(name="console-role")),
        (observe.FLOW.name, "console flow", flow()),
        (observe.IDP.name, "console-idp", entity(alias="console-idp")),
    ],
)
def test_an_object_made_in_the_console_is_listed_and_has_no_removal_line(
    world: World, kind: str, identity: str, made: dict
) -> None:
    """Cell 1: it survives the step, so the step says it exists only in Keycloak."""
    world.before = world.after = inventory(
        group("/apps"), group("console-made"), **{kind: {identity: made}}
    )

    result = world.step()

    assert isinstance(result, reconcile.RealmApplied)
    assert sorted(listed(result)) == sorted([f"{kind} {identity}", f"{GROUP} console-made"])
    assert applied(result).changes == ()


def test_what_the_files_declare_and_keycloak_brings_itself_is_not_listed(world: World) -> None:
    """Cell 2: nothing else in a realm the files made means nothing is listed."""
    world.after = inventory(
        group("/apps"),
        **{
            observe.FLOW.name: {
                "browser": flow(built_in=True),
                "sub flow": flow(top_level=False),
            },
            observe.CLIENT.name: {
                name: entity(clientId=name) for name in ("account", "realm-management")
            },
            observe.REALM_ROLE: {
                "default-roles-hallucinai": entity(name="default-roles-hallucinai")
            },
        },
    )
    world.after["master"] = {
        observe.CLIENT.name: {"hallucinai-realm": entity(clientId="hallucinai-realm")}
    }
    world.before = world.after

    result = world.step()

    assert (leftovers(result).found, leftovers(result).absent) == ((), ())
    assert leftovers(result).files_read


def test_a_declared_group_in_a_declared_sub_tree_is_not_listed(world: World) -> None:
    world.write_file(
        "realm.yaml",
        "realm: hallucinai\ngroups:\n  - name: apps\n    subGroups:\n      - name: admin\n",
    )
    world.before = world.after = inventory(group("/apps"), group("/apps/admin"), group("/other"))

    result = world.step()

    assert listed(result) == [f"{GROUP} /other"]


def test_the_kinds_that_cannot_be_read_are_carried_by_name(world: World) -> None:
    """Cell 3."""
    unread = leftovers(world.step()).unread

    assert {"defaultGroups", "workflows"} <= set(unread)
    assert not [name for name in unread if "." in name]


def test_the_list_holds_names_only(world: World) -> None:
    """Cell 6: no attribute and no secret of a listed object is in any line."""
    made = entity(clientId="console-client", secret="planted-secret", attributes={"k": "planted"})
    world.before = world.after = inventory(
        group("/apps"), **{observe.CLIENT.name: {"console-client": made}}
    )

    result = world.step()

    assert listed(result) == [f"{observe.CLIENT.name} console-client"]
    assert "planted" not in repr(applied(result))


@pytest.mark.parametrize(
    "text",
    [
        "realm: [unclosed\n",
        "realm: [a, b]\n",
        "realm: hallucinai\nclients:\n  - secret: s\n",
        "realm: hallucinai\nclients:\n  - web\n",
        "realm: hallucinai\ngroups:\n  - name: a\n    subGroups: oops\n",
    ],
)
def test_realm_files_that_cannot_be_read_leave_the_step_as_it_ended(
    world: World, text: str
) -> None:
    world.write_file("realm.yaml", text)
    without_the_list = world.step()
    world.write_file("realm.yaml", "realm: hallucinai\n")
    expected = world.step()

    assert isinstance(without_the_list, reconcile.RealmApplied)
    assert leftovers(without_the_list).files_read is False
    assert applied(without_the_list).changes == applied(expected).changes


def test_a_file_in_an_unreadable_encoding_leaves_the_step_as_it_ended(world: World) -> None:
    (world.root / "keycloak" / "realm.yaml").write_bytes(b"realm: \xff\xfe\n")

    result = world.step()

    assert isinstance(result, reconcile.RealmApplied)
    assert leftovers(result).files_read is False


def test_a_yaml_scalar_the_loader_cannot_build_still_records_and_says_unreadable(
    world: World,
) -> None:
    world.write_file("realm.yaml", "realm: hallucinai\nsince: 2026-02-30\n")

    result = world.step()

    assert isinstance(result, reconcile.RealmApplied)
    assert leftovers(result).files_read is False
    assert world.plan().settled


def test_a_key_left_empty_in_a_realm_file_still_records_and_lists(world: World) -> None:
    """The list never changes the outcome: `clients: null` reads as no clients."""
    world.write_file("realm.yaml", "realm: hallucinai\nclients: null\ngroups:\n")
    world.before = world.after = inventory(group("/console"))

    result = world.step()

    assert isinstance(result, reconcile.RealmApplied)
    assert listed(result) == [f"{GROUP} /console"]
    assert world.plan().settled


def test_a_realm_the_files_name_that_was_not_observed_is_one_line_not_a_traceback(
    world: World,
) -> None:
    world.write_file("master.yaml", "realm: elsewhere\n")

    result = world.step()

    assert isinstance(result, reconcile.RealmApplied)
    assert leftovers(result).absent == ("elsewhere",)


def test_a_failed_step_lists_nothing_only_in_keycloak(world: World) -> None:
    """Cell 5: a failure after config-cli (the checksum read) says no list."""
    world.failing = {"checksums"}
    world.after = inventory(group("/apps"), group("console-made"))

    result = world.step()

    assert isinstance(result, reconcile.RealmFailed)


# --- hal backup is stopped, not killed --------------------------------------------------------

WAITS = "while :; do sleep 0.1; done"
# A Python child, as the CI shell may have SIGTERM ignored on entry, which a shell cannot trap.
# It says it is ready; on SIGTERM it says it is cleaning up, holds until `argv[2]` exists (at most
# 30 seconds, so it cannot outlive a failed test), then writes its marker.
CLEANS_UP_ON_SIGTERM = """
import pathlib, signal, sys, time
marker = pathlib.Path(sys.argv[1])
release = pathlib.Path(sys.argv[2])
def clean_up(*_):
    pathlib.Path(f"{marker}.cleaning").touch()
    deadline = time.monotonic() + 30
    while not release.exists() and time.monotonic() < deadline:
        time.sleep(0.02)
    marker.write_text("cleaned\\n" if release.exists() else "expired\\n")
    sys.exit(143)
signal.signal(signal.SIGTERM, clean_up)
pathlib.Path(f"{marker}.pid").write_text(str(__import__("os").getpid()))
pathlib.Path(f"{marker}.ready").touch()
while True:
    time.sleep(0.1)
"""
IGNORES_SIGTERM = """
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
while True:
    time.sleep(0.1)
"""
DRIVES_THE_STEP = """
import pathlib, signal, sys
seen = pathlib.Path(sys.argv[1])
def interrupted(*_):
    with seen.open("a") as file:
        file.write("interrupted\\n")
    raise KeyboardInterrupt
signal.signal(signal.SIGINT, interrupted)
from hal.stack.realm import observe, reconcile
try:
    reconcile.run_edge_backup(sys.argv[2:], 600, waiting=print)
except KeyboardInterrupt:
    print("KeyboardInterrupt reached the step")
"""


def test_a_backup_that_runs_past_its_timeout_gets_sigterm_and_time_to_clean_up(
    tmp_path: Path,
) -> None:
    marker = tmp_path / "cleaned"
    release = tmp_path / "release"
    release.touch()

    with pytest.raises(compose.ComposeError, match="took longer than 3s"):
        reconcile.run_edge_backup(
            [sys.executable, "-c", CLEANS_UP_ON_SIGTERM, str(marker), str(release)],
            3,
            waiting=lambda _grace: None,
        )

    assert marker.read_text() == "cleaned\n"


def test_a_backup_that_ignores_sigterm_still_ends_in_the_timeout_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(reconcile, "STOP_GRACE_SECONDS", 0.3)

    with pytest.raises(compose.ComposeError, match="took longer than 3s"):
        reconcile.run_edge_backup(
            [sys.executable, "-c", IGNORES_SIGTERM], 3, waiting=lambda _grace: None
        )


def test_a_grandchild_that_holds_the_output_open_cannot_hang_the_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(reconcile, "STOP_GRACE_SECONDS", 0.2)
    monkeypatch.setattr(reconcile, "COLLECT_SECONDS", 0.5)
    escaped = tmp_path / "escaped.pid"
    leaves_a_grandchild = f"setsid sh -c 'echo $$ > {escaped}; exec sleep 60' & {WAITS}"

    try:
        started = time.monotonic()
        with pytest.raises(compose.ComposeError, match="took longer than 1s"):
            reconcile.run_edge_backup(
                ["sh", "-c", leaves_a_grandchild], 1, waiting=lambda _grace: None
            )
        assert time.monotonic() - started < 10
    finally:
        os.kill(int(escaped.read_text()), signal.SIGKILL)


def wait_for(condition: Callable[[], bool], what: str, step: subprocess.Popen[str]) -> None:
    deadline = time.monotonic() + 30
    while not condition():
        if step.poll() is not None:
            pytest.fail(
                f"the step ended before {what}: {step.stdout.read() if step.stdout else ''}"
            )
        if time.monotonic() > deadline:
            pytest.fail(f"no {what} within 30 seconds")
        time.sleep(0.02)


def kill_group(process_group: int) -> None:
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process_group, signal.SIGKILL)


def test_ctrl_c_during_the_grace_does_not_cut_the_clean_up_short(tmp_path: Path) -> None:
    """The terminal's Ctrl-C goes to the step's group alone: hal backup runs in its own."""
    marker = tmp_path / "cleaned"
    release = tmp_path / "release"
    interrupts = tmp_path / "interrupts"
    command = [
        sys.executable,
        "-c",
        DRIVES_THE_STEP,
        str(interrupts),
        *(sys.executable, "-c", CLEANS_UP_ON_SIGTERM, str(marker), str(release)),
    ]
    step = subprocess.Popen(
        command,
        env={**os.environ, "PYTHONPATH": str(REPOSITORY / "src")},
        stdout=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        wait_for(Path(f"{marker}.ready").exists, "the backup was ready", step)
        os.killpg(step.pid, signal.SIGINT)  # stops hal backup
        wait_for(Path(f"{marker}.cleaning").exists, "the backup began its clean-up", step)
        os.killpg(step.pid, signal.SIGINT)  # comes while the clean-up is held
        wait_for(
            lambda: interrupts.exists() and interrupts.read_text().count("\n") == 2,
            "the second interrupt",
            step,
        )
        release.touch()
        output, _ = step.communicate(timeout=30)
    finally:
        # Before the child wrote its pid, its own 30 second cap ends it.
        if Path(f"{marker}.pid").exists():
            kill_group(int(Path(f"{marker}.pid").read_text()))
        kill_group(step.pid)
        step.wait(timeout=30)

    assert marker.read_text() == "cleaned\n"  # released by the test, not the watchdog
    assert "KeyboardInterrupt reached the step" in output


def test_a_finished_backup_returns_its_exit_code_and_output() -> None:
    result = reconcile.run_edge_backup(
        ["sh", "-c", "echo out; echo err >&2; exit 3"], 30, waiting=lambda _grace: None
    )

    assert (result.returncode, result.stdout, result.stderr) == (3, "out\n", "err\n")
