"""`hal apply` moves a database unit's app or database service (Keycloak, LiteLLM) to the image
compose.yaml pins under the plan's one `yes`, after the unit's proven pre-apply snapshot (#995),
on the scripted boundaries of `tests/support/stack_apply.py`."""

import sys
from functools import partial

import pytest
import yaml
from support.stack_apply import (
    KEYCLOAK_ENABLED,
    OLD_IMAGE,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    switch_off,
    trusted_environment,
    write_fleet,
)
from support.stack_apply_fakes import RealmBackup
from support.stack_plan_rows import find_row, plain, row_at

from hal import cli
from hal.grammar import ExitCode
from hal.stack import apply, compose, litellm_keys, switches
from hal.stack.external import cli as external_cli
from hal.stack.plan_rows import KeysEvent, PlanEvent
from hal.stack.realm.reconcile import KEYCLOAK, REALM_UNIT
from hal.stack.result_rows import ResultEvent

LITELLM = litellm_keys.LITELLM
POSTGRES = f"postgres:17.6@sha256:{'5' * 64}"
POSTGRES_BUMP = f"postgres:17.7@sha256:{'6' * 64}"
KEYCLOAK_BUMP = f"quay.io/keycloak/keycloak:26.8.1@sha256:3f3c{'0' * 60}"
LITELLM_IMAGE = f"ghcr.io/berriai/litellm:v1.80.0@sha256:{'7' * 64}"
LITELLM_BUMP = f"ghcr.io/berriai/litellm:v1.80.1@sha256:{'8' * 64}"
FRONT_IMAGE = f"nginx:1.29.1@sha256:{'9' * 64}"
FRONT_BUMP = f"nginx:1.29.2@sha256:{'a' * 64}"
BOTH_ON = (
    "services:\n"
    "  keycloak:\n    run: {enabled: true, setup: keycloak/init}\n"
    "  litellm:\n    run: {enabled: true}\n"
)
SNAPSHOT_STEPS = ("backup", "restore test")
HEALTHY = {"condition": "service_healthy", "required": True}


@pytest.fixture
def realm_backup(scripted) -> RealmBackup:  # noqa: F811
    """The shared fake, its asks standing among Compose's calls."""
    return RealmBackup(timeline=scripted.calls)


@pytest.fixture
def database_units(
    realm_unit,  # noqa: F811
    repository,  # noqa: F811
    scripted,  # noqa: F811
    switch,  # noqa: F811
    realm_backup,
):
    """Keycloak and LiteLLM on, each app beside its database, LiteLLM's front beside it, every
    container from the current definitions and applied once; the calls so far are forgotten."""
    services = scripted.config["services"]
    for unit in (KEYCLOAK, LITELLM):
        services[unit.database] = {
            "image": POSTGRES,
            "profiles": [unit.key],
            "volumes": [{"type": "volume", "source": unit.database, "target": "/data"}],
        }
    services[KEYCLOAK.service]["depends_on"] = {KEYCLOAK.database: HEALTHY}
    services[LITELLM.service] = {
        "image": LITELLM_IMAGE,
        "profiles": [LITELLM.key],
        "depends_on": {LITELLM.database: HEALTHY},
    }
    services["litellm-front"] = {
        "image": FRONT_IMAGE,
        "profiles": [LITELLM.key],
        "depends_on": {LITELLM.service: HEALTHY},
    }
    services[litellm_keys.KEYS_SERVICE] = {"profiles": ["apply"]}
    config = repository / litellm_keys.CONFIG_FILE
    config.parent.mkdir(parents=True, exist_ok=True)
    settings = {"litellm_settings": {litellm_keys.BUDGET_ID_SETTING: "scenario-budget"}}
    config.write_text(yaml.safe_dump(settings))
    write_fleet(repository, BOTH_ON)
    running = (KEYCLOAK.database, KEYCLOAK.service, LITELLM.database, LITELLM.service)
    scripted.put_containers(dict.fromkeys((*running, "litellm-front"), "running"))
    assert switch()[0] == 0
    scripted.calls.clear()
    realm_backup.asked.clear()


def steps(scripted) -> list[tuple[str, str]]:  # noqa: F811
    """The snapshot steps and the `up` calls in the order they ran, each with its unit or its
    (last) service."""
    return [(call[2], call[-1]) for call in scripted.calls if call[2] in {"up", *SNAPSHOT_STEPS}]


def snapshot_of(unit: str) -> list[tuple[str, str]]:
    return [(step, unit) for step in SNAPSHOT_STEPS]


@pytest.mark.parametrize(
    ("service", "bump", "later"),
    [
        pytest.param(
            KEYCLOAK.service,
            KEYCLOAK_BUMP,
            (REALM_UNIT, PlanEvent.REALM_LATER, "Keycloak starts now"),
            id="C1 keycloak",
        ),
        pytest.param(
            LITELLM.service,
            LITELLM_BUMP,
            (LITELLM.key, KeysEvent.LATER, "LiteLLM starts now"),
            id="C2 litellm",
        ),
    ],
)
@pytest.mark.usefixtures("database_units")
def test_a_moved_app_is_recreated_after_its_proven_snapshot_under_one_yes_and_then_is_quiet(
    service,
    bump,
    later,
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    scripted.change_image(service, bump)

    exit_code, out, err = switch()

    assert (exit_code, err) == (0, "")
    assert plain(out).count("Type yes to apply") == 1
    assert find_row(out, service, PlanEvent.RECREATE, "→")
    assert find_row(out, service, PlanEvent.RECREATE, "snapshot first")
    assert OLD_IMAGE not in out
    assert find_row(out, *later)
    assert steps(scripted) == [*snapshot_of(service), ("up", service)]
    assert find_row(out, service, ResultEvent.RECREATED, "snapshot ab12cd34 proven")
    scripted.calls.clear()

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in plain(out)
    assert steps(scripted) == []


@pytest.fixture
def plain_apply(
    database_units, repository, scripted, setup_check, setup_run, ingress, scripted_git,  # noqa: F811
    realm_backup, state, home, at_terminal, capsys, monkeypatch,  # noqa: F811
):  # fmt: skip
    """Plain `hal apply` through its composer: the local part on the scripted boundaries, the
    publish a spy that counts its calls."""
    collaborators = apply.Collaborators(
        engine=compose.Compose(scripted.run, repository),
        check=setup_check,
        run_setup=setup_run,
        verifier=ingress.verifier,
        watch=ingress.watch,
        git=scripted_git,
        ensure_environment=trusted_environment,
        realm_backup=realm_backup,
    )
    local = partial(
        apply.apply_local, repository=repository, home=home, collaborators=collaborators
    )
    monkeypatch.setattr(apply, "apply_local", local)
    published: list[object] = []

    def publish(*arguments: object, **_keywords: object) -> int:
        published.append(arguments)
        return 0

    monkeypatch.setattr(external_cli, "apply_command", publish)

    def run() -> tuple[int, str, list[object]]:
        at_terminal("yes")
        exit_code = cli.main(["apply"])
        terminal_output = sys.stdout.getvalue()  # `at_terminal` made stdout a StringIO
        return exit_code, terminal_output + capsys.readouterr().err, published

    return run


@pytest.mark.parametrize(
    ("failing", "names_the_snapshot"),
    [("backup", False), ("restore test", True)],
    ids=["C3 the backup fails", "C3 the restore test fails"],
)
def test_a_failed_snapshot_keeps_the_old_container_and_ends_partial(
    failing,
    names_the_snapshot,
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
):
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    realm_backup.failing = failing
    ids = dict(scripted.container_ids)

    exit_code, output, published = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert find_row(output, "keycloak", ResultEvent.FAILED, f"{failing} broke")
    assert ("pre-apply snapshot ab12cd34" in output) == names_the_snapshot
    assert scripted.container_ids == ids
    assert [step for step in steps(scripted) if step[0] == "up"] == []
    assert published == []


def test_plain_hal_apply_publishes_nothing_after_a_failed_snapshot(
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
):
    """C9: the local part is `hal apply --local`'s; its failure stops the publish. The exit is
    the public one `hal` ends with, which C3 and the docs name."""
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    realm_backup.failing = "backup"

    exit_code, output, published = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert "nothing published" in output
    assert published == []


@pytest.mark.usefixtures("database_units")
def test_a_switched_off_unit_takes_no_snapshot_and_keeps_its_container(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
):
    """C4."""
    switch_off(state, unit=KEYCLOAK.key)
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in plain(out)
    assert steps(scripted) == []
    assert scripted.container_ids == ids


@pytest.mark.usefixtures("database_units")
def test_a_moved_database_alone_is_snapshotted_from_the_old_one_and_recreated_alone(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """C6."""
    scripted.change_image(KEYCLOAK.database, POSTGRES_BUMP)
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, KEYCLOAK.database, PlanEvent.RECREATE, "snapshot first")
    assert find_row(out, REALM_UNIT, PlanEvent.REALM_LATER, "its database restarts now")
    assert steps(scripted) == [*snapshot_of(KEYCLOAK.key), ("up", KEYCLOAK.database)]
    assert scripted.container_ids[KEYCLOAK.service] == ids[KEYCLOAK.service]


@pytest.mark.parametrize(
    ("moves", "expected"),
    [
        pytest.param(
            {KEYCLOAK.database: POSTGRES_BUMP, LITELLM.database: POSTGRES_BUMP},
            [
                *snapshot_of(KEYCLOAK.key),
                ("up", KEYCLOAK.database),
                *snapshot_of(LITELLM.key),
                ("up", LITELLM.database),
            ],
            id="C7 a Postgres bump moves both databases",
        ),
        pytest.param(
            {KEYCLOAK.service: KEYCLOAK_BUMP, KEYCLOAK.database: POSTGRES_BUMP},
            [*snapshot_of(KEYCLOAK.key), ("up", KEYCLOAK.database), ("up", KEYCLOAK.service)],
            id="C8 app and database of one unit",
        ),
    ],
)
@pytest.mark.usefixtures("database_units")
def test_each_moved_unit_has_one_snapshot_before_its_own_first_recreate(
    moves,
    expected,
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    for service, bump in moves.items():
        scripted.change_image(service, bump)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert steps(scripted) == expected
    assert plain(out).count("snapshot first") == [step[0] for step in expected].count("backup")


@pytest.mark.usefixtures("database_units")
def test_litellm_front_keeps_its_old_image_and_takes_no_snapshot(switch, scripted):  # noqa: F811
    """C10; step-ca's case is `test_stack_apply`'s
    `test_a_running_unit_whose_image_changed_is_named_and_nothing_changes`."""
    scripted.change_image("litellm-front", FRONT_BUMP)

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "litellm-front", PlanEvent.OLD_IMAGE)
    assert "nothing to change" in plain(out)
    assert steps(scripted) == []


@pytest.mark.usefixtures("database_units")
def test_a_litellm_without_a_key_fails_its_restore_test_and_is_not_recreated(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    """C12, through the installed `hal`: the restore test of a store with no key refuses."""
    hal = repository / ".venv/bin/hal"
    hal.parent.mkdir(parents=True)
    hal.write_text(
        "#!/bin/sh\n"
        'if [ "$1" = backup ]; then echo \'{"snapshot": "ab12cd34"}\'; exit 0; fi\n'
        "echo 'error: litellm: the restored table LiteLLM_VerificationToken is empty' >&2\n"
        "echo 'next: hal restore --test litellm' >&2\n"
        "exit 1\n"
    )
    hal.chmod(0o755)
    scripted.change_image(LITELLM.service, LITELLM_BUMP)
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch(installed_backup=True)

    assert exit_code == apply.ApplyExit.REFUSED
    assert "the restored table LiteLLM_VerificationToken is empty" in out
    assert "pre-apply snapshot ab12cd34" in out
    assert scripted.container_ids == ids


@pytest.mark.usefixtures("database_units")
def test_a_recreated_app_that_does_not_run_names_its_snapshot_and_the_live_restore(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """C13."""
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    scripted.crash_loops = {KEYCLOAK.service}

    exit_code, out, _ = switch()

    assert exit_code == apply.ApplyExit.REFUSED
    assert find_row(out, "keycloak", ResultEvent.NOT_RUNNING, "of the keycloak recreate")
    assert "hal restore keycloak --live --snapshot ab12cd34" in out


@pytest.mark.usefixtures("database_units")
def test_ctrl_c_in_the_recreate_after_the_snapshot_names_it_and_the_live_restore(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    """B1: the recreate had begun, so the interrupt line carries the way back."""

    def interrupted() -> None:
        raise KeyboardInterrupt

    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    scripted.after_up = interrupted

    exit_code, _, err = switch()

    assert exit_code == apply.ApplyExit.REFUSED
    assert "interrupted while changing keycloak" in err
    assert "hal restore keycloak --live --snapshot ab12cd34" in err


def _lock_cannot_be_taken(marks_directory, monkeypatch) -> None:
    marks_directory.chmod(0)


def _ctrl_c_at_the_lock(marks_directory, monkeypatch) -> None:
    def interrupted(_marks):
        raise KeyboardInterrupt

    monkeypatch.setattr(switches.Switches, "lock", interrupted)


def _switched_off(marks_directory, monkeypatch) -> None:
    switch_off(marks_directory, unit=KEYCLOAK.key)


@pytest.mark.parametrize(
    "disturb",
    [
        pytest.param(_lock_cannot_be_taken, id="the lock fails"),
        pytest.param(_ctrl_c_at_the_lock, id="Ctrl-C at the lock"),
        pytest.param(_switched_off, id="the unit is switched off"),
    ],
)
@pytest.mark.usefixtures("database_units")
def test_a_stop_before_the_apps_recreate_still_names_the_live_restore_the_database_needs(
    disturb,
    switch,  # noqa: F811
    scripted,  # noqa: F811
    state,  # noqa: F811
    monkeypatch,
):
    """C8: the database of the unit was recreated, so the way back holds for the app's turn."""
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    scripted.change_image(KEYCLOAK.database, POSTGRES_BUMP)
    scripted.after_up = lambda: disturb(state, monkeypatch)

    try:
        _, out, err = switch()
    finally:
        state.chmod(0o700)

    assert "hal restore keycloak --live --snapshot ab12cd34" in out + err


@pytest.mark.usefixtures("database_units")
def test_a_unit_switched_off_after_its_snapshot_names_the_snapshot_and_no_restore(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    realm_backup,
    state,  # noqa: F811
    monkeypatch,
):
    """B3: nothing was recreated, so loading the snapshot would only lose what was written since."""
    scripted.change_image(KEYCLOAK.service, KEYCLOAK_BUMP)
    proven = realm_backup.restore_test

    def proven_then_switched_off(unit, snapshot) -> None:
        proven(unit, snapshot)
        switch_off(state, unit=KEYCLOAK.key)

    monkeypatch.setattr(realm_backup, "restore_test", proven_then_switched_off)

    exit_code, out, _ = switch()

    assert exit_code == apply.ApplyExit.REFUSED
    assert find_row(out, "keycloak", ResultEvent.APP_HELD_OFF, "keycloak not recreated")
    assert "pre-apply snapshot ab12cd34" in out
    assert "hal restore" not in out


# --- a switch-on over the data of a removed unit (#1006) ---------------------------------------

LITELLM_SERVICES = (LITELLM.database, LITELLM.service, "litellm-front")
KEYCLOAK_SERVICES = (KEYCLOAK.service, KEYCLOAK.database)
LITELLM_UP = ("up", LITELLM_SERVICES)


def removed(scripted, *services: str) -> None:  # noqa: F811
    scripted.verb_rm("", ["-f", *services])


def switch_on_steps(scripted) -> list[tuple[str, tuple[str, ...]]]:  # noqa: F811
    """The snapshot steps and the `up` calls in the order they ran, each with all it names."""
    return [
        (call[2], tuple(argument for argument in call[3:] if not argument.startswith("-")))
        for call in scripted.calls
        if call[2] in {"up", *SNAPSHOT_STEPS}
    ]


@pytest.fixture
def litellm_data(database_units, scripted):  # noqa: F811
    """LiteLLM's database volume holds its data."""
    scripted.volumes[LITELLM.database] = "LiteLLM's keys"


@pytest.mark.parametrize(
    ("unit", "services", "gone", "bump"),
    [
        pytest.param(
            KEYCLOAK, KEYCLOAK_SERVICES, KEYCLOAK_SERVICES, KEYCLOAK_BUMP,
            id="S1 keycloak, every container removed, the app re-pinned",
        ),
        pytest.param(
            LITELLM, LITELLM_SERVICES, LITELLM_SERVICES, LITELLM_BUMP,
            id="S1 litellm, every container removed, the app re-pinned",
        ),
        pytest.param(
            LITELLM, LITELLM_SERVICES, (LITELLM.service, "litellm-front"), LITELLM_BUMP,
            id="S2 litellm, the database live",
        ),
    ],
)  # fmt: skip
@pytest.mark.usefixtures("database_units")
def test_a_switch_on_over_data_starts_the_database_alone_and_the_app_after_the_proven_snapshot(
    unit,
    services,
    gone,
    bump,
    plain_apply,
    scripted,  # noqa: F811
    repository,  # noqa: F811
):
    if unit is KEYCLOAK:  # LiteLLM's key step would read the Keycloak group before it runs
        removed(scripted, *LITELLM_SERVICES)
        write_fleet(repository, KEYCLOAK_ENABLED)
    scripted.volumes[unit.database] = "its data"
    removed(scripted, *gone)
    scripted.change_image(unit.service, bump)
    database = scripted.container_ids.get(unit.database)

    exit_code, output, _ = plain_apply()

    assert exit_code == ExitCode.OK, output
    assert switch_on_steps(scripted) == [
        ("up", (unit.database,)),
        *[(step, (unit.key,)) for step in SNAPSHOT_STEPS],
        ("up", services),
    ]
    assert scripted.images[unit.service] == bump
    if database is not None:
        assert scripted.container_ids[unit.database] == database
    shown = plain(sys.stdout.getvalue())
    assert row_at(shown, unit.key, ResultEvent.SWITCHED_ON, " · up") < shown.index(
        "\n    pre-apply snapshot ab12cd34 · proven"
    )
    scripted.calls.clear()

    exit_code, _, _ = plain_apply()

    assert exit_code == ExitCode.OK
    assert "nothing to change" in plain(sys.stdout.getvalue())
    assert switch_on_steps(scripted) == []


@pytest.mark.parametrize(
    ("failing", "names_the_snapshot"),
    [("backup", False), ("restore test", True)],
    ids=["S3 the backup fails", "S3 the restore test fails"],
)
@pytest.mark.usefixtures("litellm_data")
def test_a_failed_switch_on_snapshot_creates_no_app_and_names_no_restore(
    failing,
    names_the_snapshot,
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
):
    """The database started alone is not counted as created over the data: the snapshot is taken
    from it, so loading it would undo nothing of that start."""
    removed(scripted, *LITELLM_SERVICES)
    realm_backup.failing = failing

    exit_code, output, published = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert f"{failing} broke" in output
    assert output.count("pre-apply snapshot ab12cd34") == int(names_the_snapshot)
    assert "hal restore" not in output
    assert switch_on_steps(scripted)[-1] != LITELLM_UP
    assert LITELLM.service not in scripted.containers
    assert published == []


@pytest.mark.usefixtures("database_units")
def test_a_fresh_switch_on_with_no_volume_takes_no_snapshot(
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
):
    """S4."""
    removed(scripted, *LITELLM_SERVICES)

    exit_code, _, _ = plain_apply()

    assert exit_code == ExitCode.OK
    assert switch_on_steps(scripted) == [LITELLM_UP]
    assert realm_backup.asked == []


def _ctrl_c_before_the_apps_start(state, monkeypatch) -> None:  # noqa: F811
    _ctrl_c_at_the_lock(state, monkeypatch)


def _switched_off_before_the_apps_start(state, monkeypatch) -> None:  # noqa: F811
    switch_off(state, unit=LITELLM.key)


def _ctrl_c_in_the_apps_start(scripted) -> None:  # noqa: F811
    def interrupted() -> None:
        if len(switch_on_steps(scripted)) > len(SNAPSHOT_STEPS) + 1:
            raise KeyboardInterrupt

    scripted.after_up = interrupted


def _app_does_not_run(scripted) -> None:  # noqa: F811
    scripted.crash_loops = {LITELLM.service}


@pytest.mark.parametrize(
    ("after_the_proof", "in_the_start", "line", "restores", "withheld"),
    [
        pytest.param(
            _ctrl_c_before_the_apps_start, None, "interrupted while changing litellm", False, False,
            id="S5 Ctrl-C before the app is created",
        ),
        pytest.param(
            _switched_off_before_the_apps_start, None,
            "partial, litellm switched off meanwhile", False, True,
            id="switched off before the app is created",
        ),
        pytest.param(
            None, _ctrl_c_in_the_apps_start, "interrupted while changing litellm", True, False,
            id="Ctrl-C while the app is created",
        ),
        pytest.param(
            None, _app_does_not_run, "partial, litellm not running", True, False,
            id="the app does not run",
        ),
    ],
)  # fmt: skip
@pytest.mark.usefixtures("litellm_data")
def test_a_switch_on_stopped_after_its_snapshot_names_it_and_the_restore_once_the_app_began(
    after_the_proof,
    in_the_start,
    line,
    restores,
    withheld,
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
    state,  # noqa: F811
    monkeypatch,
):
    removed(scripted, *LITELLM_SERVICES)
    if after_the_proof:
        proven = realm_backup.restore_test

        def disturbed(unit, snapshot) -> None:
            proven(unit, snapshot)
            after_the_proof(state, monkeypatch)

        monkeypatch.setattr(realm_backup, "restore_test", disturbed)
    if in_the_start:
        in_the_start(scripted)

    exit_code, output, _ = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert line in output
    assert "pre-apply snapshot ab12cd34" in output
    assert ("hal restore litellm --live --snapshot ab12cd34" in output) == restores
    assert (LITELLM.service in scripted.containers) == restores
    if withheld:
        row = find_row(output, LITELLM.key, ResultEvent.APP_HELD_OFF, "not started")
        assert row
        not_started = row.group(0).partition(" · ")[2].removesuffix(" not started").split(", ")
        assert LITELLM.database not in not_started
        assert LITELLM.service in not_started


@pytest.mark.usefixtures("litellm_data")
def test_a_switch_on_that_creates_only_the_database_names_its_snapshot_and_no_restore(
    plain_apply,
    scripted,  # noqa: F811
):
    """R1: the app container kept its image, so the start created nothing a restore would undo."""
    removed(scripted, LITELLM.database)
    _ctrl_c_in_the_apps_start(scripted)

    exit_code, output, _ = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert "interrupted while changing litellm" in output
    assert "pre-apply snapshot ab12cd34" in output
    assert "hal restore" not in output


@pytest.mark.parametrize(
    ("keycloak_gone", "keycloak_fragment"),
    [
        pytest.param(
            KEYCLOAK_SERVICES,
            "hal restore keycloak --live --snapshot ab12cd34",
            id="the app was created over its data",
        ),
        pytest.param(
            (KEYCLOAK.database,),
            "keycloak: pre-apply snapshot ab12cd34 taken",
            id="only the database was created",
        ),
    ],
)
def test_a_partial_switch_on_names_the_way_back_of_every_unit_that_holds_a_snapshot(
    keycloak_gone,
    keycloak_fragment,
    plain_apply,
    scripted,  # noqa: F811
    realm_backup,
):
    """F1: Keycloak was started over its data and proven; LiteLLM's backup then fails."""
    for unit in (KEYCLOAK, LITELLM):
        scripted.volumes[unit.database] = "its data"
    removed(scripted, *keycloak_gone, *LITELLM_SERVICES)
    realm_backup.failing, realm_backup.failing_unit = "backup", LITELLM.key

    exit_code, output, _ = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert find_row(output, LITELLM.key, ResultEvent.FAILED, "backup broke")
    assert keycloak_fragment in output
    assert "hal restore litellm" not in output


@pytest.mark.usefixtures("database_units")
def test_a_switch_on_whose_later_key_step_fails_still_names_its_snapshot(
    plain_apply,
    scripted,  # noqa: F811
):
    """F1: Keycloak started over its data and proven; the key step of the running LiteLLM then
    cannot write."""
    scripted.volumes[KEYCLOAK.database] = "its data"
    removed(scripted, *KEYCLOAK_SERVICES)
    scripted.keys.fail_at = 0

    exit_code, output, _ = plain_apply()

    assert exit_code == ExitCode.FAILURE
    assert "pre-apply snapshot ab12cd34" in output
    assert "hal restore keycloak --live --snapshot ab12cd34" in output
