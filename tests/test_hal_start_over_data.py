"""`hal start` of Keycloak or LiteLLM over its database volume (#1006): with a container of the
app or the database gone it starts nothing, ends the switch and names `hal apply`, which takes the
snapshot first; with all containers, or without a volume, it starts the unit as for any other.
Acting cells run in process through `hal.cli.main` on the fakes of the other `hal start` tests."""

from pathlib import Path

import pytest
import support.hal_stack_commands as hal_stack_commands_support
import yaml
from support.hal_stack_commands import (
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
)
from support.stack_apply import (
    ENABLED,
    LITELLM_ON,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    marker,
    scripted,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch_off,
    write_fleet,
)
from support.stack_global_stop import hosts_asked  # noqa: F401 the fixture, used by `fakes`

from hal.grammar import ExitCode
from hal.stack import barrier, catalog
from hal.stack.litellm_keys import LITELLM
from hal.stack.realm.reconcile import KEYCLOAK

(fakes, hal, system_commands, systemd) = (
    hal_stack_commands_support.fakes,
    hal_stack_commands_support.hal,
    hal_stack_commands_support.system_commands,
    hal_stack_commands_support.systemd,
)  # fmt: skip

COMPOSE_FILE = Path(__file__).resolve().parent.parent / "compose.yaml"
UNIT_ON = {
    KEYCLOAK.key: "  keycloak:\n    run: {enabled: true}\n",
    LITELLM.key: LITELLM_ON,
}


@pytest.fixture(params=[KEYCLOAK, LITELLM], ids=lambda unit: unit.key)
def unit_off(fakes, request):
    """A database unit enabled and switched off: its database mounts its volume, which compose.yaml
    names, and its app and database are stopped; a case removes what it needs gone."""
    unit = request.param
    services = fakes.scripted.config["services"]
    mount = {"type": "volume", "source": unit.database, "target": "/data"}
    services[unit.database] = {"profiles": [unit.key], "volumes": [mount]}
    routed = {"traefik.enable": "true", "edge.name": unit.key}
    services[unit.service] = {"profiles": [unit.key], "labels": routed}
    declared = yaml.safe_load(COMPOSE_FILE.read_text())["volumes"][unit.database]
    if declared:  # Keycloak's volume has a fixed name; LiteLLM's takes the project's
        fakes.scripted.config["volumes"] = {unit.database: declared}
    write_fleet(fakes.repository, ENABLED + UNIT_ON[unit.key])
    fakes.scripted.put_containers(dict.fromkeys((unit.database, unit.service), "exited"))
    switch_off(fakes.state, unit=unit.key)
    return unit, fakes


@pytest.mark.parametrize("gone", ["app", "database"])
def test_start_over_a_database_volume_creates_nothing_ends_the_switch_and_names_apply(
    hal, unit_off, gone
):
    """S6: exit 0, since what the prompt said was done; `hal apply` takes the snapshot first."""
    unit, fakes = unit_off
    fakes.scripted.verb_rm("", ["-f", unit.service if gone == "app" else unit.database])
    fakes.scripted.volumes[unit.database] = "its data"
    barrier_file = barrier.Barrier.of_unit(
        fakes.scripted.config, (unit.service,), fakes.repository, catalog.Unit(unit.key, True, None)
    ).path
    barrier_file.write_text("a barrier a stop left")

    result = hal("start", unit.key, answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert f"{unit.key}: start nothing over {unit.name}'s data" in result.out
    assert f" to end the switch of {unit.key}: " in result.out
    assert "`hal apply` starts it after a snapshot" in result.out
    assert fakes.scripted.changing_verbs() == []
    assert marker(fakes.state, unit.key) is None
    assert not barrier_file.exists()


def test_start_over_a_database_volume_whose_barrier_stays_is_partial_and_does_not_say_on(
    hal, unit_off
):
    """G2: no container starts, so a barrier that cannot be proven away is not `<unit> is on`."""
    unit, fakes = unit_off
    fakes.scripted.verb_rm("", ["-f", unit.service])
    fakes.scripted.volumes[unit.database] = "its data"
    fakes.ingress.down = True

    result = hal("start", unit.key, answers=("yes",))

    assert result.exit_code == ExitCode.FAILURE
    assert f"{unit.key} is on" not in result.err + result.out
    assert "its switch stays" in result.err
    assert marker(fakes.state, unit.key) is not None


@pytest.mark.parametrize(
    ("gone", "volume"),
    [((), True), (("app", "database"), False)],
    ids=["S7 its containers exist", "S7 no volume yet"],
)
def test_start_with_its_containers_or_without_a_volume_starts_the_unit(hal, unit_off, gone, volume):
    unit, fakes = unit_off
    if gone:
        fakes.scripted.verb_rm("", ["-f", unit.service, unit.database])
    if volume:
        fakes.scripted.volumes[unit.database] = "its data"

    result = hal("start", unit.key, answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert f"{unit.key} is on" in result.out
    assert fakes.scripted.changing_verbs() == ["up"]
    assert marker(fakes.state, unit.key) is None
