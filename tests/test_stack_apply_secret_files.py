"""`hal apply` refuses before any plan and any yes when a service it would create names a secret
whose file is missing (C1-C10), on the scripted boundaries of the support module."""

from pathlib import Path

import support.stack_apply as base
import yaml
from support.stack_apply import (
    FOLLOWER_FILE,
    SCENARIO_SECRET,
    SCENARIO_SETUP,
    SCENARIO_SIDECAR,
    SCENARIO_SIDECAR_SECRET,
    SCENARIO_UNIT,
    switch_off,
    up_calls,
    write_fleet,
)
from support.stack_plan_rows import find_row

from hal.stack import apply
from hal.stack.result_rows import ResultEvent

# The fixtures of `tests/support/stack_apply.py` this module's tests request by name.
applied_core = base.applied_core
at_terminal = base.at_terminal
core_files = base.core_files
home = base.home
ingress = base.ingress
realm_backup = base.realm_backup
repository = base.repository
scenario_unit = base.scenario_unit
scripted = base.scripted
scripted_git = base.scripted_git
setup_check = base.setup_check
setup_run = base.setup_run
state = base.state
step_ca_applied = base.step_ca_applied
switch = base.switch

NEXT = "next: hal setup"


def file_of(scripted, secret: str) -> Path:
    return Path(scripted.config["secrets"][secret]["file"])


def lose(scripted, secret: str) -> Path:
    path = file_of(scripted, secret)
    path.unlink()
    return path


def needs(scripted, service: str, secret: str, tmp_path: Path) -> Path:
    """The service names a further file secret whose file does not exist."""
    path = tmp_path / "compose-home" / secret
    scripted.config.setdefault("secrets", {})[secret] = {"name": secret, "file": str(path)}
    definition = scripted.config["services"][service]
    definition["secrets"] = [*definition.get("secrets", []), {"source": secret, "target": secret}]
    return path


def refused_before_the_yes(exit_code: int, out: str, err: str, scripted, *paths: Path) -> None:
    assert exit_code == apply.ApplyExit.GUARD_REFUSED
    assert err.count("error:") == 1
    assert all(str(path) in err for path in paths)
    assert "nothing switched" in err
    assert NEXT in err
    assert "Type yes to apply" not in out
    assert scripted.changing_verbs() == []


def test_a_unit_switched_on_whose_service_lacks_its_secret_file_is_refused_before_the_yes(
    scenario_unit, switch, scripted
):
    """C1."""
    path = lose(scripted, SCENARIO_SECRET)

    exit_code, out, err = switch()

    refused_before_the_yes(exit_code, out, err, scripted, path)
    assert f"{SCENARIO_UNIT} needs {path}; nothing switched\n{NEXT}" in err


def test_a_live_service_with_a_changed_definition_whose_file_is_missing_is_refused(
    step_ca_applied, switch, scripted, tmp_path
):
    """C2, a recreate of a live service whose definition changed."""
    path = needs(scripted, "step-ca", "ca_secret", tmp_path)
    scripted.change_definition("step-ca")

    exit_code, out, err = switch()

    refused_before_the_yes(exit_code, out, err, scripted, path)
    assert f"step-ca needs {path}" in err


def test_a_changed_follower_whose_file_is_missing_is_refused(
    step_ca_applied, switch, scripted, repository, tmp_path
):
    """C4, the follower."""
    path = needs(scripted, "traefik-mcp", "follower_secret", tmp_path)
    with (repository / FOLLOWER_FILE).open("a") as file:
        file.write("# a harmless edit\n")

    exit_code, out, err = switch()

    refused_before_the_yes(exit_code, out, err, scripted, path)
    assert f"traefik-mcp needs {path}" in err


def test_a_changed_core_service_whose_file_is_missing_is_refused(
    applied_core, switch, scripted, repository, tmp_path
):
    """C4, the core."""
    path = needs(scripted, "traefik", "core_secret", tmp_path)
    base.edit_traefik_yml(repository)

    exit_code, out, err = switch()

    refused_before_the_yes(exit_code, out, err, scripted, path)
    assert f"traefik needs {path}" in err


def test_two_missing_files_of_two_services_are_named_in_one_error(scenario_unit, switch, scripted):
    """C5."""
    signing_key = lose(scripted, SCENARIO_SECRET)
    further = lose(scripted, SCENARIO_SIDECAR_SECRET)

    exit_code, out, err = switch()

    refused_before_the_yes(exit_code, out, err, scripted, signing_key, further)
    assert f"{SCENARIO_UNIT} needs {signing_key}" in err
    assert f"{SCENARIO_SIDECAR} needs {further}" in err


def test_with_every_file_there_the_plan_and_the_yes_are_as_before(scenario_unit, switch, scripted):
    """C6."""
    exit_code, out, err = switch()

    assert exit_code == 0
    assert find_row(out, SCENARIO_UNIT, ResultEvent.SWITCHED_ON)
    assert "needs" not in err


def test_a_file_the_units_own_setup_makes_is_asked_for_first_and_refuses_nothing(
    scenario_unit, switch, scripted, setup_check, setup_run
):
    """C7."""
    setup_check.exit_code, setup_check.line = 1, "the key is not made"
    path = lose(scripted, SCENARIO_SECRET)
    setup_run.meanwhile = lambda: path.write_text("x\n")

    exit_code, out, _ = switch("yes\nyes")

    assert exit_code == 0
    assert f"run `{SCENARIO_SETUP}` now" in out
    assert find_row(out, SCENARIO_UNIT, ResultEvent.SWITCHED_ON)


def test_a_file_still_missing_after_the_setup_ran_refuses_with_nothing_switched(
    scenario_unit, switch, scripted, setup_check, setup_run
):
    """C8."""
    setup_check.exit_code, setup_check.line = 1, "the key is not made"
    made = lose(scripted, SCENARIO_SECRET)
    absent = lose(scripted, SCENARIO_SIDECAR_SECRET)
    setup_run.meanwhile = lambda: made.write_text("x\n")

    exit_code, out, err = switch("yes\nyes")

    assert setup_run.commands
    refused_before_the_yes(exit_code, out, err, scripted, absent)
    assert str(made) not in err


def test_a_unit_that_is_switched_off_is_not_refused_for_a_missing_file(
    scenario_unit, switch, scripted, state
):
    """C9, off or stopped by `hal stop`."""
    switch_off(state, unit=SCENARIO_UNIT)
    lose(scripted, SCENARIO_SECRET)

    exit_code, out, err = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert "needs" not in err


def test_a_unit_disabled_in_the_fleet_with_live_containers_is_not_refused_for_a_missing_file(
    scenario_unit, switch, scripted, repository
):
    """C9, a unit switched off in the fleet file."""
    assert switch()[0] == 0
    scripted.calls.clear()
    lose(scripted, SCENARIO_SECRET)
    fleet = yaml.safe_load((repository / "fleet.yaml").read_text())
    fleet["services"][SCENARIO_UNIT]["run"]["enabled"] = False
    write_fleet(repository, yaml.safe_dump(fleet))

    exit_code, _, err = switch()

    assert exit_code == 0
    assert "needs" not in err


def test_a_changed_follower_of_a_stopped_unit_is_not_refused_for_a_missing_file(
    step_ca_applied, switch, scripted, repository, state, tmp_path
):
    """C9, a follower held back by its stopped unit."""
    switch_off(state, unit="step-ca")
    needs(scripted, "traefik-mcp", "follower_secret", tmp_path)
    with (repository / FOLLOWER_FILE).open("a") as file:
        file.write("# a harmless edit\n")

    _, _, err = switch()

    assert "needs" not in err


def test_a_changed_core_service_that_is_not_running_is_not_refused_for_a_missing_file(
    applied_core, switch, scripted, repository, tmp_path
):
    """C9, a core service that is not started."""
    needs(scripted, "traefik", "core_secret", tmp_path)
    base.edit_traefik_yml(repository)
    scripted.put_containers({"socket-proxy": "exited", "traefik": "exited"})

    exit_code, _, err = switch()

    assert exit_code == 0
    assert "needs" not in err


def test_a_running_service_the_plan_leaves_alone_is_not_refused_for_a_missing_file(
    scenario_unit, switch, scripted
):
    """C9, a running service the plan leaves alone."""
    assert switch()[0] == 0
    scripted.calls.clear()
    lose(scripted, SCENARIO_SECRET)

    exit_code, out, err = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert up_calls(scripted) == []
    assert "needs" not in err


def test_a_secret_with_an_environment_and_no_file_is_not_looked_at(scenario_unit, switch, scripted):
    """C10."""
    scripted.config["secrets"]["from_environment"] = {
        "name": "from_environment",
        "environment": "SOME_VARIABLE",
    }
    scripted.config["services"][SCENARIO_UNIT]["secrets"].append(
        {"source": "from_environment", "target": "from_environment"}
    )

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, SCENARIO_UNIT, ResultEvent.SWITCHED_ON)
