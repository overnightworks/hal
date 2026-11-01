"""`hal apply --local`, `hal stop` and `hal start` against a scripted Compose and a scripted
setup check: no containers, and a `tmp_path` HOME so that no test touches the real switches."""

import errno
import fcntl
import io
import json
import os
import shutil
import signal
import stat
import subprocess
import sys
from contextlib import nullcontext
from pathlib import Path

import pytest
import support.stack_apply as stack_apply_support
import yaml
from support.git_support import (
    advance,
    checkout_state,
    head_of,
    local_commit,
    plain_git,
    subjects,
)
from support.stack_apply import (
    APP_EXITED,
    DISABLED,
    DOCKER_GID,
    ENABLED,
    FOLLOWER_FILE,
    KEYCLOAK_ENABLED,
    NOT_SET_UP_LINE,
    NOW,
    OLD_IMAGE,
    PROBE_ENABLED,
    RECREATE_FOLLOWER,
    RECREATE_TRAEFIK,
    REPOSITORY,
    STEP_CA_BUMP,
    STEP_CA_ON,
    STEP_CA_SERVICES,
    SWITCHED_OFF_AT,
    TWO_SETUPS,
    ZONE,
    applied,
    apply_lock,
    apply_lock_held,
    bind_traefik_mcp_files,
    edge_tree,
    edit_traefik_yml,
    follower_digest,
    interrupted_at_the_prompt,
    marker,
    put_probe_in_b,
    put_unit_in,
    short,
    switch_off,
    up_calls,
    write_fleet,
    writing_environment,
)
from support.stack_apply_fakes import (
    IMAGE,
    LABELLED_IMAGE_ID,
    NOT_FOUND,
    OTHER_LABELS,
    STEP_CA_IMAGE,
    InterruptedWaitForLock,
    ScriptedGit,
    definition_hash,
    resolved_configuration,
)
from support.stack_core import bind, sha256
from support.stack_plan_rows import detail_lines, find_row, plain, row_at

from hal.stack import (
    apply,
    catalog,
    checkout,
    compose,
    core,
    emergency,
    setup,
    switches,
    tunnel,
)
from hal.stack.plan_rows import PlanEvent
from hal.stack.realm import reconcile
from hal.stack.unit_plans import ImageReference, KeptImage, plan_kept_images

(
    agent_service_unit,
    applied_core,
    at_terminal,
    core_files,
    home,
    ingress,
    missing_setup,
    origin,
    real_main,
    realm_backup,
    realm_unit,
    repository,
    scripted,
    scripted_git,
    setup_check,
    setup_run,
    start,
    state,
    step_ca_applied,
    switch,
    unreadable_profile_bind,
) = (
    stack_apply_support.agent_service_unit,
    stack_apply_support.applied_core,
    stack_apply_support.at_terminal,
    stack_apply_support.core_files,
    stack_apply_support.home,
    stack_apply_support.ingress,
    stack_apply_support.missing_setup,
    stack_apply_support.origin,
    stack_apply_support.real_main,
    stack_apply_support.realm_backup,
    stack_apply_support.realm_unit,
    stack_apply_support.repository,
    stack_apply_support.scripted,
    stack_apply_support.scripted_git,
    stack_apply_support.setup_check,
    stack_apply_support.setup_run,
    stack_apply_support.start,
    stack_apply_support.state,
    stack_apply_support.step_ca_applied,
    stack_apply_support.switch,
    stack_apply_support.unreadable_profile_bind,
)  # fmt: skip

LATER_SWITCH_AT = "2026-10-17T23:30:00+02:00"
PROBE_DISABLED = ENABLED + "  probe:\n    run: {enabled: false}\n"
# The labels beside the definition hash in a real `ps --format json` line (frozen from #87 Q1,
# Compose 2.40.3): another label's value may hold commas and an `=`.
# The `Image` of a real `ps --format json` line is the reference the container was created from,
# spelled as its resolved `image` was then (frozen from #91 Z1, Compose 2.40.3).
# compose.yaml's pins, `name:tag@sha256:<64>`, and a bump of each as a pull would bring it.
TRAEFIK_BUMP = f"traefik:v3.7.15@sha256:{'2' * 64}"
SOCKET_PROXY_BUMP = f"wollomatic/socket-proxy:1.13.2@sha256:{'3' * 64}"


@pytest.fixture
def stop(repository, scripted, capsys, state, ingress):
    """Run `hal stop <unit>` with no terminal: the path an agent takes."""

    def run(unit: str = "step-ca", marks: switches.Switches | None = None) -> tuple[int, str, str]:
        exit_code = emergency.stop_unit(
            marks or switches.Switches(state),
            unit,
            NOW,
            compose.Compose(scripted.run, repository),
            repository,
            ingress.verifier,
        )
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return run


def test_switching_on_starts_exactly_the_profiles_services(switch, scripted):
    """#52 rule 2: on names exactly the services of the profile; #75 rule 1: never recreating."""
    exit_code, out, _ = switch()

    assert exit_code == 0
    assert scripted.containers == {
        "step-ca": "running",
        "traefik-mcp-acme-owner": "exited",
        "traefik-mcp": "running",
    }
    starting = ["up", "-d", "--no-recreate", *STEP_CA_SERVICES]
    assert ["--profile", "step-ca", *starting] in scripted.calls
    assert "step-ca is on" in out


def test_switching_on_asks_the_setup_check_first(switch, setup_check, repository):
    """#52 rule 5: a unit that would be switched on is checked with `<setup> --check` first."""
    switch()

    assert setup_check.commands == [[str(repository / "step-ca/init"), "--check"]]


def test_switching_off_removes_the_containers_and_names_the_volumes_that_stay(
    switch, scripted, repository
):
    """#52 rules 2, 3, 6: off removes the containers and the plan names the volumes that stay."""
    write_fleet(repository, DISABLED)
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "running")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert scripted.containers == {}
    assert "step-ca is off" in out
    assert find_row(out, "step-ca", PlanEvent.SWITCH_OFF, "volumes step-ca, traefik-mcp-acme kept")


def test_a_unit_already_as_the_catalog_says_changes_nothing_and_asks_nothing(
    switch, scripted, setup_check, setup_run, repository
):
    """#52 rule 6 / P15: a second run changes nothing and asks no `yes`; the running unit's
    setup is only checked (#118), and a set up unit is not asked."""
    switch()
    scripted.calls.clear()

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []
    assert setup_check.commands[1:] == [[str(repository / "step-ca/init"), "--check"]]
    assert setup_run.commands == []


def test_switching_off_what_is_not_there_changes_nothing(switch, scripted, repository):
    """#52 rule 6: off with no container left is "nothing to change"."""
    write_fleet(repository, DISABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def test_a_one_shot_container_left_behind_is_removed_when_switched_off(
    switch, scripted, repository
):
    """#52 rule 6: a unit is off only when no container of its services exists."""
    write_fleet(repository, DISABLED)
    scripted.containers = {"traefik-mcp-acme-owner": "exited"}

    assert switch()[0] == 0
    assert scripted.containers == {}


def test_off_never_takes_a_volume_or_a_project_down_and_never_names_the_core(
    switch, scripted, repository
):
    """#52 rule 2: no `down`, `-v` or volume command; while the core's definition and files are
    as recorded (here it has no file and no container), traefik and socket-proxy are never named
    (#85 rule 3, #87 rule 3)."""
    switch()
    write_fleet(repository, DISABLED)
    switch()
    write_fleet(repository, ENABLED)
    switch()

    words = {word for call in scripted.calls for word in call}
    assert not words & {"down", "-v", "--volumes", "volume"}
    changing = [call for call in scripted.calls if call[2] not in {"config", "ps"}]
    assert not {"traefik", "socket-proxy"} & {word for call in changing for word in call}
    assert {call[2] for call in changing} == {"up", "stop", "rm"}


@pytest.mark.parametrize(
    ("line", "printed"),
    [
        ("\x1b[31mred\x1b[0m", "\\x1b[31mred\\x1b[0m"),
        ("bell\x07 and tab\t", "bell\\x07 and tab"),
        ("über ✓", "über ✓"),
    ],
)
def test_a_commands_last_line_is_printed_escaped_on_one_line(
    switch, scripted, setup_check, repository, line, printed
):
    """#95 rule 8: Compose's and a setup check's last line pass through the one sanitizer, so ESC
    and other control characters reach the terminal escaped."""
    write_fleet(repository, DISABLED)
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "running")
    scripted.failing_verb = "rm"
    scripted.failure_line = line

    _, _, err = switch()

    assert f"`docker compose rm` exited 1: {printed}" in err
    assert "\x1b" not in err
    setup_check.exit_code, setup_check.line = 1, f"step-ca/init --check:\n{line}"
    step_ca = catalog.Unit("step-ca", True, "step-ca/init")
    assert setup.not_set_up_line(step_ca, repository, setup_check) == printed


def test_a_failed_removal_is_partial_and_never_reported_as_applied(switch, scripted, repository):
    """#52 rule 6: a failed `rm -f` is partial (exit 1), never applied."""
    write_fleet(repository, DISABLED)
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "running")
    scripted.failing_verb = "rm"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial" in err
    assert "step-ca" in err
    assert "last line" in err
    assert "is off" not in out


def test_a_profile_of_servers_without_a_restart_policy_is_on_only_while_they_run(
    switch, scripted, repository
):
    """#52 P15: servers that exited 0 are stopped, not done; only a one-shot may be done."""
    scripted.config["services"]["hello"] = {"profiles": ["probe"]}
    scripted.config["services"]["hello-mcp"] = {"profiles": ["probe"]}
    write_fleet(repository, "services:\n  probe:\n    run: {enabled: true}\n")
    scripted.containers = {"hello": "exited", "hello-mcp": "exited"}

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" not in out
    assert scripted.containers == {"hello": "running", "hello-mcp": "running"}


def test_switching_on_off_on_keeps_the_volumes_and_what_they_hold(switch, scripted, repository):
    """#52 R1 / rule 3: off removes containers only, so on serves the same volume contents."""
    scripted.volumes = {"step-ca": "intermediate-A", "traefik-mcp-acme": "issued-B"}
    held = dict(scripted.volumes)

    switch()
    write_fleet(repository, DISABLED)
    switch()
    assert scripted.containers == {}
    assert scripted.volumes == held
    write_fleet(repository, ENABLED)
    exit_code, _, _ = switch()

    assert exit_code == 0
    assert scripted.volumes == held
    assert scripted.containers["step-ca"] == "running"


def test_a_start_that_leaves_the_unit_down_is_partial(switch, scripted):
    """#52 rule 6 / P15: success only for observed state."""
    scripted.starts_nothing = True

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, step-ca is not on after the change" in err
    assert "is on" not in out


# --- #75: switching on starts existing containers as they are, never recreates them -------------

SWITCH_ON_CELLS = {
    # cell: (containers before, services whose definition changed, the line apply prints)
    "cell 1, all running, nothing changed": (STEP_CA_ON, set(), "nothing to change"),
    "cell 2, db running, app exited, db image changed": (APP_EXITED, {"step-ca"}, "step-ca is on"),
    "cell 4, all exited, definitions changed": (
        dict.fromkeys(STEP_CA_SERVICES, "exited"),
        set(STEP_CA_SERVICES),
        "step-ca is on",
    ),
    "cell 5, no containers, the unit was off": ({}, set(), "step-ca is on"),
    # #34 finding 39: APP_EXITED with nothing changed is cell 2 without the changed definition;
    # cell 6 (an exited one-shot counts as up) is cell 1's data
    "cell 2 without a changed definition": (APP_EXITED, set(), "step-ca is on"),
}


@pytest.mark.parametrize(
    ("before", "changed", "line"), SWITCH_ON_CELLS.values(), ids=SWITCH_ON_CELLS
)
def test_switching_on_keeps_every_existing_container_and_the_volumes(
    switch, scripted, before, changed, line
):
    """#75 rule 1, cells 1, 2, 4, 5, 6: an existing container keeps its id, a missing one is
    created, the volumes are untouched, and the unit is on."""
    scripted.volumes = {"step-ca": "intermediate-A", "traefik-mcp-acme": "issued-B"}
    held = dict(scripted.volumes)
    scripted.put_containers(before)
    for service in changed:
        scripted.change_definition(service)
    existing_ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert line in out
    assert scripted.containers == STEP_CA_ON
    assert {service: scripted.container_ids[service] for service in existing_ids} == existing_ids
    assert scripted.volumes == held


def test_a_switch_on_whose_start_fails_is_partial_as_before(switch, scripted):
    """#75 cell 7 / #52 P15: a failed `up` is partial with Compose's last line, never on."""
    scripted.failing_verb = "up"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, step-ca: could not start, `docker compose up` exited 1: last line" in err
    assert "is on" not in out


def test_the_repositorys_agent_service_unit_starts_both_services_and_then_changes_nothing(
    switch, scripted, setup_check, repository, agent_service_unit
):
    """#214 S1: the real catalog line starts the profile's services; a second apply
    plans nothing. #234: it asks `agent-service/setup --check` before it switches on."""
    exit_code, out, _ = switch()

    assert exit_code == 0
    assert setup_check.commands == [[str(repository / "agent-service/setup"), "--check"]]
    assert "agent-service is on" in out
    assert scripted.containers == dict.fromkeys(agent_service_unit, "running")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == ["up"]


@pytest.mark.usefixtures("agent_service_unit")
@pytest.mark.parametrize(
    "docker_line",
    [
        "Error response from daemon: No such image: edge-agent-service:0.4.0-2.1.302",
        'Error response from daemon: invalid mount config for type "bind": bind source path '
        "does not exist: /home/operator/.secrets/agent-service/claude",
    ],
    ids=["missing image", "missing login directory"],
)
def test_an_agent_service_whose_image_or_login_is_missing_is_partial_and_never_on(
    switch, scripted, docker_line
):
    """#214 S2: apply's own start and its observation carry the precondition; no setup check is
    needed, because Compose refuses the start (`pull_policy: never`, `create_host_path: false`)
    and the unit is never reported on."""
    scripted.failing_verb, scripted.failure_line = "up", docker_line

    exit_code, out, err = switch()

    assert exit_code == 1
    assert (
        f"partial, agent-service: could not start, `docker compose up` exited 1: {docker_line}"
        in err
    )
    assert "agent-service is on" not in out


@pytest.mark.usefixtures("agent_service_unit")
def test_an_agent_service_that_is_created_but_never_runs_is_partial_and_never_on(switch, scripted):
    """#214 S2: a container that exists but does not run is not reported on."""
    scripted.unstartable = {"agent-service"}

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, agent-service" in err
    assert "agent-service is on" not in out


@pytest.mark.usefixtures("agent_service_unit")
def test_an_agent_service_that_runs_and_then_restarts_is_partial_and_never_on(switch, scripted):
    """#214 S2: the first look after `up` sees it running; a refused login makes it restart, and
    the watch finds that before the unit is reported or recorded on."""
    scripted.crash_loops = {"agent-service"}

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, agent-service is not on after the change" in err
    assert "agent-service is on" not in out


def test_every_service_that_is_down_at_any_look_of_the_watch_is_named(
    scripted, repository, ingress
):
    """#214 gate: a service that dies at once and one that restarts only later are both found,
    so neither counts as observed on."""
    engine = compose.Compose(scripted.run, repository)
    scripted.after_up = lambda: scripted.containers.update({"step-ca": "exited"})
    scripted.crash_loops = {"traefik-mcp"}
    engine.start("step-ca", STEP_CA_SERVICES)

    down = engine.down_while_watched(scripted.config, STEP_CA_SERVICES, ingress.watch)

    assert down == ("step-ca", "traefik-mcp")


def test_an_interrupt_names_the_unit_and_says_its_state_may_be_partial(switch, scripted, capsys):
    """#52 rule 6: an interrupt names the unit and says its state may be partial (exit 1)."""

    def interrupted_start(*_arguments):
        raise KeyboardInterrupt

    scripted.verb_up = interrupted_start

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "interrupted while changing step-ca" in err
    assert "may be partial" in err


QUESTION = "Type yes to run `step-ca/init` now"


def test_a_missing_setup_is_asked_separately_before_the_plan(
    switch, scripted, missing_setup, setup_run, repository
):
    """#69 rules 1, 4, 5: `yes` runs the setup, `--check` passes, the plan has its own yes."""
    exit_code, out, _ = switch("yes\nyes")

    assert exit_code == 0
    assert f"step-ca is not set up: {NOT_SET_UP_LINE}" in out
    shown = plain(out)
    assert shown.index(QUESTION) < shown.index("the plan") < shown.index("Type yes to apply")
    assert setup_run.commands == [(repository / "step-ca/init", repository)]
    assert missing_setup.commands[-1][-1] == "--check"
    assert scripted.containers["step-ca"] == "running"


def test_one_yes_does_not_cover_both_the_setup_and_the_plan(switch, scripted, missing_setup):
    """#69 rule 1: the plan has its own question; a declined plan names the completed setup."""
    exit_code, _, err = switch("yes\nno")

    assert exit_code == 1
    assert "setup of step-ca completed; nothing switched" in err
    assert "nothing changed" not in err
    assert scripted.changing_verbs() == []


def test_declining_the_setup_aborts_everything_and_runs_nothing(
    switch, scripted, missing_setup, setup_run
):
    """#69 rule 3: `no` aborts: nothing runs, nothing is switched."""
    exit_code, _, err = switch("no")

    assert exit_code == 1
    assert "aborted, nothing changed; run `step-ca/init` yourself or answer yes" in err
    assert setup_run.commands == []
    assert scripted.changing_verbs() == []


def test_a_closed_stdin_counts_as_no_to_the_setup(switch, missing_setup, setup_run):
    """#69 rule 8: EOF is a no."""
    exit_code, _, _ = switch("")

    assert exit_code == 1
    assert setup_run.commands == []


def test_a_set_up_unit_is_not_asked(switch, setup_run):
    """#69 rule 1: only a unit whose check says not set up is asked."""
    _, out, _ = switch()

    assert "not set up" not in out
    assert setup_run.commands == []


def test_a_running_unit_that_is_not_set_up_is_asked_like_one_switched_on(
    switch, scripted, setup_check, setup_run
):
    """#118: a setup interrupted after its containers started is asked again, and a no ends it."""
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "running")
    setup_check.exit_code, setup_check.line = 1, NOT_SET_UP_LINE

    exit_code, out, err = switch("no")

    assert exit_code == 1
    assert QUESTION in plain(out)
    assert "aborted, nothing changed" in err
    assert setup_run.commands == []


def test_a_unit_switched_off_is_never_asked_about_its_setup(
    switch, repository, missing_setup, setup_run
):
    """#69 rule 2: switching a unit off needs no setup."""
    write_fleet(repository, DISABLED)

    switch()

    assert setup_run.commands == []
    assert missing_setup.commands == []


def test_a_unit_kept_stopped_by_its_marker_is_never_asked(switch, state, missing_setup, setup_run):
    """#69 rule 2: STAYS_STOPPED is not switched on."""
    switch_off(state)

    exit_code, _, _ = switch()

    assert exit_code == 0
    assert setup_run.commands == []


@pytest.mark.parametrize(
    ("setup_outcome", "expected_exit", "expected_words"),
    [
        ({"exit_code": 3}, 1, "failed (exit 3)"),
        ({"exit_code": 130, "interrupted": True}, 1, "interrupted during `step-ca/init`"),
        ({"cannot_start": True}, 2, "cannot start `step-ca/init`"),
    ],
)
def test_a_failed_interrupted_or_unstartable_setup_switches_nothing(
    switch, scripted, missing_setup, setup_run, setup_outcome, expected_exit, expected_words
):
    """#69 rules 5, 6: nothing is switched after a setup that did not succeed."""
    for name, value in setup_outcome.items():
        setattr(setup_run, name, value)

    exit_code, _, err = switch("yes\nyes")

    assert exit_code == expected_exit
    assert expected_words in err
    assert len(missing_setup.commands) == 1  # the first check only: no re-check
    assert scripted.changing_verbs() == []


def test_an_interrupted_setup_says_that_keys_may_exist_and_how_to_go_on(
    switch, missing_setup, setup_run
):
    """#69 rule 6."""
    setup_run.interrupted = True

    _, _, err = switch("yes")

    assert "nothing switched; keys may already exist" in err
    assert err.splitlines()[-1] == "next: hal apply"


def test_a_setup_that_leaves_the_check_failing_is_exit_1(
    switch, scripted, missing_setup, setup_run
):
    """#69 rule 5: --check still 1 after the setup."""
    setup_run.check_afterwards = (1, "still no keys")

    exit_code, _, err = switch("yes\nyes")

    assert exit_code == 1
    assert "`step-ca/init` ran, still not set up: still no keys" in err
    assert scripted.changing_verbs() == []


def test_a_recheck_that_cannot_tell_after_the_setup_is_exit_2(
    switch, scripted, missing_setup, setup_run
):
    """#69 rule 5: --check exits 2 after the setup."""
    setup_run.check_afterwards = (2, "docker is down")

    exit_code, _, err = switch("yes\nyes")

    assert exit_code == 2
    assert "docker is down" in err
    assert scripted.changing_verbs() == []


def test_several_missing_setups_are_all_asked_first_and_a_no_stops_the_rest(
    switch, repository, missing_setup, setup_run
):
    """#69 rule 14: all questions in catalog order, then the runs; a `no` runs none."""
    write_fleet(repository, TWO_SETUPS)

    exit_code, out, _ = switch("yes\nno")

    assert exit_code == 1
    assert out.count("is not set up") == 2
    assert out.index("step-ca is not set up") < out.index("keycloak is not set up")
    assert setup_run.commands == []


def test_several_missing_setups_run_in_catalog_order_before_the_plans_own_question(
    switch, repository, missing_setup, setup_run
):
    """#69 rule 14: questions in catalog order, the setups in turn, then the plan's own yes."""
    write_fleet(repository, TWO_SETUPS)

    exit_code, out, _ = switch("yes\nyes\nyes")

    assert exit_code == 0
    shown = plain(out)
    assert (
        shown.index("run `step-ca/init` now")
        < shown.index("run `keycloak/init` now")
        < shown.index("Type yes to apply")
    )
    assert setup_run.commands == [
        (repository / "step-ca/init", repository),
        (repository / "keycloak/init", repository),
    ]


def test_a_failing_setup_stops_the_rest(switch, repository, missing_setup, setup_run):
    """#69 rule 14: a failed setup runs no later one."""
    write_fleet(repository, TWO_SETUPS)
    setup_run.exit_code = 1

    exit_code, _, _ = switch("yes\nyes")

    assert exit_code == 1
    assert setup_run.commands == [(repository / "step-ca/init", repository)]


def test_every_run_asks_again_until_the_check_says_set_up(
    switch, scripted, missing_setup, setup_run
):
    """#69 rule 9: nothing is remembered; a `no` is asked again, a passing check is not."""
    exit_code, first, _ = switch("no")
    assert exit_code == 1
    assert "step-ca is not set up" in first

    _, second, _ = switch("no")
    assert "step-ca is not set up" in second

    missing_setup.exit_code = 0
    exit_code, third, _ = switch("yes")

    assert exit_code == 0
    assert "not set up" not in third
    assert setup_run.commands == []


def test_the_plan_is_made_again_after_the_setup_from_the_states_it_left(
    switch, state, missing_setup, setup_run
):
    """#69 rule 1: states are re-read after the setup; a switch set meanwhile holds the unit."""
    setup_run.meanwhile = lambda: switch_off(state)

    exit_code, out, _ = switch("yes")

    assert exit_code == 0
    assert "nothing to change" in out


def test_a_unit_that_became_on_during_the_setup_is_refused_without_a_question_and_nothing_switches(
    switch, repository, scripted, missing_setup, setup_run
):
    """#69 rule 1: a unit that became ON during the setup still needs its own set-up check."""

    def enable_keycloak_whose_check_fails() -> None:
        write_fleet(repository, TWO_SETUPS)
        missing_setup.failing_command = "keycloak/init"

    setup_run.meanwhile = enable_keycloak_whose_check_fails

    exit_code, _, err = switch("yes")

    assert exit_code == 1
    assert "keycloak is not set up" in err
    assert scripted.changing_verbs() == []


def test_a_setup_check_that_cannot_tell_is_cannot_plan_and_quotes_its_line(
    switch, scripted, setup_check
):
    """#52 rule 5: a setup check that cannot tell is exit 2 and quoted."""
    setup_check.exit_code, setup_check.line = 2, "Cannot connect to the Docker daemon"

    exit_code, _, err = switch()

    assert exit_code == 2
    assert "Cannot connect to the Docker daemon" in err
    assert scripted.changing_verbs() == []


def test_a_setup_that_is_set_up_is_only_ever_checked_never_run(switch, setup_check, setup_run):
    """#69 rule 1: without a missing setup the command is only called with `--check`."""
    switch()

    assert all(command[-1] == "--check" for command in setup_check.commands)
    assert setup_run.commands == []


@pytest.fixture(params=["live checkout", "another copy"])
def any_tree(request, repository: Path, tmp_path: Path) -> Path:
    return repository if request.param == "live checkout" else edge_tree(tmp_path / "x" / "edge")


def apply_lock_is_free(state: Path) -> bool:
    with apply_lock(state).open("a") as probe:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


def test_without_a_terminal_it_refuses_before_anything_else(
    any_tree, scripted, missing_setup, setup_run, monkeypatch, capsys, state, home, scripted_git
):
    """#52 rule 4: no terminal refuses first (exit 1); #79 cell 6, #95 R1 and G1: before every
    other guard, from any tree: no git call, no lock file, `.env` untouched."""
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))
    environment_file = (any_tree / ".env").stat()

    exit_code = apply.apply_local(
        state, compose.Compose(scripted.run, any_tree), any_tree, missing_setup, setup_run, home,
        git=scripted_git,
    )  # fmt: skip

    assert exit_code == 1
    assert "refused, stdin and stdout must be a terminal" in capsys.readouterr().err
    assert scripted.calls == []
    assert missing_setup.commands == []
    assert setup_run.commands == []
    assert scripted_git.calls == []
    assert not apply_lock(state).exists()
    assert (any_tree / ".env").stat() == environment_file


def test_from_another_copy_it_refuses_naming_the_tree_and_runs_nothing(
    switch, scripted, setup_check, setup_run, scripted_git, state, tmp_path
):
    """#79 rule 1 cell 3, #95 rule 2 and G2/G5: the one apply-level cell of the live-checkout
    guard; exit 2, one line naming the tree, no compose or git call, no lock."""
    copy = edge_tree(tmp_path / "x" / "edge")

    exit_code, _, err = switch(tree=copy)

    assert exit_code == 2
    assert err.splitlines() == [
        f"error: runs only from the live checkout {checkout.LIVE_CHECKOUT} (this is {copy})"
    ]
    assert scripted.calls == []
    assert scripted_git.calls == []
    assert setup_check.commands == []
    assert setup_run.commands == []
    assert not apply_lock(state).exists()


def test_the_live_checkout_reached_through_a_symlinked_home_applies(
    switch, scripted, home, tmp_path
):
    """#79 cell 4: a HOME that resolves to the code tree's home proceeds as from the checkout."""
    linked_home = tmp_path / "linked-home"
    linked_home.symlink_to(home)

    exit_code, _, _ = switch(from_home=linked_home)

    assert exit_code == 0
    assert scripted.containers["step-ca"] == "running"


ENVIRONMENT_FILE_LINES = f"EDGE_DOMAIN={ZONE}\nDOCKER_GID={DOCKER_GID}\n"


def test_a_missing_environment_file_is_written_and_the_plan_follows(switch, scripted, repository):
    """#136 E1: `.env` written with both settings, private, one line saying so; then the plan."""
    (repository / ".env").unlink()

    exit_code, out, err = switch(ensure_environment=writing_environment())

    assert exit_code == 0
    assert (repository / ".env").read_text().endswith(ENVIRONMENT_FILE_LINES)
    assert stat.S_IMODE((repository / ".env").stat().st_mode) == 0o600
    assert ".env" not in err
    assert "step-ca" in out
    assert scripted.containers["step-ca"] == "running"


def test_a_matching_environment_file_is_untouched_and_silent(switch, repository):
    """#136 E2, E3: the right two keys, with a hand-added key besides, stay as they are."""
    (repository / ".env").write_text("HAND_ADDED=1\n" + ENVIRONMENT_FILE_LINES)
    before = (repository / ".env").stat()
    content = (repository / ".env").read_text()

    exit_code, _, err = switch(ensure_environment=writing_environment())

    assert exit_code == 0
    assert ".env" not in err
    after = (repository / ".env").stat()
    assert (after.st_ino, after.st_mtime_ns) == (before.st_ino, before.st_mtime_ns)
    assert (repository / ".env").read_text() == content


def test_a_differing_environment_file_is_named_and_left_alone(
    switch, scripted, scripted_git, repository
):
    """#136 E4, rule 4: exit 2 with the key, both values, the way out; after the fetch."""
    (repository / ".env").write_text(f"EDGE_DOMAIN=old.invalid\nDOCKER_GID={DOCKER_GID}\n")

    exit_code, _, err = switch(ensure_environment=writing_environment())

    assert exit_code == 2
    assert err.splitlines() == [
        f'error: {repository / ".env"}: EDGE_DOMAIN is "old.invalid" but edge '
        f'derives "{ZONE}"; delete it and `hal apply` writes it again'
    ]
    assert (repository / ".env").read_text().startswith("EDGE_DOMAIN=old.invalid")
    assert scripted.calls == []
    assert "fetch" in [call[0] for call in scripted_git.calls]


def test_without_a_docker_group_it_refuses_and_writes_nothing(switch, repository):
    """#136 E7: exit 2 naming the group."""
    (repository / ".env").unlink()

    no_docker_group = {}.__getitem__  # every lookup raises KeyError

    exit_code, _, err = switch(ensure_environment=writing_environment(no_docker_group))

    assert exit_code == 2
    assert "`docker` group" in err
    assert not (repository / ".env").exists()


def refused_by(guard: str, repository: Path, scripted_git: ScriptedGit, tmp_path: Path):
    """Arranges `guard` to fail; returns the tree to run in and the kwargs for the switch."""
    if guard == "another copy":
        return edge_tree(tmp_path / "x" / "edge"), {}
    if guard == "no terminal":
        return repository, {"at_a_terminal": False}
    if guard == "off main":
        scripted_git.reference = b"refs/heads/feature\n"
    if guard == "dirty":
        scripted_git.status = b" M fleet.yaml\0"
    return repository, {}


@pytest.mark.parametrize("guard", ["another copy", "no terminal", "off main", "dirty"])
def test_a_run_a_guard_refuses_never_writes_an_environment_file(
    guard, switch, repository, scripted_git, tmp_path
):
    """#136 E9, E10, E11: refused by I1, R1, S2 or S1 first; no `.env` written anywhere."""
    tree, options = refused_by(guard, repository, scripted_git, tmp_path)
    (tree / ".env").unlink()

    exit_code, _, _ = switch(tree=tree, ensure_environment=writing_environment(), **options)

    assert exit_code != 0
    assert not (tree / ".env").exists()


def test_while_another_apply_runs_it_never_writes_an_environment_file(switch, repository, state):
    """#136 E11: refused by S8 first."""
    (repository / ".env").unlink()

    with apply_lock_held(state):
        exit_code, _, _ = switch(ensure_environment=writing_environment())

    assert exit_code == 1
    assert not (repository / ".env").exists()


def test_while_another_apply_runs_it_refuses_and_touches_nothing(
    switch, scripted, scripted_git, state
):
    """#95 rule 4, S8, G8: exit 1, the line names both commands (#783);
    no git or compose call."""
    with apply_lock_held(state):
        exit_code, _, err = switch()

    assert exit_code == 1
    assert err == "error: another `hal apply` or `hal update` is running; nothing changed\n"
    assert scripted.calls == []
    assert scripted_git.calls == []


def test_the_state_directory_and_the_lock_are_created_private(switch, state):
    """#95 rule 4, G11: a missing state directory is created 0700, `apply.lock` 0600."""
    assert not state.exists()

    switch()

    assert stat.S_IMODE(state.stat().st_mode) == 0o700
    assert stat.S_IMODE(apply_lock(state).stat().st_mode) == 0o600


def git_that_is_missing(_tree, _arguments, _profile):
    raise FileNotFoundError(2, "No such file or directory")


def git_that_breaks(_tree, _arguments, _profile):
    raise RuntimeError("a defect")


@pytest.mark.parametrize(
    ("arrange", "outcome"),
    [
        pytest.param({}, 0, id="exit 0"),
        pytest.param({"answer": "no"}, 1, id="exit 1"),
        pytest.param({"git": git_that_is_missing}, 2, id="exit 2, git missing (G25)"),
        pytest.param({"git": git_that_breaks}, RuntimeError, id="an exception"),
        pytest.param({"while_prompt_waits": interrupted_at_the_prompt}, KeyboardInterrupt,
                     id="Ctrl-C"),
    ],
)  # fmt: skip
def test_the_lock_is_free_again_however_the_apply_ends(switch, state, arrange, outcome):
    """#95 rule 4, G9 and G25: after exit 0, 1, 2, an exception or Ctrl-C the lock is free."""
    if isinstance(outcome, int):
        exit_code, _, _ = switch(**arrange)
        assert exit_code == outcome
    else:
        with pytest.raises(outcome):
            switch(**arrange)

    assert apply_lock_is_free(state)


def test_a_missing_git_is_one_line(switch):
    """#95 G25: git missing is exit 2 with one line."""
    exit_code, _, err = switch(git=git_that_is_missing)

    assert exit_code == 2
    assert err.splitlines() == [
        "error: cannot read the live checkout, cannot run git (No such file or directory)"
    ]


def test_a_lock_that_flock_refuses_is_exit_2_and_leaves_no_descriptor_open(
    switch, state, scripted_git, monkeypatch
):
    """#95 rule 4: a flock error other than contention (ENOLCK) is exit 2 with one line, and the
    descriptor opened for `apply.lock` is closed again."""
    refused = refuse_flock(monkeypatch, OSError(errno.ENOLCK, os.strerror(errno.ENOLCK)))

    exit_code, _, err = switch()

    assert exit_code == 2
    assert err.splitlines() == [
        f"error: cannot take {apply_lock(state)} ({os.strerror(errno.ENOLCK)})"
    ]
    assert scripted_git.calls == []
    assert_closed(refused[0])


def test_a_ctrl_c_inside_flock_closes_the_descriptor_and_propagates(
    switch, scripted_git, monkeypatch
):
    """#95 rule 4 (#34 finding 67): `_take_apply_lock`'s path for an error that is no
    BlockingIOError closes the descriptor and re-raises; nothing else runs."""
    refused = refuse_flock(monkeypatch, KeyboardInterrupt())

    with pytest.raises(KeyboardInterrupt):
        switch()

    assert scripted_git.calls == []
    assert_closed(refused[0])


def refuse_flock(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> list[int]:
    """flock raises `error`; the descriptors it was asked for are returned."""
    refused: list[int] = []

    def flock(descriptor: int, _operation: int) -> None:
        refused.append(descriptor)
        raise error

    monkeypatch.setattr(apply.fcntl, "flock", flock)
    return refused


def assert_closed(descriptor: int) -> None:
    with pytest.raises(OSError) as closed:
        os.fstat(descriptor)
    assert closed.value.errno == errno.EBADF


def test_a_stop_never_waits_for_a_running_apply(switch, stop, state, ingress):
    """#95 rule 4, P7 and G10: `hal stop S` and `hal offline` complete while an apply holds
    the lock at its prompt."""
    stopped: list[int] = []

    def stop_both() -> None:
        assert not apply_lock_is_free(state)
        stopped.append(stop()[0])
        marks = switches.Switches(state)
        door = tunnel.Tunnel(run=lambda command: subprocess.CompletedProcess(command, 0, ""))
        emergency.stop_all(marks, NOW, door)
        stopped.append(int(marks.global_mark() is not None))

    switch("no", while_prompt_waits=stop_both)

    assert stopped == [0, 1]
    assert marker(state) == NOW.isoformat(timespec="seconds")


@pytest.mark.parametrize(
    ("reference", "status", "lines"),
    [
        pytest.param(b"refs/heads/feature\n", b"",
                     ["error: runs only on main (this is branch feature)"],
                     id="G12 another branch"),
        pytest.param(b"refs/heads/main\n", b" M fleet.yaml\0?? dynamic/x.yml\0", [
            "error: the live checkout has local changes, nothing changed",
            f"next: git -C {checkout.LIVE_CHECKOUT} status",
        ], id="G15 G17 changed paths"),
    ],
)  # fmt: skip
def test_off_main_or_with_changes_it_refuses_naming_why(
    switch, scripted, scripted_git, reference, status, lines
):
    """#95 rules 5 and 6: exit 2, the reason or every changed path; no compose call."""
    scripted_git.reference, scripted_git.status = reference, status

    exit_code, _, err = switch()

    assert exit_code == 2
    assert err.splitlines() == lines
    assert scripted.calls == []


@pytest.mark.parametrize("waiting", [0, 2], ids=["B3 ahead", "B4 diverged"])
def test_a_checkout_ahead_of_or_beside_origin_is_refused_and_nothing_reset(
    switch, scripted, real_main, origin, waiting
):
    """#98 rule 3, B3 and B4 (S3): exit 2 naming both shas; no compose call; nothing reset."""
    local_commit(real_main)
    tip = advance(origin, *subjects(*(f"waiting {n}" for n in range(waiting))))
    head = head_of(real_main)
    before = checkout_state(real_main)

    exit_code, _, err = switch(git=checkout.run_git)

    standing = "is ahead of" if waiting == 0 else "has diverged from"
    assert exit_code == 2
    assert err.splitlines() == [
        f"error: the live checkout {standing} origin main (HEAD "
        f"{short(real_main)}, origin main {short(real_main, tip)}); nothing reset, a change "
        "reaches it through a pull request"
    ]
    assert scripted.calls == []
    assert (head_of(real_main), checkout_state(real_main)) == (head, before)


def remove_the_repository(_real_main: Path, origin: Path) -> None:
    shutil.rmtree(origin)


def point_at_a_password_url(real_main: Path, _origin: Path) -> None:
    plain_git(real_main, "remote", "set-url", "origin", "https://u:s3cr3t-pw@127.0.0.1:1/x")


@pytest.mark.parametrize(
    ("arrange", "line"),
    [
        pytest.param(remove_the_repository,
                     "`git fetch` exited 128: fatal: Could not read from remote repository",
                     id="B5 the remote removed"),
        pytest.param(point_at_a_password_url,
                     "`git fetch` exited 128: fatal: URL 'https://<redacted>@127.0.0.1:1/x' "
                     "uses plaintext credentials", id="B6 a password in the URL"),
    ],
)  # fmt: skip
def test_a_failed_fetch_is_exit_2_with_gits_line_and_changes_nothing(
    switch, scripted, real_main, origin, state, arrange, line
):
    """#98 rule 2, B5 and B6 (S4, R3): exit 2 naming git's last error line, never the password;
    no compose call; the checkout untouched; the lock free."""
    arrange(real_main, origin)
    before = checkout_state(real_main)

    exit_code, _, err = switch(git=checkout.run_git)

    assert exit_code == 2
    assert err.splitlines() == [f"error: cannot fetch main from origin, {line}; nothing changed"]
    assert scripted.calls == []
    assert checkout_state(real_main) == before
    assert apply_lock_is_free(state)


def test_a_fetch_that_times_out_is_exit_2_and_frees_the_lock(switch, scripted, scripted_git, state):
    """#98 rule 2, B16 (S4): the transfer timeout is exit 2 with one line; the lock is free."""
    scripted_git.fetch_error = subprocess.TimeoutExpired("git", 120)

    exit_code, _, err = switch()

    assert exit_code == 2
    assert err.splitlines() == [
        "error: cannot fetch main from origin, `git fetch` took longer than 120s; nothing changed"
    ]
    assert scripted.calls == []
    assert apply_lock_is_free(state)


def test_a_clean_main_in_real_git_switches_on_as_before(switch, scripted, real_main):
    """#95 G30: real git, a clean `main`: the switch-on cell of #52 rule 2 passes unchanged."""
    exit_code, out, _ = switch(git=checkout.run_git)

    assert exit_code == 0
    assert scripted.containers["step-ca"] == "running"
    assert "step-ca is on" in out


def test_traefik_yml_replaced_by_a_directory_refuses_before_compose(switch, scripted, real_main):
    """#95 rule 6, G19 (#34 finding 49): real git; exit 2 naming `traefik.yml`, no compose call."""
    (real_main / "traefik.yml").unlink()
    (real_main / "traefik.yml").mkdir()

    exit_code, out, _ = switch(git=checkout.run_git)

    assert exit_code == 2
    assert "traefik.yml" in detail_lines(out)
    assert scripted.calls == []


def test_a_setup_child_that_outlives_the_apply_leaves_the_lock_free(
    switch, missing_setup, repository, state, tmp_path
):
    """#95 rule 4, G28: a real setup leaves a child running; it inherited no lock descriptor."""
    pid_file = tmp_path / "child.pid"
    (repository / "step-ca" / "init").write_text(
        f"#!/bin/sh\nsleep 60 </dev/null >/dev/null 2>&1 &\necho $! > {pid_file}\n"
    )

    def real_setup(command: Path, working_directory: Path) -> setup.SetupRun:
        ran = setup.run_setup(command, working_directory)
        missing_setup.exit_code, missing_setup.line = 0, "step-ca/init --check: set up"
        return ran

    try:
        exit_code, _, _ = switch("yes\nyes", run_setup=real_setup)
        assert exit_code == 0
        assert apply_lock_is_free(state)
    finally:
        if pid_file.exists():
            os.kill(int(pid_file.read_text()), signal.SIGTERM)


GUARD_LINES = (
    "refused, stdin and stdout must be a terminal",
    "runs only from the live checkout",
    "is running; nothing changed",
    "runs only on main",
    "the live checkout has local changes",
    "delete it and `hal apply` writes it again",
)


@pytest.mark.parametrize("first", range(len(GUARD_LINES)), ids=GUARD_LINES)
def test_only_the_first_failing_guard_speaks(
    switch, scripted, scripted_git, repository, state, tmp_path, first
):
    """#95 rule 1 and G29, #136 E14: with every guard from `first` on failing, only its line
    appears, in the order terminal, live checkout, `apply.lock`, `main`, clean, `.env`."""
    tree = repository if first > 1 else edge_tree(tmp_path / "x" / "edge")
    (tree / ".env").write_text("")
    if first <= 3:
        scripted_git.reference = b"refs/heads/feature\n"
    if first <= 4:
        scripted_git.status = b" M fleet.yaml\0"

    with apply_lock_held(state) if first <= 2 else nullcontext():
        exit_code, _, err = switch(
            tree=tree, at_a_terminal=first > 0, ensure_environment=writing_environment()
        )

    assert [line for line in GUARD_LINES if line in err] == [GUARD_LINES[first]]
    assert exit_code == (1 if first in (0, 2) else 2)
    assert scripted.calls == []


@pytest.mark.parametrize("answer", ["no", "", "Yes", "y", "yes please"])
def test_only_the_exact_yes_applies(switch, scripted, answer):
    """#52 rule 4: any answer but the exact `yes` aborts with nothing changed."""
    exit_code, _, err = switch(answer)

    assert exit_code == 1
    assert "aborted, nothing changed" in err
    assert scripted.changing_verbs() == []


@pytest.mark.parametrize(
    ("fleet", "named"),
    [
        ("- a\n- b\n", "fleet.yaml: must be a map"),
        ("services: false\n", "services: must be a map"),
        ("services: []\n", "services: must be a map"),
        ("services:\n  stepca:\n    run: {enabled: true}\n", "services.stepca"),
        ("services:\n  step-ca:\n    run: {enabled: 'yes'}\n", "services.step-ca.run.enabled"),
        ("services:\n  step-ca:\n    run: {}\n", "services.step-ca.run.enabled"),
        (
            "services:\n  step-ca:\n    run: {enabled: true, health: /up}\n",
            "services.step-ca.run.health",
        ),
        (
            "services:\n  step-ca:\n    run: {enabled: true, setup: step-ca/missing}\n",
            "services.step-ca.run.setup",
        ),
        (
            "services:\n  step-ca:\n    run: {enabled: true, setup: fleet.yaml}\n",
            "services.step-ca.run.setup",
        ),
    ],
)
def test_an_invalid_catalog_is_cannot_plan_with_one_line_naming_the_key(
    switch, scripted, repository, fleet, named
):
    """#52 rule 1: each catalog counterexample is exit 2 with a line that names the key."""
    write_fleet(repository, fleet)

    exit_code, _, err = switch()

    assert exit_code == 2
    assert named in err
    assert scripted.changing_verbs() == []


def test_the_line_for_an_unknown_profile_lists_the_profiles_that_exist(switch, repository):
    """#52 rule 1: the unknown-profile line lists the profiles that exist."""
    write_fleet(repository, "services:\n  stepca:\n    run: {enabled: true}\n")

    _, _, err = switch()

    assert "profiles: keycloak, probe, step-ca" in err


def test_an_entry_without_run_is_ignored(switch, scripted, repository):
    """#52 rule 1: an entry without `run` belongs to other readers."""
    write_fleet(repository, "services:\n  songmaker:\n    repo: overnightworks/songmaker\n")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out


def test_compose_that_cannot_be_read_is_cannot_plan(switch, scripted):
    """#52 rule 6: unreadable Compose configuration is exit 2."""
    scripted.failing_verb = "config"

    exit_code, _, err = switch()

    assert exit_code == 2
    assert "cannot plan" in err
    assert "last line" in err


def test_a_routed_unit_without_traefiks_edge_domain_is_cannot_plan(switch, scripted, repository):
    """#85 rule 7: a barrier that cannot be named is cannot plan, exit 2, and changes nothing."""
    write_fleet(repository, PROBE_ENABLED)
    del scripted.config["services"]["traefik"]["environment"]["EDGE_DOMAIN"]

    exit_code, _, err = switch()

    assert exit_code == 2
    assert "cannot plan, compose.yaml gives traefik no EDGE_DOMAIN" in err
    assert scripted.changing_verbs() == []


# --- catalog and compose cannot drift (catalog -> compose) --------------------------------------


def repository_profiles() -> dict[str, tuple[str, ...]]:
    return compose.profile_services(yaml.safe_load((REPOSITORY / "compose.yaml").read_text()))


def test_every_unit_of_the_repositorys_catalog_names_a_compose_profile_with_services():
    """#52 rule 9: the repository's catalog and compose.yaml do not drift."""
    document = yaml.safe_load((REPOSITORY / "fleet.yaml").read_text())

    units = catalog.units(document, repository_profiles(), REPOSITORY)

    assert {unit.key for unit in units} >= {"step-ca"}


def test_a_catalog_key_without_a_compose_profile_fails_the_drift_check():
    """#52 rule 9: the drift check fails on a key without a profile."""
    document = {"services": {"keycloack": {"run": {"enabled": False}}}}
    profiles = repository_profiles()

    with pytest.raises(catalog.CatalogError, match=r"services\.keycloack"):
        catalog.units(document, profiles, REPOSITORY)


# --- the emergency switch (#60): marker, hal stop, hal start, apply's precedence ----------------


# (exit, marker afterwards, changing verbs, asked for `yes`)
STATE_TABLE = {
    ("A", "stop"): (0, True, ["stop"], False),
    ("B", "stop"): (0, True, [], False),
    ("E", "stop"): (0, False, [], False),
    ("A", "start"): (0, False, [], False),
    ("B", "start"): (0, False, ["up"], True),
    ("E", "start"): (1, False, [], False),
    ("A", "switch"): (0, False, [], False),
    ("B", "switch"): (0, True, [], False),
    ("E", "switch"): (0, False, [], False),
}


@pytest.mark.parametrize(("situation", "command"), list(STATE_TABLE))
def test_the_state_table_cells_of_stop_start_and_apply(
    situation, command, request, scripted, repository, state
):
    """#60 proof (a) / §8: the states A, B, E crossed with the three commands."""
    put_unit_in(situation, scripted, repository, state)
    scripted.calls.clear()
    run = request.getfixturevalue(command)

    exit_code, out, _ = run()

    exit_wanted, marker_wanted, verbs_wanted, asked_wanted = STATE_TABLE[(situation, command)]
    assert exit_code == exit_wanted
    assert (marker(state) is not None) is marker_wanted
    assert scripted.changing_verbs() == verbs_wanted
    assert ("Type yes to " in plain(out)) is asked_wanted


def test_stop_records_the_time_in_a_private_marker_before_closing(
    stop, scripted, repository, state
):
    """#60 rule 1 and 2: one 0600 file in a 0700 directory; it exists before the first `stop`."""
    put_unit_in("A", scripted, repository, state)
    seen_at_stop = []
    closing = scripted.verb_stop

    def stop_and_look(profile, arguments):
        seen_at_stop.append(marker(state))
        return closing(profile, arguments)

    scripted.verb_stop = stop_and_look

    exit_code, out, _ = stop()

    assert exit_code == 0
    assert seen_at_stop == [NOW.isoformat(timespec="seconds")]
    assert all(part in out for part in ("✓ step-ca", "switched off"))
    assert stat.S_IMODE((state / "stopped").stat().st_mode) == 0o700
    assert stat.S_IMODE((state / "stopped" / "step-ca").stat().st_mode) == 0o600


def test_stop_stops_exactly_the_units_services_and_removes_nothing(
    stop, scripted, repository, state
):
    """#60 rule 2: never rm, down, -v or volume rm; never traefik or socket-proxy."""
    put_unit_in("A", scripted, repository, state)
    scripted.volumes = {"step-ca": "intermediate-A"}

    stop()

    assert ["--profile", "step-ca", "stop", *STEP_CA_SERVICES] in scripted.calls
    assert scripted.volumes == {"step-ca": "intermediate-A"}
    assert {"step-ca", "traefik-mcp"} <= set(scripted.containers)
    words = {word for call in scripted.calls for word in call}
    assert not words & {"down", "rm", "-v", "--volumes", "volume", "traefik", "socket-proxy"}


def test_stop_of_a_unit_without_a_host_says_there_is_no_barrier_and_writes_none(
    stop, scripted, repository, state
):
    """#61 rule 1: step-ca has no router on `edge`, so no `dynamic/switch-step-ca.yml`."""
    put_unit_in("A", scripted, repository, state)

    exit_code, out, _ = stop()

    assert exit_code == 0
    assert "no host, so no barrier · stopped" in out
    assert not (repository / "dynamic" / "switch-step-ca.yml").exists()


def test_a_stop_that_fails_leaves_the_switch_and_says_partial(stop, scripted, repository, state):
    """#60 rule 2 partial: the marker stays, exit 1, Compose's last line, never "switched off"."""
    put_unit_in("A", scripted, repository, state)
    scripted.failing_verb = "stop"

    exit_code, out, err = stop()

    assert exit_code == 1
    assert marker(state) is not None
    assert all(part in out for part in ("partial", "switch recorded"))
    assert "error: step-ca is only partly off" in err
    assert all(part in err for part in ("next: hal stop step-ca", "last line"))
    assert "switched off" not in out + err


def test_a_container_that_still_runs_after_the_stop_is_partial(stop, scripted, repository, state):
    """#60 rule 2 partial: a container still running after the stop is exit 1."""
    put_unit_in("A", scripted, repository, state)
    scripted.verb_stop = lambda *_: ""

    exit_code, out, err = stop()

    assert exit_code == 1
    assert "a container of it still runs" in err
    assert "switched off" not in out + err


def test_a_switch_that_cannot_be_written_still_closes_the_unit(stop, scripted, repository, state):
    """#60 rule 2: closing wins over the record; exit 1 says apply would start it again."""
    put_unit_in("A", scripted, repository, state)
    state.mkdir(parents=True)
    state.chmod(0o500)
    try:
        exit_code, out, _ = stop()
    finally:
        state.chmod(0o700)

    assert exit_code == 1
    assert scripted.containers["step-ca"] == "exited"
    assert "stopped, hal apply would start it again" in out
    assert "switch not recorded" in out


def test_stop_stops_a_switched_off_unit_again_when_something_of_it_runs(
    stop, scripted, repository, state
):
    """#60 rule 2 from B: someone started it by hand; the marker keeps its first time."""
    put_unit_in("B", scripted, repository, state)
    scripted.containers["traefik-mcp"] = "running"

    exit_code, _, _ = stop()

    assert exit_code == 0
    assert scripted.containers["traefik-mcp"] == "exited"
    assert marker(state) == SWITCHED_OFF_AT


def test_stop_closes_a_disabled_unit_that_runs_anyway(stop, scripted, repository, state):
    """#60 rule 2 from E: an emergency stop never refuses to close a running unit."""
    write_fleet(repository, DISABLED)
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "running")

    exit_code, _, _ = stop()

    assert exit_code == 0
    assert marker(state) is not None
    assert "running" not in scripted.containers.values()


def test_stop_of_an_unknown_unit_is_cannot_plan_and_lists_the_units(stop, scripted, state):
    """#60 rule 2: an unknown unit is exit 2, lists the units and changes nothing."""
    exit_code, _, err = stop("stepca")

    assert exit_code == 2
    assert "units: step-ca" in err
    assert scripted.changing_verbs() == []
    assert marker(state, "step-ca") is None


def test_start_without_a_terminal_refuses_before_anything_else(
    start, scripted, state, monkeypatch, repository, capsys
):
    """#60 rule 3: start is the operator's step; without a terminal nothing happens."""
    switch_off(state)
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))

    exit_code = emergency.start_unit(
        switches.Switches(state), "step-ca", compose.Compose(scripted.run, repository)
    )

    assert exit_code == 1
    assert "refused, stdin and stdout must be a terminal" in capsys.readouterr().err
    assert scripted.calls == []
    assert marker(state) == SWITCHED_OFF_AT


@pytest.mark.parametrize("answer", ["no", "", "Yes", "y"])
def test_start_with_any_answer_but_yes_aborts_and_keeps_the_switch(start, scripted, state, answer):
    """#60 rule 3: only the exact `yes` ends a switch."""
    switch_off(state)

    exit_code, _, err = start(answer)

    assert exit_code == 1
    assert "aborted, nothing changed" in err
    assert marker(state) == SWITCHED_OFF_AT
    assert scripted.changing_verbs() == []


@pytest.mark.usefixtures("agent_service_unit")
def test_a_start_of_an_agent_service_that_restarts_is_partial_and_never_on(start, scripted, state):
    """P15, #214: `hal start` decides through the watch, not one look: a login the upstream
    refuses makes the container restart, and the unit stays switched off."""
    switch_off(state, unit="agent-service")
    scripted.crash_loops = {"agent-service"}

    exit_code, out, err = start(unit="agent-service")

    assert exit_code == 1
    assert "partial, agent-service is not on after the start; its switch stays" in err
    assert marker(state, "agent-service") == SWITCHED_OFF_AT
    assert "is on" not in out


@pytest.mark.parametrize("failure", ["failing_verb", "starts_nothing"])
def test_a_start_that_fails_or_is_not_observed_keeps_the_switch(start, scripted, state, failure):
    """#60 rule 3: the marker is cleared only after the unit is observed on."""
    switch_off(state)
    setattr(scripted, failure, "up" if failure == "failing_verb" else True)

    exit_code, out, err = start()

    assert exit_code == 1
    assert "partial" in err
    assert marker(state) == SWITCHED_OFF_AT
    assert "is on" not in out


def test_start_keeps_the_running_db_container_whose_image_changed(start, scripted, state):
    """#75 rule 1, cell 3: `hal start` starts the exited app and leaves the running db as is."""
    switch_off(state)
    scripted.put_containers(APP_EXITED)
    scripted.change_definition("step-ca")
    db_id = scripted.container_ids["step-ca"]

    exit_code, out, _ = start()

    assert exit_code == 0
    assert "step-ca is on" in out
    assert scripted.containers == STEP_CA_ON
    assert scripted.container_ids["step-ca"] == db_id


def test_start_of_a_disabled_unit_is_refused_and_keeps_its_switch(start, repository, state):
    """#60 rule 3 from E: a re-enabled unit stays closed until `hal start`."""
    write_fleet(repository, DISABLED)
    switch_off(state)

    exit_code, _, err = start()

    assert exit_code == 1
    assert "step-ca is disabled in the catalog; enable it by PR and `hal apply`" in err
    assert marker(state) == SWITCHED_OFF_AT


def test_apply_to_a_disabled_switched_off_unit_removes_the_containers_and_keeps_the_switch(
    switch, scripted, repository, state
):
    """#60 rule 4 B to E: the usual off; the volumes and the switch stay."""
    put_unit_in("B", scripted, repository, state)
    write_fleet(repository, DISABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert scripted.containers == {}
    assert find_row(out, "step-ca", PlanEvent.SWITCH_OFF, "its switch since 17.10. 22:10 stays")
    assert marker(state) == SWITCHED_OFF_AT


def test_a_re_enabled_unit_with_a_switch_stays_stopped_and_nothing_is_created(
    switch, scripted, repository, state
):
    """#60 rule 4 E with a marker to B: nothing is created or started."""
    write_fleet(repository, DISABLED)
    switch_off(state)
    write_fleet(repository, ENABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.STAYS_STOPPED, "switched off since 17.10. 22:10")
    assert "nothing to change" in out
    assert scripted.calls[-1][2] == "ps"
    assert scripted.changing_verbs() == []


def test_a_switch_that_appears_after_the_plan_keeps_the_unit_down(switch, scripted, state):
    """#60 rule 5: apply reads the marker again after `yes`, before the `up`."""
    exit_code, out, err = switch(while_prompt_waits=lambda: switch_off(state))

    assert exit_code == 1
    assert "step-ca was switched off meanwhile (since 17.10. 22:10); not started" in err
    assert scripted.changing_verbs() == []
    assert "is on" not in out


def test_a_switch_renewed_during_a_start_is_kept(start, scripted, state):
    """#60 rule 5: start clears the marker only if it still holds the time it read."""
    switch_off(state)
    starting = scripted.verb_up

    def start_while_a_new_stop_arrives(profile, arguments):
        output = starting(profile, arguments)
        (state / "stopped" / "step-ca").write_text(LATER_SWITCH_AT)
        return output

    scripted.verb_up = start_while_a_new_stop_arrives

    exit_code, _, err = start()

    assert exit_code == 1
    assert "switched off again (since 17.10. 23:30)" in err
    assert marker(state) == LATER_SWITCH_AT


def test_a_new_stop_during_the_start_prompt_stops_the_start_before_up(start, scripted, state):
    """#60 rule 5: start reads the marker again after `yes`, immediately before its `up`."""
    switch_off(state)

    exit_code, out, err = start(
        while_prompt_waits=lambda: (state / "stopped" / "step-ca").write_text(LATER_SWITCH_AT)
    )

    assert exit_code == 1
    assert scripted.changing_verbs() == []
    assert "partial: step-ca was switched off meanwhile (since 17.10. 23:30); not started" in err
    assert "is on" not in out
    assert marker(state) == LATER_SWITCH_AT


def test_another_start_during_the_start_prompt_ends_this_start_without_up(start, scripted, state):
    """#60 rule 5: a marker that is gone means another start ended the switch."""
    switch_off(state)

    exit_code, out, err = start(while_prompt_waits=lambda: (state / "stopped" / "step-ca").unlink())

    assert exit_code == 0
    assert scripted.changing_verbs() == []
    assert "step-ca was started meanwhile" in out
    assert "is on" not in out
    assert err == ""


@pytest.mark.parametrize("stops", [1, 2])
def test_stops_of_a_switched_off_unit_during_the_start_prompt_win_over_the_start(
    start, stop, scripted, repository, state, stops
):
    """#60 rules 2 and 5: a repeated stop on B changes nothing visible, yet the start sees it."""
    put_unit_in("B", scripted, repository, state)

    def stops_arrive():
        for _ in range(stops):
            assert stop()[0] == 0

    exit_code, out, err = start(while_prompt_waits=stops_arrive)

    assert exit_code == 1
    assert scripted.changing_verbs() == []
    assert "partial: step-ca was switched off meanwhile (since 17.10. 22:10); not started" in err
    assert "is on" not in out
    assert marker(state) == SWITCHED_OFF_AT


def test_an_empty_marker_still_means_switched_off_for_apply(switch, scripted, state):
    """#60 rule 1 and 4: the file is the record, whatever it holds."""
    (state / "stopped").mkdir(parents=True)
    (state / "stopped" / "step-ca").write_text("")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.STAYS_STOPPED)
    assert scripted.changing_verbs() == []
    assert marker(state) is not None


def test_an_unreadable_marker_directory_still_closes_a_running_unit(
    stop, scripted, repository, state
):
    """#60 rule 2: closing wins over the record; exit 1, never a refusal to stop."""
    put_unit_in("A", scripted, repository, state)
    state.mkdir(parents=True)
    (state / "stopped").write_text("not a directory")

    exit_code, out, _ = stop()

    assert exit_code == 1
    assert scripted.containers["step-ca"] == "exited"
    assert "partial" in out


def test_an_interrupt_while_waiting_for_the_lock_is_partial_exit_1(
    stop, scripted, repository, state
):
    """#60 rule 2 partial: an interrupt exits 1 with the recorded switch, not a traceback."""
    put_unit_in("A", scripted, repository, state)

    exit_code, out, err = stop(marks=InterruptedWaitForLock(state))

    assert exit_code == 1
    assert "interrupted while locking · switch recorded" in out
    assert "interrupted while locking" in err
    assert marker(state) is not None


def test_an_interrupt_for_an_enabled_unit_with_nothing_running_still_records_the_switch(
    stop, scripted, repository, state
):
    """#60 rule 2: the marker is recorded first, so the partial line never lies about it."""
    put_unit_in("A", scripted, repository, state)
    scripted.containers = dict.fromkeys(STEP_CA_SERVICES, "exited")

    exit_code, out, err = stop(marks=InterruptedWaitForLock(state))

    assert exit_code == 1
    assert "interrupted while locking · switch recorded" in out
    assert "interrupted while locking" in err
    assert marker(state) is not None


def test_an_interrupt_while_a_switched_off_unit_waits_for_the_lock_is_partial_exit_1(
    stop, scripted, repository, state
):
    """#60 rule 2 partial from B with nothing running: Ctrl-C behind a start's `up` exits 1."""
    put_unit_in("B", scripted, repository, state)

    exit_code, out, err = stop(marks=InterruptedWaitForLock(state))

    assert exit_code == 1
    assert "interrupted while waiting · switch recorded" in out
    assert "next: hal stop step-ca" in err


def test_an_interrupt_after_a_start_cleared_the_marker_still_records_the_switch(
    stop, scripted, repository, state, monkeypatch
):
    """#60 rules 2 and 5: a stop behind a start's `up` records before it says "recorded"."""
    put_unit_in("B", scripted, repository, state)
    marks = switches.Switches(state)
    planned = scripted.verb_ps
    plans = []

    def start_finishes_then_interrupt(profile, arguments):
        plans.append(profile)
        if len(plans) == 1:
            return planned(profile, arguments)
        marks.clear("step-ca", marks.mark("step-ca"))
        raise KeyboardInterrupt

    monkeypatch.setattr(scripted, "verb_ps", start_finishes_then_interrupt)

    exit_code, out, _ = stop()

    assert exit_code == 1
    assert "switch recorded" in out
    assert marker(state) is not None


def test_stop_of_a_disabled_stopped_unit_with_a_marker_changes_nothing(
    stop, scripted, repository, state
):
    """#60 rule 2 from E: no marker is written, the same file stays."""
    put_unit_in("E", scripted, repository, state)
    switch_off(state)
    inode = (state / "stopped" / "step-ca").stat().st_ino

    exit_code, out, _ = stop()

    assert exit_code == 0
    assert all(part in out for part in ("· step-ca", "disabled"))
    assert "nothing of it runs" in out
    assert (state / "stopped" / "step-ca").stat().st_ino == inode


def test_a_lock_that_cannot_be_taken_does_not_blame_the_record(stop, scripted, repository, state):
    """#60 rule 2: the partial line says the switch is recorded when only the lock failed."""
    put_unit_in("A", scripted, repository, state)
    (state / "switch.lock").mkdir(parents=True)

    exit_code, out, _ = stop()

    assert exit_code == 1
    assert scripted.containers["step-ca"] == "exited"
    assert "switch recorded" in out
    assert "not recorded" not in out


def test_a_stop_of_a_switched_off_unit_looks_again_under_the_lock(
    stop, scripted, repository, state
):
    """#60 rule 5: a start that brought the unit up before the lock opened is stopped again."""
    put_unit_in("B", scripted, repository, state)
    listing = scripted.verb_ps
    looked = []

    def unit_comes_up_after_the_first_look(profile, arguments):
        output = listing(profile, arguments)
        if not looked:
            scripted.containers["step-ca"] = "running"
        looked.append(output)
        return output

    scripted.verb_ps = unit_comes_up_after_the_first_look

    exit_code, _, _ = stop()

    assert exit_code == 0
    assert scripted.containers["step-ca"] == "exited"


# --- the ingress barrier of a unit with a host behind Traefik (#61 proof b) ----------------------


@pytest.fixture
def probe_unit(repository, scripted, state, ingress):
    """`probe` is A: its `hello` runs, no marker, no barrier."""
    write_fleet(repository, PROBE_ENABLED)
    scripted.containers = {"hello": "running"}


def test_stop_writes_the_barrier_before_the_stop_and_reports_only_what_was_verified(
    probe_unit, stop, scripted, ingress, state
):
    """#61 rule 3: marker, barrier, verification, then `docker compose stop`."""
    events = []
    closing = scripted.verb_stop
    scripted.verb_stop = lambda profile, arguments: (
        events.append(f"stop with {ingress.asked[-1]} verified"),
        closing(profile, arguments),
    )[1]

    exit_code, out, _ = stop("probe")

    assert exit_code == 0
    assert events == ["stop with barrier verified"]
    assert ingress.asked == ["barrier"]
    assert all(part in out for part in ("✓ probe", "barrier up · stopped"))
    assert ingress.barrier_file().exists()
    assert marker(state, "probe") == NOW.isoformat(timespec="seconds")


def test_a_barrier_traefik_rejects_is_partial_and_still_stops_the_unit(
    probe_unit, stop, scripted, ingress, state
):
    """#61 rule 3: exit 1, containers stopped, marker and barrier kept."""
    ingress.rejecting = True

    exit_code, out, err = stop("probe")

    assert exit_code == 1
    assert "switched off" not in out + err
    assert "barrier not proven · stopped" in out
    assert (
        "Traefik did not answer the barrier's 404 (X-Edge-Barrier: probe) "
        "for hello.probe.test within 15 s" in err
    )
    assert scripted.containers == {"hello": "exited"}
    assert marker(state, "probe") is not None
    assert ingress.barrier_file().exists()


def test_a_stop_while_traefik_is_down_is_partial_with_everything_kept(
    probe_unit, stop, scripted, ingress, state
):
    """#61 rule 3: Traefik down, exit 1, containers stopped, marker and barrier kept."""
    ingress.down = True

    exit_code, out, _ = stop("probe")

    assert exit_code == 1
    assert "barrier not proven" in out
    assert scripted.containers == {"hello": "exited"}
    assert marker(state, "probe") is not None
    assert ingress.barrier_file().exists()


def test_stop_of_a_switched_off_unit_renders_a_lost_barrier_again_and_verifies_it(
    probe_unit, stop, scripted, ingress, state
):
    """#61 rule 3 from B: a `git clean -x` took the file; the marker still stands."""
    put_probe_in_b(scripted, state, ingress)
    scripted.calls.clear()

    exit_code, out, _ = stop("probe")

    assert exit_code == 0
    assert all(part in out for part in ("barrier back", "off since 17.10. 22:10"))
    assert ingress.barrier_file().exists()
    assert ingress.asked == ["barrier"]
    assert scripted.changing_verbs() == []


def test_stop_names_the_barrier_it_repaired_and_only_then(
    probe_unit, stop, scripted, ingress, state
):
    """#67 rule 3: a stop from B says when it had to put the barrier back."""
    put_probe_in_b(scripted, state, ingress)
    stop("probe")
    _, standing, _ = stop("probe")
    ingress.barrier_file().unlink()

    _, repaired, _ = stop("probe")

    assert "barrier back" not in standing
    assert "already off" in standing
    assert "barrier back" in repaired


@pytest.mark.parametrize(
    "damaged", [b"a rejected barrier", b"\xff\xfe"], ids=["differing", "not text"]
)
def test_stop_repairs_a_barrier_file_that_differs_or_cannot_be_decoded(
    damaged, probe_unit, stop, scripted, ingress, state
):
    """#67 rule 3: a rejected barrier is repaired and named, never a traceback."""
    put_probe_in_b(scripted, state, ingress)
    stop("probe")
    ingress.barrier_file().write_bytes(damaged)

    exit_code, out, _ = stop("probe")

    assert exit_code == 0
    assert "barrier back" in out
    assert ingress.barrier_file().read_bytes() != damaged


def test_stop_from_a_over_a_barrier_file_that_cannot_be_decoded_still_stops_the_unit(
    probe_unit, stop, scripted, ingress, state
):
    """#67 rule 3: a damaged barrier file does not keep the services running."""
    ingress.barrier_file().write_bytes(b"\xff\xfe")

    exit_code, _, _ = stop("probe")

    assert exit_code == 0
    assert scripted.changing_verbs() == ["stop"]


def test_a_lost_barrier_that_cannot_be_proven_makes_the_second_stop_partial(
    probe_unit, stop, scripted, ingress, state
):
    """#61 rule 3 from B: a re-rendered barrier that is not proven is partial."""
    put_probe_in_b(scripted, state, ingress)
    ingress.rejecting = True

    exit_code, out, err = stop("probe")

    assert exit_code == 1
    assert "already off" not in out
    assert "barrier not proven" in out
    assert "Traefik did not answer the barrier's 404" in err


def test_start_removes_the_barrier_after_the_up_is_observed_and_before_the_marker_clears(
    probe_unit, start, scripted, ingress, state
):
    """#61 rule 4: up, observe on, remove the barrier, verify it is gone, clear the marker."""
    put_probe_in_b(scripted, state, ingress)
    seen = []
    ingress.asked = seen
    fetching = ingress.fetch

    def look_around(address, host, seconds, clock):
        seen.append(f"marker {'kept' if marker(state, 'probe') else 'cleared'}")
        seen.append(f"hello {scripted.containers['hello']}")
        return fetching(address, host, seconds, clock)

    ingress.fetch = look_around

    exit_code, out, _ = start(unit="probe")

    assert exit_code == 0
    assert "probe is on" in out
    assert [seen[0], seen[1]] == ["marker kept", "hello running"]
    assert not ingress.barrier_file().exists()
    assert marker(state, "probe") is None


def test_a_start_that_leaves_the_barrier_answering_keeps_the_marker(
    probe_unit, start, scripted, ingress, state
):
    """#61 rule 4: exit 1, partial; a second `hal start` finishes the job."""
    put_probe_in_b(scripted, state, ingress)
    ingress.fetch = lambda *_: NOT_FOUND  # the host still answers the barrier's 404

    exit_code, out, err = start(unit="probe")

    assert exit_code == 1
    assert "probe is on" not in out
    assert "Traefik did not open hello.probe.test within 15 s" in err
    assert marker(state, "probe") is not None


def test_start_removes_a_barrier_left_behind_without_a_marker(
    probe_unit, start, scripted, ingress, state
):
    """#61 rule 4 from A: an interrupted start left the file; `yes` removes it."""
    ingress.barrier_file().write_text("leftover")

    exit_code, out, _ = start(unit="probe")

    assert exit_code == 0
    assert "remove the barrier a stop left behind" in out
    assert not ingress.barrier_file().exists()


def test_start_of_a_running_unit_without_marker_or_barrier_changes_nothing(
    probe_unit, start, scripted, ingress, state
):
    """#61 rule 4: nothing recorded and no barrier, so start changes nothing."""
    exit_code, out, _ = start(unit="probe")

    assert exit_code == 0
    assert "no change" in out
    assert ingress.asked == []


@pytest.mark.parametrize("catalog_text", [PROBE_DISABLED, PROBE_ENABLED])
def test_apply_leaves_the_barrier_in_b_to_e_and_in_e_with_a_marker_to_b(
    catalog_text, probe_unit, switch, scripted, ingress, state
):
    """#61 rule 5, narrowed by #85 S9: apply never writes or removes a barrier; it re-renders
    and proves them only after a core recreate, which this core, with no container and no file
    bind, never plans."""
    put_probe_in_b(scripted, state, ingress)
    ingress.barrier_file().write_text("the barrier")
    write_fleet(ingress.repository, catalog_text)

    exit_code, _, _ = switch()

    assert exit_code == 0
    assert ingress.barrier_file().read_text() == "the barrier"
    assert marker(state, "probe") is not None
    assert ingress.asked == []


def standing_barrier(repository) -> Path:
    barrier_file = repository / "dynamic" / "switch-step-ca.yml"
    barrier_file.parent.mkdir(exist_ok=True)
    barrier_file.write_text("the barrier")
    return barrier_file


def test_start_from_b_of_a_unit_that_is_not_set_up_is_refused_before_the_prompt(
    start, scripted, repository, state, setup_check
):
    """#67 rule 2: the unit's `--check` is asked first; the marker stays, nothing is asked."""
    put_unit_in("B", scripted, repository, state)
    setup_check.exit_code = 1
    setup_check.line = "step-ca/init --check: no keys"
    barrier_file = standing_barrier(repository)
    scripted.calls.clear()

    exit_code, out, err = start()

    assert exit_code == 1
    assert "step-ca is not set up: run `step-ca/init`, then `hal start step-ca` again" in err
    assert "step-ca/init --check: no keys" in err
    assert "start step-ca" not in out
    assert scripted.changing_verbs() == []
    assert marker(state) == SWITCHED_OFF_AT
    assert barrier_file.exists()


def test_start_from_b_whose_setup_check_cannot_tell_exits_2(
    start, scripted, repository, state, setup_check
):
    """#67 rule 2: an unclear check is `cannot plan`, with the same effect."""
    put_unit_in("B", scripted, repository, state)
    setup_check.exit_code = 3
    barrier_file = standing_barrier(repository)

    exit_code, out, err = start()

    assert exit_code == 2
    assert "cannot tell" in err
    assert "start step-ca" not in out
    assert scripted.changing_verbs() == []
    assert marker(state) == SWITCHED_OFF_AT
    assert barrier_file.exists()


def test_start_from_b_asks_the_setup_check_of_a_set_up_unit_and_starts_it(
    start, scripted, repository, state, setup_check
):
    """#67 rule 2: a set-up unit is checked once, then started and the marker cleared."""
    put_unit_in("B", scripted, repository, state)

    exit_code, _, _ = start()

    assert exit_code == 0
    assert setup_check.commands == [[str(repository / "step-ca" / "init"), "--check"]]
    assert marker(state) is None


def test_start_from_b_of_a_unit_without_a_setup_runs_no_check(
    probe_unit, start, scripted, ingress, state, setup_check
):
    """#67 rule 2: a unit without run.setup is not checked."""
    put_probe_in_b(scripted, state, ingress)

    exit_code, _, _ = start(unit="probe")

    assert exit_code == 0
    assert setup_check.commands == []


def test_start_from_a_runs_no_setup_check(start, scripted, repository, state, setup_check):
    """#67 rule 2: a start from A has no marker to clear, so nothing is checked."""
    put_unit_in("A", scripted, repository, state)

    exit_code, _, _ = start()

    assert exit_code == 0
    assert setup_check.commands == []


PROBE_STOPPED = DISABLED + "  probe:\n    run: {enabled: true}\n"
RECREATE_SOCKET_PROXY = [*RECREATE_TRAEFIK[:-1], "socket-proxy"]
RECREATED = "traefik is recreated and runs the checked-out traefik.yml"
SOCKET_PROXY_RECREATED = "\nsocket-proxy is recreated\n"  # the line, not the plan row
CORE_CURRENT = "the core is current"
UNFINISHED = {"traefik": {}}


def record_traefik(state: Path, digest: str) -> None:
    state.mkdir(parents=True, exist_ok=True)
    (state / "applied.json").write_text(json.dumps({"traefik": {"traefik.yml": digest}}))


def probe_switched_off(scripted, repository, state) -> None:
    """`probe` is B: its marker stands and `hello` is stopped, so its barrier is active."""
    write_fleet(repository, PROBE_STOPPED)
    scripted.containers["hello"] = "exited"
    switch_off(state, unit="probe")


def unit_calls(scripted, unit: str = "step-ca") -> list[list[str]]:
    return [call for call in scripted.calls if call[:2] == ["--profile", unit]]


def test_a_first_apply_recreates_traefik_proves_the_barriers_and_records_its_file(
    core_files, switch, scripted, repository, state
):
    """#85 rules 2, 3, cell U1: no record, so recreate exactly traefik, prove, then record."""
    probe_switched_off(scripted, repository, state)
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "traefik.yml has no applied record")
    assert [call for call in scripted.calls if call[2] == "up"] == [RECREATE_TRAEFIK]
    assert scripted.container_ids["traefik"] != ids["traefik"]
    assert scripted.container_ids["socket-proxy"] == ids["socket-proxy"]
    assert out.index("the barrier of probe is proven") < out.index(RECREATED)
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


def test_a_second_apply_with_the_recorded_traefik_yml_changes_nothing(core_files, switch, scripted):
    """#85 rule 2, P15, cell U2: nothing to change, no prompt, no changing compose verb."""
    switch()
    ids = dict(scripted.container_ids)
    scripted.calls.clear()

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert "nothing to change" in out
    assert "Type yes to apply" not in plain(out)
    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


def test_a_changed_traefik_yml_is_recorded_only_after_the_barriers_are_proven(
    core_files, switch, scripted, repository, state, ingress
):
    """#85 rules 2, 3, cell U3: `prove_active` runs before the record is written."""
    switch()
    probe_switched_off(scripted, repository, state)
    edit_traefik_yml(repository)
    records_seen = []
    ingress.on_fetch = lambda: records_seen.append(applied(state))

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "traefik.yml changed")
    assert RECREATE_TRAEFIK in scripted.calls
    assert records_seen[0] == UNFINISHED
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


@pytest.mark.parametrize(
    ("record", "why"),
    [
        ("not json", "RECORD is malformed: it is not JSON"),
        (
            '{"traefik": ["traefik.yml"]}',
            "RECORD is malformed: the traefik entry is not an object of files",
        ),
        ('{"socket-proxy": {}}', "traefik.yml has no applied record"),
        (
            '{"traefik": {"traefik.yml": "DIGEST", "old.yml": "DIGEST"}}',
            "applied.json names old.yml, which traefik does not mount",
        ),
    ],
)
def test_a_record_that_cannot_be_trusted_counts_as_changed(
    record, why, core_files, switch, scripted, repository, state
):
    """#85 rule 2, cell U4: malformed, missing entry or unknown key: recreate, and say why."""
    digest = sha256(repository / "traefik.yml")
    state.mkdir(parents=True, exist_ok=True)
    (state / "applied.json").write_text(record.replace("DIGEST", digest))

    exit_code, out, _ = switch()

    assert exit_code == 0
    fact = why.replace("RECORD", str(state / "applied.json"))
    assert find_row(out, "traefik", PlanEvent.RECREATE, fact)
    assert RECREATE_TRAEFIK in scripted.calls
    assert applied(state)["traefik"] == {"traefik.yml": digest}


@pytest.mark.parametrize("traefik", ["exited", None])
def test_a_changed_traefik_yml_with_no_live_traefik_is_named_and_traefik_is_not_started(
    traefik, core_files, switch, scripted, state
):
    """#85 rule 4, cell U5: exited or absent: no recreate, record old, no prompt, exit 0."""
    if traefik:
        scripted.containers["traefik"] = traefik
    else:
        scripted.containers.pop("traefik")
    record_traefik(state, "0000")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.NOT_STARTED, "traefik.yml changed · not running")
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []
    assert scripted.containers.get("traefik") == traefik
    assert applied(state) == {"traefik": {"traefik.yml": "0000"}}


def test_a_restarting_traefik_is_recreated(core_files, switch, scripted):
    """#85 rule 3, cell U6: a restarting container is live, so it is recreated."""
    scripted.containers["traefik"] = "restarting"

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert RECREATE_TRAEFIK in scripted.calls
    assert RECREATED in out


def test_a_failed_recreate_is_partial_marks_the_record_unfinished_and_touches_no_unit(
    core_files, switch, scripted, repository, state
):
    """#85 rule 5, cells U7, U11: `could not recreate traefik`, exit 1, step-ca not started."""
    write_fleet(repository, ENABLED)
    scripted.failing_verb = "up"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, could not recreate traefik, `docker compose up` exited 1" in err
    assert applied(state) == UNFINISHED
    assert unit_calls(scripted) == []
    assert RECREATED not in out


@pytest.mark.parametrize(
    ("step", "record_left", "recreated"),
    [
        ("mark traefik unfinished in applied.json", None, False),
        ("record traefik in applied.json", UNFINISHED, True),
    ],
)
def test_a_record_that_cannot_be_written_is_partial_names_the_step_and_touches_no_unit(
    step, record_left, recreated, core_files, switch, scripted, repository, state
):
    """#85 rule 5: a read-only state directory before the recreate leaves traefik untouched; one
    after it leaves the entry unfinished; either way exit 1 names the step and no unit moves."""
    write_fleet(repository, ENABLED)
    state.mkdir(parents=True, exist_ok=True)
    apply_lock(state).touch(mode=0o600)  # an earlier apply left it; it is never unlinked
    ids = dict(scripted.container_ids)
    if recreated:
        scripted.after_up = lambda: state.chmod(0o500)
    else:
        state.chmod(0o500)
    try:
        exit_code, out, err = switch()
    finally:
        state.chmod(0o700)

    assert exit_code == 1
    assert f"partial, could not {step}, cannot write {state / 'applied.json'}" in err
    assert (RECREATE_TRAEFIK in scripted.calls) is recreated
    assert (scripted.container_ids["traefik"] != ids["traefik"]) is recreated
    assert scripted.container_ids["socket-proxy"] == ids["socket-proxy"]
    assert applied(state) == record_left
    assert unit_calls(scripted) == []
    assert RECREATED not in out


def test_a_traefik_not_running_after_the_recreate_is_partial(core_files, switch, scripted, state):
    """#85 rule 5, cell U8: not observed running, so partial, exit 1, record unfinished."""
    scripted.after_up = lambda: scripted.containers.update(traefik="exited")

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, traefik is not running after the traefik recreate" in err
    assert applied(state) == UNFINISHED
    assert RECREATED not in out


def test_a_traefik_that_dies_right_after_the_recreate_is_partial_and_the_next_run_recreates_again(
    core_files, switch, scripted, state
):
    """#85 rule 3, rule 5: a traefik.yml Traefik cannot load lets it run for a moment, then it
    restarts on every start; that is not running, so partial, exit 1, the record says unfinished
    and the next run plans the recreate again."""
    scripted.crash_loops.add("traefik")

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, traefik is not running after the traefik recreate" in err
    assert applied(state) == UNFINISHED
    assert RECREATED not in out
    assert scripted.containers["traefik"] == "restarting"
    _, again, _ = switch("no")
    assert find_row(again, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")


def test_an_unproven_barrier_after_the_recreate_is_partial_and_the_next_run_recreates_again(
    core_files, switch, scripted, repository, state, ingress
):
    """#85 rule 5, S9, cell U9: partial naming the unit, that it may be reachable, and the
    emergency stop; record unfinished, the next run plans again."""
    probe_switched_off(scripted, repository, state)
    ingress.rejecting = True

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, the barrier of probe is not proven after the traefik recreate (" in err
    assert (
        "): probe may be reachable through Traefik; to close the tunnel now: hal offline; "
        "no unit switched" in err
    )
    assert applied(state) == UNFINISHED
    assert RECREATED not in out
    ingress.rejecting = False
    exit_code, out, _ = switch()
    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")


def test_every_unproven_barrier_after_the_recreate_is_named_in_the_partial_line(
    core_files, switch, scripted, repository, state, ingress
):
    """#85 rule 5, S9, P15: a failure two switched-off units share names both, because every
    active barrier is tried, not only up to the first that fails."""
    probe_switched_off(scripted, repository, state)
    scripted.config["services"]["echo"] = {
        "profiles": ["echo"],
        "labels": {"traefik.enable": "true", "edge.name": "echo"},
    }
    write_fleet(repository, PROBE_STOPPED + "  echo:\n    run: {enabled: true}\n")
    scripted.containers["echo"] = "exited"
    switch_off(state, unit="echo")
    ingress.rejecting = True

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial, the barriers of probe, echo are not proven after the traefik recreate (" in err
    assert "(probe: " in err
    assert "; echo: " in err
    assert "): probe, echo may be reachable through Traefik; to close the tunnel now: " in err
    assert applied(state) == UNFINISHED


@pytest.mark.parametrize("failure", ["unproven barrier", "traefik not running"])
def test_a_recreate_that_did_not_finish_is_planned_again_after_traefik_yml_is_reverted(
    failure, core_files, switch, scripted, repository, state, ingress
):
    """#85 rule 5, S9: a partial recreate leaves no entry that the reverted file could match, so
    the next run recreates again instead of saying `nothing to change`."""
    probe_switched_off(scripted, repository, state)
    assert switch()[0] == 0
    recorded = (repository / "traefik.yml").read_text()
    edit_traefik_yml(repository)
    if failure == "unproven barrier":
        ingress.rejecting = True
    else:
        scripted.after_up = lambda: scripted.containers.update(traefik="exited")
    assert switch()[0] == 1
    (repository / "traefik.yml").write_text(recorded)
    ingress.rejecting = False
    scripted.after_up = None
    scripted.containers["traefik"] = "running"

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")
    assert RECREATED in out
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


def test_a_traefik_yml_changed_during_the_recreate_is_recreated_again_by_the_next_run(
    core_files, switch, scripted, repository, state
):
    """#85 rule 3, cell U10: the record holds the plan-time digest, not the file's later one."""
    planned = sha256(repository / "traefik.yml")
    scripted.after_up = lambda: edit_traefik_yml(repository)

    assert switch()[0] == 0
    assert applied(state) == {"traefik": {"traefik.yml": planned}}
    scripted.after_up = None
    exit_code, out, _ = switch()
    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "traefik.yml changed")


def test_a_core_change_and_a_unit_switch_share_one_plan_and_one_yes_core_first(
    core_files, switch, scripted, repository
):
    """#85 rule 1, cell U11: the core lines come first and the core is changed first."""
    write_fleet(repository, ENABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert row_at(out, "traefik", PlanEvent.RECREATE) < row_at(out, "step-ca", PlanEvent.SWITCH_ON)
    assert plain(out).count("Type yes to apply") == 1
    starting_step_ca = unit_calls(scripted)[0]
    assert scripted.calls.index(RECREATE_TRAEFIK) < scripted.calls.index(starting_step_ca)
    assert "step-ca is on" in out


def test_a_missing_traefik_yml_cannot_be_planned_and_is_named(
    core_files, switch, scripted, repository
):
    """#85 rule 1, cell U12: a deleted traefik.yml never passes silently."""
    (repository / "traefik.yml").unlink()

    exit_code, _, err = switch()

    assert exit_code == 2
    assert f"cannot plan, cannot read {repository / 'traefik.yml'}" in err
    assert scripted.changing_verbs() == []


def test_an_enabled_unit_whose_barrier_stands_without_a_marker_stays_stopped(
    switch, scripted, repository, ingress
):
    """#85 rule 7, #34 finding 41, cell U13: a barrier alone switches the unit off."""
    write_fleet(repository, PROBE_ENABLED)
    scripted.put_containers(
        {
            "step-ca": "running",
            "traefik-mcp-acme-owner": "exited",
            "traefik-mcp": "running",
            "hello": "exited",
        }
    )
    ingress.barrier_file().write_text("the barrier")

    exit_code, out, _ = switch(answer="no")

    row = find_row(out, "probe", PlanEvent.STAYS_STOPPED, "barrier stands")
    assert row.start() < out.index("nothing to change")
    assert (exit_code, scripted.changing_verbs()) == (0, [])


@pytest.mark.parametrize(
    "arguments", [["down"], ["rm", "-v", "hello"], ["up", "-d", "--renew-anon-volumes", "hello"]]
)
def test_the_scripted_compose_fails_a_test_that_takes_volumes_or_the_project_down(
    arguments, scripted
):
    """#85 P13, cells U14, #87 D15: every test above runs on a fake that refuses these."""
    with pytest.raises(AssertionError):
        scripted.run(["docker", "compose", "-p", "d", "-f", "f", "--profile", "*", *arguments], 1)


# --- #87: the core follows its compose definition, socket-proxy first ------------------------


def test_a_changed_socket_proxy_definition_recreates_socket_proxy_then_traefik(
    applied_core, switch, scripted, state, repository
):
    """#87 rules 2, 4, 5, cell D1: the plan names both, socket-proxy first; each gets a new
    container by exactly edge's recreate argv; both success lines, then the core is current."""
    ids = dict(scripted.container_ids)
    scripted.change_definition("socket-proxy")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert row_at(out, "socket-proxy", PlanEvent.RECREATE) < row_at(
        out, "traefik", PlanEvent.RECREATE, "socket-proxy is recreated"
    )
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY, RECREATE_TRAEFIK]
    assert all(scripted.container_ids[service] != ids[service] for service in ids)
    assert out.index(SOCKET_PROXY_RECREATED) < out.index(RECREATED) < out.index(CORE_CURRENT)
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


def test_a_changed_traefik_definition_recreates_only_traefik(applied_core, switch, scripted):
    """#87 rule 2, cell D2 (#85 U1): socket-proxy's container is kept."""
    ids = dict(scripted.container_ids)
    scripted.change_definition("traefik")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "definition changed")
    assert up_calls(scripted) == [RECREATE_TRAEFIK]
    assert scripted.container_ids["socket-proxy"] == ids["socket-proxy"]
    assert CORE_CURRENT in out


@pytest.mark.parametrize("service", ["socket-proxy", "traefik"])
def test_a_second_run_after_a_definition_recreate_changes_nothing(
    service, applied_core, switch, scripted
):
    """#87 P15, cell D3: Compose labels the new container with the hash, so nothing is left."""
    scripted.change_definition(service)
    assert switch()[0] == 0
    ids = dict(scripted.container_ids)
    scripted.calls.clear()

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert "nothing to change" in out
    assert "Type yes to apply" not in plain(out)
    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


def test_a_changed_traefik_definition_and_traefik_yml_are_one_recreate_recording_the_plan_time_file(
    applied_core, switch, scripted, repository, state
):
    """#87 rule 4, cell D4 (#85 U10): one recreate; the record holds the digest as planned."""
    scripted.change_definition("traefik")
    edit_traefik_yml(repository)
    planned = sha256(repository / "traefik.yml")
    scripted.after_up = lambda: edit_traefik_yml(repository)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "definition changed · traefik.yml changed")
    assert up_calls(scripted) == [RECREATE_TRAEFIK]
    assert applied(state) == {"traefik": {"traefik.yml": planned}}


@pytest.mark.parametrize("state_of_proxy", ["exited", "created", None])
def test_a_changed_socket_proxy_that_is_not_running_is_named_and_traefik_is_left_as_it_is(
    state_of_proxy, applied_core, switch, scripted
):
    """#87 rule 3, cells D5, D6: a stopped socket-proxy with a stale label, or one created by
    hand that no recreate of edge's left, is named, never started, and does not pull traefik in;
    an absent one has nothing to compare."""
    scripted.change_definition("socket-proxy")
    if state_of_proxy:
        scripted.containers["socket-proxy"] = state_of_proxy
    else:
        scripted.containers.pop("socket-proxy")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    named = find_row(out, "socket-proxy", PlanEvent.NOT_STARTED, "definition changed · not running")
    assert bool(named) is bool(state_of_proxy)
    assert find_row(out, "traefik", PlanEvent.RECREATE) is None
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def test_a_failed_socket_proxy_recreate_is_partial_leaves_traefik_unfinished_and_touches_no_unit(
    applied_core, switch, scripted, repository, state
):
    """#87 rule 4, cell D7: traefik's entry is emptied before the first recreate and traefik is
    untouched; the next run plans both again."""
    write_fleet(repository, ENABLED)
    ids = dict(scripted.container_ids)
    scripted.change_definition("socket-proxy")
    scripted.failing_verb = "up"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, could not recreate socket-proxy, `docker compose up` exited 1" in err
    assert applied(state) == UNFINISHED
    assert scripted.container_ids == ids
    assert unit_calls(scripted) == []
    assert SOCKET_PROXY_RECREATED not in out
    scripted.failing_verb = None
    _, again, _ = switch("no")
    assert find_row(again, "socket-proxy", PlanEvent.RECREATE, "definition changed")
    assert find_row(again, "traefik", PlanEvent.RECREATE, "finish · socket-proxy is recreated")


def test_a_socket_proxy_its_recreate_left_created_is_recreated_by_the_next_run(
    applied_core, switch, scripted, state, repository
):
    """#87 rule 4: a socket-proxy that cannot start stays created with the new label, so the
    first run is partial; once it can start again, the next run recreates it, then traefik, and
    the core is current."""
    scripted.change_definition("socket-proxy")
    scripted.unstartable.add("socket-proxy")

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial, could not recreate socket-proxy, `docker compose up` exited 1" in err
    assert scripted.containers["socket-proxy"] == "created"
    scripted.unstartable.clear()
    scripted.calls.clear()
    exit_code, out, _ = switch()
    assert exit_code == 0
    assert find_row(out, "socket-proxy", PlanEvent.RECREATE, "the last recreate did not finish")
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY, RECREATE_TRAEFIK]
    assert out.index(SOCKET_PROXY_RECREATED) < out.index(RECREATED) < out.index(CORE_CURRENT)
    assert scripted.containers["socket-proxy"] == "running"
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


def test_a_traefik_its_recreate_left_created_is_recreated_by_the_next_run(
    applied_core, switch, scripted, repository
):
    """#87 rule 4: a traefik that cannot start, as a taken port 80 leaves it, stays created and
    marked unfinished; once it can start, the next run recreates only traefik, once."""
    edit_traefik_yml(repository)
    scripted.unstartable.add("traefik")

    assert switch()[0] == 1
    assert scripted.containers["traefik"] == "created"
    scripted.unstartable.clear()
    scripted.calls.clear()
    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")
    assert up_calls(scripted) == [RECREATE_TRAEFIK]
    assert out.index(RECREATED) < out.index(CORE_CURRENT)


def test_a_crash_looping_socket_proxy_is_partial_and_the_next_run_is_partial_again(
    applied_core, switch, scripted, state
):
    """#87 rule 4, P15, cell D8: traefik is observed together with socket-proxy, so a proxy that
    restarts after its recreate never lets a later run say the core is current."""
    scripted.change_definition("socket-proxy")
    scripted.crash_loops.add("socket-proxy")

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, socket-proxy is not running after the socket-proxy recreate" in err
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY]
    assert applied(state) == UNFINISHED
    exit_code, out, err = switch()
    assert exit_code == 1
    assert find_row(out, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")
    assert "partial, socket-proxy is not running after the traefik recreate" in err
    assert CORE_CURRENT not in out


def test_a_core_left_down_whole_after_the_traefik_recreate_names_both_in_start_order(
    applied_core, switch, scripted, repository, state
):
    """#89 rule 7, cell F17 (#34 finding 57): both down at one look are named socket-proxy first."""
    edit_traefik_yml(repository)
    scripted.after_up = lambda: scripted.containers.update(
        {"socket-proxy": "exited", "traefik": "exited"}
    )

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial, socket-proxy and traefik are not running after the traefik recreate" in err
    assert applied(state) == UNFINISHED


def test_every_core_recreate_proves_the_barriers_before_its_success_line(
    applied_core, switch, scripted, repository, state
):
    """#87 rule 4, S9, cell D9: after socket-proxy's recreate and again after traefik's."""
    probe_switched_off(scripted, repository, state)
    scripted.change_definition("socket-proxy")

    exit_code, out, _ = switch()

    assert exit_code == 0
    proven = "the barrier of probe is proven"
    assert out.index(proven) < out.index(SOCKET_PROXY_RECREATED)
    assert out.index(SOCKET_PROXY_RECREATED) < out.rindex(proven) < out.index(RECREATED)
    assert out.count(proven) == 2


def test_an_unproven_barrier_after_the_socket_proxy_recreate_names_the_unit_and_the_stop(
    applied_core, switch, scripted, repository, state, ingress
):
    """#87 rule 4, S9, cell D9 (#85 rule 5): partial, traefik not recreated, no success line."""
    probe_switched_off(scripted, repository, state)
    scripted.change_definition("socket-proxy")
    ingress.rejecting = True

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "the barrier of probe is not proven after the socket-proxy recreate (" in err
    assert "probe may be reachable through Traefik; to close the tunnel now: hal offline" in err
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY]
    assert SOCKET_PROXY_RECREATED not in out
    assert applied(state) == UNFINISHED


HASH_FAILURES = {
    "a malformed line": ("garbage\n", None, "`docker compose config --hash` answered 'garbage'"),
    "a missing service": (
        f"socket-proxy {definition_hash('socket-proxy')}\n",
        None,
        "`docker compose config --hash` named no hash for traefik",
    ),
    "a core container without the label": (
        None,
        "traefik",
        "a traefik container has no com.docker.compose.config-hash label",
    ),
}


@pytest.mark.parametrize(
    ("answer", "unlabelled", "line"), HASH_FAILURES.values(), ids=HASH_FAILURES
)
def test_an_unreadable_hash_or_label_cannot_be_planned(
    answer, unlabelled, line, applied_core, switch, scripted
):
    """#87 rule 1, cell D11: exit 2 and nothing changed; a fallback would churn (P15)."""
    scripted.hash_answer = answer
    if unlabelled:
        scripted.labels[unlabelled] = None

    exit_code, _, err = switch()

    assert exit_code == 2
    assert f"cannot plan, {line}" in err
    assert scripted.changing_verbs() == []


def test_apply_drops_a_ghost_entry_and_keeps_the_entry_of_a_switched_off_file_binding_service(
    applied_core, switch, scripted, repository, state
):
    """#87 rule 6, cell D13: the prune of a real recreate goes by every service that binds a file
    from the checkout, so traefik-mcp's entry survives while step-ca is off."""
    scripted.config["services"]["traefik-mcp"]["volumes"].append(
        bind(repository / "traefik-mcp.yml", "/etc/traefik/traefik.yml")
    )
    (repository / "traefik-mcp.yml").write_text("entryPoints: {}\n")
    kept = {"traefik-mcp.yml": "1" * 64}
    (state / "applied.json").write_text(
        json.dumps(applied(state) | {"ghost": {}, "traefik-mcp": kept})
    )
    edit_traefik_yml(repository)

    assert switch()[0] == 0
    assert applied(state) == {
        "traefik": {"traefik.yml": sha256(repository / "traefik.yml")},
        "traefik-mcp": kept,
    }


def test_a_profile_bind_that_cannot_be_read_is_partial_naming_the_step_and_touches_nothing(
    unreadable_profile_bind, switch, scripted, repository
):
    """#87 rule 4: the services edge follows are found after the yes; a bind of `hello` under a
    directory that cannot be entered is partial, exit 1, with the step, and no core service is
    recreated."""
    edit_traefik_yml(repository)

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial, could not find the services edge follows, cannot read" in err
    assert up_calls(scripted) == []
    assert unit_calls(scripted) == []


def test_a_unit_switch_without_a_core_recreate_never_reads_the_profile_binds(
    unreadable_profile_bind, switch, scripted, repository
):
    """#87 rule 4: the services edge follows are found only for a recorded recreate, so a bind
    that cannot be read does not stop an apply that only switches a unit."""
    write_fleet(repository, ENABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "step-ca is on" in out
    assert unit_calls(scripted) != []
    assert RECREATE_TRAEFIK not in scripted.calls


# A real `ps --format json` line and `config --hash` answer, Compose 2.40.3 (#87 Q1).
Q1_PS_LINE = json.dumps(
    {
        "ExitCode": 0,
        "ID": "d9d8994eda15",
        "Image": IMAGE,
        "Labels": (
            "com.docker.compose.config-hash="
            "6b06f5db5a8fd0a0d8f3dcdcd3a5e382a08ea099d03358a583156959264b46d4,"
            f"{OTHER_LABELS},com.docker.compose.project=edge87q1scratch,"
            "com.docker.compose.service=a"
        ),
        "Project": "edge87q1scratch",
        "Service": "a",
        "State": "running",
    }
)
Q1_HASHES = (
    "a 6b06f5db5a8fd0a0d8f3dcdcd3a5e382a08ea099d03358a583156959264b46d4\n"
    "b 8cd73dfe1764c0c8c02569ca3860a15172725ae7e146cc50d08d6e651078db83\n"
)


def answering(output: str) -> compose.Runner:
    return lambda command, _timeout: subprocess.CompletedProcess(command, 0, output, "")


def test_the_definition_hash_is_read_from_a_real_ps_line_beside_labels_holding_commas():
    """#87 rule 1, cells D11, Q1: only the config-hash label is read out of `Labels`."""
    [container] = compose.Compose(answering(Q1_PS_LINE)).containers()

    assert container == compose.Container(
        "a",
        "running",
        "6b06f5db5a8fd0a0d8f3dcdcd3a5e382a08ea099d03358a583156959264b46d4",
        IMAGE,
        LABELLED_IMAGE_ID,
    )


def test_the_config_hashes_are_read_from_a_real_config_hash_answer():
    """#87 rule 1, cell Q1: `name hash` lines, one per asked service."""
    hashes = compose.Compose(answering(Q1_HASHES)).config_hashes(("a", "b"))

    assert hashes == {
        "a": "6b06f5db5a8fd0a0d8f3dcdcd3a5e382a08ea099d03358a583156959264b46d4",
        "b": "8cd73dfe1764c0c8c02569ca3860a15172725ae7e146cc50d08d6e651078db83",
    }


@pytest.mark.parametrize(
    ("traefik_yml_changed", "why"),
    [
        (True, "traefik.yml changed · socket-proxy is recreated"),
        (False, "socket-proxy is recreated"),
    ],
)
def test_the_core_is_not_current_while_a_changed_core_service_is_not_started(
    traefik_yml_changed, why, applied_core, switch, scripted, repository
):
    """#87 rules 3, 5, cell D12 (scenario R3e): socket-proxy is recreated; a stopped traefik it
    pulls in is only named, with or without a change of its own, and the core is not current."""
    scripted.change_definition("socket-proxy")
    scripted.containers["traefik"] = "exited"
    if traefik_yml_changed:
        edit_traefik_yml(repository)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.NOT_STARTED, f"{why} · not running")
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY]
    assert SOCKET_PROXY_RECREATED in out
    assert CORE_CURRENT not in out


def test_a_socket_proxy_change_and_a_unit_switch_share_one_yes_and_the_core_goes_first(
    applied_core, switch, scripted, repository
):
    """#87 rule 4, cell D14 (#85 U11): one plan, one yes, socket-proxy, traefik, then step-ca;
    a core failure touching no unit is D7."""
    write_fleet(repository, ENABLED)
    scripted.change_definition("socket-proxy")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert row_at(out, "traefik", PlanEvent.RECREATE) < row_at(out, "step-ca", PlanEvent.SWITCH_ON)
    starting_step_ca = unit_calls(scripted)[0]
    assert scripted.calls.index(RECREATE_TRAEFIK) < scripted.calls.index(starting_step_ca)
    assert up_calls(scripted)[:2] == [RECREATE_SOCKET_PROXY, RECREATE_TRAEFIK]
    assert out.index(CORE_CURRENT) < out.index("step-ca is on")


# --- #93: a core service stopped between the plan and the yes is not started ------------------


def stopped_meanwhile(service: str) -> str:
    return f"partial, {service} was stopped meanwhile; it is not started; no unit switched"


@pytest.mark.parametrize(
    ("change", "stopped", "left_as", "ups"),
    [
        (lambda scripted, repository: edit_traefik_yml(repository), "traefik", "exited", []),
        (lambda scripted, repository: edit_traefik_yml(repository), "traefik", "created", []),
        (
            lambda scripted, repository: scripted.change_definition("socket-proxy"),
            "socket-proxy",
            "exited",
            [],
        ),
    ],
    ids=[
        "L1 traefik planned and stopped",
        "L1 traefik replaced by a container never started",
        "L2 socket-proxy stopped",
    ],
)
def test_a_core_service_stopped_while_the_prompt_waits_is_not_recreated_and_no_unit_switches(
    change, stopped, left_as, ups, applied_core, switch, scripted, repository, state
):
    """#93 rules 1, 2, C3, #87 rules 3, 4, cells L1, L2: the liveness read just before the set's
    first recreate finds it stopped, so no recreate began; partial, exit 1, no unit touched, and
    no entry changes. A container created and never started counts as live only where the plan
    found edge's own unfinished recreate left it so."""
    write_fleet(repository, ENABLED)
    change(scripted, repository)
    planned_record = applied(state)

    def stop_it() -> None:
        scripted.containers[stopped] = left_as

    exit_code, out, err = switch(while_prompt_waits=stop_it)

    assert exit_code == 1
    assert find_row(out, stopped, PlanEvent.RECREATE)
    assert stopped_meanwhile(stopped) in err
    assert up_calls(scripted) == ups
    assert scripted.containers[stopped] == left_as
    assert unit_calls(scripted) == []
    assert applied(state) == planned_record


def stop_traefik_during_the_prompt(scripted) -> dict:
    return {"while_prompt_waits": lambda: scripted.containers.update(traefik="exited")}


def stop_traefik_after_socket_proxys_recreate(scripted) -> dict:
    scripted.after_up = lambda: scripted.containers.update(traefik="exited")
    return {}


@pytest.mark.parametrize(
    "stop_traefik",
    [stop_traefik_during_the_prompt, stop_traefik_after_socket_proxys_recreate],
    ids=["L3 during the prompt", "L3 between the two recreates"],
)
def test_a_traefik_stopped_before_its_own_recreate_keeps_an_emptied_entry_for_the_next_run(
    stop_traefik, applied_core, switch, scripted, repository, state
):
    """#93 rules 1, 2 (head ruling 18.10.2026), C3, C4, #87 rule 4, cell L3: liveness is read
    again just before each core recreate, so a traefik stopped since the plan is not started
    after socket-proxy's recreate; partial, exit 1. The record follows the set: the set's first
    recreate began, so traefik's entry is emptied in both timings (P15), and the next run with
    traefik live recreates it."""
    write_fleet(repository, ENABLED)
    scripted.change_definition("socket-proxy")

    exit_code, _, err = switch(**stop_traefik(scripted))

    assert exit_code == 1
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY]
    assert stopped_meanwhile("traefik") in err
    assert scripted.containers["traefik"] == "exited"
    assert unit_calls(scripted) == []
    assert applied(state) == UNFINISHED

    scripted.after_up = None
    scripted.containers["traefik"] = "running"
    scripted.calls.clear()

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik", PlanEvent.RECREATE, "the last recreate did not finish")
    assert find_row(out, "socket-proxy", PlanEvent.RECREATE) is None
    assert up_calls(scripted)[0] == RECREATE_TRAEFIK
    assert applied(state) == {"traefik": {"traefik.yml": sha256(repository / "traefik.yml")}}


# --- #89: traefik-mcp follows traefik-mcp.yml and its definition while step-ca is on ----------

FOLLOWER_RECREATED = f"traefik-mcp is recreated and runs the checked-out {FOLLOWER_FILE}"
HELD_OFF = "traefik-mcp.yml changed · step-ca is off"
HELD_SWITCHED_OFF = "traefik-mcp.yml changed · step-ca is switched off"


def edit_traefik_mcp_yml(repository: Path) -> None:
    with (repository / FOLLOWER_FILE).open("a") as file:
        file.write("# a harmless edit\n")


def follower_entry(state: Path) -> dict | None:
    return (applied(state) or {}).get("traefik-mcp")


def test_a_changed_traefik_mcp_yml_recreates_exactly_traefik_mcp_and_records_the_plan_time_file(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 rules 2, 3, C5, C6, cell F1: one plan, one yes, the follower's own argv; step-ca keeps
    its container; the entry holds the digest as planned."""
    ids = dict(scripted.container_ids)
    edit_traefik_mcp_yml(repository)
    planned = follower_digest(repository)
    scripted.after_up = lambda: edit_traefik_mcp_yml(repository)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik-mcp", PlanEvent.RECREATE, "traefik-mcp.yml changed")
    assert plain(out).count("Type yes to apply") == 1
    assert up_calls(scripted) == [RECREATE_FOLLOWER]
    assert scripted.container_ids["traefik-mcp"] != ids["traefik-mcp"]
    assert scripted.container_ids["step-ca"] == ids["step-ca"]
    assert follower_entry(state) == planned
    assert FOLLOWER_RECREATED in out


def test_a_follower_without_an_entry_is_recreated_once_and_a_second_run_changes_nothing(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 2, P15, cells F2, F4."""
    (state / "applied.json").write_text(json.dumps({"traefik": applied(state)["traefik"]}))

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "traefik-mcp", PlanEvent.RECREATE, "traefik-mcp.yml has no applied record")
    assert up_calls(scripted) == [RECREATE_FOLLOWER]
    ids = dict(scripted.container_ids)
    scripted.calls.clear()
    exit_code, out, _ = switch(answer="no")
    assert exit_code == 0
    assert "nothing to change" in out
    assert "Type yes to apply" not in plain(out)
    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


@pytest.mark.parametrize(
    ("marked", "held"), [(False, HELD_OFF), (True, HELD_SWITCHED_OFF)], ids=["F5", "F5 marked"]
)
def test_a_changed_traefik_mcp_yml_while_step_ca_is_disabled_and_gone_is_named_only(
    marked, held, step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 4, cell F5: a non-action; nothing to change, no up, the entry unchanged; a
    marker left on the disabled unit names it switched off."""
    write_fleet(repository, DISABLED)
    for service in STEP_CA_SERVICES:
        scripted.containers.pop(service)
    if marked:
        switch_off(state)
    entry = follower_entry(state)
    edit_traefik_mcp_yml(repository)

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "traefik-mcp", PlanEvent.NOT_STARTED, held)
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []
    assert follower_entry(state) == entry


@pytest.mark.parametrize(
    "follower", ["exited", "running"], ids=["F6 stopped", "F7 running behind the switch"]
)
def test_a_changed_traefik_mcp_yml_while_step_ca_is_switched_off_is_named_and_never_recreated(
    follower, step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 4, P7, cells F6, F7: the switch holds the follower whether or not it runs."""
    scripted.containers.update({"step-ca": "exited", "traefik-mcp": follower})
    switch_off(state)
    entry = follower_entry(state)
    edit_traefik_mcp_yml(repository)

    exit_code, out, _ = switch(answer="no")

    row = find_row(out, "step-ca", PlanEvent.STAYS_STOPPED, "switched off since")
    assert row_at(out, "traefik-mcp", PlanEvent.NOT_STARTED, HELD_SWITCHED_OFF) < row.start()
    assert "nothing to change" in out
    assert (exit_code, scripted.changing_verbs()) == (0, [])
    assert follower_entry(state) == entry


def test_a_switch_that_appears_while_the_prompt_waits_holds_the_follower_and_every_unit(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 3, P7, cell F8: no recreate, partial, exit 1, no unit switched."""
    write_fleet(repository, PROBE_ENABLED)
    entry = follower_entry(state)
    edit_traefik_mcp_yml(repository)

    exit_code, out, err = switch(while_prompt_waits=lambda: switch_off(state, LATER_SWITCH_AT))

    assert exit_code == 1
    assert find_row(out, "probe", PlanEvent.SWITCH_ON)
    assert (
        "partial, step-ca was switched off meanwhile (since "
        f"{switches.describe_since(LATER_SWITCH_AT)}); traefik-mcp is not recreated; "
        "no unit switched" in err
    )
    assert up_calls(scripted) == []
    assert follower_entry(state) == entry


def test_a_failed_follower_recreate_empties_its_entry_and_the_next_runs_recreate_again(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 3 (#85 rule 5), cell F9: also after the file is reverted."""
    recorded = (repository / FOLLOWER_FILE).read_text()
    edit_traefik_mcp_yml(repository)
    scripted.failing_verb = "up"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, could not recreate traefik-mcp, `docker compose up` exited 1" in err
    assert follower_entry(state) == {}
    assert FOLLOWER_RECREATED not in out
    scripted.failing_verb = None
    (repository / FOLLOWER_FILE).write_text(recorded)
    exit_code, out, _ = switch()
    assert exit_code == 0
    assert find_row(out, "traefik-mcp", PlanEvent.RECREATE, "the last recreate did not finish")
    assert follower_entry(state) == follower_digest(repository)


def test_a_traefik_mcp_that_crash_loops_after_its_recreate_is_partial_with_its_entry_emptied(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 rule 3, cell F10: observed alone, it is not running."""
    edit_traefik_mcp_yml(repository)
    scripted.crash_loops.add("traefik-mcp")

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "partial, traefik-mcp is not running after the traefik-mcp recreate" in err
    assert follower_entry(state) == {}
    assert FOLLOWER_RECREATED not in out


def test_l5_a_traefik_mcp_stopped_while_the_prompt_waits_is_still_recreated(
    step_ca_applied, switch, scripted, repository, state
):
    """#93 rule 3, #89 rules 2, 3, cell L5: a follower's decision does not depend on liveness,
    so the stop meanwhile changes nothing."""
    edit_traefik_mcp_yml(repository)

    def stop_traefik_mcp() -> None:
        scripted.containers["traefik-mcp"] = "exited"

    exit_code, out, _ = switch(while_prompt_waits=stop_traefik_mcp)

    assert exit_code == 0
    assert up_calls(scripted) == [RECREATE_FOLLOWER]
    assert scripted.containers["traefik-mcp"] == "running"
    assert FOLLOWER_RECREATED in out
    assert follower_entry(state) == follower_digest(repository)


def test_a_fixed_file_reaches_traefik_mcp_before_a_crashed_step_ca_is_started(
    step_ca_applied, switch, scripted, repository, state
):
    """#89 head decision, cell F11: step-ca's unit plan is on, the follower is recreated first."""
    scripted.containers["step-ca"] = "exited"
    edit_traefik_mcp_yml(repository)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.SWITCH_ON)
    starting_step_ca = unit_calls(scripted)[0]
    assert scripted.calls.index(RECREATE_FOLLOWER) < scripted.calls.index(starting_step_ca)
    assert out.index(FOLLOWER_RECREATED) < out.index("step-ca is on")
    assert follower_entry(state) == follower_digest(repository)


@pytest.mark.parametrize("observed_on", [True, False], ids=["observed on", "left down"])
def test_a_switch_on_records_the_follower_only_once_the_unit_is_observed_on(
    observed_on, applied_core, switch, scripted, repository, state
):
    """#89 head decision, P15, cell F12: the follower starts with its unit, no recreate; its
    plan-time digest is written once step-ca is observed on, so the next run changes nothing."""
    bind_traefik_mcp_files(scripted.config, repository)
    write_fleet(repository, ENABLED)
    scripted.starts_nothing = not observed_on

    exit_code, out, _ = switch()

    assert find_row(out, "traefik-mcp", PlanEvent.STARTS_LATER, "no applied record · with step-ca")
    assert RECREATE_FOLLOWER not in scripted.calls
    if not observed_on:
        assert exit_code == 1
        assert follower_entry(state) is None
        return
    assert exit_code == 0
    assert follower_entry(state) == follower_digest(repository)
    scripted.calls.clear()
    exit_code, out, _ = switch(answer="no")
    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def test_a_follower_entry_that_cannot_be_written_after_a_switch_on_is_partial_and_names_the_step(
    applied_core, switch, scripted, repository, state
):
    """#89 P15, beside cell F12: step-ca is observed on, but writing the follower's entry fails;
    exit 1 names the unit and the step, and no entry is left for traefik-mcp."""
    bind_traefik_mcp_files(scripted.config, repository)
    write_fleet(repository, ENABLED)
    scripted.after_up = lambda: state.chmod(0o500)
    try:
        exit_code, _, err = switch()
    finally:
        state.chmod(0o700)

    assert exit_code == 1
    assert (
        f"partial, step-ca: could not record traefik-mcp in applied.json, "
        f"cannot write {state / 'applied.json'}"
    ) in err
    assert RECREATE_FOLLOWER not in scripted.calls
    assert follower_entry(state) is None


def test_a_core_change_a_follower_change_and_a_unit_switch_share_one_yes_in_order(
    step_ca_applied, switch, scripted, repository, state, ingress
):
    """#89 rules 1, 3, cell F13: socket-proxy, traefik, traefik-mcp, then the unit; the barriers
    are proven after each core recreate only; the core is current."""
    scripted.config["services"]["echo"] = {"profiles": ["echo"]}
    write_fleet(
        repository,
        ENABLED + "  probe:\n    run: {enabled: true}\n  echo:\n    run: {enabled: true}\n",
    )
    scripted.containers["hello"] = "exited"
    switch_off(state, unit="probe")
    scripted.change_definition("socket-proxy")
    edit_traefik_mcp_yml(repository)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert up_calls(scripted)[:3] == [RECREATE_SOCKET_PROXY, RECREATE_TRAEFIK, RECREATE_FOLLOWER]
    assert unit_calls(scripted, "echo") == [up_calls(scripted)[3]]
    proven = "the barrier of probe is proven"
    assert out.count(proven) == 2
    assert out.rindex(proven) < out.index(CORE_CURRENT) < out.index(FOLLOWER_RECREATED)
    assert out.index(FOLLOWER_RECREATED) < out.index("echo is on")


def test_a_follower_of_a_unit_the_catalog_does_not_name_is_never_planned(
    step_ca_applied, switch, scripted, repository
):
    """#89 rule 5, cell F14: no line, no hash asked, no recreate."""
    write_fleet(repository, "services:\n  probe:\n    run: {enabled: false}\n")
    (repository / FOLLOWER_FILE).unlink()

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert "traefik-mcp" not in out
    hash_calls = [call for call in scripted.calls if call[2:4] == ["config", "--hash"]]
    assert hash_calls
    assert all("traefik-mcp" not in call[4].split(",") for call in hash_calls)
    assert scripted.changing_verbs() == []


def disable_step_ca_and_remove_it(scripted, repository, _state) -> None:
    write_fleet(repository, DISABLED)
    for service in STEP_CA_SERVICES:
        scripted.containers.pop(service)


def switch_step_ca_off(_scripted, _repository, state) -> None:
    switch_off(state)


@pytest.mark.parametrize(
    "put_step_ca",
    [lambda *_: None, disable_step_ca_and_remove_it, switch_step_ca_off],
    ids=["on", "disabled and gone", "switched off"],
)
def test_a_missing_traefik_mcp_yml_cannot_be_planned_whatever_step_cas_state(
    step_ca_applied, switch, scripted, repository, state, put_step_ca
):
    """#89 rule 6, cell F15, #34 finding 58, #91 cell E12: exit 2, naming the path, while step-ca
    is on, disabled and gone, or switched off."""
    put_step_ca(scripted, repository, state)
    (repository / FOLLOWER_FILE).unlink()

    exit_code, _, err = switch()

    assert exit_code == 2
    assert f"cannot plan, cannot read {repository / FOLLOWER_FILE}" in err
    assert scripted.changing_verbs() == []


def test_a_running_unit_whose_image_changed_is_named_and_nothing_changes(
    step_ca_applied, switch, scripted
):
    """#91 rules 3, 4, cell E1: the line names unit, service, both images and the upgrade's
    owner; nothing to change, no prompt, no changing verb, the same ids; a second run is the
    same."""
    scripted.change_image("step-ca", STEP_CA_BUMP)
    ids = dict(scripted.container_ids)

    runs = [switch(answer="no"), switch(answer="no")]

    assert runs[0] == runs[1]
    exit_code, out, _ = runs[0]
    assert exit_code == 0
    assert out.index(OLD_IMAGE) < plain(out).index("nothing to change")
    assert out.count(OLD_IMAGE) == 1
    assert "Type" not in out
    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


def test_a_unit_switched_on_names_its_running_service_whose_image_changed_after_its_line(
    switch, scripted
):
    """#91 rule 4, cell E2: one `yes`; the plan holds "on" and then the line; the start never
    recreates, so the running service keeps its id; the exited one is not named (rule 6)."""
    scripted.put_containers(APP_EXITED)
    scripted.change_image("step-ca", STEP_CA_BUMP)
    scripted.change_image("traefik-mcp", TRAEFIK_BUMP)
    db_id = scripted.container_ids["step-ca"]

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert find_row(out, "step-ca", PlanEvent.SWITCH_ON).start() < out.index(OLD_IMAGE)
    assert "traefik-mcp runs" not in out
    assert up_calls(scripted) == [
        ["--profile", "step-ca", "up", "-d", "--no-recreate", *STEP_CA_SERVICES]
    ]
    assert scripted.container_ids["step-ca"] == db_id


def ps_container(state: str, exit_code: int) -> compose.Container:
    line = json.dumps({"Service": "step-ca", "State": state, "ExitCode": exit_code, "Image": IMAGE})
    [container] = compose.Compose(answering(line)).containers()
    return container


@pytest.mark.parametrize(
    ("state", "exit_code", "named"),
    [
        ("running", 0, True),
        ("restarting", 1, True),
        ("paused", 0, True),
        ("exited", 1, False),
        ("exited", 0, False),  # completed
        ("created", 0, False),
    ],
)
def test_only_a_live_container_is_named_for_its_image(state, exit_code, named):
    """#91 rules 2, 6, cell E3: running, restarting and paused are live; exited, completed and
    created are not, so a completed one-shot never becomes a permanent line."""
    config = resolved_configuration()
    config["services"]["step-ca"]["image"] = STEP_CA_BUMP

    kept = plan_kept_images(
        (catalog.Unit("step-ca", True, None),),
        compose.profile_services(config),
        config,
        [ps_container(state, exit_code)],
        [],
        (),
    )

    running, configured = ImageReference.parse(IMAGE), ImageReference.parse(STEP_CA_BUMP)
    assert kept == ([KeptImage("step-ca", running, configured)] if named else [])


def test_a_unit_planned_off_is_not_named_for_its_image(switch, scripted, repository):
    """#91 rule 2, cell E4: off removes its containers as today; no line."""
    write_fleet(repository, DISABLED)
    scripted.put_containers(STEP_CA_ON)
    scripted.change_image("step-ca", STEP_CA_BUMP)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert OLD_IMAGE not in out
    assert "step-ca is off" in out


def test_a_switched_off_unit_with_a_running_container_is_named_and_stays_stopped(
    switch, scripted, state
):
    """#91 rules 2, 4, cell E5: "stays stopped" and the line; nothing to change."""
    switch_off(state)
    scripted.put_containers({"step-ca": "running"})
    scripted.change_image("step-ca", STEP_CA_BUMP)

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "step-ca", PlanEvent.STAYS_STOPPED).start() < out.index(OLD_IMAGE)
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def test_a_traefik_bump_recreates_traefik_and_its_follower_and_names_no_image(
    step_ca_applied, switch, scripted
):
    """#91 rule 2, cell E6: the core and the follower are recreated as today; neither they nor
    the completed acme owner are named."""
    for service in ("traefik", "traefik-mcp-acme-owner", "traefik-mcp"):
        scripted.change_image(service, TRAEFIK_BUMP)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert up_calls(scripted) == [RECREATE_TRAEFIK, RECREATE_FOLLOWER]
    assert OLD_IMAGE not in out


def test_a_socket_proxy_bump_is_the_core_recreate_only(applied_core, switch, scripted):
    """#91 rule 2, cell E7: the core recreate of C4; no line."""
    scripted.change_image("socket-proxy", SOCKET_PROXY_BUMP)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert up_calls(scripted) == [RECREATE_SOCKET_PROXY, RECREATE_TRAEFIK]
    assert OLD_IMAGE not in out


def test_a_service_of_a_profile_the_catalog_does_not_name_is_not_named(
    step_ca_applied, switch, scripted
):
    """#91 rule 2, cell E8: a live container of a non-catalog profile; no line."""
    scripted.config["services"]["echo"] = {"image": IMAGE, "profiles": ["echo"]}
    scripted.put_containers({"echo": "running"})
    scripted.change_image("echo", f"traefik/whoami:v1.12.1@sha256:{'4' * 64}")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert OLD_IMAGE not in out
    assert "nothing to change" in out


def test_a_unit_service_whose_definition_names_no_image_is_not_compared(
    step_ca_applied, switch, scripted
):
    """#91 rule 2, cell E9: no pin, nothing to compare."""
    del scripted.config["services"]["step-ca"]["image"]
    scripted.images["step-ca"] = STEP_CA_IMAGE

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert OLD_IMAGE not in out
    assert "nothing to change" in out


def test_a_stop_still_closes_a_unit_whose_ps_line_names_no_image(stop, scripted, state):
    """#91 rule 3: compose's parsing stays lenient, so `hal stop` never fails on it."""
    scripted.put_containers(STEP_CA_ON)
    scripted.images["step-ca"] = None

    exit_code, _, _ = stop()

    assert exit_code == 0
    assert marker(state) is not None
    assert "running" not in scripted.containers.values()


def test_a_ps_line_without_an_image_is_read_as_naming_none():
    """#91 rule 3: compose.py reads it leniently; the plan decides."""
    line = json.loads(Q1_PS_LINE)
    del line["Image"]

    [container] = compose.Compose(answering(json.dumps(line))).containers()

    assert container.image is None


def test_a_kept_image_and_a_core_recreate_share_one_yes_core_first(
    step_ca_applied, switch, scripted, repository
):
    """#91 rule 4, cell E11: one `yes`; the core line first, the kept image after it; the unit's
    containers keep their ids."""
    scripted.change_image("step-ca", STEP_CA_BUMP)
    edit_traefik_yml(repository)
    unit_ids = {service: scripted.container_ids[service] for service in STEP_CA_SERVICES}

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert plain(out).count("Type yes to apply") == 1
    assert row_at(out, "traefik", PlanEvent.RECREATE) < out.index(OLD_IMAGE)
    assert up_calls(scripted) == [RECREATE_TRAEFIK]
    assert {service: scripted.container_ids[service] for service in STEP_CA_SERVICES} == unit_ids


@pytest.mark.usefixtures("agent_service_unit")
def test_the_repositorys_agent_service_unit_that_is_not_set_up_runs_its_setup_with_a_yes(
    switch, scripted, setup_check, setup_run, repository
):
    """#234: a missing image or token file is asked about, and the answer yes runs the setup
    the catalog names before the unit starts."""
    setup_check.exit_code, setup_check.line = 1, "the image is not built"

    exit_code, out, _ = switch("yes\nyes")

    assert exit_code == 0
    assert "run `agent-service/setup` now" in out
    assert setup_run.commands == [(repository / "agent-service/setup", repository)]
    assert "agent-service is on" in out


KEYCLOAK_DISABLED = "services:\n  keycloak:\n    run: {enabled: false, setup: keycloak/init}\n"


@pytest.mark.usefixtures("realm_unit")
def test_a_realm_not_applied_before_is_planned_and_a_no_backs_up_and_applies_nothing(
    switch, scripted, realm_backup
):
    """Cell 2."""
    exit_code, out, err = switch("no")

    assert exit_code == 1
    assert PlanEvent.REALM_APPLY in out
    assert "aborted, nothing changed" in err
    assert (realm_backup.asked, scripted.realm_applies) == ([], 0)


@pytest.mark.usefixtures("realm_unit")
def test_a_yes_backs_up_proves_applies_and_lists_the_changes_then_the_next_apply_is_quiet(
    switch, scripted, realm_backup
):
    """Cells 3 and 4: one backup and one config-cli run; the second apply asks and does nothing."""
    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "no changes · snapshot ab12cd34 proven · <1s" in out  # the dim fact of the row
    assert "only in Keycloak: not listed, the realm files could not be read" in out
    assert (realm_backup.asked, scripted.realm_applies) == (["backup", "restore test"], 1)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert (realm_backup.asked, scripted.realm_applies) == (["backup", "restore test"], 1)


@pytest.mark.usefixtures("realm_unit")
def test_the_waiting_line_of_a_stopped_hal_is_told_as_the_step_runs(
    switch, repository, monkeypatch
):
    """Cell 7, through the wiring `apply` gives the installed backup."""
    monkeypatch.setattr(reconcile, "BACKUP_SECONDS", 1)
    monkeypatch.setattr(reconcile, "STOP_GRACE_SECONDS", 0.2)
    hal = repository / ".venv/bin/hal"
    hal.parent.mkdir(parents=True)
    hal.write_text("#!/bin/sh\nexec sleep 30\n")
    hal.chmod(0o755)

    exit_code, out, _ = switch(installed_backup=True)

    assert exit_code == 1
    assert "realm: waiting up to 0.2s for hal to clean up" in out


@pytest.mark.usefixtures("realm_unit")
def test_a_failed_backup_ends_partial_exit_1_and_applies_nothing(switch, scripted, realm_backup):
    """Cell 8."""
    realm_backup.failing = "backup"

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "error: partial, realm: backup broke; nothing applied" in err
    assert scripted.realm_applies == 0


@pytest.mark.usefixtures("realm_unit")
def test_a_config_cli_that_fails_ends_partial_names_the_snapshot_and_is_planned_again(
    switch, scripted, realm_backup
):
    """Cell 11."""
    scripted.config_cli_fails = True

    exit_code, _, err = switch()

    assert exit_code == 1
    assert realm_backup.asked == ["backup", "restore test"]
    assert "partial, realm:" in err
    assert "the realm may be partly applied; pre-apply snapshot ab12cd34" in err
    assert 'docs/backup.md "Restore Keycloak"' in err

    scripted.config_cli_fails = False
    _, out, _ = switch("no")

    assert PlanEvent.REALM_APPLY in out


@pytest.mark.usefixtures("realm_unit")
def test_a_core_error_inside_the_realm_hook_ends_partial_not_in_a_traceback(
    switch, scripted, monkeypatch
):
    """The hook sits inside the partial handling: resolving config-cli's binds is part of it."""

    def refuse(*_: object) -> frozenset[str]:
        raise core.CoreError("cannot read keycloak (Permission denied)")

    monkeypatch.setattr(core, "followed_services", refuse)

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial, realm: cannot read keycloak (Permission denied); nothing applied" in err
    assert scripted.realm_applies == 0


@pytest.mark.usefixtures("realm_unit")
def test_an_interrupt_while_the_realm_step_is_built_ends_partial_without_a_traceback(
    switch, scripted, monkeypatch
):
    built = []
    original = reconcile.Observer.__init__

    def interrupted_after_the_plan(self, engine):
        if built:
            raise KeyboardInterrupt
        built.append(engine)
        original(self, engine)

    monkeypatch.setattr(reconcile.Observer, "__init__", interrupted_after_the_plan)

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "interrupted while changing keycloak (apply the realm step)" in err
    assert "Traceback" not in err
    assert scripted.realm_applies == 0


@pytest.mark.usefixtures("realm_unit")
def test_keycloak_switched_off_by_the_config_is_one_line_and_no_step(
    switch, repository, scripted, realm_backup
):
    """Cell 14."""
    write_fleet(repository, KEYCLOAK_DISABLED)

    _, out, _ = switch("no")

    assert PlanEvent.REALM_HELD in out
    assert (realm_backup.asked, scripted.realm_applies) == ([], 0)


@pytest.mark.usefixtures("realm_unit")
def test_keycloak_switched_off_by_its_marker_is_never_started_or_applied(
    switch, state, scripted, realm_backup
):
    """Cell 15: the unit stays as it was, and the changed realm waits."""
    switch_off(state, unit="keycloak")

    _, out, _ = switch()

    assert PlanEvent.REALM_HELD in out
    assert scripted.containers == {"keycloak": "running"}
    assert (realm_backup.asked, scripted.realm_applies, scripted.changing_verbs()) == ([], 0, [])


def test_keycloak_that_starts_in_this_run_is_not_checked_and_one_line_says_so(
    switch, repository, scripted, realm_backup
):
    """Its realm is checked by the next apply."""
    write_fleet(repository, KEYCLOAK_ENABLED)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert PlanEvent.REALM_LATER in out
    assert (realm_backup.asked, scripted.realm_applies) == ([], 0)
