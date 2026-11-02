"""`hal apply` swaps the image of agent-service, the one service whose unit has `run.build`, in one
recreate under the one yes, on the scripted boundaries of `tests/support/stack_apply.py`
(#482, E1-E5)."""

from dataclasses import dataclass, field
from pathlib import Path

import pytest
import support.stack_apply as base
import yaml
from support.stack_apply import (
    ENABLED,
    OLD_IMAGE,
    RECREATE_TRAEFIK,
    STEP_CA_BUMP,
    SWITCHED_OFF_AT,
    ZONE,
    switch_off,
    up_calls,
    write_fleet,
)
from support.stack_apply_fakes import (
    LABELLED_IMAGE_ID,
    ScriptedCompose,
)
from support.stack_plan_rows import find_row, plain

from hal.stack import switches
from hal.stack.plan_rows import PlanEvent
from hal.stack.result_rows import ResultEvent

BUMPED_TAG = "edge-agent-service:9.9.9-2.1.302"
REBUILT_ID = f"sha256:{'e' * 64}"
BUMPED_ID = f"sha256:{'d' * 64}"
OTHER_ID = f"sha256:{'c' * 64}"
RECREATE_AGENT_SERVICE = [*RECREATE_TRAEFIK[:-1], "agent-service"]
RECREATE_EGRESS = [*RECREATE_TRAEFIK[:-1], "agent-egress"]
DEFINITION_FACT = "definition changed"
SWITCHED_OFF_SINCE = f"switched off since {switches.describe_since(SWITCHED_OFF_AT)}"


# The fixtures of `tests/support/stack_apply.py` this module's tests request by name.
agent_service_unit = base.agent_service_unit
at_terminal = base.at_terminal
core_files = base.core_files
home = base.home
ingress = base.ingress
realm_backup = base.realm_backup
repository = base.repository
scripted_git = base.scripted_git
setup_check = base.setup_check
setup_run = base.setup_run
start = base.start
state = base.state
step_ca_applied = base.step_ca_applied
switch = base.switch
applied_core = base.applied_core


@dataclass
class BuildingCompose(ScriptedCompose):
    """Compose whose new container carries the id its image reference has when it is created."""

    created_ids: dict[str, str] = field(default_factory=dict)
    without_image_id: set[str] = field(default_factory=set)

    def create_container(self, service: str) -> None:
        super().create_container(service)
        reference = self.configured_image(service)
        self.created_ids[service] = self.image_ids.get(reference) or LABELLED_IMAGE_ID

    def labels_of(self, service: str) -> str:
        labels = super().labels_of(service)
        if service in self.without_image_id:
            return labels.replace(f"com.docker.compose.image={LABELLED_IMAGE_ID},", "")
        return labels.replace(LABELLED_IMAGE_ID, self.created_ids.get(service, LABELLED_IMAGE_ID))


@pytest.fixture
def scripted() -> BuildingCompose:
    return BuildingCompose()


@pytest.fixture
def running(agent_service_unit, switch, scripted) -> None:
    """agent-service on from the current definitions and tag; the calls so far are forgotten."""
    assert switch()[0] == 0
    scripted.calls.clear()


def configured(scripted: BuildingCompose) -> str:
    return scripted.config["services"]["agent-service"]["image"]


def bump(scripted: BuildingCompose) -> str:
    """compose.yaml now names a newer built tag; the old container keeps its image. Returns the
    old reference."""
    old = configured(scripted)
    scripted.change_image("agent-service", BUMPED_TAG)
    scripted.image_ids[BUMPED_TAG] = BUMPED_ID
    return old


def recreate_row(out: str, fact: str = "") -> bool:
    return find_row(out, "agent-service", PlanEvent.RECREATE, fact) is not None


def bump_fact(old: str) -> str:
    return f"image {old} \N{RIGHTWARDS ARROW} {BUMPED_TAG}"


def show_container_id(scripted: BuildingCompose) -> None:
    """`ps` names the container's own image id, not the reference, as it may once the tag moved."""
    scripted.images["agent-service"] = LABELLED_IMAGE_ID


def switch_on_call(scripted: BuildingCompose) -> list[str]:
    return next(call for call in up_calls(scripted) if "--no-recreate" in call)


def test_a_reference_bump_recreates_agent_service_once_under_the_one_yes(running, switch, scripted):
    """M1, E1, E2: the line names both tags and the end of runs; one question; one recreate."""
    ids = dict(scripted.container_ids)
    old = bump(scripted)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert recreate_row(out, bump_fact(old))
    assert find_row(out, "agent-service", ResultEvent.RECREATED, "5s")
    assert plain(out).count("Type yes to apply") == 1
    assert up_calls(scripted) == [RECREATE_AGENT_SERVICE]
    assert scripted.container_ids["agent-service"] != ids["agent-service"]
    assert scripted.container_ids["agent-egress"] == ids["agent-egress"]
    assert scripted.image_of("agent-service") == BUMPED_TAG


def test_a_declined_yes_runs_no_changing_verb(running, switch, scripted):
    """M2, E2: no image swap, the old container runs on."""
    ids = dict(scripted.container_ids)
    bump(scripted)

    switch(answer="no")

    assert scripted.changing_verbs() == []
    assert scripted.container_ids == ids


@pytest.mark.parametrize("ps_shows_the_id", [False, True], ids=["reference", "container id"])
def test_a_rebuilt_tag_names_the_reference_never_an_id(running, switch, scripted, ps_shows_the_id):
    """M3 (a, b), E1, U9: the same tag now names another image."""
    reference = configured(scripted)
    scripted.image_ids[reference] = REBUILT_ID
    if ps_shows_the_id:
        show_container_id(scripted)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert recreate_row(out, f"image {reference} rebuilt")
    assert LABELLED_IMAGE_ID not in out
    assert REBUILT_ID not in out
    assert up_calls(scripted) == [RECREATE_AGENT_SERVICE]


def test_a_rebuilt_tag_of_a_service_two_enabled_profiles_share_gives_one_old_image_row(
    step_ca_applied, switch, scripted, repository
):
    """Decision 4: each kept image prints as exactly one row."""
    service = scripted.config["services"]["step-ca"]
    service["image"] = "step-ca:local"
    service["profiles"].append("echo")
    scripted.config["services"]["echo"] = {"profiles": ["echo"]}
    write_fleet(repository, ENABLED + "  echo:\n    run: {enabled: true}\n")
    assert switch()[0] == 0
    scripted.images["step-ca"] = "step-ca:local"
    scripted.image_ids["step-ca:local"] = REBUILT_ID
    scripted.change_definition("step-ca")

    _, out, _ = switch()

    assert out.count(OLD_IMAGE) == 1


def test_a_bump_beside_a_definition_change_gives_the_bump_line_once(running, switch, scripted):
    """M4 (a), E1."""
    old = bump(scripted)
    scripted.change_definition("agent-service")

    _, out, _ = switch()

    assert recreate_row(out, bump_fact(old))
    assert out.count(f"  {PlanEvent.RECREATE} ") == 1
    assert not recreate_row(out, DEFINITION_FACT)


def test_a_bump_whose_old_tag_is_gone_gives_the_definition_line_not_an_id(
    running, switch, scripted
):
    """M4 (b), U9: `ps` shows the container's id, which is no reference."""
    bump(scripted)
    show_container_id(scripted)

    _, out, _ = switch()

    assert recreate_row(out, DEFINITION_FACT)
    assert LABELLED_IMAGE_ID not in out
    assert "image sha256" not in out


def test_a_definition_change_alone_gives_the_definition_line(running, switch, scripted):
    """M5, E1."""
    scripted.change_definition("agent-service")

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert recreate_row(out, DEFINITION_FACT)
    assert up_calls(scripted) == [RECREATE_AGENT_SERVICE]


def test_a_restarting_container_on_the_old_image_is_recreated_before_the_switch_on(
    running, switch, scripted
):
    """M6, the incident: the crash-looping 0.7.0 container is replaced, and the unit's `on` keeps
    the new one."""
    bump(scripted)
    scripted.containers["agent-service"] = "restarting"
    ids = dict(scripted.container_ids)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert find_row(out, "agent-service", PlanEvent.RECREATE).start() < (
        find_row(out, "agent-service", PlanEvent.SWITCH_ON).start()
    )
    assert up_calls(scripted)[0] == RECREATE_AGENT_SERVICE
    assert "--no-recreate" in up_calls(scripted)[1]
    assert scripted.container_ids["agent-service"] != ids["agent-service"]
    assert scripted.containers["agent-service"] == "running"
    assert scripted.image_of("agent-service") == BUMPED_TAG


@pytest.mark.parametrize("differing", [False, True], ids=["equal image", "differing image"])
def test_an_exited_sibling_switches_the_unit_on_and_recreates_only_a_differing_image(
    running, switch, scripted, differing
):
    """M7: agent-egress exited gives `on`; agent-service is recreated only when its image
    differs."""
    scripted.containers["agent-egress"] = "exited"
    if differing:
        bump(scripted)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert recreate_row(out) is differing
    assert [call for call in up_calls(scripted) if "--force-recreate" in call] == (
        [RECREATE_AGENT_SERVICE] if differing else []
    )
    assert scripted.containers == {"agent-egress": "running", "agent-service": "running"}


def test_an_agent_service_exited_by_hand_with_a_differing_image_is_recreated(
    running, switch, scripted
):
    """M8, E1: the exited container is not started as it is."""
    bump(scripted)
    scripted.containers["agent-service"] = "exited"

    exit_code, _, _ = switch()

    assert exit_code == 0
    assert up_calls(scripted)[0] == RECREATE_AGENT_SERVICE
    assert scripted.image_of("agent-service") == BUMPED_TAG


def test_an_agent_service_without_a_container_gets_no_line_and_is_created_as_is(
    running, switch, scripted
):
    """M9: the unit's switch-on creates it, never a recreate."""
    del scripted.containers["agent-service"]

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert not recreate_row(out)
    assert "--no-recreate" in switch_on_call(scripted)
    assert scripted.containers["agent-service"] == "running"


def test_a_bump_to_an_unbuilt_tag_is_planned_after_the_setup_ran(
    running, switch, scripted, setup_check, setup_run
):
    """M10, E2: the tag is missing, so the setup is asked first; the fresh plan holds the
    recreate."""
    old = bump(scripted)
    scripted.image_ids[BUMPED_TAG] = ""
    setup_check.exit_code, setup_check.line = 1, "the image is not built"

    exit_code, out, _ = switch("yes\nyes")

    assert exit_code == 0
    assert len(setup_run.commands) == 1
    assert recreate_row(out, bump_fact(old))
    assert up_calls(scripted) == [RECREATE_AGENT_SERVICE]


def test_an_image_of_a_unit_that_is_not_built_is_only_named(step_ca_applied, switch, scripted):
    """M11, E1 counterexample, #91: step-ca keeps its image and gets the naming line."""
    scripted.change_image("step-ca", STEP_CA_BUMP)

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert OLD_IMAGE in out
    assert scripted.changing_verbs() == []


def test_a_switched_off_agent_service_stays_stopped_and_is_not_recreated(
    running, switch, scripted, state
):
    """M12, E5: the marker keeps it off whatever its image."""
    bump(scripted)
    scripted.containers.update({"agent-service": "exited", "agent-egress": "exited"})
    switch_off(state, unit="agent-service")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "agent-service", PlanEvent.STAYS_STOPPED, SWITCHED_OFF_SINCE)
    assert not recreate_row(out)
    assert scripted.changing_verbs() == []


def test_a_switched_off_agent_service_with_a_running_container_gets_no_kept_image_line(
    running, switch, scripted, state
):
    """E5: the plan shows only that it stays stopped, not that hal never swaps its image."""
    bump(scripted)
    switch_off(state, unit="agent-service")

    exit_code, out, _ = switch(answer="no")

    assert exit_code == 0
    assert find_row(out, "agent-service", PlanEvent.STAYS_STOPPED, SWITCHED_OFF_SINCE)
    assert OLD_IMAGE not in out
    assert scripted.changing_verbs() == []


def test_a_marker_that_appears_after_the_yes_prevents_the_recreate(
    running, switch, scripted, state
):
    """M13, P7: the marker is read again under the switch lock."""
    bump(scripted)

    exit_code, _, err = switch(while_prompt_waits=lambda: switch_off(state, unit="agent-service"))

    assert exit_code == 1
    assert "agent-service was switched off meanwhile" in err
    assert up_calls(scripted) == []


def test_a_changed_follower_is_recreated_before_agent_service(running, switch, scripted):
    """M14: agent-egress goes first, then agent-service."""
    scripted.change_definition("agent-egress")
    bump(scripted)

    exit_code, _, _ = switch()

    assert exit_code == 0
    assert up_calls(scripted) == [RECREATE_EGRESS, RECREATE_AGENT_SERVICE]


def test_hal_start_keeps_the_stopped_container_whatever_image_waits(
    running, start, scripted, state
):
    """M15, E5, #75: the start is `--no-recreate`, so the container keeps its id."""
    scripted.containers.update({"agent-service": "exited", "agent-egress": "exited"})
    switch_off(state, unit="agent-service")
    bump(scripted)
    ids = dict(scripted.container_ids)

    exit_code, _, _ = start(unit="agent-service")

    assert exit_code == 0
    assert scripted.container_ids == ids
    assert all("--force-recreate" not in call for call in up_calls(scripted))


def test_an_up_that_fails_before_replacing_the_container_plans_the_recreate_again(
    running, switch, scripted
):
    """M16: no record is kept, so the next run reads the old reference and plans it again."""
    old = bump(scripted)
    ids = dict(scripted.container_ids)
    scripted.failing_verb = "up"

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "partial" in err
    assert scripted.container_ids == ids

    scripted.failing_verb = None
    exit_code, out, _ = switch()

    assert exit_code == 0
    assert recreate_row(out, bump_fact(old))
    assert scripted.image_of("agent-service") == BUMPED_TAG


def test_a_new_container_that_crash_loops_is_partial_and_the_next_run_plans_only_on(
    running, switch, scripted
):
    """M17: the recreate is not observed running; the replaced container is the intended one."""
    bump(scripted)
    scripted.crash_loops.add("agent-service")

    exit_code, _, err = switch()

    assert exit_code == 1
    assert "agent-service is not running after the agent-service recreate" in err

    exit_code, out, err = switch()

    assert exit_code == 1
    assert not recreate_row(out)
    assert find_row(out, "agent-service", PlanEvent.SWITCH_ON)
    assert "agent-service is not on after the change" in err


def test_a_new_container_that_recovers_after_the_watch_leaves_nothing_to_change(
    running, switch, scripted
):
    """M18."""
    bump(scripted)
    scripted.crash_loops.add("agent-service")
    assert switch()[0] == 1
    scripted.crash_loops.clear()
    scripted.containers["agent-service"] = "running"
    scripted.calls.clear()

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


def write_unit_fleet(repository: Path, build: str | None = "agent-service/image") -> None:
    unit = {"run": {"enabled": True, "setup": "agent-service/setup"}}
    if build is not None:
        unit["run"]["build"] = build
    write_fleet(
        repository,
        yaml.safe_dump({"cloudflare": {"zone": ZONE}, "services": {"agent-service": unit}}),
    )


def refuse_a_build_that_is_no_recipe_directory(scripted, repository) -> None:
    write_unit_fleet(repository, "agent-service")


def refuse_a_build_on_an_app(scripted, repository) -> None:
    fleet = yaml.safe_load((repository / "fleet.yaml").read_text())
    fleet["github"] = {"org": "overnightworks"}
    fleet["services"]["hopin"] = {
        "repo": {"default_branch": "main"},
        "run": {"enabled": True, "build": "agent-service/image"},
    }
    write_fleet(repository, yaml.safe_dump(fleet))


def refuse_a_unit_without_a_never_pulled_service(scripted, repository) -> None:
    del scripted.config["services"]["agent-service"]["pull_policy"]


def refuse_a_container_without_its_image(scripted, repository) -> None:
    scripted.images["agent-service"] = None


def refuse_a_container_without_its_definition_label(scripted, repository) -> None:
    scripted.labels["agent-service"] = None


def refuse_a_container_without_its_image_id_label(scripted, repository) -> None:
    scripted.without_image_id.add("agent-service")


def refuse_a_failing_lookup(scripted, repository) -> None:
    scripted.image_ids[configured(scripted)] = None


def refuse_a_lookup_naming_two_images(scripted, repository) -> None:
    scripted.image_ids[configured(scripted)] = f"{REBUILT_ID}\n{OTHER_ID}"


@pytest.mark.parametrize(
    ("arrange", "cause"),
    [
        (refuse_a_build_that_is_no_recipe_directory, "is not a directory of this repository"),
        (refuse_a_build_on_an_app, "unknown key for an app"),
        (refuse_a_unit_without_a_never_pulled_service, "exactly one of its services"),
        (refuse_a_container_without_its_image, "names no Image"),
        (refuse_a_container_without_its_definition_label, "no com.docker.compose.config-hash"),
        (refuse_a_container_without_its_image_id_label, "no com.docker.compose.image label"),
        (refuse_a_failing_lookup, "exited 1"),
        (refuse_a_lookup_naming_two_images, "names 2 images"),
    ],
)
def test_a_state_that_cannot_be_planned_is_exit_2_and_changes_nothing(
    running, switch, scripted, repository, arrange, cause
):
    """M19: each is `cannot plan` and names its cause, before a changing verb."""
    arrange(scripted, repository)

    exit_code, _, err = switch()

    assert (exit_code, scripted.changing_verbs()) == (2, [])
    assert "cannot plan" in err
    assert cause in err


def test_a_second_run_after_a_recreate_has_nothing_to_change(running, switch, scripted):
    """M20, invariant 8: the new container matches compose.yaml and the tag."""
    bump(scripted)
    assert switch()[0] == 0
    scripted.calls.clear()

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert "nothing to change" in out
    assert scripted.changing_verbs() == []


@pytest.mark.parametrize("ps_shows_the_id", [False, True], ids=["reference", "container id"])
def test_a_tag_removed_by_hand_plans_no_recreate_and_still_asks_the_setup(
    running, switch, scripted, setup_check, setup_run, ps_shows_the_id
):
    """M21 (a, b), U8, U9: a tag gone means no recreate; the setup is asked as before."""
    scripted.image_ids[configured(scripted)] = ""
    if ps_shows_the_id:
        show_container_id(scripted)
    setup_check.exit_code, setup_check.line = 1, "the image is not built"

    exit_code, out, _ = switch()

    assert exit_code == 0
    assert len(setup_run.commands) == 1
    assert not recreate_row(out)
    assert scripted.changing_verbs() == []
