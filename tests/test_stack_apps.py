"""What `hal apply` plans for an app and how it runs the plan (#255 A1-A3, A8-A12, A16-A19, A22,
A23), against a real origin and a scripted Docker: the checkout, the tags and the record are real,
the containers are a table."""

import dataclasses
import stat
import subprocess

import pytest
import support.stack_apps as stack_apps_support
from support.app_support import (
    COMPOSE,
    FLEET,
    KEY,
    NOW,
    SENTINEL,
    TWO_SERVICES,
    Clock,
    ScriptedDocker,
)
from support.git_support import head_of, plain_git
from support.stack_apps import (
    FIRST,
    SECOND,
    THIRD,
    World,
    deploy,
)

from hal.stack import apps, compose, releases

(
    docker,
    home,
    origin,
    repository,
    runtime,
    state,
    world,
) = (
    stack_apps_support.docker,
    stack_apps_support.home,
    stack_apps_support.origin,
    stack_apps_support.repository,
    stack_apps_support.runtime,
    stack_apps_support.state,
    stack_apps_support.world,
)  # fmt: skip


def test_a_first_apply_plans_tag_and_full_sha_then_runs_and_records_after_health(world, origin):
    sha = origin.release(FIRST)

    plan = world.plan()

    [planned] = plan.plans
    assert (planned.kind, planned.release.tag, planned.sha) == (apps.AppKind.ON, FIRST, sha)
    assert world.deployed() is None
    [result] = world.run(plan)
    assert isinstance(result, apps.AppOn)
    assert world.deployed() == {"tag": FIRST, "sha": sha, "time": NOW.isoformat()}
    assert stat.S_IMODE((world.state / "deployed" / KEY).stat().st_mode) == 0o600
    assert head_of(world.srv) == sha
    assert world.docker.verbs == [
        "ps", "build", "pull", "config", "image inspect", "create", "start", "ps",
    ]  # fmt: skip


def test_only_create_and_start_run_under_the_switch_lock_and_nothing_else_does(world, origin):
    origin.release(FIRST)

    world.run()

    assert world.docker.locked_verbs() == {"create", "start"}


def test_a_second_apply_changes_nothing_and_builds_creates_and_starts_nothing(world, origin):
    deploy(world, origin, FIRST)
    world.docker.calls.clear()

    plan = world.plan()

    assert plan.changes_nothing
    assert plan.kept == ()
    assert world.docker.verbs == ["ps"]


def test_a_newer_release_is_an_update_that_names_the_last_successful_deployment(world, origin):
    deploy(world, origin, FIRST)
    sha = origin.release(SECOND)

    plan = world.plan()

    [planned] = plan.plans
    assert (planned.kind, planned.release.tag, planned.sha) == (apps.AppKind.UPDATE, SECOND, sha)
    assert (planned.recorded_tag, planned.unfinished) == (FIRST, None)
    [result] = world.run(plan)
    assert isinstance(result, apps.AppOn)
    assert world.deployed()["tag"] == SECOND


def test_a_release_on_a_side_branch_is_named_and_the_newest_stays(world, origin):
    deploy(world, origin, SECOND)
    plain_git(origin.work, "switch", "--quiet", "-c", "side")
    origin.commit({"side": "1"})
    origin.tag("v2026.10.22.9")

    plan = world.plan()

    assert plan.changes_nothing
    assert plan.kept == (
        apps.SkippedNote(KEY, releases.SkippedTag("v2026.10.22.9", "not on origin master")),
    )


def test_an_off_grammar_tag_is_named_in_the_plan(world, origin):
    origin.release(FIRST)
    origin.tag("v2027.1.5.1")

    plan = world.plan()

    assert plan.kept == (
        apps.SkippedNote(KEY, releases.SkippedTag("v2027.1.5.1", "not vYYYY.MM.DD.N")),
    )
    assert plan.plans[0].release.tag == FIRST


def test_without_a_release_the_plan_is_refused_asking_for_the_first_one_and_writes_only_git(
    world, origin
):
    with pytest.raises(apps.AppError, match=r"no vYYYY.MM.DD.N release on origin master; .*first"):
        world.plan()

    assert [path.name for path in world.srv.iterdir()] == [".git"]


def test_a_new_tag_that_fails_health_stays_partial_with_the_record_on_the_old_one(world, origin):
    deploy(world, origin, SECOND)
    sha = origin.release(THIRD)
    world.docker.health_after_start = "unhealthy"

    [result] = world.run()

    failure = result.cause

    assert failure == (
        f"not healthy at {THIRD} after 300s (hopin running (unhealthy)); "
        "the record stays, the fix is a newer tag"
    )
    assert world.deployed()["tag"] == SECOND
    [planned] = world.plan().plans
    assert (planned.release.tag, planned.sha, planned.recorded_tag) == (THIRD, sha, SECOND)
    assert planned.unfinished == THIRD


def test_a_helper_without_a_healthcheck_that_runs_is_recorded_and_the_plan_has_nothing_to_change(
    world, origin, docker
):
    """H1 of #444: a running helper that reports no health is settled."""
    docker.without_health = frozenset({"worker"})

    deploy(world, origin, FIRST, {"compose.yaml": TWO_SERVICES})

    assert {row["Service"]: row["Health"] for row in docker.rows} == {
        "web": "healthy",
        "worker": "",
    }
    assert world.plan().changes_nothing


@pytest.mark.parametrize("helper_state", ["restarting", "exited", "created"])
def test_a_helper_without_a_healthcheck_that_does_not_run_leaves_the_app_unrecorded(
    world, origin, docker, helper_state
):
    """H2 of #444: a helper that does not run is unsettled even without a healthcheck."""
    origin.release(FIRST, {"compose.yaml": TWO_SERVICES})
    docker.without_health = frozenset({"worker"})
    docker.during["start"] = lambda: docker.rows[1].update(State=helper_state)

    [result] = world.run()

    failure = result.cause

    assert failure.startswith(f"not healthy at {FIRST} after 300s (")
    assert f"worker {helper_state}" in failure
    assert world.deployed() is None


def test_a_build_that_fails_leaves_the_old_containers_and_the_next_plan_says_unfinished(
    world, origin
):
    deploy(world, origin, FIRST)
    sha = origin.release(SECOND)
    world.docker.failing_verb = "build"

    [result] = world.run()

    failure = result.cause
    world.docker.failing_verb = None

    assert failure == (
        f"could not build at {SECOND}, `docker compose build` of hopin at {SECOND} "
        "exited 3; its output is withheld, run the step in the app's checkout to read it"
    )
    assert world.deployed()["tag"] == FIRST
    assert world.docker.rows[0]["Name"] == "hopin-hopin-1"
    [planned] = world.plan().plans
    assert (planned.release.tag, planned.sha, planned.recorded_tag) == (SECOND, sha, FIRST)
    assert planned.unfinished == SECOND


@pytest.mark.parametrize("verb", ["build", "pull", "create", "start"])
def test_no_word_of_composes_output_reaches_a_failure_line(world, origin, verb):
    origin.release(FIRST)
    world.docker.failing_verb = verb

    [result] = world.run()

    failure = result.cause

    assert SENTINEL not in failure
    assert f"could not {verb}" in failure
    assert f"at {FIRST}" in failure
    assert "exited 3" in failure


def test_no_word_of_composes_output_reaches_the_plan_when_ps_fails(world, origin):
    origin.release(FIRST)
    world.docker.failing_verb = "ps"

    with pytest.raises(compose.ComposeError) as failed:
        world.plan()

    assert SENTINEL not in str(failed.value)
    assert "exited 3" in str(failed.value)


@pytest.mark.parametrize(
    ("verb", "step"),
    [
        ("build", f"build at {SECOND}"),
        ("create", "create the containers"),
        ("start", "start at"),
    ],
)
def test_an_interrupt_names_the_app_and_step_and_leaves_the_record_and_the_next_plan_unfinished(
    world, origin, verb, step
):
    deploy(world, origin, FIRST)
    sha = origin.release(SECOND)
    world.docker.interrupted_verb = verb

    with pytest.raises(KeyboardInterrupt):
        world.run()
    world.docker.interrupted_verb = None

    assert world.progress.unit == KEY
    assert step in world.progress.step
    assert ("partly replaced" in world.progress.step) == (verb != "build")
    assert world.deployed()["tag"] == FIRST
    assert world.plan().plans[0].unfinished == SECOND
    assert head_of(world.srv) == sha


def test_an_interrupt_during_the_health_wait_names_it_and_records_nothing(
    world, origin, docker, home, state
):
    deploy(world, origin, FIRST)
    origin.release(SECOND)
    clock = Clock()

    def interrupted(_seconds: float) -> None:
        raise KeyboardInterrupt

    docker.health_after_start = "starting"
    world.runtime = dataclasses.replace(
        world.runtime, health=compose.Watch(clock.read, interrupted, 300)
    )

    with pytest.raises(KeyboardInterrupt):
        world.run()

    assert world.progress.step == f"wait for {KEY} to be healthy"
    assert world.deployed()["tag"] == FIRST


@pytest.mark.parametrize(
    "break_it",
    [
        lambda docker: docker.rows[0].update(State="exited", Health=""),
        lambda docker: docker.rows[0].update(Health="unhealthy"),
    ],
    ids=["stopped by hand", "unhealthy"],
)
def test_the_newest_release_recorded_and_checked_out_but_not_running_well_starts_again(
    world, origin, break_it
):
    sha = deploy(world, origin, FIRST)
    break_it(world.docker)

    [planned] = world.plan().plans
    assert (planned.kind, planned.release.tag, planned.sha) == (
        apps.AppKind.START_AGAIN,
        FIRST,
        sha,
    )


def test_an_app_whose_container_name_compose_interpolates_plans_start_again_and_update(
    world, origin, monkeypatch
):
    resolved = "hal-test-sentinel-value"
    monkeypatch.setenv("SENTINEL", resolved)
    named = COMPOSE + "    container_name: '${SENTINEL}'\n"
    create_unnamed = world.docker.verb_create

    def create_named(arguments: list[str]) -> str:
        create_unnamed(arguments)
        for row in world.docker.rows:
            row["Name"] = resolved
        return ""

    world.docker.verb_create = create_named
    sha = deploy(world, origin, FIRST, {"compose.yaml": named})
    world.docker.rows[0]["State"] = "exited"
    start_again = world.plan().plans

    assert world.docker.rows[0]["Name"] == resolved
    assert (start_again[0].kind, start_again[0].sha) == (apps.AppKind.START_AGAIN, sha)

    origin.release(SECOND, {"compose.yaml": named})
    update = world.plan().plans

    assert (update[0].kind, update[0].release.tag) == (apps.AppKind.UPDATE, SECOND)

    world.docker.health_after_start = "unhealthy"
    [result] = world.run()
    failure = result.cause

    assert world.docker.rows[0]["Name"] == resolved
    assert "hopin running (unhealthy)" in failure
    assert resolved not in failure


@pytest.mark.parametrize(
    "arrange",
    [
        lambda docker: docker.put(KEY, "running", "healthy"),
        lambda docker: docker.put("orphan", "running", "healthy"),
    ],
    ids=["a second container of a service", "a container of a service the file lacks"],
)
def test_one_container_per_service_and_no_orphan_is_needed_for_nothing_to_change(
    world, origin, arrange
):
    sha = deploy(world, origin, FIRST)
    arrange(world.docker)

    [planned] = world.plan().plans

    assert (planned.kind, planned.sha) == (apps.AppKind.START_AGAIN, sha)


def test_a_dirty_checkout_cannot_be_planned_and_is_not_reset(world, origin):
    deploy(world, origin, FIRST)
    (world.srv / "stray").write_text("mine")

    with pytest.raises(
        apps.AppError, match=r"services.hopin: ~/srv/hopin has local changes.*stray"
    ):
        world.plan()

    assert (world.srv / "stray").read_text() == "mine"


def test_a_regular_file_at_the_checkout_cannot_be_planned_with_one_line(world, origin):
    origin.release(FIRST)
    world.srv.parent.mkdir(parents=True, exist_ok=True)
    world.srv.write_text("mine")

    with pytest.raises(apps.AppError, match=r"services.hopin: ~/srv/hopin cannot be made"):
        world.plan()


def test_a_tag_moved_on_origin_against_the_record_cannot_be_planned_naming_both_shas(world, origin):
    recorded = deploy(world, origin, FIRST)
    moved = origin.commit({"other": "1"})
    origin.push("master")
    origin.tag(FIRST)

    with pytest.raises(apps.AppError) as refused:
        world.plan()

    assert str(refused.value) == (
        f"services.hopin: tag {FIRST} moved on origin; deployed {recorded}, origin now {moved}"
    )


def test_an_origin_that_cannot_be_reached_cannot_be_planned_with_gits_last_line(
    world, origin, home
):
    origin.release(FIRST)
    (home / ".gitconfig").write_text(
        '[url "file:///nowhere.git"]\n\tinsteadOf = https://github.com/\n'
    )

    with pytest.raises(apps.AppError, match=r"services.hopin: `git fetch` exited 128: fatal:"):
        world.plan()


def test_a_disabled_app_is_not_fetched_and_has_nothing_to_change(world, repository):
    (repository / "fleet.yaml").write_text(FLEET.replace("enabled: true", "enabled: false"))
    asked = []
    world.runtime = dataclasses.replace(
        world.runtime, git=lambda *call: asked.append(call) or pytest.fail("git was asked")
    )

    plan = world.plan()

    assert plan.changes_nothing
    assert asked == []
    assert world.docker.verbs == ["ps"]
    assert not world.srv.exists()


class OffDocker:
    """What the off step asks of Docker: the project's `ps` from the scripted table and the
    file-free `stop` and `rm -f`, which empty the table. Every other call goes to the scripted
    Docker, which fails the test on a `down`, a `-v` or a file-bound call."""

    def __init__(self, scripted: ScriptedDocker) -> None:
        self.scripted = scripted
        self.commands: list[list[str]] = []
        self.failing: str | None = None
        self.removal_by_identifier_works = True
        self.removal_by_identifier_exit = 0
        self.survivors: set[str] = set()  # services whose containers only `docker rm` removes

    def run(self, command, timeout, stdin=None):
        self.commands.append(command)
        if command[:3] == ["docker", "rm", "-f"]:
            return self.remove_by_identifier(command)
        if command[4:5] in (["stop"], ["rm"]):
            assert command[4:] in (["stop"], ["rm", "-f"]), command
            if self.failing == command[4]:
                return subprocess.CompletedProcess(command, 3, SENTINEL, SENTINEL)
            if command[4] == "rm":
                self.scripted.rows[:] = [
                    r for r in self.scripted.rows if r["Service"] in self.survivors
                ]
            return subprocess.CompletedProcess(command, 0, "", "")
        return self.scripted.run(command, timeout, stdin)

    def remove_by_identifier(self, command):
        assert "-v" not in command, command
        assert "--volumes" not in command, command
        listed = {row["ID"] for row in self.scripted.rows}
        assert command[3:], command
        assert set(command[3:]) <= listed, command
        if self.removal_by_identifier_exit:
            code = self.removal_by_identifier_exit
            return subprocess.CompletedProcess(command, code, SENTINEL, SENTINEL)
        if self.removal_by_identifier_works:
            self.scripted.rows[:] = [r for r in self.scripted.rows if r["ID"] not in command[3:]]
        return subprocess.CompletedProcess(command, 0, "", "")

    def compose_calls(self) -> list[list[str]]:
        return [command[4:] for command in self.commands if command[:2] == ["docker", "compose"]]


def switch_off(world: World) -> OffDocker:
    """The app disabled in the catalog while its project holds a healthy container, and a
    leftover of a service the file does not name."""
    (world.repository / "fleet.yaml").write_text(FLEET.replace("enabled: true", "enabled: false"))
    if not world.docker.rows:
        world.docker.put(KEY, "running", "healthy")
    world.docker.put("leftover", "exited")
    fake = OffDocker(world.docker)
    world.runtime = dataclasses.replace(world.runtime, docker=fake.run)
    return fake


def test_an_app_switched_off_while_running_is_planned_off(world):
    switch_off(world)

    plan = world.plan()

    assert not plan.changes_nothing
    assert len(plan.offs) == 1


def test_off_stops_then_removes_every_container_of_the_project_and_nothing_else(world):
    off = switch_off(world)
    plan = world.plan()
    off.commands.clear()

    assert world.run(plan) == []

    assert off.commands == [
        ["docker", "compose", "-p", KEY, "stop"],
        ["docker", "compose", "-p", KEY, "rm", "-f"],
        ["docker", "compose", "-p", KEY, "ps", "--all", "--format", "json"],
    ]
    assert world.docker.rows == []
    assert world.plan().changes_nothing


def test_off_never_fetches_and_leaves_the_checkout_and_the_record(world, origin):
    sha = deploy(world, origin, FIRST)
    record = world.deployed()
    off = switch_off(world)
    world.runtime = dataclasses.replace(
        world.runtime, git=lambda *call: pytest.fail("git was asked")
    )

    assert world.run() == []

    assert [call[0] for call in off.compose_calls()[-3:]] == ["stop", "rm", "ps"]
    assert head_of(world.srv) == sha
    assert world.deployed() == record


@pytest.mark.parametrize("verb", ["stop", "rm"])
def test_a_failing_off_is_one_line_without_composes_output_and_stops_there(world, verb):
    off = switch_off(world)
    plan = world.plan()
    off.failing = verb

    [result] = world.run(plan)

    failure = result.cause

    assert f"`docker compose {verb}` of {KEY}" in failure
    assert SENTINEL not in failure
    assert ("rm" in {c[0] for c in off.compose_calls()}) == (verb == "rm")


@pytest.mark.parametrize(
    "record",
    ["not json", '{"tag": "v1", "sha": "abc", "time": "x"}', '{"tag": ' + f'"{FIRST}"' + "}"],
)
def test_a_record_that_is_no_deployment_cannot_be_planned(world, origin, record):
    origin.release(FIRST)
    (world.state / "deployed").mkdir(parents=True)
    (world.state / "deployed" / KEY).write_text(record)

    with pytest.raises(apps.AppError, match="is not a record of a deployment"):
        world.plan()


@pytest.mark.parametrize("second_web", [False, True], ids=["web only created", "web twice"])
def test_an_update_interrupted_after_part_of_the_containers_was_replaced_is_repaired(
    world, origin, docker, second_web
):
    deploy(world, origin, FIRST, {"compose.yaml": TWO_SERVICES})
    origin.release(SECOND, {"compose.yaml": TWO_SERVICES + "# second\n"})
    docker.interrupted_verb = "start"
    with pytest.raises(KeyboardInterrupt):
        world.run()
    docker.interrupted_verb = None
    docker.rows.clear()
    docker.put("web", "created")
    docker.put("worker", "running", "healthy")
    if second_web:
        docker.put("web", "exited")

    [planned] = world.plan().plans

    assert (planned.recorded_tag, planned.unfinished) == (FIRST, SECOND)
    [result] = world.run()
    assert isinstance(result, apps.AppOn)
    assert sorted(row["Service"] for row in docker.rows) == ["web", "worker"]
    assert world.deployed()["tag"] == SECOND


def test_a_contract_refusal_in_a_release_is_a_plan_refusal_before_anything_is_built(world, origin):
    origin.release(FIRST, {"compose.yaml": "services: {web: {image: x, profiles: [a]}}"})

    with pytest.raises(
        apps.AppError, match=r"compose\.yaml at v2026\.10\.22\.1: service web uses profiles"
    ):
        world.plan()

    assert world.docker.verbs == []


def test_a_record_that_cannot_be_read_cannot_be_planned(world, origin):
    origin.release(FIRST)
    (world.state / "deployed" / KEY).mkdir(parents=True)

    with pytest.raises(apps.AppError, match=r"services.hopin: cannot read .*\(Is a directory\)"):
        world.plan()


def test_a_record_that_cannot_be_written_ends_the_run_partial_after_health(world, origin):
    origin.release(FIRST)
    plan = world.plan()
    (world.state / "deployed").mkdir(parents=True)
    (world.state / "deployed" / KEY / "in the way").mkdir(parents=True)

    [result] = world.run(plan)

    failure = result.cause

    assert failure == f"could not record the deployment of {FIRST} (Is a directory)"


def test_the_default_runtime_records_with_the_clock_and_lives_under_home_srv(tmp_path):
    runtime = apps.AppRuntime.of(tmp_path / "home", tmp_path / "state")

    assert runtime.srv == tmp_path / "home" / "srv"
    assert runtime.now().utcoffset() is not None


PULL_ALWAYS = {"compose.yaml": COMPOSE.replace("build: .", "build: .\n    pull_policy: always")}
COVERED = {
    "compose.yaml": COMPOSE.replace("build: .", "build: .\n    volumes: ['data:/data']")
    + "volumes:\n  data: {}\n"
}


def test_an_image_volume_no_named_volume_covers_is_partial_before_create_with_the_record_kept(
    world, origin
):
    first = deploy(world, origin, FIRST)
    origin.release(SECOND)
    world.docker.image_volumes[KEY] = ["/data"]

    [result] = world.run()

    failure = result.cause

    assert failure == (
        f"services.hopin: image of service hopin at {SECOND} declares a volume that no named "
        "volume of the service covers (volumes); give it a named volume"
    )
    assert world.docker.verbs[-1] == "image inspect"
    assert world.deployed()["sha"] == first


def test_an_image_volume_a_named_volume_covers_starts(world, origin):
    world.docker.image_volumes[KEY] = ["/data"]
    origin.release(FIRST, COVERED)

    [result] = world.run()

    assert isinstance(result, apps.AppOn)
    assert world.deployed()["tag"] == FIRST


def test_a_service_with_pull_policy_always_is_started_from_the_inspected_image(world, origin):
    origin.release(FIRST, PULL_ALWAYS)

    [result] = world.run()

    assert isinstance(result, apps.AppOn)

    verbs = world.docker.verbs
    assert "pull" not in verbs[verbs.index("image inspect") :]
    create = next(arguments for verb, arguments, _ in world.docker.calls if verb == "create")
    assert create == ("--no-build", "--pull", "never", "--remove-orphans")


def test_off_removes_a_one_off_container_that_rm_leaves_by_its_identifier_and_never_a_volume(world):
    off = switch_off(world)
    world.docker.put("oneoff", "running")
    off.survivors.add("oneoff")
    plan = world.plan()
    off.commands.clear()

    assert world.run(plan) == []

    assert ["docker", "rm", "-f", "id3"] in off.commands
    assert world.docker.rows == []


def test_a_container_that_survives_even_docker_rm_ends_the_off_partial_naming_service_and_state(
    world,
):
    off = switch_off(world)
    world.docker.put("stuck", "running")
    off.survivors.add("stuck")
    plan = world.plan()
    off.removal_by_identifier_works = False

    [result] = world.run(plan)

    failure = result.cause

    assert failure == f"could not remove every container of {KEY}, left: stuck running"


def test_a_failing_docker_rm_ends_the_off_partial_naming_service_and_state_and_withholds_output(
    world,
):
    off = switch_off(world)
    world.docker.put("stuck", "running")
    off.survivors.add("stuck")
    plan = world.plan()
    off.removal_by_identifier_exit = 5

    [result] = world.run(plan)

    failure = result.cause

    assert failure.startswith(f"could not remove every container of {KEY}, left: stuck running")
    assert "exited 5" in failure
    assert SENTINEL not in failure
