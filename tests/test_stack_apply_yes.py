"""The yes of `hal apply` and the ends of its local guards (#620): the prompt counts the printed
change rows, only `yes` applies, and every refusal is one `error:` with an optional `next:`."""

import re
import subprocess
import sys
from dataclasses import dataclass

import pytest
from support.stack_apply import (
    DISABLED,
    ENABLED,
    KEYCLOAK_ENABLED,
    PROBE_ENABLED,
    TWO_SETUPS,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    docker_group,
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    missing_setup,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    realm_unit,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    start,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    switch_off,
    write_fleet,
    writing_environment,
)
from support.stack_apply_fakes import (
    ScriptedGit,
    Setup,
)
from support.stack_plan_legal_rows import ALL_LABELS, appkit_plan, legal_plan
from support.stack_plan_rows import (
    DIGEST_A,
    DIGEST_B,
    KEYCLOAK,
    NO_APPKIT,
    detail_lines,
    kept,
    plain,
    plan_of,
    unit_plan,
)

from hal.stack import checkout
from hal.stack.external import cli as external_cli
from hal.stack.legal_step import PageChange
from hal.stack.plan_rows import changes_in
from hal.stack.realm.reconcile import RealmAction, RealmPlan
from hal.stack.unit_plans import Action, ImageReference


@dataclass
class ForgetfulSetup(Setup):
    """A setup check that answers not set up once it has been asked `forgets_after` times."""

    forgets_after: int | None = None

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        asked_too_often = (
            self.forgets_after is not None and len(self.commands) >= self.forgets_after
        )
        if asked_too_often:
            self.commands.append(command)
            return subprocess.CompletedProcess(command, 1, "not set up again", "")
        return super().__call__(command)


@pytest.fixture
def setup_check() -> ForgetfulSetup:
    return ForgetfulSetup()


CHANGE_ROW = re.compile(r"^  [+~-] ", re.MULTILINE)


def lines_of(text: str) -> list[str]:
    return plain(text).splitlines()


@pytest.mark.parametrize(
    ("fleet", "prompt"),
    [(ENABLED, "apply 1 change"), (PROBE_ENABLED, "apply 2 changes")],
    ids=["one change", "two changes"],
)
def test_the_yes_counts_the_rows_the_plan_printed(switch, fleet, prompt, repository):  # noqa: F811
    write_fleet(repository, fleet)

    _, out, _ = switch()

    assert f"Type yes to {prompt}: " in plain(out)
    assert len(CHANGE_ROW.findall(plain(out))) == int(prompt.split()[1])


@pytest.mark.parametrize(
    ("parts", "count"),
    [
        pytest.param(
            {"appkit": appkit_plan(ALL_LABELS, ("old",))}, 1, id="appkit update with stale"
        ),
        pytest.param({"appkit": appkit_plan(stale=("old", "older"))}, 1, id="stale only"),
        pytest.param(
            {"legal": legal_plan({"a": PageChange.NEW, "b": PageChange.NEW})},
            1,
            id="a legal row of two pages",
        ),
        pytest.param(
            {
                "unit_plans": [
                    unit_plan(Action.ON),
                    unit_plan(Action.OFF),
                    unit_plan(Action.STAYS_STOPPED),
                ]
            },
            2,
            id="stays stopped is no change",
        ),
        pytest.param(
            {
                "images": (
                    kept(ImageReference(KEYCLOAK, DIGEST_A), ImageReference(KEYCLOAK, DIGEST_B)),
                ),
                "realm": RealmPlan(RealmAction.UNREADABLE, error="broke"),
                "appkit": NO_APPKIT,
            },
            0,
            id="needs-you rows are no change",
        ),
    ],
)
def test_the_count_is_the_number_of_printed_change_rows(parts, count):
    assert changes_in(plan_of(**parts)) == count


@pytest.mark.parametrize("answer", ["no", "", "Yes", "y", " yes", "yes please"])
def test_an_answer_but_the_exact_yes_is_declined_in_one_error_and_changes_nothing(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    answer,
):
    exit_code, _, err = switch(answer)

    assert (exit_code, lines_of(err)) == (1, ["error: aborted, nothing changed"])
    assert scripted.changing_verbs() == []


def test_a_closed_stdin_at_the_prompt_is_a_no(switch, scripted):  # noqa: F811
    exit_code, _, err = switch(while_prompt_waits=lambda: sys.stdin.truncate(0))

    assert (exit_code, lines_of(err)) == (1, ["error: aborted, nothing changed"])
    assert scripted.changing_verbs() == []


def test_a_declined_plan_after_a_setup_names_the_setup_that_ran(switch, missing_setup):  # noqa: F811
    exit_code, _, err = switch("yes\nno")

    assert (exit_code, lines_of(err)) == (
        1,
        ["error: aborted, setup of step-ca completed; nothing switched"],
    )


def test_no_line_of_a_run_starts_with_the_old_sender_or_names_the_edge_command(
    switch,  # noqa: F811
    repository,  # noqa: F811
):
    out = ""
    for fleet in (ENABLED, ENABLED, DISABLED):
        write_fleet(repository, fleet)
        out += "".join(switch()[1:])

    assert not re.search(r"\bedge (apply|stop|start)\b", out)


def test_nothing_to_change_ends_in_the_done_verdict_with_the_run_time(
    switch,  # noqa: F811
    repository,  # noqa: F811
    ingress,  # noqa: F811
):
    write_fleet(repository, DISABLED)
    times = iter([100.0, 121.4])

    exit_code, out, err = switch(clock=lambda: next(times))

    assert (exit_code, err) == (0, "")
    assert "✓ nothing to change · units and apps checked · 21s" in plain(out)
    assert "Type yes" not in out


@pytest.mark.usefixtures("realm_unit")
def test_a_plan_that_only_cannot_read_the_realm_asks_nothing_and_refuses(
    switch,  # noqa: F811
    scripted,  # noqa: F811
):
    scripted.failing_verb = "run"  # the observer reads the realm through `compose run`

    exit_code, out, err = switch()

    assert exit_code == 1
    assert "Type yes" not in out
    assert "the plan" not in out
    assert "realm skipped" in plain(out)
    assert lines_of(err) == [
        "error: realm: Keycloak could not be read; not checked "
        "(the realm observer failed (`docker compose run` exited 1: last line))",
        "next: hal apply",
    ]
    assert scripted.changing_verbs() == ["run"]  # only the failed realm read


@pytest.mark.usefixtures("realm_unit")
def test_an_unreadable_realm_beside_another_change_is_skipped_after_the_one_yes(
    switch,  # noqa: F811
    repository,  # noqa: F811
    scripted,  # noqa: F811
):
    write_fleet(repository, KEYCLOAK_ENABLED + ENABLED.removeprefix("services:\n"))
    scripted.failing_verb = "run"

    exit_code, out, err = switch()

    assert exit_code == 1
    assert plain(out).count("Type yes") == 1
    assert re.search(r"^  ! keycloak +realm skipped +the realm observer failed", plain(out), re.M)
    assert "step-ca is on" not in out
    assert lines_of(err) == ["error: partial, keycloak realm skipped", "next: hal apply"]
    assert "up" in scripted.changing_verbs()


def test_a_dirty_tree_is_a_failed_checkout_row_with_its_paths_then_one_error(
    switch,  # noqa: F811
    scripted,  # noqa: F811
    scripted_git,  # noqa: F811
):
    scripted_git.status = b" M fleet.yaml\0?? dynamic/x.yml\0"

    exit_code, out, err = switch()

    assert exit_code == 2
    assert re.search(r"^  ✗ checkout +local changes +2 files$", plain(out), re.MULTILINE)
    assert detail_lines(out) == ["fleet.yaml", "dynamic/x.yml"]
    assert lines_of(err) == [
        "error: the live checkout has local changes, nothing changed",
        f"next: git -C {checkout.LIVE_CHECKOUT} status",
    ]
    assert scripted.calls == []


def test_external_apply_on_a_dirty_tree_prints_the_same_bytes_as_before(
    repository,  # noqa: F811
    home,  # noqa: F811
    capsys,
):
    git = ScriptedGit(status=b" M fleet.yaml\0?? dynamic/x.yml\0")

    exit_code = external_cli._refusal_off_clean_live_main(repository, home, git)

    assert exit_code == 2
    lines = capsys.readouterr().err.splitlines()
    assert [line.partition(": ")[2] for line in lines] == [
        "the live checkout has local changes, nothing changed; a change reaches it through a "
        "pull request and `hal update`:",
        "  fleet.yaml",
        "  dynamic/x.yml",
    ]


def test_a_written_environment_is_one_done_row_before_the_checkout_row(switch, repository):  # noqa: F811
    (repository / ".env").unlink()

    exit_code, out, _ = switch(ensure_environment=writing_environment(docker_group))

    shown = plain(out)
    assert exit_code == 0
    assert re.search(r"^  ✓ \.env +written +EDGE_DOMAIN=\S+ · DOCKER_GID=\d+$", shown, re.M)
    assert shown.index("  ✓ .env") < shown.index("  ✓ checkout")


def test_a_differing_environment_names_hal_apply_and_exits_2(switch, repository):  # noqa: F811
    (repository / ".env").write_text("")

    exit_code, _, err = switch(ensure_environment=writing_environment(docker_group))

    assert exit_code == 2
    assert lines_of(err)[0].endswith("delete it and `hal apply` writes it again")
    assert lines_of(err)[0].startswith("error: ")


def test_without_a_terminal_apply_refuses_in_one_error(switch, scripted):  # noqa: F811
    exit_code, _, err = switch(at_a_terminal=False)

    assert (exit_code, lines_of(err)) == (
        1,
        ["error: refused, stdin and stdout must be a terminal"],
    )
    assert scripted.calls == []


@pytest.mark.parametrize("answer", ["Yes", "y", "no", ""])
def test_the_start_prompt_accepts_only_the_exact_yes(start, scripted, state, answer):  # noqa: F811
    switch_off(state)

    exit_code, out, _ = start(answer)

    assert "Type yes to start step-ca: " in plain(out)
    assert exit_code == 1
    assert scripted.changing_verbs() == []


def test_a_setup_that_fails_is_one_error_and_next_hal_apply(switch, missing_setup, setup_run):  # noqa: F811
    setup_run.exit_code = 1

    exit_code, _, err = switch("yes\nyes")

    assert exit_code == 1
    assert lines_of(err) == [
        "error: `step-ca/init` failed (exit 1); nothing switched; keys may already exist",
        "next: hal apply",
    ]


def test_units_still_not_set_up_after_their_setups_ran_end_in_one_error(
    switch,  # noqa: F811
    repository,  # noqa: F811
    missing_setup: ForgetfulSetup,  # noqa: F811
    setup_run,  # noqa: F811
    scripted,  # noqa: F811
):
    write_fleet(repository, TWO_SETUPS)
    missing_setup.forgets_after = 4  # two checks asking, two checks after each setup ran

    exit_code, _, err = switch("yes\nyes")

    assert exit_code == 1
    assert lines_of(err) == [
        "error: step-ca is not set up after the setups ran; nothing switched; "
        "run `step-ca/init` first; not set up again; "
        "keycloak is not set up after the setups ran; nothing switched; "
        "run `keycloak/init` first; not set up again",
        "next: hal apply",
    ]
    assert scripted.changing_verbs() == []
