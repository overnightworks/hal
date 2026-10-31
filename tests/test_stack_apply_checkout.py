"""`hal apply --local` prints the live checkout against origin's `main` as one row (#612), in a
real git repository on the scripted boundaries of `tests/support/stack_apply.py`."""

import pytest
from support.git_support import FETCH_WRITES, advance, checkout_state, subjects
from support.stack_apply import (
    ENABLED,
    ZONE,
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    origin,  # noqa: F401 the fixture, requested by name below
    real_main,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    short,
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
    writing_environment,
)
from support.stack_plan_rows import detail_lines, find_row, plain

from hal.stack import checkout
from hal.stack.apply import ApplyExit
from hal.stack.plan_rows import CHECKOUT, CheckoutEvent

OLD_TEXT = (
    "fetched main from",
    "live checkout current (",
    "wait on origin",
    "their files, by what",
)


def test_an_equal_main_is_one_current_row_before_the_plan(switch, real_main, origin):  # noqa: F811
    exit_code, out, _ = switch(git=checkout.run_git)

    assert exit_code == 0
    assert find_row(out, CHECKOUT, CheckoutEvent.CURRENT, f"{short(real_main)} · origin/main")
    assert plain(out).index("  ✓ checkout") < plain(out).index("the plan")
    assert not [text for text in OLD_TEXT if text in out]


ENVIRONMENTS = ("present", "missing", "differing")


@pytest.mark.parametrize("environment", ENVIRONMENTS)
@pytest.mark.parametrize("waiting", [1, 3])
def test_a_behind_checkout_is_refused_naming_hal_update_and_writes_nothing(
    switch, scripted, real_main, origin, repository, waiting, environment  # noqa: F811
):  # fmt: skip
    """#783 F2: behind origin, whatever `.env` holds, the apply names the waiting commits and
    `hal update`; no `.env` is written or refused, nothing is planned or asked."""
    advance(origin, *subjects(*(f"waiting {n}" for n in range(waiting))))
    if environment == "missing":
        (repository / ".env").unlink()
    if environment == "differing":
        (repository / ".env").write_text("EDGE_DOMAIN=old.invalid\n")
    env_before = (repository / ".env").read_bytes() if environment != "missing" else None
    before = checkout_state(real_main, (*FETCH_WRITES, ".env"))

    exit_code, out, err = switch(git=checkout.run_git, ensure_environment=writing_environment())

    assert exit_code == ApplyExit.CANNOT_PLAN
    assert find_row(
        out, CHECKOUT, CheckoutEvent.BEHIND, f"origin/main {short(real_main, 'origin/main')}"
    )
    assert f"{waiting} behind" in plain(out)
    assert err.splitlines() == [
        f"error: {waiting} commit{'s' if waiting - 1 else ''} wait{'' if waiting - 1 else 's'}"
        " on origin main; nothing changed",
        "next: hal update",
    ]
    assert not detail_lines(out)
    assert "the plan" not in out and ".env" not in out
    assert scripted.calls == []
    assert checkout_state(real_main, (*FETCH_WRITES, ".env")) == before
    if environment == "missing":
        assert not (repository / ".env").exists()
    else:
        assert (repository / ".env").read_bytes() == env_before


def test_a_current_checkout_prints_the_environment_row_before_its_own(
    switch, real_main, origin, repository  # noqa: F811
):  # fmt: skip
    """#783 F1: current, a written `.env` is still announced before the checkout row."""
    (repository / ".env").unlink()

    exit_code, out, _ = switch(git=checkout.run_git, ensure_environment=writing_environment())

    assert exit_code == 0
    assert plain(out).index("  ✓ .env") < plain(out).index("  ✓ checkout")


@pytest.fixture
def unplannable_fleet(repository):  # noqa: F811
    """A fleet.yaml that cannot be planned, committed by `real_main` (request it first)."""
    other = "  other: {repo: {default_branch: master}, run: {enabled: maybe}}\n"
    (repository / "fleet.yaml").write_text(f"cloudflare:\n  zone: {ZONE}\n{ENABLED}{other}")


def test_a_current_checkout_still_prints_its_row_when_planning_then_refuses(
    unplannable_fleet, switch, real_main, origin  # noqa: F811
):  # fmt: skip
    exit_code, out, err = switch(git=checkout.run_git)

    assert exit_code == ApplyExit.CANNOT_PLAN
    assert "cannot plan, services.other.run.enabled: must be true or false" in err
    assert find_row(out, CHECKOUT, CheckoutEvent.CURRENT, f"{short(real_main)} · origin/main")
