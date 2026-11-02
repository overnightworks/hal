"""The emergency barrier covers every host a unit declares in the catalog (#325): `hal stop`,
`hal start` and `hal apply --local` over the scripted Compose and Traefik of the stack tests."""

from pathlib import Path
from types import SimpleNamespace

import pytest
from support.hal_stack_commands import (
    applying,  # noqa: F401 the fixture, requested by name below
    fakes,  # noqa: F401 the fixture, requested by name below
    hal,  # noqa: F401 the fixture, requested by name below
    system_commands,  # noqa: F401 the autouse fixture of the stack tests
    systemd,  # noqa: F401 the fixture, requested by `fakes`
)
from support.stack_apply import (
    PROBE_ENABLED,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    put_probe_in_b,
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch_off,
    write_fleet,
)
from support.stack_apply_publish import (
    fake_tofu,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    world,  # noqa: F401 the fixture, requested by name below
)
from support.stack_external import (
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
)
from support.stack_global_stop import hosts_asked  # noqa: F401 the fixture, requested by `fakes`
from support.stack_plan_rows import find_row

from hal.grammar import ExitCode
from hal.stack.result_rows import ResultEvent

APEX_HOST = "probe.test"  # EDGE_DOMAIN as the scripted Compose gives traefik
APEX = "    hosts: [{name: '@', exposure: public, reason: a public page}]\n"


def declare_apex(checkout: Path, *, enabled: bool) -> None:
    """`probe` declares the apex of the zone, enabled or not."""
    fleet = PROBE_ENABLED.replace(
        "probe:\n    run: {enabled: true}", f"probe:\n    run: {{enabled: {enabled}}}"
    )
    write_fleet(checkout, "cloudflare: {zone: edge-fixture.invalid}\n" + fleet.lower() + APEX)


def barred_at_the_apex(checkout: Path) -> bool:
    barrier_file = checkout / "dynamic" / "switch-probe.yml"
    return barrier_file.exists() and "switch-probe-_apex" in barrier_file.read_text()


@pytest.fixture
def stack(fakes, hal):  # noqa: F811
    """The stack's scripted boundaries and the `hal` door over them."""
    return SimpleNamespace(fakes=fakes, hal=hal)


@pytest.fixture
def local_apply(core_files, hal, repository, applying):  # noqa: F811
    """`hal apply --local` over a running core, in the checkout whose fleet the test writes."""
    return lambda: hal("apply", "--local", answers=("yes",)), repository, applying.state


@pytest.mark.parametrize(
    ("enabled", "situation", "line", "barred"),
    [
        pytest.param(True, "A", "switched off", True, id="B4 running"),
        pytest.param(False, "A", "switched off", True, id="B4 disabled but running"),
        pytest.param(False, "gone", "nothing of it runs", False, id="B5"),
        pytest.param(True, "B", "barrier back", True, id="B6 repair"),
    ],
)
def test_stop_bars_the_apex_a_unit_declares_and_proves_it(stack, enabled, situation, line, barred):
    """#325 B4-B6: a declared host is barred enabled or not, and a lost file is put back."""
    declare_apex(stack.fakes.repository, enabled=enabled)
    stack.fakes.scripted.containers = {"hello": "running" if situation == "A" else "exited"}
    if situation == "B":
        put_probe_in_b(stack.fakes.scripted, stack.fakes.state, stack.fakes.ingress)

    result = stack.hal("stop", "probe", answers=("",))

    assert line in result.text
    assert barred_at_the_apex(stack.fakes.repository) is barred
    assert (APEX_HOST in stack.fakes.hosts_asked) is barred


def test_start_removes_the_apex_barrier_and_proves_the_apex_unmarked(stack):
    """#325 B9: after `yes` the barrier is gone and the apex answers without the mark."""
    declare_apex(stack.fakes.repository, enabled=True)
    put_probe_in_b(stack.fakes.scripted, stack.fakes.state, stack.fakes.ingress)
    stack.hal("stop", "probe", answers=("",))
    stack.fakes.hosts_asked.clear()

    result = stack.hal("start", "probe", answers=("yes",))

    assert result.exit_code == ExitCode.OK
    assert not barred_at_the_apex(stack.fakes.repository)
    assert APEX_HOST in stack.fakes.hosts_asked


def test_stop_refuses_to_plan_when_another_entry_declares_a_malformed_host(stack):
    """#325 B10: the key of the malformed host is named, as a malformed `run` is today."""
    declare_apex(stack.fakes.repository, enabled=True)
    text = (stack.fakes.repository / "fleet.yaml").read_text()
    write_fleet(
        stack.fakes.repository,
        text.replace("setup: step-ca/init}", "setup: step-ca/init}\n    hosts: [{name: Bad_Name}]"),
    )

    result = stack.hal("stop", "probe", answers=("",))

    assert result.exit_code == ExitCode.FAILURE
    assert "cannot plan, services.step-ca.hosts[0].name:" in result.err


def test_apply_local_proves_the_apex_barrier_of_a_switched_off_unit_again(local_apply):
    """#325 B8: `hal apply --local` re-renders and proves the barrier, the declared apex too."""
    apply_local, checkout, state_directory = local_apply
    declare_apex(checkout, enabled=False)
    switch_off(state_directory, unit="probe")

    result = apply_local()

    assert find_row(result.out, "traefik", ResultEvent.RECREATED, "barriers proven")
    assert barred_at_the_apex(checkout)
