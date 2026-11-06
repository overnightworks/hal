"""The publish of `hal apply` reads hal's tunnel once: its plan and its closing host check
evaluate the same id, though the machine's tunnel config changes in between."""

from pathlib import Path

from support.stack_external import (
    CHANGING_PLAN,
    fake_tofu,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    live_checkout,  # noqa: F401 the fixture, requested by name below
    publish_on_stand_in,
)

from hal.stack.external import apply as external_apply
from hal.stack.external import cli as external_cli
from hal.stack.external import cloudflare_read, tofu


def test_the_plan_and_the_closing_check_use_the_tunnel_read_once(
    home,  # noqa: F811
    fake_tofu,  # noqa: F811
    live_checkout,  # noqa: F811
    monkeypatch,
):
    config = Path("/scenario/cloudflared/config.yml")
    answers = iter(
        (
            cloudflare_read.OwnTunnel("first-id", config),
            cloudflare_read.OwnTunnel("second-id", config),
        )
    )
    checked: list[str] = []

    def closing_check(_home, *, own_tunnel):
        checked.append(own_tunnel().id)
        return 0

    fake_tofu.configure(**CHANGING_PLAN)
    monkeypatch.setattr(tofu, "PROJECT_ROOT", live_checkout)
    monkeypatch.setattr(external_apply, "refusal_without_terminal", lambda: None)
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    monkeypatch.setattr(external_cli, "check_command", closing_check)

    publish_on_stand_in(home, live_checkout, own_tunnel=lambda: next(answers))

    assert "-var=tunnel_id=first-id" in fake_tofu.call("plan")["argv"]
    assert checked == ["first-id"]
