"""The live smoke command (`agent-service/live_smoke.py`, #221): the report, the cells and the
no-secret rule against a scripted docker. The command against a running service is driven by
probe/agent-service/unit.py (cell U16) and by the operator.
"""

import json
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "agent-service"))

import live_smoke  # noqa: E402
from device_sign_in import SignInFailed  # noqa: E402
from live_smoke import Cell, LiveSmokeFailed, Report, Verdict  # noqa: E402
from smoke import served_line  # noqa: E402
from support.live_smoke_fakes import (  # noqa: E402
    GATEWAY,
    KNOWN,
    LITELLM_GATEWAY,
    PAID_OUTPUT,
    SERVED_LINE,
    TOKENS,
    FakeProcess,
    FakeStack,
    completed,
    healthy_service,
)

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhIn0.c2lnbmF0dXJl"

# --- the report -------------------------------------------------------------------------------


def test_the_report_removes_every_known_secret_from_a_line():
    printed: list[str] = []
    report = Report(KNOWN.values(), out=printed.append)

    report.add(Cell("L2", Verdict.HELD, f"the answer held {TOKENS.person} and {KNOWN.login_token}"))

    assert printed == ["L2 held: the answer held [secret] and [secret]"]


def test_one_failed_cell_fails_the_run_and_an_observation_does_not():
    report = Report([], out=lambda _: None)
    report.add(Cell("L4", Verdict.OBSERVED, "x"), Cell("L2", Verdict.HELD, "x"))
    assert not report.failed()

    report.add(Cell("L6", Verdict.FAILED, "x"))
    assert report.failed()


def started(*lines: str) -> str:
    return "".join(f"{line}\n" for line in ("event: run_started", SERVED_LINE, *lines))


@pytest.mark.parametrize(
    ("returncode", "output", "paid", "admitted"),
    [
        (0, started("event: assistant_text", "ok", "event: succeeded", "ok"), True, True),
        (0, started("event: succeeded", ""), False, True),
        (0, started("event: assistant_text", "", "event: succeeded"), False, True),
        (0, started("event: assistant_text", "   ", "event: succeeded", " "), False, True),
        (1, started("event: failed", "provider_error: x"), False, True),
        (1, "refused with 401 unauthorized: expired\n", False, False),
    ],
)
def test_the_paid_turn_holds_only_on_succeeded_and_admission_on_run_started(
    returncode, output, paid, admitted
):
    l2, l3 = live_smoke.turn_cells(returncode, output, KNOWN)

    assert (l2.verdict is Verdict.HELD, l3.verdict is Verdict.HELD) == (paid, admitted)
    assert ("unauthorized" in l2.figure) == ("401" in output)


def test_l3_holds_when_the_run_started_names_a_listed_model_on_route_cli_and_shows_both():
    _, l3 = live_smoke.turn_cells(0, started(), KNOWN)

    assert l3.verdict is Verdict.HELD
    assert "anthropic/opus" in l3.figure
    assert "cli" in l3.figure


@pytest.mark.parametrize(
    "route_line",
    [
        "served by  on route cli",
        "served by claude/opus on route cli",
        "served by anthropic/fable on route cli",
        "served by anthropic/opus on route api",
        "served by anthropic/opus on route ",
        None,
    ],
    ids=["no model", "old name", "unlisted model", "route api", "no route", "no line"],
)
def test_l3_fails_on_a_missing_or_unlisted_model_or_a_route_other_than_cli(route_line):
    lines = ["event: run_started", *([route_line] if route_line else []), "event: succeeded"]

    _, l3 = live_smoke.turn_cells(0, "\n".join(lines) + "\n", KNOWN)

    assert l3.verdict is Verdict.FAILED


@pytest.mark.parametrize(
    ("served", "empty"),
    [
        ("served by  on route cli", "no model"),
        ("served by anthropic/opus on route ", "no route"),
        ("served by  on route ", "no model and no route"),
        ("", "no served-by line"),
    ],
)
def test_l3_names_which_field_of_the_served_line_is_empty(served, empty):
    output = f"event: run_started\n{served}\nevent: succeeded\n"

    _, l3 = live_smoke.turn_cells(0, output, KNOWN)

    assert l3.verdict is Verdict.FAILED
    assert l3.figure == f"run_started names {empty}"


def test_l3_fails_when_only_the_answer_text_looks_like_the_served_line():
    output = f"event: run_started\n{served_line('', 'cli')}\nevent: assistant_text\n{SERVED_LINE}\n"

    _, l3 = live_smoke.turn_cells(0, output, KNOWN)

    assert l3.verdict is Verdict.FAILED


def test_l3_fails_when_the_answer_text_repeats_the_run_started_record_with_a_model():
    output = (
        f"event: run_started\n{served_line('', 'cli')}\nevent: assistant_text\n"
        f"event: run_started\n{SERVED_LINE}\nevent: succeeded\n"
    )

    _, l3 = live_smoke.turn_cells(0, output, KNOWN)

    assert l3.verdict is Verdict.FAILED


def test_l3_holds_and_l2_fails_when_model_and_route_are_seen_but_no_text_comes():
    l2, l3 = live_smoke.turn_cells(0, started("event: succeeded"), KNOWN)

    assert (l2.verdict, l3.verdict) == (Verdict.FAILED, Verdict.HELD)


def test_the_route_line_is_no_part_of_the_answer_text_l2_judges():
    assert live_smoke.other_lines(f"event: run_started\n{SERVED_LINE}\nok\n") == "ok"


def test_a_forbidden_refusal_names_the_membership_and_the_token_binding():
    l2, _ = live_smoke.turn_cells(1, "refused with 403 forbidden: no\n", KNOWN)

    assert f"/apps/{live_smoke.CLIENT}" in l2.figure
    assert "azp" in l2.figure


def test_a_not_enabled_refusal_names_the_subscription_groups_of_the_service_toml():
    l2, _ = live_smoke.turn_cells(1, "refused with 403 not_enabled: no\n", KNOWN)

    service = tomllib.loads((ROOT / "agent-service/service.toml").read_text(encoding="utf-8"))
    assert service["identity"]["subscription_groups"]
    assert all(group in l2.figure for group in service["identity"]["subscription_groups"])


@pytest.mark.parametrize("code", ["forbidden", "not_enabled"])
def test_an_answer_line_shaped_like_a_refusal_holds_and_gets_no_hint(code):
    answer = f"refused with 403 {code}: no"
    output = f"event: run_started\nevent: assistant_text\n{answer}\nevent: succeeded\n"

    l2, _ = live_smoke.turn_cells(0, output, KNOWN)

    assert l2.verdict is Verdict.HELD
    assert "/apps/" not in l2.figure
    assert "subscription" not in l2.figure


# --- the service, against a scripted docker ---------------------------------------------------


def held_cancel() -> FakeProcess:
    return FakeProcess(["event: run_started\n", "holding the stream open 3 s\n", "closing\n"])


def run_smoke_cells(stack: FakeStack) -> list[Cell]:
    report = Report(KNOWN.values(), out=lambda _: None)
    live_smoke.smoke_cells(stack, KNOWN, report, pause=lambda _: None)
    return report.cells


def test_a_clean_run_holds_l2_l3_l6_l7_and_l9_and_only_observes_l4():
    stack = FakeStack(answer=healthy_service, cancelling=held_cancel())

    cells = {cell.name.split()[0]: cell for cell in run_smoke_cells(stack)}

    held = [cells[name].verdict for name in ("L2", "L3", "L6", "L7", "L9")]
    assert held == [Verdict.HELD] * 5
    assert cells["L4"].verdict is Verdict.OBSERVED
    assert "idle memory.current 1234" in cells["L7"].figure


def test_the_live_smoke_has_no_offer_cell_and_asks_no_offer():
    stack = FakeStack(answer=healthy_service, cancelling=held_cancel())

    cells = run_smoke_cells(stack)

    assert not any(cell.name.startswith("L8") for cell in cells)
    assert not any("--offer" in command for command in asked_commands(stack))


def paid_answering(output: str, returncode: int = 0, stderr: str = ""):
    def answer(command):
        if "agent-smoke" in command:
            return completed(output, returncode=returncode, stderr=stderr)
        return healthy_service(command)

    return answer


def smoke_cell(prefix: str, output: str, returncode: int = 0, stderr: str = "") -> Cell:
    stack = FakeStack(answer=paid_answering(output, returncode, stderr), cancelling=held_cancel())
    return next(cell for cell in run_smoke_cells(stack) if cell.name.startswith(prefix))


def test_a_jwt_only_in_the_paid_stderr_fails_l9():
    cell = smoke_cell("L9", PAID_OUTPUT, stderr=JWT)

    assert cell.verdict is Verdict.FAILED


def test_a_secret_only_in_the_paid_stderr_fails_l6():
    cell = smoke_cell("L6", PAID_OUTPUT, stderr=TOKENS.person)

    assert cell.verdict is Verdict.FAILED


def test_the_tokens_go_to_the_smoke_on_stdin_and_on_no_command_line():
    stack = FakeStack(answer=healthy_service, cancelling=held_cancel())

    run_smoke_cells(stack)

    commands = " ".join(" ".join(command) for command in stack.asked)
    assert all(secret not in commands for secret in KNOWN.values())
    assert stack.cancelling.stdin.closed


def test_a_service_that_never_listens_fails_the_recreate_and_goes_no_further():
    def silent(command):
        return completed("starting\n") if "logs" in command else completed()

    stack = FakeStack(answer=silent)

    cells = run_smoke_cells(stack)

    assert [(cell.name, cell.verdict) for cell in cells] == [("recreate", Verdict.FAILED)]
    assert not any("agent-smoke" in command for command in stack.asked)


@pytest.mark.parametrize("place", ["docker inspect", "logs", "smoke"])
def test_a_secret_in_any_searched_place_fails_l6_and_names_the_place(place):
    def leaking(command):
        if place == "docker inspect" and "inspect" in command:
            return completed(f'"Env": ["X={KNOWN.client_secret}"]')
        if place == "logs" and "logs" in command:
            return completed(f"token {TOKENS.workload}")
        if "ps" in command:
            return completed("container-id\n")
        return completed("")

    stack = FakeStack(answer=leaking)
    smoke_output = f"oops {KNOWN.login_token}" if place == "smoke" else ""

    cell, _ = live_smoke.leak_cells(stack, KNOWN, smoke_output)

    assert cell.verdict is Verdict.FAILED
    searched = {"docker inspect": "docker inspect", "logs": "the service log", "smoke": "the smoke"}
    assert f"{searched[place]} 1 (0)" in cell.figure.replace(" output", "")
    assert all(secret not in cell.figure for secret in KNOWN.values())


@pytest.mark.parametrize("place", ["docker inspect", "logs", "smoke"])
def test_a_jwt_shaped_string_in_any_searched_place_fails_l9_only(place):
    """L9, cell 10: a JWT in any searched place fails L9 only."""

    def leaking(command):
        if place == "docker inspect" and "inspect" in command:
            return completed(f'"Env": ["X={JWT}"]')
        if place == "logs" and "logs" in command:
            return completed(f"Authorization: Bearer {JWT}")
        if "ps" in command:
            return completed("container-id\n")
        return completed("")

    stack = FakeStack(answer=leaking)

    l6, l9 = live_smoke.leak_cells(stack, KNOWN, JWT if place == "smoke" else "")

    assert (l6.verdict, l9.verdict) == (Verdict.HELD, Verdict.FAILED)
    assert JWT not in l9.figure


def test_two_dotted_parts_are_no_jwt():
    """L9, cell 10: two dotted parts are no JWT shape."""
    _, l9 = live_smoke.leak_cells(FakeStack(answer=healthy_service), KNOWN, "eyJhbGciOiJ.eyJzdWI")

    assert l9.verdict is Verdict.HELD


def test_a_search_that_could_not_run_prints_sample_failed_never_zero():
    def broken(command):
        return completed("", returncode=1)

    cell, _ = live_smoke.leak_cells(FakeStack(answer=broken), KNOWN, "")

    assert cell.verdict is Verdict.FAILED
    assert "docker inspect SAMPLE FAILED" in cell.figure
    assert "the service log SAMPLE FAILED" in cell.figure


def test_a_cli_count_that_could_not_be_read_prints_sample_failed():
    stack = FakeStack(answer=lambda _: completed("not a number", returncode=0))

    assert live_smoke.cli_processes(stack) == "SAMPLE FAILED"


def with_leftover(command: list[str]) -> subprocess.CompletedProcess:
    if command[:2] == ["docker", "ps"]:
        return completed("leftover\n")
    return healthy_service(command)


def asked_commands(stack: FakeStack) -> list[str]:
    return [" ".join(command) for command in stack.asked]


@pytest.mark.parametrize("secret", KNOWN.values())
def test_a_secret_across_the_cut_of_the_paid_answer_leaves_no_beginning(secret):
    output = f"event: run_started\nevent: succeeded\n{'x' * 290}{secret}\n"

    l2, _ = live_smoke.turn_cells(0, output, KNOWN)

    assert secret[:8] not in l2.figure


@pytest.mark.parametrize("secret", KNOWN.values())
def test_a_secret_across_the_cut_of_the_cancelled_answer_leaves_no_beginning(secret):
    lines = ["event: run_started\n", "holding the stream open 3 s\n", f"{'x' * 290}{secret}\n"]
    stack = FakeStack(answer=healthy_service, cancelling=FakeProcess(lines))

    turn = live_smoke.cancelled_turn(stack, TOKENS)
    (cell,) = live_smoke.cancel_cells(stack, "0", turn, KNOWN, pause=lambda _: None)

    assert secret[:8] not in cell.figure


def test_a_log_that_failed_to_be_read_does_not_make_the_recreate_ready():
    def failing_logs(command):
        if "logs" in command:
            return completed("Uvicorn running on http://0.0.0.0:8080\n", returncode=1)
        return healthy_service(command)

    stack = FakeStack(answer=failing_logs)

    cells = run_smoke_cells(stack)

    assert [(cell.name, cell.verdict) for cell in cells] == [("recreate", Verdict.FAILED)]


@pytest.mark.parametrize("failing", ["ps", "rm"])
def test_a_cleanup_that_failed_is_reported_without_the_secret(failing):
    secret = KNOWN.client_secret

    def failing_cleanup(command):
        if command[:2] == ["docker", "ps"]:
            if failing == "ps":
                return completed("", returncode=1, stderr=f"no daemon {secret}\n")
            return completed("leftover\n")
        if command[:2] == ["docker", "rm"]:
            return completed("", returncode=1, stderr=f"busy {secret}\n")
        return healthy_service(command)

    stack = FakeStack(answer=failing_cleanup, cancelling=held_cancel())

    cells = [c for c in run_smoke_cells(stack) if c.name.startswith("cleanup")]

    assert len(cells) == 2  # the paid turn's and the cancelled turn's, each its own
    assert all(cell.verdict is Verdict.FAILED for cell in cells)
    assert all(f"docker {failing} exited 1" in cell.figure for cell in cells)
    assert all(secret[:8] not in cell.figure for cell in cells)


def test_a_network_inspect_that_is_not_json_fails_in_one_line():
    stack = FakeStack(answer=lambda _: completed("not json"))

    with pytest.raises(LiveSmokeFailed, match="gave no network"):
        live_smoke.inspect_network(stack, "network-id")


def test_a_failed_recreate_is_failed_even_when_the_old_container_still_listens():
    secret = KNOWN.client_secret

    def failing_up(command):
        if "up" in command:
            return completed("", returncode=1, stderr=f"first\n{'e' * 190}{secret}\n")
        return healthy_service(command)

    stack = FakeStack(answer=failing_up)

    cells = run_smoke_cells(stack)

    assert [(cell.name, cell.verdict) for cell in cells] == [("recreate", Verdict.FAILED)]
    assert "exited 1" in cells[0].figure
    assert secret[:8] not in cells[0].figure
    assert not any("agent-smoke" in command for command in stack.asked)


def test_a_log_that_could_not_be_read_prints_sample_failed_for_l4():
    def unreadable_since(command):
        if "--since" in command:
            return completed("", returncode=1)
        return healthy_service(command)

    stack = FakeStack(answer=unreadable_since, cancelling=held_cancel())

    cells = {cell.name.split()[0]: cell for cell in run_smoke_cells(stack)}

    assert "ERROR lines since (0) SAMPLE FAILED" in cells["L4"].figure
    assert cells["L4"].verdict is Verdict.OBSERVED


def test_a_paid_turn_the_host_stops_waiting_for_fails_l2_and_removes_its_container():
    def hanging(command):
        if "agent-smoke" in command and "--cancel" not in command:
            raise subprocess.TimeoutExpired(command, 1)
        return with_leftover(command)

    stack = FakeStack(answer=hanging, cancelling=held_cancel())

    cells = {cell.name.split()[0]: cell for cell in run_smoke_cells(stack)}

    assert cells["L2"].verdict is Verdict.FAILED
    assert "the host gave up" in cells["L2"].figure
    assert "docker rm -f leftover" in asked_commands(stack)


def test_an_interrupted_paid_turn_still_removes_its_container():
    def interrupted(command):
        if "agent-smoke" in command:
            raise KeyboardInterrupt
        return with_leftover(command)

    stack = FakeStack(answer=interrupted)

    with pytest.raises(KeyboardInterrupt):
        live_smoke.paid_turn(stack, TOKENS)

    assert "docker rm -f leftover" in asked_commands(stack)


def test_a_cancelled_turn_that_hangs_is_killed_at_the_deadline_and_its_container_removed():
    hanging = FakeProcess(["event: run_started\n"], hangs=True)
    stack = FakeStack(
        answer=with_leftover,
        cancelling=hanging,
    )

    turn = live_smoke.cancelled_turn(stack, TOKENS, seconds=0.05)

    assert hanging.killed
    assert "the host gave up after 0.05 s" in turn.output
    assert "docker rm -f leftover" in asked_commands(stack)


def test_an_interrupted_cancelled_turn_ends_its_child_and_removes_its_container():
    interrupted = FakeProcess(["event: run_started\n"], interrupted=True)
    stack = FakeStack(
        answer=with_leftover,
        cancelling=interrupted,
    )

    with pytest.raises(KeyboardInterrupt):
        live_smoke.cancelled_turn(stack, TOKENS)

    assert interrupted.terminated
    assert "docker rm -f leftover" in asked_commands(stack)


# --- L5, judged from what the container saw ---------------------------------------------------


REACH = {
    "docker0": "172.17.0.1", "internet": "172.31.251.1", "lan": "192.168.1.5",
    "agent-songmaker_free": "172.31.248.2", "agent-presentator_free": "172.31.249.2",
    "agent-hopin_free": "172.31.247.2",
    "mcp_free": "172.31.250.2", "egress_free": "172.31.252.2",
}  # fmt: skip
TARGETS = live_smoke.EgressTargets(
    provider="160.79.104.10", reach=REACH, agent_gateways=[], egress_gateways=[]
)


def test_the_targets_cover_every_network_the_resolved_service_joins_but_name_none_by_literal():
    """#351 F2 / E7: the targets follow the resolved service's networks, none named by literal."""

    def docker(command: list[str]) -> subprocess.CompletedProcess:
        if "config" in command:
            return healthy_service(command)
        if command[:3] == ["docker", "network", "ls"]:
            return completed("id-" + next(a for a in command if "network=" in a).rpartition("=")[2])
        subnets = {"mcp": "10.0.1.0/24", "agent-songmaker": "10.0.2.0/24"}
        key = command[3].removeprefix("id-")
        subnet = subnets.get(key, "10.0.3.0/24")
        gateway = subnet.replace("0/24", "1")
        config = [{"Subnet": subnet, "Gateway": gateway}]
        return completed(json.dumps([{"IPAM": {"Config": config}, "Containers": {}}]))

    targets = live_smoke.egress_targets(
        FakeStack(answer=docker),
        resolve_provider=lambda _: "160.79.104.10",
        discover_lan=lambda: "192.168.1.5",
    )

    assert {
        "mcp_free",
        "agent-songmaker_free",
        "agent-presentator_free",
        "agent-hopin_free",
    } <= set(targets.reach)
    assert "agent_free" not in targets.reach
    assert "10.0.1.1" in targets.agent_gateways
    assert targets.reach["mcp_free"] == "10.0.1.254"


def held_sighting() -> dict:
    refused = "ENETUNREACH"
    return {
        "public_tcp": {"1.1.1.1": refused, TARGETS.provider: refused},
        "defaults": [],
        "reach": dict.fromkeys(REACH, refused),
        "ipv6_interfaces": ["lo"],
        "ipv6_tcp": refused,
        "udp": {"443": refused, "53": refused},
        "outside": [],
        "gateway": [GATEWAY],
    }


def test_the_unreachable_world_holds_e6_to_e10():
    cells = live_smoke.judge_egress(TARGETS, held_sighting(), GATEWAY)

    assert [cell.name.split()[0] for cell in cells] == ["E6", "E7", "E8", "E9", "E10"]
    assert {cell.verdict for cell in cells} == {Verdict.HELD}


@pytest.mark.parametrize(
    ("cell", "change"),
    [
        ("E6", lambda seen: seen["public_tcp"].update({"1.1.1.1": "ECONNREFUSED"})),
        ("E7", lambda seen: seen["reach"].update({"lan": "connected"})),
        ("E7", lambda seen: seen.update(defaults=["eth0"])),
        ("E8", lambda seen: seen.update(ipv6_interfaces=["lo", "eth0"])),
        ("E9", lambda seen: seen["udp"].update({"53": "routable"})),
        ("E10", lambda seen: seen.update(outside=["93.184.216.34"])),
        ("E10", lambda seen: seen.update(gateway=["10.0.0.1"])),
    ],
)
def test_a_reachable_address_fails_exactly_its_cell(cell, change):
    seen = held_sighting()
    change(seen)

    cells = live_smoke.judge_egress(TARGETS, seen, GATEWAY)

    assert {c.name.split()[0] for c in cells if c.verdict is Verdict.FAILED} == {cell}


def test_a_gateway_on_a_service_network_fails_e7():
    targets = live_smoke.EgressTargets(**{**TARGETS.__dict__, "agent_gateways": ["172.31.250.1"]})

    cells = live_smoke.judge_egress(targets, held_sighting(), GATEWAY)

    assert [c.name.split()[0] for c in cells if c.verdict is Verdict.FAILED] == ["E7"]


ENTRYPOINTS = [GATEWAY, LITELLM_GATEWAY]


@pytest.mark.parametrize(
    ("listening", "held"),
    [
        (
            {
                "tcp": [f"{LITELLM_GATEWAY}:443", f"{GATEWAY}:443", "127.0.0.11:40001"],
                "udp": ["127.0.0.11:50002"],
            },
            True,
        ),
        ({"tcp": [f"{GATEWAY}:443"], "udp": []}, False),
        ({"tcp": [f"{LITELLM_GATEWAY}:443"], "udp": []}, False),
        ({"tcp": [f"{GATEWAY}:443", f"{LITELLM_GATEWAY}:443", "0.0.0.0:8080"], "udp": []}, False),
        ({"tcp": [f"{GATEWAY}:443", f"{LITELLM_GATEWAY}:443"], "udp": [f"{GATEWAY}:53"]}, False),
        ({"tcp": [f"{GATEWAY}:443", f"{LITELLM_GATEWAY}:443", "[::]:443"], "udp": []}, False),
        ({"tcp": [f"{GATEWAY}:443", f"{GATEWAY}:443"], "udp": []}, False),
        ({"tcp": ["127.0.0.11:40001"], "udp": []}, False),
    ],
)
def test_only_each_entrypoints_443_and_the_embedded_resolver_may_listen(listening, held):
    assert (live_smoke.judge_listeners(listening, ENTRYPOINTS).verdict is Verdict.HELD) is held


def test_the_unused_address_is_the_last_one_no_member_holds():
    network = {
        "IPAM": {"Config": [{"Subnet": "172.31.250.0/24", "Gateway": "172.31.250.1"}]},
        "Containers": {"a": {"IPv4Address": "172.31.250.254/24"}},
    }

    assert live_smoke.unused_address(network) == "172.31.250.253"
    assert live_smoke.gateways_of(network) == ["172.31.250.1"]
    assert live_smoke.gateways_of({"IPAM": {"Config": [{"Subnet": "10.0.0.0/24"}]}}) == []


def test_the_stack_is_anchored_to_the_repository_and_names_what_compose_resolves():
    stack = FakeStack(answer=healthy_service)

    assert stack.compose_prefix[:5] == (
        "docker", "compose", "--project-directory", str(ROOT), "--file",
    )  # fmt: skip
    assert (stack.project, stack.gateway) == ("edge", GATEWAY)
    assert stack.entrypoint_addresses == ENTRYPOINTS


def test_a_compose_that_cannot_resolve_stops_the_run_with_its_last_line():
    def refusing(command):
        return completed(
            "", returncode=1, stderr="warning\nrequired variable EDGE_DOMAIN missing\n"
        )

    with pytest.raises(LiveSmokeFailed, match="config failed: required variable EDGE_DOMAIN"):
        FakeStack(answer=refusing).project  # noqa: B018


def test_the_listeners_probe_container_logs_to_none():
    """#384 U3"""
    stack = FakeStack(answer=healthy_service)

    live_smoke.listeners_cell(stack, "service-id")

    (probe,) = [command for command in stack.asked if command[:2] == ["docker", "run"]]
    assert probe[probe.index("--log-driver") + 1] == "none"


@pytest.mark.parametrize(
    ("failure", "code", "printed"),
    [
        (LiveSmokeFailed("the stack did not come up"), 1, "live smoke: the stack did not come up"),
        (SignInFailed("the realm refused"), 1, "live smoke: the realm refused"),
        (
            subprocess.TimeoutExpired("docker", 1),
            1,
            "live smoke: a docker command ran out of time",
        ),
        (KeyboardInterrupt(), 130, "live smoke: interrupted"),
    ],
)
def test_a_failed_live_run_ends_with_its_exit_code_and_its_line_on_standard_error(
    monkeypatch, capsys, failure, code, printed
):
    def failing(*_):
        raise failure

    monkeypatch.setattr(live_smoke, "read_secret", failing)

    assert live_smoke.main([]) == code
    captured = capsys.readouterr()
    assert captured.err.strip() == printed
    assert captured.out == ""
