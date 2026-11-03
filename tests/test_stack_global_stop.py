"""`hal offline` and `hal online` against a fake systemctl: no systemd, no tunnel, and a
`tmp_path` HOME so that no test touches the real switches."""

import subprocess
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

import pytest
import support.stack_global_stop as stack_global_stop_support
from support.stack_apply import (
    NOW,
    SWITCHED_OFF_AT,
    at_terminal,  # noqa: F401 the fixture, requested by name below
    switch_off,
)
from support.stack_apply_fakes import (
    PLAIN_NOT_FOUND,
    Ingress,
    InterruptedWaitForLock,
    ScriptedCompose,
)
from support.stack_global_stop import (
    FIRST_STOP,
    FakeSystemd,
)

from hal.stack import barrier, catalog, emergency, switches, tunnel

(
    home,
    ingress,
    marks,
    repository,
    start_all,
    stopped_tunnel,
    systemd,
) = (
    stack_global_stop_support.home,
    stack_global_stop_support.ingress,
    stack_global_stop_support.marks,
    stack_global_stop_support.repository,
    stack_global_stop_support.start_all,
    stack_global_stop_support.stopped_tunnel,
    stack_global_stop_support.systemd,
)  # fmt: skip


@pytest.fixture
def stop_all(marks, systemd, at_terminal, capsys) -> Callable[..., tuple[int, str]]:  # noqa: F811
    def run(typed_at_terminal: bool = False) -> tuple[int, str]:
        if typed_at_terminal:
            at_terminal("")
        exit_code = emergency.stop_all(marks, NOW, tunnel.Tunnel(run=systemd.run))
        captured = capsys.readouterr()
        return exit_code, captured.out + captured.err

    return run


def switch_off_probe(marks: switches.Switches, ingress: Ingress, repository: Path) -> None:
    """Unit `probe` switched off the way `hal stop probe` leaves it: marker and barrier file."""
    switch_off(marks.directory, unit="probe")
    config = ScriptedCompose().config
    unit = catalog.Unit("probe", enabled=True, setup=None)
    barrier.Barrier.of_unit(config, ("hello",), repository, unit, ingress.verifier).close()


# --- hal offline ---------------------------------------------------------------------------


def test_stop_all_records_the_switch_stops_the_tunnel_and_says_so(stop_all, marks, systemd):
    """#70 rule 2: record first, stop, report only the observed state."""
    exit_code, output = stop_all()

    assert exit_code == 0
    assert "the tunnel is stopped (since 18.10. 08:00); services keep running locally" in output
    assert marks.global_mark() is not None
    assert not systemd.active


def test_stop_all_without_a_terminal_never_waits_for_a_password(stop_all, systemd):
    """#70 rule 2.2 and rule 9: an agent's stop never waits for a password."""
    stop_all()

    stop_command = next(call for call in systemd.calls if "stop" in call)
    assert "--no-ask-password" in stop_command


def test_stop_all_at_a_terminal_lets_the_system_ask_for_the_password(stop_all, systemd):
    """#70 rule 2.2: at a terminal the system asks for the password."""
    stop_all(typed_at_terminal=True)

    stop_command = next(call for call in systemd.calls if "stop" in call)
    assert "--no-ask-password" not in stop_command


def test_a_refused_stop_is_partial_and_keeps_the_switch(stop_all, marks, systemd):
    """#70 rule 3: a refused stop is partial, exit 1, and the marker stays."""
    systemd.refuses_stop = True

    exit_code, output = stop_all()

    assert exit_code == 1
    assert (
        "partial: the global switch is recorded, but the tunnel still runs; "
        "`systemctl stop cloudflared`" in output
    )
    assert marks.global_mark() is not None


def test_a_missing_boot_drop_in_is_incomplete_though_the_tunnel_is_stopped(
    stop_all, marks, systemd
):
    """#70 rule 3: a missing boot drop-in is incomplete, exit 1."""
    systemd.drop_ins = []

    exit_code, output = stop_all()

    assert exit_code == 1
    assert "incomplete: a reboot would reopen the tunnel" in output
    assert "`hal setup`" in output
    assert "home-tools" not in output
    assert not systemd.active
    assert marks.global_mark() is not None


def test_a_repeated_stop_all_keeps_the_first_time(stop_all, marks):
    """#70 rule 1: a repeated stop keeps the first time."""
    marks.record_global(emergency.datetime.fromisoformat(FIRST_STOP))

    _, output = stop_all()

    assert "since 17.10. 22:10" in output


def test_stop_all_leaves_the_unit_switches_alone(stop_all, marks):
    """#70 rule 2: unit switches are not touched by stop --all."""
    switch_off(marks.directory, unit="probe")

    stop_all()

    assert marks.since("probe") == SWITCHED_OFF_AT


def test_the_global_switch_is_no_unit_marker(marks):
    """#70 rule 1: the global switch is its own fact, no unit name can fake it."""
    marks.record_global(NOW)

    assert marks.global_mark() is not None
    assert marks.mark("global-stop") is None


def test_stop_all_still_stops_the_tunnel_when_the_switch_cannot_be_recorded(
    stop_all, marks, systemd
):
    """#70 rule 2 and rule 3: a record failure never keeps the tunnel open."""
    marks.directory.mkdir(parents=True)
    (marks.directory / switches.GLOBAL_STOP_FILE).mkdir()

    exit_code, output = stop_all()

    assert exit_code == 1
    assert "could not be recorded" in output
    assert not systemd.active


def test_stop_all_reports_a_missing_systemctl_as_not_stopped(marks, capsys):
    """#70 rule 3: a stop that could not even be asked is partial with the stop hint."""

    def no_systemctl(_command):
        raise tunnel.TunnelError("cannot run systemctl (missing)")

    exit_code = emergency.stop_all(marks, NOW, tunnel.Tunnel(run=no_systemctl))

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "is not confirmed stopped" in err
    assert "`systemctl stop cloudflared`" in err
    assert marks.global_mark() is not None


def test_a_stop_that_times_out_but_left_the_tunnel_stopped_is_a_success(stop_all, marks, systemd):
    """#70 rule 2.3: success only once is-active says inactive, whatever the stop itself raised."""
    systemd.stop_times_out_after_stopping = True

    exit_code, output = stop_all()

    assert exit_code == 0
    assert "the tunnel is stopped" in output
    assert marks.global_mark() is not None


def test_an_unreadable_state_after_a_failed_record_is_not_called_stopped(marks, capsys):
    """#70 rule 2 and rule 3: an unseen state is reported as not confirmed, never as not stopped."""
    marks.directory.mkdir(parents=True)
    (marks.directory / switches.GLOBAL_STOP_FILE).mkdir()

    def no_systemctl(_command):
        raise tunnel.TunnelError("cannot run systemctl (missing)")

    exit_code = emergency.stop_all(marks, NOW, tunnel.Tunnel(run=no_systemctl))

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "could not be recorded" in err
    assert "is not confirmed stopped" in err
    assert "not stopped" not in err.replace("not confirmed stopped", "")


def test_a_lost_locked_record_is_partial_when_a_start_cleared_the_switch(marks, systemd, capsys):
    """#70 rule 2: if the locked record fails and the switch is gone, the stop is not a success."""
    busy = InterruptedWaitForLock(marks.directory)
    systemd.while_stopping = lambda: busy.clear_global(busy.global_mark())

    exit_code = emergency.stop_all(busy, NOW, tunnel.Tunnel(run=systemd.run))

    assert exit_code == 1
    assert "could not be recorded" in capsys.readouterr().err
    assert busy.global_mark() is None


def test_concurrent_first_stops_keep_the_earlier_time(marks):
    """#70 rule 1: a repeated stop keeps the first time, though the unlocked read missed it."""
    earlier = NOW.replace(year=NOW.year - 1)

    class ReadsStale(switches.Switches):
        def global_mark(self):
            mark = super().global_mark()
            if not self.read_once:
                self.read_once = True
                return None  # the read that happened before the other stop published
            return mark

    stale = ReadsStale(marks.directory)
    stale.read_once = False
    marks.record_global(earlier)

    stale.record_global(NOW)

    assert marks.global_mark().since == earlier.isoformat(timespec="seconds")


def test_stop_all_stops_the_tunnel_though_a_start_holds_the_lock(marks, systemd, capsys):
    """#70 rule 2: the stop never waits for switch.lock, which a start holds through `up`."""
    busy = InterruptedWaitForLock(marks.directory)  # every wait for the lock ends in Ctrl-C

    exit_code = emergency.stop_all(busy, NOW, tunnel.Tunnel(run=systemd.run))

    assert exit_code == 0
    assert not systemd.active
    assert busy.global_mark() is not None


def test_a_start_that_cleared_the_switch_during_the_stop_cannot_undo_it(stop_all, marks, systemd):
    """#70 rule 2 and P7: the switch is recorded again under the lock, after the stop."""
    systemd.while_stopping = lambda: marks.clear_global(marks.global_mark())

    exit_code, _ = stop_all()

    assert exit_code == 0
    assert marks.global_mark() is not None


def test_an_interrupt_at_the_password_prompt_of_the_stop_is_partial_with_the_sudo_hint(
    stop_all, marks, systemd
):
    """#70 rule 3: a Ctrl-C is reported as partial, exit 1, never as a traceback."""

    def ctrl_c():
        raise KeyboardInterrupt

    systemd.while_stopping = ctrl_c

    exit_code, output = stop_all()

    assert exit_code == 1
    assert (
        "partial: the global switch is recorded, but the tunnel still runs; "
        "`systemctl stop cloudflared`"
    ) in output
    assert marks.global_mark() is not None


def test_a_tunnel_of_another_unit_is_named_in_the_success_line(marks, systemd, capsys):
    """#70 rule 2 and Proof: the operator can tell a probe unit from cloudflared."""
    probe_tunnel = tunnel.Tunnel("edge-probe-tunnel-1.service", run=systemd.run)

    emergency.stop_all(marks, NOW, probe_tunnel)

    assert "unit edge-probe-tunnel-1.service" in capsys.readouterr().out


def test_a_failed_unit_counts_as_stopped():
    """#70 head ruling: `is-active` printing failed means the process is not running."""

    def failed(_command):
        return subprocess.CompletedProcess([], 3, "failed\n")

    assert tunnel.Tunnel(run=failed).is_inactive()


def test_an_unrelated_drop_in_does_not_certify_the_reboot_protection(stop_all, systemd):
    """#70 rule 3: only the exact boot drop-in name counts as the boot drop-in."""
    systemd.drop_ins = ["130-" + tunnel.BOOT_DROP_IN.removeprefix("30-")]

    exit_code, output = stop_all()

    assert exit_code == 1
    assert "incomplete: a reboot would reopen the tunnel" in output


# --- hal online ----------------------------------------------------------------------------


def test_start_all_reopens_the_tunnel_and_clears_only_the_global_switch(
    start_all, stopped_tunnel, marks, systemd, ingress, repository
):
    """#70 rule 4 and rule 6: start --all lifts only the global switch."""
    switch_off_probe(marks, ingress, repository)

    exit_code, output = start_all()

    assert exit_code == 0
    assert "the tunnel is open" in output
    assert systemd.active
    assert marks.global_mark() is None
    assert marks.since("probe") == SWITCHED_OFF_AT
    assert (repository / "dynamic" / "switch-probe.yml").exists()


def test_start_all_names_a_tunnel_of_another_unit(start_all, stopped_tunnel):
    """#70 rule 2 and Proof: the operator can tell a probe unit from cloudflared."""
    exit_code, output = start_all(unit="edge-probe-tunnel-1.service")

    assert exit_code == 0
    assert "the tunnel is open; unit edge-probe-tunnel-1.service" in output


def test_start_all_proves_each_standing_barrier_before_it_reopens(
    start_all, stopped_tunnel, marks, ingress, repository
):
    """#70 rule 4.1, rule 7 and rule 10: every barrier is proven, one line each."""
    switch_off_probe(marks, ingress, repository)
    (repository / "dynamic" / "switch-probe.yml").unlink()  # a lost file is rendered again

    _, output = start_all()

    assert "the barrier of probe is proven" in output
    assert "host check not built yet (#50 SW3)" in output
    assert (repository / "dynamic" / "switch-probe.yml").exists()


APEX_FLEET = (
    "cloudflare: {zone: probe.test}\n"
    "services:\n  probe:\n    run: {enabled: false}\n"
    "    hosts: [{name: '@', exposure: public, reason: a public page}]\n"
)


APEX_HOST = "probe.test"


@dataclass
class ApexProof:
    """What the barrier proof of the apex saw: whether the tunnel was already started when it
    asked, and whether Traefik is made to leave the apex unmarked while the routed host is fine."""

    unmarked: bool = False
    tunnel_started_when_asked: list[bool] = field(default_factory=list)


@pytest.fixture
def apex_proof(ingress: Ingress, systemd: FakeSystemd, monkeypatch: pytest.MonkeyPatch):
    proof = ApexProof()
    answer = ingress.fetch

    def fetch(address: str, host: str, seconds: float, clock: Callable[[], float]):
        if host != APEX_HOST:
            return answer(address, host, seconds, clock)
        proof.tunnel_started_when_asked.append(systemd.started)
        if proof.unmarked:
            return PLAIN_NOT_FOUND
        return answer(address, host, seconds, clock)

    monkeypatch.setattr(ingress, "fetch", fetch)
    return proof


def test_start_all_proves_the_apex_barrier_of_a_disabled_unit_before_it_reopens(
    apex_proof, start_all, stopped_tunnel, marks, repository, systemd
):
    """#325 B7: the unit is switched off and disabled; the apex it declares is proven first."""
    (repository / "fleet.yaml").write_text(APEX_FLEET)
    switch_off(marks.directory, unit="probe")

    exit_code, output = start_all()

    assert exit_code == 0
    assert "the barrier of probe is proven" in output
    assert apex_proof.tunnel_started_when_asked == [False]
    assert systemd.active


def test_an_unproven_apex_barrier_keeps_the_tunnel_closed_and_names_the_unit(
    apex_proof, start_all, stopped_tunnel, marks, repository, systemd
):
    """#325 B7: only the apex proof fails, the routed host succeeds; the tunnel never starts."""
    (repository / "fleet.yaml").write_text(APEX_FLEET)
    switch_off(marks.directory, unit="probe")
    apex_proof.unmarked = True

    exit_code, output = start_all()

    assert exit_code == 1
    assert "the tunnel stays closed: the barrier of probe is not proven" in output
    assert not systemd.started
    assert not systemd.active


def test_stop_all_reads_no_catalog(stop_all, repository):
    """#325 B10: a malformed host in the catalog does not stop the global brake."""
    (repository / "fleet.yaml").write_text(
        "cloudflare: {zone: probe.test}\n"
        "services: {probe: {run: {enabled: true}, hosts: [{name: Bad}]}}\n"
    )

    exit_code, _ = stop_all()

    assert exit_code == 0


def test_a_barrier_that_cannot_be_proven_keeps_the_tunnel_closed(
    start_all, stopped_tunnel, marks, ingress, repository, systemd
):
    """#70 rule 5: an unproven barrier keeps the tunnel closed."""
    switch_off_probe(marks, ingress, repository)
    ingress.rejecting = True

    exit_code, output = start_all()

    assert exit_code == 1
    assert "the tunnel stays closed: the barrier of probe is not proven" in output
    assert not systemd.active
    assert marks.global_mark() is not None


def test_authorization_that_fails_leaves_the_tunnel_closed_and_the_switch_recorded(
    start_all, stopped_tunnel, marks, systemd
):
    """#70 rule 5: a failed authorization is partial, exit 1, marker recorded."""
    systemd.authorizes = False

    exit_code, output = start_all()

    assert exit_code == 1
    assert "the system did not authorize the start" in output
    assert "start" not in systemd.verbs()
    assert marks.global_mark().since == FIRST_STOP


def test_authorization_is_asked_before_the_switch_is_cleared(
    start_all, stopped_tunnel, marks, systemd
):
    """#70 rule 4.2: authorization comes before the marker is cleared."""
    seen = []
    systemd.while_asking = lambda: seen.append(marks.global_mark())

    start_all()

    assert seen[0] is not None


def test_a_failed_start_records_the_global_switch_again(start_all, stopped_tunnel, marks, systemd):
    """#70 rule 5: a failed start records the marker again."""
    systemd.start_fails = True

    exit_code, output = start_all()

    assert exit_code == 1
    assert "the tunnel did not start" in output
    assert marks.global_mark() is not None
    assert not systemd.active


def test_a_stop_during_the_prompt_wins(start_all, stopped_tunnel, marks, systemd):
    """#70 rule 4.3 and rule 5: a stop during the prompt wins."""
    exit_code, output = start_all(while_prompt_waits=lambda: marks.record_global(NOW))

    assert exit_code == 1
    assert "switched off again meanwhile" in output
    assert "start" not in systemd.verbs()
    assert marks.global_mark() is not None


def test_a_start_that_leaves_the_unit_activating_stops_it_and_reports_what_is_observed(
    start_all, stopped_tunnel, marks, systemd
):
    """#70 rule 5 and P15: a start systemd accepted but that is not active is stopped again."""
    systemd.start_leaves_unit_activating = True

    exit_code, output = start_all()

    assert exit_code == 1
    assert "the tunnel is closed" in output
    assert not systemd.activating
    assert marks.global_mark() is not None


def test_an_unreadable_state_after_the_start_never_claims_the_tunnel_closed(
    start_all, stopped_tunnel, marks, systemd
):
    """#70 rule 5 and P15: a closed state is claimed only after it was observed."""
    systemd.state_unreadable_after_start = True

    exit_code, output = start_all()

    assert exit_code == 1
    assert "stays closed" not in output
    assert "the tunnel is not confirmed closed; check `systemctl is-active" in output
    assert marks.global_mark() is not None


def test_an_interrupt_during_the_start_records_the_switch_again(
    start_all, stopped_tunnel, marks, systemd
):
    """#70 rule 5: a Ctrl-C after the marker was cleared records it again, partial, exit 1."""

    def ctrl_c():
        raise KeyboardInterrupt

    systemd.while_starting = ctrl_c

    exit_code, output = start_all()

    assert exit_code == 1
    assert "interrupted while reopening the tunnel" in output
    assert marks.global_mark() is not None


def test_authorization_is_asked_with_the_internal_agent_so_an_ssh_session_can_answer(
    start_all, stopped_tunnel, systemd
):
    """#70 rule 4.2 and rule 8: the system's own prompt appears where no desktop agent runs."""
    start_all()

    pkcheck = next(call for call in systemd.calls if call[0] == "pkcheck")
    assert pkcheck[:5] == [
        "pkcheck",
        "--action-id",
        tunnel.MANAGE_UNITS_ACTION,
        "--process",
        pkcheck[4],
    ]
    assert pkcheck[5:] == ["--allow-user-interaction", "--enable-internal-agent"]


@pytest.mark.parametrize("answer", ["no", "", "Yes", "yes please"])
def test_only_the_exact_yes_reopens_the_tunnel(start_all, stopped_tunnel, marks, systemd, answer):
    """#70 rule 4: start --all needs the exact `yes`."""
    exit_code, _ = start_all(answer)

    assert exit_code == 1
    assert marks.global_mark() is not None
    assert not systemd.active


def test_start_all_refuses_without_a_terminal(marks, systemd, capsys, stopped_tunnel):
    """#70 rule 9: start --all refuses without a terminal."""
    exit_code = emergency.start_all(marks, NOW, tunnel.Tunnel(run=systemd.run))

    assert exit_code == 1
    assert "must be a terminal" in capsys.readouterr().err
    assert not systemd.calls
    assert marks.global_mark() is not None


def test_start_all_with_nothing_switched_off_changes_nothing(start_all, systemd):
    """#70 rule 4: nothing switched off, nothing changes."""
    exit_code, output = start_all()

    assert exit_code == 0
    assert "no change" in output
    assert "start" not in systemd.verbs()


# --- the command line ----------------------------------------------------------------------


def test_the_tunnel_is_cloudflared_of_the_system_manager_unless_the_environment_names_another():
    """#70 Files (tunnel.py): unit and manager are parameters for the probe."""
    default = tunnel.Tunnel.from_environment({})
    probe = tunnel.Tunnel.from_environment(
        {tunnel.UNIT_VARIABLE: "edge-probe-tunnel-1.service", tunnel.MANAGER_VARIABLE: "user"}
    )

    assert (default.unit, default.manager) == ("cloudflared.service", tunnel.Manager.SYSTEM)
    assert (probe.unit, probe.manager) == ("edge-probe-tunnel-1.service", tunnel.Manager.USER)


def test_a_user_manager_tunnel_is_driven_with_systemctl_user_and_needs_no_authorization(systemd):
    """#70 Proof (probe cell): a throwaway user unit stands in for the tunnel."""
    user_tunnel = tunnel.Tunnel("edge-probe-tunnel-1.service", tunnel.Manager.USER, systemd.run)

    user_tunnel.stop(may_ask_password=False)

    assert systemd.calls == [
        ["systemctl", "--user", "--no-ask-password", "stop", "edge-probe-tunnel-1.service"]
    ]
    assert user_tunnel.authorized_to_start(1)


def test_a_stop_that_cannot_be_asked_names_edges_own_reason_beside_the_partial(stop_all, systemd):
    """#70 rule 3: the partial line stays and the cause of the failed stop is not lost."""
    systemd.refuses_stop = True
    systemd.stop_times_out_after_stopping = True

    exit_code, output = stop_all()

    assert exit_code == 1
    assert "the tunnel still runs; `systemctl stop cloudflared`" in output
    assert "stop failed: cannot run systemctl (timed out)" in output


def test_a_failed_stop_and_failed_record_still_name_edges_own_reason(marks, systemd, capsys):
    """#70 rule 3: with no switch recorded, the partial line keeps the stop error and hint."""
    marks.directory.mkdir(parents=True)
    (marks.directory / switches.GLOBAL_STOP_FILE).mkdir()
    systemd.refuses_stop = True
    systemd.stop_times_out_after_stopping = True

    exit_code = emergency.stop_all(marks, NOW, tunnel.Tunnel(run=systemd.run))

    assert exit_code == 1
    err = capsys.readouterr().err
    assert "could not be recorded" in err
    assert "`systemctl stop cloudflared`" in err
    assert "stop failed: cannot run systemctl (timed out)" in err


def test_an_older_switch_survives_two_failed_records_and_the_stop_is_a_success(
    marks, systemd, capsys
):
    """#70 rule 2: a readable older switch stays the record, whatever the new writes did."""
    earlier = NOW.replace(year=NOW.year - 1)
    marks.record_global(earlier)

    class WritesFail(switches.Switches):
        def record_global(self, now):
            raise switches.SwitchError("disk full")

    exit_code = emergency.stop_all(WritesFail(marks.directory), NOW, tunnel.Tunnel(run=systemd.run))

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "the tunnel is stopped" in captured.out
    assert "could not be recorded" not in captured.err
    assert marks.global_mark().since == earlier.isoformat(timespec="seconds")
