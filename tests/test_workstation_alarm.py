"""`hal alarm` (#4 M3): the five-minute run mails a service or backup finding after the configured runs in a row, in the check mail's words, and shares the daily check's remembered set."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from support.workstation_support import PASSWORD_CANARY, RunnerWithCleanLogs, Sandbox, home_check, message_of, no_container_restarts, restarting_containers, write_backup_status, write_hal_config

from hal import alarm_commands
from hal import cli as hal_cli
from hal.grammar import ExitCode
from hal.workstation import check
from hal.workstation import ports as home_ports
from hal.workstation.layout import Layout

pytestmark = pytest.mark.usefixtures("quiet_pc")

RESTARTING = "presentator-live keeps restarting and is therefore unreachable."
RECOVERED = "presentator-live no longer keeps restarting."


@pytest.fixture
def clean_home(sandbox: Sandbox, furnish_clean_home: Callable[[Path], Path]) -> Path:
    return furnish_clean_home(sandbox.home)


@pytest.fixture
def runner() -> RunnerWithCleanLogs:
    return RunnerWithCleanLogs()


@pytest.fixture
def alarm(clean_home, runner, monkeypatch, capsys) -> Callable[[], int]:
    """`hal alarm` through `hal.cli.main`, over the clean home and the fake runner instead of this machine."""

    def build_ports():
        return home_ports.build_layout_and_ports(home=clean_home, run=runner)

    monkeypatch.setattr(alarm_commands, "build_layout_and_ports", build_ports)
    return lambda: hal_cli.main(["alarm"])


class ForbiddenStdin:
    def __getattr__(self, name: str) -> object:
        raise AssertionError("stdin was touched")


def bodies(mail_stub) -> list[str]:
    return [message_of(sent).get_content() for sent in mail_stub.sent]


def test_a_finding_of_one_run_sends_no_mail(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")

    assert alarm() == ExitCode.OK

    assert mail_stub.sent == []


def test_a_finding_of_two_runs_in_a_row_is_mailed_once_in_the_check_mails_words(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")

    alarm()
    alarm()
    alarm()

    [body] = bodies(mail_stub)
    assert RESTARTING + " (new)" in body
    assert "Services: Action needed" in body


def test_a_finding_that_is_gone_one_run_later_never_reaches_the_second_run(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    no_container_restarts(runner)
    alarm()
    restarting_containers(runner, "presentator-live")

    alarm()

    assert mail_stub.sent == []


def test_a_mailed_finding_that_goes_is_mailed_as_done_once(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    alarm()
    no_container_restarts(runner)

    alarm()
    alarm()

    assert [RECOVERED in body for body in bodies(mail_stub)] == [False, True]


def test_a_mailed_finding_absent_for_one_run_and_back_sends_no_mail(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    alarm()
    no_container_restarts(runner)
    alarm()
    restarting_containers(runner, "presentator-live")

    alarm()
    alarm()

    assert len(mail_stub.sent) == 1


def test_a_mailed_finding_absent_for_the_configured_runs_is_mailed_as_done_once(alarm, clean_home, runner, mail_stub) -> None:
    write_hal_config(clean_home, "[alarm]\nruns = 3\n")
    restarting_containers(runner, "presentator-live")
    for _ in range(3):
        alarm()
    no_container_restarts(runner)

    counts = []
    for _ in range(4):
        alarm()
        counts.append(len(mail_stub.sent))

    assert counts == [1, 1, 2, 2]
    assert RECOVERED in bodies(mail_stub)[-1]


def test_a_delivered_mail_is_not_sent_again_while_the_popup_keeps_failing(alarm, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    runner.notify_delivers = False

    alarm()
    alarm()
    alarm()
    alarm()

    assert len(mail_stub.sent) == 1


def test_a_failed_popup_without_a_mail_channel_is_tried_again_by_the_next_run(alarm, runner, capsys) -> None:
    restarting_containers(runner, "presentator-live")
    runner.notify_delivers = False
    alarm()
    alarm()
    runner.notify_delivers = True

    alarm()

    output = capsys.readouterr()
    assert f"! {check.Delivery.POPUP_FAILED}" in output.out
    assert len(runner.notifications) == 2


@pytest.mark.parametrize(
    ("scenario", "line"),
    [
        ("mail_fails", "! mail failed, retries next run"),
        ("popup_fails_without_mail", "! popup failed, retries next run"),
        ("nothing_new", "✓ nothing new, no mail"),
        ("mail_sent", "✓ mail sent"),
        ("news_sent_without_mail", "✓ news sent"),
        ("notifications_off", "✓ notifications off"),
        ("no_mail_and_no_session", "✓ no mail set up"),
    ],
)
def test_the_verdict_line_marks_a_delivery_that_retries_next_run_and_every_other_one_as_done(alarm, clean_home, runner, mail_stub, capsys, scenario, line) -> None:
    if scenario != "nothing_new":
        restarting_containers(runner, "presentator-live")
    if scenario == "mail_fails":
        mail_stub.exit_with(1)
    if scenario in {"popup_fails_without_mail", "news_sent_without_mail", "no_mail_and_no_session"}:
        (Layout(clean_home).secrets_dir / "smtp" / "account.toml").unlink()
    if scenario == "popup_fails_without_mail":
        runner.notify_delivers = False
    if scenario == "no_mail_and_no_session":
        runner.session_active = False
    if scenario == "notifications_off":
        write_hal_config(clean_home, "[check]\nnotify = false\n")
    alarm()
    capsys.readouterr()

    alarm()

    assert capsys.readouterr().out.strip() == line


def test_a_failed_popup_beside_a_delivered_mail_promises_no_retry(alarm, runner, mail_stub, capsys) -> None:
    restarting_containers(runner, "presentator-live")
    runner.notify_delivers = False
    alarm()
    alarm()

    output = capsys.readouterr()
    assert "retries" not in output.out + output.err
    assert "next run" not in output.out + output.err


def test_the_daily_check_after_an_alarm_remembers_the_findings_of_other_areas(alarm, clean_home, runner, mail_stub) -> None:
    (clean_home / ".secrets" / "gitlab").chmod(0o644)
    home_check(clean_home, runner)
    mails_after_daily_check = len(mail_stub.sent)
    alarm()
    alarm()

    home_check(clean_home, runner)

    assert (mails_after_daily_check, len(mail_stub.sent)) == (1, 1)


def test_the_daily_check_after_an_alarm_mail_sends_nothing_new(alarm, clean_home, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    alarm()

    home_check(clean_home, runner)

    assert len(mail_stub.sent) == 1


def test_the_alarm_after_a_daily_mail_sends_nothing_new(alarm, clean_home, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    home_check(clean_home, runner)

    alarm()
    alarm()

    assert len(mail_stub.sent) == 1


def test_the_mail_carries_no_secret_and_no_home_file(alarm, clean_home, runner, mail_stub) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    alarm()

    [body] = bodies(mail_stub)
    assert PASSWORD_CANARY not in body
    assert str(clean_home) not in body
    assert ".secrets" not in body


@pytest.mark.parametrize(("table", "mailed_after"), [("", 2), ("[alarm]\nruns = 1\n", 1), ("[alarm]\nruns = 3\n", 3), ("[alarm]\ninterval = 10\n", 2)])
def test_the_runs_in_a_row_come_from_the_config(alarm, clean_home, runner, mail_stub, table, mailed_after) -> None:
    write_hal_config(clean_home, table)
    restarting_containers(runner, "presentator-live")

    counts = []
    for _ in range(mailed_after):
        alarm()
        counts.append(len(mail_stub.sent))

    assert counts == [0] * (mailed_after - 1) + [1]


def test_a_mail_that_could_not_be_delivered_is_sent_again_by_the_next_run(alarm, runner, mail_stub, capsys) -> None:
    restarting_containers(runner, "presentator-live")
    mail_stub.exit_with(1)
    alarm()
    alarm()
    mail_stub.exit_with(0)

    alarm()

    assert [RESTARTING + " (new)" in body for body in bodies(mail_stub)] == [True, True]


def test_the_alarm_follows_the_notify_setting_of_the_check(alarm, clean_home, runner, mail_stub) -> None:
    write_hal_config(clean_home, "[check]\nnotify = false\n")
    restarting_containers(runner, "presentator-live")

    alarm()
    alarm()

    assert mail_stub.sent == []


@pytest.mark.parametrize(
    ("text", "complaint"),
    [
        ("[alarm]\nspeed = 3\n", "unknown key(s) or table(s): speed"),
        ("[alarm]\ninterval = \"5\"\n", "interval must be a whole number of at least 1"),
        ("[alarm]\nruns = true\n", "runs must be a whole number of at least 1"),
        ("[alarm]\nruns = 0\n", "runs must be a whole number of at least 1"),
    ],
)
def test_an_unknown_key_or_a_wrong_type_in_the_alarm_table_fails_loud_before_any_check(alarm, clean_home, runner, mail_stub, capsys, text, complaint) -> None:
    write_hal_config(clean_home, text)
    restarting_containers(runner, "presentator-live")

    code = alarm()

    assert (code, mail_stub.sent) == (ExitCode.USAGE, [])
    assert complaint in capsys.readouterr().err
    assert not Layout(clean_home).check_findings_file.exists()


@pytest.mark.parametrize("content", ["[1, 2]", '{"seen": {"a": "x"}, "absent": {}}'])
def test_a_counter_file_that_hal_did_not_write_stops_the_run_without_a_mail(alarm, clean_home, runner, mail_stub, capsys, content) -> None:
    restarting_containers(runner, "presentator-live")
    alarm()
    counter = next(Layout(clean_home).hal_state_dir.glob("alarm*"))
    counter.write_text(content)

    code = alarm()

    assert (code, mail_stub.sent) == (ExitCode.FAILURE, [])
    assert "unexpected error (ValueError)" in capsys.readouterr().err


def test_the_alarm_runs_only_the_services_and_the_backup(alarm, clean_home, runner, mail_stub) -> None:
    write_backup_status(clean_home, state="failed")
    runner.calls.clear()

    alarm()
    alarm()

    [body] = bodies(mail_stub)
    assert "The last backup failed." in body
    assert not any(call[0] == "journalctl" for call in runner.calls)


def test_the_alarm_never_reads_stdin(alarm, runner, mail_stub, monkeypatch) -> None:
    """G-11 for `hal alarm`, on the fakes of the other cells: any touch of stdin raises."""
    monkeypatch.setattr(sys, "stdin", ForbiddenStdin())
    restarting_containers(runner, "presentator-live")

    assert (alarm(), alarm()) == (ExitCode.OK, ExitCode.OK)
    assert len(mail_stub.sent) == 1
