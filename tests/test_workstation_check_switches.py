"""An app switched off with `hal stop` in `hal check` (overnightworks/edge#466 E-1..E-3, #415 Z8): the mail, the report and an unreadable switch directory."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

import pytest
from support.workstation_support import RunnerWithCleanLogs, Sandbox, home_check, message_of

from hal.stack import switches
from hal.workstation.layout import Layout

pytestmark = pytest.mark.usefixtures("quiet_pc")

HOPIN_EXITED = "/hopin-web-1\texited\t\t143\thopin\n"


@pytest.fixture
def clean_home(sandbox: Sandbox, furnish_clean_home: Callable[[Path], Path]) -> Path:
    """The conftest's clean home, inside the sandbox's HOME."""
    return furnish_clean_home(sandbox.home)


@pytest.fixture
def runner() -> RunnerWithCleanLogs:
    runner = RunnerWithCleanLogs()
    runner.platform_listing = HOPIN_EXITED
    return runner


def switch_off_hopin() -> switches.Switches:
    state = switches.Switches(switches.default_state_directory())
    state.record("hopin", datetime(2026, 10, 27, 9, 0).astimezone())
    return state


def test_an_app_switched_off_with_hal_stop_sends_no_mail_and_the_report_names_the_switch(clean_home, runner, mail_stub) -> None:
    """#466 E-1 (#415 Z8, Z4)."""
    switch_off_hopin()

    code = home_check(clean_home, runner)

    assert code == 0
    assert mail_stub.sent == []
    assert "Mit hal stop abgeschaltet: hopin" in Layout(clean_home).check_report_file.read_text()


def test_the_same_exit_is_mailed_once_the_switch_is_gone(clean_home, runner, mail_stub) -> None:
    """#466 E-2: the counterexample, driven through the real switch writer."""
    state = switch_off_hopin()
    home_check(clean_home, runner)
    state.clear("hopin", state.mark("hopin"))

    home_check(clean_home, runner)

    body = message_of(mail_stub.sent[0]).get_content()
    assert "hopin stopped with an error." in body
    assert "Services: Action needed" in body


def test_a_switch_directory_that_cannot_be_read_breaks_the_platform_check_and_leaves_the_other_findings(clean_home, runner, sandbox) -> None:
    """#466 E-3 (#340 S5): a run fails rather than guesses."""
    stopped = switches.default_state_directory() / switches.STOPPED_DIRECTORY
    stopped.parent.mkdir(parents=True, exist_ok=True)
    stopped.write_text("")
    (clean_home / ".secrets" / "gitlab").unlink()

    code = home_check(clean_home, runner)

    report = Layout(clean_home).check_report_file.read_text()
    assert code == 3
    assert "check platform failed" in report
    assert "| missing | gitlab |" in report
