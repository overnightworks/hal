"""`hal check` driven through `hal.cli.main`, with a fake `docker` and `ss` first on PATH."""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from support.git_support import elsewhere, hal_command, hal_environment, hal_program, run_hal
from support.workstation_support import RunnerWithCleanLogs, home_check

from hal import check_commands, cli, exposure_rows
from hal.exposure import host, inspection
from hal.exposure.exposure import Finding, Problem, Protocol
from hal.workstation import check
from hal.workstation.exposure_check import ExposureRule
from hal.workstation.layout import Layout

CLEAN_LINE = "✓ nothing reaches beyond loopback\n"
SSHD_LISTENS_ON_ALL = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=900,fd=3)) <->\n'
FORBIDDEN_STDIN = """
class Forbidden:
    def __getattr__(self, name):
        raise AssertionError("stdin was touched")
sys.stdin = Forbidden()
"""


@pytest.fixture
def run_hal_check(fake_host, tmp_path, capsys):
    def run(*arguments: str, ss: str = "") -> tuple[int, str, str]:
        fake_host(ss)
        allow_list = tmp_path / "allow-list.toml"
        allow_list.write_text("", encoding="utf-8")
        arguments = tuple(str(allow_list) if item == "ALLOW_LIST" else item for item in arguments)
        try:
            exit_code = cli.main(["check", *arguments])
        except SystemExit as usage_error:
            exit_code = usage_error.code
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return run


def test_an_area_runs_without_the_daily_check(tmp_path, fake_host, monkeypatch, capsys):
    """The area leaves the daily check's report and remembered findings alone."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    fake_host()

    assert cli.main(["check", "exposure"]) == 0
    assert capsys.readouterr().err == ""
    layout = Layout(home)
    assert not layout.check_report_file.exists()
    assert not layout.check_findings_file.exists()


def test_a_clean_host_says_so_and_exits_0(run_hal_check):
    """E2, cell 1."""
    assert run_hal_check("exposure", "--allow-list", "ALLOW_LIST") == (0, CLEAN_LINE, "")


def test_sshd_on_all_interfaces_is_one_row_and_a_verdict_and_exits_1(run_hal_check):
    """E2, cell 3."""
    exit_code, out, err = run_hal_check(
        "exposure", "--allow-list", "ALLOW_LIST", ss=SSHD_LISTENS_ON_ALL
    )

    assert (exit_code, err) == (1, "")
    assert [line.split() for line in out.splitlines()] == [
        ["!", "sshd", "listens", "1", "TCP", "port", "beyond", "loopback"],
        ["!", "1", "finding"],
    ]


def test_272_listeners_of_one_process_are_one_row(run_hal_check, monkeypatch):
    """E2, cell 2."""
    monkeypatch.setattr(host, "command_line", lambda _pid: None)
    sockets = "".join(
        f'udp UNCONN 0 0 *:{port} *:* users:(("python3",pid=93017,fd=3)) <->\n'
        for port in range(32000, 32272)
    )

    exit_code, out, err = run_hal_check("exposure", "--allow-list", "ALLOW_LIST", ss=sockets)

    assert (exit_code, err) == (1, "")
    assert [re.split(" {2,}", line.strip().removeprefix("! ")) for line in out.splitlines()] == [
        ["python3", "listens", "272 UDP ports beyond loopback"],
        ["1 finding · 272 ports · --json lists each"],
    ]


def test_a_process_named_with_an_escape_prints_as_text(run_hal_check):
    """E2, cell 11: the JSON subject keeps the byte, the terminal never gets it."""
    socket = 'tcp LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("\x1b[31mx",pid=900,fd=3)) <->\n'
    arguments = ("exposure", "--allow-list", "ALLOW_LIST")

    _, out, _ = run_hal_check(*arguments, ss=socket)
    _, json_out, _ = run_hal_check(*arguments, "--json", ss=socket)

    assert "\x1b" not in out
    assert "\\x1b[31mx" in out
    assert json.loads(json_out)["exposure"][0]["subject"] == "\x1b[31mx"


def test_json_is_one_object_keyed_by_the_area(run_hal_check):
    """E3, cell 6."""
    exit_code, out, err = run_hal_check(
        "exposure", "--allow-list", "ALLOW_LIST", "--json", ss=SSHD_LISTENS_ON_ALL
    )

    assert (exit_code, err) == (1, "")
    assert list(json.loads(out)) == ["exposure"]
    assert [finding["subject"] for finding in json.loads(out)["exposure"]] == ["sshd"]


def test_json_of_a_clean_host_is_an_empty_list(run_hal_check):
    """E3, cell 6."""
    exit_code, out, _ = run_hal_check("exposure", "--allow-list", "ALLOW_LIST", "--json")

    assert (exit_code, json.loads(out)) == (0, {"exposure": []})


def test_a_check_that_cannot_run_exits_3_with_the_cause_and_empty_stdout(run_hal_check, tmp_path):
    """E2 and E3, cells 4 and 6."""
    for arguments in (("exposure", "--json"), ("exposure",)):
        exit_code, out, err = run_hal_check(
            *arguments, "--allow-list", str(tmp_path / "absent.toml")
        )

        assert (exit_code, out) == (3, "")
        assert err.splitlines()[0].startswith(
            "error: hal check: exposure: cannot check, cannot read"
        )


def test_a_bare_check_with_an_allow_list_is_a_usage_error(run_hal_check):
    """E4, cell 5."""
    exit_code, out, err = run_hal_check("--allow-list", "ALLOW_LIST")

    assert (exit_code, out) == (2, "")
    assert err.splitlines()[-1] == "next: hal check exposure --allow-list FILE"


@pytest.mark.parametrize("area", ["services", "hosts"])
def test_an_area_that_does_not_exist_is_a_usage_error(run_hal_check, area):
    """E1, cell 5."""
    exit_code, out, _ = run_hal_check(area)

    assert (exit_code, out) == (2, "")


def test_an_interrupt_exits_130_with_empty_stdout(fake_host, tmp_path, capsys):
    """E2, cell 7: the fake `docker` sends SIGINT to the process that runs it."""
    fake_host(docker_script="kill -INT $PPID\nexec sleep 30")
    allow_list = tmp_path / "allow-list.toml"
    allow_list.write_text("", encoding="utf-8")

    exit_code = cli.main(["check", "exposure", "--allow-list", str(allow_list)])

    assert (exit_code, capsys.readouterr().out) == (130, "")


def test_the_exposure_check_never_reads_stdin(fake_host, monkeypatch, tmp_path):
    """Cell 8: a real `hal` process whose stdin raises on any touch, as G-11 runs the commands."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    fake_host()

    result = run_hal(tmp_path, hal_program(before=FORBIDDEN_STDIN), "check", "exposure")

    assert (result.returncode, result.stdout) == (0, CLEAN_LINE)


@pytest.fixture
def shimmed_tools(tmp_path) -> Path:
    """The only PATH of a real bare `hal check`: `git` and `sh` as they are, every other tool a
    shim that records its call; `systemctl` sees a graphical session and `systemd-run` fails, so
    the popup is tried and not delivered."""
    directory = tmp_path / "shims"
    directory.mkdir()
    for real in ("git", "sh"):
        (directory / real).symlink_to(shutil.which(real))
    for name in ("systemd-run", "systemctl", "journalctl", "notify-send", "msmtp", "docker", "ss"):
        exit_code = 1 if name in {"systemd-run", "journalctl"} else 0
        shim = directory / name
        record = f'echo "{name} $*" >> "{tmp_path / "calls"}"'
        shim.write_text(f"#!/bin/sh\n{record}\nexit {exit_code}\n")
        shim.chmod(0o755)
    return directory


def test_a_bare_check_runs_the_daily_check_in_a_real_process_without_reading_stdin(
    shimmed_tools, monkeypatch, tmp_path
):
    """The daily check as `hal check` runs it, on a throwaway HOME: no mail, popup, systemd or
    Docker beyond the shims."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))

    result = subprocess.run(
        hal_command(hal_program(before=FORBIDDEN_STDIN), "check"),
        cwd=elsewhere(tmp_path), env=hal_environment(PATH=str(shimmed_tools)),
        stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8", timeout=60,
    )  # fmt: skip

    calls = (tmp_path / "calls").read_text().splitlines()
    assert result.returncode in (1, 3)
    assert "services" in result.stdout
    assert any(call.startswith("systemd-run") for call in calls)
    report = (home / ".local/state/hal/check-report.md").read_text()
    assert "job-failed" not in report
    assert "systemd-unreadable" not in report


def test_every_problem_the_scan_reports_has_an_exposure_rule_with_a_level():
    """Every scan problem maps to a daily-check rule, and every rule has a level."""
    assert set(check_commands.EXPOSURE_RULES) == set(Problem)
    assert set(check_commands.EXPOSURE_RULES.values()) == set(ExposureRule)
    assert {("exposure", rule.value) for rule in ExposureRule} <= set(check.RULE_REPORTS)


def finding_of(problem: Problem) -> Finding:
    """A finding as the scan builds it: a socket problem names a protocol, a routing one a name."""
    socket_problems = {
        Problem.PUBLICATION_BEYOND_LOOPBACK,
        Problem.PUBLICATION_WITHOUT_HOST_IP,
        Problem.LISTENER_BEYOND_LOOPBACK,
    }
    if problem in socket_problems:
        return Finding(problem, "subject", Protocol.TCP)
    return Finding(problem, "subject", edge_name="name")


@pytest.mark.parametrize("problem", list(Problem))
def test_every_kind_of_finding_shows_in_the_rows_and_in_json(problem):
    """E3, done when: every finding kind shows in text and JSON."""
    finding = finding_of(problem)

    assert [row.subject for row in exposure_rows.rows_of([finding])] == ["subject"]
    assert inspection.as_json_objects([finding])[0]["problem"] == problem.value


def test_every_protocol_has_a_port_label():
    assert set(exposure_rows.PORT_LABELS) == set(Protocol)


@pytest.mark.usefixtures("quiet_pc")
def test_a_link_at_a_declared_secret_file_is_a_finding_in_the_daily_report(clean_home, capsys):
    place = clean_home / ".secrets" / "gitlab"
    target = clean_home / "elsewhere"
    target.write_text("FAKE-LINK-TARGET")
    place.unlink()
    place.symlink_to(target)

    code = home_check(clean_home, RunnerWithCleanLogs())

    assert code == 1
    report = Layout(clean_home).check_report_file.read_text()
    assert "| symlinked-file | ~/.secrets/gitlab |" in report
    assert "A secret file is a link" in capsys.readouterr().out
