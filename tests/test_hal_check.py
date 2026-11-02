"""`hal check` driven through `hal.cli.main`, with a fake `docker` and `ss` first on PATH."""

import errno
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
from pathlib import Path

import pytest
from support.git_support import elsewhere, hal_command, hal_environment, hal_program, run_hal
from support.workstation_support import RunnerWithCleanLogs, home_check

from hal import check_commands, cli, exposure_rows
from hal.exposure import host, inspection
from hal.exposure.exposure import Finding, Problem, Protocol
from hal.stack.external import cloudflare_read, host_probe, tofu
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


@pytest.mark.parametrize("area", ["exposure", "hosts"])
def test_an_area_runs_without_the_daily_check(area, hosts_home, fake_host, monkeypatch, capsys):
    """The areas leave the daily check's report and remembered findings alone."""
    monkeypatch.setattr(cloudflare_read, "CloudflareClient", FakeCloudflare(CLEAN_SNAPSHOT))
    monkeypatch.setattr(host_probe, "HttpProber", AnsweringProber())
    fake_host()

    assert cli.main(["check", area]) == 0
    assert capsys.readouterr().err == ""
    layout = Layout(hosts_home)
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


def test_an_area_that_does_not_exist_is_a_usage_error(run_hal_check):
    """E1, cell 5."""
    exit_code, out, _ = run_hal_check("services")

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


SENTINEL = "sentinel-4b1d-never-print-me"
ZONE_TARGET = "t-1.cfargotunnel.com"
DECLARED_HOSTS = """\
cloudflare: {zone: example.test}
services:
  site:
    hosts:
      - {name: "@", exposure: public, reason: the site}
"""


def snapshot_with(*records: cloudflare_read.Record) -> cloudflare_read.Snapshot:
    return cloudflare_read.Snapshot("t-1", records, (), ())


CLEAN_SNAPSHOT = snapshot_with(cloudflare_read.Record("example.test", "CNAME", ZONE_TARGET, True))
FINDING_SNAPSHOT = snapshot_with(
    cloudflare_read.Record("example.test", "A", SENTINEL, True),
    cloudflare_read.Record("stray.example.test", "CNAME", ZONE_TARGET, True),
)


class FakeCloudflare:
    """Stands in for `CloudflareClient`: answers a snapshot, raises, or runs a callable first."""

    def __init__(self, outcome) -> None:
        self.outcome = outcome

    def __call__(self, _token: str) -> FakeCloudflare:
        return self

    def read(self, _zone: str):
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            self.outcome()
            return CLEAN_SNAPSHOT
        return self.outcome


class AnsweringProber:
    def __init__(self, answer=None) -> None:
        self.answer = answer or host_probe.Answer(200, None, True, False)

    def __call__(self) -> AnsweringProber:
        return self

    def ask(self, _name: str, _path: str = "/"):
        return self.answer


@pytest.fixture
def hosts_home(tmp_path, monkeypatch) -> Path:
    """A temporary HOME whose read-token file holds the sentinel, and a one-host catalog."""
    home = tmp_path / "home"
    token_file = home / ".secrets/cloudflare/fleet-read"
    token_file.parent.mkdir(parents=True)
    token_file.write_text(SENTINEL + "\n")
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "fleet.yaml").write_text(DECLARED_HOSTS)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setattr(tofu, "PROJECT_ROOT", tree)
    return home


@pytest.fixture
def run_hosts(hosts_home, monkeypatch, capsys):
    def run(*arguments: str, reads=CLEAN_SNAPSHOT, prober=None) -> tuple[int, str, str]:
        monkeypatch.setattr(cloudflare_read, "CloudflareClient", FakeCloudflare(reads))
        monkeypatch.setattr(host_probe, "HttpProber", prober or AnsweringProber())
        try:
            exit_code = cli.main(["check", "hosts", *arguments])
        except SystemExit as usage_error:
            exit_code = usage_error.code
        captured = capsys.readouterr()
        return exit_code, captured.out, captured.err

    return run


def test_clean_hosts_say_how_many_and_exit_0(run_hosts):
    assert run_hosts() == (0, "no findings (1 hosts)\n", "")


def test_clean_hosts_in_json_are_an_empty_list_keyed_by_the_area(run_hosts):
    exit_code, out, err = run_hosts("--json")

    assert (exit_code, json.loads(out), err) == (0, {"hosts": []}, "")


def test_findings_exit_1_and_never_print_the_token_in_text(run_hosts):
    exit_code, out, err = run_hosts(reads=FINDING_SNAPSHOT)

    assert (exit_code, err) == (1, "")
    assert out.splitlines()[0].startswith("record-wrong example.test: ")
    assert SENTINEL not in out


def test_findings_in_json_are_one_object_keyed_by_the_area_without_the_token(run_hosts):
    exit_code, out, err = run_hosts("--json", reads=FINDING_SNAPSHOT)

    assert (exit_code, err) == (1, "")
    assert [item["problem"] for item in json.loads(out)["hosts"]] == [
        "record-wrong",
        "undeclared-record",
    ]
    assert SENTINEL not in out


@pytest.mark.parametrize(
    "reads, prober, problem, next_step",
    [
        (snapshot_with(), None, "record-missing", "`hal apply`"),
        (
            snapshot_with(cloudflare_read.Record("example.test", "A", "192.0.2.1", True)),
            None,
            "record-wrong",
            "`hal apply` shows the Cloudflare plan before its yes; nothing is converted (D12), "
            "so fix a foreign type by hand",
        ),
        (
            CLEAN_SNAPSHOT,
            AnsweringProber(host_probe.Answer(200, None, False, False)),
            "answer-wrong",
            "`hal apply` shows the Cloudflare plan before its yes",
        ),
    ],
)
def test_a_finding_that_apply_fixes_or_shows_names_hal_apply_as_its_next_step(
    run_hosts, reads, prober, problem, next_step
):
    _, out, _ = run_hosts("--json", reads=reads, prober=prober)

    hosts = {item["problem"]: item["next"] for item in json.loads(out)["hosts"]}
    assert hosts[problem] == next_step


@pytest.mark.parametrize(
    "outcome, problem",
    [
        (host_probe.Unreachable(host_probe.FailureKind.TIMEOUT), "unreachable"),
        (host_probe.Answer(200, None, False, False), "answer-wrong"),
    ],
)
def test_a_host_that_answers_wrong_or_not_at_all_is_a_finding_in_text_and_json(
    run_hosts, outcome, problem
):
    text = run_hosts(prober=AnsweringProber(outcome))
    as_json = run_hosts("--json", prober=AnsweringProber(outcome))

    assert text[0] == as_json[0] == 1
    assert text[1].startswith(f"{problem} example.test: ")
    assert json.loads(as_json[1])["hosts"][0]["problem"] == problem


@pytest.mark.parametrize(
    "failure, cause",
    [
        (cloudflare_read.CloudflareReadError(f"/zones: {SENTINEL}"), "/zones: ***"),
        (OSError(errno.EIO, SENTINEL), "OSError: "),
        (ValueError(SENTINEL), "ValueError"),
    ],
    ids=["read error", "os error", "value error"],
)
@pytest.mark.parametrize("flags", [(), ("--json",)], ids=["text", "json"])
def test_a_reader_failure_exits_3_names_the_cause_without_the_token_and_prints_no_stdout(
    run_hosts, failure, cause, flags
):
    exit_code, out, err = run_hosts(*flags, reads=failure)

    assert (exit_code, out) == (3, "")
    assert err.splitlines()[0].startswith(f"error: hal check: hosts: cannot check, {cause}")
    assert len(err.splitlines()) == 1
    assert SENTINEL not in err


def test_a_missing_token_file_exits_3_naming_it(run_hosts, hosts_home):
    token_file = hosts_home / ".secrets/cloudflare/fleet-read"
    token_file.unlink()

    exit_code, out, err = run_hosts("--json")

    assert (exit_code, out) == (3, "")
    assert err.splitlines()[0] == (
        f"error: hal check: hosts: cannot check, cannot read {token_file}: "
        "No such file or directory"
    )


def test_an_invalid_catalog_exits_3_before_any_token_is_read(run_hosts, hosts_home):
    (tofu.PROJECT_ROOT / "fleet.yaml").write_text("services: 3\n")
    (hosts_home / ".secrets/cloudflare/fleet-read").unlink()

    exit_code, out, err = run_hosts()

    assert (exit_code, out) == (3, "")
    assert err.startswith("error: hal check: hosts: cannot check, ")
    assert "fleet-read" not in err


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("flags", [(), ("--json",)], ids=["text", "json"])
def test_an_interrupt_before_the_output_exits_130_with_stdout_empty(run_hosts, interrupt, flags):
    reads = lambda: os.kill(os.getpid(), interrupt)  # noqa: E731

    exit_code, out, err = run_hosts(*flags, reads=reads)

    assert (exit_code, out) == (130, "")
    assert SENTINEL not in err


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_an_interrupt_while_the_output_is_written_leaves_the_whole_document_and_the_verdict(
    hosts_home, monkeypatch, interrupt
):
    class InterruptedHalfway(io.StringIO):
        delivered = False

        def write(self, text: str) -> int:
            if self.delivered or len(text) < 2:
                return super().write(text)
            self.delivered = True
            middle = len(text) // 2
            super().write(text[:middle])
            os.kill(os.getpid(), interrupt)
            return middle + super().write(text[middle:])

    stdout = InterruptedHalfway()
    monkeypatch.setattr(sys, "stdout", stdout)
    monkeypatch.setattr(cloudflare_read, "CloudflareClient", FakeCloudflare(FINDING_SNAPSHOT))
    monkeypatch.setattr(host_probe, "HttpProber", AnsweringProber())

    exit_code = cli.main(["check", "hosts", "--json"])

    assert exit_code == 1
    assert len(json.loads(stdout.getvalue())["hosts"]) == 2


def test_the_allow_list_belongs_to_the_exposure_area(run_hosts):
    exit_code, out, err = run_hosts("--allow-list", "ALLOW_LIST")

    assert (exit_code, out) == (2, "")
    assert err.splitlines()[-1] == "next: hal check exposure --allow-list FILE"


def test_the_exposure_area_reads_no_cloudflare(fake_host, hosts_home, monkeypatch, capsys):
    allow_list = hosts_home / "allow-list.toml"
    allow_list.write_text("", encoding="utf-8")

    def forbidden(*_arguments, **_keywords):
        raise AssertionError("Cloudflare was read")

    monkeypatch.setattr(cloudflare_read, "CloudflareClient", forbidden)
    fake_host()

    assert cli.main(["check", "exposure", "--allow-list", str(allow_list)]) == 0
    assert capsys.readouterr().err == ""


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
