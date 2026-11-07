from __future__ import annotations

import email.message
import email.policy
import fnmatch
import http.client
import hashlib
import json
import os
import re
import stat
import subprocess
import time
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO, NoReturn

import pytest

from hal import check_commands, secrets_commands, setup_commands
from hal import cli as hal_cli
from hal import config as hal_config
import support.host_support as host_support
from support.terminal_support import type_at_prompt
from hal.workstation import backup_check, logs_check, platform_check, secrets_view, system_step
from hal.workstation import ports as home_ports
from hal.workstation.secrets_setup import Boundaries as SecretsBoundaries
from hal.workstation.secrets_setup import Terminal as SecretsTerminal
from hal.workstation.secrets_view import load_manifest
from hal.workstation.setup import QUALITY_SOURCE
from hal.workstation.layout import Layout, run_command
from hal.workstation.tunnel_config import TUNNEL_ID_PLACEHOLDER


# Path-shaped tokens make these entries known, so the state `home` writes never becomes a finding itself.
HOME_README = "`.local/state`, `.config/home`, `.secrets` and `git/` belong here.\n"

# Every planted secret file holds this; no output and no report may ever contain any of it.
FAKE_SECRET_VALUE = "FAKE-SECRET-VALUE ghp_0000notarealtoken glpat-0000notarealtoken"


# The one `docker inspect --format` the platform check may send: named fields, and the compose project label.
# A fake docker answers any other format with a line that carries the canary, so a wider projection shows in the report.
ALLOWED_PLATFORM_INSPECT_FORMAT = (
    '{{.Name}}\t{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}\t{{.State.ExitCode}}'
    '\t{{index .Config.Labels "com.docker.compose.project"}}'
)
INSPECT_CANARY = "CANARY-ENV-VALUE-s3cr3t"
CANARY_INSPECT_LINE = f"/{INSPECT_CANARY}\trunning\tunhealthy\t0\tedge\n"


def symlinked_folder_fix(place: str) -> str:
    """The command `hal secrets` names for a symlink on the way to a secret: the folder it points to, or a new one, takes its place."""
    real_folder = f'if [ -e "$t" ]; then mv -T "$t" {place}; else mkdir {place}; fi'
    return f"t=$(readlink -m {place}) && rm {place} && {real_folder} && chmod 700 {place}"


# A small manifest of three kinds of place: one file, a wildcard plus a file, and a verified tool login.
TEST_TUNNEL_ID = "0000-test-tunnel"
TEST_MANIFEST = """\
[[secret]]
name = "gitlab"
kind = "token"
paths = ["~/.secrets/gitlab"]
read_by = [".bashrc"]
recreate = "https://gitlab.example/-/user_settings/personal_access_tokens"

[[secret]]
name = "cloudflared"
kind = "tool-login"
paths = ["~/.secrets/cloudflared/*.json", "~/.secrets/cloudflared/cert.pem"]
read_by = ["cloudflared.service", ".bashrc"]
recreate = "`cloudflared tunnel login`"

[[secret]]
name = "gh"
kind = "tool-login"
paths = ["~/.config/gh"]
read_by = ["gh"]
recreate = "`gh auth login --web`"
verify = "gh auth status"
"""


class FakeDisk:
    """The disk the platform check reads; the free share is the scenario, never this machine's."""

    TOTAL = 1000 * platform_check.BYTES_PER_GIGABYTE

    def __init__(self) -> None:
        self.free_share = 0.5
        self.unreadable = False
        self.asked: list[Path] = []

    def __call__(self, path: Path) -> platform_check.DiskSpace:
        self.asked.append(path)
        if self.unreadable:
            raise OSError("no disk")
        return platform_check.DiskSpace(self.TOTAL, round(self.TOTAL * self.free_share))


def plant_secrets(home: Path) -> None:
    """Every place the active manifest names for a live entry gets a fake secret, with the modes a tidy ~/.secrets keeps."""
    for entry in load_manifest(secrets_view.MANIFEST_PATH):
        for pattern in () if entry.retired else entry.paths:
            path = home / str(pattern).replace("*", "fake").replace(TUNNEL_ID_PLACEHOLDER, TEST_TUNNEL_ID)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(FAKE_SECRET_VALUE)
            path.chmod(0o600)
    secrets_dir = Layout(home).secrets_dir
    for directory in (secrets_dir, *(path for path in secrets_dir.rglob("*") if path.is_dir())):
        directory.chmod(0o700)


PASSWORD_CANARY = "CANARY-SMTP-PASSWORD-9f3"
SMTP_ENTRIES = """
[[secret]]
name = "smtp/password"
kind = "token"
paths = ["~/.secrets/smtp/password"]
read_by = ["hal check"]
recreate = "r"

[[secret]]
name = "smtp/account.toml"
kind = "configuration"
paths = ["~/.secrets/smtp/account.toml"]
read_by = ["hal check"]
recreate = "r"
"""
# Stands in for msmtp: records argv and stdin per call, runs --passwordeval through sh like msmtp does, exits as the `exit` file says.
STUB_MSMTP = """\
#!/bin/sh
call=$(mktemp -d "$STUB_MAIL_DIR/call.$(date +%s%N).XXXXXX")
for argument; do printf '%s\\n' "$argument"; done > "$call/argv"
cat > "$call/stdin"
for argument; do
    case "$argument" in --passwordeval=*) sh -c "${argument#--passwordeval=}" > "$call/password" ;; esac
done
exit "$(cat "$STUB_MAIL_DIR/exit" 2>/dev/null || echo 0)"
"""


@dataclass
class SentMail:
    arguments: list[str]
    stdin: str
    password: str


class MailStub:
    def __init__(self, directory: Path) -> None:
        self.directory = directory

    def exit_with(self, code: int) -> None:
        (self.directory / "exit").write_text(str(code))

    @property
    def sent(self) -> list[SentMail]:
        calls = sorted(self.directory.glob("call.*"))
        return [SentMail((call / "argv").read_text().splitlines(), (call / "stdin").read_text(), (call / "password").read_text()) for call in calls]


def set_up_mail(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, port: int = 587) -> MailStub:
    """An account and password under home, a stub msmtp first on PATH, and a manifest that knows both files."""
    directory = tmp_path / "mail-stub"
    directory.mkdir(exist_ok=True)
    stub = directory / "bin" / "msmtp"
    stub.parent.mkdir(exist_ok=True)
    stub.write_text(STUB_MSMTP)
    stub.chmod(0o755)
    monkeypatch.setenv("STUB_MAIL_DIR", str(directory))
    monkeypatch.setenv("PATH", f"{stub.parent}{os.pathsep}{os.environ['PATH']}")
    smtp = Layout(home).secrets_dir / "smtp"
    smtp.mkdir(parents=True, exist_ok=True)
    (smtp / "account.toml").write_text(f'host = "smtp.example.test"\nport = {port}\nuser = "home@example.test"\nto = "me@example.test"\n')
    (smtp / "password").write_text(PASSWORD_CANARY)
    for file in smtp.iterdir():
        file.chmod(0o600)
    smtp.chmod(0o700)
    manifest = secrets_view.MANIFEST_PATH
    assert tmp_path in manifest.parents, "set_up_mail edits the manifest; point it at a temporary copy first (use_manifest)"
    manifest.write_text(manifest.read_text() + SMTP_ENTRIES)
    return MailStub(directory)


def unit_listing_matching(listing: str | None, pattern: str) -> str | None:
    """What `systemctl list-units PATTERN` prints of a listing: only the lines whose unit name matches the pattern."""
    if listing is None:
        return None
    return "".join(line for line in listing.splitlines(keepends=True) if fnmatch.fnmatchcase(line.split(maxsplit=1)[0], pattern))


class RecordingRunner:
    """Delivers notifications (systemd-run succeeds only if notify-send did), answers the graphical-session probe and the failed-unit listing, fails every other tool as missing, records calls."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.notify_delivers = True
        self.session_active = True
        self.failed_units: str | None = ""  # what `systemctl --user list-units --state=failed` prints

    def __call__(self, argv: Sequence[str]) -> str | None:
        self.calls.append(list(argv))
        if argv[:3] == ["systemctl", "--user", "list-units"]:
            return unit_listing_matching(self.failed_units, argv[-1])
        delivers = {"systemd-run": self.notify_delivers, "systemctl": self.session_active}
        return "" if delivers.get(argv[0], False) else None

    @property
    def notifications(self) -> list[str]:
        """The summary line of every notification sent."""
        return [call[-3] for call in self.notification_calls]

    @property
    def notification_bodies(self) -> list[str]:
        return [call[-2] for call in self.notification_calls]

    @property
    def notification_calls(self) -> list[list[str]]:
        """The detached waiter commands: [..., summary, body, report path]."""
        return [call for call in self.calls if call[0] == "systemd-run"]


class RunnerWithRealGitAndQuality(RecordingRunner):
    """The hook check reads git and the stub quality, so these two run for real; every other tool stays as in RecordingRunner."""

    def __call__(self, argv: Sequence[str]) -> str | None:
        if Path(argv[0]).name in {"git", "quality"}:
            self.calls.append(list(argv))
            return run_command(argv)
        return super().__call__(argv)


class FakeProbe:
    """Answers every probe with one exit code (None: the tool hung or is missing) and remembers what it ran."""

    def __init__(self) -> None:
        self.code: int | None = 0
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: Sequence[str]) -> int | None:
        self.calls.append(tuple(argv))
        return self.code


class ProbeThatCannotStart(FakeProbe):
    """`gh` is there but not executable: starting the probe raises, and the secrets checker breaks on it."""

    def __call__(self, argv: Sequence[str]) -> int | None:
        raise PermissionError(argv[0])


# What the stub scanner refuses; assembled from parts, as every fake key in these tests is.
FAKE_KEY = "FAKE" + "KEY-" + "0000"

STUB_QUALITY = """\
#!/bin/sh
case "$1" in
scan-staged)
    [ -n "$STUB_SCAN_EXIT" ] && exit "$STUB_SCAN_EXIT"
    if git diff --cached | grep -q "FAKE""KEY-"; then
        echo "quality: secret.txt fake-key sha256=0000 (Wert nicht gezeigt)"
        exit 1
    fi
    ;;
engines)
    case "$2" in
    install)
        [ -n "$STUB_ENGINES_FAIL" ] && exit 1
        mkdir -p "$3" && touch "$3/installed"
        ;;
    verify) [ -e "$3/installed" ] || exit 1 ;;
    esac
    ;;
esac
exit 0
"""

# The `git` value real uv 0.10.9 wrote to uv-receipt.toml after installing QUALITY_SOURCE's pinned SHA; only the revision follows the pin.
RECORDED_RECEIPT_GIT = f"https://github.com/overnightworks/quality?rev={QUALITY_SOURCE.rpartition('@')[2]}"

# Writes what `uv tool install` leaves behind for the requirement it is given: the tool's executable and uv's receipt for it.
# Ansible's executable is a dummy, since the sandbox hands the system step a FakePlaybook instead of running it.
STUB_UV = """\
#!/bin/sh
echo "$@" >> "$STUB_UV_LOG"
[ -n "$STUB_UV_FAIL" ] && exit 1
mkdir -p "$HOME/.local/bin"
case "$4" in
ansible-core==*)
    mkdir -p "$HOME/.local/share/uv/tools/ansible-core"
    printf '#!/bin/sh\\nexit 1\\n' > "$HOME/.local/bin/ansible-playbook" && chmod 755 "$HOME/.local/bin/ansible-playbook"
    printf '[tool]\\nrequirements = [{ name = "ansible-core", specifier = "==%s" }]\\n' "${4#ansible-core==}" \\
        > "$HOME/.local/share/uv/tools/ansible-core/uv-receipt.toml"
    ;;
*)
    mkdir -p "$HOME/.local/share/uv/tools/overnightworks-quality"
    cp "$STUB_QUALITY" "$HOME/.local/bin/quality" && chmod 755 "$HOME/.local/bin/quality"
    printf '[tool]\\nrequirements = [{ name = "overnightworks-quality", git = "%s" }]\\n' "$STUB_RECEIPT_GIT" \\
        > "$HOME/.local/share/uv/tools/overnightworks-quality/uv-receipt.toml"
    ;;
esac
"""


# The bytes the sandbox's download serves as the pinned mise; the sandbox pins their hash.
FAKE_MISE = b"#!/bin/sh\necho mise\n"
FAKE_MISE_SHA256 = hashlib.sha256(FAKE_MISE).hexdigest()
STALE_MISE = b"#!/bin/sh\necho stale\n"


def serve_fake_mise(_url: str, writer: BinaryIO) -> None:
    writer.write(FAKE_MISE)


class RecordingDownload:
    """A download that serves the pinned stub and remembers what it was asked for and how the file it writes into was staged."""

    def __init__(self) -> None:
        self.urls: list[str] = []
        self.staging_modes: list[int] = []

    def __call__(self, url: str, writer: BinaryIO) -> None:
        self.urls.append(url)
        self.staging_modes.append(os.fstat(writer.fileno()).st_mode & 0o777)
        serve_fake_mise(url, writer)


def serve_wrong_bytes(_url: str, writer: BinaryIO) -> None:
    writer.write(b"not the pinned release")


def serve_half(_url: str, writer: BinaryIO) -> None:
    writer.write(FAKE_MISE[: len(FAKE_MISE) // 2])


def time_out(_url: str, writer: BinaryIO) -> None:
    writer.write(FAKE_MISE[:4])
    raise TimeoutError("timed out")


def cut_off_mid_transfer(url: str, writer: BinaryIO) -> None:
    """The real download boundary over a chunked response that ends early, which `http.client` reports as an HTTPException."""

    class CutOffResponse:
        def __enter__(self) -> CutOffResponse:
            return self

        def __exit__(self, *_exception: object) -> None:
            return None

        def read(self, _size: int = -1) -> bytes:
            raise http.client.IncompleteRead(b"#!/bin/sh\n", 100)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(urllib.request, "urlopen", lambda _url, timeout: CutOffResponse())
        home_ports.download_release(url, writer)


def fail_to_write(_url: str, _writer: BinaryIO) -> None:
    raise OSError(28, "No space left on device")


def plant_mise(home: Path, content: bytes = STALE_MISE, mode: int = 0o755) -> Path:
    mise = Layout(home).mise_executable
    mise.parent.mkdir(parents=True, exist_ok=True)
    mise.write_bytes(content)
    mise.chmod(mode)
    return mise


def bin_entries(home: Path) -> set[str]:
    return {entry.name for entry in Layout(home).mise_executable.parent.iterdir()}


def write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class StubSudo:
    """A `sudo` first on PATH: it writes one line per call (its argv, working directory and every ANSIBLE_* it received), then runs the rest.

    `-k` only forgets a ticket, so it is recorded and not executed; with `refusing`, any other call is recorded and exits 1 without running anything.
    """

    def __init__(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, forgetting_exit_code: int = 0, refusing: bool = False) -> None:
        self.log = tmp_path / "sudo.log"
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        sudo = bin_dir / "sudo"
        sudo.write_text(
            "#!/bin/sh\n"
            f'printf \'%s\\n\' "$* | $(pwd) | $(env | grep \'^ANSIBLE_\' | tr \'\\n\' \' \')" >> {self.log}\n'
            f'[ "$1" = "-k" ] && exit {forgetting_exit_code}\n'
            + ("exit 1\n" if refusing else 'exec "$@"\n')
        )
        sudo.chmod(0o755)
        monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    def calls(self) -> list[list[str]]:
        # `str.splitlines` would also cut at the mark's control character.
        return [[part.strip() for part in line.split(" | ")] for line in self.log.read_text().rstrip("\n").split("\n")]


TASK_MESSAGE = "/etc/cloudflared/config.yml names no `tunnel:`"


class FakePlaybook:
    """Ansible as the system step sees it: a converging playbook, whose check finds a change until a run has applied it."""

    def __init__(self) -> None:
        self.calls: list[list[str]] = []
        self.succeeds = True
        self.refused = False
        self.failure = ""
        self.changed_before_failing: int | None = None
        self.applied = False
        self.tasks = ("Write edge files", "Restart Docker")

    def __call__(self, argv: Sequence[str]) -> system_step.PlaybookRun:
        self.calls.append(list(argv))
        if self.refused:
            return system_step.PlaybookNotStarted()
        tasks = () if self.applied else self.tasks
        if self.succeeds and "--check" not in argv:
            self.applied = True
        if not self.succeeds:
            return system_step.PlaybookUnfinished(self.failure, self.changed_before_failing)
        return system_step.PlaybookFinished(len(tasks), tasks)


@dataclass
class FakeSystem:
    """The system step's boundaries: a terminal that is there or not, the FakePlaybook, and the running user (the operator unless a test says otherwise)."""

    playbook: FakePlaybook
    terminal: bool = True
    user: str = "operator"
    docker_driver: str | None = "journald"  # what `docker info` tells the operator, None when Docker does not answer
    running_policies: tuple[str, ...] | None = ()  # the restart policy of each running container, None when they cannot be read
    driver_reads: int = 0  # how often `docker info` was asked

    def _read_docker_driver(self) -> str | None:
        self.driver_reads += 1
        return self.docker_driver

    @property
    def boundaries(self) -> system_step.Boundaries:
        return system_step.Boundaries(lambda: self.terminal, self.playbook, lambda: self.user, self._read_docker_driver, lambda: self.running_policies)


class FakeClock:
    """A monotonic clock that moves `step` seconds on every reading, so a run that reads it at its start and its end took `step`."""

    def __init__(self, step: float = 47.9) -> None:
        self.step = step
        self._reading = -step

    def __call__(self) -> float:
        self._reading += self.step
        return self._reading


@dataclass(frozen=True)
class Sandbox:
    """A throwaway HOME whose global git config, `uv`, scanner and system step are stubs; nothing reaches the operator's own or sudo."""

    home: Path
    global_git_config: Path
    uv_calls: Path
    system: FakeSystem

    @property
    def layout(self) -> Layout:
        return Layout(self.home)

    @property
    def secrets_boundaries(self) -> SecretsBoundaries:
        """The wizard's boundaries over the one sandbox terminal; asking a person, opening a page, the network and the disk sync fail the test."""

        def never(*_arguments: object) -> NoReturn:
            pytest.fail("the sandbox terminal answers no question, opens no page and reaches no network")

        terminal = SecretsTerminal(lambda: self.system.terminal, never, never, never)
        return SecretsBoundaries(terminal, never, never)


class RunnerWithCleanLogs(RunnerWithRealGitAndQuality):
    """The logs check reads docker and journalctl; this machine runs no container and its journal is young."""

    container_listing = ""
    platform_listing = ""  # what `docker inspect` answers the platform check: name, state, health, exit code, compose project or nothing per line

    def __call__(self, argv: Sequence[str]) -> str | None:
        if argv[0] == "journalctl":
            return f'[{{"index":0,"first_entry":{int(time.time() * 1_000_000)}}}]'
        if argv[:2] == ["docker", "inspect"] and argv[3] != logs_check.INSPECT_FORMAT:
            self.calls.append(list(argv))
            return self.platform_listing if argv[3] == ALLOWED_PLATFORM_INSPECT_FORMAT else CANARY_INSPECT_LINE
        if argv[0] == "docker" and (argv[1] in {"ps", "inspect"} or "{{.LoggingDriver}}" in argv):
            self.calls.append(list(argv))
            return {"ps": "id0\n" if self.container_listing or self.platform_listing else "", "info": "journald\n", "inspect": self.container_listing or "/quiet-1\tjournald\t\n"}[argv[1]]
        if argv[0] == "sh":
            self.calls.append(list(argv))
            return run_command(argv)
        return super().__call__(argv)


def write_backup_status(home: Path, state: str = "ok", last_backup: datetime | None = None) -> None:
    last_backup = last_backup or datetime.now().astimezone()
    document = {"schema": 2, "state": state, "last_attempt": last_backup.isoformat(), "failing_app": None, "exit_category": None}
    document["apps"] = {"songmaker": {"last_successful_backup": last_backup.isoformat()}}
    status_file = home / backup_check.STATUS_FILE
    status_file.parent.mkdir(parents=True, exist_ok=True)
    status_file.write_text(json.dumps(document))


def write_hal_config(home: Path, text: str) -> Path:
    """Write hal's settings file under `home`, at the path `hal.config` reads."""
    config_file = hal_config.config_path(home)
    config_file.parent.mkdir(parents=True, exist_ok=True)
    config_file.write_text(text)
    return config_file


def home_check(
    home: Path,
    runner,
    probe: FakeProbe | None = None,
    disk: FakeDisk | None = None,
    *,
    arguments: Sequence[str] = (),
    listeners: str = "",
    docker_script: str = "exit 0",
) -> int:
    """`hal check` through `hal.cli.main`, over the given home and runner instead of this machine; the exposure scan runs shimmed `docker` and `ss`."""

    def build_ports():
        return home_ports.build_layout_and_ports(home=home, run=runner, probe=probe or FakeProbe(), disk_space=disk or FakeDisk())

    shims = home.parent / "host-shims"
    host_support.write_host_shims(shims, listeners, docker_script)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(check_commands, "build_layout_and_ports", build_ports)
        patch.setenv("PATH", f"{shims}{os.pathsep}{os.environ['PATH']}")
        return hal_cli.main(["check", *arguments])


def run_hal_secrets(home: Path, probe: FakeProbe, *options: str, now: datetime | None = None, runner=None) -> int:
    """`hal secrets` through `hal.cli.main`, over the given home and probe instead of this machine."""

    def build_ports():
        return home_ports.build_layout_and_ports(home=home, run=runner, probe=probe, now=now)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(secrets_commands, "build_layout_and_ports", build_ports)
        return hal_cli.main(["secrets", *options])


def run_hal_setup(*flags: str, answer: str | type[BaseException] | None = "yes", **port_overrides) -> int:
    """`hal setup` through `hal.cli.main`, over the given ports (`home`, `run`, `probe`, `now`, `clock`, `secrets_setup_boundaries`, `system_boundaries`) instead of this machine's.

    `answer` is what the person types at the yes prompt: a line, `None` for EOF, or an exception class raised as Ctrl-C is.
    """

    def build_ports():
        return home_ports.build_layout_and_ports(**port_overrides)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(setup_commands, "build_layout_and_ports", build_ports)
        type_at_prompt(patch, answer)
        return hal_cli.main(["setup", *flags])


YES_PROMPT = re.compile(r"Type yes to [^:\n]*: ")


def split_at_the_prompt(output: str) -> tuple[list[str], list[str]]:
    """The stdout lines before the yes prompt (the plan) and after it (the run); an output without a prompt is all plan."""
    prompt = YES_PROMPT.search(output)
    if prompt is None:
        return output.splitlines(), []
    return output[: prompt.start()].splitlines(), output[prompt.end() :].splitlines()


def run_captured_hal_setup(capsys: pytest.CaptureFixture[str], *flags: str, **port_overrides) -> tuple[int, list[str], str]:
    """`run_hal_setup`, with what it printed: the exit code, the stdout lines of the run (all of them when no yes was asked) and the stderr text."""
    code = run_hal_setup(*flags, **port_overrides)
    captured = capsys.readouterr()
    return code, lines_of_the_run(captured.out), captured.err


def lines_of_the_run(output: str) -> list[str]:
    """What `hal setup` printed after the yes; an output that asked no yes is all of it."""
    plan, run = split_at_the_prompt(output)
    return run if YES_PROMPT.search(output) else plan


UNEXPECTED_ERROR_PREFIX = "error: unexpected error ("


def run_report_command(command: str, home: Path, runner, probe: FakeProbe) -> int:
    if command == "check":
        return home_check(home, runner, probe)
    return run_hal_secrets(home, probe, runner=runner)


REPORT_DISPLAY = "~/.local/state/hal/check-report.md"


def restarting_containers(runner, *names: str) -> None:
    """A finding at Handlungsbedarf: each container restarts all the time (#415 Z3)."""
    runner.platform_listing = "".join(f"/{name}-1\trestarting\t\t0\t{name}\n" for name in names or ("edge-a",))


def no_container_restarts(runner) -> None:
    runner.platform_listing = ""


def message_of(sent: SentMail) -> email.message.EmailMessage:
    return email.message_from_string(sent.stdin, policy=email.policy.default)  # type: ignore[return-value]


COMMIT_HOOK, PATH, TIMERS, SYSTEM, SECRETS = "commit hook", "path", "timers", "system", "secrets"


# The sandbox declares no timer job: the timers have nothing to change, and no secret is open.
SUDO_ANNOUNCEMENT = "  › system          needs sudo     tunnel, polkit, journal, mail, agent account"
FRESH_APPLY = [
    "  ✓ commit hook     changed",
    "  · path            unchanged",
    "  · timers          unchanged",
    SUDO_ANNOUNCEMENT,
    "  ✓ system          changed",
    "  · secrets         complete",
    "✓ setup done · 2 changed, 3 unchanged · 47s",
]
REPEATED_APPLY = [
    "  · commit hook     unchanged",
    "  · path            unchanged",
    "  · timers          unchanged",
    SUDO_ANNOUNCEMENT,
    "  · system          unchanged",
    "  · secrets         complete",
    "✓ setup done · 5 unchanged · 47s",
]

NOT_RUN = {
    PATH: "  · path            not run",
    TIMERS: "  · timers          not run",
    SYSTEM: "  · system          not run",
    SECRETS: "  · secrets         not run",
}


def run_setup(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], *flags: str) -> tuple[int, list[str], str]:
    return run_captured_hal_setup(capsys, *flags, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries)


def global_hooks_path(sandbox: Sandbox) -> str:
    completed = subprocess.run(["git", "config", "--global", "--get", "core.hooksPath"], capture_output=True, text=True, check=False)
    return completed.stdout.strip()
