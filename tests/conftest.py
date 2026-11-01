"""The scripted Docker host, the CLI driver, the network backstop, the shimmed host commands and the
workstation fixtures that test modules share."""

import json
import os
import shutil
import signal
import socket
import time
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest
from support.backup_support import (
    CANARY_PASSWORD,
    SONGMAKER_TOML,
    Machine,
    Outcome,
)
from support.host_support import write_host_shims
from support.live_stack import LIVE_STACK_PORTS
from support.workstation_support import (
    FAKE_MISE_SHA256,
    HOME_README,
    RECORDED_RECEIPT_GIT,
    STUB_QUALITY,
    STUB_UV,
    TEST_MANIFEST,
    TEST_TUNNEL_ID,
    FakeClock,
    FakeDisk,
    FakePlaybook,
    FakeProbe,
    FakeSystem,
    MailStub,
    RecordingRunner,
    Sandbox,
    plant_secrets,
    run_hal_setup,
    serve_fake_mise,
    set_up_mail,
    write_backup_status,
    write_executable,
)

from hal import cli
from hal.backup import host
from hal.grammar import ExitCode
from hal.stack import appkit_step
from hal.workstation import check, jobs, secrets_view, setup, system_step, tunnel_config
from hal.workstation import ports as home_ports

LOOPBACK_ADDRESSES = {"127.0.0.1", "::1"}


@pytest.fixture
def seed_appkit() -> Callable[[Path], Path]:
    """Puts the installed appkit's files where the step writes them (every target) in a fake
    repository, as a finished apply leaves them; returns the repository. A fixture, because a test
    module that imports from `conftest` breaks in a full run."""

    def seed(repository: Path) -> Path:
        for target in appkit_step.served_directories(repository):
            shutil.copytree(appkit_step.installed_static(), target)
        return repository

    return seed


@pytest.fixture
def loopback_only(monkeypatch):
    """The backstop: whatever a test builds, a connection beyond loopback or to the live stack's
    ports fails loudly, before the real connect runs."""
    real_connect = socket.socket.connect

    def connect(self, address):
        if self.family in (socket.AF_INET, socket.AF_INET6):
            if address[0] not in LOOPBACK_ADDRESSES:
                raise AssertionError(f"a test connection leaves loopback: {address[0]}")
            if address[1] in LIVE_STACK_PORTS:
                raise AssertionError(
                    f"a test connection reaches the live stack: {address[0]}:{address[1]}"
                )
        return real_connect(self, address)

    monkeypatch.setattr(socket.socket, "connect", connect)


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("HOME", str(tmp_path))
    (tmp_path / "backups/restic").mkdir(parents=True)
    (tmp_path / "backups/restic/config").write_text("restic repository config")
    password = tmp_path / ".secrets/restic/password"
    password.parent.mkdir(parents=True, mode=0o700)
    password.write_text(CANARY_PASSWORD)
    password.chmod(0o600)
    return tmp_path


@pytest.fixture
def fake_host(monkeypatch, tmp_path):
    """A `docker` without containers and an `ss` printing the listeners, first on PATH; `docker`
    can run another script."""
    directory = tmp_path / "bin"

    def install(listeners: str = "", docker_script: str = "exit 0") -> None:
        write_host_shims(directory, listeners, docker_script)
        monkeypatch.setenv("PATH", f"{directory}:{os.environ['PATH']}")

    return install


@pytest.fixture
def restored_signal_handlers() -> Iterator[None]:
    saved = {name: signal.getsignal(name) for name in (signal.SIGTERM, signal.SIGINT)}
    yield
    for name, handler in saved.items():
        signal.signal(name, handler)


@pytest.fixture
def berlin_time(monkeypatch) -> Iterator[None]:
    monkeypatch.setenv("TZ", "Europe/Berlin")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.fixture
def machine(monkeypatch, home) -> Machine:
    machine = Machine(status_file=home / ".local/state/edge/backup-status.json")
    monkeypatch.setattr(host, "run", machine.run)
    monkeypatch.setattr(host, "now", machine.clock.now)
    monkeypatch.setattr(host, "monotonic", machine.clock.monotonic)
    monkeypatch.setattr(host, "sleep", machine.clock.sleep)
    return machine


def _status_if_readable(status_file: Path) -> dict | None:
    """A status a run refused to touch may be unreadable or no JSON: then there is none to read."""
    if not status_file.exists() or not os.access(status_file, os.R_OK):
        return None
    try:
        return json.loads(status_file.read_text())
    except ValueError:
        return None


@pytest.fixture
def edge_backup(machine, home, capsys):
    (home / "songmaker-only.toml").write_text(SONGMAKER_TOML)
    songmaker_only = ("--apps", str(home / "songmaker-only.toml"))

    def run(*arguments: str) -> Outcome:
        """Songmaker alone unless the test declares its apps: most cases are about one app.
        hal has no global option, so a test's `--apps FILE` is moved behind the verb."""
        arguments_list = list(arguments)
        if "--apps" in arguments_list:
            at = arguments_list.index("--apps")
            declared = arguments_list[at : at + 2]
            del arguments_list[at : at + 2]
        else:
            declared = list(songmaker_only)
        exit_code = cli.main([*arguments_list, *declared])
        captured = capsys.readouterr()
        status_file = home / ".local/state/edge/backup-status.json"
        status = _status_if_readable(status_file)
        return Outcome(exit_code, captured.out, captured.err, status)

    return run


@pytest.fixture(autouse=True)
def empty_log_directory(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The logs check looks at /var/log, which this machine fills; the tests look at an empty
    directory."""
    monkeypatch.setattr(check, "LOG_DIRECTORY", tmp_path / "var-log")


@pytest.fixture
def fake_disk() -> FakeDisk:
    """A runner's disk may be over 90 % full, and a nearly full disk is an action: a `hal check`
    test hands in this roomy fake."""
    return FakeDisk()


@pytest.fixture(autouse=True)
def stand_in_tunnel_config(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> Path:
    """The tunnel config at /etc names this machine's tunnel; the tests read a stand-in naming a
    test tunnel."""
    config = tmp_path_factory.mktemp("etc-cloudflared") / "config.yml"
    config.write_text(f"tunnel: {TEST_TUNNEL_ID}\n")
    monkeypatch.setattr(tunnel_config, "TUNNEL_CONFIG", config)
    return config


@pytest.fixture
def use_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Callable[[str], Path]:
    """Points `hal secrets` at a manifest written from the given text."""

    def use(text: str) -> Path:
        path = tmp_path / "secrets_manifest.toml"
        path.write_text(text)
        monkeypatch.setattr(secrets_view, "MANIFEST_PATH", path)
        return path

    return use


@pytest.fixture
def furnish_clean_home(use_manifest: Callable[[str], Path]) -> Callable[[Path], Path]:
    """Makes a home directory one with nothing to report: the README knows every entry and every
    secret of the test manifest is in place."""

    def furnish(home: Path) -> Path:
        use_manifest(TEST_MANIFEST)
        home.mkdir(exist_ok=True)
        (home / "README.md").write_text(HOME_README)
        plant_secrets(home)
        return home

    return furnish


@pytest.fixture
def clean_home(tmp_path: Path, furnish_clean_home: Callable[[Path], Path]) -> Path:
    return furnish_clean_home(tmp_path / "home")


@pytest.fixture
def runner() -> RecordingRunner:
    return RecordingRunner()


@pytest.fixture
def probe() -> FakeProbe:
    return FakeProbe()


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Sandbox:
    home = tmp_path / "home"
    home.mkdir()
    stub_bin = tmp_path / "stub-bin"
    stub_bin.mkdir()
    write_executable(stub_bin / "uv", STUB_UV)
    write_executable(tmp_path / "stub-quality", STUB_QUALITY)
    global_git_config = tmp_path / "global-gitconfig"
    global_git_config.write_text(
        "[user]\n\tname = Test\n\temail = test@example.invalid\n[init]\n\tdefaultBranch = main\n"
    )
    uv_calls = tmp_path / "uv-calls"
    for name, value in {
        "HOME": str(home),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "GIT_CONFIG_GLOBAL": str(global_git_config),
        "GIT_CONFIG_SYSTEM": os.devnull,
        "PATH": f"{stub_bin}{os.pathsep}{os.environ['PATH']}",
        "STUB_QUALITY": str(tmp_path / "stub-quality"),
        "STUB_UV_LOG": str(uv_calls),
        "STUB_RECEIPT_GIT": RECORDED_RECEIPT_GIT,
    }.items():
        monkeypatch.setenv(name, value)
    for name in ("STUB_UV_FAIL", "STUB_ENGINES_FAIL", "STUB_SCAN_EXIT", "HOME_GIT_HOOK_CHAINED"):
        monkeypatch.delenv(name, raising=False)
    # No timer job and a failing `systemctl`: no `hal setup` test reaches a user manager.
    monkeypatch.setattr(jobs, "TIMER_JOBS", ())
    write_executable(stub_bin / "systemctl", "#!/bin/sh\nexit 1\n")
    # The packaged manifest names secrets this sandbox home lacks; the secrets step of `hal setup`
    # looks at none unless a test names some.
    empty_manifest = tmp_path / "empty-secrets-manifest.toml"
    empty_manifest.write_text("secret = []\n")
    monkeypatch.setattr(secrets_view, "MANIFEST_PATH", empty_manifest)
    system = FakeSystem(FakePlaybook())
    monkeypatch.setattr(system_step, "TERMINAL_BOUNDARIES", system.boundaries)
    monkeypatch.setattr(home_ports, "MONOTONIC_CLOCK", FakeClock())
    # No test downloads: the pinned mise is a stub, and its pin is the stub's hash.
    monkeypatch.setattr(home_ports, "DOWNLOAD", serve_fake_mise)
    monkeypatch.setattr(setup, "MISE_SHA256", FAKE_MISE_SHA256)
    return Sandbox(home, global_git_config, uv_calls, system)


@pytest.fixture
def executable_staging_grants(monkeypatch: pytest.MonkeyPatch) -> list[bytes]:
    """The bytes of every staged mise when made executable: proof rejected bytes never are."""
    grants: list[bytes] = []
    real_chmod = Path.chmod

    def record_grant(path: Path, mode: int, **options: bool) -> None:
        if mode & 0o111 and path.name.startswith(".mise-"):
            grants.append(path.read_bytes())
        real_chmod(path, mode, **options)

    monkeypatch.setattr(Path, "chmod", record_grant)
    return grants


@pytest.fixture
def quiet_pc(
    sandbox: Sandbox, clean_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The check's reporting and news are tested on a PC whose other checks are clean: no pending
    reboot (this machine's flag is not read), a backup that ran today and a set-up hook."""
    monkeypatch.setattr(check, "REBOOT_REQUIRED_FILE", tmp_path / "reboot-required")
    write_backup_status(clean_home)
    assert (
        run_hal_setup(home=clean_home, secrets_setup_boundaries=sandbox.secrets_boundaries)
        == ExitCode.OK
    )


@pytest.fixture
def mail_stub(clean_home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> MailStub:
    return set_up_mail(clean_home, tmp_path, monkeypatch)
