"""`hal setup` against a sandboxed HOME with stub `uv`, `quality`, `mise` and Ansible; the rules are those of #22 and, for the system step, #40."""

from __future__ import annotations

import os
import socket
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

import pytest
from support.workstation_support import (
    COMMIT_HOOK,
    FAKE_MISE,
    FRESH_APPLY,
    FakeClock,
    NOT_RUN,
    PATH,
    REPEATED_APPLY,
    RecordingDownload,
    SECRETS,
    STALE_MISE,
    SUDO_ANNOUNCEMENT,
    SYSTEM,
    Sandbox,
    TIMERS,
    bin_entries,
    cut_off_mid_transfer,
    fail_to_write,
    global_hooks_path,
    move_stub_scanner_pins,
    plant_mise,
    remove_stub_scanners,
    run_captured_hal_setup,
    run_hal_setup,
    run_setup,
    serve_half,
    serve_wrong_bytes,
    stub_scanner_manifest_dir,
    time_out,
)

from hal import cli as hal_cli
from hal.grammar import ExitCode
from hal.workstation import ports, system_step
from hal.workstation.layout import Layout
from hal.workstation.secrets_setup import Boundaries, Terminal
from hal.workstation.setup import ANSIBLE_SOURCE, HOOK_NAMES, MISE_URL, QUALITY_SOURCE, RERUN
from hal.workstation.system_step import AGENT_USER

ROWS = [COMMIT_HOOK, PATH, TIMERS, SYSTEM, SECRETS]


NOT_CHECKED_WITHOUT_ANSIBLE = (
    "  ! system          not checked    needs Ansible, which `hal setup` installs first"
)
CHANGED_ROW = {
    COMMIT_HOOK: "  ✓ commit hook     changed",
    SYSTEM: "  ✓ system          changed",
}


GENERATED_SECRET = '''
[[secret]]
name = "opentofu/passphrase"
kind = "service-password"
paths = ["~/.secrets/opentofu/passphrase"]
read_by = ["hal apply"]
recreate = "hal setup"
'''


QUALITY_URL = "https://github.com/overnightworks/quality"


def test_the_verdict_shows_the_time_the_run_took_by_the_clock_the_ports_carry(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """#500: setup measures from its start to its verdict with the monotonic clock of its ports."""

    code = run_hal_setup("--dry-run", home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries, clock=FakeClock(65))

    assert (code, capsys.readouterr().out.splitlines()[-1]) == (
        0,
        "~ setup plan · 2 open, 3 unchanged · 1m05s · run hal setup",
    )


def uv_installs(sandbox: Sandbox) -> list[str]:
    return sandbox.uv_calls.read_text().splitlines() if sandbox.uv_calls.exists() else []


def scanner_installs(sandbox: Sandbox) -> list[str]:
    """The arguments of every `install` the stub mise was asked for."""
    calls = sandbox.mise_calls.read_text().splitlines() if sandbox.mise_calls.exists() else []
    return [call for call in calls if " install " in f"{call} "]


def locked_install_in_the_manifest_dir(sandbox: Sandbox) -> str:
    return f"--cd {stub_scanner_manifest_dir(sandbox.layout).resolve()} install --locked"


def test_setup_without_apply_only_reports_and_changes_nothing(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4 and E1: `hal setup` prints what it would change; before Ansible is installed the system step is not checked."""
    code, lines, error = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines, error) == (
        ExitCode.OK,
        [
            "  ~ commit hook     will change",
            "  · path            unchanged",
            "  · timers          unchanged",
            NOT_CHECKED_WITHOUT_ANSIBLE,
            "  · secrets         complete",
            "~ setup plan · 2 open, 3 unchanged · 47s · run hal setup",
        ],
        "",
    )
    assert uv_installs(sandbox) == []
    assert scanner_installs(sandbox) == []
    assert sandbox.system.playbook.calls == []
    assert global_hooks_path(sandbox) == ""
    assert not sandbox.layout.git_hooks_dir.exists()


def test_apply_installs_pinned_quality_its_scanners_and_both_hooks_then_activates(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4, steps 1-4 and rule 2: the pinned sources are installed, the scanners from quality's own manifest and lock, hooks are mode 755, hooksPath is the rendered directory."""
    code, lines, _ = run_setup(sandbox, capsys)

    layout = sandbox.layout
    assert (code, lines) == (ExitCode.OK, FRESH_APPLY)
    assert uv_installs(sandbox) == [
        f"tool install --force {QUALITY_SOURCE}",
        f"tool install --force {ANSIBLE_SOURCE}",
    ]
    assert scanner_installs(sandbox) == [locked_install_in_the_manifest_dir(sandbox)]
    assert [oct((layout.git_hooks_dir / name).stat().st_mode & 0o777) for name in HOOK_NAMES] == [
        "0o755",
        "0o755",
    ]
    assert global_hooks_path(sandbox) == str(layout.git_hooks_dir)


def test_a_dry_run_with_a_terminal_announces_no_sudo(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """#498: the announcement belongs to an apply; a dry run asks for the password in the check, and prints no `needs sudo` row."""
    run_setup(sandbox, capsys)
    _, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert SUDO_ANNOUNCEMENT not in lines


def test_second_apply_reports_every_step_unchanged_and_reinstalls_nothing(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4 example and #40 cell 9: a second --apply is `unchanged` for every step and reinstalls neither tool."""
    run_setup(sandbox, capsys)
    code, lines, _ = run_setup(sandbox, capsys)

    assert (code, lines) == (ExitCode.OK, REPEATED_APPLY)
    assert len(uv_installs(sandbox)) == 2
    assert len(scanner_installs(sandbox)) == 1


def test_a_walk_that_stored_everything_ends_setup_with_its_verdict_and_next_hal_apply(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], use_manifest
) -> None:
    """#503: the wizard prints no ending; the verdict of `hal setup` is followed by `next: hal apply`."""
    use_manifest(GENERATED_SECRET)
    at_the_keyboard = Boundaries(Terminal(lambda: True, lambda _: "", lambda _: "", lambda _: True), lambda *_: None, lambda _: None)

    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=at_the_keyboard)
    lines = capsys.readouterr().out.splitlines()

    assert code == ExitCode.OK
    assert "  ✓ secrets         stored" in lines
    assert lines[-2:] == ["✓ setup done · 3 changed, 2 unchanged · 47s", "next: hal apply"]
    assert [line for line in lines if line.startswith("next:") or "offen" in line] == ["next: hal apply"]


def test_failing_quality_install_leaves_hooks_path_untouched_and_exits_nonzero(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule 4 counterexample: when `uv tool install` fails, core.hooksPath is unchanged and the step is named."""
    monkeypatch.setenv("STUB_UV_FAIL", "1")

    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines) == (
        ExitCode.FAILURE,
        [
            "  ✗ commit hook     failed         uv could not install quality",
            NOT_RUN[PATH], NOT_RUN[TIMERS], NOT_RUN[SYSTEM], NOT_RUN[SECRETS],
        ],
    )
    assert error.splitlines()[0] == "error: setup stopped at commit hook"
    assert error.splitlines()[1].startswith("next: uv tool install --force ")
    assert global_hooks_path(sandbox) == ""
    assert not sandbox.layout.git_hooks_dir.exists()


def test_failing_scanner_install_stops_before_hooks_and_activation_and_names_the_install_command(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Rule 4: apply stops at the first failure, naming the step and the exact command that installs the scanners; activation never runs after it."""
    monkeypatch.setenv("STUB_MISE_INSTALL_FAIL", "1")

    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines) == (
        ExitCode.FAILURE,
        [
            "  ✗ commit hook     failed         mise could not install quality's scanners",
            NOT_RUN[PATH], NOT_RUN[TIMERS], NOT_RUN[SYSTEM], NOT_RUN[SECRETS],
        ],
    )
    assert error.splitlines() == [
        "error: setup stopped at commit hook",
        f"next: {sandbox.layout.mise_executable} {locked_install_in_the_manifest_dir(sandbox)}",
    ]
    assert global_hooks_path(sandbox) == ""
    assert not sandbox.layout.git_hooks_dir.exists()


@pytest.mark.parametrize("damage", [move_stub_scanner_pins, remove_stub_scanners], ids=["quality pins other versions", "scanners removed"])
def test_a_scanner_that_is_not_installed_at_the_pinned_version_is_installed_again(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], damage: Callable[[Layout], None]
) -> None:
    """Rule 4: the scanner step is current only while mise locates the hook's scanner at the version quality's manifest pins."""
    run_setup(sandbox, capsys)
    damage(sandbox.layout)

    planned = run_setup(sandbox, capsys, "--dry-run")
    repaired = run_setup(sandbox, capsys)
    again = run_setup(sandbox, capsys)

    assert (planned[1][0], repaired[1][0]) == ("  ~ commit hook     will change", "  ✓ commit hook     changed")
    assert scanner_installs(sandbox) == [locked_install_in_the_manifest_dir(sandbox)] * 2
    assert again[1] == REPEATED_APPLY


@pytest.mark.parametrize(
    "damage",
    [lambda layout: layout.quality_python.unlink(), lambda layout: (stub_scanner_manifest_dir(layout) / "mise.toml").unlink()],
    ids=["interpreter gone", "manifest gone"],
)
def test_a_quality_installation_without_its_scanner_manifest_stops_before_the_hooks_and_names_the_reinstall(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], damage: Callable[[Layout], None]
) -> None:
    """Rule 4: without the manifest quality ships no scanner can be installed, so the step fails and the next line reinstalls quality."""
    run_setup(sandbox, capsys)
    damage(sandbox.layout)

    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines[0]) == (ExitCode.FAILURE, "  ✗ commit hook     failed         quality's installation shows no scanner manifest")
    assert error.splitlines() == ["error: setup stopped at commit hook", f"next: uv tool install --force '{QUALITY_SOURCE}'"]


def test_failing_activation_is_a_failed_last_step(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4 step 4: a global config git cannot write fails the activation step."""
    sandbox.global_git_config.unlink()
    sandbox.global_git_config.mkdir()

    code, lines, error = run_setup(sandbox, capsys)

    assert (code, lines) == (
        ExitCode.FAILURE,
        [
            "  ✗ commit hook     failed         git could not set core.hooksPath",
            NOT_RUN[PATH], NOT_RUN[TIMERS], NOT_RUN[SYSTEM], NOT_RUN[SECRETS],
        ],
    )
    assert error.splitlines() == [
        "error: setup stopped at commit hook",
        f"next: git config --global core.hooksPath {sandbox.layout.git_hooks_dir}",
    ]
    assert sandbox.system.playbook.calls == []


def test_apply_repoints_a_hooks_path_that_differs(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4 step 4: core.hooksPath is set when it differs from the rendered directory."""
    subprocess.run(["git", "config", "--global", "core.hooksPath", "/elsewhere"], check=True)

    code, lines, _ = run_setup(sandbox, capsys)

    assert (code, lines[0]) == (ExitCode.OK, "  ✓ commit hook     changed")
    assert global_hooks_path(sandbox) == str(sandbox.layout.git_hooks_dir)


def test_apply_reinstalls_a_deleted_quality_executable_despite_matching_uv_metadata(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rule 4 step 1 recovery: matching receipt, deleted executable, so quality is reinstalled and reported `changed`."""
    run_setup(sandbox, capsys)
    sandbox.layout.quality_executable.unlink()

    code, lines, _ = run_setup(sandbox, capsys)

    assert (code, lines) == (
        0,
        [
            "  ✓ commit hook     changed",
            *REPEATED_APPLY[1:-1],
            "✓ setup done · 1 changed, 4 unchanged · 47s",
        ],
    )
    assert len(uv_installs(sandbox)) == 3


@pytest.mark.parametrize(
    ("step", "row", "receipt"),
    [
        ("quality", COMMIT_HOOK, "not toml ["),
        ("quality", COMMIT_HOOK, "[tool]\nrequirements = []\n"),
        (
            "quality",
            COMMIT_HOOK,
            f'[tool]\nrequirements = [{{ name = "overnightworks-quality", git = "{QUALITY_URL}?rev=0000" }}]\n',
        ),
        (
            "Ansible",
            SYSTEM,
            '[tool]\nrequirements = [{ name = "ansible-core", specifier = "==2.0.0" }]\n',
        ),
    ],
    ids=["unreadable", "no requirement", "other revision", "other Ansible version"],
)
def test_apply_reinstalls_a_tool_when_uv_recorded_another_requirement(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], step: str, row: str, receipt: str
) -> None:
    """Rule 4 step 1 and #40 rule 1: a requirement uv recorded that is not the pinned source triggers the install."""
    run_setup(sandbox, capsys)
    receipt_path = sandbox.layout.quality_uv_receipt if step == "quality" else sandbox.layout.ansible_uv_receipt
    receipt_path.write_text(receipt)

    code, lines, _ = run_setup(sandbox, capsys)

    assert code == ExitCode.OK
    assert CHANGED_ROW[row] in lines


@pytest.mark.parametrize("damage", ["lost executable bit", "other content"])
def test_apply_repairs_a_damaged_hook_file_and_a_following_apply_is_unchanged(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], damage: str
) -> None:
    """Rule 4 step 3 recovery: a hook without mode 755 or with other content is rewritten and reported `changed`."""
    run_setup(sandbox, capsys)
    hook = sandbox.layout.git_hooks_dir / HOOK_NAMES[0]
    if damage == "other content":
        hook.write_text("#!/bin/sh\nexit 0\n")
    else:
        hook.chmod(0o644)

    repaired = run_setup(sandbox, capsys)
    again = run_setup(sandbox, capsys)

    assert repaired[1][0] == "  ✓ commit hook     changed"
    assert os.access(hook, os.X_OK)
    assert again[1] == REPEATED_APPLY


def test_unwritable_hook_directory_fails_the_hook_step_by_name_and_skips_activation(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    """Rule 4: a filesystem failure in the Hook-Dateien step names the step and exits 1, not the generic error."""
    sandbox.layout.git_hooks_dir.parent.parent.mkdir(parents=True)
    sandbox.layout.git_hooks_dir.parent.write_text("a file where the hooks parent directory belongs")

    code, lines, error = run_setup(sandbox, capsys)

    assert code == ExitCode.FAILURE
    assert lines[0].startswith("  ✗ commit hook     failed         could not write the hook files:")
    assert error.splitlines() == ["error: setup stopped at commit hook", f"next: {RERUN}"]
    assert global_hooks_path(sandbox) == ""


def test_dry_run_with_a_non_executable_quality_reports_instead_of_crashing(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 4: the reporting-only `hal setup` copes with a quality that is present but not executable."""
    run_setup(sandbox, capsys)
    sandbox.layout.quality_executable.chmod(0o644)

    code, lines, _ = run_setup(sandbox, capsys, "--dry-run")

    assert (code, lines[0]) == (ExitCode.OK, "  ~ commit hook     will change")


def test_apply_tightens_a_hook_whose_mode_is_wider_than_755(sandbox: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """Rule 3 and rule 4 step 3: the hook is mode 755; a world-writable hook with the right content is repaired."""
    run_setup(sandbox, capsys)
    hook = sandbox.layout.git_hooks_dir / HOOK_NAMES[0]
    hook.chmod(0o777)

    repaired = run_setup(sandbox, capsys)

    assert repaired[1][0] == "  ✓ commit hook     changed"
    assert hook.stat().st_mode & 0o777 == 0o755


def run_setup_with(sandbox: Sandbox, *flags: str, **port_overrides) -> int:
    return run_hal_setup(*flags, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries, **port_overrides)


def test_apply_installs_the_pinned_mise_from_its_release_url_through_a_private_staging_file(sandbox: Sandbox, executable_staging_grants: list[bytes]) -> None:
    """#679: the pinned release binary is downloaded into a file only its owner can touch, made executable once its bytes are complete, then published."""
    download = RecordingDownload()

    code = run_setup_with(sandbox, download=download)

    mise = sandbox.layout.mise_executable
    assert code == ExitCode.OK
    assert download.urls == [MISE_URL]
    assert download.staging_modes == [0o600]
    assert executable_staging_grants == [FAKE_MISE]
    assert (mise.read_bytes(), oct(mise.stat().st_mode & 0o777)) == (FAKE_MISE, "0o755")
    assert bin_entries(sandbox.home) == {"mise", "quality", "ansible-playbook"}


def test_a_dry_run_downloads_nothing_and_a_second_apply_leaves_a_current_mise_alone(sandbox: Sandbox) -> None:
    """#679: the plan before the yes neither downloads nor installs, and a current mise is not fetched again."""
    download = RecordingDownload()
    run_setup_with(sandbox, "--dry-run", download=download)
    assert not sandbox.layout.mise_executable.exists()

    run_setup_with(sandbox, download=download)
    run_setup_with(sandbox, download=download)

    assert len(download.urls) == 1


@pytest.mark.parametrize("answer", ["no", None], ids=repr)
def test_a_refused_yes_installs_no_mise(sandbox: Sandbox, answer: str | None) -> None:
    """#679: not yes and EOF end the run before any step, so no download happens."""
    download = RecordingDownload()

    run_setup_with(sandbox, answer=answer, download=download)

    assert (download.urls, sandbox.layout.mise_executable.exists()) == ([], False)


@pytest.mark.parametrize("damage", [lambda mise: mise.write_bytes(STALE_MISE), lambda mise: mise.chmod(0o644)], ids=["hash drifted", "not executable"])
def test_a_drifted_or_non_executable_mise_is_replaced_by_the_pinned_one(sandbox: Sandbox, damage: Callable[[Path], object]) -> None:
    """#679: the pin is exact, so an unlike file or one that cannot run is put back."""
    mise = plant_mise(sandbox.home, FAKE_MISE)
    damage(mise)

    code = run_setup_with(sandbox)

    assert (code, mise.read_bytes(), oct(mise.stat().st_mode & 0o777)) == (ExitCode.OK, FAKE_MISE, "0o755")


def test_the_agents_account_installs_mise_and_quality_s_scanners_in_its_own_home(sandbox: Sandbox) -> None:
    """The agents' own run needs the pinned scan, so it installs mise and the scanners in its own home."""
    sandbox.system.user = AGENT_USER

    code = run_setup_with(sandbox)

    assert (code, sandbox.layout.mise_executable.read_bytes()) == (ExitCode.OK, FAKE_MISE)
    assert scanner_installs(sandbox) == [locked_install_in_the_manifest_dir(sandbox)]


@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "existing binary"])
@pytest.mark.parametrize(
    ("download", "sentence"),
    [
        (serve_wrong_bytes, "the download of mise does not match its pinned sha256"),
        (serve_half, "the download of mise does not match its pinned sha256"),
        (time_out, "mise could not be downloaded: timed out"),
        (fail_to_write, "mise could not be downloaded: No space left on device"),
        (cut_off_mid_transfer, "mise could not be downloaded: IncompleteRead(10 bytes read, 100 more expected)"),
    ],
    ids=["mismatch", "truncated", "timeout", "write error", "response cut off"],
)
def test_a_failed_download_publishes_nothing_keeps_an_existing_mise_and_leaves_no_staging_file(
    sandbox: Sandbox,
    capsys: pytest.CaptureFixture[str],
    executable_staging_grants: list[bytes],
    download: Callable[[str, BinaryIO], None],
    sentence: str,
    existing: bool,
) -> None:
    """#679: a download that fails or does not hash to the pin fails the commit hook row with its own sentence and never makes its bytes executable."""
    if existing:
        plant_mise(sandbox.home)

    code, lines, _ = run_captured_hal_setup(capsys, home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries, download=download)

    mise = sandbox.layout.mise_executable
    assert (code, lines[0]) == (ExitCode.FAILURE, f"  ✗ commit hook     failed         {sentence}")
    assert (mise.read_bytes() if mise.exists() else None) == (STALE_MISE if existing else None)
    assert bin_entries(sandbox.home) == ({"mise"} if existing else set())
    assert executable_staging_grants == []


@pytest.mark.parametrize("existing", [False, True], ids=["fresh", "existing binary"])
def test_a_failing_rename_keeps_an_existing_mise_and_leaves_no_staging_file(
    sandbox: Sandbox, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch, existing: bool
) -> None:
    """#679: when the verified file cannot be moved into place, the failure is named and the directory is as it was."""
    if existing:
        plant_mise(sandbox.home)
    real_replace = os.replace

    def refuse_mise(source: Path, destination: Path) -> None:
        if Path(destination) == sandbox.layout.mise_executable:
            raise OSError(1, "Operation not permitted")
        real_replace(source, destination)

    monkeypatch.setattr(os, "replace", refuse_mise)

    code, lines, _ = run_setup(sandbox, capsys)

    mise = sandbox.layout.mise_executable
    assert (code, lines[0]) == (ExitCode.FAILURE, "  ✗ commit hook     failed         mise could not be installed: Operation not permitted")
    assert (mise.read_bytes() if mise.exists() else None) == (STALE_MISE if existing else None)
    assert bin_entries(sandbox.home) == ({"mise"} if existing else set())


def test_a_release_download_writes_what_the_url_serves(tmp_path: Path) -> None:
    served = tmp_path / "served"
    served.write_bytes(b"release bytes")

    with (tmp_path / "written").open("wb") as writer:
        ports.download_release(served.as_uri(), writer)

    assert (tmp_path / "written").read_bytes() == b"release bytes"


def test_a_download_whose_server_stays_silent_ends_in_an_os_error(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The download has its own timeout, so a stalled connection fails the step instead of hanging setup."""
    monkeypatch.setattr(ports, "DOWNLOAD_TIMEOUT_SECONDS", 0.2)
    with socket.socket() as silent_server, (tmp_path / "written").open("wb") as writer:
        silent_server.bind(("127.0.0.1", 0))
        silent_server.listen()
        url = f"http://127.0.0.1:{silent_server.getsockname()[1]}/mise"

        with pytest.raises(OSError):
            ports.download_release(url, writer)


def test_setup_help_warns_that_the_system_step_restarts_docker(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        hal_cli.main(["setup", "--help"])

    help_text = " ".join(capsys.readouterr().out.split())
    assert "restarts Docker while its default driver is not journald: every container stops meanwhile" in help_text
    assert "--dry-run" in help_text
    assert "--apply" not in help_text


def test_the_running_user_is_the_operator_the_polkit_rule_names(tmp_path: Path) -> None:
    """Rule 5: @OPERATOR_USER@ is whoever runs `hal setup`, the owner of the files it creates."""
    assert system_step.TERMINAL_BOUNDARIES.operator_user() == tmp_path.owner()
