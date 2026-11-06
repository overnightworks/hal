"""Publish phase of `hal apply`: tokens only in the child, allowlisted environment, pinned tofu."""

import errno
import fcntl
import functools
import inspect
import io
import json
import os
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from pathlib import Path

import pytest
import support.stack_external as stack_external_support
from support.live_stack import LIVE_STACK_PORTS
from support.stack_external import (
    CHANGING_PLAN,
    CLEAN_SNAPSHOT,
    EMPTY_PLAN,
    FAILING_APPLY,
    PLANS_DIRECTORY,
    PROJECT_ROOT,
    STRAY_SNAPSHOT,
    TOKEN_FILES,
    TUNNEL_TARGET,
    WRITE_TOKEN_FILES,
    FakeProber,
    FakeReader,
    RecordingReadyProber,
    commit_catalog,
    plain_git,
    said,
)
from support.stack_host_probe import RAY, Behaviour, serving

from hal.stack import catalog, checkout
from hal.stack.external import apply as external_apply
from hal.stack.external import cli as external_cli
from hal.stack.external import cloudflare_read, host_probe, secrets, tofu

(
    fake_tofu,
    home,
    live_checkout,
    publish,
    terminal,
) = (
    stack_external_support.fake_tofu,
    stack_external_support.home,
    stack_external_support.live_checkout,
    stack_external_support.publish,
    stack_external_support.terminal,
)  # fmt: skip

SENTINEL = "sentinel-4b1d-never-print-me"
ALLOWED_NAMES = {
    "PATH",
    "HOME",
    "LANG",
    "TMPDIR",
    "TF_INPUT",
    "TF_CLI_CONFIG_FILE",
    "CLOUDFLARE_API_TOKEN",
    "TF_VAR_state_passphrase",
}
PROMPT = "to apply exactly this plan"


@pytest.mark.parametrize("token_file", TOKEN_FILES)
def test_a_missing_token_file_exits_2_naming_it_without_running_tofu(
    home, fake_tofu, capsys, token_file, publish
):
    """#40 rule 1: a missing token file stops the run before tofu."""
    (home / token_file).unlink()
    assert publish() == 2
    assert str(home / token_file) in capsys.readouterr().err
    assert fake_tofu.calls() == []


def test_the_tokens_never_reach_the_wrapper_output(home, fake_tofu, capsys, publish):
    """#40 rule 1: tokens reach only the tofu child, never the wrapper output."""
    (home / ".secrets/opentofu/state-passphrase").write_text(SENTINEL)
    fake_tofu.configure(echo_environment=True)
    publish()
    printed = capsys.readouterr()
    assert SENTINEL not in printed.out + printed.err
    assert SENTINEL in json.dumps(fake_tofu.call("plan")["env"])


DROPPED_VARIABLE_FAMILIES = [
    pytest.param(
        {"TF_LOG": "TRACE", "TF_LOG_PATH": "{tmp}/trace", "TF_LOG_PROVIDER": "TRACE"}, id="TF_LOG"
    ),
    pytest.param(
        {"TF_CLI_ARGS": "-lock=false", "TF_CLI_ARGS_plan": "-refresh=false"}, id="TF_CLI_ARGS"
    ),
    pytest.param({"TF_ENCRYPTION": "unenforced-config"}, id="TF_ENCRYPTION"),
    pytest.param({"TF_VAR_state_passphrase": "wrong", "TF_VAR_other": "x"}, id="TF_VAR"),
    pytest.param(
        {"TF_DATA_DIR": "{tmp}/d", "TF_PLUGIN_CACHE_DIR": "{tmp}/c", "TF_WORKSPACE": "w"},
        id="TF_DIRS",
    ),
    pytest.param(
        {"GITHUB_TOKEN": "wrong", "GITHUB_OWNER": "x", "GH_TOKEN": "x", "GH_HOST": "x"},
        id="GITHUB",
    ),
    pytest.param({"CLOUDFLARE_API_TOKEN": "wrong", "CLOUDFLARE_EMAIL": "x"}, id="CLOUDFLARE"),
    pytest.param(
        {"HTTPS_PROXY": "http://p", "http_proxy": "http://p", "ALL_PROXY": "http://p"}, id="PROXY"
    ),
]
TOFU_VERSIONS = [
    pytest.param(None, 0, id="pinned"),
    pytest.param("1.12.0", 2, id="other"),
]


def inherit(monkeypatch, tmp_path, variables):
    for name, value in variables.items():
        monkeypatch.setenv(name, value.format(tmp=tmp_path))


@pytest.mark.parametrize("version,expected_exit", TOFU_VERSIONS)
@pytest.mark.parametrize("inherited", DROPPED_VARIABLE_FAMILIES)
def test_tofu_gets_exactly_the_allowlisted_variables(
    home, fake_tofu, monkeypatch, tmp_path, inherited, version, expected_exit, publish
):
    """#40 rule 2: tofu gets exactly the allowlisted variables, tokens from the files."""
    fake_tofu.configure(version=version)
    inherit(monkeypatch, tmp_path, inherited)
    assert publish() == expected_exit
    environment = fake_tofu.call("version")["env"]
    assert set(environment) == ALLOWED_NAMES
    assert environment["TF_VAR_state_passphrase"] == "file-passphrase"
    assert (
        environment["CLOUDFLARE_API_TOKEN"] == WRITE_TOKEN_FILES[".secrets/cloudflare/fleet-write"]
    )
    assert not (tmp_path / "trace").exists()


def test_the_child_environment_values(home, fake_tofu, publish):
    """#40 rule 2: the allowlisted variables carry the wrapper's own values."""
    publish()
    environment = fake_tofu.call("plan")["env"]
    assert environment["PATH"] == f"{fake_tofu.directory.resolve()}:/usr/bin:/bin"
    assert environment["HOME"] == str(home)
    assert environment["LANG"] == "C.UTF-8"
    assert environment["TF_INPUT"] == "0"
    assert environment["TF_CLI_CONFIG_FILE"] == str(PROJECT_ROOT / "external/tofurc")
    assert Path(environment["TMPDIR"]).parent == home / ".secrets/opentofu/tmp"


def test_every_file_tofu_creates_is_for_the_owner_only_whatever_the_umask_of_the_wrapper(
    home, fake_tofu, publish
):
    """#159 T1: the state tofu writes was 664 under the PC's umask 002."""
    previous = os.umask(0o002)
    try:
        publish()
    finally:
        os.umask(previous)
    assert (fake_tofu.directory / "made-by-tofu").stat().st_mode & 0o777 == 0o600


def test_the_temporary_directory_is_private_and_removed_afterwards(home, fake_tofu, publish):
    """#40 rule 2: TMPDIR is a 0700 directory removed afterwards."""
    publish()
    assert fake_tofu.call("plan")["tmpdir_mode"] == 0o700
    assert list((home / ".secrets/opentofu/tmp").iterdir()) == []


def test_another_tofu_version_exits_2_naming_both_versions(home, fake_tofu, capsys, publish):
    """#40 rule 3: another tofu version exits 2 naming both versions."""
    fake_tofu.configure(version="1.12.0")
    assert publish() == 2
    error = capsys.readouterr().err
    assert "1.12.0" in error
    assert tofu.pinned_version() in error
    assert [call["argv"][0] for call in fake_tofu.calls()] == ["version"]


def test_init_is_locked_non_interactive_and_uses_the_state_in_secrets(home, fake_tofu, publish):
    """#40 rule 3: init is locked, non-interactive and uses the state in secrets."""
    publish()
    assert fake_tofu.call("init")["argv"] == [
        "init",
        "-input=false",
        "-lockfile=readonly",
        f"-backend-config=path={home}/.secrets/opentofu/fleet.tfstate",
    ]
    assert fake_tofu.call("plan")["argv"][:3] == ["plan", "-refresh=true", "-detailed-exitcode"]


def test_a_failed_init_exits_2_without_planning(home, fake_tofu, publish):
    """#40 rule 4: a failed init exits 2 without planning."""
    fake_tofu.configure(init=1)
    assert publish() == 2
    assert [call["argv"][0] for call in fake_tofu.calls()] == ["version", "init"]


@pytest.mark.parametrize(
    "version", [version.values[0] for version in TOFU_VERSIONS], ids=["pinned", "other"]
)
@pytest.mark.parametrize("family", DROPPED_VARIABLE_FAMILIES)
@pytest.mark.parametrize("credential_inherited", [True, False], ids=["inherited", "absent"])
@pytest.mark.parametrize(
    "token_file,variable",
    [
        (".secrets/cloudflare/fleet-read", "CLOUDFLARE_API_TOKEN"),
        (".secrets/cloudflare/fleet-write", "CLOUDFLARE_API_TOKEN"),
        (".secrets/opentofu/state-passphrase", "TF_VAR_state_passphrase"),
    ],
)
def test_a_missing_token_file_is_not_replaced_by_the_inherited_credential(
    home,
    fake_tofu,
    monkeypatch,
    tmp_path,
    capsys,
    token_file,
    variable,
    family,
    version,
    credential_inherited,
    publish,
):
    """#40 rule 1: an inherited credential never stands in for an absent token file."""
    fake_tofu.configure(version=version)
    inherit(monkeypatch, tmp_path, family)
    if credential_inherited:
        monkeypatch.setenv(variable, SENTINEL)
    else:
        monkeypatch.delenv(variable, raising=False)
    (home / token_file).unlink()
    assert publish() == 2
    printed = capsys.readouterr()
    assert str(home / token_file) in printed.err
    assert SENTINEL not in printed.out + printed.err
    assert fake_tofu.calls() == []


def test_a_token_file_that_is_not_utf8_exits_2_without_quoting_it(home, fake_tofu, capsys, publish):
    """#40 rule 4: an unreadable token file is exit 2, not a traceback with exit 1."""
    token_file = home / ".secrets/cloudflare/fleet-read"
    token_file.write_bytes(b"\xff\xfe")
    assert publish() == 2
    assert capsys.readouterr().err == f"{REFUSAL}{token_file} is not valid UTF-8\n"
    assert fake_tofu.calls() == []


def test_a_temporary_parent_that_is_a_file_exits_2_naming_error_and_path(
    home, fake_tofu, capsys, publish
):
    """#40 rule 4: a filesystem failure while preparing the run is exit 2 naming what failed."""
    in_the_way = home / ".secrets/opentofu/tmp"
    in_the_way.write_text("in the way")
    assert publish() == 2
    error = capsys.readouterr().err
    assert "FileExistsError" in error
    assert str(in_the_way) in error
    assert fake_tofu.calls() == []


def test_a_version_report_carrying_a_token_never_prints_it(home, fake_tofu, capsys, publish):
    """#40 rule 1: child-derived diagnostics are redacted before they are printed."""
    write_token = WRITE_TOKEN_FILES[".secrets/cloudflare/fleet-write"]
    fake_tofu.configure(version=write_token)
    assert publish() == 2
    printed = capsys.readouterr()
    assert write_token not in printed.out + printed.err


def test_a_temporary_directory_that_cannot_be_removed_exits_1(home, fake_tofu, capsys, publish):
    """#40 rule 4: a cleanup failure is reported, not reported as success."""
    fake_tofu.configure(leave_undeletable=True)
    try:
        assert publish() == 1
        assert "PermissionError" in capsys.readouterr().err
    finally:
        for locked in (home / ".secrets/opentofu/tmp").glob("*/locked"):
            locked.chmod(0o700)


def test_a_cleanup_failure_never_prints_a_token_named_by_the_child(
    home, fake_tofu, capsys, publish
):
    """#40 rule 1: a child-controlled name in a cleanup failure is redacted."""
    write_token = WRITE_TOKEN_FILES[".secrets/cloudflare/fleet-write"]
    fake_tofu.configure(leave_undeletable=True, locked_name=write_token)
    try:
        assert publish() == 1
        printed = capsys.readouterr()
        assert "PermissionError" in printed.err
        assert write_token not in printed.out + printed.err
    finally:
        for locked in (home / ".secrets/opentofu/tmp").glob(f"*/{write_token}"):
            locked.chmod(0o700)


def test_the_temporary_directory_is_removed_when_the_run_is_interrupted(home):
    """#40 rule 2: Ctrl-C during tofu still removes TMPDIR."""
    with pytest.raises(KeyboardInterrupt), secrets.private_temporary_directory(home) as directory:
        (directory / "child-artifact").write_text("x")
        raise KeyboardInterrupt
    assert list((home / ".secrets/opentofu/tmp").iterdir()) == []


def test_a_cleanup_failure_after_another_version_still_names_both_versions(
    home, fake_tofu, capsys, publish
):
    """#40 rule 3: a failing cleanup does not hide the version mismatch already in flight."""
    fake_tofu.configure(version="1.12.0", leave_undeletable=True)
    try:
        assert publish() == 2
        error = capsys.readouterr().err
        assert "1.12.0" in error
        assert tofu.pinned_version() in error
        assert "cannot remove" in error
    finally:
        for locked in (home / ".secrets/opentofu/tmp").glob("*/locked"):
            locked.chmod(0o700)


def plan_files(home) -> list[Path]:
    return list((home / PLANS_DIRECTORY).glob("*"))


def test_apply_without_a_terminal_exits_1_before_any_tofu_call(home, fake_tofu, capsys):
    """#45 rule 2: stdin or stdout that is no terminal refuses before tofu."""
    assert external_cli.apply_command(home) == 1
    assert "terminal" in capsys.readouterr().err
    assert fake_tofu.calls() == []


def a_linked_worktree_as_the_live_checkout(live_checkout, tmp_path) -> Path:
    main_worktree = tmp_path / "main-worktree"
    live_checkout.rename(main_worktree)
    plain_git(main_worktree, "worktree", "add", "--quiet", "--detach", str(live_checkout))
    return live_checkout


def another_copy(live_checkout, tmp_path) -> Path:
    copy = tmp_path / "copy"
    plain_git(tmp_path, "clone", "--quiet", str(live_checkout), str(copy))
    return copy


def on_a_branch(live_checkout, _tmp_path) -> Path:
    plain_git(live_checkout, "switch", "--quiet", "--create", "feature/x")
    return live_checkout


def detached(live_checkout, _tmp_path) -> Path:
    plain_git(live_checkout, "switch", "--quiet", "--detach")
    return live_checkout


def modified(live_checkout, _tmp_path) -> Path:
    (live_checkout / "external" / "main.tf").write_text("# edited\n")
    return live_checkout


def with_a_stray_tfvars(live_checkout, _tmp_path) -> Path:
    (live_checkout / "external" / "x.auto.tfvars").write_text("zone = 1\n")
    return live_checkout


REFUSAL = "cloudflare: "
LIVE_ONLY = f"{REFUSAL}runs only from the live checkout {checkout.LIVE_CHECKOUT} ("
MAIN_ONLY = f"{REFUSAL}runs only on main ("
APPLY_INTERRUPTED = f"{REFUSAL}interrupted during tofu apply, live services may be partly changed"


@pytest.mark.parametrize(
    ("arrange", "reason"),
    [
        pytest.param(a_linked_worktree_as_the_live_checkout,
                     f"{LIVE_ONLY}a linked worktree, not the main checkout)", id="E1-linked"),
        pytest.param(another_copy, f"{LIVE_ONLY}this is ", id="E2-another-copy"),
        pytest.param(on_a_branch, f"{MAIN_ONLY}this is branch feature/x)", id="E3-branch"),
        pytest.param(detached, f"{MAIN_ONLY}HEAD is detached at ", id="E3-detached"),
        pytest.param(modified, f"{REFUSAL}the live checkout has local changes",
                     id="E4-modified-file"),
        pytest.param(modified, f"{REFUSAL}external/main.tf", id="E4-the-path-on-its-own-line"),
        pytest.param(with_a_stray_tfvars, f"{REFUSAL}external/x.auto.tfvars",
                     id="E5-untracked-tfvars"),
    ],
)  # fmt: skip
def test_apply_outside_a_clean_main_of_the_live_checkout_exits_2_before_any_token_or_tofu(
    home, fake_tofu, terminal, live_checkout, tmp_path, arrange, reason
):
    """#124 rule 2: the reason is named, no token file is read (a missing one is not named)."""
    tree = arrange(live_checkout, tmp_path)
    (home / next(iter(WRITE_TOKEN_FILES))).unlink()
    apply = terminal(tree=tree)
    assert apply.finish() == 2
    assert reason in " ".join(apply.output.split())
    assert str(home / ".secrets") not in apply.output
    assert fake_tofu.calls() == []


def test_apply_from_a_clean_main_ignores_ignored_files(home, fake_tofu, terminal, live_checkout):
    """#124 rule 3, E6: `.terraform/` and a `*.tfplan` are no change."""
    (live_checkout / "external" / ".terraform").mkdir()
    (live_checkout / "external" / ".terraform" / "x").touch()
    (live_checkout / "external" / "x.tfplan").touch()
    fake_tofu.configure(plan=0)
    assert terminal().finish() == 0


def test_apply_with_a_failing_git_exits_2_saying_it_cannot_read_the_checkout(
    home, fake_tofu, terminal
):
    """#124 rule 2, E11."""
    broken_git = fake_tofu.directory / "git"
    broken_git.write_text("#!/bin/sh\nexit 128\n")
    broken_git.chmod(0o755)
    apply = terminal()
    assert apply.finish() == 2
    assert "cloudflare: cannot read the live checkout, " in apply.output
    assert fake_tofu.calls() == []


def git_exiting_128(tree, arguments, profile):
    return subprocess.CompletedProcess(arguments, 128, b"", b"fatal: broken\n")


@pytest.mark.parametrize(
    ("arrange", "git", "exit_code", "stderr_contains"),
    [
        pytest.param(a_linked_worktree_as_the_live_checkout, checkout.run_git, 2,
                     f"{LIVE_ONLY}a linked worktree, not the main checkout)", id="E1-linked"),
        pytest.param(on_a_branch, checkout.run_git, 2,
                     f"{MAIN_ONLY}this is branch feature/x)", id="E3-branch"),
        pytest.param(lambda live, _tmp: live, git_exiting_128, 2,
                     f"{REFUSAL}cannot read the live checkout, ", id="E11-failing-git"),
        pytest.param(lambda live, _tmp: live, checkout.run_git, 42, "", id="E7-clean-main"),
    ],
)  # fmt: skip
def test_apply_command_refuses_off_a_clean_live_main_in_process(
    home,
    fake_tofu,
    capsys,
    monkeypatch,
    live_checkout,
    tmp_path,
    arrange,
    git,
    exit_code,
    stderr_contains,
):
    """#124 rule 2 in process: the terminal refusal is lifted, the tree decides, `git=` is used."""
    monkeypatch.setattr(external_apply, "refusal_without_terminal", lambda: None)
    monkeypatch.setattr(
        external_apply,
        "apply_plan",
        lambda _home, _tokens, **_ports: external_apply.ApplyOutcome(
            42, external_apply.ClosingCheck.NO_CHECK_REFUSED
        ),
    )
    tree = arrange(live_checkout, tmp_path)
    assert external_cli.apply_command(home, tree, git) == exit_code
    error = " ".join(capsys.readouterr().err.split())
    assert stderr_contains in error
    assert (error == "") == (exit_code == 42)


def test_apply_without_a_terminal_from_a_wrong_tree_exits_1_first(
    home, fake_tofu, capsys, live_checkout, tmp_path
):
    """#124 E9: the terminal refusal comes before the tree is asked."""
    assert external_cli.apply_command(home, another_copy(live_checkout, tmp_path)) == 1
    assert "terminal" in capsys.readouterr().err


INVALID_CATALOG = """\
cloudflare: {zone: edge-fixture.invalid}
services:
  songmaker:
    hosts:
      - {name: www, exposure: private}
"""
CATALOG_LINE = "services.songmaker.hosts[0].exposure: must be one of public, bypass, protected"


def without_tokens(home) -> None:
    for token_file in TOKEN_FILES | WRITE_TOKEN_FILES:
        (home / token_file).unlink()


def test_apply_with_an_invalid_catalog_exits_2_before_any_token_or_tofu(
    home, fake_tofu, live_checkout, terminal
):
    """#131 P1: after the terminal and live-main refusals, before the tokens."""
    commit_catalog(live_checkout, INVALID_CATALOG)
    without_tokens(home)
    apply = terminal()
    assert apply.finish() == 2
    assert f"cloudflare: {CATALOG_LINE}" in apply.output
    assert fake_tofu.calls() == []


def test_apply_without_a_terminal_refuses_before_the_catalog_is_read(
    home, fake_tofu, live_checkout, monkeypatch, capsys
):
    """#131 P2: the terminal refusal still comes first."""
    commit_catalog(live_checkout, INVALID_CATALOG)
    monkeypatch.setattr(tofu, "PROJECT_ROOT", live_checkout)
    assert external_cli.apply_command(home) == 1
    assert "terminal" in capsys.readouterr().err


def test_apply_without_a_terminal_exits_1_even_when_the_write_tokens_are_missing(
    home, fake_tofu, capsys
):
    """#45 rule 2: the refusal comes before any token file is read."""
    for write_file in WRITE_TOKEN_FILES:
        (home / write_file).unlink()
    assert external_cli.apply_command(home) == 1
    assert "terminal" in capsys.readouterr().err
    assert fake_tofu.calls() == []


@pytest.mark.parametrize(
    "terminals",
    [
        pytest.param({"stdout_is_terminal": False}, id="stdin-terminal-stdout-redirected"),
        pytest.param({"stdin_is_terminal": False}, id="stdin-redirected-stdout-terminal"),
    ],
)
def test_apply_with_only_one_of_stdin_and_stdout_a_terminal_exits_1_before_tofu(
    home, fake_tofu, terminal, terminals
):
    """#45 rule 2: stdin and stdout must both be terminals."""
    apply = terminal(**terminals)
    assert apply.finish() == 1
    assert apply_line("refused, stdin and stdout must be a terminal") in apply.output
    assert fake_tofu.calls() == []


def test_apply_reads_the_write_tokens_through_the_allowlist(home, fake_tofu, terminal):
    """#45 rule 1: apply uses fleet-write, same environment as plan."""
    fake_tofu.configure(plan=2, echo_environment=True)
    apply = terminal()
    apply.read_until(PROMPT)
    apply.type("yes\n")
    assert apply.finish() == 0
    environment = fake_tofu.call("apply")["env"]
    assert set(environment) == ALLOWED_NAMES
    assert environment["CLOUDFLARE_API_TOKEN"] == "cloudflare-write-token"
    assert "write-token" not in apply.output


@pytest.mark.parametrize("write_file", WRITE_TOKEN_FILES)
def test_a_missing_write_token_exits_2_naming_it_without_running_tofu(
    home, fake_tofu, terminal, write_file
):
    """#45 rule 1: a missing write file stops apply before tofu; the read file is no stand-in."""
    (home / write_file).unlink()
    apply = terminal()
    assert apply.finish() == 2
    assert str(home / write_file) in apply.output
    assert fake_tofu.calls() == []


@pytest.mark.parametrize(
    "typed,expected_exit,applied",
    [
        pytest.param("yes\n", 0, True, id="yes"),
        pytest.param("y\n", 1, False, id="y"),
        pytest.param("Yes\n", 1, False, id="Yes"),
        pytest.param("\n", 1, False, id="empty"),
        pytest.param(" yes\n", 1, False, id="padded"),
        pytest.param("\x04", 1, False, id="end-of-input"),
    ],
)
def test_only_the_exact_yes_applies(home, fake_tofu, terminal, typed, expected_exit, applied):
    """#45 rule 2: only the exact input `yes` proceeds; anything else aborts with exit 1."""
    fake_tofu.configure(plan=2)
    apply = terminal()
    apply.read_until(PROMPT)
    apply.type(typed)
    assert apply.finish() == expected_exit
    assert ("apply" in [call["argv"][0] for call in fake_tofu.calls()]) is applied


def test_apply_applies_exactly_the_encrypted_plan_file_in_the_private_directory(
    home, fake_tofu, terminal
):
    """#45 rules 2 and 3: the shown plan file is in the 0700 plans directory and is what applies."""
    fake_tofu.configure(plan=2)
    apply = terminal()
    apply.read_until(PROMPT)
    assert (home / PLANS_DIRECTORY).stat().st_mode & 0o777 == 0o700
    apply.type("yes\n")
    assert apply.finish() == 0
    out_argument = next(a for a in fake_tofu.call("plan")["argv"] if a.startswith("-out="))
    plan_file = Path(out_argument.removeprefix("-out="))
    assert plan_file.parent == home / PLANS_DIRECTORY
    assert fake_tofu.call("apply")["argv"] == ["apply", str(plan_file)]
    assert fake_tofu.call("apply")["plan_file_existed"]


CLEANUP_PATHS = [
    pytest.param({"plan": 2}, "yes\n", 0, id="success"),
    pytest.param({"plan": 2}, "no\n", 1, id="abort"),
    pytest.param({"plan": 1}, None, 2, id="plan-failure"),
    pytest.param({"plan": 2, "apply": 1}, "yes\n", 1, id="apply-failure"),
    pytest.param({"plan": 2}, signal.SIGINT, 1, id="sigint-at-prompt"),
    pytest.param({"plan": 2}, signal.SIGTERM, 1, id="sigterm-at-prompt"),
    pytest.param({"plan": 2, "hang_in": "apply"}, signal.SIGINT, 1, id="sigint-in-apply"),
    pytest.param({"plan": 2, "hang_in": "apply"}, signal.SIGTERM, 1, id="sigterm-in-apply"),
]


@pytest.mark.parametrize("configuration,reaction,expected_exit", CLEANUP_PATHS)
def test_the_plan_file_is_deleted_on_every_path(
    home, fake_tofu, terminal, configuration, reaction, expected_exit
):
    """#45 rule 4: success, abort, failures and signals leave the plans directory empty."""
    fake_tofu.configure(**configuration)
    apply = terminal()
    with fake_tofu.watch_hang() as wait_until_hanging:
        if reaction is not None:
            apply.read_until(PROMPT)
            if configuration.get("hang_in") == "apply":
                apply.type("yes\n")
                wait_until_hanging()
            if isinstance(reaction, signal.Signals):
                apply.signal(reaction)
            else:
                apply.type(reaction)
        assert apply.finish() == expected_exit
    assert plan_files(home) == []
    assert list((home / ".secrets/opentofu/tmp").iterdir()) == []


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_an_interrupt_during_apply_lets_tofu_stop_gracefully_and_names_the_step(
    home, fake_tofu, terminal, interrupt
):
    """#45 rule 4/5: SIGINT or SIGTERM reaches tofu as one SIGINT and is awaited, not killed.

    #156 AC6 (row 7, ruled option A): nothing unchecked is claimed, so the check does not run
    and the line names the manual one.
    """
    fake_tofu.configure(plan=2, hang_in="apply")
    apply = terminal()
    with fake_tofu.watch_hang() as wait_until_hanging:
        apply.read_until(PROMPT)
        apply.type("yes\n")
        wait_until_hanging()
        apply.signal(interrupt)
        assert apply.finish() == 1
    assert fake_tofu.stopped_gracefully
    assert "tofu stopped gracefully" in apply.output
    assert APPLY_INTERRUPTED in apply.output
    assert "run hal check hosts" in " ".join(apply.output.split())
    assert apply.checks() == []


def test_further_interrupts_while_tofu_drains_are_not_forwarded_to_it(home, fake_tofu, terminal):
    """#45 rule 4/5: later interrupts while tofu drains are not forwarded as further SIGINTs."""
    fake_tofu.configure(plan=2, hang_in="apply", drain_until_released=True)
    apply = terminal()
    with fake_tofu.watch_hang() as wait_until_hanging:
        apply.read_until(PROMPT)
        apply.type("yes\n")
        wait_until_hanging()
        apply.signal(signal.SIGINT)
        deadline = time.monotonic() + 20
        while fake_tofu.sigints_received < 1:
            assert time.monotonic() < deadline, "tofu never received the forwarded SIGINT"
        apply.signal(signal.SIGINT)
        apply.signal(signal.SIGTERM)
        assert apply.process.poll() is None
        fake_tofu.release_draining_apply()
        assert apply.finish() == 1
    assert fake_tofu.sigints_received == 1
    assert fake_tofu.stopped_gracefully


def test_a_second_non_terminal_apply_keeps_the_plan_file_of_an_apply_awaiting_confirmation(
    home, fake_tofu, terminal
):
    """#45 rule 4: only leftovers of killed runs are deleted, not a live run's plan."""
    fake_tofu.configure(plan=2)
    apply = terminal()
    apply.read_until(PROMPT)
    external_cli.apply_command(home)
    apply.type("yes\n")
    assert apply.finish() == 0
    assert fake_tofu.call("apply")["plan_file_existed"]


def test_a_tofu_that_vanishes_after_the_confirmation_fails_the_apply_step_with_exit_1(
    home, fake_tofu, terminal
):
    """#45 rule 5: a failure after a good plan is exit 1 naming the step, not 'cannot plan'.

    #156 AC7 (row 8): a failed APPLY step is a `CHECK_APPLY_FAILED`, so the check runs.
    """
    fake_tofu.configure(plan=2)
    apply = terminal()
    apply.read_until(PROMPT)
    (fake_tofu.directory / "tofu").unlink()
    apply.type("yes\n")
    assert apply.finish() == 1
    assert apply_line("tofu apply failed") in apply.output
    assert "cannot plan" not in apply.output
    assert plan_files(home) == []
    assert len(apply.checks()) == 1
    assert "the apply failed; the host check ran" in " ".join(apply.output.split())


def leave_a_killed_run_behind(home) -> Path:
    leftover = home / PLANS_DIRECTORY / "killed.tfplan"
    leftover.parent.mkdir(mode=0o700)
    leftover.write_text("encrypted plan")
    leftover.with_suffix(".lock").write_text("")
    return leftover


def test_a_leftover_plan_file_is_deleted_and_named_at_the_next_apply(home, fake_tofu, terminal):
    """#45 rule 4: the same sweep runs at the start of apply, naming only the plan file."""
    leftover = leave_a_killed_run_behind(home)
    apply = terminal()
    assert apply.finish() == 0
    assert plan_files(home) == []
    assert apply_line(f"removed the leftover plan file {leftover}") in apply.output
    assert ".lock" not in apply.output


def test_a_non_terminal_apply_still_deletes_and_names_a_leftover_before_refusing(
    home, fake_tofu, capsys
):
    """#45 rule 4: the refusal comes after the sweep, so a killed run's plan is not kept."""
    leftover = leave_a_killed_run_behind(home)
    assert external_cli.apply_command(home) == 1
    error = capsys.readouterr().err
    assert plan_files(home) == []
    assert apply_line(f"removed the leftover plan file {leftover}") in error
    assert apply_line("refused, stdin and stdout must be a terminal") in error
    assert fake_tofu.calls() == []


def test_a_plan_file_whose_lock_is_gone_is_a_leftover(home, capsys):
    """#45 rule 4: a live run holds its lock until the plan is deleted, so a bare plan is dead."""
    leftover = leave_a_killed_run_behind(home)
    leftover.with_suffix(".lock").unlink()
    external_apply.remove_leftover_plans(home)
    assert plan_files(home) == []
    assert apply_line(f"removed the leftover plan file {leftover}") in capsys.readouterr().err


def test_a_sweep_keeps_the_files_of_a_live_run_that_replaced_the_lock_it_opened(home):
    """#45 rule 4: the sweep deletes only what the lock it holds still names."""
    directory = home / PLANS_DIRECTORY
    directory.mkdir(mode=0o700)
    stale_lock = directory / "run.lock"
    stale_lock.write_text("")
    live_plan = directory / "run.tfplan"

    def replace_the_lock_then_take_it(descriptor):
        stale_lock.unlink()
        stale_lock.write_text("live run's replacement")
        live_plan.write_text("live plan")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    external_apply.remove_leftover_plans(home, take_lock=replace_the_lock_then_take_it)
    assert stale_lock.exists()
    assert live_plan.exists()


def test_a_sweep_keeps_the_plan_of_a_live_run_that_takes_over_a_bare_plans_stem(home):
    """#45 rule 4: the lock the sweep creates for a bare plan does not shield a replaced stem."""
    directory = home / PLANS_DIRECTORY
    directory.mkdir(mode=0o700)
    live_plan = directory / "run.tfplan"
    live_plan.write_text("dead plan")
    lock = directory / "run.lock"

    def let_a_live_run_replace_the_stem_then_take_the_lock(descriptor):
        lock.unlink()
        lock.write_text("live run's lock")
        live_plan.write_text("live plan")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

    external_apply.remove_leftover_plans(
        home, take_lock=let_a_live_run_replace_the_stem_then_take_the_lock
    )
    assert live_plan.read_text() == "live plan"
    assert lock.exists()


@pytest.mark.parametrize(
    "plan_exit,typed",
    [pytest.param(0, None, id="no-changes"), pytest.param(2, "no\n", id="abort")],
)
def test_a_failed_cleanup_after_no_changes_or_an_abort_exits_1_naming_the_cleanup(
    home, fake_tofu, terminal, plan_exit, typed
):
    """#45 rule 5: a cleanup that fails after a good plan is exit 1 naming it, not 'cannot plan'."""
    fake_tofu.configure(plan=plan_exit, leave_undeletable=True)
    apply = terminal()
    try:
        if typed is not None:
            apply.read_until(PROMPT)
            apply.type(typed)
        assert apply.finish() == 1
        assert "the cleanup failed" in apply.output
        assert "cannot plan" not in apply.output
    finally:
        for locked in (home / ".secrets/opentofu/tmp").glob("*/locked"):
            locked.chmod(0o700)


@pytest.mark.parametrize(
    "plan_exit,typed,live_services_may_have_changed",
    [
        pytest.param(0, None, False, id="no-changes"),
        pytest.param(2, "no", False, id="abort"),
        pytest.param(1, None, False, id="failed-plan"),
        pytest.param(2, "yes", True, id="after-apply"),
    ],
)
def test_an_interrupted_cleanup_exits_1_and_warns_of_live_changes_only_after_apply(
    home, fake_tofu, capsys, monkeypatch, plan_exit, typed, live_services_may_have_changed
):
    """#45 rule 5: the interrupt consequence follows whether apply was reached, not the step.

    #156 AC7: an interrupt skips the check exactly when live services may be partly changed.
    """
    fake_tofu.configure(plan=plan_exit)

    @contextmanager
    def interrupted_when_leaving(home_directory):
        with external_apply.private_plan_file(home_directory) as plan_file:
            yield plan_file
        raise KeyboardInterrupt

    monkeypatch.setattr("builtins.input", lambda _prompt: typed)
    outcome = external_apply.apply_plan(home, {}, plan_file_scope=interrupted_when_leaving)
    assert outcome.exit == 1
    error = capsys.readouterr().err
    assert apply_line("interrupted during the cleanup") in error
    assert ("live services may be partly changed" in error) is live_services_may_have_changed
    assert ("hal check hosts" in error) is live_services_may_have_changed
    assert outcome.closing is (
        external_apply.ClosingCheck.NO_CHECK_INTERRUPTED
        if live_services_may_have_changed
        else external_apply.ClosingCheck.NO_CHECK_REFUSED
    )


def test_a_failed_cleanup_after_a_clean_body_is_raised_even_inside_an_except_block(home):
    """#34 finding 11 (a): the in-flight exception is the body's own, not an outer handled one."""

    def leave_with_a_locked_directory():
        with secrets.private_temporary_directory(home) as directory:
            locked = directory / "locked"
            locked.mkdir()
            (locked / "file").write_text("x")
            locked.chmod(0o500)

    try:
        try:
            raise ValueError("handled elsewhere")
        except ValueError:
            with pytest.raises(PermissionError):
                leave_with_a_locked_directory()
    finally:
        for locked in (home / ".secrets/opentofu/tmp").glob("*/locked"):
            locked.chmod(0o700)


def test_a_failed_cleanup_after_a_good_apply_is_not_an_interrupt_because_one_was_handled_earlier(
    home, fake_tofu, monkeypatch
):
    """AC7: that this run was interrupted is recorded when it happens, not read off the context."""
    fake_tofu.configure(**CHANGING_PLAN)

    @contextmanager
    def failing_when_leaving(home_directory):
        with external_apply.private_plan_file(home_directory) as plan_file:
            yield plan_file
        raise PermissionError("the plan file cannot be deleted")

    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    try:
        raise KeyboardInterrupt
    except KeyboardInterrupt:
        with pytest.raises(external_apply.StepFailed) as failure:
            external_apply.apply_plan(home, {}, plan_file_scope=failing_when_leaving)
    assert failure.value.closing is external_apply.ClosingCheck.CHECK_APPLIED


HOSTS_CATALOG = """\
cloudflare: {zone: example.test}
services:
  site:
    hosts:
      - {name: "@", exposure: public, reason: the site}
"""


PROTECTED_WILDCARD_CATALOG = """\
cloudflare: {zone: example.test}
services:
  site:
    hosts:
      - {name: "*", exposure: protected, reason: the operator's wildcard}
"""


def checkout_declaring(tmp_path, monkeypatch, fleet: str) -> Path:
    tree = tmp_path / "elsewhere"
    tree.mkdir()
    (tree / "fleet.yaml").write_text(fleet)
    monkeypatch.setattr(tofu, "PROJECT_ROOT", tree)
    return tree


@pytest.fixture
def hosts_catalog(tmp_path, monkeypatch) -> Path:
    """A checkout that is not the live main, declaring one public apex."""
    return checkout_declaring(tmp_path, monkeypatch, HOSTS_CATALOG)


def run_check(
    home, reader: FakeReader, *, as_json: bool = False, prober: FakeProber | None = None
) -> int:
    return external_cli.run_host_check(
        home, as_json=as_json, cloudflare=reader, prober=prober or FakeProber()
    ).exit_code


def test_a_clean_check_exits_0_and_says_how_many_hosts(home, hosts_catalog, capsys):
    """K1."""
    assert run_check(home, FakeReader(CLEAN_SNAPSHOT)) == 0
    assert capsys.readouterr().out == "no findings (1 hosts)\n"


def test_findings_exit_1_and_json_is_one_document_of_four_strings(home, hosts_catalog, capsys):
    """K1."""
    assert run_check(home, FakeReader(STRAY_SNAPSHOT), as_json=True) == 1
    printed = capsys.readouterr()
    findings = json.loads(printed.out)
    assert [item["problem"] for item in findings] == ["record-wrong", "undeclared-record"]
    assert all(set(item) == {"problem", "subject", "detail", "next"} for item in findings)
    assert all(isinstance(value, str) for item in findings for value in item.values())
    assert printed.err == ""


def test_check_reads_only_the_cloudflare_read_file(home, hosts_catalog):
    """K4."""
    (home / ".secrets/opentofu/state-passphrase").unlink()
    reader = FakeReader(CLEAN_SNAPSHOT)
    assert run_check(home, reader) == 0
    assert reader.tokens == ["cloudflare-token"]


class BrokenChunkedServer:
    """A loopback server whose every answer is a chunked body that breaks off."""

    def __init__(self, status: int, chunks: bytes) -> None:
        answer = (
            f"HTTP/1.1 {status} X\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
        ).encode() + chunks

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                self.request.recv(65536)
                self.request.sendall(answer)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.usefixtures("loopback_only")
@pytest.mark.parametrize("status", [200, 500])
@pytest.mark.parametrize(
    "chunks",
    [
        pytest.param(SENTINEL.encode() + b"\r\n", id="a malformed chunk size"),
        pytest.param(b"5\r\nab", id="a truncated chunk"),
    ],
)
def test_a_broken_chunked_answer_exits_2_and_never_prints_the_token(
    home, hosts_catalog, capfd, status, chunks
):
    """K5 (rule 12): both response-reading branches end as a read error, with no chained cause."""
    (home / ".secrets/cloudflare/fleet-read").write_text(SENTINEL)
    broken = BrokenChunkedServer(status, chunks)
    try:
        outcome = external_cli.run_host_check(
            home,
            cloudflare=lambda token: cloudflare_read.CloudflareClient(token, base_url=broken.url),
            prober=FakeProber(),
        )
    finally:
        broken.close()
    printed = capfd.readouterr()
    assert outcome.exit_code == 2
    assert printed.out == ""
    assert outcome.cause[0].startswith("/zones: ")
    assert SENTINEL not in printed.out + printed.err + "".join(outcome.cause)


def test_check_starts_no_tofu_and_keeps_a_leftover_plan(home, fake_tofu, hosts_catalog):
    """K6: the sweep belongs to plan and apply."""
    leftover = leave_a_killed_run_behind(home)
    assert run_check(home, FakeReader(CLEAN_SNAPSHOT)) == 0
    assert fake_tofu.calls() == []
    assert leftover.exists()


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_an_interrupt_exits_130_with_stdout_empty(home, hosts_catalog, capsys, interrupt, as_json):
    """K7."""
    reader = FakeReader(lambda: os.kill(os.getpid(), interrupt))
    assert run_check(home, reader, as_json=as_json) == 130
    assert capsys.readouterr().out == ""


def test_a_sigterm_while_the_reader_is_built_exits_130_with_stdout_empty(
    home, hosts_catalog, capsys
):
    """K7: the whole command body, not only the Cloudflare read, is covered."""

    def build_and_get_terminated(_token: str):
        os.kill(os.getpid(), signal.SIGTERM)

    outcome = external_cli.run_host_check(
        home, cloudflare=build_and_get_terminated, prober=FakeProber()
    )
    assert outcome.exit_code == 130
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(
    ("snapshot", "verdict"), [(CLEAN_SNAPSHOT, 0), (STRAY_SNAPSHOT, 1)], ids=["clean", "findings"]
)
def test_an_interrupt_after_the_writing_began_leaves_the_whole_document_and_the_verdict(
    home, hosts_catalog, capsys, interrupt, snapshot, verdict
):
    """K8: writing the result is the commit point, so no signal cuts the document or the exit.

    Row 3 (the gap before the write) is proven by code order, as no injected seam reaches it: the
    redaction runs before the ignored region and the commit mark is set inside it.
    """

    def interrupted_halfway(text: str) -> None:
        middle = len(text) // 2
        sys.stdout.write(text[:middle])
        os.kill(os.getpid(), interrupt)
        sys.stdout.write(text[middle:] + "\n")

    code = external_cli.run_host_check(
        home,
        as_json=True,
        cloudflare=FakeReader(snapshot),
        prober=FakeProber(),
        emit=interrupted_halfway,
    ).exit_code
    printed = capsys.readouterr()
    assert code == verdict
    assert isinstance(json.loads(printed.out), list)
    assert "interrupted" not in printed.err


@pytest.mark.parametrize(
    ("snapshot", "verdict"), [(CLEAN_SNAPSHOT, 0), (STRAY_SNAPSHOT, 1)], ids=["clean", "findings"]
)
def test_an_interrupt_after_the_whole_document_is_written_keeps_the_verdict(
    home, hosts_catalog, capsys, snapshot, verdict
):
    """K8: a signal that lands once the handlers are restored is not an interruption."""

    def written_then_interrupted(text: str) -> None:
        sys.stdout.write(text + "\n")
        raise KeyboardInterrupt

    code = external_cli.run_host_check(
        home,
        as_json=True,
        cloudflare=FakeReader(snapshot),
        prober=FakeProber(),
        emit=written_then_interrupted,
    ).exit_code
    printed = capsys.readouterr()
    assert code == verdict
    assert isinstance(json.loads(printed.out), list)
    assert "interrupted" not in printed.err


@pytest.mark.parametrize(
    ("outcome", "problem"),
    [
        pytest.param(
            host_probe.Unreachable(host_probe.FailureKind.TIMEOUT), "unreachable", id="down"
        ),
        pytest.param(host_probe.Answer(200, None, False, False), "answer-wrong", id="no-cf-ray"),
    ],
)
@pytest.mark.parametrize("as_json", [False, True], ids=["text", "json"])
def test_a_wrong_or_missing_answer_exits_1_never_2(
    home, hosts_catalog, capsys, outcome, problem, as_json
):
    """PB8: the probe's findings are findings; the new values are strings in the JSON list."""
    assert (
        run_check(home, FakeReader(CLEAN_SNAPSHOT), as_json=as_json, prober=FakeProber(outcome))
        == 1
    )
    printed = capsys.readouterr().out
    if as_json:
        (finding,) = json.loads(printed)
        assert finding["problem"] == problem
        assert all(isinstance(value, str) for value in finding.values())
    else:
        assert printed.startswith(f"{problem} example.test: ")


def test_a_host_without_a_record_is_never_asked(home, hosts_catalog):
    """PB8."""
    prober = FakeProber()
    no_record = cloudflare_read.Snapshot("t-1", (), (), ())
    assert run_check(home, FakeReader(no_record), prober=prober) == 1
    assert prober.asked == []


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_an_interrupt_while_the_prober_asks_exits_130_with_stdout_empty(
    home, hosts_catalog, capsys, interrupt
):
    """PB9."""
    prober = FakeProber(lambda: os.kill(os.getpid(), interrupt))
    assert run_check(home, FakeReader(CLEAN_SNAPSHOT), as_json=True, prober=prober) == 130
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize("code", [errno.ENETUNREACH, errno.EHOSTUNREACH])
def test_an_os_error_in_the_transport_is_one_unreachable_finding_without_its_text(
    home, hosts_catalog, capsys, code
):
    """PB3, PB10: through the command; the exception's text reaches neither stream."""

    def unreachable_connection(_name, _timeout):
        raise OSError(code, SENTINEL)

    def probing_over_the_failing_transport():
        return host_probe.HttpProber(connection=unreachable_connection)

    exit_code = external_cli.run_host_check(
        home,
        cloudflare=FakeReader(CLEAN_SNAPSHOT),
        prober=probing_over_the_failing_transport,
        as_json=True,
    ).exit_code
    assert exit_code == 1
    printed = capsys.readouterr()
    (finding,) = json.loads(printed.out)
    assert finding["problem"] == "unreachable"
    assert SENTINEL not in printed.out + printed.err


@pytest.mark.usefixtures("loopback_only")
@pytest.mark.parametrize(
    "mitigation",
    [[("cf-mitigated", "challenge")], [("cf-mitigated", "challenge")] * 2],
    ids=["once", "repeated"],
)
def test_a_challenge_hides_nothing_on_the_protected_wildcard_however_it_is_sent(
    home, tmp_path, monkeypatch, capsys, mitigation
):
    """PB1, PB4: a valid Access redirect with a challenge header is answer-wrong, exit 1."""
    checkout_declaring(tmp_path, monkeypatch, PROTECTED_WILDCARD_CATALOG)
    operator = cloudflare_read.AccessGroup("g-operator", "operator")
    include = cloudflare_read.Include("group", operator.id)
    operator_app = cloudflare_read.App(
        cloudflare_read.SELF_HOSTED,
        ("*.example.test",),
        (cloudflare_read.Policy("allow", (include,)),),
    )
    record = cloudflare_read.Record("*.example.test", "CNAME", TUNNEL_TARGET, True)
    snapshot = cloudflare_read.Snapshot("t-1", (record,), (operator,), (operator_app,))
    login = "https://team.cloudflareaccess.com/cdn-cgi/access/login/x"
    answering = Behaviour(302, [RAY, ("Location", login), *mitigation])
    with serving(answering) as origin:
        exit_code = external_cli.run_host_check(
            home,
            as_json=True,
            cloudflare=FakeReader(snapshot),
            prober=lambda: host_probe.HttpProber(origin),
        ).exit_code
    (finding,) = json.loads(capsys.readouterr().out)
    assert (exit_code, finding["problem"]) == (1, "answer-wrong")


# #156: the publish phase of `hal apply` ends on the host check.
REAL_CHECK_COMMAND = external_cli.check_command
INTERRUPTED_CHECK = 130
RUN_MANUALLY = "run hal check hosts"


def apply_line(text: str) -> str:
    return f"cloudflare: {text}"


@pytest.mark.parametrize(
    ("configuration", "check_exit", "expected_exit", "line"),
    [
        pytest.param(EMPTY_PLAN, 0, 0, None, id="AC1a-empty-plan-clean"),
        pytest.param(CHANGING_PLAN, 0, 0, None, id="AC1b-applied-clean"),
        pytest.param(
            CHANGING_PLAN, 1, 1, "applied; the host check has findings, see above",
            id="AC2-a-planned-repair-excuses-nothing",
        ),
        pytest.param(EMPTY_PLAN, 1, 1, None, id="AC3-undeclared-record-after-an-empty-plan"),
        pytest.param(
            FAILING_APPLY, 0, 1, "the apply failed; the host check ran", id="AC5-failed-clean"
        ),
        pytest.param(
            FAILING_APPLY, 1, 1, "the apply failed; the host check ran", id="AC5-failed-findings"
        ),
        pytest.param(
            EMPTY_PLAN, 2, 1, "the host check could not run", id="AC8-empty-plan-cannot-check"
        ),
        pytest.param(
            CHANGING_PLAN, 2, 1, "applied, but the host check could not run",
            id="AC8-applied-cannot-check",
        ),
        pytest.param(
            FAILING_APPLY, 2, 1, "the apply failed; the host check could not run",
            id="AC8-failed-cannot-check",
        ),
        pytest.param(
            EMPTY_PLAN, INTERRUPTED_CHECK, 1, f"the host check was interrupted; {RUN_MANUALLY}",
            id="AC9-empty-plan-interrupted",
        ),
        pytest.param(
            CHANGING_PLAN, INTERRUPTED_CHECK, 1,
            f"applied; the host check was interrupted; {RUN_MANUALLY}",
            id="AC9-applied-interrupted",
        ),
        pytest.param(
            FAILING_APPLY, INTERRUPTED_CHECK, 1,
            f"the apply failed; the host check was interrupted; {RUN_MANUALLY}",
            id="AC9-failed-interrupted",
        ),
    ],
)  # fmt: skip
def test_apply_ends_on_the_host_check_and_maps_its_verdict_to_the_exit(
    home, fake_tofu, terminal, configuration, check_exit, expected_exit, line
):
    """AC1a, AC1b, AC2, AC3, AC5, AC8, AC9: the check runs after the session, the exit follows."""
    fake_tofu.configure(**configuration)
    apply = terminal(check_exit=check_exit)
    if configuration is not EMPTY_PLAN:
        apply.read_until(PROMPT)
        apply.type("yes\n")
    assert apply.finish() == expected_exit
    (check,) = apply.checks()
    commands = [call["argv"][0] for call in fake_tofu.calls()]
    assert check["tofu_commands"] == commands
    assert (check["plans_left"], check["tmp_left"]) == ([], [])
    assert ("apply" in commands) is (configuration is not EMPTY_PLAN)
    printed = said(apply.output)
    if line is None:
        assert f"{external_apply.SENDER}:" not in printed
    else:
        assert apply_line(line) in printed
    if configuration is EMPTY_PLAN:
        assert "applied" not in printed
    assert "Traceback" not in printed


@pytest.mark.parametrize(
    ("configuration", "reaction", "expected_exit"),
    [
        pytest.param(CHANGING_PLAN, "no\n", 1, id="declined"),
        pytest.param({"plan": 1}, None, 2, id="plan-fails"),
        pytest.param({"hang_in": "plan"}, signal.SIGINT, 1, id="sigint-in-the-plan"),
        pytest.param({"hang_in": "plan"}, signal.SIGTERM, 1, id="sigterm-in-the-plan"),
    ],
)
def test_an_apply_that_applied_nothing_and_found_a_plan_never_calls_the_check(
    home, fake_tofu, terminal, configuration, reaction, expected_exit
):
    """AC4 (rows 4, 5, 6): declined, a failed plan and an interrupted plan skip the check."""
    fake_tofu.configure(**configuration)
    apply = terminal()
    with fake_tofu.watch_hang() as wait_until_hanging:
        if configuration.get("hang_in"):
            wait_until_hanging()
            apply.signal(reaction)
        else:
            if reaction:
                apply.read_until(PROMPT)
                apply.type(reaction)
        assert apply.finish() == expected_exit
    assert apply.checks() == []


@pytest.fixture
def cleanup_that_fails(home):
    """The plans directory is made read-only by tofu; it is restored for the test's end."""
    yield
    plans = home / PLANS_DIRECTORY
    if plans.exists():
        plans.chmod(0o700)
    for locked in (home / ".secrets/opentofu/tmp").glob("*/locked"):
        locked.chmod(0o700)


@pytest.mark.usefixtures("cleanup_that_fails")
@pytest.mark.parametrize(
    ("configuration", "reaction", "checks_run"),
    [
        pytest.param(CHANGING_PLAN, "no\n", 0, id="declined-plan"),
        pytest.param(EMPTY_PLAN, None, 1, id="empty-plan"),
        pytest.param(CHANGING_PLAN, "yes\n", 1, id="successful-apply"),
        pytest.param(FAILING_APPLY, "yes\n", 1, id="failed-apply"),
        pytest.param(
            {"plan": 2, "hang_in": "apply", "lock_plans_in": "apply"}, signal.SIGINT, 0,
            id="sigint-in-the-apply-then-the-plan-file-cannot-be-deleted",
        ),
        pytest.param(
            {"plan": 2, "hang_in": "apply", "lock_plans_in": "apply"}, signal.SIGTERM, 0,
            id="sigterm-in-the-apply-then-the-plan-file-cannot-be-deleted",
        ),
    ],
)  # fmt: skip
def test_a_failing_cleanup_keeps_the_disposition_decided_before_it(
    home, fake_tofu, terminal, configuration, reaction, checks_run
):
    """AC7: the cleanup fails after each disposition; the check runs or not as before it, exit 1."""
    fake_tofu.configure(leave_undeletable=True, **configuration)
    apply = terminal()
    with fake_tofu.watch_hang() as wait_until_hanging:
        if reaction is not None:
            apply.read_until(PROMPT)
            if configuration.get("hang_in") == "apply":
                apply.type("yes\n")
                wait_until_hanging()
                apply.signal(reaction)
            else:
                apply.type(reaction)
        assert apply.finish() == 1
    assert len(apply.checks()) == checks_run
    assert apply_line("the cleanup failed,") in said(apply.output)
    assert (RUN_MANUALLY in said(apply.output)) is (configuration.get("hang_in") == "apply")


@pytest.mark.parametrize("damage", ["missing", "empty"])
def test_a_missing_cloudflare_read_file_stops_the_apply_before_tofu_runs(
    home, fake_tofu, terminal, damage
):
    """AC13 (rule 20): the check's token is verified first, so no apply can end unchecked."""
    read_file = home / ".secrets/cloudflare/fleet-read"
    if damage == "missing":
        read_file.unlink()
    else:
        read_file.write_text("\n")
    apply = terminal()
    assert apply.finish() == 2
    assert str(read_file) in said(apply.output)
    assert fake_tofu.calls() == []
    assert apply.checks() == []


@pytest.mark.parametrize(
    "environment",
    [
        pytest.param({}, id="AC14a-utf8-terminal"),
        pytest.param({"PYTHONIOENCODING": "ascii"}, id="AC14b-terminal-that-cannot-encode-it"),
    ],
)
def test_output_of_tofu_that_is_not_utf8_does_not_stop_the_apply_before_its_check(
    home, fake_tofu, terminal, environment
):
    """AC14 (rule 23): bytes tofu printed after a live apply never become a traceback."""
    fake_tofu.configure(plan=2, apply_output=b"applied \xff\xfe and done\n")
    apply = terminal(environment=environment)
    apply.read_until(PROMPT)
    apply.type("yes\n")
    assert apply.finish() == 0
    assert len(apply.checks()) == 1
    assert "Traceback" not in apply.output
    assert "applied" in apply.output
    assert "and done" in apply.output


def test_the_real_check_in_the_child_is_stopped_by_the_loopback_guard(home, fake_tofu, terminal):
    """AC11: the backstop. The real check meets a resolver that names a public address."""
    fake_tofu.configure(plan=2)
    apply = terminal(real_check=True, resolver_stub=True, guard_refusal_expected=True)
    apply.read_until(PROMPT)
    apply.type("yes\n")
    assert apply.finish() == 1
    assert apply.guard_marker.read_text() == "203.0.113.7"
    assert apply_line("applied, but the host check could not run") in said(apply.output)
    assert "Traceback" not in apply.output


@pytest.fixture
def confirmations(monkeypatch) -> list[str]:
    """The operator at the pretend terminal: every prompt it is shown is recorded and answered
    `yes`, so a cell that refuses before the confirmation can say none was ever asked."""
    asked: list[str] = []

    def answer_yes(prompt: str) -> str:
        asked.append(prompt)
        return "yes"

    monkeypatch.setattr("builtins.input", answer_yes)
    return asked


@pytest.fixture
def apply_in_process(home, fake_tofu, live_checkout, monkeypatch, loopback_only, confirmations):
    """`apply_command` in this process at a pretend terminal, ending on the real `check_command`.

    The catalog declares one public apex unless a cell commits its own `fleet`; the check gets the
    reader and prober a cell passes and, through `around`, can be wrapped (the module global
    `external.cli.check_command` is the seam). The ready hosts are asked through `ready_prober`, a
    recording fake that answers 200 by default; nothing here leaves the guarded loopback.
    """
    commit_catalog(live_checkout, HOSTS_CATALOG)
    monkeypatch.setattr(tofu, "PROJECT_ROOT", live_checkout)
    monkeypatch.setattr(external_apply, "refusal_without_terminal", lambda: None)

    def run(reader, *, emit=None, around=lambda check: check, fleet=None, ready_prober=None) -> int:
        if fleet:
            commit_catalog(live_checkout, fleet)
        ports = {"cloudflare": reader, "prober": FakeProber()}
        if emit:
            ports["emit"] = emit
        monkeypatch.setattr(
            external_cli, "check_command", around(functools.partial(REAL_CHECK_COMMAND, **ports))
        )
        return external_cli.apply_command(
            home, live_checkout, prober_for=ready_prober or RecordingReadyProber()
        )

    return run


@pytest.mark.usefixtures("loopback_only")
def test_an_unreadable_cloudflare_answer_after_an_apply_exits_1_never_2(
    home, fake_tofu, apply_in_process, capsys
):
    """AC8: the real check meets a broken answer from a loopback server after a good apply."""
    fake_tofu.configure(**CHANGING_PLAN)
    broken = BrokenChunkedServer(200, b"5\r\nab")
    try:
        code = apply_in_process(
            lambda token: cloudflare_read.CloudflareClient(token, base_url=broken.url)
        )
    finally:
        broken.close()
    printed = capsys.readouterr()
    assert code == 1
    assert apply_line("applied, but the host check could not run") in printed.err
    assert "cloudflare-token" not in printed.out + printed.err


class StdoutFailingOn(io.StringIO):
    """A stdout whose write fails, the way a broken terminal does, for one marked text."""

    def write(self, text: str) -> int:
        if "published-after-the-apply" in text:
            raise RuntimeError(SENTINEL)
        return super().write(text)


def test_an_error_while_publishing_tofus_output_after_the_apply_still_runs_the_check(
    home, fake_tofu, apply_in_process, capsys, monkeypatch
):
    """AC7 (row 8): any error after `apply_reached` runs the check: exit 1, the type only."""
    fake_tofu.configure(apply_output=b"published-after-the-apply\n", **CHANGING_PLAN)
    monkeypatch.setattr(sys, "stdout", StdoutFailingOn())
    reader = FakeReader(CLEAN_SNAPSHOT)
    assert apply_in_process(reader) == 1
    error = capsys.readouterr().err
    assert apply_line("tofu apply failed, RuntimeError") in error
    assert apply_line("the apply failed; the host check ran") in error
    assert SENTINEL not in error
    assert reader.tokens == ["cloudflare-token"]


def test_the_check_reads_with_the_read_token_and_tofu_never_sees_it(
    home, fake_tofu, apply_in_process, capsys
):
    """AC10: the write tokens stay with tofu, the read token with the check alone."""
    fake_tofu.configure(echo_environment=True, **CHANGING_PLAN)
    environment_before = dict(os.environ)
    reader = FakeReader(CLEAN_SNAPSHOT)
    assert apply_in_process(reader) == 0
    assert reader.tokens == ["cloudflare-token"]
    for call in fake_tofu.calls():
        assert "cloudflare-token" not in call["env"].values()
    assert fake_tofu.call("apply")["env"]["CLOUDFLARE_API_TOKEN"] == "cloudflare-write-token"
    assert dict(os.environ) == environment_before
    printed = capsys.readouterr()
    for write_token in WRITE_TOKEN_FILES.values():
        assert write_token not in printed.out + printed.err


INTERRUPTED_LINES = [
    pytest.param(EMPTY_PLAN, f"the host check was interrupted; {RUN_MANUALLY}", id="empty-plan"),
    pytest.param(
        CHANGING_PLAN, f"applied; the host check was interrupted; {RUN_MANUALLY}", id="applied"
    ),
    pytest.param(
        FAILING_APPLY,
        f"the apply failed; the host check was interrupted; {RUN_MANUALLY}",
        id="failed-apply",
    ),
]


def interrupt_myself(interrupt):
    os.kill(os.getpid(), interrupt)


@contextmanager
def signalling_on_the_line(function, statement: str, interrupt: int):
    """Sends `interrupt` once, as `function` is about to run its line that starts with
    `statement`: a boundary inside one function, which no injected port reaches."""
    lines, first_line = inspect.getsourcelines(function)
    statement_line = next(
        first_line + offset
        for offset, text in enumerate(lines)
        if text.strip().startswith(statement)
    )
    pending = True

    def trace_line(frame, event, _argument):
        nonlocal pending
        if event == "line" and pending and frame.f_lineno == statement_line:
            pending = False
            interrupt_myself(interrupt)
        return trace_line

    def trace_call(frame, _event, _argument):
        return trace_line if frame.f_code is function.__code__ else None

    previous = sys.gettrace()
    sys.settrace(trace_call)
    try:
        yield
    finally:
        sys.settrace(previous)


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("configuration,line", INTERRUPTED_LINES)
@pytest.mark.parametrize(
    "where", ["while-reading", "before-the-check-starts", "as-the-session-returns"]
)
def test_a_signal_before_the_check_commits_exits_1_and_says_it_was_interrupted(
    home, fake_tofu, apply_in_process, capsys, monkeypatch, configuration, line, where, interrupt
):
    """AC9 (a): including the gap after the tofu session; never 130, no traceback, plan gone.

    The last `where` wraps `external.apply.apply_plan` (the body's "Signal-timing seams").
    """
    fake_tofu.configure(**configuration)
    reader = FakeReader(CLEAN_SNAPSHOT)

    def interrupted_first(check):
        return lambda home_directory: (interrupt_myself(interrupt), check(home_directory))[1]

    if where == "while-reading":
        code = apply_in_process(FakeReader(lambda: interrupt_myself(interrupt)))
    elif where == "before-the-check-starts":
        code = apply_in_process(reader, around=interrupted_first)
    else:
        monkeypatch.setattr(
            external_apply,
            "apply_plan",
            signalling_as_it_returns(external_apply.apply_plan, interrupt),
        )
        code = apply_in_process(reader)
        assert reader.tokens == []
    assert code == 1
    assert apply_line(line) in capsys.readouterr().err
    assert plan_files(home) == []


def signalling_as_it_returns(real_apply_plan, interrupt):
    """The signal lands right after the tofu session, where the outcome is lost with the raise."""

    def apply_plan(*arguments, **keywords):
        outcome = real_apply_plan(*arguments, **keywords)
        interrupt_myself(interrupt)
        return outcome

    return apply_plan


class SignallingOnce(io.StringIO):
    """A stream that sends a signal instead of taking the first write that contains `marker`,
    or, with `after_the_write`, right after taking it."""

    def __init__(self, marker: str, interrupt: int, *, after_the_write: bool = False) -> None:
        super().__init__()
        self.marker = marker
        self.interrupt = interrupt
        self.after_the_write = after_the_write
        self.pending = True

    def write(self, text: str) -> int:
        if not (self.pending and self.marker in text):
            return super().write(text)
        self.pending = False
        if self.after_the_write:
            written = super().write(text)
            interrupt_myself(self.interrupt)
            return written
        interrupt_myself(self.interrupt)
        return super().write(text)


@contextmanager
def plan_file_failing_to_leave(home_directory):
    """A cleanup that fails with an error that is not an `OSError`, even while unwinding."""
    with external_apply.private_plan_file(home_directory) as plan_file:
        try:
            yield plan_file
        except BaseException:
            raise RuntimeError("the plan file cannot be deleted") from None


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_a_cleanup_failure_of_any_kind_after_an_interrupted_apply_still_reports_the_interrupt(
    home, fake_tofu, capsys, monkeypatch, interrupt
):
    """AC7 (row 7) with AC9 (a): the cleanup replaced the interrupt; the step failed in the
    cleanup, no check follows, and the interrupt is still reported.

    Calls `apply_plan` directly with its own cleanup port, which fails with a non-OSError.
    """
    fake_tofu.configure(apply_output=b"published-after-the-apply\n", **CHANGING_PLAN)
    monkeypatch.setattr(sys, "stdout", SignallingOnce("published-after-the-apply", interrupt))
    monkeypatch.setattr("builtins.input", lambda _prompt: "yes")
    with pytest.raises(external_apply.StepFailed) as failure:
        external_apply.apply_plan(home, {}, plan_file_scope=plan_file_failing_to_leave)
    assert failure.value.step is external_apply.Step.CLEANUP
    assert failure.value.closing is external_apply.ClosingCheck.NO_CHECK_INTERRUPTED
    error = capsys.readouterr().err
    assert APPLY_INTERRUPTED in error


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize("after_the_write", [False, True], ids=["before-it", "right-after-it"])
def test_a_signal_while_the_interrupt_line_is_published_shows_it_exactly_once(
    home, fake_tofu, apply_in_process, monkeypatch, interrupt, after_the_write
):
    """AC9 (a), rule 22 (B3-2): the line and its `reported` record are one step under the mask.

    Real signals on replaced streams; no module attribute is wrapped. A signal after the write
    would, unmasked, abort the step and have the handler print the line a second time.
    """
    fake_tofu.configure(apply_output=b"published-after-the-apply\n", **CHANGING_PLAN)
    stderr = SignallingOnce("interrupted during", interrupt, after_the_write=after_the_write)
    monkeypatch.setattr(sys, "stderr", stderr)
    monkeypatch.setattr(sys, "stdout", SignallingOnce("published-after-the-apply", interrupt))
    reader = FakeReader(CLEAN_SNAPSHOT)
    assert apply_in_process(reader) == 1
    assert stderr.getvalue().count(APPLY_INTERRUPTED) == 1
    assert reader.tokens == []


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_as_the_interrupt_is_recorded_as_reported_shows_the_line_exactly_once(
    home, fake_tofu, apply_in_process, capsys, monkeypatch, interrupt
):
    """AC9 (a), rule 22 (B4-1): a trace hook, because no injected port reaches the statement
    that records the line as printed; there a signal must be dropped by the mask, not handled.
    """
    fake_tofu.configure(apply_output=b"published-after-the-apply\n", **CHANGING_PLAN)
    monkeypatch.setattr(sys, "stdout", SignallingOnce("published-after-the-apply", interrupt))
    reader = FakeReader(CLEAN_SNAPSHOT)
    with signalling_on_the_line(
        external_apply.report_interrupt, "progress.reported = True", interrupt
    ):
        assert apply_in_process(reader) == 1
    assert capsys.readouterr().err.count(APPLY_INTERRUPTED) == 1
    assert reader.tokens == []


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_while_the_apply_run_is_set_up_exits_1_saying_nothing_was_applied(
    home, fake_tofu, apply_in_process, capsys, interrupt
):
    """AC9 (a), row 6, rule 22 (B4-2): a trace hook, because no injected port reaches the setup
    statement inside `apply_command`; SIGTERM must already be an interrupt there.
    """
    reader = FakeReader(CLEAN_SNAPSHOT)
    with signalling_on_the_line(external_cli.apply_command, "run = _ApplyRun()", interrupt):
        assert apply_in_process(reader) == 1
    assert apply_line("interrupted, nothing was applied") in capsys.readouterr().err
    assert (fake_tofu.calls(), reader.tokens) == ([], [])


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_before_the_tofu_session_exits_1_saying_nothing_was_applied(
    home, fake_tofu, apply_in_process, capsys, monkeypatch, interrupt
):
    """AC9 (a), row 6: the sweep and the refusals come first; no traceback, tofu never started."""
    monkeypatch.setattr(
        external_apply, "refusal_without_terminal", lambda: interrupt_myself(interrupt)
    )
    reader = FakeReader(CLEAN_SNAPSHOT)
    assert apply_in_process(reader) == 1
    assert apply_line("interrupted, nothing was applied") in capsys.readouterr().err
    assert (fake_tofu.calls(), reader.tokens) == ([], [])


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(
    ("configuration", "snapshot", "expected_exit"),
    [
        pytest.param(EMPTY_PLAN, CLEAN_SNAPSHOT, 0, id="empty-plan-clean"),
        pytest.param(EMPTY_PLAN, STRAY_SNAPSHOT, 1, id="empty-plan-findings"),
        pytest.param(CHANGING_PLAN, CLEAN_SNAPSHOT, 0, id="applied-clean"),
        pytest.param(CHANGING_PLAN, STRAY_SNAPSHOT, 1, id="applied-findings"),
        pytest.param(FAILING_APPLY, CLEAN_SNAPSHOT, 1, id="failed-apply-stays-1"),
    ],
)
def test_a_signal_during_the_publication_keeps_the_committed_verdict(
    home, fake_tofu, apply_in_process, capsys, configuration, snapshot, expected_exit, interrupt
):
    """AC9 (b): the check's write is its commit point; the mapped exit stands."""
    fake_tofu.configure(**configuration)

    def interrupted_halfway(text: str) -> None:
        middle = len(text) // 2
        sys.stdout.write(text[:middle])
        interrupt_myself(interrupt)
        sys.stdout.write(text[middle:] + "\n")

    code = apply_in_process(FakeReader(snapshot), emit=interrupted_halfway)
    printed = capsys.readouterr()
    assert code == expected_exit
    assert "interrupted" not in printed.err


class SignalsAfterArming(io.StringIO):
    """A stderr that sends a signal on every write once armed."""

    armed = False

    def __init__(self, interrupt: int) -> None:
        super().__init__()
        self.interrupt = interrupt

    def write(self, text: str) -> int:
        if self.armed:
            interrupt_myself(self.interrupt)
        return super().write(text)


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(
    ("configuration", "snapshot", "line"),
    [
        pytest.param(
            EMPTY_PLAN, cloudflare_read.CloudflareReadError("unreadable"),
            "the host check could not run", id="empty-plan-cannot-check",
        ),
        pytest.param(
            CHANGING_PLAN, STRAY_SNAPSHOT, "applied; the host check has findings, see above",
            id="applied-findings",
        ),
        pytest.param(
            FAILING_APPLY, CLEAN_SNAPSHOT, "the apply failed; the host check ran",
            id="failed-apply-clean",
        ),
    ],
)  # fmt: skip
def test_a_signal_after_the_check_returned_does_not_turn_its_verdict_into_an_interruption(
    home, fake_tofu, apply_in_process, monkeypatch, configuration, snapshot, line, interrupt
):
    """AC9 (c): the mapping and its line run with the signals ignored."""
    fake_tofu.configure(**configuration)
    stderr = SignalsAfterArming(interrupt)
    monkeypatch.setattr(sys, "stderr", stderr)

    def armed_once_returned(check):
        def run(home_directory):
            verdict = check(home_directory)
            stderr.armed = True
            return verdict

        return run

    code = apply_in_process(FakeReader(snapshot), around=armed_once_returned)
    assert code == 1
    assert apply_line(line) in stderr.getvalue()
    assert "interrupted" not in stderr.getvalue()


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
@pytest.mark.parametrize(
    ("configuration", "snapshot", "expected_exit"),
    [
        pytest.param(EMPTY_PLAN, CLEAN_SNAPSHOT, 0, id="empty-plan-clean"),
        pytest.param(CHANGING_PLAN, CLEAN_SNAPSHOT, 0, id="applied-clean"),
        pytest.param(CHANGING_PLAN, STRAY_SNAPSHOT, 1, id="applied-findings"),
        pytest.param(FAILING_APPLY, CLEAN_SNAPSHOT, 1, id="failed-apply-clean"),
    ],
)
def test_a_signal_right_after_the_mask_is_lifted_keeps_the_committed_verdict(
    home,
    fake_tofu,
    apply_in_process,
    capsys,
    monkeypatch,
    configuration,
    snapshot,
    expected_exit,
    interrupt,
):
    """AC9 (c): the handlers are back, the verdict is committed; its exit stands, no traceback.

    Wraps `external.cli._signals_ignored` (the body's "Signal-timing seams"): the real mask runs,
    the signal is raised as it lifts.
    """
    fake_tofu.configure(**configuration)
    check_returned = []
    real_mask = external_cli._signals_ignored

    @contextmanager
    def signalling_once_lifted():
        with real_mask():
            yield
        if check_returned:
            interrupt_myself(interrupt)

    def noting_the_return(check):
        def run(home_directory):
            verdict = check(home_directory)
            check_returned.append(verdict)
            return verdict

        return run

    monkeypatch.setattr(external_cli, "_signals_ignored", signalling_once_lifted)
    code = apply_in_process(FakeReader(snapshot), around=noting_the_return)
    assert code == expected_exit
    assert "interrupted" not in capsys.readouterr().err


READY_PATH = "/realms/example/.well-known/openid-configuration"
AUTH = "auth.example.test"
DOCS = "docs.example.test"
READY_CATALOG = f"""\
cloudflare: {{zone: example.test}}
services:
  site:
    hosts:
      - {{name: "@", exposure: public, reason: the site}}
  auth:
    hosts:
      - {{name: auth, exposure: public, reason: sign in, ready: {READY_PATH}}}
"""
TWO_READY_CATALOG = (
    READY_CATALOG
    + """\
  docs:
    hosts:
      - {name: docs, exposure: public, reason: the docs, ready: /ready}
"""
)
DISABLED_READY_CATALOG = """\
cloudflare: {zone: example.test}
services:
  site:
    hosts:
      - {name: "@", exposure: public, reason: the site}
  old:
    run: {enabled: false}
    hosts:
      - {name: old, exposure: public, reason: switched off, ready: /ready}
"""
NOT_OK = host_probe.Answer(503, None, False, False)
REFUSED = host_probe.Unreachable(host_probe.FailureKind.REFUSED)


@pytest.mark.parametrize(
    ("fleet", "configuration", "applied"),
    [
        pytest.param(None, CHANGING_PLAN, True, id="R1-no-host-declares-ready"),
        pytest.param(READY_CATALOG, EMPTY_PLAN, False, id="R2-the-plan-has-no-changes"),
        pytest.param(DISABLED_READY_CATALOG, CHANGING_PLAN, True, id="R11-a-disabled-entry"),
    ],
)
def test_no_host_is_asked_unless_an_enabled_ready_host_meets_a_plan_with_changes(
    home, fake_tofu, apply_in_process, fleet, configuration, applied
):
    """R1, R2, R11: even a 503 for every name (as here) blocks nothing nobody is asked about."""
    fake_tofu.configure(**configuration)
    reader = FakeReader(CLEAN_SNAPSHOT)
    prober = RecordingReadyProber(otherwise=NOT_OK)
    apply_in_process(reader, fleet=fleet, ready_prober=prober)
    assert prober.asked == []
    assert reader.reads == 1
    assert ("apply" in [call["argv"][0] for call in fake_tofu.calls()]) is applied


def test_a_ready_host_that_answers_is_followed_by_the_prompt_and_the_same_plan_file(
    home, fake_tofu, terminal, live_checkout
):
    """R3: through the real CLI with the hosts read from the committed fleet.yaml."""
    commit_catalog(live_checkout, READY_CATALOG)
    fake_tofu.configure(**CHANGING_PLAN)
    apply = terminal()
    apply.read_until(PROMPT)
    apply.type("yes\n")
    assert apply.finish() == 0
    assert apply.ready_asked() == [
        {"fqdn": AUTH, "path": READY_PATH, "target": "http://127.0.0.1:8081"}
    ]
    out_argument = next(a for a in fake_tofu.call("plan")["argv"] if a.startswith("-out="))
    assert fake_tofu.call("apply")["argv"] == ["apply", out_argument.removeprefix("-out=")]


def assert_refused_before_yes(home, fake_tofu, confirmations, reader, code, error: str) -> None:
    assert code == 1
    assert confirmations == [], "the operator was asked to confirm a refused plan"
    assert "apply" not in [call["argv"][0] for call in fake_tofu.calls()]
    assert reader.reads == 0
    assert plan_files(home) == []
    assert apply_line("refused, a ready host does not answer, nothing applied") in error
    assert "deleted" not in error


@pytest.mark.parametrize(
    ("outcome", "said_as"),
    [
        pytest.param(NOT_OK, "status 503", id="R4-503"),
        pytest.param(host_probe.Answer(404, None, False, False), "status 404", id="R5-404"),
        pytest.param(REFUSED, "the connection was refused", id="R6-connection-refused"),
        pytest.param(
            host_probe.Unreachable(host_probe.FailureKind.TIMEOUT),
            "the request timed out",
            id="R7-timeout",
        ),
        pytest.param(
            host_probe.Unreachable(host_probe.FailureKind.MALFORMED),
            "the answer was malformed",
            id="R8-malformed",
        ),
        pytest.param(
            host_probe.Answer(302, "https://elsewhere.test/", False, False),
            "status 302",
            id="R9-redirect",
        ),
    ],
)
def test_a_plan_is_refused_before_yes_while_a_ready_host_does_not_answer(
    home, fake_tofu, apply_in_process, confirmations, capsys, outcome, said_as
):
    """R4-R9 and R14: the unrelated apex change is refused too; the plan's content is not read."""
    fake_tofu.configure(**CHANGING_PLAN)
    reader = FakeReader(CLEAN_SNAPSHOT)
    prober = RecordingReadyProber({AUTH: outcome})
    code = apply_in_process(reader, fleet=READY_CATALOG, ready_prober=prober)
    error = capsys.readouterr().err
    assert_refused_before_yes(home, fake_tofu, confirmations, reader, code, error)
    assert f"{AUTH} did not answer {READY_PATH} on http://127.0.0.1:8081: {said_as}" in error
    assert prober.asked == [(AUTH, READY_PATH, "http://127.0.0.1:8081")]


def test_only_the_host_that_does_not_answer_is_named_and_the_whole_plan_is_refused(
    home, fake_tofu, apply_in_process, confirmations, capsys
):
    """R10."""
    fake_tofu.configure(**CHANGING_PLAN)
    reader = FakeReader(CLEAN_SNAPSHOT)
    code = apply_in_process(
        reader, fleet=TWO_READY_CATALOG, ready_prober=RecordingReadyProber({DOCS: NOT_OK})
    )
    error = capsys.readouterr().err
    assert_refused_before_yes(home, fake_tofu, confirmations, reader, code, error)
    assert apply_line(f"{DOCS} did not answer /ready") in error
    assert AUTH not in error


def test_every_ready_host_is_asked_and_every_one_that_fails_is_named_once_in_one_refusal(
    home, fake_tofu, apply_in_process, confirmations, capsys
):
    """R17."""
    fake_tofu.configure(**CHANGING_PLAN)
    reader = FakeReader(CLEAN_SNAPSHOT)
    prober = RecordingReadyProber({AUTH: NOT_OK, DOCS: REFUSED})
    code = apply_in_process(reader, fleet=TWO_READY_CATALOG, ready_prober=prober)
    error = capsys.readouterr().err
    assert_refused_before_yes(home, fake_tofu, confirmations, reader, code, error)
    assert prober.names == [AUTH, DOCS]
    assert f"{AUTH} did not answer {READY_PATH} on http://127.0.0.1:8081: status 503" in error
    assert (
        f"{DOCS} did not answer /ready on http://127.0.0.1:8081: the connection was refused"
        in error
    )
    assert error.count("refused, a ready host") == 1


@pytest.mark.parametrize("reverted", [True, False], ids=["edit-and-revert", "lasting-edit"])
def test_the_plan_reads_the_catalog_the_ready_hosts_were_taken_from_however_the_file_changes(
    home,
    fake_tofu,
    apply_in_process,
    confirmations,
    live_checkout,
    monkeypatch,
    reverted,
):
    """Tofu is handed the validated bytes, so an edit while it plans (kept or reverted) cannot
    publish a host nobody asked: every host of what it read was probed."""
    fake_tofu.configure(**CHANGING_PLAN)
    catalog_file = live_checkout / catalog.FLEET_FILE
    read_by_tofu: list[bytes] = []
    real_run = tofu.run

    def editing_the_catalog_while_tofu_plans(binary, arguments, environment):
        if arguments[0] != "plan":
            return real_run(binary, arguments, environment)
        snapshot_flag = next((a for a in arguments if a.startswith("-var=catalog_file=")), None)
        original = catalog_file.read_text()
        catalog_file.write_text(TWO_READY_CATALOG)
        read_by_tofu.append(
            Path(snapshot_flag.split("=", 2)[2]).read_bytes()
            if snapshot_flag
            else catalog_file.read_bytes()
        )
        if reverted:
            catalog_file.write_text(original)
        return real_run(binary, arguments, environment)

    monkeypatch.setattr(tofu, "run", editing_the_catalog_while_tofu_plans)
    prober = RecordingReadyProber()
    apply_in_process(FakeReader(CLEAN_SNAPSHOT), fleet=READY_CATALOG, ready_prober=prober)
    assert confirmations, "the plan was refused"
    (planned,) = read_by_tofu
    assert planned.decode() == READY_CATALOG
    planned_ready = {
        host.fqdn for host in catalog.hosts(catalog.parse(planned, "fleet.yaml")) if host.ready
    }
    assert set(prober.names) == planned_ready


def test_the_snapshot_handed_to_tofu_is_private_and_removed_with_the_session(
    home, fake_tofu, apply_in_process, monkeypatch
):
    fake_tofu.configure(**CHANGING_PLAN)
    modes: list[int] = []
    real_run = tofu.run

    def noting_the_snapshot_mode(binary, arguments, environment):
        if arguments[0] == "plan":
            flag = next(a for a in arguments if a.startswith("-var=catalog_file="))
            snapshot = Path(flag.split("=", 2)[2])
            modes.append(snapshot.stat().st_mode & 0o777)
            assert snapshot.parent == Path(environment["TMPDIR"])
            modes.append(snapshot.parent.stat().st_mode & 0o777)
            noted.append(snapshot)
        return real_run(binary, arguments, environment)

    noted: list[Path] = []
    monkeypatch.setattr(tofu, "run", noting_the_snapshot_mode)
    apply_in_process(FakeReader(CLEAN_SNAPSHOT))
    assert modes == [0o600, 0o700]
    assert not noted[0].exists()


@pytest.mark.parametrize("interrupt", [signal.SIGINT, signal.SIGTERM])
def test_a_signal_during_the_ready_probe_leaves_nothing_applied_and_no_plan_file(
    home, fake_tofu, terminal, live_checkout, interrupt
):
    """R13: the child's fake prober hangs until the signal arrives."""
    commit_catalog(live_checkout, READY_CATALOG)
    fake_tofu.configure(**CHANGING_PLAN)
    apply = terminal(ready_hangs=True)
    apply.wait_until_probing()
    apply.signal(interrupt)
    assert apply.finish() == 1
    assert apply_line(
        "interrupted during the readiness check, nothing was applied; the plan file is deleted"
    ) in said(apply.output)
    assert plan_files(home) == []
    assert PROMPT not in said(apply.output)
    assert "apply" not in [call["argv"][0] for call in fake_tofu.calls()]
    assert apply.checks() == []


@pytest.mark.usefixtures("loopback_only")
def test_the_host_check_still_asks_the_root_path(home, hosts_catalog):
    """R15."""
    prober = FakeProber()
    run_check(home, FakeReader(CLEAN_SNAPSHOT), prober=prober)
    assert prober.asked
    assert set(prober.paths) == {"/"}


@pytest.fixture
def reached_connections(monkeypatch) -> list[tuple]:
    """The connect `loopback_only` would hand on to, as a recorder: this machine has listeners on
    127.0.0.1:8080 and :8081, so a guard that let one through must not reach them. A test lists it
    before `loopback_only`, which captures whatever `connect` is then in place."""
    reached: list[tuple] = []
    monkeypatch.setattr(socket.socket, "connect", lambda _self, address: reached.append(address))
    return reached


LOOPBACK_FAMILIES = {"127.0.0.1": socket.AF_INET, "::1": socket.AF_INET6}


@pytest.mark.parametrize("address", LOOPBACK_FAMILIES)
@pytest.mark.parametrize("port", LIVE_STACK_PORTS)
def test_the_guard_refuses_the_live_stack_ports_before_connecting(
    reached_connections, loopback_only, address, port
):
    """R18, in process: the fixture's error names the address and port, and nothing is handed to
    the real connect."""
    with (
        socket.socket(LOOPBACK_FAMILIES[address]) as candidate,
        pytest.raises(AssertionError) as refusal,
    ):
        candidate.connect((address, port))
    assert f"{address}:{port}" in str(refusal.value)
    assert reached_connections == []


@pytest.mark.parametrize("address", LOOPBACK_FAMILIES)
@pytest.mark.parametrize("port", LIVE_STACK_PORTS)
def test_the_childs_guard_refuses_the_live_stack_ports_before_connecting(terminal, address, port):
    """R18, in the child, whose real connect is a recorder: the marker names the pair."""
    attempt = terminal(connect_attempt=[address, port], guard_refusal_expected=True)
    assert attempt.finish() == 0
    assert attempt.guard_marker.read_text() == f"{address}:{port}"
    assert not (attempt.scratch / "reached-the-network").exists()


def test_the_childs_guard_hands_another_loopback_port_on(terminal):
    """The control of the cells above: the recorder does see a connect the guard lets through."""
    attempt = terminal(connect_attempt=["127.0.0.1", 9])
    assert attempt.finish() == 0
    assert (attempt.scratch / "reached-the-network").read_text() == "127.0.0.1:9"


def test_the_real_ready_prober_in_the_child_is_stopped_by_the_guard_at_the_default_target(
    home, fake_tofu, terminal, live_checkout
):
    """R18 (child) and R19: the backstop; the ready host keeps the default target 127.0.0.1:8081."""
    commit_catalog(live_checkout, READY_CATALOG)
    fake_tofu.configure(**CHANGING_PLAN)
    apply = terminal(real_ready_prober=True, guard_refusal_expected=True)
    assert apply.finish() == 1
    assert apply.guard_marker.read_text() == "127.0.0.1:8081"
    printed = said(apply.output)
    assert (
        f"{AUTH} did not answer {READY_PATH} on http://127.0.0.1:8081: the connection was refused"
        in printed
    )
    assert PROMPT not in printed
    assert "apply" not in [call["argv"][0] for call in fake_tofu.calls()]


@pytest.mark.usefixtures("cleanup_that_fails")
@pytest.mark.parametrize(
    ("answer", "said_of_the_end"),
    [
        pytest.param(
            lambda: NOT_OK,
            "refused, a ready host does not answer, nothing applied",
            id="R20-refusal",
        ),
        pytest.param(
            lambda: interrupt_myself(signal.SIGINT),
            "interrupted during the readiness check, nothing was applied",
            id="R21-sigint",
        ),
        pytest.param(
            lambda: interrupt_myself(signal.SIGTERM),
            "interrupted during the readiness check, nothing was applied",
            id="R21-sigterm",
        ),
    ],
)  # fmt: skip
def test_a_plan_file_that_cannot_be_deleted_after_the_readiness_step_is_named_not_claimed_deleted(
    home, fake_tofu, apply_in_process, confirmations, capsys, answer, said_of_the_end
):
    """R20, R21: the plans directory turns read-only after the plan, so the real deletion of the
    selected plan file fails; the run exits 1 through `apply_command`, names the cleanup, runs no
    check and claims no deletion."""
    fake_tofu.configure(lock_plans_in="plan", **CHANGING_PLAN)
    reader = FakeReader(CLEAN_SNAPSHOT)
    code = apply_in_process(
        reader, fleet=READY_CATALOG, ready_prober=RecordingReadyProber({AUTH: answer})
    )
    error = said(capsys.readouterr().err)
    out_argument = next(a for a in fake_tofu.call("plan")["argv"] if a.startswith("-out="))
    assert code == 1
    assert apply_line(said_of_the_end) in error
    assert apply_line("the cleanup failed,") in error
    assert "deleted" not in error
    assert reader.reads == 0
    assert confirmations == []
    assert Path(out_argument.removeprefix("-out=")).exists()
    assert "apply" not in [call["argv"][0] for call in fake_tofu.calls()]
