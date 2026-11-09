"""The rendered commit hook under real `git commit` in a sandboxed HOME with a stub `quality`; rules of overnightworks/home-tools#22."""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
from support.workstation_support import FAKE_KEY, Sandbox, run_hal_setup

from hal.grammar import ExitCode
from hal.workstation.setup import HOOK_NAMES

REFUSAL_LINE = "quality: secret.txt fake-key sha256=0000"
GIT_TIMEOUT_SECONDS = 30


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=False, timeout=GIT_TIMEOUT_SECONDS)


def head(repo: Path) -> str:
    return git(repo, "rev-parse", "--verify", "-q", "HEAD").stdout.strip()


def write_repository_hook(repo: Path, body: str, name: str = "pre-commit") -> Path:
    hook = repo / ".git" / "hooks" / name
    hook.write_text(f"#!/bin/sh\n{body}\n")
    hook.chmod(0o755)
    return hook


@pytest.fixture
def hooked(sandbox: Sandbox) -> Sandbox:
    assert run_hal_setup(home=sandbox.home, secrets_setup_boundaries=sandbox.secrets_boundaries) == ExitCode.OK
    return sandbox


@pytest.fixture
def repo(hooked: Sandbox, tmp_path: Path) -> Path:
    """A repository whose tracked `secret.txt` is clean; the global hook is already active."""
    path = tmp_path / "repo"
    path.mkdir()
    git(path, "init", "-q")
    (path / "secret.txt").write_text("clean\n")
    git(path, "add", "secret.txt")
    assert git(path, "commit", "-q", "-m", "first").returncode == 0
    return path


def leak(repo: Path, *, stage: bool) -> None:
    (repo / "secret.txt").write_text(f"{FAKE_KEY}\n")
    if stage:
        git(repo, "add", "secret.txt")


@pytest.mark.parametrize(
    ("stage", "commit_args"),
    [
        (True, ["commit", "-m", "x"]),
        (False, ["commit", "-a", "-m", "x"]),
        (False, ["commit", "-m", "x", "secret.txt"]),
        (True, ["commit", "--amend", "-m", "x"]),
    ],
    ids=["plain", "commit -a", "commit <path>", "amend"],
)
def test_staged_fake_key_is_refused_with_quality_line_and_head_unchanged(repo: Path, stage: bool, commit_args: list[str]) -> None:
    """Rules 3 and 4, done-when `Refusal works`: every commit form is refused with quality's line."""
    before = head(repo)
    leak(repo, stage=stage)

    refused = git(repo, *commit_args)

    assert refused.returncode != 0
    assert REFUSAL_LINE in refused.stderr
    assert head(repo) == before


def test_merge_of_a_branch_carrying_the_key_is_refused(repo: Path) -> None:
    """Rule 3: pre-merge-commit refuses a merge whose result holds the key (the branch was made with --no-verify)."""
    git(repo, "switch", "-q", "-c", "carrier")
    leak(repo, stage=True)
    assert git(repo, "commit", "-q", "--no-verify", "-m", "carrier").returncode == 0
    git(repo, "switch", "-q", "main")
    (repo / "other.txt").write_text("other\n")
    git(repo, "add", "other.txt")
    assert git(repo, "commit", "-q", "-m", "other").returncode == 0
    before = head(repo)

    refused = git(repo, "merge", "--no-ff", "-m", "merge", "carrier")

    assert refused.returncode != 0
    assert REFUSAL_LINE in refused.stderr
    assert head(repo) == before


def test_commit_in_a_linked_worktree_is_refused(repo: Path, tmp_path: Path) -> None:
    """Rule 6: a linked worktree uses the same global hook."""
    worktree = tmp_path / "repo-worktrees" / "issue-1-x"
    assert git(repo, "worktree", "add", "-q", "-b", "side", str(worktree)).returncode == 0
    before = head(worktree)
    leak(worktree, stage=True)

    refused = git(worktree, "commit", "-m", "x")

    assert refused.returncode != 0
    assert REFUSAL_LINE in refused.stderr
    assert head(worktree) == before


def test_final_scan_refuses_a_key_the_repository_hook_staged(repo: Path) -> None:
    """Rule 3 step 4: a repository hook that stages a key and exits 0 is caught by the second scan."""
    write_repository_hook(repo, f"echo {FAKE_KEY} > secret.txt; git add secret.txt")
    before = head(repo)
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    refused = git(repo, "commit", "-m", "x")

    assert refused.returncode != 0
    assert REFUSAL_LINE in refused.stderr
    assert head(repo) == before


def test_repository_hook_runs_between_two_scans_on_a_clean_commit(repo: Path, hooked: Sandbox, tmp_path: Path) -> None:
    """Rule 3 order: scan, then the repository's own pre-commit, then the scan again."""
    events = tmp_path / "events"
    scanner = hooked.layout.quality_executable
    scanner.write_text(f"#!/bin/sh\necho scan >> {shlex.quote(str(events))}\n")
    scanner.chmod(0o755)
    write_repository_hook(repo, f"echo repository-hook >> {shlex.quote(str(events))}")
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    assert git(repo, "commit", "-m", "x").returncode == 0
    assert events.read_text().split() == ["scan", "repository-hook", "scan"]


def test_refused_scan_never_reaches_the_repository_hook(repo: Path) -> None:
    """Rule 3: the first scan ends the hook, so a repository hook does not run for a refused commit."""
    write_repository_hook(repo, "touch ran-repository-hook")
    leak(repo, stage=True)

    assert git(repo, "commit", "-m", "x").returncode != 0
    assert not (repo / "ran-repository-hook").exists()


def test_clean_commit_passes_without_a_repository_hook(repo: Path) -> None:
    """Rule 3 step 3: no repository hook means the scan alone decides."""
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    assert git(repo, "commit", "-m", "x").returncode == 0


def test_commit_reaches_the_scanner_when_the_git_client_has_no_mise_on_its_path(
    repo: Path, hooked: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """quality finds mise on PATH: the hook gives its call the directory of hal's mise, though the client's PATH lacks it."""
    directories = os.environ["PATH"].split(os.pathsep)
    monkeypatch.setenv("PATH", os.pathsep.join(d for d in directories if not (Path(d) / "mise").exists()))
    hooked.layout.quality_executable.write_text('#!/bin/sh\ncommand -v mise >/dev/null || exit 2\n')
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    assert shutil.which("mise") is None
    assert git(repo, "commit", "-m", "x").returncode == 0


def test_unstaged_key_does_not_block_a_commit_of_other_files(repo: Path) -> None:
    """Rule 3: only the staged change is scanned."""
    leak(repo, stage=False)
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    assert git(repo, "commit", "-m", "x").returncode == 0


def test_first_commit_without_head_is_scanned_too(hooked: Sandbox, tmp_path: Path) -> None:
    """Rule 3 risk case: a repository without HEAD is refused as well."""
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    git(fresh, "init", "-q")
    leak(fresh, stage=True)

    refused = git(fresh, "commit", "-m", "x")

    assert refused.returncode != 0
    assert REFUSAL_LINE in refused.stderr
    assert head(fresh) == ""


def test_no_verify_skips_the_hook_as_the_readme_says(repo: Path) -> None:
    """Rule 7: `--no-verify` is not covered by the hook."""
    leak(repo, stage=True)

    assert git(repo, "commit", "-q", "--no-verify", "-m", "x").returncode == 0


@pytest.mark.parametrize("scan_exit", [1, 2])
def test_scanner_exit_codes_pass_through_the_hook(repo: Path, monkeypatch: pytest.MonkeyPatch, scan_exit: int) -> None:
    """Rule 3 exit codes: 1 (secret found) and 2 (cannot judge) end the hook with that code."""
    monkeypatch.setenv("STUB_SCAN_EXIT", str(scan_exit))

    assert git(repo, "hook", "run", "pre-commit").returncode == scan_exit


def test_repository_hook_exit_code_ends_the_hook_and_refuses_the_commit(repo: Path) -> None:
    """Rule 3 step 3: a repository hook that exits 3 refuses the commit with 3."""
    write_repository_hook(repo, "exit 3")
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")
    before = head(repo)

    assert git(repo, "hook", "run", "pre-commit").returncode == 3
    assert git(repo, "commit", "-m", "x").returncode != 0
    assert head(repo) == before


@pytest.mark.parametrize("damage", [Path.unlink, lambda path: path.chmod(0o644)], ids=["deleted", "not executable"])
def test_missing_quality_gives_exit_2_and_the_setup_hint(repo: Path, hooked: Sandbox, damage: Callable[[Path], object]) -> None:
    """Rule 3 step 1: without an executable quality the commit is blocked with exit 2 and the message."""
    damage(hooked.layout.quality_executable)
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")
    before = head(repo)

    checked = git(repo, "hook", "run", "pre-commit")
    refused = git(repo, "commit", "-m", "x")

    assert checked.returncode == 2
    missing_line = f"pre-commit: quality fehlt ({hooked.layout.quality_executable}), Commit gesperrt. Einrichten: hal setup"
    assert missing_line in refused.stderr
    assert refused.returncode != 0
    assert head(repo) == before


def test_a_repository_hook_that_is_a_copy_of_the_global_one_does_not_loop(repo: Path, hooked: Sandbox) -> None:
    """Rule 3 recursion guard: HOME_GIT_HOOK_CHAINED makes the copy only scan."""
    shutil.copy(hooked.layout.git_hooks_dir / HOOK_NAMES[0], repo / ".git" / "hooks" / HOOK_NAMES[0])
    (repo / "note.txt").write_text("note\n")
    git(repo, "add", "note.txt")

    assert git(repo, "commit", "-m", "x").returncode == 0


def test_hook_runs_the_repository_hook_of_a_linked_worktree_from_the_common_dir(repo: Path, tmp_path: Path) -> None:
    """Rule 6: the chained repository hook is found through --git-common-dir."""
    write_repository_hook(repo, "exit 3")
    worktree = tmp_path / "repo-worktrees" / "issue-2-y"
    assert git(repo, "worktree", "add", "-q", "-b", "side", str(worktree)).returncode == 0

    assert git(worktree, "hook", "run", "pre-commit").returncode == 3


def test_hook_files_are_executable_and_named_after_both_git_events(hooked: Sandbox) -> None:
    """Rule 3: pre-commit and pre-merge-commit are both rendered and executable."""
    assert all(os.access(hooked.layout.git_hooks_dir / name, os.X_OK) for name in HOOK_NAMES)
