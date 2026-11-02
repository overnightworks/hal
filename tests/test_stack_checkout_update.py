"""What `hal update` asks and does of a checkout (#783): the fast-forward merge of a pinned sha,
the questions about the waiting commits and the process-group runner both git and the sync use,
on real git in `tmp_path`."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import support.throwaway_home as throwaway_home
from support.git_support import (
    FETCH_WRITES,
    advance,
    checkout_state,
    committed_main,
    head_of,
    plain_git,
    subjects,
    with_origin,
)
from support.process_support import is_gone

from hal.stack import checkout

home = throwaway_home.home
MAY_CHANGE = (*FETCH_WRITES, "ORIG_HEAD")  # git writes it before it looks at the merge


@pytest.fixture
def main_tree(tmp_path: Path) -> Path:
    tree = committed_main(tmp_path / "main")
    with_origin(tree, tmp_path / "origin.git")
    return tree


@pytest.fixture
def origin(tmp_path: Path, main_tree: Path) -> Path:
    return tmp_path / "origin.git"


@pytest.fixture
def git(main_tree: Path) -> checkout.Git:
    return checkout.Git(main_tree)


@pytest.mark.parametrize(
    "source", ["repository core.hooksPath", ".git/hooks", "global core.hooksPath"]
)
def test_a_merge_moves_head_index_and_tree_to_the_pinned_sha_and_runs_no_hook(
    git, main_tree, origin, tmp_path, source
):
    """M1: a hook from each source runs in a plain merge of a copy of the checkout (the positive
    control) and does not run in the merge."""
    tip = advance(origin, (b"waiting", {b"README.md": b"new\n"}))
    plain_git(main_tree, "fetch", "--quiet", "origin")
    sentinel = tmp_path / "hook-ran"
    hooks = main_tree / ".git" / "hooks" if source == ".git/hooks" else tmp_path / "hooks"
    hooks.mkdir(exist_ok=True)
    for name in ("post-merge", "reference-transaction"):
        (hooks / name).write_text(f"#!/bin/sh\necho {name} >> {sentinel}\n")
        (hooks / name).chmod(0o755)
    if source != ".git/hooks":
        scope = "--global" if source.startswith("global") else "--local"
        plain_git(main_tree, "config", scope, "core.hooksPath", str(hooks))
    control = shutil.copytree(main_tree, tmp_path / "control", symlinks=True)
    plain_git(control, "merge", "--quiet", "--ff-only", tip)
    assert sentinel.exists(), "the positive control: a plain merge runs the hook"
    sentinel.unlink()

    git.merge_fast_forward(tip)

    assert head_of(main_tree) == tip
    assert (main_tree / "README.md").read_bytes() == b"new\n"
    assert plain_git(main_tree, "status", "--porcelain").stdout == ""
    assert not sentinel.exists()


def test_a_merge_that_would_overwrite_an_ignored_local_file_is_refused_and_keeps_it(
    git, main_tree, origin
):
    """M2: R4, an ignored `.env` lies where the merge brings a tracked one."""
    (main_tree / ".env").write_bytes(b"local secret\n")
    tip = advance(origin, (b"tracks it", {b".env": b"from origin\n"}))
    plain_git(main_tree, "fetch", "--quiet", "origin")
    before = checkout_state(main_tree, MAY_CHANGE)

    with pytest.raises(checkout.GitError, match="`git merge` exited"):
        git.merge_fast_forward(tip)

    assert checkout_state(main_tree, MAY_CHANGE) == before
    assert (main_tree / ".env").read_bytes() == b"local secret\n"


def test_a_merge_git_refuses_for_an_index_lock_changes_nothing(git, main_tree, origin):
    """M3: another reason git refuses."""
    tip = advance(origin, (b"waiting", {b"README.md": b"new\n"}))
    plain_git(main_tree, "fetch", "--quiet", "origin")
    (main_tree / ".git" / "index.lock").touch()
    before = checkout_state(main_tree, MAY_CHANGE)

    with pytest.raises(checkout.GitError, match="`git merge` exited"):
        git.merge_fast_forward(tip)

    assert checkout_state(main_tree, MAY_CHANGE) == before


def test_the_waiting_commits_and_files_are_listed_raw_for_the_caller_to_escape(
    git, main_tree, origin
):
    """A3: a subject with ESC and a path with a newline arrive unchanged."""
    first = b"first \x1b[31mred"
    advance(origin, (first, {b"a\nb.txt": b"x"}), (b"second", {b"src/hal/x.py": b"y"}))
    plain_git(main_tree, "fetch", "--quiet", "origin")
    tip = plain_git(main_tree, "rev-parse", "FETCH_HEAD").stdout.strip()

    commits = git.commits_to(tip)

    assert [commit.subject for commit in commits] == ["second", first.decode()]
    assert all(plain_git(main_tree, "rev-parse", commit.short).stdout for commit in commits)
    assert sorted(git.files_changed_to(tip)) == ["a\nb.txt", "src/hal/x.py"]


def test_five_hundred_waiting_commits_are_all_listed(git, main_tree, origin):
    """A2: nothing is truncated."""
    tip = advance(origin, *subjects(*(f"commit {number}" for number in range(500))))
    plain_git(main_tree, "fetch", "--quiet", "origin")

    assert len(git.commits_to(tip)) == 500


def test_the_questions_about_a_sha_tell_commit_and_ancestry(git, main_tree, origin):
    """R3: a fast-forward target is a commit descending from HEAD; a sibling is not."""
    start = head_of(main_tree)
    tip = advance(origin, *subjects("waiting"))
    plain_git(main_tree, "fetch", "--quiet", "origin")
    assert git.is_commit(tip)
    assert not git.is_commit("0" * 40)
    assert git.is_ancestor(start, tip)
    assert not git.is_ancestor(tip, start)
    assert git.full() == start


def test_origin_keeps_heads_full_sha(git, main_tree, origin):
    advance(origin, *subjects("waiting"))

    fetched = checkout.fetch_origin(git)

    assert fetched.head_sha == head_of(main_tree)


def test_a_call_that_does_not_finish_ends_with_its_whole_group_killed(tmp_path):
    """The sync and git share the runner: a descendant holding the pipes dies with the call."""
    pidfile = tmp_path / "child.pid"
    script = f"sleep 60 & echo $! > {pidfile}; wait"

    with pytest.raises(subprocess.TimeoutExpired):
        checkout.run_in_own_group(["sh", "-c", script], dict(os.environ), 0.5)

    assert is_gone(int(pidfile.read_text()))


SESSION_GIT = """#!/bin/sh
ps -o pid=,pgid=,sid= -p $$ > "$IDS_LOG"
exec "$REAL_GIT" "$@"
"""


@pytest.mark.parametrize("profile", list(checkout.Profile), ids=lambda profile: profile.name)
def test_every_git_call_leads_its_own_group_and_only_the_merge_its_own_session(
    main_tree, tmp_path, monkeypatch, profile
):
    """M4's premise: a terminal's Ctrl-C reaches no git call; the merge also leaves the terminal's
    session, so nothing sent to that session reaches a merge that must run to its end."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git").write_text(SESSION_GIT)
    (shim / "git").chmod(0o755)
    monkeypatch.setenv("REAL_GIT", shutil.which("git"))
    monkeypatch.setenv("IDS_LOG", str(tmp_path / "ids"))
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")

    checkout.run_git(main_tree, ["status"], profile)

    pid, group, session = (tmp_path / "ids").read_text().split()
    assert group == pid
    assert (session == pid) == (profile is checkout.Profile.MERGE)
