"""`hal update` at its entry point (#783): the checkout of the live tree brought to origin's `main`
after one `yes`, on real git in `tmp_path`, with a real child as the sync. A real Ctrl-C has its own
module, `test_stack_update_ctrl_c`."""

import fcntl
import json
import os
import shutil
import signal
import sys

import pytest
import support.stack_update as stack_update_support
import support.throwaway_home as throwaway_home
from support.git_support import head_of, plain_git, subjects
from support.stack_apply_fakes import Terminal
from support.stack_update import (
    APPLIED_RECORD,
    FAKE_SYNC,
    Engine,
    Tamper,
    answered,
    edit,
    errors,
)

from hal import cli
from hal.grammar import ExitCode
from hal.output import verbose_run
from hal.stack import apply, checkout
from hal.stack import cli as stack_cli
from hal.stack.update import UpdateEnd

home = throwaway_home.home
world = stack_update_support.world


# --- guards and the fetch ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("guard", "line"),
    [
        ("no terminal", "error: refused, stdin and stdout must be a terminal"),
        ("another tree", "error: runs only from the live checkout"),
    ],
)
def test_without_a_terminal_or_off_the_live_checkout_it_refuses_with_that_line_only(
    world, capsys, tmp_path, guard, line
):
    """U2: no terminal, not the live checkout."""
    if guard == "no terminal":
        world.output.isatty = lambda: False

    end = world.run(home=tmp_path / "elsewhere" if guard == "another tree" else None)

    assert end is UpdateEnd.REFUSED
    assert errors(capsys).splitlines()[0].startswith(line)
    assert world.stdout() == ""


@pytest.mark.parametrize("trouble", ["branch", "dirty"])
def test_off_a_clean_main_it_refuses_naming_the_branch_or_every_dirty_path(world, capsys, trouble):
    """U2: not main, dirty (every path, `next:` the status command)."""
    if trouble == "branch":
        plain_git(world.live, "switch", "--quiet", "--create", "feature/x")
    else:
        (world.live / "README.md").write_text("edited\n")
        (world.live / "new.txt").write_text("new\n")

    end = world.run()

    assert end is UpdateEnd.REFUSED
    err = errors(capsys)
    assert ("feature/x" in err) == (trouble == "branch")
    assert ("README.md" in world.stdout() and "new.txt" in world.stdout()) == (trouble == "dirty")
    assert ("next: git -C ~/srv/hal status" in err) == (trouble == "dirty")


def test_while_an_apply_holds_the_lock_it_refuses_and_touches_nothing(world, capsys):
    """U3: the lock held by another process."""
    with (world.state / apply.APPLY_LOCK).open("w") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        end = world.run()

    assert end is UpdateEnd.REFUSED
    assert errors(capsys) == (
        "error: another `hal apply` or `hal update` is running; nothing changed\n"
    )


def test_an_apply_is_refused_while_the_update_waits_at_its_question(world, capsys):
    """U3: the other way round, at the handler."""
    world.wait(*subjects("waiting"))
    seen = {}

    def apply_meanwhile() -> None:
        seen["exit"] = apply.apply_local(world.state, repository=world.live)

    world.run(at_the_question=apply_meanwhile)

    assert seen["exit"] == apply.ApplyExit.REFUSED
    assert "another `hal apply` or `hal update` is running" in errors(capsys)


def test_the_sync_runs_while_the_lock_is_held_so_an_apply_would_be_refused(world, monkeypatch):
    """U3: during the sync, a second locker is refused; the update itself still ends 0."""
    world.wait(*subjects("waiting"))
    monkeypatch.setenv("FAKE_SYNC", "lock")

    assert world.run() is UpdateEnd.DONE
    assert world.logged("sync.lock").strip() == "1"


def test_a_lock_that_cannot_be_opened_is_a_failure(world, capsys, tmp_path):
    """U4: the state directory path is a file."""
    blocker = tmp_path / "file"
    blocker.write_text("x")
    world.state = blocker / "state"

    end = world.run()

    assert end is UpdateEnd.FAILED
    assert f"error: cannot take {blocker / 'state' / apply.APPLY_LOCK}" in errors(capsys)


@pytest.mark.parametrize("trouble", ["fetch fails", "ahead"])
def test_a_failed_fetch_or_a_head_off_origin_ends_with_its_reason_and_no_question(
    world, capsys, trouble
):
    """F3: the reasons of the fetch are the apply's own."""
    if trouble == "fetch fails":
        shutil.rmtree(world.origin)
    else:
        plain_git(
            world.live, "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-qm", "x"
        )

    end = world.run()

    assert end is UpdateEnd.FAILED
    assert errors(capsys).startswith(
        "error: cannot fetch main" if trouble != "ahead" else "error: the live checkout is ahead"
    )
    assert "Type yes" not in world.stdout()


# --- current, declined, the display --------------------------------------------------------------


def test_a_current_checkout_prints_its_row_and_the_next_step_without_a_question(world, capsys):
    """U1."""
    end = world.run()

    assert end is UpdateEnd.DONE
    assert "✓ checkout" in world.stdout()
    assert "current" in world.stdout()
    assert world.stdout().splitlines()[-2:] == ["✓ nothing to update", "next: hal apply"]
    assert "Type yes" not in world.stdout()
    assert not (world.log / "sync.args").exists()


@pytest.mark.parametrize("answer", ["no", "", "yes ", None], ids=["no", "empty", "yes ", "EOF"])
def test_anything_but_yes_changes_nothing_and_exits_declined(world, capsys, monkeypatch, answer):
    """A1 at the entry point: no, an empty line, `yes `, a closed stdin without a newline."""
    world.wait(*subjects("one", "two"))
    before = head_of(world.live)
    monkeypatch.setattr(stack_cli, "update_checkout", lambda: world.run(answer))

    assert cli.main(["update"]) == ExitCode.FINDINGS
    assert errors(capsys) == "error: aborted, nothing changed; 2 commits wait on origin\n"
    assert head_of(world.live) == before
    assert world.lock_is_free
    assert not (world.log / "sync.args").exists()
    assert world.record() == APPLIED_RECORD


def test_every_waiting_commit_is_a_line_escaped_and_untruncated(world):
    """A2: 500 commits, one subject with ESC."""
    world.wait((b"red \x1b[31m", {}), *subjects(*(f"commit {n}" for n in range(499))))

    world.run("no")

    shown = world.stdout()
    assert shown.count("commit ") >= 499
    assert "red \\x1b[31m" in shown
    assert "\x1b" not in shown


def test_the_files_are_grouped_by_what_they_change_with_conditional_lines(world):
    """A3: code, a directory bind, a planned file and the rest."""
    world.wait(
        edit("src/hal/x.py"),
        edit("legal/nginx/default.conf"),
        edit("traefik.yml"),
        edit("README.md"),
    )

    world.run("no")

    rows = [line.strip() for line in world.stdout().splitlines()]
    grouped = {
        subject: rows[next(i for i, row in enumerate(rows) if row.startswith(f"~ {subject}")) + 1]
        for subject in ("hal code", "directory bind", "planned", "other")
    }
    assert grouped == {
        "hal code": "src/hal/x.py",
        "directory bind": "legal/nginx/default.conf",
        "planned": "traefik.yml",
        "other": "README.md",
    }
    assert not {"live", "active", "running", "applied"} & set(world.stdout().lower().split())


def test_files_that_cannot_be_classified_are_one_line_and_the_question_stands(world):
    """A3: compose unreadable."""
    world.wait(edit("README.md"))

    end = world.run(engine=Engine(world.live, fails=True))

    assert end is UpdateEnd.DONE
    assert "not classified" in world.stdout()
    assert "Type yes to update" in world.stdout()


def test_two_updates_without_an_apply_between_follow_the_configuration_at_head(world):
    """A5: the first moves a directory bind in the configuration, the second changes files under
    the new and the old source."""
    (world.live / "dynamic-two").mkdir()
    world.wait(
        edit("compose.json", json.dumps(["dynamic-two", "legal/nginx", "traefik.yml"])),
        edit("dynamic-two/.gitkeep", ""),
    )
    assert world.run() is UpdateEnd.DONE
    world.output = Terminal()
    world.wait(edit("dynamic-two/new.txt"), edit("dynamic/old.txt"))

    world.run("no")

    rows = world.stdout().splitlines()
    bind = next(index for index, row in enumerate(rows) if row.lstrip().startswith("~ directory"))
    assert "dynamic-two/new.txt" in rows[bind + 1]
    assert "dynamic/old.txt" in "\n".join(rows[rows.index(next(r for r in rows if "other" in r)) :])


# --- the recheck after the yes ----------------------------------------------------------------


@pytest.mark.parametrize(
    "change", ["head moved", "other branch", "detached", "tracked edit", "untracked file"]
)
def test_a_checkout_that_changed_after_the_yes_is_refused_saying_how(world, capsys, change):
    """R1: both shas. R2: what it is and every path."""
    world.wait(*subjects("waiting"))
    planned = head_of(world.live)
    actions = {
        "head moved": lambda: plain_git(world.live, "commit", "--allow-empty", "-qm", "m"),
        "other branch": lambda: plain_git(world.live, "switch", "-q", "-c", "other"),
        "detached": lambda: plain_git(world.live, "switch", "-q", "--detach"),
        "tracked edit": lambda: (world.live / "README.md").write_text("edited\n"),
        "untracked file": lambda: (world.live / "stray.txt").write_text("x\n"),
    }

    end = world.run(at_the_question=actions[change])

    assert end is UpdateEnd.REFUSED
    err = errors(capsys)
    seen = err + world.stdout()
    said = {
        "head moved": f"planned {planned}, now {head_of(world.live)}",
        "other branch": "other",
        "detached": "detached",
        "tracked edit": "README.md",
        "untracked file": "stray.txt",
    }
    assert said[change] in seen
    assert "nothing changed" in seen
    assert err.endswith("next: hal update\n")


def test_a_pinned_sha_that_is_no_commit_any_more_is_refused(world, capsys):
    """R3: the fetched commit is gone from the repository."""
    tip = world.wait(*subjects("waiting"))

    def forget() -> None:
        plain_git(world.live, "update-ref", "-d", checkout.ORIGIN_MAIN)
        (world.live / ".git/FETCH_HEAD").unlink()
        plain_git(world.live, "reflog", "expire", "--expire=now", "--all")
        plain_git(world.live, "gc", "--prune=now", "-q")

    end = world.run(at_the_question=forget)

    assert end is UpdateEnd.REFUSED
    err = errors(capsys)
    assert tip in err
    assert "nothing changed" in err


@pytest.mark.parametrize(
    ("answer", "said"),
    [
        pytest.param(answered(1), "no fast-forward", id="git says it does not descend from HEAD"),
        pytest.param(answered(128, b"", b"fatal: boom\n"), "cannot read", id="git cannot tell"),
    ],
)
def test_a_pinned_sha_git_cannot_confirm_as_a_fast_forward_is_refused(world, capsys, answer, said):
    """R3."""
    world.wait(*subjects("waiting"))

    end = world.run(git=Tamper(world, "merge-base", answer, merged=True))

    assert end is UpdateEnd.REFUSED
    assert said in errors(capsys)


def test_waiting_commits_git_cannot_list_end_the_run_before_the_question(world, capsys):
    """A2: the listing fails; nothing is asked and nothing changed."""
    world.wait(*subjects("waiting"))

    end = world.run(git=Tamper(world, "diff", answered(128, b"", b"fatal: boom\n"), merged=True))

    assert end is UpdateEnd.FAILED
    assert "cannot list the waiting commits" in errors(capsys)
    assert "Type yes" not in world.stdout()


# --- the merge ----------------------------------------------------------------------------------


@pytest.mark.parametrize("refusal", ["ignored file in the way", "index lock"])
def test_a_merge_git_refuses_before_changing_anything_is_failed_with_nothing_changed(
    world, capsys, refusal
):
    """M2: an ignored local file lies where the merge brings a tracked one (R4). M3: an index
    lock."""
    (world.live / ".env").write_text("local\n")
    brought = ".env" if refusal == "ignored file in the way" else "README.md"
    tip = world.wait(edit(brought, "from origin\n"))
    before = head_of(world.live)
    lock = (world.live / ".git/index.lock").touch if refusal == "index lock" else None

    end = world.run(at_the_question=lock)

    err = errors(capsys)
    assert end is UpdateEnd.FAILED
    assert head_of(world.live) == before
    assert tip in err
    assert "nothing changed" in err
    assert err.endswith("next: hal update\n")
    assert (world.live / ".env").read_text() == "local\n"


@pytest.mark.parametrize("damage", ["head moved", "branch changed", "path changed", "unreadable"])
def test_a_refused_merge_that_left_a_mark_is_partial_never_nothing_changed(world, capsys, damage):
    """M6: O3, whatever git left behind; git's refusal is simulated, the merge never runs, so
    only the check of what changed tells O3 from O2."""
    tip = world.wait(*subjects("waiting"))
    effects = {
        "head moved": lambda: plain_git(world.live, "merge", "-q", "--ff-only", tip),
        "branch changed": lambda: plain_git(world.live, "switch", "-q", "-c", "other"),
        "path changed": lambda: (world.live / "README.md").write_text("edited\n"),
        "unreadable": lambda: (world.live / ".git/index").write_bytes(b"not an index"),
    }
    refuse = Tamper(
        world, "merge", answered(1, b"", b"fatal: refused\n"), effect=effects[damage], merged=True
    )

    end = world.run(git=refuse)

    err = errors(capsys)
    assert end is UpdateEnd.FAILED
    assert tip in err
    assert "partial" in err
    assert "merge" in err
    assert "nothing changed" not in err
    assert err.endswith("next: hal apply\n")


# --- the checks after the merge -----------------------------------------------------------------

READ_ANSWERS = {
    "HEAD moved": ("rev-parse", answered(0, b"1" * 40 + b"\n")),
    "branch changed": ("symbolic-ref", answered(0, b"refs/heads/other\n")),
    "tree dirty": ("status", answered(0, b" M README.md\0")),
    "HEAD unreadable": ("rev-parse", answered(128, b"", b"fatal: boom\n")),
    "branch unreadable": ("symbolic-ref", answered(128, b"", b"fatal: boom\n")),
    "status unreadable": ("status", answered(128, b"", b"fatal: boom\n")),
}


@pytest.mark.parametrize(
    ("stage", "trouble"),
    [
        *(("merged", trouble) for trouble in READ_ANSWERS),
        ("synced", "HEAD moved"),
        ("synced", "HEAD unreadable"),
    ],
)
def test_a_head_branch_or_tree_that_is_not_the_approved_one_after_a_step_is_partial(
    world, capsys, stage, trouble
):
    """M5: O4 after the merge, mismatch or unreadable; S5: O7 after the sync, HEAD only."""
    tip = world.wait(*subjects("waiting"))
    verb, answer = READ_ANSWERS[trouble]

    end = world.run(git=Tamper(world, verb, answer, stage=stage))

    err = errors(capsys)
    step = f"check HEAD after the {'merge' if stage == 'merged' else 'sync'}"
    assert end is UpdateEnd.FAILED
    assert tip in err
    assert "partial" in err
    assert step in err
    assert "nothing changed" not in err
    assert err.endswith("next: hal apply\n")
    assert (world.log / "sync.args").exists() == (stage == "synced")
    assert head_of(world.live) == tip


def test_an_unexpected_error_after_the_merge_is_partial_with_its_type_only(world, capsys):
    """M5: O8."""
    tip = world.wait(*subjects("waiting"))

    def explode(*_):
        raise RuntimeError("secret text")

    end = world.run(git=Tamper(world, "status", explode))

    err = errors(capsys)
    assert end is UpdateEnd.FAILED
    assert tip in err
    assert "unexpected error (RuntimeError)" in err
    assert "secret text" not in err


# --- the sync ----------------------------------------------------------------------------------


def test_the_sync_is_the_merged_trees_script_with_the_checkout_alone_and_inherits_nothing(world):
    """S1: no lock descriptor, SIGINT neither blocked nor ignored, its own process group in the
    caller's session."""
    world.wait(*subjects("waiting"))

    assert world.run() is UpdateEnd.DONE

    assert world.logged("sync.args").splitlines() == [str(world.live)]
    assert str(world.state / apply.APPLY_LOCK) not in world.logged("sync.fds")
    masks = [int(line.split()[1], 16) for line in world.logged("sync.mask").splitlines()]
    assert len(masks) == 2
    assert not any(mask & 1 << (signal.SIGINT - 1) for mask in masks)
    assert world.logged("sync.ids").split() == [world.logged("sync.pid").strip(), str(os.getsid(0))]


@pytest.mark.parametrize("sync", ["exits 1", "is not executable"])
def test_a_failed_sync_is_partial_and_never_names_uv_sync(world, capsys, monkeypatch, sync):
    """S2: O5 with uv's last line, credentials redacted (R3). S3: the merged commit carries the
    script without its executable bit. HEAD stays at the sha, the record unchanged; then the retry
    finds nothing behind."""
    if sync == "exits 1":
        tip = world.wait(*subjects("waiting"))
        monkeypatch.setenv("FAKE_SYNC", "fail")
    else:
        tip = world.wait(edit("bin/hal-sync", FAKE_SYNC))

    end = world.run()

    err = errors(capsys)
    assert end is UpdateEnd.FAILED
    assert tip in err
    assert "sync the dependencies" in err
    assert "hunter2" not in err
    uv_line = "uv: cannot fetch https://<redacted>@pypi.invalid/simple"
    assert (uv_line in err) == (sync == "exits 1")
    assert "uv sync" not in err + world.stdout()
    assert err.endswith("next: hal apply\n")
    assert head_of(world.live) == tip
    assert world.record() == APPLIED_RECORD
    world.output = Terminal()
    assert world.run() is UpdateEnd.DONE
    assert world.stdout().splitlines()[-1] == "next: hal apply"


# --- the whole run ----------------------------------------------------------------------------


def test_a_yes_fast_forwards_syncs_and_names_the_apply_without_touching_the_record(world, capsys):
    """E1, and E3 without `-v`: nothing on stderr."""
    tip = world.wait(edit("README.md"), edit("src/hal/x.py"))
    short = plain_git(world.live, "rev-parse", "--short", tip).stdout.strip()

    end = world.run()

    out = world.stdout().splitlines()
    assert end is UpdateEnd.DONE
    assert head_of(world.live) == tip
    assert (world.live / "README.md").read_text() == "changed\n"
    assert plain_git(world.live, "status", "--porcelain").stdout == ""
    assert world.record() == APPLIED_RECORD
    assert world.lock_is_free
    assert out[-2].startswith("✓ checkout updated to ")
    assert out[-2].endswith("dependencies synced")
    assert out[-1] == "next: hal apply"
    assert short in out[-2]
    assert errors(capsys) == ""


def test_nothing_is_imported_between_the_merge_and_the_return(world):
    """E2: the editable install would read the merged code into this process."""
    world.wait(edit("src/hal/stack/update.py", "raise SystemExit\n"))
    seen = {}

    def snapshot(tree, arguments, profile):
        result = checkout.run_git(tree, arguments, profile)
        if "merge" in arguments:
            seen["after the merge"] = set(sys.modules)
        return result

    assert world.run(git=snapshot) is UpdateEnd.DONE
    assert set(sys.modules) == seen["after the merge"]


def test_verbose_echoes_every_git_call_and_the_sync_command_without_the_environment(
    world, capsys, monkeypatch
):
    """E3."""
    world.wait(*subjects("waiting"))
    monkeypatch.setenv("SECRET_TOKEN", "hunter2")

    with verbose_run(True):
        world.run()

    err = errors(capsys)
    assert "git fetch" in err
    assert "git merge --ff-only" in err
    assert f"{world.live / 'bin/hal-sync'} {world.live}" in err
    assert "hunter2" not in err
    assert "SECRET_TOKEN" not in err
