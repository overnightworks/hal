"""`hal update` at its entry point (#783): the checkout of the live tree brought to origin's `main`
after one `yes`, on real git in `tmp_path`, with a real child as the sync and real signals where a
cell names them. The sync is a fake `bin/hal-sync` that the repository itself carries."""

import fcntl
import json
import os
import shutil
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
import support.throwaway_home as throwaway_home
from support.git_support import advance, committed_main, head_of, plain_git, subjects, with_origin
from support.process_support import group_is_gone
from support.stack_apply_fakes import Terminal
from support.stack_plan_rows import plain

from hal import cli
from hal.grammar import ExitCode
from hal.output import verbose_run
from hal.stack import apply, checkout, compose, switches, update
from hal.stack import cli as stack_cli
from hal.stack.update import UpdateEnd

home = throwaway_home.home

FAKE_SYNC = """#!/bin/sh
echo "$$" > "$FAKE_LOG/sync.pid"
printf '%s\\n' "$@" > "$FAKE_LOG/sync.args"
for descriptor in /proc/$$/fd/*; do readlink "$descriptor"; done > "$FAKE_LOG/sync.fds"
grep -E 'SigBlk|SigIgn' /proc/$$/status > "$FAKE_LOG/sync.mask"
ps -o pgid=,sid= -p $$ > "$FAKE_LOG/sync.ids"
case "${FAKE_SYNC-}" in
fail) echo "uv: cannot fetch https://operator:hunter2@pypi.invalid/simple" >&2; exit 1 ;;
lock) flock -n -x "$FAKE_LOCK" -c true; echo $? > "$FAKE_LOG/sync.lock" ;;
interrupt)
    sleep 300 &
    echo $! > "$FAKE_LOG/sync.child"
    kill -INT "$PPID"
    wait ;;
hold) sleep 10 ;;
esac
touch "$FAKE_LOG/sync.done"
"""
SIGNALLING_GIT = """#!/bin/sh
case "${FAKE_SIGNAL-}:$*" in
merge:*" merge "*|synced:*" rev-parse "*)
    if [ "$FAKE_SIGNAL" = merge ] || [ -e "$FAKE_LOG/sync.done" ]; then
        kill -INT -"$(ps -o pgid= -p "$PPID" | tr -d ' ')"
    fi ;;
esac
exec "$REAL_GIT" "$@"
"""
APPLIED_RECORD = b'{"recorded": "before"}\n'


@dataclass
class World:
    live: Path
    origin: Path
    log: Path
    state: Path
    output: Terminal

    def run(self, answer: str | None = "yes", **options) -> UpdateEnd:
        keyboard = Terminal("" if answer is None else f"{answer}\n")  # None: stdin closed
        keyboard.while_prompt_waits = options.pop("at_the_question", None)
        sys.stdin, sys.stdout = keyboard, self.output
        sys.stderr = options.pop("stderr", sys.stderr)
        return update.update_checkout(
            self.state,
            options.pop("repository", self.live),
            options.pop("home", None),
            options.pop("git", checkout.run_git),
            options.pop("engine", Engine(self.live)),
        )

    @property
    def lock_is_free(self) -> bool:
        with (self.state / apply.APPLY_LOCK).open("w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            return True

    def wait(self, *commits: tuple[bytes, dict[bytes, bytes]]) -> str:
        return advance(self.origin, *commits)

    def logged(self, name: str) -> str:
        return (self.log / name).read_text()

    def stdout(self) -> str:
        return plain(self.output.getvalue())

    def record(self) -> bytes:
        return (self.state / "applied.json").read_bytes()


@dataclass
class Engine:
    """Compose as the update reads it: the binds `compose.json` of the tree names."""

    tree: Path
    fails: bool = False

    def resolved_configuration(self) -> dict:
        if self.fails:
            raise compose.ComposeError("`docker compose config` exited 1: broken")
        binds = json.loads((self.tree / "compose.json").read_text())
        mounts = [{"type": "bind", "source": str(self.tree / bind)} for bind in binds]
        return {"services": {"web": {"volumes": mounts}}}


def edit(path: str, content: str = "changed\n") -> tuple[bytes, dict[bytes, bytes]]:
    return (f"edit {path}".encode(), {path.encode(): content.encode()})


@pytest.fixture
def world(home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys) -> Iterator[World]:
    live = checkout.live_checkout(home)
    for name, text in {
        "README.md": "readme\n",
        "dynamic/.gitkeep": "",
        "legal/nginx/default.conf": "server {}\n",
        "traefik.yml": "entryPoints: {}\n",
        "fleet.yaml": "services: {}\n",
        "compose.json": json.dumps(["dynamic", "legal/nginx", "traefik.yml"]),
        "bin/hal-sync": FAKE_SYNC,
    }.items():
        (live / name).parent.mkdir(parents=True, exist_ok=True)
        (live / name).write_text(text)
    (live / "bin/hal-sync").chmod(0o755)
    committed_main(live)
    with_origin(live, tmp_path / "origin.git")
    log = tmp_path / "log"
    log.mkdir()
    state = switches.default_state_directory()
    state.mkdir(parents=True)
    (state / "applied.json").write_bytes(APPLIED_RECORD)
    monkeypatch.setenv("FAKE_LOG", str(log))
    monkeypatch.setenv("FAKE_LOCK", str(state / apply.APPLY_LOCK))
    monkeypatch.setenv("REAL_GIT", shutil.which("git"))
    saved = sys.stdin, sys.stdout, sys.stderr
    yield World(live, tmp_path / "origin.git", log, state, Terminal())
    sys.stdin, sys.stdout, sys.stderr = saved


def errors(capsys) -> str:
    return capsys.readouterr().err


@pytest.fixture
def signalling_git(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Callable]:
    """A `git` on PATH that sends SIGINT to the run's process group, as a terminal's Ctrl-C does,
    on the call the returned setter names. pytest leads its own group meanwhile, so the signal
    reaches nothing of the group that started it (a session leader leads one already)."""
    shim = tmp_path / "shim"
    shim.mkdir()
    (shim / "git").write_text(SIGNALLING_GIT)
    (shim / "git").chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim}{os.pathsep}{os.environ['PATH']}")
    started_in = os.getpgrp()
    if started_in != os.getpid():
        os.setpgid(0, 0)
    yield lambda signal_on: monkeypatch.setenv("FAKE_SIGNAL", signal_on)
    monkeypatch.delenv("FAKE_SIGNAL", raising=False)
    if started_in != os.getpid():
        os.setpgid(0, started_in)


def interrupt(*_) -> None:
    os.kill(os.getpid(), signal.SIGINT)


def answered(code: int, stdout: bytes = b"", stderr: bytes = b"") -> Callable[..., object]:
    return lambda *_: subprocess.CompletedProcess([], code, stdout, stderr)


@dataclass
class Tamper:
    """The real git, but one verb answers otherwise, without running, once the stage is reached:
    `merged` from the merge on, `synced` once the sync has ended; `effect` runs first on the real
    checkout."""

    world: World
    verb: str
    answer: Callable[..., object]
    stage: str = "merged"
    effect: Callable[[], None] = lambda: None
    merged: bool = False

    def __call__(self, tree, arguments, profile):
        verb = next(argument for argument in arguments if not argument.startswith("-"))
        synced = (self.world.log / "sync.done").exists()
        if verb == self.verb and (synced if self.stage == "synced" else self.merged):
            self.effect()
            return self.answer(tree, arguments, profile)
        real = checkout.run_git(tree, arguments, profile)
        self.merged = self.merged or (verb == "merge" and real.returncode == 0)
        return real


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
    assert errors(capsys).splitlines()[0].startswith(line) and world.stdout() == ""


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
    assert "✓ checkout" in world.stdout() and "current" in world.stdout()
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
    assert head_of(world.live) == before and world.lock_is_free
    assert not (world.log / "sync.args").exists()
    assert world.record() == APPLIED_RECORD


def test_every_waiting_commit_is_a_line_escaped_and_untruncated(world):
    """A2: 500 commits, one subject with ESC."""
    world.wait((b"red \x1b[31m", {}), *subjects(*(f"commit {n}" for n in range(499))))

    world.run("no")

    shown = world.stdout()
    assert shown.count("commit ") >= 499 and "red \\x1b[31m" in shown
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
    assert "not classified" in world.stdout() and "Type yes to update" in world.stdout()


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


@pytest.mark.parametrize("moment", ["at the question", "during the recheck"])
def test_a_ctrl_c_before_the_merge_is_the_doors_130_and_changes_nothing(
    world, capsys, monkeypatch, moment
):
    """A4: a real SIGINT while the question waits or while the recheck asks git."""
    world.wait(*subjects("waiting"))
    before = head_of(world.live)
    recheck = Tamper(world, "merge-base", interrupt, merged=True)
    hit = {
        "at the question": {"at_the_question": interrupt},
        "during the recheck": {"git": recheck},
    }
    monkeypatch.setattr(stack_cli, "update_checkout", lambda: world.run(**hit[moment]))

    assert cli.main(["update"]) == ExitCode.INTERRUPTED
    assert head_of(world.live) == before and world.lock_is_free
    assert errors(capsys) == "" and "updated" not in world.stdout()


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
    assert said[change] in seen and "nothing changed" in seen
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
    assert tip in err and "nothing changed" in err


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
    assert end is UpdateEnd.FAILED and head_of(world.live) == before
    assert tip in err and "nothing changed" in err and err.endswith("next: hal update\n")
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
    assert tip in err and "partial" in err and "merge" in err
    assert "nothing changed" not in err and err.endswith("next: hal apply\n")


@pytest.mark.parametrize("moment", ["merge succeeds", "merge refused", "check fails", "synced"])
def test_a_real_ctrl_c_from_the_merge_on_waits_and_ends_interrupted_with_its_line_only(
    world, capsys, signalling_git, moment
):
    """M4: the group's SIGINT reaches the run while git merges in its own session; the merge ends
    and the sync never starts. O6: a merge git refuses, or a failed check after it, still ends
    130, with only its line; a refusal that changed nothing says so and names `hal update`. S6:
    a SIGINT after the sync names the HEAD check."""
    start, tip = head_of(world.live), world.wait(*subjects("waiting"))
    refused, synced = moment == "merge refused", moment == "synced"
    signalling_git("synced" if synced else "merge")
    hit = {
        "merge refused": {"at_the_question": (world.live / ".git/index.lock").touch},
        "check fails": {"git": Tamper(world, "status", answered(0, b" M README.md\0"))},
    }

    end = world.run(**hit.get(moment, {}))
    signalling_git("")

    error, next_line = errors(capsys).splitlines()
    assert end is UpdateEnd.INTERRUPTED and head_of(world.live) == (start if refused else tip)
    assert error.startswith("error: interrupted at '") and tip in error
    assert f"the sync had {'ended' if synced else 'not started'}" in error
    assert ("nothing changed" in error) == refused
    assert ("'check HEAD after the sync'" in error) == synced
    assert next_line == f"next: hal {'update' if refused else 'apply'}"
    assert (world.log / "sync.args").exists() == synced and world.lock_is_free
    assert world.record() == APPLIED_RECORD


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
    assert end is UpdateEnd.FAILED and tip in err and "partial" in err and step in err
    assert "nothing changed" not in err and err.endswith("next: hal apply\n")
    assert (world.log / "sync.args").exists() == (stage == "synced") and head_of(world.live) == tip


def test_an_unexpected_error_after_the_merge_is_partial_with_its_type_only(world, capsys):
    """M5: O8."""
    tip = world.wait(*subjects("waiting"))

    def explode(*_):
        raise RuntimeError("secret text")

    end = world.run(git=Tamper(world, "status", explode))

    err = errors(capsys)
    assert end is UpdateEnd.FAILED
    assert tip in err and "unexpected error (RuntimeError)" in err and "secret text" not in err


# --- the sync ----------------------------------------------------------------------------------


def test_the_sync_is_the_merged_trees_script_with_the_checkout_alone_and_inherits_nothing(world):
    """S1: no lock descriptor, SIGINT neither blocked nor ignored, its own process group in the
    caller's session."""
    world.wait(*subjects("waiting"))

    assert world.run() is UpdateEnd.DONE

    assert world.logged("sync.args").splitlines() == [str(world.live)]
    assert str(world.state / apply.APPLY_LOCK) not in world.logged("sync.fds")
    masks = [int(line.split()[1], 16) for line in world.logged("sync.mask").splitlines()]
    assert len(masks) == 2 and not any(mask & 1 << (signal.SIGINT - 1) for mask in masks)
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
    assert tip in err and "sync the dependencies" in err and "hunter2" not in err
    uv_line = "uv: cannot fetch https://<redacted>@pypi.invalid/simple"
    assert (uv_line in err) == (sync == "exits 1")
    assert "uv sync" not in err + world.stdout() and err.endswith("next: hal apply\n")
    assert head_of(world.live) == tip and world.record() == APPLIED_RECORD
    world.output = Terminal()
    assert world.run() is UpdateEnd.DONE
    assert world.stdout().splitlines()[-1] == "next: hal apply"


@pytest.mark.parametrize("moment", ["while it runs", "before it is registered"])
def test_a_real_ctrl_c_at_the_sync_kills_its_whole_group_before_the_lock_is_freed(
    world, capsys, monkeypatch, moment
):
    """S4: the stand-in has a child of its own; no process of its group is alive when the update
    returns, also after a Ctrl-C between the sync's start and its registration, and it never
    finished (`hold` would finish after a while)."""
    tip, sync = world.wait(*subjects("waiting")), str(world.live / update.SYNC_SCRIPT)
    monkeypatch.setenv("FAKE_SYNC", "interrupt" if moment == "while it runs" else "hold")
    started = []

    class Started(subprocess.Popen):
        def __init__(self, command, **options) -> None:
            super().__init__(command, **options)
            if command[0] == sync:
                started.append(self.pid)
                if moment == "before it is registered":
                    interrupt()

    monkeypatch.setattr(subprocess, "Popen", Started)
    end = world.run()

    err = errors(capsys)
    assert end is UpdateEnd.INTERRUPTED and tip in err and "half synced" in err
    assert group_is_gone(started[0]) and world.lock_is_free
    assert not (world.log / "sync.done").exists()


class Troubled(Terminal):
    """A terminal on which writing a text that holds `on` runs `trouble` first."""

    def __init__(self, trouble: Callable[[], None], on: str = "checkout updated") -> None:
        super().__init__()
        self.trouble, self.on = trouble, on

    def write(self, text: str) -> int:
        if self.on in text:
            self.trouble()
        return super().write(text)


def broken_pipe() -> None:
    raise BrokenPipeError


@pytest.mark.parametrize("trouble", [interrupt, broken_pipe], ids=["Ctrl-C", "output fails"])
def test_a_ctrl_c_or_an_output_failure_at_the_closing_verdict_names_the_sha_and_the_step(
    world, monkeypatch, trouble
):
    """O6: a real SIGINT while the closing verdict is written ends 130, and a second one while
    the O6 line is written still leaves that whole line; O8: a failing output 3."""
    tip = world.wait(*subjects("waiting"))
    world.output, stderr = Troubled(trouble), Troubled(interrupt, on="interrupted")
    monkeypatch.setattr(stack_cli, "update_checkout", lambda: world.run(stderr=stderr))

    code = cli.main(["update"])

    err = plain(stderr.getvalue())
    assert code == (ExitCode.INTERRUPTED if trouble is interrupt else ExitCode.FAILURE)
    assert tip in err and "'write the closing verdict'" in err and err.endswith("next: hal apply\n")
    assert ("unexpected error (BrokenPipeError)" in err) == (trouble is broken_pipe)
    assert head_of(world.live) == tip and world.lock_is_free


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
    assert world.record() == APPLIED_RECORD and world.lock_is_free
    assert out[-2].startswith("✓ checkout updated to ") and out[-2].endswith("dependencies synced")
    assert out[-1] == "next: hal apply" and short in out[-2]
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
    assert "git fetch" in err and "git merge --ff-only" in err
    assert f"{world.live / 'bin/hal-sync'} {world.live}" in err
    assert "hunter2" not in err and "SECRET_TOKEN" not in err
