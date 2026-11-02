"""The world of `hal update` tests (#783): a live checkout on real git under a throwaway home, its
bare origin, the state directory, and a fake `bin/hal-sync` the repository itself carries. A module
that uses `world` also takes `support.throwaway_home.home`."""

import fcntl
import json
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from support.git_support import advance, committed_main, with_origin
from support.stack_apply_fakes import Terminal
from support.stack_plan_rows import plain

from hal.stack import apply, checkout, compose, switches, update
from hal.stack.update import UpdateEnd

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
    sleep 30 &
    echo $! > "$FAKE_LOG/sync.child"
    kill -INT "$PPID"
    wait ;;
hold) sleep 10 ;;
esac
touch "$FAKE_LOG/sync.done"
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
