"""Real git repositories under `tmp_path` and runs of hal's console script against them, shared by
the tests of `hal.stack.checkout` and `hal`.

Nothing here sets GIT_CONFIG_GLOBAL: the code under test drops every `GIT_*` variable, so a test
setting one would prove nothing. A test module points HOME and XDG_CONFIG_HOME at throwaway
directories, so a global git config is one that test wrote."""

import os
import shutil
import subprocess
import sys
from collections.abc import Collection, Mapping
from pathlib import Path

from hal.stack import checkout

SOURCE = Path(__file__).resolve().parents[2] / "src"
HAL_SOURCE = SOURCE / "hal"
IGNORED = ".env\n/dynamic/switch-*\n.venv/\n__pycache__/\n"
# What a fetch of origin's main may write to `.git`, by path or directory (#98 rule 5).
FETCH_WRITES = (
    "objects",
    "FETCH_HEAD",
    "refs/remotes/origin/main",
    "logs/refs/remotes/origin/main",
)


def plain_git(
    tree: Path, *arguments: str, environment: Mapping[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Git as the operator's shell runs it, global config, hooks and all (the positive control),
    but with no `GIT_*` of the shell that runs the tests, and `environment` on top."""
    inherited = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    environment = inherited | dict(environment or {})
    return subprocess.run(
        ["git", "-C", str(tree), *arguments],
        capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, env=environment,
    )  # fmt: skip


def committed_main(tree: Path) -> Path:
    """`tree`'s files committed as the one commit of a fresh `main`, with this repository's
    ignores, an ignored `.env` and a repository identity; the fixture's own commit runs no hook."""
    tree.mkdir(parents=True, exist_ok=True)
    (tree / ".gitignore").write_text(IGNORED)
    (tree / ".env").touch()
    plain_git(tree, "init", "--quiet", "--initial-branch", checkout.MAIN)
    for key, value in (("user.name", "edge test"), ("user.email", "test@edge.invalid")):
        plain_git(tree, "config", key, value)
    plain_git(tree, "add", "--all")
    plain_git(tree, "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "--message", "init")
    return tree


def with_origin(tree: Path, bare: Path) -> Path:
    """`tree`'s `main` pushed to a fresh bare repository at `bare`, its `file://` remote."""
    plain_git(tree, "init", "--quiet", "--bare", "--initial-branch", checkout.MAIN, str(bare))
    plain_git(tree, "remote", "add", "origin", bare.as_uri())
    plain_git(tree, "push", "--quiet", "origin", checkout.MAIN)
    return bare


def advance(bare: Path, *commits: tuple[bytes, Mapping[bytes, bytes]]) -> str:
    """`commits` (each a raw message and the files it writes) appended to `bare`'s `main` by
    `git fast-import`, as a merged pull request would bring them; the new tip's sha. Raw bytes,
    so a message or a path may hold what no editor would type."""
    tip = plain_git(bare, "rev-parse", checkout.MAIN).stdout.strip()
    stream = bytearray()
    for number, (message, files) in enumerate(commits):
        stream += b"commit refs/heads/main\ncommitter edge test <test@edge.invalid> 0 +0000\n"
        stream += b"data %d\n%s\n" % (len(message), message)
        if number == 0:
            stream += b"from %s\n" % tip.encode()
        for path, content in files.items():
            stream += b"M 100644 inline %s\ndata %d\n%s\n" % (quoted(path), len(content), content)
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    subprocess.run(
        ["git", "-C", str(bare), "fast-import", "--quiet"],
        input=bytes(stream), capture_output=True, check=True, env=environment,
    )  # fmt: skip
    return plain_git(bare, "rev-parse", checkout.MAIN).stdout.strip()


def quoted(path: bytes) -> bytes:
    """`path` C-quoted as fast-import reads it, so a newline in it stays part of the path."""
    escaped = path.replace(b"\\", b"\\\\").replace(b'"', b'\\"').replace(b"\n", b"\\n")
    return b'"%s"' % escaped


def subjects(*names: str) -> list[tuple[bytes, Mapping[bytes, bytes]]]:
    return [(name.encode(), {}) for name in names]


def head_of(tree: Path) -> str:
    return plain_git(tree, "rev-parse", "HEAD").stdout.strip()


def local_commit(tree: Path, message: str = "local only") -> str:
    plain_git(tree, "-c", "core.hooksPath=/dev/null", "commit", "--quiet", "--allow-empty",
              "--message", message)  # fmt: skip
    return head_of(tree)


def checkout_state(tree: Path, may_change: Collection[str] = FETCH_WRITES) -> dict[str, bytes]:
    """Every file of the checkout, `.git` included, by path, but the `.git` entries named in
    `may_change` (a path or a directory; by default what a fetch writes): what must stay
    byte-identical."""
    state = {}
    for path in sorted(tree.rglob("*")):
        relative = path.relative_to(tree).as_posix()
        inside_git = relative.removeprefix(".git/")
        allowed = any(
            inside_git == name or inside_git.startswith(f"{name}/") for name in may_change
        )
        if path.is_file() and not allowed:
            state[relative] = path.read_bytes()
    state[".git/index mtime"] = str((tree / ".git" / "index").stat().st_mtime_ns).encode()
    return state


def main_checkout(tmp_path: Path, carrying_hal: bool = False) -> Path:
    """A clean `main` at `tmp_path/main` whose `origin/main` equals HEAD; with `carrying_hal`, the
    code under test is committed in it, so the code lives in the checkout it reads."""
    tree = tmp_path / "main"
    if carrying_hal:
        shutil.copytree(
            HAL_SOURCE, tree / "src" / "hal", ignore=shutil.ignore_patterns("__pycache__")
        )
    committed_main(tree)
    with_origin(tree, tmp_path / "origin.git")
    return tree


def linked_worktree(main: Path, tmp_path: Path) -> Path:
    """`main`'s `main` checked out in a linked worktree, whose `.git` is a file; `main` itself is
    detached to free the branch."""
    plain_git(main, "switch", "--detach")
    plain_git(main, "worktree", "add", str(tmp_path / "linked"), checkout.MAIN)
    return tmp_path / "linked"


def hal_program(tree: Path | None = None, before: str = "") -> str:
    """The body uv writes into `.venv/bin/hal`; `tree` points `hal version` at another tree, and
    `before` is Python run first (a fault, a signal handler, a stdin)."""
    point = f"import hal.version, pathlib; hal.version.CODE_TREE = pathlib.Path({str(tree)!r})\n"
    run = "from hal.cli import main\nsys.exit(main())\n"
    return f"import sys\n{point if tree else ''}{before}\n{run}"


def hal_environment(
    source: Path = SOURCE, path_first: Path | None = None, **extra: str
) -> dict[str, str]:
    """The environment of one hal run: the test's own, so coverage's configuration reaches the
    child (F4) and HOME is the test's empty one; hal imports from `source`, then from this
    repository; no bytecode is written, so no tree a test compares gains a `__pycache__`."""
    environment = {**os.environ, "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1", **extra}
    environment["PYTHONPATH"] = os.pathsep.join(dict.fromkeys([str(source), str(SOURCE)]))
    if path_first:
        environment["PATH"] = f"{path_first}{os.pathsep}{environment['PATH']}"
    return environment


def hal_command(program: str, *arguments: str) -> list[str]:
    return [sys.executable, "-c", program, *arguments]


def elsewhere(tmp_path: Path) -> Path:
    """The cwd of every hal run: an empty directory that no checkout encloses."""
    directory = tmp_path / "elsewhere"
    directory.mkdir(exist_ok=True)
    return directory


def assert_quiet_run(stdout: str, stderr: str) -> None:
    """What holds after every hal run: HOME is still empty, no escape sequence, at most one `next:`
    line, no traceback."""
    assert list(Path(os.environ["HOME"]).iterdir()) == []
    assert "\x1b[" not in stdout + stderr
    assert sum(line.startswith("next:") for line in stderr.splitlines()) <= 1
    assert "Traceback" not in stderr


def run_hal(
    tmp_path: Path, program: str, *arguments: str, **environment: Path | str | None
) -> subprocess.CompletedProcess[str]:
    """One run of hal's console script (`hal_program`) from an empty directory; `environment` is
    what `hal_environment` takes."""
    result = subprocess.run(
        hal_command(program, *arguments),
        cwd=elsewhere(tmp_path), env=hal_environment(**environment), stdin=subprocess.DEVNULL,
        capture_output=True, encoding="utf-8", timeout=60,
    )  # fmt: skip
    assert_quiet_run(result.stdout, result.stderr)
    return result
