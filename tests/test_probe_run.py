"""The probes' shared run loop (#842): `edge_copy.run_probe` and `run_main` empty --scratch after
the teardown on every way out, and remove only what lies under the directory they opened first."""

import os
import signal
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "probe"))
sys.path.insert(0, str(ROOT / "src"))

import edge_copy  # noqa: E402
from support.git_support import committed_main  # noqa: E402

PASSED = "PROBE PASSED"
SENTINEL = "sentinel"


@pytest.fixture(autouse=True)
def restored_signal_handlers(request):
    for number in (signal.SIGTERM, signal.SIGINT):
        request.addfinalizer(partial(signal.signal, number, signal.getsignal(number)))


@pytest.fixture
def scratch(tmp_path):
    directory = tmp_path / "scratch"
    directory.mkdir()
    return directory


@dataclass
class FakeProbe:
    events: list[str]
    teardown_action: Callable[[], None] = lambda: None
    scratch: Path | None = None

    def teardown(self) -> None:
        self.events.append(
            "sentinel kept" if (self.scratch / SENTINEL).exists() else "sentinel gone"
        )
        self.teardown_action()
        self.events.append("teardown ended")


@dataclass
class Scenario:
    """A fake probe that fills the scratch, as the real ones do, and records what happened."""

    scratch: Path
    events: list[str] = field(default_factory=list)
    prove_action: Callable[[], int] = lambda: 0
    teardown_action: Callable[[], None] = lambda: None
    extra: Callable[[Path], None] = lambda scratch: None
    create_error: BaseException | None = None

    def create(self, scratch: Path) -> FakeProbe:
        self.events.append("create")
        for directory in ("home/srv/hal/.venv/lib", "origin.git/objects", "work/src"):
            (scratch / directory).mkdir(parents=True)
            (scratch / directory / "file").write_text("x")
        (scratch / SENTINEL).write_text("x")
        self.extra(scratch)
        if self.create_error:
            raise self.create_error
        return FakeProbe(self.events, self.teardown_action, scratch)

    def prove(self, _probe: FakeProbe) -> int:
        self.events.append("prove")
        return self.prove_action()

    def run(self) -> int:
        return edge_copy.run_probe(self.scratch, self.create, self.prove, PASSED)


def listing(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir())


def printed(capsys) -> list[str]:
    return capsys.readouterr().out.splitlines()


def raising(error: BaseException) -> Callable[[], None]:
    def action() -> None:
        raise error

    return action


def terminated() -> int:
    os.kill(os.getpid(), signal.SIGTERM)
    return 0


@pytest.fixture
def unlockable():
    """Directories a test made unwritable, writable again before pytest removes them."""
    made: list[Path] = []
    yield made
    for directory in made:
        directory.chmod(0o700)


def make_unwritable(made: list[Path]) -> Callable[[Path], None]:
    def extra(scratch: Path) -> None:
        locked = scratch / "locked"
        locked.mkdir()
        (locked / "file").write_text("x")
        locked.chmod(0o500)
        made.append(locked)

    return extra


@pytest.mark.parametrize(
    ("proof_exit", "teardown_error", "exit_code", "lines"),
    [
        (0, None, 0, [PASSED]),
        (1, None, 1, []),
        (0, edge_copy.ProbeFailed("boom"), 1, ["PROBE FAILED: teardown, boom"]),
    ],
    ids=["passed", "failed-proof", "failed-teardown"],
)
def test_a_run_ends_with_an_empty_scratch_after_the_teardown(
    scratch, capsys, proof_exit, teardown_error, exit_code, lines
):
    run = Scenario(
        scratch,
        prove_action=lambda: proof_exit,
        teardown_action=raising(teardown_error) if teardown_error else lambda: None,
    )

    assert run.run() == exit_code
    assert listing(scratch) == []
    assert printed(capsys) == lines
    assert "sentinel kept" in run.events


@pytest.mark.parametrize(
    ("prove_action", "teardown_error", "escaping"),
    [
        (raising(ValueError("proof")), None, ValueError),
        (terminated, None, KeyboardInterrupt),
        (lambda: 0, ValueError("teardown"), ValueError),
    ],
    ids=["prove-raises", "prove-stopped", "teardown-raises"],
)
def test_an_escaped_exception_tears_down_empties_and_propagates(
    scratch, capsys, prove_action, teardown_error, escaping
):
    run = Scenario(
        scratch,
        prove_action=prove_action,
        teardown_action=raising(teardown_error) if teardown_error else lambda: None,
    )

    with pytest.raises(escaping):
        run.run()

    assert "sentinel kept" in run.events
    assert listing(scratch) == []
    assert PASSED not in printed(capsys)


def test_a_stop_during_create_empties_the_scratch_and_propagates(scratch):
    def stop_after_writing(directory: Path) -> None:
        (directory / "late").write_text("x")
        os.kill(os.getpid(), signal.SIGTERM)

    run = Scenario(scratch, extra=stop_after_writing)

    with pytest.raises(KeyboardInterrupt):
        run.run()

    assert run.events == ["create"]
    assert listing(scratch) == []


def test_a_failed_create_empties_the_scratch_and_raises(scratch):
    run = Scenario(scratch, create_error=RuntimeError("create"))

    with pytest.raises(RuntimeError):
        run.run()

    assert run.events == ["create"]
    assert listing(scratch) == []


def test_a_ctrl_c_during_the_teardown_and_the_removal_cuts_neither_short(scratch, monkeypatch):
    interrupts = []
    real_unlink = os.unlink

    def interrupting_unlink(*arguments, **keywords):
        if not interrupts:
            interrupts.append("unlink")
            os.kill(os.getpid(), signal.SIGINT)
        return real_unlink(*arguments, **keywords)

    def interrupt() -> None:
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(os, "unlink", interrupting_unlink)
    run = Scenario(scratch, teardown_action=interrupt)

    assert run.run() == 0
    assert interrupts == ["unlink"]
    assert "teardown ended" in run.events
    assert listing(scratch) == []


def test_a_failed_removal_names_the_path_and_exits_one(scratch, capsys, unlockable):
    run = Scenario(scratch, extra=make_unwritable(unlockable))

    assert run.run() == 1

    lines = printed(capsys)
    assert any(line.startswith(f"PROBE FAILED: --scratch not emptied, {scratch}") for line in lines)
    assert PASSED not in lines


def test_a_failed_removal_while_an_exception_propagates_still_names_the_path(
    scratch, capsys, unlockable
):
    run = Scenario(
        scratch, prove_action=raising(ValueError("proof")), extra=make_unwritable(unlockable)
    )

    with pytest.raises(ValueError, match="proof"):
        run.run()

    lines = printed(capsys)
    assert any(line.startswith(f"PROBE FAILED: --scratch not emptied, {scratch}") for line in lines)
    assert PASSED not in lines


def test_the_previous_signal_handlers_come_back(scratch):
    def terminate(_number, _frame):
        pass

    signal.signal(signal.SIGTERM, terminate)
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    Scenario(scratch).run()

    assert signal.getsignal(signal.SIGTERM) is terminate
    assert signal.getsignal(signal.SIGINT) is signal.SIG_DFL


def test_a_scratch_that_is_not_empty_is_refused_untouched(scratch, capsys):
    (scratch / "kept").write_text("x")
    run = Scenario(scratch)

    assert run.run() == edge_copy.NOT_RUNNABLE

    assert printed(capsys) == ["PROBE FAILED: --scratch is not empty"]
    assert listing(scratch) == ["kept"]
    assert run.events == []


def test_symlinks_are_removed_and_never_followed(scratch, tmp_path):
    outside = tmp_path / "outside"
    (outside / "inner").mkdir(parents=True)
    (outside / "inner" / "file").write_text("x")
    (tmp_path / "outside-file").write_text("x")

    def link(directory: Path) -> None:
        (directory / "to-directory").symlink_to(outside, target_is_directory=True)
        (directory / "to-file").symlink_to(tmp_path / "outside-file")
        (directory / "work" / "to-directory").symlink_to(outside, target_is_directory=True)

    assert Scenario(scratch, extra=link).run() == 0

    assert listing(scratch) == []
    assert listing(outside) == ["inner"]
    assert (outside / "inner" / "file").exists()
    assert (tmp_path / "outside-file").exists()


def test_nothing_above_the_scratch_is_removed(scratch, tmp_path):
    (tmp_path / "sibling").write_text("x")

    assert Scenario(scratch).run() == 0

    assert listing(tmp_path) == ["scratch", "sibling"]


def test_removal_stays_bound_to_the_directory_that_was_opened(scratch, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "file").write_text("x")
    moved = tmp_path / "moved"

    def swap(directory: Path) -> None:
        directory.rename(moved)
        directory.symlink_to(elsewhere, target_is_directory=True)

    assert Scenario(scratch, extra=swap).run() == 0

    assert listing(elsewhere) == ["file"]
    assert listing(moved) == []


@pytest.mark.parametrize(
    ("swapped_before_open", "refused"), [(True, True), (False, False)], ids=["before", "after"]
)
def test_the_emptiness_check_reads_the_directory_that_was_opened(
    scratch, tmp_path, monkeypatch, capsys, swapped_before_open, refused
):
    real_open = os.open
    aside = tmp_path / "aside"

    def swap_in_a_directory_holding_a_file() -> None:
        scratch.rename(aside)
        scratch.mkdir()
        (scratch / "swapped-in").write_text("x")

    def open_with_a_swap(path, *arguments, **keywords):
        if os.fspath(path) != os.fspath(scratch):
            return real_open(path, *arguments, **keywords)
        if swapped_before_open:
            swap_in_a_directory_holding_a_file()
        descriptor = real_open(path, *arguments, **keywords)
        if not swapped_before_open:
            swap_in_a_directory_holding_a_file()
        return descriptor

    monkeypatch.setattr(os, "open", open_with_a_swap)
    run = Scenario(scratch)

    exit_code = run.run()

    assert (exit_code == edge_copy.NOT_RUNNABLE) is refused
    assert (run.events == []) is refused
    assert (scratch / "swapped-in").read_text() == "x"
    assert listing(aside) == []


def test_a_symlinked_scratch_is_refused_before_anything_is_created(tmp_path, capsys):
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    link.symlink_to(target, target_is_directory=True)
    run = Scenario(link)

    exit_code = edge_copy.run_main("probe", ["--scratch", str(link)], run.create, run.prove, PASSED)

    assert exit_code == edge_copy.NOT_RUNNABLE
    assert run.events == []
    assert target.is_dir()
    assert link.is_symlink()


def test_the_real_copy_venv_remote_and_work_clone_are_removed(tmp_path, scratch):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "fleet.yaml").write_text("services: {}\n")
    (repository / "compose.yaml").write_text("networks:\n  mcp:\n    name: hal_mcp\n")
    (repository / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0"\nrequires-python = ">=3.12"\n'
        "dependencies = []\n"
    )
    committed_main(repository)
    before = sorted(str(path.relative_to(repository)) for path in repository.rglob("*"))
    home = scratch / "home"

    def create(directory: Path) -> FakeProbe:
        home.mkdir()
        edge_copy.repository_copy(repository, home, directory)
        edge_copy.advance_origin(directory, "advance", {"fleet.yaml": "# more\n"})
        assert (directory / edge_copy.WORK_CLONE).is_dir()
        return FakeProbe([], scratch=directory)

    assert edge_copy.run_probe(scratch, create, lambda _probe: 0, PASSED) == 0

    assert listing(scratch) == []
    assert sorted(str(path.relative_to(repository)) for path in repository.rglob("*")) == before
    status = subprocess.run(
        ["git", "-C", str(repository), "status", "--porcelain"],
        capture_output=True, text=True, check=True,
    )  # fmt: skip
    assert status.stdout == ""
