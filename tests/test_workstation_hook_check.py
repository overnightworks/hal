"""`hal check`'s hook check against real git repositories in a sandboxed HOME."""

from __future__ import annotations

import shlex
import shutil
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
from support.workstation_support import Sandbox, home_check, move_stub_scanner_pins, remove_stub_scanners, run_hal_setup

from hal.grammar import ExitCode
from hal.workstation import hook_check
from hal.workstation.hook_check import HookCheckUnavailable
from hal.workstation.setup import HOOK_NAMES, HOOK_SCANNER
from hal.workstation.layout import Layout, run_command

NOW = datetime(2026, 10, 16, 12, 0)


def git(*arguments: str | Path, cwd: Path | None = None) -> str:
    return subprocess.run(["git", *map(str, arguments)], cwd=cwd, capture_output=True, text=True, check=True).stdout


@dataclass(frozen=True)
class Machine:
    """A sandboxed HOME with a set-up hook, a repository under ~/git and one worktree of it outside ~/git."""

    sandbox: Sandbox
    repo: Path
    outside_worktree: Path

    @property
    def layout(self) -> Layout:
        return self.sandbox.layout

    @property
    def global_config(self) -> Path:
        return self.sandbox.home / ".gitconfig"

    def findings(self) -> dict[tuple[str, str], str]:
        """(rule, subject) -> fix of every finding."""
        return {(f.rule, f.subject): f.fix for f in hook_check.collect_findings(self.layout, run_command)}

    def apply_setup(self) -> None:
        assert run_hal_setup(home=self.sandbox.home, secrets_setup_boundaries=self.sandbox.secrets_boundaries) == ExitCode.OK


@pytest.fixture
def machine(sandbox: Sandbox, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Machine:
    monkeypatch.delenv("GIT_CONFIG_GLOBAL")  # git then reads the global file where `home` expects it: ~/.gitconfig
    shutil.copy(sandbox.global_git_config, sandbox.home / ".gitconfig")
    repo = sandbox.home / "git" / "project"
    git("init", "-q", repo)
    git("commit", "-q", "--allow-empty", "-m", "start", cwd=repo)
    outside_worktree = tmp_path / "outside-worktree"
    git("worktree", "add", "-q", outside_worktree, cwd=repo)
    (sandbox.home / "git" / "notes.txt").write_text("not a repository")
    machine = Machine(sandbox, repo, outside_worktree)
    machine.apply_setup()
    return machine


def test_a_set_up_machine_is_clean_even_with_a_worktree_outside_git(machine: Machine) -> None:
    """#23 rule 2 counterexample: a clone whose effective value comes from the global file is clean, even with a worktree outside ~/git."""
    assert machine.findings() == {}


def test_the_report_of_a_clean_machine_says_so(machine: Machine) -> None:
    """#23 rule 1: the check has one report, which says so when nothing is found."""
    _, report = hook_check.inspect(machine.layout, run_command, NOW)

    assert report.splitlines() == ["# hook 16.10.2026 12:00 | 0 findings", "", "No findings."]


def fix_command(fix: str) -> list[str]:
    return shlex.split(fix.strip("`"))


def test_a_local_hooks_path_is_found_with_its_unset_command_and_clean_after_it(machine: Machine) -> None:
    """#23 rule 2.1: a local hooksPath gives the local-config fix line and is clean after it."""
    git("config", "--local", "core.hooksPath", "/dev/null", cwd=machine.repo)

    (fix,) = [fix for (rule, subject), fix in machine.findings().items() if rule == "hooks-path" and subject == str(machine.repo)]

    assert fix == f"`git -C {machine.repo} config --local --unset core.hooksPath`"
    subprocess.run(fix_command(fix), check=True)
    assert machine.findings() == {}


def test_a_worktree_config_hooks_path_is_found_with_its_unset_command_and_clean_after_it(machine: Machine) -> None:
    """#23 rule 2.1: a worktree-config hooksPath gives the `--worktree` fix line and is clean after it."""
    git("config", "extensions.worktreeConfig", "true", cwd=machine.repo)
    git("config", "--worktree", "core.hooksPath", "/dev/null", cwd=machine.outside_worktree)

    assert list(machine.findings()) == [("hooks-path", str(machine.outside_worktree))]
    fix = machine.findings()[("hooks-path", str(machine.outside_worktree))]
    assert fix == f"`git -C {machine.outside_worktree} config --worktree --unset core.hooksPath`"
    subprocess.run(fix_command(fix), check=True)
    assert machine.findings() == {}


def test_a_conditionally_included_hooks_path_names_the_included_file_and_is_clean_after_removing_it(machine: Machine) -> None:
    """#23 rule 2.1: an includeIf file that sets hooksPath is named, not the global file."""
    included = machine.sandbox.home / "override.gitconfig"
    included.write_text("[core]\n\thooksPath = /dev/null\n")
    with machine.global_config.open("a") as config:
        config.write(f'[includeIf "gitdir:{machine.repo}/"]\n\tpath = {included}\n')

    findings = machine.findings()

    fix = findings[("hooks-path", str(machine.repo))]  # git also applies the gitdir condition to the repository's linked worktrees
    assert str(included) in fix
    assert "core.hooksPath" in fix
    included.write_text("")
    assert machine.findings() == {}


def test_a_hooks_path_from_the_system_file_names_that_file(machine: Machine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """#23 rule 2.1: a hooksPath from the system file names that file."""
    system_config = tmp_path / "system-gitconfig"
    system_config.write_text("[core]\n\thooksPath = /dev/null\n")
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", str(system_config))
    git("config", "--global", "--unset", "core.hooksPath")

    assert str(system_config) in machine.findings()[("hooks-path", str(machine.repo))]


@pytest.mark.parametrize(
    "damage",
    [
        lambda machine: git("config", "--global", "core.hooksPath", "/dev/null"),
        lambda machine: git("config", "--global", "--unset", "core.hooksPath"),
    ],
    ids=["wrong value", "unset"],
)
def test_a_wrong_or_unset_global_hooks_path_is_found_for_every_worktree_and_repaired_by_setup(
    machine: Machine, damage: Callable[[Machine], object]
) -> None:
    """#23 rule 2.1: a wrong or unset global hooksPath is found for every worktree and repaired by `hal setup`."""
    damage(machine)

    findings = machine.findings()

    assert {subject: fix for (rule, subject), fix in findings.items() if rule == "hooks-path"} == {
        str(machine.repo): "`hal setup`",
        str(machine.outside_worktree): "`hal setup`",
    }
    machine.apply_setup()
    assert machine.findings() == {}


def remove_hooks_directory(machine: Machine) -> None:
    shutil.rmtree(machine.layout.git_hooks_dir)


def make_hook_not_executable(machine: Machine) -> None:
    (machine.layout.git_hooks_dir / HOOK_NAMES[0]).chmod(0o644)


def make_hook_world_writable(machine: Machine) -> None:
    (machine.layout.git_hooks_dir / HOOK_NAMES[0]).chmod(0o777)


def edit_hook_by_hand(machine: Machine) -> None:
    with (machine.layout.git_hooks_dir / HOOK_NAMES[1]).open("a") as hook:
        hook.write("exit 0\n")


def delete_quality(machine: Machine) -> None:
    machine.layout.quality_executable.unlink()


def make_quality_unpinned(machine: Machine) -> None:
    receipt = machine.layout.quality_uv_receipt
    receipt.write_text(receipt.read_text().replace("?rev=", "?rev=0"))


def delete_mise(machine: Machine) -> None:
    machine.layout.mise_executable.unlink()


def make_mise_not_executable(machine: Machine) -> None:
    machine.layout.mise_executable.chmod(0o644)


def drift_mise(machine: Machine) -> None:
    machine.layout.mise_executable.write_bytes(b"#!/bin/sh\necho another mise\n")


def remove_scanners(machine: Machine) -> None:
    remove_stub_scanners(machine.layout)


def pin_other_scanner_versions(machine: Machine) -> None:
    move_stub_scanner_pins(machine.layout)


@pytest.mark.parametrize(
    ("damage", "rule", "subject"),
    [
        (remove_hooks_directory, "hook-file", HOOK_NAMES[0]),
        (make_hook_not_executable, "hook-file", HOOK_NAMES[0]),
        (make_hook_world_writable, "hook-file", HOOK_NAMES[0]),
        (edit_hook_by_hand, "hook-file", HOOK_NAMES[1]),
        (delete_quality, "quality", "quality"),
        (make_quality_unpinned, "quality", "quality"),
        (delete_mise, "mise", "mise"),
        (make_mise_not_executable, "mise", "mise"),
        (drift_mise, "mise", "mise"),
        (remove_scanners, "scanner", HOOK_SCANNER),
        (pin_other_scanner_versions, "scanner", HOOK_SCANNER),
    ],
    ids=[
        "hooks directory missing",
        "hook not executable",
        "hook world-writable",
        "hook edited",
        "quality missing",
        "quality at another source",
        "mise missing",
        "mise not executable",
        "mise at another hash",
        "scanners removed",
        "scanner at another version",
    ],
)
def test_a_damaged_installation_is_found_with_the_setup_command_and_clean_after_it(
    machine: Machine, damage: Callable[[Machine], None], rule: str, subject: str
) -> None:
    """Rules 2.2, 2.3 and 2.4: a damaged hook file, quality, mise or a scanner not at quality's pin gets the setup command and is clean after it."""
    damage(machine)

    findings = machine.findings()

    layout = machine.layout
    owners = {"hook-file": layout.git_hooks_dir / subject, "quality": layout.quality_executable, "mise": layout.mise_executable, "scanner": subject}
    expected_subject = owners[rule]
    assert findings[(rule, str(expected_subject))] == "`hal setup`"
    machine.apply_setup()
    assert machine.findings() == {}


def test_a_repository_hook_hidden_by_the_global_path_is_found_but_not_the_chained_names_or_samples(machine: Machine) -> None:
    """#23 rule 2.5: a hidden repository hook is found with its fix line, not the chained names or samples."""
    hooks = machine.repo / ".git" / "hooks"
    (hooks / "post-commit").write_text("#!/bin/sh\n")
    (hooks / HOOK_NAMES[0]).write_text("#!/bin/sh\n")
    (hooks / "pre-push.sample").write_text("#!/bin/sh\n")

    findings = machine.findings()

    assert set(findings) == {("hidden-hook", str(hooks / "post-commit"))}
    assert all(f"`{name}`" in fix for fix in findings.values() for name in HOOK_NAMES)
    (hooks / "post-commit").unlink()
    assert machine.findings() == {}


def test_the_global_config_under_xdg_config_home_outside_home_counts_as_the_global_file(
    machine: Machine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#23 rule 2.1: the global origin is `$XDG_CONFIG_HOME/git/config`, wherever that variable points."""
    xdg_config_home = tmp_path / "xdg"
    (xdg_config_home / "git").mkdir(parents=True)
    machine.global_config.rename(xdg_config_home / "git" / "config")
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg_config_home))

    assert machine.findings() == {}


def test_a_worktree_whose_path_contains_a_newline_is_still_checked(machine: Machine, tmp_path: Path) -> None:
    """#23 rule 2.1: every registered worktree is checked, wherever it sits and however it is named."""
    odd_worktree = tmp_path / "odd\nworktree"
    git("worktree", "add", "-q", "-b", "odd", odd_worktree, cwd=machine.repo)
    git("config", "extensions.worktreeConfig", "true", cwd=machine.repo)
    git("config", "--worktree", "core.hooksPath", "/dev/null", cwd=odd_worktree)

    assert ("hooks-path", str(odd_worktree)) in machine.findings()


def test_a_local_hooks_path_of_a_repository_with_a_separate_git_dir_is_unset_in_that_repository(machine: Machine, tmp_path: Path) -> None:
    """#23 rule 2.1: the local repair targets the affected repository, also when its git directory sits elsewhere."""
    separate = machine.sandbox.home / "git" / "separate"
    git("init", "-q", f"--separate-git-dir={tmp_path / 'metadata'}", separate)
    git("config", "--local", "core.hooksPath", "/dev/null", cwd=separate)

    (fix,) = [fix for (rule, _subject), fix in machine.findings().items() if rule == "hooks-path" and "--local" in fix]

    subprocess.run(fix_command(fix), check=True)
    assert machine.findings() == {}


def delegating_to_git_only(*, broken: Sequence[str] = ()) -> Callable[[Sequence[str]], str | None]:
    """Real git, but a git subcommand named in `broken` cannot be run; every other tool counts as missing."""

    def run(argv: Sequence[str]) -> str | None:
        if argv[0] != "git" or any(word in argv for word in broken):
            return None
        return run_command(argv)

    return run


@pytest.mark.parametrize("broken_subcommand", ["worktree", "config"])
def test_git_that_cannot_be_run_makes_the_check_fail_instead_of_clean(machine: Machine, broken_subcommand: str) -> None:
    """#23 rule 4: git that cannot be run is a broken check, never a clean one."""
    run = delegating_to_git_only(broken=[broken_subcommand])

    with pytest.raises(HookCheckUnavailable):
        hook_check.collect_findings(machine.layout, run)


@pytest.mark.parametrize(
    ("damage", "rule", "executable"),
    [
        (delete_quality, "quality", lambda layout: layout.quality_executable),
        (delete_mise, "mise", lambda layout: layout.mise_executable),
        (make_mise_not_executable, "mise", lambda layout: layout.mise_executable),
        (drift_mise, "mise", lambda layout: layout.mise_executable),
    ],
    ids=["quality missing", "mise missing", "mise not executable", "mise at another hash"],
)
def test_home_check_reports_a_hook_finding_in_its_one_report_and_a_broken_hook_check_as_failed(
    machine: Machine, damage: Callable[[Machine], None], rule: str, executable: Callable[[Layout], Path]
) -> None:
    """`hal check` joins a hook finding, mise's included, into its one report with `hal setup` as the fix and shows a broken hook check as failed."""
    damage(machine)
    layout = machine.layout

    code = home_check(machine.sandbox.home, delegating_to_git_only())
    report = layout.check_report_file.read_text()
    assert code == 1
    assert "# hook " in report
    assert "| Rule | Subject | Finding | Fix |" in report.splitlines()
    (row,) = [line for line in report.splitlines() if line.startswith(f"| {rule} |")]
    assert str(executable(layout)) in row
    assert row.endswith("| `hal setup` |")

    code = home_check(machine.sandbox.home, delegating_to_git_only(broken=["worktree"]))
    assert code == 3
    assert "check hook failed (HookCheckUnavailable)" in layout.check_report_file.read_text()
