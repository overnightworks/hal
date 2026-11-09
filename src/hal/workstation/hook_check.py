"""`hal check`'s hook check: sees when the global commit hook stops applying, because git fails open when it drifts.

`setup.py` owns the expected state (the rendered hook, the pinned quality and its scanner, the hooks directory); this module only compares
the machine against it and names the fix command of each difference. A tool that cannot be run raises, so the check
shows up as broken and never as clean.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from shlex import quote

from hal.workstation.report import findings_count, markdown_table
from hal.workstation.setup import HOOK_NAMES, HOOK_SCANNER, _has_hook_mode, _is_executable, _recorded_quality_source_matches, hook_scanner_installed, mise_hash_is_pinned, render_hook
from hal.workstation.layout import CommandRunner, Layout, is_git_repo, registered_worktrees
from hal.output.command import Verb, command

SETUP_APPLY = f"`{command(Verb.SETUP)}`"
HOOKS_PATH_KEY = "core.hookspath"
SAMPLE_SUFFIX = ".sample"


class HookCheckUnavailable(RuntimeError):
    """A tool the check needs could not be run, so nothing can be said about the hook."""


@dataclass(frozen=True)
class HookFinding:
    rule: str
    subject: str
    detail: str
    fix: str

    @property
    def identity(self) -> str:
        return f"{self.rule}\t{self.subject}"


@dataclass(frozen=True)
class WorktreeConfig:
    """Where git reads the settings of one worktree from, and which of those files belong to the repository itself."""

    worktree: Path
    common_dir: Path
    local_file: Path
    worktree_file: Path
    hooks_path_setting: tuple[Path, str] | None
    """The file the effective core.hooksPath comes from and its value; None when it is unset."""


def _git(run: CommandRunner, worktree: Path, *arguments: str) -> str:
    output = run(["git", "-C", str(worktree), *arguments])
    if output is None:
        raise HookCheckUnavailable(f"git {' '.join(arguments)} in {worktree} cannot be run")
    return output


def _last_hooks_path_setting(listing: str, worktree: Path) -> tuple[Path, str] | None:
    """`git config --list --show-origin -z` prints `<origin>\\0<key>\\n<value>\\0`; the last core.hooksPath wins."""
    fields = listing.split("\0")
    setting = None
    for origin, entry in zip(fields[0::2], fields[1::2], strict=False):
        key, _, value = entry.partition("\n")
        if key == HOOKS_PATH_KEY:
            setting = (worktree / origin.removeprefix("file:"), value)
    return setting


def _read_worktree_config(worktree: Path, run: CommandRunner) -> WorktreeConfig:
    common_dir, local_file, worktree_file = _git(
        run, worktree, "rev-parse", "--path-format=absolute", "--git-common-dir", "--git-path", "config", "--git-path", "config.worktree"
    ).splitlines()
    listing = _git(run, worktree, "config", "--list", "--show-origin", "-z")
    return WorktreeConfig(worktree, Path(common_dir), Path(local_file), Path(worktree_file), _last_hooks_path_setting(listing, worktree))


def _same_file(first: Path, second: Path) -> bool:
    return first.resolve() == second.resolve()


def _global_config_files(layout: Layout) -> tuple[Path, ...]:
    xdg_config_home = Path(os.environ.get("XDG_CONFIG_HOME") or layout.home / ".config")
    return layout.home / ".gitconfig", xdg_config_home / "git" / "config"


def _unapplied_hooks_path(config: WorktreeConfig, layout: Layout) -> HookFinding | None:
    """The effective core.hooksPath must be the hooks directory, set by the global config file itself; the origin decides, not the scope."""
    expected = str(layout.git_hooks_dir)
    subject = str(config.worktree)
    if config.hooks_path_setting is None:
        return HookFinding("hooks-path", subject, "core.hooksPath is not set", SETUP_APPLY)
    origin, value = config.hooks_path_setting
    if not any(_same_file(origin, candidate) for candidate in _global_config_files(layout)):
        return HookFinding("hooks-path", subject, f"core.hooksPath = {value} is set by {origin}", _remove_override(config, origin))
    if value != expected:
        return HookFinding("hooks-path", subject, f"the global core.hooksPath is {value}, expected {expected}", SETUP_APPLY)
    return None


def _remove_override(config: WorktreeConfig, origin: Path) -> str:
    if _same_file(origin, config.local_file):
        return f"`git -C {quote(str(config.worktree))} config --local --unset core.hooksPath`"
    if _same_file(origin, config.worktree_file):
        return f"`git -C {quote(str(config.worktree))} config --worktree --unset core.hooksPath`"
    return f"edit {origin} and remove the core.hooksPath line (or the include)"


def _worktrees_under_git(layout: Layout, run: CommandRunner) -> Iterator[tuple[Path, Path]]:
    """Every repository below ~/git with each of its registered worktrees, wherever they sit."""
    for repo in sorted(layout.git.iterdir()) if layout.git.is_dir() else []:
        if not is_git_repo(repo):
            continue
        worktrees = registered_worktrees(repo, run)
        if not worktrees:
            raise HookCheckUnavailable(f"git worktree list in {repo} cannot be run")
        yield from ((repo, worktree) for worktree in sorted(worktrees) if worktree.is_dir())


def _hook_file_problem(path: Path, rendered_hook: str) -> str | None:
    if not path.is_file():
        return "missing"
    if not _has_hook_mode(path):
        return "mode is not 755"
    return None if path.read_text() == rendered_hook else "differs from the expected text"


def _hook_file_findings(layout: Layout) -> list[HookFinding]:
    rendered_hook = render_hook(layout)
    problems = ((layout.git_hooks_dir / name, _hook_file_problem(layout.git_hooks_dir / name, rendered_hook)) for name in HOOK_NAMES)
    return [HookFinding("hook-file", str(path), problem, SETUP_APPLY) for path, problem in problems if problem]


def _quality_findings(layout: Layout, run: CommandRunner) -> list[HookFinding]:
    quality = layout.quality_executable
    if not _is_executable(quality):
        return [HookFinding("quality", str(quality), "missing or not executable", SETUP_APPLY)]
    findings = []
    if not _recorded_quality_source_matches(layout):
        findings.append(HookFinding("quality", str(quality), "not pinned to QUALITY_SOURCE", SETUP_APPLY))
    if not hook_scanner_installed(layout, run):
        findings.append(HookFinding("scanner", HOOK_SCANNER, "mise does not locate it at the version quality pins", SETUP_APPLY))
    return findings


def _mise_findings(layout: Layout) -> list[HookFinding]:
    mise = layout.mise_executable
    if not _is_executable(mise):
        return [HookFinding("mise", str(mise), "missing or not executable", SETUP_APPLY)]
    if not mise_hash_is_pinned(mise):
        return [HookFinding("mise", str(mise), "differs from the pinned sha256", SETUP_APPLY)]
    return []


def _hidden_repository_hooks(common_dir: Path) -> list[HookFinding]:
    """The global hooks path hides a repository's own hook unless it carries one of the chained names."""
    hooks_dir = common_dir / "hooks"
    chained_names = " or ".join(f"`{name}`" for name in HOOK_NAMES)
    hidden = sorted(
        path
        for path in (hooks_dir.iterdir() if hooks_dir.is_dir() else [])
        if path.is_file() and not path.name.endswith(SAMPLE_SUFFIX) and path.name not in HOOK_NAMES
    )
    return [
        HookFinding("hidden-hook", str(path), "hidden by the global hooks path", f"rename it to {chained_names}, or delete it")
        for path in hidden
    ]


def collect_findings(layout: Layout, run: CommandRunner) -> list[HookFinding]:
    findings = [*_hook_file_findings(layout), *_mise_findings(layout), *_quality_findings(layout, run)]
    seen_common_dirs: set[Path] = set()
    for _repo, worktree in _worktrees_under_git(layout, run):
        config = _read_worktree_config(worktree, run)
        if (unapplied := _unapplied_hooks_path(config, layout)) is not None:
            findings.append(unapplied)
        if (common_dir := config.common_dir.resolve()) not in seen_common_dirs:
            seen_common_dirs.add(common_dir)
            findings.extend(_hidden_repository_hooks(common_dir))
    return findings


def render_report(findings: list[HookFinding], now: datetime) -> str:
    lines = [f"# hook {now:%d.%m.%Y %H:%M} | {findings_count(len(findings))}", ""]
    if findings:
        rows = [[f.rule, f.subject, f.detail, f.fix] for f in findings]
        lines += markdown_table(["Rule", "Subject", "Finding", "Fix"], rows)
    else:
        lines.append("No findings.")
    return "\n".join(lines) + "\n"


def inspect(layout: Layout, run: CommandRunner, now: datetime) -> tuple[list[HookFinding], str]:
    """What `hal check` reads of the hook; findings and their report."""
    findings = collect_findings(layout, run)
    return findings, render_report(findings, now)
