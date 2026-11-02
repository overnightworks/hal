"""`hal rename OLD NEW`: moves the clones of a renamed repository on this PC. The repository is
renamed on GitHub first; this moves what the rename leaves behind here: every clone under
`~/git` with its worktrees, its `origin` URL and its Claude project memory, and the `origin` of a
deploy checkout elsewhere. Without `--dry-run` it shows, asks one yes and moves. Units, links and
uv tools that point into a moved clone are reported, never rewritten: the repository's own head
owns them.

The plan reads the state it finds, so a rerun after a halfway stop finishes the clones that
were moved but not completed."""

import argparse
import os
import re
import subprocess
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from hal import rename_rows
from hal.grammar import Asks, Command, ExitCode, add_dry_run
from hal.output import confirmed, printable
from hal.output.command import Verb
from hal.rename_rows import Finding, StepKind, StepRow
from hal.stack.terminal import at_terminal
from hal.workstation.layout import Layout, registered_worktrees

OWNER = "overnightworks"
NAME_PATTERN = re.compile(r"[a-z0-9][a-z0-9._-]*")
WORKTREES = "-worktrees"
DEPLOY_PARENTS = ("", "srv")  # under HOME: a deploy checkout sits one level below one of these


@dataclass(frozen=True)
class RunningProcess:
    pid: int
    command: str
    directory: Path


@dataclass(frozen=True)
class DeployCheckout:
    path: Path
    new_url: str


@dataclass
class World:
    """The boundaries to the outside: HOME, GitHub, the process table, uv, the terminal and the
    clock."""

    home: Path
    github_knows: Callable[[str], bool]
    running_in: Callable[[Sequence[Path]], list[RunningProcess]]
    uv: Callable[[Path, tuple[str, ...]], None]
    uv_tools: Callable[[], str]
    is_interactive: Callable[[], bool]
    clock: Callable[[], float]


@dataclass(frozen=True)
class Move:
    source: Path
    target: Path

    @property
    def is_noop(self) -> bool:
        """Two spellings that name the same place, such as the memory of `a.b` and `a-b`."""
        return self.source == self.target


@dataclass(frozen=True)
class GitCall:
    """git works in `directory` and in every path among `arguments`."""

    directory: Path
    arguments: tuple[str | Path, ...]


@dataclass(frozen=True)
class Sync:
    """A project with a lock file, synced on each run where the moves take it."""

    project: Path
    python: str | None  # the `major.minor` its venv was made with


@dataclass(frozen=True)
class Step:
    """`inputs` are what `run` was built from; plans compare by them, never by the callable."""

    description: str
    run: Callable[[], None] = field(compare=False)
    row: StepRow
    inputs: Move | GitCall | Sync


@dataclass(frozen=True)
class Site:
    """A clone as found: where it is now (`here`, the source or already the target), its moves."""

    here: Path
    clone: Move
    worktrees: Move
    memory: Move


@dataclass(frozen=True)
class Relocation:
    """What one clone still needs; a worktree's `source` is the path git has recorded for it."""

    site: Site
    new_url: str | None  # None when `origin` already names the new repository
    clone_moves: tuple[Move, ...]  # the clone and its `-worktrees` that still lie at the old name
    memory_move: Move | None
    linked: tuple[Move, ...]
    outside: tuple[Path, ...]
    syncs: tuple[Sync, ...]

    @property
    def needs_repair(self) -> bool:
        return any(not move.is_noop for move in self.linked)

    @property
    def needs_work(self) -> bool:
        return bool(
            self.clone_moves or self.new_url or self.needs_repair or self.memory_move or self.syncs
        )


@dataclass(frozen=True)
class Plan:
    steps: tuple[Step, ...]
    findings: tuple[Finding, ...]
    refusals: tuple[str, ...]


class Halfway(NamedTuple):
    """A run that stopped, in the order `write_halfway` takes it."""

    failed: Step
    reason: str
    done: tuple[Step, ...]
    pending: tuple[Step, ...]


def _output_of(argv: Sequence[str]) -> str:
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    return subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        argv, capture_output=True, text=True, check=True, stdin=subprocess.DEVNULL, env=environment
    ).stdout  # fmt: skip


def _git(directory: Path, *arguments: str) -> str:
    return _output_of(["git", "-C", str(directory), *arguments]).strip()


def processes_inside(roots: Sequence[Path]) -> list[RunningProcess]:
    """Every process whose working directory is inside one of `roots`."""
    found = []
    for entry in Path("/proc").glob("[0-9]*"):
        try:
            working_directory = Path(os.readlink(entry / "cwd"))
            command = (entry / "comm").read_text().strip()
        except OSError:  # another user's process, or one that ended meanwhile
            continue
        if any(working_directory.is_relative_to(root) for root in roots):
            found.append(RunningProcess(int(entry.name), command, working_directory))
    return found


def _github_knows(name: str) -> bool:
    return subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["gh", "api", f"repos/{OWNER}/{name}"], capture_output=True, stdin=subprocess.DEVNULL  # noqa: S607 - gh is found on PATH by design
    ).returncode == 0  # fmt: skip


def _uv(project: Path, arguments: tuple[str, ...]) -> None:
    subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["uv", *arguments],  # noqa: S607 - uv is found on PATH by design
        cwd=project, check=True, stdin=subprocess.DEVNULL,
    )  # fmt: skip


def _uv_tools() -> str:
    try:
        return subprocess.run(
            ["uv", "tool", "list", "--show-version-specifiers"],  # noqa: S607 - uv is found on PATH by design
            capture_output=True, text=True, stdin=subprocess.DEVNULL,
        ).stdout  # fmt: skip
    except FileNotFoundError:  # no uv, no uv tools
        return ""


@dataclass
class Disk:
    """Every filesystem access of one plan: the reads that find the work and the actions its
    steps run. Each access first looks for symbolic links in its path and the path's parents,
    both where the path will be and where a planned move takes it from, and remembers them; the
    plan refuses them all before any change; a read of a path with a link in it comes back empty,
    so planning goes on to that refusal. An action touches only the paths it was built with, so
    nothing a run reads or changes escapes the check. `is_link`, `link_target`, `target_text` and
    `unfollowed_origin` are the one exception: they look at a scanned link or at a checkout behind
    one without following it into the checked set, and only to report."""

    moves: tuple[Move, ...] = ()
    links: dict[Path, None] = field(default_factory=dict)  # an ordered set

    def _check(self, path: Path) -> bool:
        """Remembers the links in `path`; whether there are any."""
        found = [
            part
            for place in (path, *self._sources_of(path))
            for part in (place, *place.parents)
            if part.is_symlink()
        ]
        self.links.update(dict.fromkeys(found))
        return bool(found)

    def _sources_of(self, path: Path) -> list[Path]:
        return [
            move.source / path.relative_to(move.target)
            for move in self.moves
            if path.is_relative_to(move.target)
        ]

    def exists(self, path: Path) -> bool:
        self._check(path)
        return os.path.lexists(path)

    def is_dir(self, path: Path) -> bool:
        self._check(path)
        return path.is_dir()

    def is_file(self, path: Path) -> bool:
        self._check(path)
        return path.is_file()

    def read_text(self, path: Path) -> str:
        return "" if self._check(path) else path.read_text(errors="replace")

    def entries(self, directory: Path) -> list[Path]:
        if self._check(directory) or not directory.is_dir():
            return []
        return sorted(directory.iterdir())

    def walk(self, directory: Path) -> list[Path]:
        """Everything below `directory`; a linked directory is listed, never entered."""
        self._check(directory)
        return sorted(directory.rglob("*"))

    def real_path(self, path: Path) -> Path:
        self._check(path)
        return path.resolve()

    def is_link(self, path: Path) -> bool:
        self._check(path.parent)
        return path.is_symlink()

    def link_target(self, link: Path) -> Path:
        self._check(link.parent)
        return Path(os.path.normpath(link.parent / os.readlink(link)))

    def target_text(self, link: Path) -> str:
        """The text of the regular file a link points at; empty for anything else."""
        try:
            target = self.link_target(link)
            return target.read_text(errors="replace") if target.is_file() else ""
        except OSError:  # a file this user cannot read has nothing to report
            return ""

    def unfollowed_origin(self, checkout: Path) -> str | None:
        """`origin` of the checkout at `checkout`, None when there is none to read."""
        if not (checkout / ".git").exists():
            return None
        try:
            return _git(checkout, "config", "--get", "remote.origin.url")
        except subprocess.CalledProcessError:
            return None

    def refuse(self, link: Path) -> None:
        self._check(link)

    def git(self, directory: Path, *arguments: str) -> str:
        self._check(directory / ".git")
        return _git(directory, *arguments)

    def worktrees_of(self, clone: Path) -> set[Path]:
        self._check(clone / ".git")
        return registered_worktrees(clone, _output_of, resolve_links=False)

    def move_action(self, move: Move) -> Callable[[], None]:
        self._check(move.source)
        self._check(move.target)
        return lambda: move.source.rename(move.target)

    def git_action(self, call: GitCall) -> Callable[[], None]:
        """Each repository the call works in is checked with its `.git`."""
        for repository in (call.directory, *(a for a in call.arguments if isinstance(a, Path))):
            self._check(repository / ".git")

        def run() -> None:
            _git(call.directory, *map(str, call.arguments))

        return run

    def uv_action(
        self, uv: Callable[[Path, tuple[str, ...]], None], sync: Sync
    ) -> Callable[[], None]:
        """uv reads `uv.lock` and rewrites `.venv` in place: `uv venv --allow-existing` and a
        reinstall make a moved `.venv` name its new path in `bin/activate*` and in its scripts,
        and nothing is deleted. `uv venv` is told the venv's own Python version, because it would
        otherwise pick the newest interpreter it finds."""
        self._check(sync.project / "uv.lock")
        self._check(sync.project / ".venv")
        python = ("--python", sync.python) if sync.python else ()
        calls = (("venv", "--allow-existing", *python), ("sync", "--locked", "--reinstall"))

        def run() -> None:
            for arguments in calls:
                uv(sync.project, arguments)

        return run


def real_world(home: Path) -> World:
    return World(home, _github_knows, processes_inside, _uv, _uv_tools, at_terminal, time.monotonic)


def _remote_pattern(name: str) -> re.Pattern[str]:
    """A GitHub remote of `OWNER/name`, https or ssh; `before` and `after` keep its spelling."""
    host = r"(?:https://(?:[\w.-]+@)?github\.com/|(?:ssh://)?git@github\.com[:/])"
    return re.compile(rf"(?P<before>{host}{OWNER}/){re.escape(name)}(?P<after>(?:\.git)?/?)")


def _renamed_url(url: str | None, old: str, new: str) -> str | None:
    match = _remote_pattern(old).fullmatch(url) if url else None
    return f"{match['before']}{new}{match['after']}" if match else None


def _origin(disk: Disk, path: Path) -> str | None:
    try:
        return disk.git(path, "config", "--get", "remote.origin.url")
    except subprocess.CalledProcessError:
        return None


def _names(url: str | None, *names: str) -> bool:
    return url is not None and any(_remote_pattern(name).fullmatch(url) for name in names)


def _suffix(directory_name: str, prefix: str) -> str | None:
    """`-land` for `prefix-land`, `` for `prefix`, None for a name that is not a sibling."""
    rest = directory_name.removeprefix(prefix)
    if rest == directory_name or (rest and not rest.startswith("-")):
        return None
    return None if directory_name.endswith(WORKTREES) else rest


def _suffix_of(directory_name: str, old: str, new: str) -> str | None:
    """The longer of the two names wins, so `demo-app` is `demo-app` and not `demo` + `-app`
    when `demo` becomes `demo-app`, and a repeat never takes a moved clone for a source."""
    longer, shorter = sorted((old, new), key=len, reverse=True)
    found = _suffix(directory_name, longer)
    return found if found is not None else _suffix(directory_name, shorter)


def memory_directory(home: Path, clone: Path) -> Path:
    """Claude Code names a project directory by turning every non-alphanumeric character of the
    path into `-`."""
    return home / ".claude" / "projects" / re.sub(r"[^A-Za-z0-9]", "-", str(clone))


def _worktrees_of(clone: Path) -> Path:
    return clone.with_name(f"{clone.name}{WORKTREES}")


def _sites(world: World, disk: Disk, old: str, new: str) -> list[Site]:
    git_directory = Layout(world.home).git
    names = [path.name for path in disk.entries(git_directory)]
    suffixes = {_suffix_of(name, old, new) for name in names} - {None}
    sites = []
    for suffix in sorted(suffixes):
        clone = Move(git_directory / f"{old}{suffix}", git_directory / f"{new}{suffix}")
        here = next(
            (
                path
                for path in (clone.source, clone.target)
                if disk.is_dir(path / ".git") and _names(_origin(disk, path), old, new)
            ),
            None,
        )
        if here:
            sites.append(
                Site(
                    here,
                    clone,
                    Move(_worktrees_of(clone.source), _worktrees_of(clone.target)),
                    Move(
                        memory_directory(world.home, clone.source),
                        memory_directory(world.home, clone.target),
                    ),
                )
            )
    return sites


def _relocated(path: Path, moves: Iterable[Move]) -> Path | None:
    """Where `path` lies after the moves, None when it lies outside every moved tree."""
    for move in moves:
        for root in (move.source, move.target):
            if path.is_relative_to(root):
                return move.target / path.relative_to(root)
    return None


def _current(disk: Disk, move: Move) -> Path:
    return move.source if disk.exists(move.source) else move.target


def _worktrees(disk: Disk, site: Site, moves: Sequence[Move]) -> tuple[list[Move], list[Path]]:
    """The worktrees git lists for the clone: those under a moved tree, and those outside."""
    linked, outside = [], []
    for path in sorted(disk.worktrees_of(site.here) - {site.here, disk.real_path(site.here)}):
        relocated = _relocated(path, moves)
        if relocated is None and disk.exists(path):
            outside.append(path)
        elif relocated is not None and (disk.exists(path) or disk.exists(relocated)):
            linked.append(Move(path, relocated))
    return linked, outside


def _syncs(disk: Disk, projects: Iterable[Move]) -> tuple[Sync, ...]:
    syncs = []
    for project in projects:
        here = _current(disk, project)
        if disk.is_file(here / "uv.lock"):
            syncs.append(Sync(project.target, _venv_python_version(disk, here / ".venv")))
    return tuple(syncs)


def _relocation(disk: Disk, site: Site, moves: Sequence[Move], old: str, new: str) -> Relocation:
    linked, outside = _worktrees(disk, site, moves)
    memory = site.memory
    return Relocation(
        site=site,
        new_url=_renamed_url(_origin(disk, site.here), old, new),
        clone_moves=tuple(
            move for move in (site.clone, site.worktrees) if disk.exists(move.source)
        ),
        memory_move=memory if disk.is_dir(memory.source) and not memory.is_noop else None,
        linked=tuple(linked),
        outside=tuple(outside),
        syncs=_syncs(disk, (site.clone, *linked)),
    )


def _deploy_checkouts(
    world: World, disk: Disk, old: str, new: str, moved: Sequence[Path]
) -> tuple[DeployCheckout, ...]:
    found = []
    for parent in DEPLOY_PARENTS:
        for path in disk.entries(world.home / parent):
            hidden_or_clones = path.name.startswith(".") or path == Layout(world.home).git
            if not hidden_or_clones and (checkout := _deploy_checkout(disk, path, old, new, moved)):
                found.append(checkout)
    return tuple(found)


def _deploy_checkout(
    disk: Disk, path: Path, old: str, new: str, moved: Sequence[Path]
) -> DeployCheckout | None:
    """A link, or a `.git` that is one, is never followed: a checkout of this repository behind
    it is refused at the link, and what lies behind it otherwise is not hal's to judge."""
    link = next((place for place in (path, path / ".git") if disk.is_link(place)), None)
    if link is None:
        url = _renamed_url(_origin(disk, path), old, new) if disk.is_dir(path / ".git") else None
        return DeployCheckout(path, url) if url else None
    if link == path and _points_into(disk, path, moved):
        return None
    behind = disk.link_target(path) if link == path else path
    if _names(disk.unfollowed_origin(behind), old, new):
        disk.refuse(link)
    return None


def _mentions(text: str, roots: Iterable[Path], home: Path | None = None) -> bool:
    """Whether `text` names a root, absolute or (with `home`) as the unit specifier `%h/<path>`."""
    spellings = [str(root) for root in roots]
    if home:
        spellings += [f"%h/{root.relative_to(home)}" for root in roots if root.is_relative_to(home)]
    return any(re.search(rf"{re.escape(spelling)}(?![\w.-])", text) for spelling in spellings)


def _points_into(disk: Disk, link: Path, roots: Iterable[Path]) -> bool:
    if not disk.is_link(link):
        return False
    target = disk.link_target(link)
    return any(target.is_relative_to(root) for root in roots)


def _unit_findings(disk: Disk, directory: Path, roots: Sequence[Path], home: Path) -> list[Finding]:
    """A unit link is read, never followed: its target is only read for what it names."""
    found = []
    for entry in disk.walk(directory):
        if _points_into(disk, entry, roots):
            found.append(Finding("unit link", f"{entry} points into a moved clone"))
        elif disk.is_link(entry):
            if _mentions(disk.target_text(entry), roots, home):
                found.append(Finding("unit link", f"{entry} names a moved clone"))
        elif disk.is_file(entry) and _mentions(disk.read_text(entry), roots, home):
            found.append(Finding("unit", f"{entry} points into a moved clone"))
    return found


def _findings(
    world: World, disk: Disk, roots: Sequence[Path], relocations: Sequence[Relocation]
) -> list[Finding]:
    found = _unit_findings(disk, world.home / ".config" / "systemd" / "user", roots, world.home)
    found += [
        Finding("link", f"{link} points into a moved clone")
        for directory in (world.home / ".local" / "bin", world.home, world.home / "srv")
        for link in disk.entries(directory)
        if _points_into(disk, link, roots)
    ]
    found += [
        Finding("uv tool", f"installed from a moved clone: {line.strip()}")
        for line in world.uv_tools().splitlines()
        if _mentions(line, roots)
    ]
    found += [
        Finding(
            "worktree",
            f"{path} lies outside the moved trees and may still point at the old clone: "
            f"git -C {relocation.site.clone.target} worktree repair {path}",
        )
        for relocation in relocations
        for path in relocation.outside
        if not _names_clone(disk, path, relocation.site.clone.target)
    ]
    return found


def _names_clone(disk: Disk, worktree: Path, clone: Path) -> bool:
    """Whether the worktree's `.git` file names a registration inside the clone that exists and
    names that `.git` file back."""
    gitfile = worktree / ".git"
    if not disk.is_file(gitfile):
        return False
    registration = Path(disk.read_text(gitfile).removeprefix("gitdir:").strip())
    pointer = registration / "gitdir"
    return (
        registration.parent == clone / ".git" / "worktrees"
        and disk.is_file(pointer)
        and Path(disk.read_text(pointer).strip()) == gitfile
    )


def _both_exist(disk: Disk, move: Move) -> bool:
    return not move.is_noop and disk.exists(move.source) and disk.exists(move.target)


def _refusals(
    world: World, disk: Disk, relocations: Sequence[Relocation], has_work: bool, new: str
) -> list[str]:
    """Runs after every other access of the plan, so the links the disk met are all of them."""
    refusals = [
        f"{move.target} already exists"
        for relocation in relocations
        for move in (relocation.site.clone, relocation.site.worktrees, relocation.site.memory)
        if _both_exist(disk, move)
    ]
    sessions = _process_refusals(world, disk, relocations)
    refusals += [f"{path} is a symbolic link, which is never followed" for path in disk.links]
    if has_work and not world.github_knows(new):
        refusals.append(f"GitHub does not know {OWNER}/{new}")
    return refusals + sessions


def _trees_of(relocation: Relocation) -> list[Path]:
    """Every tree of the clone as it is now: the clone, its `-worktrees` directory and each
    worktree git lists, under the old and the new name."""
    site = relocation.site
    places = [
        site.clone.source,
        site.clone.target,
        site.worktrees.source,
        site.worktrees.target,
    ]
    for move in relocation.linked:
        places += [move.source, move.target]
    return [*places, *relocation.outside]


def _process_refusals(world: World, disk: Disk, relocations: Sequence[Relocation]) -> list[str]:
    """A session counts wherever any tree of any clone is now: a rerun can find it already
    moved, and a worktree can lie under another clone's directory."""
    roots = (
        {
            disk.real_path(path)
            for relocation in relocations
            for path in _trees_of(relocation)
            if disk.exists(path)
        }
        if any(relocation.needs_work for relocation in relocations)
        else set()
    )
    running = world.running_in(sorted(roots)) if roots else []
    return [
        f"pid {process.pid} ({process.command}) runs in {process.directory}: end that session first"
        for process in running
    ]


def _move_step(disk: Disk, move: Move, kind: StepKind) -> Step:
    row = StepRow.of_move(kind, move.source, move.target)
    return Step(f"move {move.source} -> {move.target}", disk.move_action(move), row, move)


def _origin_step(disk: Disk, path: Path, url: str, deploy: bool = False) -> Step:
    call = GitCall(path, ("remote", "set-url", "origin", url))
    return Step(
        f"origin of {path} -> {url}",
        disk.git_action(call),
        StepRow.of_origin(url, path if deploy else None),
        call,
    )


def _repair_step(disk: Disk, relocation: Relocation) -> Step:
    clone = relocation.site.clone.target
    worktrees = [move.target for move in relocation.linked]
    call = GitCall(clone, ("worktree", "repair", *worktrees))
    return Step(
        f"repair {len(worktrees)} worktrees of {clone}",
        disk.git_action(call),
        StepRow.of_repair(relocation.site.worktrees.target, len(worktrees)),
        call,
    )


def _venv_python_version(disk: Disk, venv: Path) -> str | None:
    """The `major.minor` Python a venv was made with, None when it has no `pyvenv.cfg`."""
    config = venv / "pyvenv.cfg"
    if not disk.is_file(config):
        return None
    entries = (line.partition("=") for line in disk.read_text(config).splitlines())
    return next(
        (
            ".".join(value.strip().split(".")[:2])
            for key, _, value in entries
            if key.strip() in ("version_info", "version")
        ),
        None,
    )


def _sync_step(world: World, disk: Disk, sync: Sync) -> Step:
    return Step(
        f"uv sync in {sync.project}",
        disk.uv_action(world.uv, sync),
        StepRow(StepKind.SYNC, f"in {sync.project}"),
        sync,
    )


def _clone_move_kind(move: Move, site: Site) -> StepKind:
    return StepKind.MOVE_CLONE if move == site.clone else StepKind.MOVE_WORKTREES


def _steps(
    world: World, disk: Disk, relocations: Sequence[Relocation], deploy: Sequence[DeployCheckout]
) -> tuple[Step, ...]:
    """The work still to do, in the order that is safe: every move first, because a worktree
    of one clone can lie inside another clone's `-worktrees`."""
    steps = [
        _move_step(disk, move, _clone_move_kind(move, relocation.site))
        for relocation in relocations
        for move in relocation.clone_moves
    ]
    steps += [
        _origin_step(disk, relocation.site.clone.target, relocation.new_url)
        for relocation in relocations
        if relocation.new_url
    ]
    steps += [
        _repair_step(disk, relocation) for relocation in relocations if relocation.needs_repair
    ]
    steps += [
        _move_step(disk, relocation.memory_move, StepKind.MOVE_MEMORY)
        for relocation in relocations
        if relocation.memory_move
    ]
    steps += [
        _origin_step(disk, checkout.path, checkout.new_url, deploy=True) for checkout in deploy
    ]
    steps += [
        _sync_step(world, disk, sync) for relocation in relocations for sync in relocation.syncs
    ]
    return tuple(steps)


def make_plan(world: World, old: str, new: str) -> Plan:
    """Reads only through one `Disk`, and its steps act only through it."""
    disk = Disk()
    sites = _sites(world, disk, old, new)
    moves = [move for site in sites for move in (site.clone, site.worktrees)]
    disk.moves = tuple(moves)
    relocations = [_relocation(disk, site, moves, old, new) for site in sites]
    roots = [move.source for move in moves]
    deploy = _deploy_checkouts(world, disk, old, new, roots + [move.target for move in moves])
    steps = _steps(world, disk, relocations, deploy)
    findings = _findings(world, disk, roots, relocations) if steps else []
    refusals = _refusals(world, disk, relocations, bool(steps), new)
    return Plan(steps, tuple(findings), tuple(refusals))


def _reason(error: subprocess.CalledProcessError | OSError) -> str:
    stderr = error.stderr if isinstance(error, subprocess.CalledProcessError) else None
    return " / ".join((stderr or "").strip().splitlines()) or str(error)


def _execute(steps: Sequence[Step], world: World) -> Halfway | None:
    for index, step in enumerate(steps):
        started = world.clock()
        try:
            step.run()
        except (subprocess.CalledProcessError, OSError) as error:
            return Halfway(step, _reason(error), tuple(steps[:index]), tuple(steps[index + 1 :]))
        took = world.clock() - started if step.row.kind is StepKind.SYNC else None
        rename_rows.write_done_row(step.row, world.home, took)
    return None


def _apply(world: World, old: str, new: str, shown: Plan) -> ExitCode:
    """The plan stood on screen while the person decided: it is made once more, and a refusal or
    a difference from what was shown ends the run before the first change."""
    started = world.clock()
    plan = make_plan(world, old, new)
    if plan.refusals or (plan.steps, plan.findings) != (shown.steps, shown.findings):
        rename_rows.write_refusals(plan.refusals or ("the plan changed since it was shown",))
        return ExitCode.REFUSED
    halfway = _execute(plan.steps, world)
    if halfway:
        rename_rows.write_halfway(old, new, *halfway)
        return ExitCode.FAILURE
    rename_rows.write_done(len(plan.steps), len(plan.findings), world.clock() - started)
    return ExitCode.FINDINGS if plan.findings else ExitCode.OK


def rename(world: World, old: str, new: str, dry_run: bool) -> ExitCode:
    plan = make_plan(world, old, new)
    if plan.refusals:
        rename_rows.write_refusals(plan.refusals)
        return ExitCode.REFUSED
    if not (plan.steps or plan.findings):
        rename_rows.write_nothing_to_do(old)
        return ExitCode.OK
    rename_rows.write_plan(plan.steps, plan.findings, world.home)
    if dry_run:
        rename_rows.write_plan_only(old, new)
        return ExitCode.FINDINGS if plan.findings else ExitCode.OK
    if not world.is_interactive():
        rename_rows.write_without_terminal(old, new)
        return ExitCode.REFUSED
    if not confirmed(rename_rows.apply_purpose(len(plan.steps))):
        rename_rows.write_declined()
        return ExitCode.FINDINGS
    return _apply(world, old, new, plan)


def _repository_name(text: str) -> str:
    if not NAME_PATTERN.fullmatch(text):
        raise argparse.ArgumentTypeError(f"not a repository name: {printable(text)}")
    return text


def _configure(parser: argparse.ArgumentParser) -> None:
    for name, text in (("old", "the repository's former name"), ("new", "its name on GitHub now")):
        parser.add_argument(name, type=_repository_name, help=text)
    add_dry_run(parser)


def _run(arguments: argparse.Namespace) -> ExitCode:
    return rename(real_world(Path.home()), arguments.old, arguments.new, arguments.dry_run)


COMMANDS = (
    Command(
        Verb.RENAME,
        "move the clones of a repository renamed on GitHub"
        " (shows the plan, asks yes, moves; --dry-run only shows)",
        _run,
        _configure,
        json=False,
        asks=Asks.YES,
    ),
)
