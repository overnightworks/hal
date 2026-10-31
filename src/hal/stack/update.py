"""`hal update`: brings the live checkout to origin's `main` after one `yes` on the exact fetched
sha, and syncs its locked dependencies; `hal apply` then plans the units (#783).

It guards in `hal apply`'s order, only the first failing guard speaking: a terminal, the live
checkout, `apply.lock` (the same lock, held from before the fetch until the command returns, so
neither command runs during the other) and a clean `main`. It fetches, shows every waiting commit
and the changed files by effect, and asks. After the `yes` it rechecks that the checkout is still
the clean `main` at the planned HEAD and that the pinned sha is a fast-forward of it; then it
merges that full sha with SIGINT blocked, checks HEAD, the branch and the tree, syncs the
dependencies through the merged tree's `bin/hal-sync` in its own process group, and checks HEAD
again. It never writes `applied.json`.

Every handled failure from the merge on is a partial update: one `error:` line with the full sha
and the step, `next: hal apply`. Nothing is imported after the merge, because the editable install
would make a later import read the merged code into this process.
"""

import os
import signal
from collections.abc import Collection, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path

from hal.output import (
    Glyph,
    Stream,
    Verdict,
    confirmed,
    is_verbose,
    printable,
    write_error,
    write_line,
    write_row,
    write_verdict,
)
from hal.output.command import Verb, command
from hal.stack import apply, catalog, checkout, compose, core
from hal.stack.plan_rows import (
    Effect,
    checkout_row,
    local_changes_row,
    update_rows,
    waiting_text,
)
from hal.stack.terminal import NEEDS_TERMINAL, at_terminal
from hal.stack.waiting import fetched

SYNC_SCRIPT = "bin/hal-sync"
_CODE_DIRECTORIES = ("src/", "bin/")
_CODE_FILES = ("pyproject.toml", "uv.lock")
_PLANNED_FILES = ("compose.yaml", catalog.FLEET_FILE)
_NOTHING_CHANGED = "nothing changed"
_APPLY = command(Verb.APPLY)
_AGAIN = command(Verb.UPDATE)


class UpdateEnd(Enum):
    """How `hal update` ended; the door maps each to its exit code."""

    DONE = "done"
    DECLINED = "declined"
    REFUSED = "refused"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


class Step(StrEnum):
    MERGE = "merge"
    CHECK_AFTER_MERGE = "check HEAD after the merge"
    SYNC = "sync the dependencies"
    CHECK_AFTER_SYNC = "check HEAD after the sync"


class SyncProgress(StrEnum):
    """What an interrupt should say about the sync."""

    NOT_STARTED = "the sync had not started"
    RUNNING = "the sync was running, so the environment may be half synced"
    ENDED = "the sync had ended"


def update_checkout(
    state_directory: Path,
    repository: Path = compose.REPOSITORY,
    home: Path | None = None,
    git: checkout.Runner = checkout.run_git,
    engine: compose.Compose | None = None,
) -> UpdateEnd:
    if not at_terminal():
        write_error(NEEDS_TERMINAL)
        return UpdateEnd.REFUSED
    if refusal := checkout.not_live_checkout_line(repository, home or Path.home()):
        write_error(refusal)
        return UpdateEnd.REFUSED
    try:
        lock = apply.take_apply_lock(state_directory)
    except OSError as error:
        write_error(f"cannot take {state_directory / apply.APPLY_LOCK} ({error.strerror})")
        return UpdateEnd.FAILED
    if lock is None:
        write_error(apply.APPLY_RUNNING)
        return UpdateEnd.REFUSED
    try:
        runner = checkout.echoing(git) if is_verbose() else git
        live = checkout.Git(repository, runner)
        return _update(live, engine or compose.Compose(repository=repository))
    finally:
        os.close(lock)


def _update(live: checkout.Git, engine: compose.Compose) -> UpdateEnd:
    if not apply.on_clean_main(live):
        return UpdateEnd.REFUSED
    if (origin := fetched(live, write_error)) is None:
        return UpdateEnd.FAILED
    if origin.standing is checkout.Standing.CURRENT:
        write_row(checkout_row(origin))
        write_verdict(Verdict(Glyph.DONE, "nothing to update", (), next_step=_APPLY))
        return UpdateEnd.DONE
    try:
        _show_waiting(live, engine, origin)
    except checkout.GitError as error:
        write_error(f"cannot list the waiting commits, {error}; {_NOTHING_CHANGED}")
        return UpdateEnd.FAILED
    if not confirmed(f"update the checkout to {origin.short}"):
        write_error(f"aborted, {_NOTHING_CHANGED}; {waiting_text(origin.behind)}")
        return UpdateEnd.DECLINED
    if reason := _changed_since_planned(live, origin):
        write_error(
            reason if _NOTHING_CHANGED in reason else f"{reason}; {_NOTHING_CHANGED}", _AGAIN
        )
        return UpdateEnd.REFUSED
    return _Merge(live, origin).run()


def _show_waiting(live: checkout.Git, engine: compose.Compose, origin: checkout.Origin) -> None:
    paths = live.files_changed_to(origin.sha)
    try:
        tracked = core.Checkout.read(engine.resolved_configuration(), live)
    except (compose.ComposeError, core.CoreError, checkout.GitError) as error:
        by_effect, reason = None, f"{len(paths)} changed files cannot be classified: {error}"
    else:
        by_effect, reason = classify(paths, tracked.kinds), ""
    for row in update_rows(origin, live.commits_to(origin.sha), by_effect, reason):
        write_row(row)


def classify(
    paths: Iterable[str], kinds: Mapping[str, checkout.EntryKind]
) -> dict[Effect, list[str]]:
    """The changed `paths` by effect, the first match winning: hal's code, under a directory bind
    source, a file bind source or a planned file, the rest. `kinds` are the bind sources of the
    configuration the checkout holds, by the tree entry at its HEAD."""
    directories = tuple(
        f"{source}/" for source, kind in kinds.items() if kind is checkout.EntryKind.DIRECTORY
    )
    files = {source for source, kind in kinds.items() if kind is checkout.EntryKind.FILE}
    grouped: dict[Effect, list[str]] = {effect: [] for effect in Effect}
    for path in paths:
        grouped[_effect_of(path, directories, files)].append(path)
    return grouped


def _effect_of(path: str, directories: Collection[str], files: Collection[str]) -> Effect:
    if path.startswith(_CODE_DIRECTORIES) or path in _CODE_FILES:
        return Effect.CODE
    if path.startswith(tuple(directories)):
        return Effect.DIRECTORY_BIND
    if path in files or path in _PLANNED_FILES:
        return Effect.PLANNED
    return Effect.OTHER


def _changed_since_planned(git: checkout.Git, origin: checkout.Origin) -> str | None:
    """Why the update must not start after the `yes`, else None; says the dirty paths itself."""
    try:
        if refusal := checkout.not_clean_main(git):
            if refusal.paths:
                write_row(local_changes_row(refusal.paths))
            return refusal.message
        head = git.full()
        if head != origin.head_sha:
            return f"HEAD moved while the question waited, planned {origin.head_sha}, now {head}"
        if not git.is_commit(origin.sha):
            return f"{origin.sha} is no commit any more"
        if not git.is_ancestor(head, origin.sha):
            return f"{origin.sha} is no fast-forward of HEAD {head}"
    except checkout.GitError as error:
        return f"cannot read the live checkout, {error}"
    return None


class _Stop(Exception):
    """A handled outcome from the merge on: how the run ends and what it says."""

    def __init__(self, end: UpdateEnd, message: str, next_step: str) -> None:
        super().__init__(message)
        self.end = end
        self.next_step = next_step


@dataclass
class _Merge:
    """The steps from the merge to the closing verdict, with SIGINT blocked but for the sync."""

    git: checkout.Git
    origin: checkout.Origin
    step: Step = Step.MERGE
    sync: SyncProgress = SyncProgress.NOT_STARTED

    def run(self) -> UpdateEnd:
        try:
            with _sigint_blocked():
                self._merge()
                self._check(Step.CHECK_AFTER_MERGE, with_tree=True)
                _stop_if_interrupted()
                self._sync()
                self._check(Step.CHECK_AFTER_SYNC, with_tree=False)
                _stop_if_interrupted()
        except KeyboardInterrupt:
            end = self._report(
                f"interrupted at '{self.step}' of the update to {self.origin.sha}, {self.sync}",
                UpdateEnd.INTERRUPTED,
            )
        except _Stop as stop:
            write_error(str(stop), stop.next_step)
            end = stop.end
        except Exception as error:
            end = self._report(self._partial(f"unexpected error ({type(error).__name__})"))
        else:
            summary = f"checkout updated to {self.origin.short} · dependencies synced"
            write_verdict(Verdict(Glyph.DONE, summary, (), next_step=_APPLY))
            return UpdateEnd.DONE
        return end

    def _report(self, message: str, end: UpdateEnd = UpdateEnd.FAILED) -> UpdateEnd:
        write_error(message, _APPLY)
        return end

    def _partial(self, reason: str) -> str:
        return f"partial update to {self.origin.sha} at '{self.step}': {reason}"

    def _stop(self, reason: str) -> _Stop:
        return _Stop(UpdateEnd.FAILED, self._partial(reason), _APPLY)

    def _merge(self) -> None:
        try:
            self.git.merge_fast_forward(self.origin.sha)
        except checkout.GitError as refused:
            raise self._after_refusal(refused) from refused

    def _after_refusal(self, refused: checkout.GitError) -> _Stop:
        """O2 when HEAD, the branch and the tree prove that git changed nothing, else O3."""
        try:
            found = self._differences(self.origin.head_sha, with_tree=True)
        except checkout.GitError as unreadable:
            return self._stop(f"{refused}; the checkout cannot be read afterwards, {unreadable}")
        if found:
            return self._stop(f"{refused}; afterwards {found}")
        message = f"{refused}; {self.origin.sha} is not merged, {_NOTHING_CHANGED}"
        return _Stop(UpdateEnd.FAILED, message, _AGAIN)

    def _check(self, step: Step, *, with_tree: bool) -> None:
        self.step = step
        try:
            found = self._differences(self.origin.sha, with_tree=with_tree)
        except checkout.GitError as unreadable:
            raise self._stop(f"cannot read the checkout, {unreadable}") from unreadable
        if found:
            raise self._stop(found)

    def _differences(self, expected_head: str, *, with_tree: bool) -> str:
        """What differs from `expected_head` on `main` with nothing changed, else an empty string;
        only HEAD is read without the tree."""
        found = []
        if (head := self.git.full()) != expected_head:
            found.append(f"HEAD is {head}, not {expected_head}")
        if with_tree:
            if (branch := self.git.branch()) != checkout.MAIN:
                found.append(f"the branch is {printable(branch or 'detached')}")
            if changed := self.git.changed_paths():
                found.append(f"changed: {', '.join(changed)}")
        return "; ".join(found)

    def _sync(self) -> None:
        self.step = Step.SYNC
        script = self.git.tree / SYNC_SCRIPT
        sync = [str(script), str(self.git.tree)]
        if is_verbose():
            write_line(printable(" ".join(sync)), stream=Stream.STDERR)
        self.sync = SyncProgress.RUNNING
        try:
            with _sigint_unblocked():
                result = checkout.run_in_own_group(sync, os.environ, None)
        except OSError as error:
            raise self._stop(f"cannot start {script} ({error.strerror})") from error
        self.sync = SyncProgress.ENDED
        if result.returncode:
            last = compose.last_line(result.stderr.decode("utf-8", "backslashreplace"))
            raise self._stop(f"the sync exited {result.returncode}: {last}")


@contextmanager
def _sigint_blocked() -> Iterator[None]:
    """SIGINT blocked for the block: a Ctrl-C neither reaches git nor interrupts the wait. A
    signal still pending at the end is consumed, so unblocking raises nothing."""
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.sigtimedwait({signal.SIGINT}, 0)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


@contextmanager
def _sigint_unblocked() -> Iterator[None]:
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGINT})
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})


def _stop_if_interrupted() -> None:
    """Raise the interrupt a blocked Ctrl-C left pending, and consume it."""
    if signal.sigtimedwait({signal.SIGINT}, 0) is not None:
        raise KeyboardInterrupt
