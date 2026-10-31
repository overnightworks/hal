"""The cells of `hal update` (#783 P1-P4) over the switches probe's `Probe`: the copy of the
repository behind a bare remote, every `hal` run through the copy's `bin/hal`.

P1 a commit waiting on origin: `hal apply --local` refuses and names `hal update`; `hal update`
answered `no` changes nothing and shows the files by effect on the real configuration. P2 a commit
that bumps the project version in `pyproject.toml` and `uv.lock` and, while `HAL_PROBE_MARKER`
names a file, writes the interpreter and the installed version at import: `hal update` brings the
new lock in before any other run, and the next `hal apply` runs the merged code with it. P3 a
`pyproject.toml` bump without `uv.lock` and P4 code that fails at import: `hal update` ends with 3
or 0, every later `bin/hal` run ends before it fetches, and a hand pull repairs it.

Each cell asserts outcomes (exit code, output, installed version, marker), not the sha alone.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from edge_copy import HAL_FAILURE, ProbeFailed, advance_origin, expect, git

from hal.output import write_line
from hal.stack import checkout

if TYPE_CHECKING:
    from probe import Probe

DECLINED = 1  # hal's exit for an update answered `no`
IMPORT_FAILED = 1  # Python's exit for a traceback
MARKER_VARIABLE = "HAL_PROBE_MARKER"
PROJECT_NAME = "overnightworks-hal"
NOTHING_TO_CHANGE = "nothing to change"
WAITING_NOTE = "\n"  # a change that touches no setting
APPLY_MODULE = "src/hal/stack/apply.py"
MARKER_CODE = f"""
import os as _probe_os

if _probe_os.environ.get("{MARKER_VARIABLE}"):
    import importlib.metadata as _probe_metadata
    import sys as _probe_sys

    with open(_probe_os.environ["{MARKER_VARIABLE}"], "w") as _probe_file:
        _version = _probe_metadata.version("{PROJECT_NAME}")
        _probe_file.write(f"{{_probe_sys.executable}} {{_version}}")
"""
BROKEN_IMPORT = '\nraise RuntimeError("probe: broken import")\n'


def installed_version(copy: Path) -> str:
    """The version of the project the copy's venv has installed."""
    shown = subprocess.run(
        [str(copy / ".venv" / "bin" / "python"), "-c",
         f"import importlib.metadata as m; print(m.version('{PROJECT_NAME}'))"],
        capture_output=True, check=True, text=True, timeout=60,
    )  # fmt: skip
    return shown.stdout.strip()


def project_version(copy: Path) -> str:
    [version] = re.findall(r'^version = "(.*)"$', (copy / "pyproject.toml").read_text(), re.M)
    return version


def bumped(version: str) -> str:
    *release, patch = version.split(".")
    return ".".join([*release, str(int(patch) + 1)])


def pyproject_edit(old: str, new: str) -> dict[str, tuple[str, str]]:
    """The edit that moves the project's version in `pyproject.toml` from `old` to `new`."""
    return {"pyproject.toml": (f'version = "{old}"', f'version = "{new}"')}


def lock_edit(old: str, new: str) -> dict[str, tuple[str, str]]:
    """The edit that moves the project's version in `uv.lock` from `old` to `new`."""
    entry = f'name = "{PROJECT_NAME}"\nversion = "'
    return {"uv.lock": (f'{entry}{old}"', f'{entry}{new}"')}


def fetched_state(copy: Path) -> tuple[bytes, str]:
    """What a fetch would change: FETCH_HEAD and origin's `main` as the copy last saw them."""
    fetch_head = copy / ".git" / "FETCH_HEAD"
    return fetch_head.read_bytes(), checkout.Git(copy).full(checkout.ORIGIN_MAIN)


def record_bytes(probe: Probe) -> bytes:
    return (probe.state / "applied.json").read_bytes()


def update(probe: Probe, *, typed: bytes = b"yes\n", exit_code: int = 0, **options) -> str:
    return probe.hal(
        "update", terminal=True, typed=typed, exit_code=exit_code, launcher=True, **options
    )


def apply_local(probe: Probe, *, exit_code: int = 0, terminal: bool = True, **options) -> str:
    return probe.hal(
        "apply", "--local", terminal=terminal, typed=b"no\n", exit_code=exit_code, launcher=True,
        **options,
    )  # fmt: skip


def pull(copy: Path) -> None:
    """The repair of a revision hal cannot run: the hand pull."""
    git(copy, "pull", "--quiet", "--ff-only", "origin", checkout.MAIN)


def cell_p1_behind_and_declined(probe: Probe) -> None:
    """P1: apply refuses behind origin and names `hal update`; `no` changes nothing."""
    copy, live = probe.copy, checkout.Git(probe.copy)
    head, containers, record = live.full(), probe.container_ids(), record_bytes(probe)
    version = installed_version(copy)
    waiting = advance_origin(
        probe.scratch,
        "probe: a commit waiting on origin",
        {"dynamic/.gitkeep": WAITING_NOTE, "README.md": WAITING_NOTE},
    )
    refused = apply_local(probe, exit_code=HAL_FAILURE)
    for shown in ("! checkout 1 behind", "1 commit waits on origin main", "next: hal update"):
        expect(shown in refused, f"apply behind origin said {shown!r}? {refused[-300:]}")
    declined = update(probe, typed=b"no\n", exit_code=DECLINED)
    for shown in ("aborted, nothing changed", "directory bind", "dynamic/.gitkeep", "other"):
        expect(shown in declined, f"the declined update said {shown!r}? {declined[-400:]}")
    expect(declined.index("dynamic/.gitkeep") < declined.index("README.md"), "groups out of order")
    expect(live.full() == head, "a declined update moved HEAD")
    expect(probe.container_ids() == containers, "a declined update touched a container")
    expect(record_bytes(probe) == record, "a declined update wrote applied.json")
    expect(installed_version(copy) == version, "a declined update changed the venv")
    write_line(
        f"#783 P1 held: {waiting} waiting is refused by apply naming hal update; "
        "`no` changed HEAD, containers, record and venv not at all"
    )


def cell_p2_new_lock_and_new_code(probe: Probe) -> None:
    """P2: the update's own sync used the new lock; the next apply ran the merged code."""
    copy, marker = probe.copy, probe.scratch / "marker"
    old = project_version(copy)
    new = bumped(old)
    advance_origin(
        probe.scratch,
        "probe: a new version and import-time code",
        {APPLY_MODULE: MARKER_CODE},
        {**pyproject_edit(old, new), **lock_edit(old, new)},
    )
    tip = checkout.Git(probe.scratch / "work").full()
    watching = {MARKER_VARIABLE: str(marker)}
    out = update(probe, extra_environment=watching)
    expect("next: hal apply" in out, f"the update said: {out[-300:]}")
    expect(checkout.Git(copy).full() == tip, "HEAD is not the pushed sha after the update")
    expect(installed_version(copy) == new, f"the venv holds {installed_version(copy)}, not {new}")
    expect(not marker.exists(), "the old process ran merged code")
    applied = apply_local(probe, extra_environment=watching)
    expect(NOTHING_TO_CHANGE in applied, f"the apply after the update said: {applied[-300:]}")
    executable, ran = marker.read_text().rsplit(" ", 1)
    expect(Path(executable).parent == copy / ".venv" / "bin", f"the apply ran {executable}")
    expect(ran == new, f"the merged code saw version {ran}, not {new}")
    write_line(f"#783 P2 held: update to {tip[:7]} synced version {new}, the apply ran it")


def cell_p3_lock_that_does_not_sync(probe: Probe) -> None:
    """P3: a bump without its lock ends the update with 3; the launcher then refuses before any
    fetch; the hand pull of a fixing commit repairs it."""
    copy, containers = probe.copy, probe.container_ids()
    old = project_version(copy)
    new = bumped(old)
    advance_origin(probe.scratch, "probe: a bump without its lock", {}, pyproject_edit(old, new))
    tip = checkout.Git(probe.scratch / "work").full()
    record = record_bytes(probe)
    out = update(probe, exit_code=HAL_FAILURE)
    for shown in (tip, "sync the dependencies", "next: hal apply"):
        expect(shown in out, f"the failed sync said {shown!r}? {out[-400:]}")
    expect(checkout.Git(copy).full() == tip, "HEAD is not at the sha after the failed sync")
    expect(record_bytes(probe) == record, "a failed sync wrote applied.json")
    seen = fetched_state(copy)
    refused = apply_local(probe, exit_code=HAL_FAILURE, terminal=False)
    expect("cannot sync the live checkout's dependencies" in refused, f"launcher: {refused[-300:]}")
    expect(fetched_state(copy) == seen, "the launcher fetched after a failed sync")
    advance_origin(probe.scratch, "probe: the lock follows", {}, lock_edit(old, new))
    pull(copy)
    current = update(probe)
    expect("nothing to update" in current and "next: hal apply" in current, current[-300:])
    expect(NOTHING_TO_CHANGE in apply_local(probe), "the apply after the repair planned a change")
    expect(probe.container_ids() == containers, "the repair replaced a container")
    write_line(
        "#783 P3 held: a lock that does not sync ends 3, the launcher stops, the pull repairs"
    )


def cell_p4_code_that_fails_at_import(probe: Probe) -> None:
    """P4: the update imports nothing after the merge and ends 0; every later run ends with
    Python's traceback and exit 1 before it fetches; the hand pull repairs it."""
    copy = probe.copy
    advance_origin(probe.scratch, "probe: code that fails at import", {APPLY_MODULE: BROKEN_IMPORT})
    tip = checkout.Git(probe.scratch / "work").full()
    out = update(probe)
    expect("next: hal apply" in out, f"the update said: {out[-300:]}")
    expect(checkout.Git(copy).full() == tip, "HEAD is not the pushed sha after the update")
    seen = fetched_state(copy)
    for broken in (
        apply_local(probe, exit_code=IMPORT_FAILED),
        update(probe, exit_code=IMPORT_FAILED),
    ):
        expect("Traceback" in broken and "probe: broken import" in broken, broken[-300:])
    expect(fetched_state(copy) == seen, "a run that failed at import fetched")
    advance_origin(
        probe.scratch, "probe: the import is fixed", {}, {APPLY_MODULE: (BROKEN_IMPORT, "")}
    )
    pull(copy)
    expect("next: hal apply" in update(probe), "the update after the repair did not name the apply")
    expect(NOTHING_TO_CHANGE in apply_local(probe), "the apply after the repair planned a change")
    write_line(
        "#783 P4 held: a failing import ends every run with a traceback, the pull repairs it"
    )


def cells(probe: Probe) -> None:
    """P1 to P4 in order; each starts from what the one before left."""
    for cell in (
        cell_p1_behind_and_declined,
        cell_p2_new_lock_and_new_code,
        cell_p3_lock_that_does_not_sync,
        cell_p4_code_that_fails_at_import,
    ):
        try:
            cell(probe)
        except subprocess.CalledProcessError as failure:
            raise ProbeFailed(f"{cell.__name__}: {failure}") from failure
