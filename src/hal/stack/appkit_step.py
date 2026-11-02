"""The appkit step of the closed apply: the installed appkit's static files (tokens and fonts),
compared with `appkit-<version>/` in three targets and written there after the operator's `yes`:
`legal/assets/`, which the legal unit serves at `/_rechtliches/appkit-<version>/`, and the
`resources/` of the login and the account theme, which Keycloak serves at
`/resources/<id>/appkit-<version>/`. The version in the path is the version in the lock. The step
runs whether or not `services.legal` is enabled, and every refusal comes at plan time, before the
question: nothing is written on one.

`python -m hal.stack.appkit_step <repository>` runs the whole step without the question, for the
Keycloak probe, whose stack binds the themes from a checkout where no apply runs.
"""

import os
import shutil
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from importlib import import_module, metadata
from pathlib import Path
from types import ModuleType

from hal.output import Stream, write_line
from hal.stack.unit_plans import NotWritten, Progress

DISTRIBUTION = "overnightworks-appkit"
APPKIT_UNIT = "appkit"
_DIRECTORY_PREFIX = "appkit-"
_TEMPORARY_PREFIX = ".appkit-"
_DIRECTORY_MODE = 0o755  # nginx-unprivileged must read what a 0700 mkdtemp directory would hide
_FILE_MODE = 0o644

type Rename = Callable[[Path, Path], object]


@dataclass(frozen=True)
class AppkitTarget:
    """One place the appkit files are served from: the directory holding `appkit-<version>/`,
    relative to the repository, and how a row names it."""

    directory: str
    label: str

    def served(self, repository: Path, version: str) -> Path:
        return repository / self.directory / f"{_DIRECTORY_PREFIX}{version}"


TARGETS = (
    AppkitTarget("legal/assets", "legal assets"),
    AppkitTarget("keycloak/themes/hallucinai/login/resources", "login theme"),
    AppkitTarget("keycloak/themes/hallucinai/account/resources", "account theme"),
)


class AppkitError(Exception):
    """The step cannot plan: appkit is not installed, or a target's parent is missing."""


@dataclass(frozen=True)
class AppkitPlan:
    version: str
    source: Path
    repository: Path
    changed: tuple[Path, ...]  # the targets that are missing or differ from the installed files
    stale: tuple[Path, ...]  # this step's other `appkit-*` directories, relative to the repository
    rename: Rename = os.rename

    @property
    def changes_nothing(self) -> bool:
        return not (self.changed or self.stale)

    @property
    def changed_labels(self) -> tuple[str, ...]:
        """The labels of the targets in `changed`, in the order of `TARGETS`."""
        return tuple(
            target.label
            for target in TARGETS
            if target.served(self.repository, self.version) in self.changed
        )

    @property
    def stale_names(self) -> tuple[str, ...]:
        """The names of the stale directories, sorted, each once whatever the target."""
        return tuple(sorted({path.name for path in self.stale}))

    def write(self, progress: Progress) -> NotWritten | None:
        """Write the directory and remove the stale ones; the failure, or None. The progress
        names this step only while it runs."""
        progress.unit, progress.step = APPKIT_UNIT, "write the appkit files"
        target = self.repository
        try:
            for target in self.changed:
                _replace_directory(self.source, target, self.rename)
            for name in self.stale:
                target = self.repository / name
                shutil.rmtree(target)
        except OSError as error:
            return NotWritten.from_error(APPKIT_UNIT, target, error)
        finally:
            progress.unit = progress.step = ""
        return None


def plan_appkit(
    repository: Path,
    find_package: Callable[[str], ModuleType] = import_module,
    rename: Rename = os.rename,
) -> AppkitPlan:
    """What the step would write. The lookup happens here, not at import: `hal.stack_commands`
    imports `hal.stack.apply`, and a machine without a synced environment must still run `hal`."""
    source = installed_static(find_package)
    targets = served_directories(repository)
    for parent in dict.fromkeys(target.parent for target in targets):
        if not parent.is_dir():
            raise AppkitError(f"{parent} is missing, the checkout is broken")
    stale = tuple(
        sorted(
            path.relative_to(repository)
            for target in targets
            for path in target.parent.glob(f"{_DIRECTORY_PREFIX}*")
            if path.is_dir() and path != target
        )
    )
    installed = _bytes_of(source)
    changed = tuple(target for target in targets if installed != _bytes_of(target))
    return AppkitPlan(metadata.version(DISTRIBUTION), source, repository, changed, stale, rename)


def installed_static(find_package: Callable[[str], ModuleType] = import_module) -> Path:
    try:
        appkit = find_package("appkit")
    except ImportError as error:
        raise AppkitError("appkit is not installed, run `uv sync`") from error
    return Path(str(appkit.__file__)).parent / "static"


def served_directories(repository: Path) -> tuple[Path, ...]:
    version = metadata.version(DISTRIBUTION)
    return tuple(target.served(repository, version) for target in TARGETS)


def _bytes_of(directory: Path) -> dict[str, bytes]:
    """Every file under the directory by its relative path; empty while it does not exist."""
    return {
        str(path.relative_to(directory)): path.read_bytes()
        for path in directory.rglob("*")
        if path.is_file()
    }


def _replace_directory(source: Path, directory: Path, rename: Rename = os.rename) -> None:
    """The files in a temporary directory beside the target, then renamed into place; a damaged
    directory moves aside first and moves back when the final rename fails. When it cannot move
    back, the temporary directory stays and the error names where the previous copy is."""
    temporary = Path(tempfile.mkdtemp(dir=directory.parent, prefix=_TEMPORARY_PREFIX))
    displaced = temporary / "displaced"
    previous_copy_is_only_in_temporary = False
    try:
        shutil.copytree(source, temporary / "files", copy_function=_copy_readable)
        _make_readable(temporary / "files")
        if directory.exists():
            rename(directory, displaced)
        try:
            rename(temporary / "files", directory)
        except BaseException:
            if displaced.exists():
                previous_copy_is_only_in_temporary = True
                try:
                    rename(displaced, directory)
                except OSError as restore_error:
                    raise OSError(
                        restore_error.errno,
                        f"{restore_error.strerror}; the previous copy is kept in {displaced}",
                    ) from restore_error
                except BaseException as interruption:
                    interruption.add_note(f"the previous copy is kept in {displaced}")
                    raise
                previous_copy_is_only_in_temporary = False
            raise
    finally:
        if not previous_copy_is_only_in_temporary:
            shutil.rmtree(temporary, ignore_errors=True)


def _copy_readable(source: str, destination: str) -> str:
    shutil.copyfile(source, destination)
    os.chmod(destination, _FILE_MODE)  # NOSONAR python:S2612 public files, read by nginx
    return destination


def _make_readable(tree: Path) -> None:
    for directory in (tree, *(path for path in tree.rglob("*") if path.is_dir())):
        os.chmod(directory, _DIRECTORY_MODE)  # NOSONAR python:S2612 read by nginx


def main(arguments: list[str]) -> int:
    """Plan and write without the question; the failure on stderr and exit 1, a refusal exit 2."""
    (repository,) = arguments
    try:
        failure = plan_appkit(Path(repository)).write(Progress())
    except AppkitError as error:
        write_line(f"appkit: cannot plan, {error}", stream=Stream.STDERR)
        return 2
    if failure:
        write_line(f"{failure.subject}: {failure.fact}", stream=Stream.STDERR)
    return 1 if failure else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
