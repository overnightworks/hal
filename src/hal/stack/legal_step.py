"""The legal step of `hal apply --local`: the three pages built from `legal/frame`, the
sections of `legal/sections` and each app's own `legal/` files at the release it shows
(`apps.ShownRelease`; a host-only app's is HEAD of its checkout), compared with `legal/built`, and
written there after the operator's `yes`.

The step runs only while `services.legal` is in the catalog and enabled. Every refusal comes at
plan time, before the question, and nothing is written on one.
"""

import json
import os
import tempfile
from collections.abc import Callable, Collection, Mapping
from dataclasses import asdict, dataclass, field
from datetime import date
from enum import Enum, StrEnum
from hashlib import sha256
from pathlib import Path

from hal.stack import apps, catalog, checkout, deploy_checkout
from hal.stack.legal_pages import (
    TEMPLATES,
    Block,
    BlockFingerprint,
    BlockKind,
    Frame,
    PageFingerprint,
    build_pages,
    fingerprint_pages,
    frame_page_path,
    frame_template_path,
)
from hal.stack.legal_section import PAGES, LegalError, parse_fragment, parse_general
from hal.stack.unit_plans import Fleet, NotWritten, Progress

LEGAL_UNIT = "legal"
GENERAL_UNIT = "allgemein"
SECTIONS_DIRECTORY = "legal/sections"
BUILT_DIRECTORY = "legal/built"
SECTION_PAGES = ("datenschutz", "nutzungsbedingungen")
PRIVACY_PAGE = "datenschutz"
APP_DIRECTORY = "legal"
# The anchor of a block of edge's own services; any other block's anchor is its catalog key.
SERVICE_ANCHORS = {
    "keycloak": "anmeldung",
    "agent-service": "agent-dienst",
    "speech-runtime": "sprachdienst",
}
_BUILT_MODE = 0o644  # nginx-unprivileged must read the page whatever the umask


class PageChange(Enum):
    NEW = "no built page"
    CHANGED = "the built page differs"
    UNRECORDED = "the page matches, its record is missing, unreadable or stale"


class Change(StrEnum):
    NEW = "new"
    CHANGED = "changed"
    LEFT = "left"


@dataclass(frozen=True)
class BlockChange:
    """A block of a page, or its frame (no anchor), as the new build changes it."""

    path: str
    change: Change
    anchor: str = ""
    tag: str = ""  # the release an app's block is read at; empty for edge's own


@dataclass(frozen=True)
class LegalPlan:
    repository: Path
    record: Path  # what the last write was made of, in the apply state
    pages: Mapping[str, str]  # empty while the step does not run
    changed: Mapping[str, PageChange]  # the pages to write
    changed_blocks: Mapping[str, tuple[BlockChange, ...]] = field(default_factory=dict)  # by page
    fingerprints: Mapping[str, PageFingerprint] = field(default_factory=dict)

    @property
    def changes_nothing(self) -> bool:
        return not self.changed

    def write(self, progress: Progress) -> NotWritten | None:
        """Write the changed pages; the failure, or None. The progress names this step only
        while it runs."""
        progress.unit, progress.step = LEGAL_UNIT, "write the legal pages"
        failed = self.repository
        try:
            for page, change in self.changed.items():
                if change is not PageChange.UNRECORDED:
                    failed = Path(BUILT_DIRECTORY, f"{page}.html")
                    _replace(self.repository / BUILT_DIRECTORY, page, self.pages[page])
            if self.changed:
                failed = self.record
                write_record(self.record, self.fingerprints)
        except OSError as error:
            return NotWritten.from_error(LEGAL_UNIT, failed, error)
        finally:
            progress.unit = progress.step = ""
        return None


def plan_legal(
    repository: Path,
    record: Path,
    fleet: Fleet,
    released: apps.AppsPlan,
    run_git: checkout.Runner = checkout.run_git,
) -> LegalPlan:
    """What the step would write; a plan without pages while the legal unit does not run."""
    if not any(unit.key == LEGAL_UNIT and unit.enabled for unit in fleet.units):
        return LegalPlan(repository, record, {}, {})
    release_blocks = _shown_release_blocks(repository, released)
    git = checkout.Git(repository, run_git)
    all_blocks = read_blocks(
        repository, _catalog_keys(repository), lambda path: _commit_date(git, path)
    )
    tags: dict[str, str] = {}
    for shown, app in release_blocks:
        all_blocks += app
        tags |= {block.path: shown.tag for block in app}
    frame = read_frame(repository)
    pages = build_pages(frame, all_blocks)
    fingerprints = fingerprint_pages(frame, all_blocks, pages)
    changed: dict[str, PageChange] = {}
    named: dict[str, tuple[BlockChange, ...]] = {}
    for page, text in pages.items():
        built = _read_built(repository, page)
        previous = None if built is None else read_recorded_page(record, built, page)
        if change := _change(built, previous, text):
            changed[page] = change
            if change is PageChange.CHANGED:
                named[page] = block_changes(page, previous, fingerprints[page], tags)
            elif change is PageChange.NEW:
                named[page] = tuple(
                    one for one in block_changes(page, None, fingerprints[page], tags) if one.tag
                )
    return LegalPlan(repository, record, pages, changed, named, fingerprints)


def _shown_release_blocks(
    repository: Path, released: apps.AppsPlan
) -> list[tuple[apps.ShownRelease, list[Block]]]:
    """Each release the pages show, with its blocks; refuses a key whose text edge holds too."""
    document = catalog.read(repository / catalog.FLEET_FILE)
    host_only = catalog.host_only_keys(document)
    zone = catalog.zone(document)
    shown_releases = [*released.shown, *(_head_of(key, released.runtime) for key in host_only)]
    release_blocks = [(shown, _release_blocks(shown, zone)) for shown in shown_releases]
    _refuse_two_owners(
        repository,
        {app.key for app in released.catalogued} | set(host_only),
        {shown.key for shown, blocks in release_blocks if blocks},
    )
    return release_blocks


def _read_built(repository: Path, page: str) -> bytes | None:
    try:
        return (repository / BUILT_DIRECTORY / f"{page}.html").read_bytes()
    except FileNotFoundError:
        return None


def read_frame(repository: Path) -> Frame:
    return Frame(
        {page: _read(repository, frame_page_path(page)).decode() for page in PAGES},
        {name: _read(repository, frame_template_path(name)).decode() for name in TEMPLATES},
    )


def read_blocks(
    repository: Path, catalog_keys: Collection[str], date_of: Callable[[str], date]
) -> list[Block]:
    """The blocks of `legal/sections`: the general part, and one per unit that is in the catalog."""
    zone = catalog.zone(catalog.read(repository / catalog.FLEET_FILE))
    blocks: list[Block] = []
    for page in SECTION_PAGES:
        path = f"{SECTIONS_DIRECTORY}/{GENERAL_UNIT}/{page}.html"
        parsed = parse_general(path, _read(repository, path), zone)
        blocks.append(Block(path, page, BlockKind.GENERAL, parsed, date_of(path)))
    for unit in sorted(path.name for path in (repository / SECTIONS_DIRECTORY).iterdir()):
        if unit in catalog_keys and unit != GENERAL_UNIT:
            blocks += _unit_blocks(repository, unit, zone, date_of)
    return blocks


def _unit_blocks(
    repository: Path, unit: str, zone: str, date_of: Callable[[str], date]
) -> list[Block]:
    blocks = []
    for page in SECTION_PAGES:
        path = f"{SECTIONS_DIRECTORY}/{unit}/{page}.html"
        if (repository / path).is_file():
            blocks.append(
                unit_block(path, _read(repository, path), page, unit, zone, date_of(path))
            )
    return blocks


def unit_block(path: str, data: bytes, page: str, unit: str, zone: str, written: date) -> Block:
    """One unit's file for one page as a block; the anchor is its key or its service anchor."""
    anchor = SERVICE_ANCHORS.get(unit, unit)
    kind = BlockKind.SERVICE if unit in SERVICE_ANCHORS else BlockKind.APP
    return Block(path, page, kind, parse_fragment(path, data, anchor, zone), written)


def app_blocks(
    read: Callable[[str], bytes | None],
    key: str,
    zone: str,
    date_of: Callable[[str], date],
    shown_under: str,
) -> list[Block]:
    """The blocks of the app's own `legal` files that exist; `read` gives a file's bytes by its
    path inside the app, None when it is absent, and `shown_under` prefixes the path a block is
    named by."""
    blocks = []
    for page in SECTION_PAGES:
        inside = f"{APP_DIRECTORY}/{page}.html"
        if (data := read(inside)) is not None:
            path = f"{shown_under}{inside}"
            blocks.append(unit_block(path, data, page, key, zone, date_of(inside)))
    return blocks


def check_app(repository: Path, key: str, directory: Path, today: date) -> tuple[str, ...]:
    """Builds the pages with the app's files in place of the checkout's own block for `key`;
    returns the files that were valid, and raises LegalError for what `hal apply` would refuse
    and for a missing privacy file, which every app needs."""
    zone = catalog.zone(catalog.read(repository / catalog.FLEET_FILE))
    others = _catalog_keys(repository) - {key}
    blocks = read_blocks(repository, others, lambda _path: today)
    app = app_blocks(lambda inside: _app_file(directory, inside), key, zone, lambda _: today, "")
    if PRIVACY_PAGE not in {block.page for block in app}:
        raise LegalError(
            f"{APP_DIRECTORY}/{PRIVACY_PAGE}.html is missing; every app needs a privacy section"
        )
    _refuse_two_owners(repository, {key}, {key})
    build_pages(read_frame(repository), [*blocks, *app])
    return tuple(block.path for block in app)


def _app_file(directory: Path, inside: str) -> bytes | None:
    file = directory / inside
    if not file.is_symlink() and not file.exists():
        return None
    if file.is_symlink() or not file.is_file():
        raise LegalError(f"{inside} is not a regular file")
    return _read(directory, inside)


def _release_blocks(shown: apps.ShownRelease, zone: str) -> list[Block]:
    """The app's blocks read at the release the pages show, from its checkout `~/srv/<key>`."""
    where = f"~/srv/{shown.key}"
    git = shown.checkout.git
    try:
        shown.checkout.require_repository()
        blocks = app_blocks(
            lambda inside: shown.checkout.file_at(shown.sha, inside),
            shown.key,
            zone,
            lambda inside: _commit_date(git, inside, shown.sha),
            f"{where}/",
        )
    except (checkout.GitError, deploy_checkout.CheckoutRefused) as error:
        raise LegalError(f"{where}: cannot read {shown.tag} ({shown.sha}): {error}") from error
    # Without the privacy file the release has no block at all, its terms included.
    return blocks if any(block.page == PRIVACY_PAGE for block in blocks) else []


def _head_of(key: str, runtime: apps.AppRuntime) -> apps.ShownRelease:
    """The release of an app without origin: HEAD of its checkout `~/srv/<key>`, named by its
    short sha."""
    where = f"~/srv/{key}"
    tree = deploy_checkout.AppCheckout(checkout.Git(runtime.srv / key, runtime.git), "", "")
    try:
        tree.require_repository()
        sha = tree.head()
        if sha is None:
            raise LegalError(f"{where}: has no commit")
        return apps.ShownRelease(key, tree.git.short(sha), sha, tree)
    except (checkout.GitError, deploy_checkout.CheckoutRefused) as error:
        raise LegalError(f"{where}: cannot read its HEAD: {error}") from error


def _refuse_two_owners(
    repository: Path, app_keys: Collection[str], shipping: Collection[str]
) -> None:
    """An app's text is its release's own; edge holding a section for the key too is refused,
    unless the key is one of edge's own services whose release has no block (is not `shipping`)."""
    for key in sorted(app_keys):
        edge_owns = key in SERVICE_ANCHORS and key not in shipping
        if not edge_owns and (repository / SECTIONS_DIRECTORY / key).exists():
            raise LegalError(
                f"{SECTIONS_DIRECTORY}/{key}/ and ~/srv/{key}/{APP_DIRECTORY}/ both hold the text "
                f"of {key}; one block has one owner, so remove {SECTIONS_DIRECTORY}/{key}/"
            )


def _catalog_keys(repository: Path) -> set[str]:
    document = catalog.read(repository / catalog.FLEET_FILE)
    return set(document.get("services", {}))


def _read(repository: Path, relative: str) -> bytes:
    try:
        return (repository / relative).read_bytes()
    except FileNotFoundError as error:
        what = "the general part" if relative.startswith(SECTIONS_DIRECTORY) else "the frame"
        raise LegalError(
            f"{relative} is missing; {what} is required while services.{LEGAL_UNIT} runs"
        ) from error
    except OSError as error:
        raise LegalError(f"{relative}: cannot read it ({error.strerror})") from error


def _commit_date(git: checkout.Git, relative: str, revision: str = "HEAD") -> date:
    """The committer date of the newest commit up to `revision` that touched the file, in git's
    `%cs` form."""
    newest = ["log", "-1", "--format=%cs", revision, "--", relative]
    answer = git.call(newest).stdout.decode().strip()
    try:
        return date.fromisoformat(answer)
    except ValueError as error:
        raise LegalError(f"{relative}: has no commit") from error


def _change(built: bytes | None, previous: PageFingerprint | None, text: str) -> PageChange | None:
    if built is None:
        return PageChange.NEW
    if built != text.encode():
        return PageChange.CHANGED
    return PageChange.UNRECORDED if previous is None else None


def _replace(directory: Path, page: str, text: str) -> None:
    """The page's new bytes under a temporary name in the same directory, then renamed over it."""
    descriptor, temporary = tempfile.mkstemp(dir=directory, prefix=f".{page}.", suffix=".tmp")
    try:
        os.fchmod(descriptor, _BUILT_MODE)  # NOSONAR python:S2612 a public page, read by nginx
        with os.fdopen(descriptor, "wb") as file:
            file.write(text.encode())
        os.replace(temporary, directory / f"{page}.html")
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


# The record of what the step last wrote sits in the apply state, not beside the pages: nginx serves
# `legal/built/`. A page's entry is trusted only while the built page still has the bytes the entry
# was made from; a missing, unreadable or stale entry makes every block of the page new, and the
# plan then writes the record even when the page bytes already match.
RECORD_FILE = "legal-built.json"
_RECORD_MODE = 0o600


def read_recorded_page(record: Path, built_text: bytes, page: str) -> PageFingerprint | None:
    """The page's entry, or None when there is none or it does not describe `built_text`."""
    try:
        entry = json.loads(record.read_text())[page]
        fingerprint = PageFingerprint(
            entry["page_sha256"],
            entry["frame_sha256"],
            tuple(
                BlockFingerprint(
                    block["path"], block["anchor"], BlockKind(block["kind"]), block["sha256"]
                )
                for block in entry["blocks"]
            ),
        )
    except OSError, ValueError, KeyError, TypeError:
        return None
    return fingerprint if fingerprint.page_sha256 == sha256(built_text).hexdigest() else None


def write_record(target: Path, fingerprints: Mapping[str, PageFingerprint]) -> None:
    """The whole record under a temporary name, then renamed over the old one."""
    text = json.dumps({page: asdict(one) for page, one in fingerprints.items()}, indent=1)
    temporary = target.with_name(f".{target.name}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, _RECORD_MODE)
    with os.fdopen(descriptor, "w") as file:
        file.write(text)
    os.replace(temporary, target)


def block_changes(
    page: str,
    previous: PageFingerprint | None,
    current: PageFingerprint,
    tags: Mapping[str, str],
) -> tuple[BlockChange, ...]:
    """What the new build changes on the page against what was written; `tags` names the release
    of each app block by its path."""
    if previous is None:
        return tuple(_block_change(block, Change.NEW, tags) for block in current.blocks)
    before = {(block.path, block.anchor): block for block in previous.blocks}
    after = {(block.path, block.anchor): block for block in current.blocks}
    changes = []
    if previous.frame_sha256 != current.frame_sha256:
        changes.append(BlockChange(frame_page_path(page), Change.CHANGED))
    for key, block in after.items():
        if key not in before:
            changes.append(_block_change(block, Change.NEW, tags))
        elif before[key] != block:
            changes.append(_block_change(block, Change.CHANGED, tags))
    changes += (
        _block_change(block, Change.LEFT, {}) for key, block in before.items() if key not in after
    )
    return tuple(changes)


def _block_change(block: BlockFingerprint, change: Change, tags: Mapping[str, str]) -> BlockChange:
    return BlockChange(block.path, change, block.anchor, tags.get(block.path, ""))
