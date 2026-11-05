"""The three legal pages assembled from the frame and the validated sections, as pure text.

The code owns the order of the blocks, the ids, the table of contents and the checks; the frame
(`legal/frame/`) owns the markup. A page lists its blocks as the general part in file order, then
the services and then the apps, each group sorted by anchor; the frame decides where each group
stands. Every id stands once in the assembled page, and every link to an id has a target there.
"""

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from string import Template

from hal.stack.legal_section import PAGES, Heading, LegalError, Parsed, refusal

FRAME_DIRECTORY = "legal/frame"
TEMPLATES = (
    "general",
    "service",
    "app",
    "app-section",
    "toc-entry",
    "toc-entry-with-sections",
)
TOC_TEMPLATES = ("toc-entry", "toc-entry-with-sections")
# Edge renames or removes none of these without asking the apps that link them first.
STABLE_IDS: Mapping[str, frozenset[str]] = {
    "datenschutz": frozenset(
        {
            "verantwortlicher",
            "cloudflare",
            "rechte",
            "widerspruch",
            "kein-tracking",
            "automatisierte-entscheidungen",
            "pseudonym",
            "anmeldung",
            "agent-dienst",
        }
    ),
    "nutzungsbedingungen": frozenset({"recht"}),
    "impressum": frozenset({"verantwortlich", "kontakt"}),
}
_MONTHS = (
    "Januar",
    "Februar",
    "März",
    "April",
    "Mai",
    "Juni",
    "Juli",
    "August",
    "September",
    "Oktober",
    "November",
    "Dezember",
)
_ID_ATTRIBUTE = re.compile(r'\sid="([^"]*)"')
FRAME_OWNER = "frame"


class BlockKind(StrEnum):
    GENERAL = "general"
    SERVICE = "service"
    APP = "app"


@dataclass(frozen=True)
class Block:
    path: str
    page: str
    kind: BlockKind
    parsed: Parsed
    date: date


@dataclass(frozen=True)
class BlockFingerprint:
    """One rendered block of a page: a general heading or a whole service or app block."""

    path: str
    anchor: str
    kind: BlockKind
    sha256: str


@dataclass(frozen=True)
class PageFingerprint:
    page_sha256: str
    frame_sha256: str  # the page's skeleton with no block in it
    blocks: tuple[BlockFingerprint, ...]


@dataclass(frozen=True)
class Frame:
    pages: Mapping[str, str]  # the page skeletons by page
    templates: Mapping[str, str]  # the block templates by name, `TEMPLATES`


def frame_page_path(page: str) -> str:
    return f"{FRAME_DIRECTORY}/{page}.html"


def frame_template_path(name: str) -> str:
    return f"{FRAME_DIRECTORY}/blocks/{name}.html"


def build_pages(frame: Frame, blocks: Sequence[Block]) -> dict[str, str]:
    """Every page's text; raises LegalError for an id clash or a link without a target."""
    ordered = {page: _in_page_order(blocks, page) for page in PAGES}
    rendered = {page: [(block, _render(frame, block)) for block in ordered[page]] for page in PAGES}
    owners = {page: _owners_of_ids(frame, page, rendered[page]) for page in PAGES}
    for page_blocks in ordered.values():
        for block in page_blocks:
            _check_links(block, owners)
    return {page: _page(frame, page, rendered[page]) for page in PAGES}


def fingerprint_pages(
    frame: Frame, blocks: Sequence[Block], pages: Mapping[str, str]
) -> dict[str, PageFingerprint]:
    """What each page of `pages` is made of, for telling the next build's changes from it."""
    return {
        page: PageFingerprint(
            _sha256(pages[page]),
            _frame_sha256(frame, page),
            tuple(
                BlockFingerprint(block.path, anchor, block.kind, _sha256(body))
                for block in _in_page_order(blocks, page)
                for anchor, body in _anchored_bodies(frame, block)
            ),
        )
        for page in PAGES
    }


def _frame_sha256(frame: Frame, page: str) -> str:
    """The skeleton with no block in it, with the templates its table of contents is filled by."""
    entries = (frame.templates[name] for name in TOC_TEMPLATES)
    return _sha256("\0".join((_page(frame, page, []), *entries)))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _anchored_bodies(frame: Frame, block: Block) -> list[tuple[str, str]]:
    """A general block's headings each on their own, any other block as a whole."""
    if block.kind is BlockKind.GENERAL:
        return [
            (heading.id, _fill_heading(frame, "general", heading))
            for heading in block.parsed.headings
        ]
    return [(_anchor(block), _render(frame, block).body)]


@dataclass(frozen=True)
class _Owner:
    """What owns an id: the frame or a block file, and the unit that block belongs to."""

    name: str
    unit: str | None  # a service's or app's anchor; None for the frame and the general part


@dataclass(frozen=True)
class _Rendered:
    body: str
    toc: str


def _in_page_order(blocks: Sequence[Block], page: str) -> list[Block]:
    """The general part, then the services and the apps, each group by anchor."""
    on_page = (block for block in blocks if block.page == page)
    return sorted(on_page, key=lambda block: (list(BlockKind).index(block.kind), _anchor(block)))


def _anchor(block: Block) -> str:
    return "" if block.kind is BlockKind.GENERAL else block.parsed.headings[0].id


def _owner_of(block: Block) -> _Owner:
    return _Owner(block.path, None if block.kind is BlockKind.GENERAL else _anchor(block))


def _fill(text: str, path: str, **fields: str) -> str:
    try:
        return Template(text).substitute(fields)
    except KeyError as error:
        raise LegalError(f"{path}: unknown field ${error.args[0]}") from error
    except ValueError as error:
        raise LegalError(f"{path}: a $ that starts no field") from error


def _heading_fields(heading: Heading, subs: str = "") -> dict[str, str]:
    return {"id": heading.id, "title": heading.title, "content": heading.content, "subs": subs}


def _fill_heading(frame: Frame, name: str, heading: Heading, subs: str = "") -> str:
    return _fill(frame.templates[name], frame_template_path(name), **_heading_fields(heading, subs))


def _render(frame: Frame, block: Block) -> _Rendered:
    def fill(name: str, heading: Heading, subs: str = "") -> str:
        return _fill_heading(frame, name, heading, subs)

    parsed = block.parsed
    if block.kind is BlockKind.GENERAL:
        return _Rendered(
            "".join(fill("general", heading) for heading in parsed.headings),
            "".join(fill("toc-entry", heading) for heading in parsed.headings),
        )
    heading = parsed.headings[0]
    body = fill(
        block.kind.value, heading, "".join(fill("app-section", s) for s in parsed.subsections)
    )
    entries = "".join(fill("toc-entry", subsection) for subsection in parsed.subsections)
    toc = fill("toc-entry-with-sections" if parsed.subsections else "toc-entry", heading, entries)
    return _Rendered(body, toc)


def _page(frame: Frame, page: str, rendered: Sequence[tuple[Block, _Rendered]]) -> str:
    def joined(kind: BlockKind, part: str) -> str:
        return "".join(getattr(one, part) for block, one in rendered if block.kind is kind)

    stand = _german(max(block.date for block, _ in rendered)) if rendered else ""
    return _fill(
        frame.pages[page],
        frame_page_path(page),
        general=joined(BlockKind.GENERAL, "body"),
        services=joined(BlockKind.SERVICE, "body"),
        apps=joined(BlockKind.APP, "body"),
        toc_general=joined(BlockKind.GENERAL, "toc"),
        toc_services=joined(BlockKind.SERVICE, "toc"),
        toc_apps=joined(BlockKind.APP, "toc"),
        stand=stand,
    )


def _owners_of_ids(
    frame: Frame, page: str, rendered: Sequence[tuple[Block, _Rendered]]
) -> dict[str, _Owner]:
    """Every id of the assembled page with its owner (the frame or a block file); a clash raises."""
    owners = dict.fromkeys(_ids(_page(frame, page, [])), _Owner(FRAME_OWNER, None))
    for block, one in rendered:
        for identifier in _ids(one.body):
            if identifier in owners:
                line = _heading_line(block, identifier)
                raise refusal(
                    block.path,
                    line,
                    f'id "{identifier}" is already used by {owners[identifier].name}',
                )
            owners[identifier] = _owner_of(block)
    return owners


def _ids(markup: str) -> list[str]:
    return _ID_ATTRIBUTE.findall(markup)


def _heading_line(block: Block, identifier: str) -> int | None:
    for heading in (*block.parsed.headings, *block.parsed.subsections):
        if heading.id == identifier:
            return heading.line
    return None


def _check_links(block: Block, owners: Mapping[str, Mapping[str, _Owner]]) -> None:
    """A text links the ids of its own file or unit and the stable ids; each target must exist."""
    mine = _owner_of(block)
    for link in block.parsed.links:
        page = link.page or block.page
        owner = owners[page].get(link.fragment)
        own = owner is not None and (
            owner.name == mine.name or (mine.unit is not None and owner.unit == mine.unit)
        )
        if not own and link.fragment not in STABLE_IDS[page]:
            whose = f" (an id of {owner.name})" if owner else ""
            raise refusal(
                block.path,
                link.line,
                f"link to #{link.fragment} on /{page}{whose} is not allowed "
                "(ids of its own unit and the stable ids only)",
            )
        if owner is None:
            raise refusal(
                block.path, link.line, f"link to #{link.fragment} has no target on /{page}"
            )


def _german(day: date) -> str:
    return f"{day.day}. {_MONTHS[day.month - 1]} {day.year}"
