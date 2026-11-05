"""The assembly of the legal pages (#435): order, table of contents, ids, links and the Stand,
from a small frame of the tests' own and sections they parse."""

import itertools
import re
from datetime import date

import pytest

from hal.stack.legal_pages import TEMPLATES, Block, BlockKind, Frame, build_pages
from hal.stack.legal_section import LegalError, parse_fragment, parse_general

ZONE = "edge-fixture.invalid"
TEXT_PAGE = (
    '<h1 id="inhalt">T</h1>[toc $toc_general|$toc_services|$toc_apps]'
    "[body $general|$services|$apps]<p>Stand: $stand</p>"
)
FRAME = Frame(
    pages={
        "impressum": '<h2 id="verantwortlich">V</h2><h2 id="kontakt">K</h2>',
        "datenschutz": TEXT_PAGE,
        "nutzungsbedingungen": TEXT_PAGE,
    },
    templates={
        "general": '<h2 id="$id">$title</h2>$content',
        "service": '<h2 id="$id">$title</h2>$content$subs',
        "app": '<section id="$id"><h2>$title</h2>$content$subs</section>',
        "app-section": '<h3 id="$id">$title</h3>$content',
        "toc-entry": "<li>$title</li>",
        "toc-entry-with-sections": "<li>$title<ol>$subs</ol></li>",
    },
)


def block(
    kind: BlockKind,
    text: str,
    anchor: str = "",
    page: str = "datenschutz",
    day: date = date(2026, 10, 1),
) -> Block:
    path = f"legal/sections/{anchor or 'allgemein'}/{page}.html"
    if kind is BlockKind.GENERAL:
        parsed = parse_general(path, text.encode(), ZONE)
    else:
        parsed = parse_fragment(path, text.encode(), anchor, ZONE)
    return Block(path, page, kind, parsed, day)


def general(text: str = '<h2 id="recht">Recht</h2>\n<p>a</p>\n', **kwargs) -> Block:
    return block(BlockKind.GENERAL, text, **kwargs)


def app(anchor: str, body: str = "<p>a</p>\n", sections: str = "", **kwargs) -> Block:
    text = f'<h2 id="{anchor}">{anchor.title()}</h2>\n{body}{sections}'
    return block(BlockKind.APP, text, anchor, **kwargs)


def service(anchor: str, **kwargs) -> Block:
    text = f'<h2 id="{anchor}">{anchor.title()}</h2>\n<p>s</p>\n'
    return block(BlockKind.SERVICE, text, anchor, **kwargs)


def built(blocks: list[Block], page: str = "datenschutz") -> str:
    return build_pages(FRAME, blocks)[page]


def refusal(blocks: list[Block]) -> str:
    with pytest.raises(LegalError) as refused:
        build_pages(FRAME, blocks)
    return str(refused.value)


SECTIONS = '<section id="zeta-eins">\n<h3>Eins</h3>\n<p>x</p>\n</section>\n'


def test_the_groups_stand_where_the_frame_puts_them_and_each_group_is_sorted_by_anchor():
    """L6."""
    blocks = [app("zeta"), service("anmeldung"), app("alpha"), general(), service("agent-dienst")]

    page = built(blocks)

    assert re.search(
        r"\[body <h2 id=\"recht\">Recht</h2>\n<p>a</p>\n"
        r"\|<h2 id=\"agent-dienst\">.*<h2 id=\"anmeldung\">.*"
        r"\|<section id=\"alpha\">.*<section id=\"zeta\">.*\]",
        page,
        re.DOTALL,
    )


def test_the_build_is_the_same_for_every_order_of_the_blocks():
    """L14."""
    blocks = [
        general(),
        service("anmeldung"),
        service("agent-dienst"),
        app("alpha"),
        app("zeta", sections=SECTIONS),
    ]

    pages = {
        tuple(build_pages(FRAME, list(order)).items()) for order in itertools.permutations(blocks)
    }

    assert len(pages) == 1


def test_the_general_part_keeps_the_files_order_of_its_headings():
    """L14."""
    text = '<h2 id="zebra">Z</h2>\n<p>z</p>\n<h2 id="apfel">A</h2>\n<p>a</p>\n'

    page = built([general(text)])

    assert page.index('id="zebra"') < page.index('id="apfel"')


def test_an_app_with_sections_gets_a_nested_table_of_contents_entry_and_one_without_a_plain_one():
    """L6."""
    page = built([general(), app("alpha"), app("zeta", sections=SECTIONS)])

    assert "[toc <li>Recht</li>||<li>Alpha</li><li>Zeta<ol><li>Eins</li></ol></li>]" in page
    assert (
        '<section id="zeta"><h2>Zeta</h2>\n<p>a</p>\n<h3 id="zeta-eins">Eins</h3>\n<p>x</p>\n'
        in page
    )


def test_a_group_without_blocks_emits_nothing():
    """L14."""
    assert '[body <h2 id="recht">Recht</h2>\n<p>a</p>\n||]' in built([general()])


def test_stand_is_the_newest_date_of_the_pages_sections_in_german():
    """L12."""
    blocks = [
        general(day=date(2026, 3, 9)),
        app("alpha", day=date(2026, 10, 27)),
        app("zeta", day=date(2025, 12, 31)),
    ]

    assert "<p>Stand: 27. Oktober 2026</p>" in built(blocks)


def test_stand_of_a_page_counts_only_the_sections_of_that_page():
    """L12."""
    pages = build_pages(
        FRAME,
        [
            general(day=date(2026, 1, 2)),
            general(
                '<h2 id="recht">Recht</h2>\n<p>a</p>\n',
                page="nutzungsbedingungen",
                day=date(2026, 3, 4),
            ),
        ],
    )

    assert "Stand: 2. Januar 2026" in pages["datenschutz"]
    assert "Stand: 4. März 2026" in pages["nutzungsbedingungen"]


def test_a_heading_title_with_escaped_text_is_published_as_the_files_bytes():
    """L7, L14."""
    sections = '<section id="zeta-eins">\n<h3>T &lt;b&gt;</h3>\n<p>x</p>\n</section>\n'
    text = f'<h2 id="zeta">A &lt;img src=x&gt; &amp; B</h2>\n<p>a</p>\n{sections}'

    page = built([block(BlockKind.APP, text, "zeta")])

    assert "<h2>A &lt;img src=x&gt; &amp; B</h2>" in page
    assert "<li>A &lt;img src=x&gt; &amp; B<ol><li>T &lt;b&gt;</li></ol></li>" in page
    assert "<img" not in page


def test_the_imprint_is_the_frame_as_it_is():
    """L14."""
    assert built([general()], "impressum") == FRAME.pages["impressum"]


def test_an_id_used_by_two_blocks_is_refused_naming_both_files():
    """L6."""
    other = general('<h2 id="alpha">A</h2>\n<p>a</p>\n')

    message = refusal([other, app("alpha")])

    assert message == (
        'legal: legal/sections/alpha/datenschutz.html: line 1: id "alpha" is already used by '
        "legal/sections/allgemein/datenschutz.html"
    )


def test_an_id_of_the_frame_cannot_be_taken_by_a_block():
    """L6."""
    message = refusal([general('<h2 id="inhalt">I</h2>\n<p>a</p>\n')])

    assert message.endswith('id "inhalt" is already used by frame')


def test_a_subsection_id_that_is_also_a_heading_of_the_general_part_is_refused():
    """L6."""
    clash = general('<h2 id="zeta-eins">E</h2>\n<p>a</p>\n')

    assert 'id "zeta-eins" is already used by' in refusal([clash, app("zeta", sections=SECTIONS)])


@pytest.mark.parametrize(
    "link",
    ["#alpha", "#alpha-eins", "/datenschutz#alpha", "/nutzungsbedingungen"],
)
def test_a_text_may_link_its_own_ids_and_the_pages(link):
    """L13."""
    sections = '<section id="alpha-eins">\n<h3>Eins</h3>\n<p>x</p>\n</section>\n'
    linking = app("alpha", body=f'<p><a href="{link}">l</a></p>\n', sections=sections)

    assert built([general(), linking])


def test_a_text_may_link_a_stable_id_of_another_block_while_its_target_exists():
    """L13."""
    linking = app("alpha", body='<p><a href="#anmeldung">l</a></p>\n')

    assert built([general(), service("anmeldung"), linking])


def test_a_link_to_a_stable_id_whose_block_left_refuses_the_run():
    """L13."""
    linking = app("alpha", body='<p><a href="#anmeldung">l</a></p>\n')

    assert refusal([general(), linking]).endswith(
        "link to #anmeldung has no target on /datenschutz"
    )


def test_a_link_to_another_apps_id_is_refused_naming_its_owner():
    """L13."""
    linking = app("alpha", body='<p><a href="#zeta-eins">l</a></p>\n')

    message = refusal([general(), linking, app("zeta", sections=SECTIONS)])

    assert message == (
        "legal: legal/sections/alpha/datenschutz.html: line 2: link to #zeta-eins on /datenschutz "
        "(an id of legal/sections/zeta/datenschutz.html) is not allowed "
        "(ids of its own unit and the stable ids only)"
    )


@pytest.mark.parametrize("link", ["/datenschutz#alpha", "/datenschutz#alpha-eins"])
def test_an_apps_terms_may_link_the_ids_of_its_own_privacy_part(link):
    """L13."""
    sections = '<section id="alpha-eins">\n<h3>Eins</h3>\n<p>x</p>\n</section>\n'
    terms = app("alpha", body=f'<p><a href="{link}">l</a></p>\n', page="nutzungsbedingungen")
    privacy = app("alpha", sections=sections)

    assert build_pages(FRAME, [general(), privacy, terms])


@pytest.mark.parametrize(
    ("target", "other_blocks"),
    [
        ("/datenschutz#zeta-eins", [app("zeta", sections=SECTIONS)]),
        ("/datenschutz#recht", []),
    ],
    ids=["another apps id", "a central id that is not stable"],
)
def test_an_apps_terms_may_not_link_the_ids_of_another_part_than_its_own(target, other_blocks):
    """L13."""
    terms = app("alpha", body=f'<p><a href="{target}">l</a></p>\n', page="nutzungsbedingungen")

    assert "is not allowed" in refusal([general(), *other_blocks, app("alpha"), terms])


def test_a_link_to_an_unknown_id_is_refused():
    """L13."""
    linking = app("alpha", body='<p><a href="/datenschutz#nirgends">l</a></p>\n')

    assert "link to #nirgends on /datenschutz is not allowed" in refusal([general(), linking])


def test_a_terms_text_may_link_a_stable_id_of_the_privacy_page():
    """L13."""
    terms = app(
        "alpha",
        body='<p><a href="/datenschutz#anmeldung">l</a></p>\n',
        page="nutzungsbedingungen",
    )

    assert build_pages(FRAME, [general(), service("anmeldung"), terms])


def test_a_link_to_the_imprints_stable_ids_resolves_through_the_frame():
    """L13."""
    linking = app("alpha", body='<p><a href="/impressum#kontakt">l</a></p>\n')

    assert built([general(), linking])


@pytest.mark.parametrize("name", TEMPLATES)
def test_a_template_with_an_unknown_field_is_refused_naming_its_file(name):
    """L14."""
    templates = {**FRAME.templates, name: FRAME.templates[name] + "$unknown"}
    blocks = [general(), service("anmeldung"), app("zeta", sections=SECTIONS)]

    frame = Frame(FRAME.pages, templates)

    with pytest.raises(LegalError) as refused:
        build_pages(frame, blocks)

    assert str(refused.value) == f"legal: legal/frame/blocks/{name}.html: unknown field $unknown"


def test_a_template_with_a_stray_dollar_sign_is_refused():
    """L14."""
    templates = {**FRAME.templates, "general": "cost $ 5"}

    frame = Frame(FRAME.pages, templates)
    blocks = [general()]

    with pytest.raises(LegalError, match=r"legal/frame/blocks/general.html: a \$ that starts no"):
        build_pages(frame, blocks)
