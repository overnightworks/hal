"""`hal apply --local` builds an app's legal block from the app's own release, read at its sha
(#110 B2): the planned release of an enabled app, the settled one, or the one a stopped or
disabled app last deployed. The real origin and scripted Docker of `tests/support/app_support.py`
beside the legal unit of `tests/support/stack_apps.py`."""

import json
import shutil

import pytest
import support.stack_apply_apps as stack_apply_apps_support
import support.stack_apps as stack_apps_support
from support.app_support import KEY
from support.git_support import plain_git
from support.stack_apply import (
    at_terminal,  # noqa: F401 the fixture, requested by name below
    home,  # noqa: F401 the fixture, requested by name below
    ingress,  # noqa: F401 the fixture, requested by name below
    realm_backup,  # noqa: F401 the fixture, requested by name below
    repository,  # noqa: F401 the fixture, requested by name below
    scripted,  # noqa: F401 the fixture, requested by name below
    scripted_git,  # noqa: F401 the fixture, requested by name below
    setup_check,  # noqa: F401 the fixture, requested by name below
    setup_run,  # noqa: F401 the fixture, requested by name below
    state,  # noqa: F401 the fixture, requested by name below
    switch,  # noqa: F401 the fixture, requested by name below
)
from support.stack_apps import (
    FIRST,
    PRIVACY_FILE,
    SECOND,
    LegalApps,
)
from support.stack_plan_rows import detail_lines, find_row, plain

from hal.stack.legal_section import MAXIMUM_BYTES
from hal.stack.plan_rows import LegalEvent

app_world = stack_apply_apps_support.app_world
legal_apps = stack_apps_support.legal_apps

HEADING = f'<h2 id="{KEY}">Hopin</h2>\n'
TEXT = "<p>Hopin speichert Start und Ziel deiner Fahrt.</p>\n"
CHANGED_TEXT = "<p>Hopin speichert keine Fahrt mehr.</p>\n"
PRIVACY, CHANGED = HEADING + TEXT, HEADING + CHANGED_TEXT
BLOCK = f'id="{KEY}"'


def deployed_tag(world: LegalApps) -> str:
    return json.loads((world.world.state / "deployed" / KEY).read_text())["tag"]


def block_lines(out: str) -> list[str]:
    """The plan's lines under an edited page that name the app's block."""
    return [line for line in detail_lines(out) if f"#{KEY} " in line]


def test_an_enabled_apps_privacy_file_at_its_planned_tag_is_its_block_named_with_the_tag(
    legal_apps,
):
    """M1, L1, L3, L6."""
    legal_apps.release(FIRST, PRIVACY)
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 0, err
    [line] = block_lines(out)
    assert PRIVACY_FILE in line
    assert "new" in line
    assert FIRST in line
    assert TEXT in legal_apps.page()


def test_a_first_build_names_the_app_block_with_its_tag_before_the_question(legal_apps):
    """M1, L3: a page that is built for the first time names the text it first publishes."""
    for built in (legal_apps.world.repository / "legal/built").glob("*.html"):
        built.unlink()
    legal_apps.release(FIRST, PRIVACY)
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert find_row(out, "legal", LegalEvent.NEW_PAGE)
    [line] = block_lines(out)
    assert PRIVACY_FILE in line
    assert FIRST in line


def test_a_new_tag_with_the_same_privacy_file_changes_no_page(legal_apps):
    """M2, head decision 3."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.release(SECOND)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert deployed_tag(legal_apps) == SECOND
    assert not find_row(out, "legal", LegalEvent.EDITED_PAGE)
    assert block_lines(out) == []


def test_a_privacy_file_changed_at_a_new_tag_is_named_with_it_and_live_before_the_app_runs(
    legal_apps,
):
    """M3, L3: the pages are written before the apps, so a new tag that fails leaves its text
    live while the old version runs."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.release(SECOND, CHANGED)
    legal_apps.world.docker.failing_verb = "build"

    exit_code, out, _ = legal_apps.world.apply()

    assert exit_code == 1
    [line] = block_lines(out)
    assert "changed" in line
    assert SECOND in line
    assert CHANGED_TEXT in legal_apps.page()
    assert deployed_tag(legal_apps) == FIRST


def test_a_settled_app_has_its_block_from_the_sha_it_runs(legal_apps):
    """M4."""
    legal_apps.deploy(FIRST, PRIVACY)
    (legal_apps.world.repository / "legal/built/datenschutz.html").unlink()
    legal_apps.world.docker.calls.clear()

    exit_code, _, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert "create" not in legal_apps.world.docker.verbs
    assert TEXT in legal_apps.page()


def test_a_stopped_app_keeps_its_block_from_its_recorded_sha(legal_apps):
    """M5, L5."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.stop()

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert not find_row(out, "legal", LegalEvent.EDITED_PAGE)
    assert TEXT in legal_apps.page()


def test_a_stopped_app_never_deployed_has_no_block(legal_apps):
    """M6, L5."""
    legal_apps.release(FIRST, PRIVACY)
    legal_apps.catalog(enabled=True)
    legal_apps.stop()

    exit_code, _, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert BLOCK not in legal_apps.page()


def test_a_disabled_app_with_a_record_keeps_its_block(legal_apps):
    """M7, L4b."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.catalog(enabled=False)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert legal_apps.world.docker.rows == []
    assert not find_row(out, "legal", LegalEvent.EDITED_PAGE)
    assert TEXT in legal_apps.page()


TERMS_FILE = "legal/nutzungsbedingungen.html"
TERMS = f'<h2 id="{KEY}">Hopin</h2>\n<p>Die Nutzung ist frei.</p>\n'


@pytest.mark.parametrize(
    "files", [{}, {TERMS_FILE: TERMS}], ids=["no legal file", "terms without privacy"]
)
def test_a_release_without_a_privacy_file_has_no_block_and_is_no_refusal(legal_apps, files):
    """M8, head decision 4: before C, a release has either the whole block or none."""
    legal_apps.origin.release(FIRST, {"release": FIRST, **files})
    legal_apps.catalog(enabled=True)

    exit_code, _, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert deployed_tag(legal_apps) == FIRST
    assert BLOCK not in legal_apps.page()
    assert BLOCK not in legal_apps.page("nutzungsbedingungen")


def test_an_invalid_terms_file_refuses_the_run_even_without_a_privacy_file(legal_apps):
    """M9, L11: a broken file never waits silently."""
    broken = f'<h2 id="{KEY}">Hopin</h2>\n<script>x</script>\n'
    legal_apps.origin.release(FIRST, {"release": FIRST, TERMS_FILE: broken})
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert TERMS_FILE in err
    assert "Type yes" not in plain(out)


@pytest.mark.parametrize(
    ("privacy", "rule"),
    [
        (f'<h2 id="{KEY}">Hopin</h2>\n<script>x</script>\n', "<script>"),
        (
            f'<h2 id="{KEY}">Hopin</h2>\n<section id="andere-daten">\n<h3>Daten</h3>\n'
            "<p>Text</p>\n</section>\n",
            f'"{KEY}-"',
        ),
        (PRIVACY + "<p>" + "a" * MAXIMUM_BYTES + "</p>\n", str(MAXIMUM_BYTES)),
    ],
    ids=["script", "id outside the key", "over 64 KiB"],
)
def test_an_invalid_privacy_file_refuses_the_run_before_the_question(legal_apps, privacy, rule):
    """M9, L6, L11, L14."""
    legal_apps.release(FIRST, privacy)
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert PRIVACY_FILE in err
    assert rule in err
    assert "Type yes" not in plain(out)
    assert not (legal_apps.world.state / "deployed" / KEY).exists()
    assert BLOCK not in legal_apps.page()


def test_a_symlink_at_the_privacy_file_refuses_the_run_and_is_not_read_as_absent(legal_apps):
    """M10."""
    work = legal_apps.origin.work
    (work / PRIVACY_FILE).parent.mkdir()
    (work / PRIVACY_FILE).symlink_to("../release")
    legal_apps.release(FIRST)
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert PRIVACY_FILE in err
    assert "symlink" in err
    assert "Type yes" not in plain(out)


def test_a_key_whose_text_edge_and_the_app_both_hold_refuses_naming_both(legal_apps):
    """M11, L8, head decision 1."""
    held = legal_apps.world.repository / "legal/sections" / KEY
    held.mkdir()
    (held / "datenschutz.html").write_text(PRIVACY)
    legal_apps.release(FIRST, PRIVACY)
    legal_apps.catalog(enabled=True)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert f"legal/sections/{KEY}/" in err
    assert f"~/srv/{KEY}/legal/" in err
    assert "Type yes" not in plain(out)


def lose_the_checkout(world: LegalApps) -> None:
    shutil.rmtree(world.world.srv)


def lose_the_recorded_commit(world: LegalApps) -> None:
    record = world.world.state / "deployed" / KEY
    fields = json.loads(record.read_text())
    record.write_text(json.dumps(fields | {"sha": "1" * 40}))


@pytest.mark.parametrize("lose", [lose_the_checkout, lose_the_recorded_commit])
def test_a_stopped_app_whose_recorded_release_cannot_be_read_refuses_naming_the_path(
    legal_apps, lose
):
    """M12, L5, head decision 2."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.stop()
    lose(legal_apps)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert f"~/srv/{KEY}" in err
    assert "Type yes" not in plain(out)
    assert TEXT in legal_apps.page()


def test_a_stopped_app_whose_git_directory_is_invalid_refuses_even_under_a_parent_repository(
    legal_apps,
):
    """M12, head decision 2: git must not discover the repository above the checkout."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.stop()
    checkout, parent = legal_apps.world.srv, legal_apps.world.srv.parent
    plain_git(parent, "init", "--quiet")
    plain_git(parent, "fetch", "--quiet", legal_apps.origin.bare.as_uri(), "master")
    shutil.rmtree(checkout / ".git")
    (checkout / ".git").mkdir()

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert f"~/srv/{KEY}" in err
    assert "Type yes" not in plain(out)


def test_a_stopped_app_whose_git_directory_is_a_symlink_refuses_naming_the_path(legal_apps):
    """M12, head decision 2."""
    legal_apps.deploy(FIRST, PRIVACY)
    legal_apps.stop()
    git_directory = legal_apps.world.srv / ".git"
    moved = legal_apps.world.srv.parent / "moved.git"
    git_directory.rename(moved)
    git_directory.symlink_to(moved)

    exit_code, out, err = legal_apps.world.apply()

    assert exit_code == 2
    assert f"~/srv/{KEY}" in err
    assert "Type yes" not in plain(out)


def test_the_stand_is_the_newest_commit_date_over_every_section_the_apps_included(legal_apps):
    """M13, L12."""
    legal_apps.dated_release(FIRST, PRIVACY, "2031-05-06T12:00:00+00:00")
    legal_apps.catalog(enabled=True)

    exit_code, _, err = legal_apps.world.apply()

    assert exit_code == 0, err
    assert '<p class="stand">Stand: 6. Mai 2031</p>' in legal_apps.page()


def test_every_block_of_an_apps_section_is_published_byte_for_byte(legal_apps):
    """M14, L14: the frame renders the headings and the section tags; every block inside them
    stands unchanged."""
    blocks = [
        "<p>Start, Ziel &amp; Uhrzeit <strong>deiner</strong> Fahrt,\n  über zwei Zeilen.</p>\n",
        "<ul>\n  <li>Start</li>\n  <li>Ziel <em>und</em> Zeit</li>\n</ul>\n",
        "<ol>\n<li>Eins</li>\n<li><code>zwei</code></li>\n</ol>\n",
    ]
    inner = [
        "<p>Gespeichert, bis die Fahrt endet.<br>\nDanach gelöscht.</p>\n",
        '<p><a href="https://example.org/a?b=1&amp;c=2">Mehr</a></p>\n',
    ]
    subsection = f'<section id="{KEY}-daten">\n<h3>Welche Daten</h3>\n{"".join(inner)}</section>\n'
    legal_apps.release(FIRST, HEADING + "".join(blocks) + subsection)
    legal_apps.catalog(enabled=True)

    exit_code, _, err = legal_apps.world.apply()

    assert exit_code == 0, err
    built = legal_apps.page()
    assert [block for block in (*blocks, *inner) if block not in built] == []
