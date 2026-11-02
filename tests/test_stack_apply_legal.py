"""`hal apply --local` with the legal step (#435): the three pages built from the repository's own
frame and sections on the scripted boundaries of `tests/support/stack_apply.py`, in a real git
repository (the Stand of a page is a commit date)."""

import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import pytest
from support.git_support import committed_main
from support.stack_apply import (
    REPOSITORY,
    ZONE,
    applied_core,  # noqa: F401 the fixture, requested by name below
    at_terminal,  # noqa: F401 the fixture, requested by name below
    core_files,  # noqa: F401 the fixture, requested by name below
    edit_traefik_yml,
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
    switch_off,
    unreadable_profile_bind,  # noqa: F401 the fixture, requested by name below
    write_fleet,
)
from support.stack_apply_fakes import (
    ScriptedCompose,
)
from support.stack_plan_rows import detail_lines, find_row, plain, row_at

from hal.stack import apply, appkit_step
from hal.stack.legal_step import RECORD_FILE
from hal.stack.plan_rows import LegalEvent
from hal.stack.result_rows import ResultEvent

FLEET = (
    f"cloudflare:\n  zone: {ZONE}\nservices:\n"
    "  legal:\n    run: {enabled: true}\n"
    "  agent-service:\n    run: {enabled: false, setup: agent-service/setup}\n"
)
WITHOUT_AGENT = FLEET.split("  agent-service:")[0]
THE_PAGES = [".gitkeep", "datenschutz.html", "impressum.html", "nutzungsbedingungen.html"]
PRIVACY = "legal/sections/allgemein/datenschutz.html"
AGENT = "legal/sections/agent-service/datenschutz.html"
NEW_HEADING = b'<h2 id="neu">Neu</h2>\n<p>Text</p>\n'


@dataclass
class World:
    """A tree with the legal unit enabled, and how to run `hal apply --local` on it."""

    repository: Path
    scripted: ScriptedCompose
    switch: Callable[..., tuple[int, str, str]]
    state: Path

    @property
    def built(self) -> Path:
        return self.repository / "legal/built"

    def built_names(self) -> list[str]:
        return sorted(path.name for path in self.built.iterdir())

    def built_page(self, name: str) -> str:
        return (self.built / f"{name}.html").read_text()

    def edit(self, path: str, change: Callable[[bytes], bytes]) -> None:
        file = self.repository / path
        file.write_bytes(change(file.read_bytes()))


@pytest.fixture
def world(repository: Path, scripted: ScriptedCompose, switch, state: Path) -> World:  # noqa: F811
    """The repository's own frame, general part and agent service block (a catalog entry,
    disabled) and its Songmaker text (no catalog entry), committed, with an empty `legal/built`."""
    legal = repository / "legal"
    shutil.copytree(REPOSITORY / "legal/frame", legal / "frame")
    for unit in ("allgemein", "agent-service", "songmaker"):
        shutil.copytree(REPOSITORY / "legal/sections" / unit, legal / "sections" / unit)
    (legal / "built").mkdir()
    (legal / "built/.gitkeep").touch()
    write_fleet(repository, FLEET)
    scripted.config["services"]["legal"] = {
        "image": "nginxinc/nginx-unprivileged:test",
        "restart": "unless-stopped",
        "profiles": ["legal"],
    }
    scripted.config["services"]["agent-service"] = {
        "image": "agent-service:test",
        "restart": "unless-stopped",
        "profiles": ["agent-service"],
    }
    shutil.rmtree(repository / ".git")
    committed_main(repository)
    return World(repository, scripted, switch, state)


@pytest.fixture
def private_umask():
    previous = os.umask(0o077)
    yield
    os.umask(previous)


@pytest.mark.usefixtures("private_umask")
def test_the_first_apply_names_and_writes_the_three_pages_readable_by_the_unit(world):
    """L3."""
    exit_code, out, err = world.switch()

    assert exit_code == 0, err
    assert find_row(
        out, "legal", LegalEvent.NEW_PAGE, "impressum, datenschutz, nutzungsbedingungen"
    )
    assert re.search(r"^  \+ legal +3 new pages ", plain(out), re.MULTILINE)
    assert detail_lines(out) == []
    assert find_row(
        out, "legal", ResultEvent.PAGES_WRITTEN, "impressum, datenschutz, nutzungsbedingungen"
    )
    assert not find_row(out, "legal", ResultEvent.RECORD_WRITTEN)
    assert world.built_names() == THE_PAGES
    for name in THE_PAGES[1:]:
        assert stat.S_IMODE((world.built / name).stat().st_mode) == 0o644
    privacy = world.built_page("datenschutz")
    assert 'id="agent-dienst"' in privacy
    assert 'id="songmaker"' not in privacy
    assert re.search(r'<p class="stand">Stand: \d{1,2}\. [A-Za-zä]+ 20\d\d</p>', privacy)


def test_the_second_apply_changes_nothing_and_says_so(world):
    """L3."""
    world.switch()
    world.scripted.calls.clear()

    exit_code, out, _ = world.switch(answer="no")

    assert exit_code == 0
    assert not re.search(r"^  \S legal\b", plain(out), re.MULTILINE)
    assert "nothing to change" in out
    assert world.scripted.changing_verbs() == []


def test_a_changed_text_goes_live_only_after_yes_and_the_plan_names_its_page(world):
    """L3."""
    world.switch()
    world.edit(PRIVACY, lambda text: text + NEW_HEADING)

    declined_exit, declined_out, _ = world.switch(answer="no")

    assert declined_exit == apply.ApplyExit.DECLINED
    assert find_row(declined_out, "legal", LegalEvent.EDITED_PAGE, "datenschutz")
    assert "nutzungsbedingungen" not in declined_out
    assert 'id="neu"' not in world.built_page("datenschutz")

    exit_code, out, _ = world.switch()

    assert exit_code == 0
    assert find_row(out, "legal", LegalEvent.EDITED_PAGE, "datenschutz")
    assert 'id="neu"' in world.built_page("datenschutz")


def test_the_plan_names_the_block_whose_text_changed_and_no_other(world):
    """L3."""
    world.switch()
    world.edit(AGENT, lambda text: text + b"<p>Neu</p>\n")

    _, out, _ = world.switch(answer="no")

    assert find_row(out, "legal", LegalEvent.EDITED_PAGE, "datenschutz")
    assert detail_lines(out) == [f"{AGENT}#agent-dienst changed"]


def test_the_plan_names_a_block_whose_title_was_only_shortened(world):
    """L3."""
    terms = "legal/sections/allgemein/nutzungsbedingungen.html"
    world.switch()
    world.edit(terms, lambda text: text.replace(b"Anwendbares Recht", b"Recht", 1))

    _, out, _ = world.switch(answer="no")

    assert find_row(out, "legal", LegalEvent.EDITED_PAGE, "nutzungsbedingungen")
    assert detail_lines(out) == [f"{terms}#recht changed"]


def test_the_plan_names_a_general_block_whose_final_paragraph_was_removed(world):
    """L3."""
    terms = "legal/sections/allgemein/nutzungsbedingungen.html"
    world.switch()
    world.edit(terms, lambda text: text + b"<p>Zusatz.</p>\n")
    world.switch()
    world.edit(terms, lambda text: text.replace(b"<p>Zusatz.</p>\n", b""))

    _, out, _ = world.switch(answer="no")

    assert detail_lines(out) == [f"{terms}#recht changed"]


def test_the_plan_names_a_general_block_whose_final_heading_was_removed(world):
    """L3."""

    def without_final_heading(text: bytes) -> bytes:
        return text[: text.rindex(b"<h2 ")]

    world.switch()
    world.edit(PRIVACY, without_final_heading)

    _, out, _ = world.switch(answer="no")

    [line] = detail_lines(out)
    assert re.fullmatch(rf"{PRIVACY}#[a-z-]+ left", line)


def test_a_block_whose_catalog_entry_left_leaves_the_page(world):
    """L3."""
    world.switch()
    assert 'id="agent-dienst"' in world.built_page("datenschutz")
    write_fleet(world.repository, WITHOUT_AGENT)

    exit_code, out, _ = world.switch()

    assert exit_code == 0
    assert find_row(out, "legal", LegalEvent.EDITED_PAGE, "datenschutz")
    assert 'id="agent-dienst"' not in world.built_page("datenschutz")


def test_the_plan_names_a_block_that_left_and_no_other(world):
    """L3."""
    world.switch()
    write_fleet(world.repository, WITHOUT_AGENT)

    _, out, _ = world.switch(answer="no")

    assert detail_lines(out) == [f"{AGENT}#agent-dienst left"]


def test_the_plan_names_a_changed_frame_and_no_block(world):
    """L3."""
    world.switch()
    world.edit("legal/frame/datenschutz.html", lambda text: text + b"<!-- frame -->\n")

    _, out, _ = world.switch(answer="no")

    assert detail_lines(out) == ["legal/frame/datenschutz.html changed"]
    assert "legal/sections/" not in out


@pytest.mark.parametrize("record", [None, b"{not json"], ids=["missing", "unreadable"])
def test_without_a_usable_record_the_plan_names_every_block_as_new(world, record):
    """L3."""
    world.switch()
    record_file = world.state / "legal-built.json"
    record_file.unlink()
    if record is not None:
        record_file.write_bytes(record)
    world.edit(AGENT, lambda text: text + b"<p>Neu</p>\n")

    _, out, _ = world.switch(answer="no")

    assert find_row(out, "legal", LegalEvent.EDITED_PAGE, "datenschutz")
    assert find_row(out, "legal", LegalEvent.NEW_RECORD, "impressum, nutzungsbedingungen")
    lines = detail_lines(out)
    assert f"{AGENT}#agent-dienst new" in lines
    assert f"{PRIVACY}#verantwortlicher new" in lines
    assert not any(line.endswith(" changed") for line in lines)


@pytest.mark.parametrize("record", [None, b"{not json"], ids=["missing", "unreadable"])
def test_a_page_that_matches_is_planned_again_when_its_record_is_unusable(world, record):
    """L3."""
    world.switch()
    record_file = world.state / "legal-built.json"
    record_file.unlink()
    if record is not None:
        record_file.write_bytes(record)

    _, out, _ = world.switch(answer="no")
    assert find_row(out, "legal", LegalEvent.NEW_RECORD, "datenschutz")
    assert detail_lines(out) == []

    world.switch()
    _, again, _ = world.switch(answer="no")
    assert not re.search(r"^  \S legal\b", plain(again), re.MULTILINE)
    assert "nothing to change" in again


def test_the_plan_names_a_changed_table_of_contents_template(world):
    """L3."""
    world.switch()
    world.edit(
        "legal/frame/blocks/toc-entry.html", lambda text: text.replace(b"<li", b"<li data-x", 1)
    )

    _, out, _ = world.switch(answer="no")

    assert detail_lines(out) == [
        "legal/frame/datenschutz.html changed",
        "legal/frame/nutzungsbedingungen.html changed",
    ]


def test_a_built_page_edited_by_hand_makes_every_block_of_it_new(world):
    """L3."""
    world.switch()
    page = world.built / "datenschutz.html"
    page.write_text(page.read_text() + "<!-- by hand -->")

    _, out, _ = world.switch(answer="no")

    assert f"{AGENT}#agent-dienst new" in detail_lines(out)


def test_the_record_stays_out_of_the_directory_the_unit_serves(world):
    """L3."""
    world.switch()

    assert (world.state / "legal-built.json").is_file()
    assert world.built_names() == THE_PAGES


def test_the_imprint_plan_line_names_the_page_and_no_block(world):
    """L3."""
    _, out, _ = world.switch(answer="no")

    assert find_row(out, "legal", LegalEvent.NEW_PAGE, "impressum")
    assert detail_lines(out) == []


def test_a_unit_switched_off_by_edge_stop_still_gets_its_pages_written(world):
    """L3."""
    switch_off(world.state, unit="legal")

    exit_code, out, _ = world.switch()

    assert exit_code == 0
    assert find_row(out, "legal", LegalEvent.NEW_PAGE, "datenschutz")
    assert world.built_names() == THE_PAGES


def add_image(text: bytes) -> bytes:
    return text.replace(b"<p>", b'<p><img src="x">', 1)


def grow_beyond_the_limit(text: bytes) -> bytes:
    return text + b"x" * 70_000


def write_a_non_breaking_space(text: bytes) -> bytes:
    return text.replace(b"<p>", b"<p>a&nbsp;", 1)


def link_to_a_missing_id(text: bytes) -> bytes:
    return text.replace(b"<p>", b'<p><a href="#nirgends">x</a>', 1)


def link_to_the_agent_service(text: bytes) -> bytes:
    return text.replace(b"<p>", b'<p><a href="#agent-dienst">Agent</a> ', 1)


@pytest.mark.parametrize(
    ("path", "change", "line"),
    [
        (AGENT, add_image, f"{AGENT}: line 2: <img> is not allowed"),
        (AGENT, grow_beyond_the_limit, f"{AGENT}: is 7"),
        (AGENT, write_a_non_breaking_space, f"{AGENT}: line 2: not in canonical form"),
        (PRIVACY, link_to_a_missing_id, f"{PRIVACY}: line 2: link to #nirgends"),
    ],
)
def test_a_refused_section_stops_the_run_before_the_question_and_writes_nothing(
    world, path, change, line
):
    """L11."""
    world.edit(path, change)

    exit_code, out, err = world.switch()

    assert exit_code == 2
    assert f"cannot plan, legal: {line}" in err
    assert "Type yes" not in plain(out)
    assert world.built_names() == [".gitkeep"]


def test_a_link_to_a_block_that_left_refuses_the_run(world):
    """L13."""
    world.edit(PRIVACY, link_to_the_agent_service)
    assert world.switch(answer="no")[0] == apply.ApplyExit.DECLINED
    write_fleet(world.repository, WITHOUT_AGENT)

    exit_code, _, err = world.switch()

    assert exit_code == 2
    assert (
        f"cannot plan, legal: {PRIVACY}: line 2: "
        "link to #agent-dienst has no target on /datenschutz" in err
    )


@pytest.mark.parametrize(
    ("missing", "what"),
    [(PRIVACY, "the general part"), ("legal/frame/datenschutz.html", "the frame")],
)
def test_a_missing_general_part_or_frame_is_cannot_plan(world, missing, what):
    """L11."""
    (world.repository / missing).unlink()

    exit_code, _, err = world.switch()

    assert exit_code == 2
    assert (
        f"cannot plan, legal: {missing} is missing; {what} is required while services.legal runs"
        in err
    )


@pytest.mark.parametrize("services", ["{}", "\n  legal:\n    run: {enabled: false}"])
def test_without_an_enabled_legal_unit_there_is_no_step_and_no_line(world, services):
    """L3."""
    write_fleet(world.repository, f"cloudflare:\n  zone: {ZONE}\nservices: {services}\n")
    (world.repository / PRIVACY).write_bytes(b"<script>not even read</script>")

    exit_code, out, err = world.switch()

    assert exit_code == 0
    assert "legal" not in out + err
    assert world.built_names() == [".gitkeep"]


def test_the_appkit_row_comes_before_the_legal_row_after_the_yes(world):
    for target in appkit_step.served_directories(world.repository):
        shutil.rmtree(target)

    _, out, _ = world.switch()

    assert row_at(out, "appkit", ResultEvent.FILES_WRITTEN) < row_at(
        out, "legal", ResultEvent.PAGES_WRITTEN
    )


def test_a_page_that_gained_only_its_record_is_named_as_a_record_written(world):
    world.switch()
    (world.state / RECORD_FILE).unlink()

    _, out, _ = world.switch()

    assert find_row(out, "legal", ResultEvent.RECORD_WRITTEN, "impressum")
    assert not find_row(out, "legal", ResultEvent.PAGES_WRITTEN)


def test_a_write_that_fails_is_partial_and_switches_no_unit(world):
    """L3."""
    world.built.chmod(0o500)
    try:
        exit_code, out, err = world.switch()
    finally:
        world.built.chmod(0o700)

    assert exit_code == 1
    assert find_row(
        out,
        "legal",
        ResultEvent.NOT_WRITTEN,
        "could not write legal/built/impressum.html (Permission denied)",
    )
    assert not find_row(out, "legal", ResultEvent.PAGES_WRITTEN)
    assert err.splitlines() == [
        "error: partial, legal not written · no unit switched",
        "next: hal apply",
    ]
    assert world.scripted.changing_verbs() == []


@pytest.mark.parametrize("failing", ["copy", "removal"])
def test_a_failed_appkit_write_stops_the_run_before_legal_writes_anything(world, failing):
    served = appkit_step.served_directories(world.repository)[0]
    if failing == "removal":
        (served.parent / "appkit-0.0.1").mkdir()
    else:
        shutil.rmtree(served)
    served.parent.chmod(0o500)
    try:
        exit_code, out, _ = world.switch()
    finally:
        served.parent.chmod(0o700)

    assert exit_code == 1
    assert find_row(out, "appkit", ResultEvent.NOT_WRITTEN, "could not write ")
    assert not find_row(out, "legal", ResultEvent.PAGES_WRITTEN)
    assert not re.search(r"[✓✗] legal", plain(out))
    assert world.built_names() == [".gitkeep"]
    assert world.scripted.changing_verbs() == []


def test_a_failed_legal_write_keeps_the_appkit_row_that_was_written_before(world):
    for target in appkit_step.served_directories(world.repository):
        shutil.rmtree(target)
    world.built.chmod(0o500)
    try:
        _, out, _ = world.switch()
    finally:
        world.built.chmod(0o700)

    assert find_row(out, "appkit", ResultEvent.FILES_WRITTEN)
    assert find_row(out, "legal", ResultEvent.NOT_WRITTEN)
    assert not re.search(r"✓ legal", plain(out))


def test_a_failed_record_write_names_the_record_and_the_next_apply_writes_it(world):
    record = world.state / RECORD_FILE
    record.mkdir(parents=True)
    exit_code, out, _ = world.switch()
    record.rmdir()

    assert exit_code == 1
    assert find_row(out, "legal", ResultEvent.NOT_WRITTEN, f"could not write {record} (")
    assert not find_row(out, "legal", ResultEvent.PAGES_WRITTEN)
    assert world.scripted.changing_verbs() == []

    _, next_out, _ = world.switch()

    assert find_row(next_out, "legal", ResultEvent.RECORD_WRITTEN)


@pytest.mark.usefixtures("unreadable_profile_bind")
def test_a_core_failure_after_the_write_names_its_own_step_and_never_legal(world):
    """L3."""
    edit_traefik_yml(world.repository)

    exit_code, _, err = world.switch()

    assert exit_code == 1
    assert world.built_names() == THE_PAGES
    assert "partial, could not find the services edge follows, cannot read" in err
    assert "partial, legal" not in err


@pytest.mark.parametrize(
    ("path", "ignored"),
    [
        ("legal/built/.datenschutz.k3j2.tmp", True),
        ("legal/built/datenschutz.html", True),
        ("legal/built/.gitkeep", False),
    ],
)
def test_the_ignore_rules_keep_the_built_pages_and_leftovers_out_of_the_tree(path, ignored):
    """L3."""
    result = subprocess.run(
        ["git", "-C", str(REPOSITORY), "check-ignore", "--quiet", path],
        stdin=subprocess.DEVNULL,
        check=False,
    )

    assert (result.returncode == 0) is ignored
