"""The legal unit (#285): the repository's real compose.yaml, fleet.yaml and legal/ tree."""

import re
from datetime import date
from functools import cache
from importlib import metadata
from pathlib import Path

import pytest
import yaml

from hal.backup.restic import PRE_APPLY_MAX_AGE
from hal.stack import appkit_step, catalog, legal_pages, legal_step
from hal.workstation.system_step import LOG_RETENTION_DAYS

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())


@pytest.fixture(scope="module")
def legal(document) -> dict:
    return document["services"]["legal"]


def test_the_unit_is_hardened_like_the_stacks_other_services(legal):
    assert legal["read_only"] is True
    assert legal["cap_drop"] == ["ALL"]
    assert legal["security_opt"] == ["no-new-privileges:true"]


def test_the_image_is_pinned_by_digest(legal):
    assert "@sha256:" in legal["image"]


def test_the_unit_does_not_run_as_root_and_listens_on_the_port_traefik_routes_to(legal):
    listen = re.search(
        r"^\s*listen\s+(\d+);", (ROOT / "legal/nginx/default.conf").read_text(), re.M
    )
    port = legal["labels"]["traefik.http.services.legal.loadbalancer.server.port"]

    assert legal["image"].split(":")[0] == "nginxinc/nginx-unprivileged"
    assert str(legal.get("user", "nonroot")).split(":")[0] not in {"0", "root"}
    assert int(listen.group(1)) > 1023
    assert listen.group(1) == port


def test_the_router_serves_the_edge_entrypoint_by_a_host_rule(legal):
    labels = legal["labels"]

    assert labels["traefik.http.routers.legal.entrypoints"]
    assert labels["traefik.http.routers.legal.rule"].startswith("Host(")


def test_the_unit_has_no_route_out_and_no_published_port(document, legal):
    assert legal["networks"] == ["legal"]
    assert document["networks"]["legal"] == {"internal": True}
    assert "ports" not in legal


def test_every_bind_is_read_only(legal):
    assert all(bind.endswith(":ro") for bind in legal["volumes"])
    assert all((ROOT / bind.split(":")[0]).is_dir() for bind in legal["volumes"])


def test_the_security_headers_stand_at_server_level_and_no_location_overrides_them():
    config = (ROOT / "legal/nginx/default.conf").read_text()
    server_level, *locations = config.split("location ")
    for header in (
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Cache-Control",
    ):
        assert f"add_header {header} " in server_level
    # nginx drops every inherited add_header in a location that sets its own.
    assert not any("add_header" in location for location in locations)


def test_every_cache_asks_the_unit_again_before_it_shows_a_stored_page():
    """A changed text is the one people get once it is written: no cache may answer from a stored
    copy without asking first, and nothing grants a lifetime or a stale answer."""
    config = (ROOT / "legal/nginx/default.conf").read_text()
    value = re.search(r'add_header Cache-Control "([^"]*)" always;', config).group(1)
    directives = {part.strip().lower().split("=")[0] for part in value.split(",")}

    assert directives & {"no-cache", "no-store"}
    assert not directives & {
        "public",
        "max-age",
        "s-maxage",
        "immutable",
        "stale-while-revalidate",
        "stale-if-error",
    }


VERSION = metadata.version(appkit_step.DISTRIBUTION)
PAGES = ("impressum", "datenschutz", "nutzungsbedingungen")
TEXT_PAGES = PAGES[1:]


@cache
def built_pages() -> dict[str, str]:
    """The pages `hal apply` builds from this repository's frame and sections, at a fixed date."""
    keys = catalog.read(ROOT / "fleet.yaml")["services"]
    blocks = legal_step.read_blocks(ROOT, keys, lambda _path: date(2026, 1, 1))
    return legal_pages.build_pages(legal_step.read_frame(ROOT), blocks)


def read_page(name: str) -> str:
    return built_pages()[name]


@pytest.mark.parametrize("name", PAGES)
def test_each_page_is_built_with_content(name):
    assert read_page(name)


@pytest.mark.parametrize("name", PAGES)
def test_a_page_links_only_assets_the_unit_has_files_for(name):
    served = {f"/_rechtliches/{path.name}" for path in (ROOT / "legal/assets").iterdir()}
    appkit = appkit_step.installed_static()
    served |= {
        f"/_rechtliches/appkit-{VERSION}/{path.relative_to(appkit)}"
        for path in appkit.rglob("*")
        if path.is_file()
    }
    linked = set(re.findall(r'(?:href|src)="(/_rechtliches/[^"]+)"', read_page(name)))
    assert linked
    assert linked <= served


@pytest.mark.parametrize("name", PAGES)
def test_every_appkit_link_and_preload_names_the_installed_version(name):
    linked = re.findall(r'(?:href|src)="/_rechtliches/(appkit-[^/"]+)/', read_page(name))
    assert linked
    assert set(linked) == {f"appkit-{VERSION}"}


@pytest.mark.parametrize("name", PAGES)
def test_a_page_links_appkit_css_before_legal_css(name):
    page = read_page(name)
    assert page.index(f"/_rechtliches/appkit-{VERSION}/appkit.css") < page.index(
        "/_rechtliches/legal-2.css"
    )


@pytest.mark.parametrize("name", PAGES)
def test_a_page_carries_no_inline_style_and_no_script_the_csp_would_refuse(name):
    page = read_page(name)
    assert " style=" not in page
    assert "<style" not in page
    assert "<script" not in page


@pytest.mark.parametrize("name", TEXT_PAGES)
def test_every_table_of_contents_entry_targets_an_id_of_the_page(name):
    page = read_page(name)
    contents = page.split('<aside class="toc"')[1].split("</aside>")[0]
    targets = re.findall(r'href="#([^"]+)"', contents)
    assert targets
    assert all(f'id="{target}"' in page for target in targets)


@pytest.mark.parametrize(
    "sentence",
    [
        "Die verschlüsselte Verbindung Ihres Browsers endet bei Cloudflare",
        "kann ihren Inhalt technisch einsehen",
        "dafür ist Cloudflare selbst verantwortlich",
        "CELEX:32023D1795",
        "Bayerische Landesamt für Datenschutzaufsicht (BayLDA)",
    ],
)
def test_the_shared_privacy_part_says_what_cloudflare_sees_and_who_hears_complaints(sentence):
    assert sentence in read_page("datenschutz")


@pytest.mark.parametrize(
    ("section", "sentence"),
    [
        ("automatisierte-entscheidungen", "Art. 22 Abs. 1 und 4 DSGVO"),
        ("pseudonym", "§ 19 Abs. 2 TDDDG"),
    ],
)
def test_a_shared_section_is_in_the_table_of_contents(section, sentence):
    page = read_page("datenschutz")
    assert f'<a href="#{section}">' in page
    assert sentence in page.split(f'id="{section}"')[1]


@pytest.mark.parametrize(
    "sentence",
    [
        "Sie endet nach 7 Tagen ohne Aktivität, spätestens nach 30 Tagen",
        "§ 25 Abs. 2 Nr. 2 TDDDG",
        "Eine Einwilligung ist dafür nicht nötig",
        "90 Tage lang",
        "1 Jahr lang",
        "12 Stunden nach dem letzten Fehlversuch",
        "den Zeitpunkt des letzten Fehlversuchs",
        "KC_STATE_CHECKER",
        "etwa drei Monate",
    ],
)
def test_the_shared_sign_in_section_names_what_keycloak_keeps_and_for_how_long(sentence):
    page = read_page("datenschutz")
    assert '<a href="#anmeldung">Anmeldung (Keycloak)</a>' in page
    assert sentence in page.split('id="anmeldung"')[1]


def test_the_sign_in_section_states_the_age_bound_of_the_snapshots_before_an_update():
    section = read_page("datenschutz").split('id="anmeldung"')[1].split("<h2")[0]
    assert f"auch sie löschen wir nach {PRE_APPLY_MAX_AGE.days} Tagen" in section


def test_the_sign_in_section_states_the_age_bound_of_the_container_log():
    section = read_page("datenschutz").split('id="anmeldung"')[1].split("<h2")[0]
    assert f"bevor er {LOG_RETENTION_DAYS} Tage alt ist" in section


TEXT_SOURCES = [
    path.relative_to(ROOT).as_posix()
    for pattern in ("legal/frame/*.html", "legal/frame/blocks/*.html", "legal/sections/*/*.html")
    for path in sorted(ROOT.glob(pattern))
]


@pytest.mark.parametrize("path", [*TEXT_SOURCES, "docs/design/legal-pages.html"])
@pytest.mark.parametrize(
    "mark",
    [
        "Zu prüfen",
        "zu prüfen",
        'class="check',
        'class="todo"',
        'class="slot"',
        "hopin",
        "presentator",
        "TODO",
    ],
)
def test_neither_a_page_nor_the_frozen_picture_carries_a_placeholder_or_a_review_mark(path, mark):
    assert mark not in (ROOT / path).read_text()
