import re
from pathlib import Path

import pytest
import yaml
from support.backup_support import SONGMAKER_TOML, SQLITE_TOML

from hal.backup.apps import PRE_APPLY_TAG, App, AppsError, PostgresDatabase, parse_apps
from hal.backup.cli import DEFAULT_APPS
from hal.stack import catalog
from hal.stack.compose import profile_services

COMPOSE = Path(__file__).parent.parent / "compose.yaml"

KEYCLOAK_RECORD = """\
compose_project = "edge"
db_service = "keycloak-db"
dump = "pg_dump_custom"
db_user = "keycloak"
db_name = "keycloak"
postgres_major = 17
"""


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("[app", "apps.toml is not valid TOML"),
        ("[other]", "apps.toml: unknown key; only ['app'] is allowed"),
        ("", "apps.toml declares no app"),
        ('[app."Not Plain"]', "apps.toml: an app name must match [a-z_][a-z0-9_-]{0,62}"),
        (f"[app.{PRE_APPLY_TAG}]", "the app name is taken by the restic tag"),
        ("[app]\nkeycloak = 1", "apps.toml [app.keycloak]: must be a table"),
        (f"[app.keycloak]\n{KEYCLOAK_RECORD}restore_test = 1", "restore_test: must be a table"),
    ],
)
def test_apps_toml_refuses_a_document_that_is_no_table_of_named_apps(text, message):
    with pytest.raises(AppsError, match=re.escape(message)):
        parse_apps(text)


def test_a_refused_dump_names_the_plain_values_it_allows():
    text = f"[app.keycloak]\n{KEYCLOAK_RECORD.replace('pg_dump_custom', 'sh')}"

    with pytest.raises(AppsError) as refusal:
        parse_apps(text)

    assert str(refusal.value).endswith(
        "dump must be one of ['pg_dump_custom', 'sqlite_online_copy']"
    )


@pytest.mark.parametrize(
    ("count_table", "accepted"),
    [
        ("LiteLLM_VerificationToken", True),
        ('LiteLLM"Token', False),
        ("LiteLLM Token", False),
        ("LiteLLM;Token", False),
        ("LiteLLMTokenü", False),
    ],
)
def test_count_table_admits_a_mixed_case_name_and_refuses_a_quote_a_space_a_semicolon_or_non_ascii(
    count_table, accepted
):
    restore_test = f"[app.keycloak.restore_test]\ncount_table = {count_table!r}\n"
    text = f"[app.keycloak]\n{KEYCLOAK_RECORD}{restore_test}"

    if accepted:
        assert parse_apps(text)[0].restore_test.count_table == count_table
    else:
        with pytest.raises(AppsError, match="count_table must match"):
            parse_apps(text)


def _shipped_stack_apps() -> list[App]:
    compose = yaml.safe_load(COMPOSE.read_text())
    apps = [
        app
        for app in parse_apps(DEFAULT_APPS.read_text())
        if isinstance(app.database, PostgresDatabase)
        and (
            app.compose_project == compose["name"] or app.database.db_service in compose["services"]
        )
    ]
    assert apps, "no shipped Postgres record belongs to compose.yaml"
    return apps


@pytest.mark.parametrize("app", _shipped_stack_apps(), ids=lambda app: app.name)
def test_a_shipped_stack_record_names_its_compose_project_service_user_database_and_major(app):
    compose = yaml.safe_load(COMPOSE.read_text())
    database = app.database
    service = compose["services"][database.db_service]
    image_major = re.match(r"postgres:(\d+)", service["image"])

    assert (app.compose_project, database.db_user, database.db_name, database.postgres_major) == (
        compose["name"],
        service["environment"]["POSTGRES_USER"],
        service["environment"]["POSTGRES_DB"],
        int(image_major[1]),
    )


@pytest.mark.parametrize(
    "app",
    [app for app in _shipped_stack_apps() if app.database.audio is None],
    ids=lambda app: app.name,
)
def test_a_db_only_stack_record_is_a_unit_whose_profile_holds_its_database(app):
    """`hal restore <app> --live` reads the unit's switch by the record's name and starts only
    its database container."""
    profiles = profile_services(yaml.safe_load(COMPOSE.read_text()))
    units = {unit.key for unit in catalog.load(COMPOSE.parent, profiles)}

    assert app.name in units
    assert app.database.db_service in profiles[app.name]


@pytest.mark.parametrize("key", ["files_volume", "files_skip"])
def test_a_sqlite_record_naming_a_files_key_is_refused_as_an_unknown_key(key):
    record = SQLITE_TOML.replace(
        'database_file = "presentator.sqlite3"\n',
        f'database_file = "presentator.sqlite3"\n{key} = "builds"\n',
    )

    with pytest.raises(AppsError, match="unknown key"):
        parse_apps(record)


@pytest.mark.parametrize(
    "dropped",
    [
        pytest.param(["volume"], id="references-without-a-volume"),
        pytest.param(["audio_reference_table", "audio_reference_column"], id="volume-alone"),
        pytest.param(["audio_reference_column"], id="a-table-without-its-column"),
    ],
)
def test_apps_toml_refuses_audio_that_is_not_declared_whole(dropped):
    """#107 T2: a reference table without a volume (or the reverse) is refused at load."""
    text = "\n".join(
        line
        for line in SONGMAKER_TOML.splitlines()
        if not any(line.startswith(f"{key} =") for key in dropped)
    )

    with pytest.raises(AppsError, match="audio needs volume and audio_reference_table"):
        parse_apps(text)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (("dump", '"sh -c pg_dump"'), "dump must be one of"),
        (("volume", '"audio files"'), "volume must match"),
        (("hook", '"rm -rf /"'), "unknown key; only ["),
        (("db_name", '"x; DROP TABLE songs"'), "db_name must match"),
    ],
)
def test_apps_toml_accepts_only_validated_records(change, message):
    key, value = change
    lines = [line for line in SONGMAKER_TOML.splitlines() if not line.startswith(f"{key} =")]
    lines.insert(lines.index("[app.songmaker]") + 1, f"{key} = {value}")
    text = "\n".join(lines)

    with pytest.raises(AppsError, match=re.escape(message)):
        parse_apps(text)


def test_apps_toml_rejects_an_unsafe_sql_identifier():
    text = SONGMAKER_TOML.replace('"songs"', '"songs\\"; --"')

    with pytest.raises(AppsError, match="count_table must match"):
        parse_apps(text)
