import re
from pathlib import Path

import pytest
import yaml

from hal.backup.apps import PRE_APPLY_TAG, AppsError, PostgresDatabase, parse_apps
from hal.backup.cli import DEFAULT_APPS

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
        ('LiteLLM"; DROP TABLE x; --', False),
        ("LiteLLM Token", False),
        ("LiteLLM;Token", False),
    ],
)
def test_count_table_admits_a_mixed_case_name_and_refuses_a_quote_a_space_or_a_semicolon(
    count_table, accepted
):
    restore_test = f"[app.keycloak.restore_test]\ncount_table = {count_table!r}\n"
    text = f"[app.keycloak]\n{KEYCLOAK_RECORD}{restore_test}"

    if accepted:
        assert parse_apps(text)[0].restore_test.count_table == count_table
    else:
        with pytest.raises(AppsError, match="count_table must match"):
            parse_apps(text)


def _shipped_stack_databases() -> list[tuple[str, PostgresDatabase]]:
    compose_name = yaml.safe_load(COMPOSE.read_text())["name"]
    return [
        (app.name, app.database)
        for app in parse_apps(DEFAULT_APPS.read_text())
        if app.compose_project == compose_name and isinstance(app.database, PostgresDatabase)
    ]


@pytest.mark.parametrize(("name", "database"), _shipped_stack_databases())
def test_a_shipped_stack_record_names_its_compose_service_user_database_and_major(name, database):
    services = yaml.safe_load(COMPOSE.read_text())["services"]
    service = services[database.db_service]
    image_major = re.match(r"postgres:(\d+)", service["image"])

    assert (database.db_user, database.db_name, database.postgres_major) == (
        service["environment"]["POSTGRES_USER"],
        service["environment"]["POSTGRES_DB"],
        int(image_major[1]),
    )
