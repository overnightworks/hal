import re

import pytest

from hal.backup.apps import PRE_APPLY_TAG, AppsError, parse_apps

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
