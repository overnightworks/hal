"""The realm observer's members mode (#965): the issuer from the realm's discovery document and
the ids of one group's direct members, against the fake Keycloak of the observer's tests."""

import io
import json
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest
from support.realm_fake import PUBLIC_ORIGIN, SECRET, TOKEN, FakeKeycloak, serving, uid

from hal.stack import litellm_keys
from hal.stack.realm import observe as observer

GROUP = litellm_keys.ADMIN_GROUP
REALM = "hallucinai"
DISCOVERY_PATH = f"/realms/{REALM}/.well-known/openid-configuration"


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str


@pytest.fixture
def keycloak() -> Iterator[FakeKeycloak]:
    with serving() as server:
        yield server


@pytest.fixture
def members_of(
    keycloak: FakeKeycloak, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> Callable[[str], Run]:
    """The observer's command line in members mode, as `hal apply` runs it: nothing on stdin."""
    secret_file = tmp_path / "config-cli-secret"
    secret_file.write_text(SECRET + "\n")

    def run(path: str) -> Run:
        arguments = ["--base-url", keycloak.url, "--members", path]
        code = observer.main(arguments, io.StringIO(""), secret_file)
        captured = capsys.readouterr()
        return Run(code, captured.out, captured.err)

    return run


def test_the_members_mode_prints_the_issuer_and_exactly_the_groups_direct_members(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run]
) -> None:
    person, other, parent_only = (uid(REALM, name) for name in ("p", "q", "parent-only"))
    groups = keycloak.realms[REALM].groups
    groups[GROUP].members = [person]
    groups["/services/litellm"].members = [parent_only]
    groups["/apps/hopin"].members = [other]

    run = members_of(GROUP)

    assert (run.exit_code, run.stderr) == (0, "")
    assert json.loads(run.stdout) == {
        "issuer": f"{PUBLIC_ORIGIN}/realms/{REALM}",
        "members": [person],
    }


def test_a_group_with_more_members_than_one_page_lists_every_member(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run]
) -> None:
    members = [uid(REALM, "member", str(number)) for number in range(130)]
    keycloak.realms[REALM].groups[GROUP].members = members

    run = members_of(GROUP)

    assert sorted(json.loads(run.stdout)["members"]) == sorted(members)


def test_a_group_without_members_is_an_empty_list(members_of: Callable[[str], Run]) -> None:
    run = members_of(GROUP)

    assert (run.exit_code, json.loads(run.stdout)["members"]) == (0, [])


def test_an_absent_group_is_a_failure_with_one_line_and_never_an_empty_list(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run]
) -> None:
    groups = keycloak.realms[REALM].groups
    del groups[GROUP]

    run = members_of(GROUP)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == f"realm-observer: {REALM} has no group {GROUP}\n"


def test_the_issuer_is_read_without_a_token_and_every_other_read_is_an_admin_get(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run]
) -> None:
    members_of(GROUP)

    sent = list(zip(keycloak.requests, keycloak.authorizations, strict=True))
    assert sent[0][0] == ("POST", "/realms/master/protocol/openid-connect/token")
    assert [header for call, header in sent if call == ("GET", DISCOVERY_PATH)] == [None]
    admin_reads = [(call, header) for call, header in sent[1:] if call[1] != DISCOVERY_PATH]
    assert admin_reads
    assert all(
        method == "GET" and path.startswith("/admin/realms/") and header == f"Bearer {TOKEN}"
        for (method, path), header in admin_reads
    )


def test_a_discovery_document_keycloak_refuses_is_one_line_and_no_members(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run]
) -> None:
    keycloak.faults.status[DISCOVERY_PATH] = 503

    run = members_of(GROUP)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == f"realm-observer: status 503 at {DISCOVERY_PATH}\n"


def test_an_error_nobody_expected_ends_in_one_fixed_line_that_quotes_nothing(
    keycloak: FakeKeycloak, members_of: Callable[[str], Run], monkeypatch: pytest.MonkeyPatch
) -> None:
    subject = uid(REALM, "p")
    keycloak.realms[REALM].groups[GROUP].members = [subject]

    def broken(*_: object, **__: object) -> list:
        raise RuntimeError(f"a reply quoting {subject}")

    monkeypatch.setattr(observer.Session, "paged", broken)
    run = members_of(GROUP)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == "realm-observer: unexpected RuntimeError\n"
