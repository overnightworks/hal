"""Cells SP1-SP6 and SP8 of probe.py: the speech service's audience reaches a token only
through the client scope that names it, an optional scope of the clients that declare it, so a
token carries `speech-service` only when one of them asks for it, and the others cannot ask. The
service is a bearer-only client, and `/services/speech-service` has no subgroup. The held lines
print the decoded claims the speech service reads and never a token. After them, hopin's branch
runs the measurements of `scope_measurement_cell` on clients the probe makes."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

import scope_measurement_cell
from test_rp import token_claims

REALM = "hallucinai"
TOKEN_PATH = f"/realms/{REALM}/protocol/openid-connect/token"
AUTH_PATH = f"/realms/{REALM}/protocol/openid-connect/auth"
SPEECH_SERVICE = "speech-service"
SPEECH_WORKLOAD_ROLE = "speech-workload"
SPEECH_SCOPE = "speech-service-audience"
PROOF_CLIENT = "hopin"  # the client whose branch also runs the bearer-only and measurement cells
SPEECH_GROUP = f"/services/{SPEECH_SERVICE}"
USERNAME = f"probe-{PROOF_CLIENT}-speech-member"
FLOWS = (
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
)


def audience_of(access: dict[str, Any]) -> list[str]:
    audience = access.get("aud", [])
    return [audience] if isinstance(audience, str) else audience


def has_workload_role(access: dict[str, Any]) -> bool:
    return SPEECH_WORKLOAD_ROLE in access.get("realm_access", {}).get("roles", [])


def is_workload_of(access: dict[str, Any], client_id: str) -> bool:
    """An app's workload token: the workload role, `client_id` and `azp` both naming the app, and
    no group."""
    return (
        has_workload_role(access)
        and access.get("client_id") == client_id
        and access.get("azp") == client_id
        and not access.get("groups")
    )


def is_workload_identity_of(access: dict[str, Any], client_id: str) -> bool:
    """The shape the speech service accepts: an app's workload token with its audience."""
    return is_workload_of(access, client_id) and SPEECH_SERVICE in audience_of(access)


def decoded(access: dict[str, Any]) -> str:
    """The claims a held line shows: no token and no subject."""
    roles = access.get("realm_access", {}).get("roles", [])
    checked = [role for role in roles if role == SPEECH_WORKLOAD_ROLE]
    return (
        f"aud {audience_of(access)}, roles {checked}, groups {access.get('groups', [])}, "
        f"client_id {access.get('client_id')}, azp {access.get('azp')}"
    )


class Answer(Protocol):
    status: int
    text: str
    headers: Any

    def json(self) -> Any: ...


class Admin(Protocol):
    def get(self, path: str) -> Any: ...

    def find(self, path: str, key: str, value: str) -> dict[str, Any]: ...

    def create_user(self, realm: str, username: str, password: str) -> str: ...

    def join_group(self, user_id: str, group_path: str) -> None: ...


class Client(Protocol):
    client_id: str
    group: str
    secret_file: str
    optional_scopes: frozenset[str]


class Probe(scope_measurement_cell.Probe, Protocol):
    admin: Admin
    secret_values: dict[str, str]

    def app_client_authorization_query(self, client: Any, **changes: str) -> str: ...


@dataclass(frozen=True)
class ServiceAudienceCell:
    probe: Probe
    expect: Callable[[bool, str], None]
    client: Client

    @property
    def name(self) -> str:
        return self.client.client_id

    def workload(self, scope: str = "") -> Answer:
        credentials = {
            "grant_type": "client_credentials",
            "client_id": self.name,
            "client_secret": self.probe.secret_values[self.client.secret_file],
        }
        form = credentials | ({"scope": scope} if scope else {})
        return self.probe.through_tunnel("POST", TOKEN_PATH, form=form)

    def workload_claims(self, scope: str = "") -> dict[str, Any]:
        holder = f"{self.name} workload {scope or 'without a scope'}"
        return token_claims(self.probe.tokens_from(holder, self.workload(scope))["access_token"])

    def bearer_only_service(self) -> None:
        admin = self.probe.admin
        found = admin.find(f"/{REALM}/clients", "clientId", SPEECH_SERVICE)
        on = [flow for flow in FLOWS if found.get(flow)]
        self.expect(
            found.get("bearerOnly") is True and not on,
            f"{SPEECH_SERVICE} is bearerOnly {found.get('bearerOnly')} with flows on: {on}",
        )
        self.probe.held("SP6", f"{SPEECH_SERVICE} is bearer-only with every flow off")
        group = admin.get(f"/{REALM}/group-by-path{SPEECH_GROUP}")
        children = admin.get(f"/{REALM}/groups/{group['id']}/children")
        self.expect(not children, f"{SPEECH_GROUP} has subgroups {children}")
        self.probe.held("SP8", f"{SPEECH_GROUP} exists with no subgroup")

    def workload_with_and_without_the_scope(self) -> None:
        asked = self.workload_claims(SPEECH_SCOPE)
        self.expect(
            is_workload_identity_of(asked, self.name),
            f"{self.name}'s workload token asked for {SPEECH_SCOPE}: {decoded(asked)}",
        )
        self.probe.held(
            "SP1", f"{self.name}'s client_credentials token asked for the scope: {decoded(asked)}"
        )
        plain = self.workload_claims()
        self.expect(
            is_workload_of(plain, self.name) and SPEECH_SERVICE not in audience_of(plain),
            f"{self.name}'s workload token asked for no scope: {decoded(plain)}",
        )
        self.probe.held(
            "SP2", f"{self.name}'s client_credentials token asked for none: {decoded(plain)}"
        )

    def member_token_with_the_scope(self) -> None:
        password = self.probe.keep_secret(f"{USERNAME} password", secrets.token_urlsafe(16))
        member = self.probe.admin.create_user(REALM, USERNAME, password)
        for path in (self.client.group, SPEECH_GROUP):
            self.probe.admin.join_group(member, path)
        tokens = self.probe.app_client_sign_in(
            self.client,
            self.probe.browser(f"{self.name} speech"),
            USERNAME,
            password,
            self.probe.secret_values[self.client.secret_file],
            scope=f"openid {SPEECH_SCOPE}",
        )
        access, identity = token_claims(tokens["access_token"]), token_claims(tokens["id_token"])
        self.expect(
            SPEECH_SERVICE in audience_of(access)
            and SPEECH_GROUP in access.get("groups", [])
            and "/services" not in access["groups"]
            and not has_workload_role(access)
            and SPEECH_SERVICE not in audience_of(identity),
            f"a member's token asked for {SPEECH_SCOPE}: {decoded(access)}; "
            f"ID token aud {audience_of(identity)}",
        )
        self.probe.held(
            "SP3",
            f"a member's access token asked for the scope: {decoded(access)}; "
            f"ID token aud {audience_of(identity)}",
        )

    def person_token_without_the_scope(self, person_access_token: str) -> None:
        access = token_claims(person_access_token)
        self.expect(
            SPEECH_SERVICE not in audience_of(access),
            f"a person's token from {self.name} asked for no scope: {decoded(access)}",
        )
        self.probe.held("SP4", f"a person's access token asked for none: {decoded(access)}")

    def client_without_the_scope(self, person_access_token: str) -> None:
        """A client without the scope has no service account, so it can ask only at sign-in."""
        query = self.probe.app_client_authorization_query(
            self.client, scope=f"openid {SPEECH_SCOPE}", **scope_measurement_cell.PKCE
        )
        refused = self.probe.through_tunnel("GET", f"{AUTH_PATH}?{query}")
        error = parse_qs(urlsplit(refused.headers.get("Location", "")).query).get("error")
        self.expect(
            refused.status == 302 and error == ["invalid_scope"],
            f"{self.name} asked for {SPEECH_SCOPE} at sign-in and was answered {refused.status} "
            f"with {error}",
        )
        person = token_claims(person_access_token)
        self.expect(
            SPEECH_SERVICE not in audience_of(person),
            f"{self.name}'s person token carries {SPEECH_SERVICE}: {decoded(person)}",
        )
        self.probe.held(
            "SP5",
            f"{self.name} asking for the scope at sign-in: invalid_scope; its person token "
            f"({decoded(person)}) carries no {SPEECH_SERVICE}",
        )


def prove(
    probe: Probe,
    expect: Callable[[bool, str], None],
    client: Client,
    person_access_token: str,
) -> None:
    cell = ServiceAudienceCell(probe, expect, client)
    runs_whole_proof = client.client_id == PROOF_CLIENT
    if runs_whole_proof:
        expect(SPEECH_SCOPE in client.optional_scopes, f"{PROOF_CLIENT} offers {SPEECH_SCOPE}")
    elif SPEECH_SCOPE not in client.optional_scopes:
        cell.client_without_the_scope(person_access_token)
        return
    if runs_whole_proof:
        cell.bearer_only_service()
    cell.workload_with_and_without_the_scope()
    if runs_whole_proof:
        cell.member_token_with_the_scope()
        cell.person_token_without_the_scope(person_access_token)
        scope_measurement_cell.prove(probe, expect)
