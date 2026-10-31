"""Cells SP1-SP6, SP8 and W4 of probe.py: a service's audience reaches a token only
through the client scope that names it. The agent service's scope is a default of every app
client; the speech service's is an optional scope of hopin alone, so a token carries
`speech-service` only when hopin asks for it, and songmaker and presentator cannot ask. Each
service is a bearer-only client, and `/services/speech-service` has no subgroup. The held lines
print the decoded claims the speech service reads and never a token. After them, hopin's branch
runs the measurements of `scope_measurement_cell` on clients the probe makes."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import scope_measurement_cell
from test_rp import token_claims

REALM = "hallucinai"
TOKEN_PATH = f"/realms/{REALM}/protocol/openid-connect/token"
AGENT_SERVICE = "agent-service"
SPEECH_SERVICE = "speech-service"
WORKLOAD_ROLES = {AGENT_SERVICE: "agent-workload", SPEECH_SERVICE: "speech-workload"}
SPEECH_SCOPE = "speech-service-audience"
SPEECH_CALLER = "hopin"
SPEECH_GROUP = f"/services/{SPEECH_SERVICE}"
USERNAME = "probe-hopin-speech-member"
BEARER_ONLY_PROOFS = {AGENT_SERVICE: "W4", SPEECH_SERVICE: "SP6"}
FLOWS = (
    "standardFlowEnabled",
    "implicitFlowEnabled",
    "directAccessGrantsEnabled",
    "serviceAccountsEnabled",
)


def audience_of(access: dict[str, Any]) -> list[str]:
    audience = access.get("aud", [])
    return [audience] if isinstance(audience, str) else audience


def is_workload_identity_of(
    access: dict[str, Any], client_id: str, service: str = AGENT_SERVICE
) -> bool:
    """The shape a service accepts: its workload role and audience, `client_id` and `azp` both
    naming the app, and no group."""
    roles = access.get("realm_access", {}).get("roles", [])
    return (
        WORKLOAD_ROLES[service] in roles
        and service in audience_of(access)
        and access.get("client_id") == client_id
        and access.get("azp") == client_id
        and not access.get("groups")
    )


def decoded(access: dict[str, Any]) -> str:
    """The claims a held line shows: no token and no subject."""
    roles = access.get("realm_access", {}).get("roles", [])
    checked = [role for role in roles if role in WORKLOAD_ROLES.values()]
    return (
        f"aud {audience_of(access)}, roles {checked}, groups {access.get('groups', [])}, "
        f"client_id {access.get('client_id')}, azp {access.get('azp')}"
    )


class Answer(Protocol):
    status: int
    text: str

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


class Probe(Protocol):
    admin: Admin
    secret_values: dict[str, str]

    def through_tunnel(self, method: str, path: str, **kwargs: Any) -> Answer: ...

    def keep_secret(self, name: str, value: str) -> str: ...

    def tokens_from(self, holder: str, response: Answer) -> dict[str, Any]: ...

    def browser(self, name: str) -> Any: ...

    def held(self, proof: str, detail: str) -> None: ...

    def app_client_sign_in(
        self,
        client: Any,
        opener: Any,
        username: str,
        password: str,
        client_secret: str,
        scope: str = ...,
    ) -> dict[str, Any]: ...


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

    def bearer_only_services(self) -> None:
        admin = self.probe.admin
        for service, proof in BEARER_ONLY_PROOFS.items():
            found = admin.find(f"/{REALM}/clients", "clientId", service)
            on = [flow for flow in FLOWS if found.get(flow)]
            self.expect(
                found.get("bearerOnly") is True and not on,
                f"{service} is bearerOnly {found.get('bearerOnly')} with flows on: {on}",
            )
            self.probe.held(proof, f"{service} is bearer-only with every flow off")
        group = admin.get(f"/{REALM}/group-by-path{SPEECH_GROUP}")
        children = admin.get(f"/{REALM}/groups/{group['id']}/children")
        self.expect(not children, f"{SPEECH_GROUP} has subgroups {children}")
        self.probe.held("SP8", f"{SPEECH_GROUP} exists with no subgroup")

    def workload_with_and_without_the_scope(self) -> None:
        asked = self.workload_claims(SPEECH_SCOPE)
        self.expect(
            is_workload_identity_of(asked, self.name, SPEECH_SERVICE),
            f"{self.name}'s workload token asked for {SPEECH_SCOPE}: {decoded(asked)}",
        )
        self.probe.held(
            "SP1", f"{self.name}'s client_credentials token asked for the scope: {decoded(asked)}"
        )
        plain = self.workload_claims()
        self.expect(
            is_workload_identity_of(plain, self.name) and SPEECH_SERVICE not in audience_of(plain),
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
            and WORKLOAD_ROLES[SPEECH_SERVICE]
            not in access.get("realm_access", {}).get("roles", [])
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
        refused = self.workload(SPEECH_SCOPE)
        error = refused.json().get("error") if refused.status == 400 else None
        self.expect(
            error == "invalid_scope" and "access_token" not in refused.text,
            f"{self.name} asked for {SPEECH_SCOPE} and was answered {refused.status}",
        )
        workload, person = self.workload_claims(), token_claims(person_access_token)
        self.expect(
            SPEECH_SERVICE not in audience_of(workload) + audience_of(person),
            f"{self.name}'s tokens carry {SPEECH_SERVICE}: {decoded(workload)}; {decoded(person)}",
        )
        self.probe.held(
            "SP5",
            f"{self.name} asking for the scope: 400 invalid_scope; its workload token "
            f"({decoded(workload)}) and person token ({decoded(person)}) carry no {SPEECH_SERVICE}",
        )


def prove(
    probe: Probe,
    expect: Callable[[bool, str], None],
    client: Client,
    person_access_token: str,
) -> None:
    cell = ServiceAudienceCell(probe, expect, client)
    if client.client_id != SPEECH_CALLER:
        cell.client_without_the_scope(person_access_token)
        return
    cell.bearer_only_services()
    cell.workload_with_and_without_the_scope()
    cell.member_token_with_the_scope()
    cell.person_token_without_the_scope(person_access_token)
    scope_measurement_cell.prove(probe, expect)
