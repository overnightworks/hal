"""Cells F0, U3-0 to U3-c, U4-0 to U4c, RF0 to RF2 of probe.py (#674 S2): what Keycloak does with
an audience scope, measured on clients, a scope and a role the probe makes. The scope is copied from
the declared `speech-service-audience`, so `include.in.token.scope: "false"` is the real one. U3: a
workload token's audience and roles under Keycloak's defaults (the control), without the default
roles, with `fullScopeAllowed` off, and with a role scope mapping beside it. U4: what a refresh
gives sessions signed in while the scope was a default, once it is optional. RF1 and RF2: what a
session that never had the scope gets by a refresh or a new authorization request that names it.
Only the setup is held; every answer is printed as measured, and an upgrade may change it."""

from __future__ import annotations

import secrets
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import parse_qs, urlencode, urlsplit

import terms_cell
from device_grant_cell import PKCE
from test_rp import token_claims

REALM = "hallucinai"
TOKEN_PATH = f"/realms/{REALM}/protocol/openid-connect/token"
AUTH_PATH = f"/realms/{REALM}/protocol/openid-connect/auth"
DECLARED_SCOPE = "speech-service-audience"
DECLARED_CLIENT = "hopin"
AUDIENCE_MAPPER = "oidc-audience-mapper"
TARGET = "probe-measured-service"
SCOPE = "probe-measured-audience"
ROLE = "probe-measured-workload"
WORKLOAD_CLIENT = "probe-u3-workload"
SESSION_CLIENT = "probe-u4-session"
CALLBACK = "https://probe-u4.invalid/callback"
USERNAME = "probe-u4-member"
DEFAULT_ROLES = f"default-roles-{REALM}"
OAUTH_ERRORS = frozenset(
    {
        "invalid_request",
        "invalid_client",
        "invalid_grant",
        "unauthorized_client",
        "unsupported_grant_type",
        "invalid_scope",
    }
)


class Answer(Protocol):
    status: int
    text: str
    headers: Any

    def json(self) -> Any: ...


class Admin(Protocol):
    def get(self, path: str) -> Any: ...

    def create(self, path: str, representation: dict[str, Any]) -> str: ...

    def must(self, method: str, path: str, json_body: Any = None) -> None: ...

    def create_user(self, realm: str, username: str, password: str) -> str: ...

    def service_account_user(self, client_id: str, realm: str = ...) -> dict[str, Any]: ...


class Probe(Protocol):
    admin: Admin

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
class SessionClient:
    """What `app_client_sign_in` reads from a client."""

    client_id: str
    callback: str


@dataclass(frozen=True)
class Made:
    scope_id: str
    workload_id: str
    workload_secret: str
    session_id: str
    session_secret: str
    account_id: str
    role: dict[str, Any]


def audiences(claims: dict[str, Any]) -> list[str]:
    value = claims.get("aud", [])
    return [value] if isinstance(value, str) else list(value)


def declared_scope_copy() -> dict[str, Any]:
    declared = terms_cell.declared_realm()
    (original,) = (s for s in declared["clientScopes"] if s["name"] == DECLARED_SCOPE)
    copy = deepcopy(original)
    copy["name"] = SCOPE
    for mapper in copy["protocolMappers"]:
        mapper["name"] = SCOPE
        mapper["config"]["included.client.audience"] = TARGET
    return copy


def hopin_scopes_without_audiences() -> list[str]:
    """hopin's declared default scopes minus the ones that only add an audience."""
    declared = terms_cell.declared_realm()
    audience_scopes = {
        scope["name"]
        for scope in declared["clientScopes"]
        if any(m["protocolMapper"] == AUDIENCE_MAPPER for m in scope.get("protocolMappers", []))
    }
    (hopin,) = (c for c in declared["clients"] if c["clientId"] == DECLARED_CLIENT)
    return [name for name in hopin["defaultClientScopes"] if name not in audience_scopes]


def line_of(claims: dict[str, Any]) -> str:
    """The claims a measured line shows: no token and no subject."""
    audience = audiences(claims)
    roles = claims.get("realm_access", {}).get("roles", [])
    return (
        f"aud {audience} ({'exact' if audience == [TARGET] else 'not exact'}), roles {roles}, "
        f"resource_access {sorted(claims.get('resource_access', {}))}, "
        f"role {ROLE} {'kept' if ROLE in roles else 'not kept'}, scope {claims.get('scope')!r}"
    )


class ScopeMeasurement:
    def __init__(self, probe: Probe, expect: Callable[[bool, str], None]) -> None:
        self.probe, self.expect = probe, expect
        self.admin = probe.admin
        self.browsers: dict[str, Any] = {}

    def create_objects(self) -> Made:
        admin, base = self.admin, hopin_scopes_without_audiences()
        admin.create(f"/{REALM}/clients", {"clientId": TARGET, "enabled": True, "bearerOnly": True})
        scope_id = admin.create(f"/{REALM}/client-scopes", declared_scope_copy())
        admin.create(f"/{REALM}/roles", {"name": ROLE})
        workload_id = admin.create(
            f"/{REALM}/clients",
            {
                "clientId": WORKLOAD_CLIENT,
                "enabled": True,
                "publicClient": False,
                "standardFlowEnabled": False,
                "serviceAccountsEnabled": True,
                "defaultClientScopes": base,
                "optionalClientScopes": [SCOPE],
            },
        )
        session_id = admin.create(
            f"/{REALM}/clients",
            {
                "clientId": SESSION_CLIENT,
                "enabled": True,
                "publicClient": False,
                "standardFlowEnabled": True,
                "serviceAccountsEnabled": False,
                "redirectUris": [CALLBACK],
                "attributes": {"pkce.code.challenge.method": "S256", "use.refresh.tokens": "true"},
                "defaultClientScopes": [*base, SCOPE],
                "optionalClientScopes": [],
            },
        )
        made = Made(
            scope_id,
            workload_id,
            self.secret_of(WORKLOAD_CLIENT, workload_id),
            session_id,
            self.secret_of(SESSION_CLIENT, session_id),
            admin.service_account_user(WORKLOAD_CLIENT)["id"],
            admin.get(f"/{REALM}/roles/{ROLE}"),
        )
        self.admin.must(
            "POST", f"/{REALM}/users/{made.account_id}/role-mappings/realm", [made.role]
        )
        self.hold_the_copy(made, base)
        return made

    def secret_of(self, client_id: str, client_uuid: str) -> str:
        secret = self.admin.get(f"/{REALM}/clients/{client_uuid}/client-secret")["value"]
        return self.probe.keep_secret(f"{client_id} client secret", secret)

    def scopes_of(self, client_uuid: str, kind: str) -> list[str]:
        listed = self.admin.get(f"/{REALM}/clients/{client_uuid}/{kind}-client-scopes")
        return sorted(scope["name"] for scope in listed)

    def hold_the_copy(self, made: Made, base: list[str]) -> None:
        scope = self.admin.get(f"/{REALM}/client-scopes/{made.scope_id}")
        mappers = scope.get("protocolMappers", [])
        mapper = mappers[0] if len(mappers) == 1 else {}
        config = mapper.get("config", {})
        self.expect(
            scope["attributes"].get("include.in.token.scope") == "false"
            and mapper.get("protocolMapper") == AUDIENCE_MAPPER
            and config.get("access.token.claim") == "true"
            and config.get("id.token.claim") == "false"
            and config.get("included.client.audience") == TARGET,
            f"the copied scope reads back as {scope.get('attributes')} with mappers {mappers}",
        )
        workload_default = self.scopes_of(made.workload_id, "default")
        session_default = self.scopes_of(made.session_id, "default")
        self.expect(
            workload_default == sorted(base) and session_default == sorted([*base, SCOPE]),
            f"the probe clients' default scopes are {workload_default} and {session_default}",
        )
        self.probe.held(
            "F0",
            f"{SCOPE} is a copy of {DECLARED_SCOPE}: include.in.token.scope false, an "
            f"access-token-only audience mapper for {TARGET}; {WORKLOAD_CLIENT} and "
            f"{SESSION_CLIENT} have hopin's "
            f"default scopes without its audience scopes {sorted(base)}",
        )

    def measure(self, holder: str, answer: Answer) -> tuple[str, dict[str, Any]]:
        """A 200 is registered for proof 7; a 400 must be an OAuth error; anything else fails."""
        if answer.status == 200:
            tokens = self.probe.tokens_from(holder, answer)
            return f"200, {line_of(token_claims(tokens['access_token']))}", tokens
        error = answer.json().get("error") if answer.status == 400 else None
        self.expect(
            error in OAUTH_ERRORS, f"{holder} answered {answer.status}: neither 200 nor OAuth"
        )
        return f"{answer.status} {error}", {}

    def ask(self, client_id: str, secret: str, **fields: str) -> Answer:
        form = {"client_id": client_id, "client_secret": secret, **fields}
        return self.probe.through_tunnel("POST", TOKEN_PATH, form=form)

    def workload_token(self, made: Made, proof: str) -> dict[str, Any]:
        answer = self.ask(
            WORKLOAD_CLIENT,
            made.workload_secret,
            grant_type="client_credentials",
            scope=SCOPE,
        )
        line, tokens = self.measure(f"{WORKLOAD_CLIENT} {proof}", answer)
        self.probe.held(proof, f"{WORKLOAD_CLIENT} client_credentials asking for {SCOPE}: {line}")
        return tokens

    def workload_arms(self, made: Made) -> None:
        control = token_claims(self.workload_token(made, "U3-0")["access_token"])
        self.expect(
            ROLE in control.get("realm_access", {}).get("roles", [])
            and TARGET in audiences(control)
            and control.get("client_id") == control.get("azp") == WORKLOAD_CLIENT,
            f"the U3 control is not the shape the arms compare against: {line_of(control)}",
        )
        account = f"/{REALM}/users/{made.account_id}/role-mappings/realm"
        default_roles = self.admin.get(f"/{REALM}/roles/{DEFAULT_ROLES}")
        self.admin.must("DELETE", account, [default_roles])
        self.workload_token(made, "U3-a")
        self.admin.must("POST", account, [default_roles])
        client = f"/{REALM}/clients/{made.workload_id}"
        self.admin.must("PUT", client, {**self.admin.get(client), "fullScopeAllowed": False})
        self.workload_token(made, "U3-b")
        self.admin.must("POST", f"{client}/scope-mappings/realm", [made.role])
        self.workload_token(made, "U3-c")

    def refresh(
        self, made: Made, proof: str, refresh_token: str, scope: str = ""
    ) -> dict[str, Any]:
        fields = {"grant_type": "refresh_token", "refresh_token": refresh_token}
        answer = self.ask(SESSION_CLIENT, made.session_secret, **fields, **self.named(scope))
        line, tokens = self.measure(f"{SESSION_CLIENT} {proof}", answer)
        asked = f"naming {scope!r}" if scope else "naming no scope"
        self.probe.held(proof, f"a refresh {asked}: {line}")
        return tokens

    @staticmethod
    def named(scope: str) -> dict[str, str]:
        return {"scope": scope} if scope else {}

    def browser(self, who: str) -> Any:
        """One browser per session, so a later request meets the session's cookies."""
        if who not in self.browsers:
            self.browsers[who] = self.probe.browser(f"{SESSION_CLIENT} {who}")
        return self.browsers[who]

    def sign_in(self, made: Made, who: str, password: str, scope: str) -> dict[str, Any]:
        client = SessionClient(SESSION_CLIENT, CALLBACK)
        return self.probe.app_client_sign_in(
            client, self.browser(who), USERNAME, password,
            made.session_secret, scope=scope,
        )  # fmt: skip

    def session_arms(self, made: Made) -> None:
        password = self.probe.keep_secret(f"{USERNAME} password", secrets.token_urlsafe(16))
        self.admin.create_user(REALM, USERNAME, password)
        asked = f"openid {SCOPE}"
        old = self.sign_in(made, "Sa", password, "openid")
        named = self.sign_in(made, "Sb", password, asked)
        for who, tokens in (("Sa", old), ("Sb", named)):
            self.expect(
                TARGET in audiences(token_claims(tokens["access_token"]))
                and "refresh_token" in tokens,
                f"{who} signed in while {SCOPE} was a default, without {TARGET} or a refresh token",
            )
        self.probe.held(
            "U4-0", f"Sa (openid) and Sb ({asked}) signed in while {SCOPE} was a default"
        )
        self.admin.must(
            "DELETE", f"/{REALM}/clients/{made.session_id}/default-client-scopes/{made.scope_id}"
        )
        self.admin.must(
            "PUT", f"/{REALM}/clients/{made.session_id}/optional-client-scopes/{made.scope_id}"
        )
        newest = self.refresh(made, "U4a", old["refresh_token"]).get(
            "refresh_token", old["refresh_token"]
        )
        self.refresh(made, "U4b", newest, asked)
        self.refresh(made, "U4c", named["refresh_token"])
        fresh = self.sign_in(made, "Sc", password, "openid")
        self.expect(
            TARGET not in audiences(token_claims(fresh["access_token"]))
            and "refresh_token" in fresh,
            f"Sc signed in with openid after the move, with {TARGET} or without a refresh token",
        )
        self.probe.held(
            "RF0", f"Sc signed in with openid once {SCOPE} was optional: no {TARGET} audience"
        )
        self.refresh(made, "RF1", fresh["refresh_token"], asked)
        self.silent_sign_in(made, asked)

    def silent_sign_in(self, made: Made, scope: str) -> None:
        """Whether a session's browser gets a code for the scope with no password; not exchanged."""
        query = urlencode(
            {
                "client_id": SESSION_CLIENT,
                "redirect_uri": CALLBACK,
                "response_type": "code",
                "scope": scope,
                "state": secrets.token_urlsafe(8),
                "nonce": secrets.token_urlsafe(8),
                **PKCE,
            }
        )
        opener = self.browser("Sc")
        answer = self.probe.through_tunnel("GET", f"{AUTH_PATH}?{query}", opener=opener)
        if answer.status == 302:
            parameters = parse_qs(urlsplit(answer.headers.get("Location", "")).query)
            if "code" in parameters:
                self.probe.keep_secret(
                    f"{SESSION_CLIENT} RF2 authorization code", parameters["code"][0]
                )
            outcome = (
                "302 to the callback with a code"
                if "code" in parameters
                else (f"302 with error {parameters.get('error')}")
            )
        else:
            self.expect(
                answer.status == 200 and 'name="username"' in answer.text,
                f"the silent sign-in answered {answer.status}: neither a redirect nor a login page",
            )
            outcome = "200 with the login page"
        self.probe.held(
            "RF2", f"an authorization request in Sc's browser naming {scope!r}: {outcome}"
        )


def prove(probe: Probe, expect: Callable[[bool, str], None]) -> None:
    cell = ScopeMeasurement(probe, expect)
    made = cell.create_objects()
    cell.workload_arms(made)
    cell.session_arms(made)
