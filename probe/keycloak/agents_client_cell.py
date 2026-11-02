"""Cells D1-D3, B1-B3, A1-A10, C1-C4 and E1 of probe.py: the public client `agents` signs a
person's own AI agent in with the authorization code and PKCE at one loopback address, and a
token carries an app's `/mcp` audience only for the optional scope `mcp-<app>`. The cell first
proves the realm's transition (sessions of the app clients live through the apply that adds the
client, the scopes and the groups), then the client on the shipped configuration. Expected values
are read from `keycloak/realm.yaml`; the held lines print decoded claims and never a token."""

from __future__ import annotations

import base64
import hashlib
import secrets
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from urllib.parse import parse_qs, urlsplit

import terms_cell
import yaml
from service_audience_cell import audience_of
from test_rp import token_claims

from hal.stack.realm.observe import CLIENT, CONFIG_CLI_STATE, canonical, without_volatile

REALM = "hallucinai"
AUTH_PATH = f"/realms/{REALM}/protocol/openid-connect/auth"
TOKEN_PATH = f"/realms/{REALM}/protocol/openid-connect/token"
DEVICE_PATH = f"{AUTH_PATH}/device"
DISCOVERY_PATH = f"/realms/{REALM}/.well-known/openid-configuration"
REGISTRATION_PATH = f"/realms/{REALM}/clients-registrations/openid-connect"
INSERTED_DISCOVERY = (
    f"/.well-known/openid-configuration/realms/{REALM}",
    f"/.well-known/oauth-authorization-server/realms/{REALM}",
)
INTERNAL_HOST = "songmaker.mcp.internal"
REALM_FILE = Path(__file__).resolve().parents[2] / "keycloak" / "realm.yaml"
MCP_SCOPE_PREFIX = "mcp-"
APPS_GROUP = "/apps"


class Answer(Protocol):
    status: int
    headers: dict[str, str]
    text: str

    def json(self) -> Any: ...


class Admin(Protocol):
    def call(self, method: str, path: str, json_body: Any = None) -> Answer: ...

    def get(self, path: str) -> Any: ...

    def must(self, method: str, path: str, json_body: Any = None) -> None: ...

    def create_user(self, realm: str, username: str, password: str) -> str: ...

    def join_group(self, user_id: str, group_path: str) -> None: ...

    def group_paths(self, user_id: str) -> list[str]: ...

    def client(self, client_id: str, realm: str = REALM) -> dict[str, Any]: ...


class Stack(Protocol):
    scratch: Path

    def copy_config(self, target: Path) -> Path: ...

    def must_apply(self, label: str, **kwargs: Any) -> str: ...


class AppClient(Protocol):
    client_id: str
    group: str
    secret_file: str


class Probe(Protocol):
    admin: Admin
    stack: Stack
    secret_values: dict[str, str]

    def through_tunnel(self, method: str, path: str, **kwargs: Any) -> Answer: ...

    def through_tunnel_url(self, method: str, url: str, **kwargs: Any) -> Answer: ...

    def keep_secret(self, name: str, value: str) -> str: ...

    def tokens_from(self, holder: str, response: Answer) -> dict[str, Any]: ...

    def browser(self, name: str) -> Any: ...

    def held(self, proof: str, detail: str) -> None: ...

    def say(self, line: str) -> None: ...

    def app_client_authorization_query(self, client: Any, **changes: str) -> str: ...

    def app_client_sign_in(
        self, client: Any, opener: Any, username: str, password: str, client_secret: str
    ) -> dict[str, Any]: ...


@dataclass(frozen=True)
class Declared:
    """What `keycloak/realm.yaml` says about the client and its scopes."""

    client_id: str
    callback: str
    apps: dict[str, str]  # app -> the audience its scope names
    consent_texts: dict[str, str]  # app -> the words its scope shows on the consent page

    @classmethod
    def read(cls) -> Declared:
        realm = yaml.safe_load(REALM_FILE.read_text())
        (client,) = (c for c in realm["clients"] if c["clientId"] == "agents")
        scopes = {scope["name"]: scope for scope in realm["clientScopes"]}
        audiences = {
            name.removeprefix(MCP_SCOPE_PREFIX): scope["protocolMappers"][0]["config"][
                "included.custom.audience"
            ]
            for name, scope in scopes.items()
            if name.startswith(MCP_SCOPE_PREFIX)
        }
        texts = {
            name.removeprefix(MCP_SCOPE_PREFIX): scope["attributes"]["consent.screen.text"]
            for name, scope in scopes.items()
            if name.startswith(MCP_SCOPE_PREFIX)
        }
        return cls(client["clientId"], client["redirectUris"][0], audiences, texts)


def header_of(jwt: str) -> dict[str, Any]:
    """The header is encoded like the payload, which `token_claims` reads as the second segment."""
    return token_claims(f"x.{jwt.split('.')[0]}")


def without_state(value: Any) -> Any:
    """Drops config-cli's bookkeeping attributes, which change on every import, and the keys that
    never leave (a client's secret), so a difference never prints them."""
    if isinstance(value, dict):
        return {
            key: without_state(item)
            for key, item in value.items()
            if key not in CLIENT.secret and not key.startswith(CONFIG_CLI_STATE)
        }
    if isinstance(value, list):
        return [without_state(item) for item in value]
    return value


def settings(value: Any) -> Any:
    """A representation the observe's way (no ids, sets in order) and without the import's state."""
    return canonical(without_volatile(without_state(value)))


def differences(before: Any, after: Any, path: str = "") -> list[str]:
    """The paths where two representations differ, with both values."""
    if isinstance(before, dict) and isinstance(after, dict):
        return [
            line
            for key in sorted(before.keys() | after.keys())
            for line in differences(before.get(key), after.get(key), f"{path}/{key}")
        ]
    return [] if before == after else [f"{path}: {before!r} -> {after!r}"]


def decoded(access: dict[str, Any]) -> str:
    """The claims a held line shows: no token and no subject."""
    return (
        f"aud {audience_of(access)}, azp {access.get('azp')}, groups {access.get('groups', [])}, "
        f"scope {access.get('scope')!r}, realm_access {'realm_access' in access}, "
        f"resource_access {'resource_access' in access}"
    )


def query_of(answer: Answer) -> dict[str, list[str]]:
    return parse_qs(urlsplit(answer.headers.get("Location", "")).query)


@dataclass
class AgentsClientCell:
    probe: Probe
    expect: Callable[[bool, str], None]
    form_with: Callable[[Any, str], tuple[str, dict[str, str]]]
    app_clients: Sequence[AppClient]
    declared: Declared

    @property
    def admin(self) -> Admin:
        return self.probe.admin

    @property
    def client(self) -> Declared:
        return self.declared

    def unique(self, name: str) -> str:
        """A name proof 7 keeps apart: a repeated name would drop the earlier value it sweeps."""
        return f"{name} {secrets.token_hex(3)}"

    def browser(self, name: str) -> Any:
        return self.probe.browser(self.unique(name))

    def person(self, name: str, *groups: str) -> terms_cell.User:
        password = self.probe.keep_secret(f"{name} password", secrets.token_urlsafe(16))
        user_id = self.admin.create_user(REALM, name, password)
        for group in groups:
            self.admin.join_group(user_id, group)
        return terms_cell.User(user_id, name, password)

    # --- the authorization code flow ------------------------------------------------------------

    def start(
        self, opener: Any, scope: str, *, pkce: bool = True, **changes: str
    ) -> tuple[Answer, str]:
        """The authorization request with S256 (unless `changes` say otherwise); the verifier."""
        verifier = self.probe.keep_secret(
            f"agents PKCE verifier {secrets.token_hex(3)}", secrets.token_urlsafe(48)
        )
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        challenged = {
            "code_challenge": challenge.rstrip(b"=").decode(),
            "code_challenge_method": "S256",
        }
        query = self.probe.app_client_authorization_query(
            self.client, scope=scope, **((challenged if pkce else {}) | changes)
        )
        return self.probe.through_tunnel("GET", f"{AUTH_PATH}?{query}", opener=opener), verifier

    def sign_in(self, opener: Any, who: terms_cell.User, page: Answer) -> Answer:
        action, fields = self.form_with(page, "username")
        answer = self.probe.through_tunnel_url(
            "POST",
            action,
            form=fields | {"username": who.name, "password": who.password},
            opener=opener,
        )
        location = answer.headers.get("Location", "")
        if answer.status == 302 and not location.startswith(self.declared.callback):
            answer = self.probe.through_tunnel_url("GET", location, opener=opener)
        return answer

    def code_of(self, answer: Answer) -> str:
        location = answer.headers.get("Location", "")
        self.expect(
            answer.status == 302 and location.startswith(f"{self.declared.callback}?"),
            f"the answer {answer.status} to {location.partition('?')[0]!r} is no code at "
            f"{self.declared.callback}",
        )
        return self.probe.keep_secret(
            self.unique("agents authorization code"), query_of(answer)["code"][0]
        )

    def consent_button(self, page: Answer, button: str) -> str:
        found = terms_cell.TermsCell(self.probe, self.expect, self.form_with, self.client)
        return found.button_form(page, button)

    def answer_consent(self, opener: Any, page: Answer, button: str) -> Answer:
        action = self.consent_button(page, button)
        return self.probe.through_tunnel("POST", action, form={button: ""}, opener=opener)

    def exchange(self, code: str, verifier: str, **extra: str) -> Answer:
        return self.probe.through_tunnel(
            "POST",
            TOKEN_PATH,
            form={
                "grant_type": "authorization_code",
                "client_id": self.declared.client_id,
                "redirect_uri": self.declared.callback,
                "code": code,
                "code_verifier": verifier,
                **extra,
            },
        )

    def first_page(
        self, who: terms_cell.User, scope: str, **changes: str
    ) -> tuple[Any, Answer, str]:
        """A fresh browser signed in up to the page Keycloak answers with (consent or code)."""
        opener = self.browser(f"agents {who.name}")
        login, verifier = self.start(opener, scope, **changes)
        self.expect(login.status == 200, f"the login page for {who.name} answered {login.status}")
        return opener, self.sign_in(opener, who, login), verifier

    def token_response(self, who: terms_cell.User, scope: str) -> Answer:
        opener, page, verifier = self.first_page(who, scope)
        if page.status == 200:
            page = self.answer_consent(opener, page, "accept")
        return self.exchange(self.code_of(page), verifier)

    def access_of(self, who: terms_cell.User, scope: str) -> dict[str, Any]:
        tokens = self.probe.tokens_from(
            self.unique(f"agents {who.name}"), self.token_response(who, scope)
        )
        return token_claims(tokens["access_token"])

    # --- D: the transition ----------------------------------------------------------------------

    def remove_the_new_objects(self) -> None:
        client_id = self.admin.client(self.declared.client_id)["id"]
        self.admin.must("DELETE", f"/{REALM}/clients/{client_id}")
        for scope in self.admin.get(f"/{REALM}/client-scopes"):
            if scope["name"].startswith(MCP_SCOPE_PREFIX):
                self.admin.must("DELETE", f"/{REALM}/client-scopes/{scope['id']}")
        for app in self.declared.apps:
            path = f"{APPS_GROUP}/{app}/mcp"
            group = self.admin.get(f"/{REALM}/group-by-path{path}")
            self.admin.must("DELETE", f"/{REALM}/groups/{group['id']}")

    def realm_and_app_clients(self) -> dict[str, Any]:
        found = {"realm": settings(self.admin.get(f"/{REALM}"))}
        for client in self.app_clients:
            found[client.client_id] = settings(self.admin.client(client.client_id))
        return found

    def refresh(self, client: AppClient, refresh_token: str) -> Answer:
        return self.probe.through_tunnel(
            "POST",
            TOKEN_PATH,
            form={
                "grant_type": "refresh_token",
                "client_id": client.client_id,
                "client_secret": self.probe.secret_values[client.secret_file],
                "refresh_token": refresh_token,
            },
        )

    def sessions_live_through_the_apply(self) -> None:
        stack = self.probe.stack
        shipped = stack.copy_config(stack.scratch / "config-agents")
        stack.must_apply("shipped apply before the agents cell", config_dir=shipped)
        self.remove_the_new_objects()
        keeper = self.person("probe-agents-keeper", "/apps/hopin", "/apps/songmaker/admin")
        refresh_tokens = {}
        for client in self.app_clients:
            who = self.person(f"probe-agents-{client.client_id}-session", client.group)
            tokens = self.probe.app_client_sign_in(
                client,
                self.browser(f"agents {client.client_id} session"),
                who.name,
                who.password,
                self.probe.secret_values[client.secret_file],
            )
            refresh_tokens[client] = tokens["refresh_token"]
        before = self.realm_and_app_clients()
        memberships = self.admin.group_paths(keeper.id)
        stack.must_apply("shipped apply that adds the agents objects", config_dir=shipped)
        changed = differences(before, self.realm_and_app_clients())
        self.expect(not changed, f"the apply that adds the agents objects changed {changed}")
        self.probe.held(
            "D2",
            f"the realm and the clients {sorted(c.client_id for c in self.app_clients)} read the "
            "same "
            "before and after the apply that adds the agents client, its scopes and groups",
        )
        self.expect(
            self.admin.group_paths(keeper.id) == memberships,
            f"the memberships of the seeded member changed: {self.admin.group_paths(keeper.id)}",
        )
        self.probe.held("D3", f"a member of {memberships} keeps them through that apply")
        for client, token in refresh_tokens.items():
            answers = [self.refresh(client, token), self.refresh(client, token)]
            with ThreadPoolExecutor(max_workers=2) as pool:
                answers += [
                    f.result() for f in [pool.submit(self.refresh, client, token) for _ in "ab"]
                ]
            for answer in answers:
                self.probe.tokens_from(self.unique(f"agents {client.client_id} refresh"), answer)
            self.probe.held(
                "D1",
                f"{client.client_id}: a session signed in before the apply refreshes twice in turn "
                f"and twice at once with one refresh token: {[a.status for a in answers]}",
            )

    # --- B and A -------------------------------------------------------------------------------

    def groups_start_empty(self) -> None:
        for app in self.declared.apps:
            path = f"{APPS_GROUP}/{app}/mcp"
            group = self.admin.get(f"/{REALM}/group-by-path{path}")
            members = self.admin.get(f"/{REALM}/groups/{group['id']}/members")
            self.expect(not members, f"{path} has members {len(members)}")
        self.probe.held(
            "B1", f"{sorted(self.declared.apps)}: each /apps/<app>/mcp exists with no member"
        )

    def tokens_per_app(self) -> dict[str, terms_cell.User]:
        lifespan = self.admin.get(f"/{REALM}")["accessTokenLifespan"]
        members = {}
        for app, audience in self.declared.apps.items():
            who = self.person(f"probe-agents-{app}-member", f"{APPS_GROUP}/{app}/mcp")
            members[app] = who
            scope = f"{MCP_SCOPE_PREFIX}{app} offline_access"
            opener, page, verifier = self.first_page(who, scope, resource=audience)
            first = app == next(iter(self.declared.apps))
            if first:
                self.consent_is_asked(page, app)
            page = self.answer_consent(opener, page, "accept")
            if first:
                self.second_authorization_asks_nothing(opener, scope, audience)
            response = self.exchange(self.code_of(page), verifier, resource=audience)
            tokens = self.probe.tokens_from(f"agents {app} member", response)
            access = token_claims(tokens["access_token"])
            self.expect(
                header_of(tokens["access_token"]).get("typ") == "at+jwt"
                and audience_of(access) == [audience]
                and access.get("azp") == self.declared.client_id
                and access.get("sub")
                and access.get("groups") == [f"{APPS_GROUP}/{app}/mcp"]
                and f"{MCP_SCOPE_PREFIX}{app}" in access.get("scope", "").split()
                and access["exp"] - access["iat"] - lifespan in (0, 1)
                and "realm_access" not in access
                and "resource_access" not in access
                and "refresh_token" not in tokens,
                f"{app}'s agent token: {decoded(access)}; refresh_token in response "
                f"{'refresh_token' in tokens}",
            )
            self.probe.held(
                "A1",
                f"{app}: {decoded(access)}, typ at+jwt, lifespan {lifespan} s, no refresh token",
            )
            self.no_offline_session()
            self.probe.held(
                "B2", f"{app}: a member of {APPS_GROUP}/{app}/mcp alone: groups {access['groups']}"
            )
        return members

    def no_offline_session(self) -> None:
        client_id = self.admin.client(self.declared.client_id)["id"]
        count = self.admin.get(f"/{REALM}/clients/{client_id}/offline-session-count")["count"]
        self.expect(count == 0, f"asking offline_access left {count} offline sessions on agents")
        self.probe.held("A2", "offline_access asked and consented: no offline session is stored")

    def consent_is_asked(self, page: Answer, app: str) -> None:
        text, scope = self.declared.consent_texts[app], f"{MCP_SCOPE_PREFIX}{app}"
        self.expect(
            page.status == 200 and text in page.text and scope not in page.text,
            f"the first sign-in answered {page.status}; the page shows {text!r}: "
            f"{text in page.text}, the scope name instead: {scope in page.text}",
        )
        offline = "ffline" in page.text
        self.probe.held(
            "C1",
            f"the consent page shows {text!r}, not {scope!r}; it lists offline_access: {offline}",
        )

    def second_authorization_asks_nothing(self, opener: Any, scope: str, audience: str) -> None:
        answer, _verifier = self.start(opener, scope, resource=audience)
        self.code_of(answer)
        self.probe.held(
            "C2", "a second authorization in the same SSO session answers a code, no consent page"
        )

    def tokens_without_the_scope_or_with_two(self, members: dict[str, terms_cell.User]) -> None:
        first, second, *_ = self.declared.apps
        both = self.access_of(
            members[first], f"{MCP_SCOPE_PREFIX}{first} {MCP_SCOPE_PREFIX}{second}"
        )
        self.probe.say(
            f"PROOF A3 measured: two mcp scopes in one request give aud {audience_of(both)}"
        )
        plain = self.access_of(members[first], "openid")
        self.expect(
            not any(url in audience_of(plain) for url in self.declared.apps.values()),
            f"a token asked for no mcp scope has aud {audience_of(plain)}",
        )
        self.probe.held("A4", f"no mcp scope: {decoded(plain)}")

    def a_person_without_a_group_and_a_decline(self) -> None:
        app = next(iter(self.declared.apps))
        lone = self.person("probe-agents-lone")
        access = self.access_of(lone, f"{MCP_SCOPE_PREFIX}{app}")
        self.expect(
            not access.get("groups") and audience_of(access) == [self.declared.apps[app]],
            f"a person with no group: {decoded(access)}",
        )
        self.probe.held("B3", f"a person with no group gets a token: {decoded(access)}")
        decliner = self.person("probe-agents-decliner")
        opener, page, _verifier = self.first_page(decliner, f"{MCP_SCOPE_PREFIX}{app}")
        answer = self.answer_consent(opener, page, "cancel")
        error = query_of(answer)
        consents = self.admin.get(f"/{REALM}/users/{decliner.id}/consents")
        self.expect(
            answer.status == 302
            and error.get("error") == ["access_denied"]
            and "code" not in error
            and not consents,
            f"decline answered {answer.status} with error {error.get('error')}, code issued "
            f"{'code' in error}, consents {len(consents)}",
        )
        self.probe.held("C3", "decline: access_denied, no code, no stored consent")

    def another_apps_scope_asks_again(self, members: dict[str, terms_cell.User]) -> None:
        """Measured on the last app's member, who consented to that app's scope alone."""
        (other, *_), last = list(self.declared.apps), list(self.declared.apps)[-1]
        opener, page, _verifier = self.first_page(members[last], f"{MCP_SCOPE_PREFIX}{last}")
        self.code_of(page)
        again, _ = self.start(opener, f"{MCP_SCOPE_PREFIX}{other}")
        page = (
            self.probe.through_tunnel_url("GET", again.headers["Location"], opener=opener)
            if again.status == 302 and not query_of(again).get("code")
            else again
        )
        asked = 'name="accept"' in page.text
        self.probe.say(
            f"PROOF C4 measured: after consent to {last}, the scope of {other} in the same "
            f"session meets the consent page again: {asked}"
        )

    def refusals(self) -> None:
        wrong_methods = {
            "no challenge": {"pkce": False},
            "plain": {"code_challenge_method": "plain"},
        }
        for label, changes in wrong_methods.items():
            answer, _ = self.start(self.browser("agents A5"), "openid", **changes)
            error = query_of(answer)
            self.expect(
                answer.status == 302 and "error" in error and "code" not in error,
                f"PKCE {label} answered {answer.status} with error "
                f"{error.get('error')}, code issued {'code' in error}",
            )
        self.probe.held(
            "A5", "an authorization request without PKCE or with plain is refused, no code"
        )
        callback = urlsplit(self.declared.callback)
        for redirect in (
            callback._replace(netloc=f"localhost:{callback.port + 1}").geturl(),
            callback._replace(path="/other").geturl(),
            callback._replace(netloc=f"127.0.0.1:{callback.port}").geturl(),
            callback._replace(netloc=f"example.invalid:{callback.port}").geturl(),
        ):
            answer, _ = self.start(self.browser("agents A6"), "openid", redirect_uri=redirect)
            self.expect(
                answer.status == 400 and "Invalid parameter: redirect_uri" in answer.text,
                f"redirect_uri {redirect} answered {answer.status}",
            )
        self.probe.held(
            "A6", "another port, another path, the 127.0.0.1 form and a foreign host are refused"
        )
        self.other_grants_are_refused()

    def other_grants_are_refused(self) -> None:
        name = self.declared.client_id
        member = self.person("probe-agents-grant")
        grants = {
            "password": {
                "grant_type": "password",
                "username": member.name,
                "password": member.password,
            },
            "client_credentials": {"grant_type": "client_credentials"},
        }
        for label, form in grants.items():
            refused = self.probe.through_tunnel(
                "POST", TOKEN_PATH, form={"client_id": name, **form}
            )
            error = refused.json().get("error") if refused.status in (400, 401) else None
            self.expect(
                error == "unauthorized_client" and "access_token" not in refused.text,
                f"{label} on {name} answered {refused.status} with error {error}",
            )
        device = self.probe.through_tunnel("POST", DEVICE_PATH, form={"client_id": name})
        self.expect(
            device.status in (400, 401) and "device_code" not in device.text,
            f"device grant answered {device.status}",
        )
        implicit, _ = self.start(self.browser("agents A7"), "openid", response_type="token")
        self.expect(
            "access_token" not in implicit.headers.get("Location", "")
            and implicit.status in (302, 400),
            f"implicit answered {implicit.status}",
        )
        self.probe.held("A7", "password, device, implicit and client_credentials are refused")

    def registration_and_scope_crossing(self) -> None:
        before = [c["clientId"] for c in self.admin.get(f"/{REALM}/clients")]
        refused = self.probe.through_tunnel(
            "POST", REGISTRATION_PATH, json_body={"redirect_uris": ["http://localhost:1/x"]}
        )
        after = [c["clientId"] for c in self.admin.get(f"/{REALM}/clients")]
        self.expect(
            400 <= refused.status < 500 and before == after,
            f"client registration answered {refused.status}; clients unchanged {before == after}",
        )
        self.probe.held(
            "A8",
            f"anonymous client registration through the edge: {refused.status}, list unchanged",
        )
        app = self.app_clients[0]
        for client_id, scope in (
            (app.client_id, f"openid {MCP_SCOPE_PREFIX}{next(iter(self.declared.apps))}"),
            (self.declared.client_id, "openid agent-service-audience"),
            (self.declared.client_id, "openid speech-service-audience"),
        ):
            query = self.probe.app_client_authorization_query(
                app if client_id == app.client_id else self.client,
                scope=scope,
                code_challenge="x" * 43,
                code_challenge_method="S256",
            )
            answer = self.probe.through_tunnel("GET", f"{AUTH_PATH}?{query}")
            self.expect(
                answer.status == 302 and query_of(answer).get("error") == ["invalid_scope"],
                f"{client_id} asking {scope!r} answered {answer.status} with error "
                f"{query_of(answer).get('error')}",
            )
        self.probe.held(
            "A9",
            "an app client asking an mcp scope and agents asking a service audience: invalid_scope",
        )

    def discovery_and_spoofed_hosts(self) -> None:
        plain = self.probe.through_tunnel("GET", DISCOVERY_PATH)
        forged = self.probe.through_tunnel(
            "GET", DISCOVERY_PATH, headers={"X-Forwarded-Host": INTERNAL_HOST}
        )
        document = plain.json()
        self.expect(
            plain.status == 200
            and "S256" in document["code_challenge_methods_supported"]
            and "offline_access" in document["scopes_supported"]
            and forged.json()["issuer"] == document["issuer"],
            f"discovery answered {plain.status}; forged-host issuer {forged.json()['issuer']}",
        )
        inserted = [self.probe.through_tunnel("GET", path).status for path in INSERTED_DISCOVERY]
        self.expect(inserted == [404, 404], f"the inserted discovery forms answered {inserted}")
        self.probe.held(
            "A10",
            "the appended discovery answers with S256 and offline_access; the inserted forms are "
            "404; the issuer ignores X-Forwarded-Host",
        )
        by_host = self.probe.through_tunnel("GET", "/mcp", host=INTERNAL_HOST)
        by_header = self.probe.through_tunnel(
            "GET", "/mcp", headers={"X-Forwarded-Host": INTERNAL_HOST}
        )
        self.expect(
            (by_host.status, by_header.status) == (404, 404),
            f"/mcp answered {by_host.status} for the internal Host and {by_header.status} for a "
            "forged X-Forwarded-Host",
        )
        self.probe.held(
            "E1",
            "/mcp with the internal Host, or a forged X-Forwarded-Host: 404 at the edge",
        )


def prove(
    probe: Probe,
    expect: Callable[[bool, str], None],
    form_with: Callable[[Any, str], tuple[str, dict[str, str]]],
    current: AppClient,
    app_clients: Sequence[AppClient],
) -> None:
    """Runs once, after proof 10 has signed in to the last app client."""
    if current != app_clients[-1]:
        return
    cell = AgentsClientCell(probe, expect, form_with, app_clients, Declared.read())
    cell.sessions_live_through_the_apply()
    cell.groups_start_empty()
    members = cell.tokens_per_app()
    cell.tokens_without_the_scope_or_with_two(members)
    cell.a_person_without_a_group_and_a_decline()
    cell.another_apps_scope_asks_again(members)
    cell.refusals()
    cell.registration_and_scope_crossing()
    cell.discovery_and_spoofed_hosts()
