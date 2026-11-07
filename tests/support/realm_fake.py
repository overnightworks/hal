"""A fake Keycloak 26.8.1 admin API for the realm observer's tests (#66): the realms it
serves, the faults it injects, and the server that runs it."""

import json
import os
import re
import signal
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, unquote, urlsplit

from hal.stack.realm import new_digest_key

SECRET = "the-config-cli-secret"
TOKEN = "an-access-token-from-the-fake"
REFUSAL_BODY = "invalid_client: the reply body the observer must not print"
KEY = new_digest_key()
# The public issuer the fake's discovery documents name, as Keycloak's KC_HOSTNAME makes it.
PUBLIC_ORIGIN = "https://auth.hallucinai.test"
DISCOVERY = re.compile(r"/realms/([^/]+)/\.well-known/openid-configuration")
# Values the observer reads but must never let out (rule 4).
PLANTED = {
    "client secret": "planted-client-secret",
    "registration access token": "planted-registration-token",
    "rotated secret": "planted-rotated-secret",
    "saml private key": "planted-saml-private-key",
    "idp client secret": "planted-idp-client-secret",
    "smtp password": "planted-smtp-password",
    "component config": "planted-component-key",
    "unlisted client attribute": "planted-unlisted-attribute-value",
}


def uid(*parts: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "/".join(parts)))


# --- Representations as Keycloak 26.8.1 answers them ---------------------------------------


def realm_rep(name: str) -> dict[str, Any]:
    return {
        "id": uid(name),
        "realm": name,
        "enabled": True,
        "sslRequired": "external",
        "accessTokenLifespan": 300 if name == "hallucinai" else 60,
        "ssoSessionIdleTimeout": 604800,
        "ssoSessionMaxLifespan": 2592000,
        "bruteForceProtected": True,
        "failureFactor": 30,
        "eventsEnabled": True,
        "eventsListeners": ["jboss-logging"],
        "eventsExpiration": 7776000,
        "enabledEventTypes": ["LOGIN", "LOGIN_ERROR"],
        "adminEventsEnabled": True,
        "browserFlow": "browser-mfa" if name == "master" else "browser",
        "directGrantFlow": "direct-grant-mfa" if name == "master" else "direct grant",
        "webAuthnPolicyRpId": "localhost" if name == "master" else "hallucinai.de",
        "notBefore": 0,
        "defaultRole": {"id": uid(name, "default-roles"), "name": f"default-roles-{name}"},
        "smtpServer": {"host": "smtp.invalid", "port": "587", "password": PLANTED["smtp password"]},
        "browserSecurityHeaders": {"xFrameOptions": "SAMEORIGIN"},
        "attributes": {
            "frontendUrl": "http://localhost:8090" if name == "master" else "",
            "adminEventsExpiration": "31536000",
            "de.adorsys.keycloak.config.import-checksum-default": "a-checksum",
            "cibaInterval": "5",
        },
    }


def mapper_rep(owner: str, name: str, mapper: str, **config: str) -> dict[str, Any]:
    return {
        "id": uid(owner, name),
        "name": name,
        "protocol": "openid-connect",
        "protocolMapper": mapper,
        "consentRequired": False,
        "config": config,
    }


def client_rep(realm: str, client_id: str, **changes: Any) -> dict[str, Any]:
    return {
        "id": uid(realm, client_id),
        "clientId": client_id,
        "name": client_id,
        "surrogateAuthRequired": False,
        "enabled": True,
        "alwaysDisplayInConsole": False,
        "clientAuthenticatorType": "client-secret",
        "secret": PLANTED["client secret"],
        "registrationAccessToken": PLANTED["registration access token"],
        "redirectUris": ["https://b.invalid/cb", "https://a.invalid/cb"],
        "webOrigins": [],
        "notBefore": 0,
        "bearerOnly": False,
        "consentRequired": False,
        "standardFlowEnabled": False,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "publicClient": False,
        "frontchannelLogout": False,
        "protocol": "openid-connect",
        "attributes": {
            "post.logout.redirect.uris": "+",
            "client.secret.creation.time": "1760000000",
            "client.secret.rotated": PLANTED["rotated secret"],
            "saml.signing.private.key": PLANTED["saml private key"],
            "probe.unlisted": PLANTED["unlisted client attribute"],
        },
        "authenticationFlowBindingOverrides": {},
        "fullScopeAllowed": True,
        "nodeReRegistrationTimeout": -1,
        "protocolMappers": [],
        "defaultClientScopes": ["web-origins", "acr", "profile", "roles", "basic", "email"],
        "optionalClientScopes": ["address", "phone", "offline_access", "microprofile-jwt"],
        "access": {"view": True, "configure": True, "manage": True},
        **changes,
    }


def role_rep(realm: str, container: str, name: str, *, client: bool = False) -> dict[str, Any]:
    return {
        "id": uid(realm, container, name),
        "name": name,
        "description": f"${{role_{name}}}",
        "composite": False,
        "clientRole": client,
        "containerId": uid(realm, container) if client else uid(realm),
        "attributes": {},
    }


def step_rep(
    realm: str, flow: str, level: int, index: int, *, authenticator: str = "", sub_flow: str = ""
) -> dict[str, Any]:
    step = {
        "id": uid(realm, flow, str(level), str(index), authenticator or sub_flow),
        "requirement": "REQUIRED",
        "displayName": sub_flow or authenticator.replace("-", " ").title(),
        "requirementChoices": ["REQUIRED", "ALTERNATIVE", "DISABLED"],
        "configurable": False,
        "level": level,
        "index": index,
        "priority": (index + 1) * 10,
    }
    if sub_flow:
        step |= {
            "authenticationFlow": True,
            "description": f"the {sub_flow} sub-flow",
            "providerId": "basic-flow",
            "flowId": uid(realm, sub_flow),
        }
    else:
        step |= {"authenticationFlow": False, "providerId": authenticator}
    return step


def user_rep(realm: str, username: str, client_id: str) -> dict[str, Any]:
    return {
        "id": uid(realm, username),
        "username": username,
        "emailVerified": False,
        "createdTimestamp": 1760000000000,
        "enabled": True,
        "totp": False,
        "serviceAccountClientId": client_id,
        "disableableCredentialTypes": [],
        "requiredActions": [],
        "notBefore": 0,
        "access": {"manage": True},
    }


@dataclass
class Group:
    members: list[str] = field(default_factory=list)
    realm_roles: list[str] = field(default_factory=list)


@dataclass
class FakeRealm:
    """One realm's state, from which the fake answers every admin endpoint."""

    name: str
    realm: dict[str, Any]
    groups: dict[str, Group] = field(default_factory=dict)
    roles: list[dict[str, Any]] = field(default_factory=list)
    composites: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    clients: list[dict[str, Any]] = field(default_factory=list)
    client_roles: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    service_accounts: dict[str, dict[str, Any]] = field(default_factory=dict)
    role_mappings: dict[str, dict[str, Any]] = field(default_factory=dict)
    user_groups: dict[str, list[str]] = field(default_factory=dict)
    client_scopes: list[dict[str, Any]] = field(default_factory=list)
    default_scopes: list[str] = field(default_factory=list)
    optional_scopes: list[str] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)
    executions: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    configs: dict[str, dict[str, Any]] = field(default_factory=dict)
    required_actions: list[dict[str, Any]] = field(default_factory=list)
    providers: list[dict[str, Any]] = field(default_factory=list)
    provider_mappers: dict[str, list[dict[str, Any]]] = field(default_factory=dict)
    components: list[dict[str, Any]] = field(default_factory=list)

    def group_rep(self, path: str) -> dict[str, Any]:
        group = self.groups[path]
        children = self.children_of(path)
        return {
            "id": uid(self.name, "group", path),
            "name": path.rsplit("/", 1)[1],
            "path": path,
            "parentId": uid(self.name, "group", path.rsplit("/", 1)[0]),
            "subGroupCount": len(children),
            "subGroups": [],
            "attributes": {},
            "realmRoles": group.realm_roles,
            "clientRoles": {},
            "access": {"view": True, "manage": True},
        }

    def children_of(self, parent: str) -> list[str]:
        return [path for path in self.groups if path.rsplit("/", 1)[0] == parent]


HALLUCINAI_GROUPS = (
    "/apps",
    "/apps/songmaker",
    "/apps/presentator",
    "/apps/hopin",
    "/apps/hopin/admin",
    "/services",
    "/services/agent-service",
    "/services/agent-service/api",
    "/services/litellm",
    "/services/litellm/admin",
)


def hallucinai() -> FakeRealm:
    realm = FakeRealm("hallucinai", realm_rep("hallucinai"))
    realm.groups = {path: Group() for path in HALLUCINAI_GROUPS}
    realm.groups["/apps/hopin"].members = [uid("hallucinai", "anna"), uid("hallucinai", "ben")]
    realm.roles = [role_rep("hallucinai", "", name) for name in ("offline_access", "uma")]
    speech = client_rep("hallucinai", "speech-service", bearerOnly=True)
    speech["protocolMappers"] = [
        mapper_rep(
            "speech-service", "audience", "oidc-audience-mapper", **{"access.token.claim": "true"}
        )
    ]
    realm.clients = [speech, client_rep("hallucinai", "account", publicClient=True)]
    realm.client_roles = {
        speech["id"]: [role_rep("hallucinai", "speech-service", "use", client=True)]
    }
    groups_scope = {
        "id": uid("hallucinai", "scope", "groups"),
        "name": "groups",
        "description": "The user's groups as full paths",
        "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        "protocolMappers": [
            mapper_rep(
                "groups",
                "groups",
                "oidc-group-membership-mapper",
                **{"claim.name": "groups", "full.path": "true"},
            )
        ],
    }
    realm.client_scopes = [groups_scope]
    realm.default_scopes = ["groups"]
    realm.flows = [
        {
            "id": uid("hallucinai", "browser"),
            "alias": "browser",
            "description": "Browser based authentication",
            "providerId": "basic-flow",
            "topLevel": True,
            "builtIn": True,
            "authenticationExecutions": [],
        }
    ]
    realm.executions = {
        "browser": [step_rep("hallucinai", "browser", 0, 0, authenticator="auth-cookie")]
    }
    realm.required_actions = [
        {
            "alias": "CONFIGURE_TOTP",
            "name": "Configure OTP",
            "providerId": "CONFIGURE_TOTP",
            "enabled": True,
            "defaultAction": False,
            "priority": 10,
            "config": {},
        }
    ]
    realm.providers = [
        {
            "alias": "console-idp",
            "internalId": uid("hallucinai", "idp"),
            "providerId": "oidc",
            "enabled": True,
            "trustEmail": False,
            "config": {"clientId": "edge", "clientSecret": PLANTED["idp client secret"]},
        }
    ]
    realm.provider_mappers = {
        "console-idp": [
            {
                "id": uid("hallucinai", "idp-mapper"),
                "name": "email",
                "identityProviderAlias": "console-idp",
                "identityProviderMapper": "oidc-user-attribute-idp-mapper",
                "config": {"claim": "email", "syncMode": "INHERIT"},
            }
        ]
    }
    realm.components = [
        component("hallucinai", "rsa-generated", "org.keycloak.keys.KeyProvider", "rsa-generated"),
        component(
            "hallucinai",
            "Allowed Client Scopes",
            "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
            "allowed-client-templates",
            sub_type="anonymous",
        ),
        component(
            "hallucinai",
            "Allowed Client Scopes",
            "org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy",
            "allowed-client-templates",
            sub_type="authenticated",
        ),
    ]
    return realm


def component(
    realm: str, name: str, provider_type: str, provider_id: str, *, sub_type: str = ""
) -> dict[str, Any]:
    rep = {
        "id": uid(realm, provider_type, name, sub_type),
        "name": name,
        "providerId": provider_id,
        "providerType": provider_type,
        "parentId": uid(realm),
        "config": {"privateKey": [PLANTED["component config"]]},
    }
    return rep | ({"subType": sub_type} if sub_type else {})


def master() -> FakeRealm:
    realm = FakeRealm("master", realm_rep("master"))
    admin = role_rep("master", "", "admin")
    admin["composite"] = True
    realm.roles = [admin, role_rep("master", "", "create-realm")]
    config_cli = client_rep("master", "config-cli", serviceAccountsEnabled=True)
    realm_management = client_rep("master", "hallucinai-realm")
    realm.clients = [config_cli, realm_management]
    manage = role_rep("master", "hallucinai-realm", "manage-realm", client=True)
    realm.client_roles = {realm_management["id"]: [manage]}
    realm.composites = {admin["id"]: [role_rep("master", "", "create-realm"), manage]}
    account = user_rep("master", "service-account-config-cli", "config-cli")
    realm.service_accounts = {config_cli["id"]: account}
    realm.role_mappings = {
        account["id"]: {
            "realmMappings": [
                role_rep("master", "", "admin"),
                role_rep("master", "", "default-roles-master"),
            ]
        }
    }
    realm.flows = [
        {
            "id": uid("master", "browser-mfa"),
            "alias": "browser-mfa",
            "description": "Password plus a required second factor",
            "providerId": "basic-flow",
            "topLevel": True,
            "builtIn": False,
            "authenticationExecutions": [],
        }
    ]
    without_passkey = {
        "id": uid("master", "config", "browser-mfa-without-passkey"),
        "alias": "browser-mfa-without-passkey",
        "config": {"flow_to_check": "browser-mfa-passkey", "check_result": "not-executed"},
    }
    realm.configs = {without_passkey["id"]: without_passkey}
    conditional = step_rep(
        "master", "browser-mfa", 2, 0, authenticator="conditional-sub-flow-executed"
    )
    conditional |= {
        "authenticationConfig": without_passkey["id"],
        "alias": without_passkey["alias"],
    }
    realm.executions = {
        "browser-mfa": [
            step_rep("master", "browser-mfa", 0, 0, authenticator="auth-cookie"),
            step_rep("master", "browser-mfa", 0, 1, sub_flow="browser-mfa-forms"),
            step_rep("master", "browser-mfa", 1, 0, authenticator="auth-username-password-form"),
            step_rep("master", "browser-mfa", 1, 1, sub_flow="browser-mfa-totp"),
            conditional,
            step_rep("master", "browser-mfa", 2, 1, authenticator="auth-otp-form"),
        ]
    }
    return realm


def keycloak_realms() -> dict[str, FakeRealm]:
    return {"master": master(), "hallucinai": hallucinai()}


# --- The fake admin API ---------------------------------------------------------------------


@dataclass
class Faults:
    token_status: int = 200
    status: dict[str, int] = field(default_factory=dict)  # path -> status, every time
    delay: dict[str, float] = field(default_factory=dict)  # path -> seconds
    unauthorized_after: int | None = None  # 401 for the GET after this many GETs
    unauthorized_times: int = 1
    truncate_children: bool = False
    redirect: dict[str, str] = field(default_factory=dict)  # path -> Location
    not_json: set[str] = field(default_factory=set)  # paths answered 200 with a non-JSON body
    first_page_again: set[str] = field(default_factory=set)  # paths whose every page is the first
    stop: dict[str, signal.Signals] = field(default_factory=dict)  # path -> signal once answered


class FakeKeycloak(ThreadingHTTPServer):
    def __init__(self) -> None:
        super().__init__(("127.0.0.1", 0), AdminApi)
        self.realms = keycloak_realms()
        self.faults = Faults()
        self.requests: list[tuple[str, str]] = []
        self.authorizations: list[str | None] = []  # each request's Authorization header
        self.gets = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.server_port}"


def paged(items: list[Any], query: dict[str, list[str]]) -> list[Any]:
    first = int(query.get("first", ["0"])[0])
    count = int(query.get("max", ["100"])[0])
    return items[first : first + count]


class AdminApi(BaseHTTPRequestHandler):
    server: FakeKeycloak

    def parse_request(self) -> bool:
        """Records every request before dispatch, so the read-only test sees any method, even
        one without a handler that the base class answers 501."""
        parsed = super().parse_request()
        if parsed:
            self.server.requests.append((self.command, unquote(urlsplit(self.path).path)))
            self.server.authorizations.append(self.headers.get("Authorization"))
        return parsed

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers["Content-Length"]))
        if self.server.faults.token_status != 200:
            self.reply({"error": REFUSAL_BODY}, self.server.faults.token_status)
        else:
            self.reply({"access_token": TOKEN, "expires_in": 60})

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        path, query = unquote(split.path), parse_qs(split.query)
        if discovery := DISCOVERY.fullmatch(path):
            return self.discovery(path, discovery[1])
        faults = self.server.faults
        self.server.gets += 1
        expired = (
            faults.unauthorized_after is not None and self.server.gets > faults.unauthorized_after
        )
        if expired and faults.unauthorized_times:
            faults.unauthorized_times -= 1
            return self.reply({"error": "token expired"}, 401)
        if self.headers["Authorization"] != f"Bearer {TOKEN}":
            return self.reply({"error": "no token"}, 401)
        time.sleep(faults.delay.get(path, 0))
        if path in faults.first_page_again:
            query.pop("first", None)
        if path in faults.not_json:
            return self.reply_raw(200, b"<html>not JSON</html>")
        if path in faults.redirect:
            self.send_response(302)
            self.send_header("Location", faults.redirect[path])
            self.send_header("Content-Length", "0")
            return self.end_headers()
        if path in faults.status:
            return self.reply({"error": "server error"}, faults.status[path])
        _, _, _, realm_name, *rest = path.split("/")
        answer = self.answer(self.server.realms[realm_name], "/" + "/".join(rest), query)
        if answer is None:
            return self.reply({"error": "not found"}, 404)
        self.reply(answer)
        # After the reply, so the observer's abandoned connection never breaks the fake's write.
        if path in faults.stop:
            os.kill(os.getpid(), faults.stop[path])

    def discovery(self, path: str, realm: str) -> None:
        """A realm's public OpenID document, which Keycloak serves without a token."""
        if path in self.server.faults.status:
            return self.reply({"error": "server error"}, self.server.faults.status[path])
        return self.reply({"issuer": f"{PUBLIC_ORIGIN}/realms/{realm}"})

    def refuse_a_write(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.reply({"error": "method not allowed"}, 405)

    do_PUT = do_DELETE = do_PATCH = refuse_a_write

    def answer(self, realm: FakeRealm, path: str, query: dict[str, list[str]]) -> Any:
        groups_by_id = {uid(realm.name, "group", path): path for path in realm.groups}
        parts = path.strip("/").split("/")
        match parts:
            case [""]:
                return realm.realm
            case ["groups", "count"]:
                return {"count": len(realm.children_of(""))}
            case ["groups"]:
                return paged([realm.group_rep(p) for p in realm.children_of("")], query)
            case ["groups", group_id, "children"]:
                children = [realm.group_rep(p) for p in realm.children_of(groups_by_id[group_id])]
                if self.server.faults.truncate_children:
                    children = children[:-1]
                return paged(children, query)
            case ["groups", group_id, "members"]:
                members = realm.groups[groups_by_id[group_id]].members
                return paged([{"id": member, "username": member} for member in members], query)
            case ["roles"]:
                return paged(realm.roles, query)
            case ["roles-by-id", role_id, "composites"]:
                return realm.composites.get(role_id, [])
            case ["clients"]:
                return paged(realm.clients, query)
            case ["clients", client_uuid, "roles"]:
                return paged(realm.client_roles.get(client_uuid, []), query)
            case ["clients", client_uuid, "service-account-user"]:
                return realm.service_accounts[client_uuid]
            case ["users", user_id, "role-mappings"]:
                return realm.role_mappings.get(user_id, {})
            case ["users", user_id, "groups"]:
                return paged(
                    [{"id": p, "path": p} for p in realm.user_groups.get(user_id, [])], query
                )
            case ["client-scopes"]:
                return realm.client_scopes
            case ["default-default-client-scopes"]:
                return [{"id": uid(name), "name": name} for name in realm.default_scopes]
            case ["default-optional-client-scopes"]:
                return [{"id": uid(name), "name": name} for name in realm.optional_scopes]
            case ["authentication", "flows"]:
                return realm.flows
            case ["authentication", "flows", alias, "executions"]:
                return realm.executions[alias]
            case ["authentication", "config", config_id]:
                return realm.configs[config_id]
            case ["authentication", "required-actions"]:
                return realm.required_actions
            case ["identity-provider", "instances"]:
                return paged(realm.providers, query)
            case ["identity-provider", "instances", alias, "mappers"]:
                return realm.provider_mappers.get(alias, [])
            case ["components"]:
                return realm.components
        return None

    def reply(self, body: Any, status: int = 200) -> None:
        self.reply_raw(status, json.dumps(body).encode())

    def reply_raw(self, status: int, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_: object) -> None:
        pass


@contextmanager
def serving() -> Iterator[FakeKeycloak]:
    server = FakeKeycloak()
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()
