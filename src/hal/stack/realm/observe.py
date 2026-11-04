"""The realm observer: reads the master and hallucinai realms through the admin API, read-only.

It runs inside the `realm-observer` compose service (compose.yaml), standard library only, so it
imports with `python -I` and nothing beside it:

    printf '%s\\n' "$DIGEST_KEY_HEX" | docker compose run -T --rm --no-deps realm-observer

The service's entrypoint carries `--base-url http://keycloak:8080`.

It signs in once as `config-cli` (client credentials, the secret from a file), sends GET only to
`/admin/realms/...`, and prints one JSON inventory to stdout: per realm, per type, every object
by its identity (never its UUID) with its allow-listed fields. Any other key of a representation
leaves only as its name plus an HMAC-SHA256 digest under the per-run key the host writes to
stdin, so a change in it still shows; the named secret keys never leave, not even as a digest.
A failure is one line on stderr naming the status and the path, never a reply body or a token,
and stdout stays empty. A stop by SIGINT or SIGTERM exits 130; sent to `compose run`, it ends
compose at once, which stops relaying the container's output, so stdout may hold the start of
an inventory, which never parses. Stdout is an inventory only when the exit is 0.

`--import-checksums` prints `{realm: {attribute: value}}` instead: the realms'
`de.adorsys.keycloak.config.import-checksum…` attributes, and nothing else. It reads no
inventory and needs no digest key, so a console name that breaks the inventory cannot block it.

`--members PATH` prints hallucinai's issuer, from its discovery document (the one GET sent with
no token), and the ids of the group's direct members; a group that does not exist fails.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import signal
import sys
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TextIO
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PEOPLE_REALM = "hallucinai"
REALMS = ("master", PEOPLE_REALM)
CLIENT_ID = "config-cli"
TOKEN_PATH = "/realms/master/protocol/openid-connect/token"  # noqa: S105 - an OpenID endpoint path and no credential
ADMIN_PATH = "/admin/realms"
PAGE = 100
REQUEST_SECONDS = 15.0
# compose.yaml mounts the config-cli secret here; a fixed path, never one an argument names.
SECRET_FILE = Path("/run/secrets/config_cli_secret")
# config-cli's own checksum and state attributes change on every apply that writes them.
CONFIG_CLI_STATE = "de.adorsys.keycloak.config"
IMPORT_CHECKSUM = f"{CONFIG_CLI_STATE}.import-checksum"  # keycloak-config-cli writes it last
# UUIDs and the caller's own permissions: never an identity, never compared.
VOLATILE = frozenset({"id", "containerId", "parentId", "flowId", "internalId", "access"})

Representation = Mapping[str, Any]
Entity = dict[str, dict[str, Any]]
Inventory = dict[str, dict[str, dict[str, Entity]]]


class ObserveError(Exception):
    """The observe failed; the message is one line without a reply body, a token or a secret."""


# --- Allow-lists ------------------------------------------------------------------------------


@dataclass(frozen=True)
class MapShape:
    """A free-form map (attributes, config): which keys print, which never leave."""

    allowed: frozenset[str] = frozenset()
    secret: re.Pattern[str] | None = None
    all_secret: bool = False

    def is_secret(self, key: str) -> bool:
        return self.all_secret or bool(self.secret and self.secret.search(key))


@dataclass(frozen=True)
class Shape:
    """One representation's allow-list. A required field that is missing fails the observe; an
    optional one that is missing is null (Keycloak leaves out empty fields). `elsewhere` names
    the keys another read covers; `secret` the keys that never leave."""

    name: str
    required: frozenset[str]
    optional: frozenset[str] = frozenset()
    maps: Mapping[str, MapShape] = field(default_factory=dict)
    elsewhere: frozenset[str] = frozenset()
    secret: frozenset[str] = frozenset()

    @property
    def listed(self) -> frozenset[str]:
        return self.required | self.optional


def shape(
    name: str,
    required: str,
    optional: str = "",
    *,
    maps: Mapping[str, MapShape] | None = None,
    elsewhere: str = "",
    secret: str = "",
) -> Shape:
    return Shape(name, keys(required), keys(optional), maps or {}, keys(elsewhere), keys(secret))


def keys(names: str) -> frozenset[str]:
    return frozenset(names.split())


SMTP = MapShape(
    keys("host port from fromDisplayName replyTo replyToDisplayName ssl starttls auth user"),
    secret=re.compile(r"^password$"),
)
REALM_ATTRIBUTES = MapShape(keys("frontendUrl adminEventsExpiration"))
REALM = shape(
    "realm",
    "realm enabled",
    """displayName displayNameHtml sslRequired registrationAllowed registrationEmailAsUsername
    rememberMe verifyEmail loginWithEmailAllowed duplicateEmailsAllowed resetPasswordAllowed
    editUsernameAllowed bruteForceProtected permanentLockout maxTemporaryLockouts
    maxFailureWaitSeconds minimumQuickLoginWaitSeconds waitIncrementSeconds
    quickLoginCheckMilliSeconds maxDeltaTimeSeconds failureFactor accessTokenLifespan
    accessTokenLifespanForImplicitFlow ssoSessionIdleTimeout ssoSessionMaxLifespan
    ssoSessionIdleTimeoutRememberMe ssoSessionMaxLifespanRememberMe offlineSessionIdleTimeout
    offlineSessionMaxLifespanEnabled offlineSessionMaxLifespan clientSessionIdleTimeout
    clientSessionMaxLifespan accessCodeLifespan accessCodeLifespanUserAction
    accessCodeLifespanLogin actionTokenGeneratedByAdminLifespan
    actionTokenGeneratedByUserLifespan revokeRefreshToken refreshTokenMaxReuse
    defaultSignatureAlgorithm eventsEnabled eventsExpiration eventsListeners enabledEventTypes
    adminEventsEnabled adminEventsDetailsEnabled browserFlow registrationFlow directGrantFlow
    resetCredentialsFlow clientAuthenticationFlow dockerAuthenticationFlow firstBrokerLoginFlow
    passwordPolicy otpPolicyType otpPolicyAlgorithm otpPolicyDigits otpPolicyPeriod
    otpPolicyLookAheadWindow otpPolicyInitialCounter otpPolicyCodeReusable webAuthnPolicyRpId
    webAuthnPolicyRpEntityName webAuthnPolicySignatureAlgorithms
    webAuthnPolicyUserVerificationRequirement webAuthnPolicyPasswordlessRpId
    webAuthnPolicyPasswordlessRpEntityName webAuthnPolicyPasswordlessPasskeysEnabled
    webAuthnPolicyPasswordlessUserVerificationRequirement
    loginTheme accountTheme adminTheme emailTheme internationalizationEnabled supportedLocales
    defaultLocale organizationsEnabled smtpServer attributes""",
    maps={"smtpServer": SMTP, "attributes": REALM_ATTRIBUTES},
    elsewhere="""users clients groups roles defaultGroups clientScopes defaultDefaultClientScopes
    defaultOptionalClientScopes identityProviders identityProviderMappers components
    authenticationFlows authenticatorConfig requiredActions""",
)
GROUP = shape(
    "group",
    "name path subGroupCount",
    "realmRoles clientRoles attributes",
    maps={"attributes": MapShape()},
    elsewhere="subGroups",
)
ROLE = shape(
    "role",
    "name composite",
    "description attributes",
    maps={"attributes": MapShape()},
    elsewhere="composites clientRole",
)
REALM_ROLE = "realm role"
CLIENT_ROLE = "client role"
CLIENT_ATTRIBUTES = MapShape(
    keys(
        """post.logout.redirect.uris pkce.code.challenge.method backchannel.logout.url
        backchannel.logout.session.required backchannel.logout.revoke.offline.tokens
        frontchannel.logout.url frontchannel.logout.session.required access.token.lifespan
        client.session.idle.timeout client.session.max.lifespan use.refresh.tokens
        oauth2.device.authorization.grant.enabled oidc.ciba.grant.enabled
        display.on.consent.screen consent.screen.text login_theme
        standard.token.exchange.enabled"""
    ),
    secret=re.compile(r"^client\.secret\.rotated$|^saml\..*private\.key"),
)
CLIENT = shape(
    "client",
    "clientId enabled",
    """name description protocol publicClient bearerOnly consentRequired standardFlowEnabled
    implicitFlowEnabled directAccessGrantsEnabled serviceAccountsEnabled frontchannelLogout
    fullScopeAllowed rootUrl baseUrl adminUrl redirectUris webOrigins clientAuthenticatorType
    alwaysDisplayInConsole surrogateAuthRequired authorizationServicesEnabled
    defaultClientScopes optionalClientScopes attributes""",
    maps={"attributes": CLIENT_ATTRIBUTES},
    elsewhere="protocolMappers",
    secret="secret registrationAccessToken",  # noqa: S106 - names the realm export fields that hold a secret and holds none
)
MAPPER_CONFIG = MapShape(
    keys(
        """claim.name jsonType.label id.token.claim access.token.claim userinfo.token.claim
        introspection.token.claim lightweight.claim full.path multivalued
        included.client.audience included.custom.audience user.attribute claim.value
        usermodel.realmRoleMapping.rolePrefix usermodel.clientRoleMapping.clientId"""
    )
)
PROTOCOL_MAPPER = shape(
    "protocol mapper",
    "name protocol protocolMapper",
    "consentRequired config",
    maps={"config": MAPPER_CONFIG},
)
SCOPE_ATTRIBUTES = MapShape(
    keys("include.in.token.scope display.on.consent.screen consent.screen.text gui.order")
)
CLIENT_SCOPE = shape(
    "client scope",
    "name",
    "description protocol attributes",
    maps={"attributes": SCOPE_ATTRIBUTES},
    elsewhere="protocolMappers",
)
FLOW = shape(
    "flow", "alias", "description providerId topLevel builtIn", elsewhere="authenticationExecutions"
)
# One entry of /authentication/flows/{alias}/executions: an authenticator or a sub-flow.
FLOW_STEP = shape(
    "flow step",
    "requirement level index",
    "displayName description providerId authenticationFlow priority authenticationConfig",
    elsewhere="alias",
)
AUTHENTICATOR_CONFIG = shape(
    "authenticator config",
    "alias",
    "config",
    maps={"config": MapShape(keys("flow_to_check check_result defaultProvider"))},
)
REQUIRED_ACTION = shape(
    "required action",
    "alias",
    "name providerId enabled defaultAction priority config",
    maps={"config": MapShape(keys("max_auth_age"))},
)
IDP_CONFIG = MapShape(
    keys(
        """clientId authorizationUrl tokenUrl userInfoUrl issuer jwksUrl logoutUrl
        defaultScope syncMode validateSignature useJwksUrl pkceEnabled pkceMethod
        clientAuthMethod"""
    ),
    secret=re.compile(r"^clientSecret$"),
)
IDP = shape(
    "identity provider",
    "alias providerId",
    """displayName enabled trustEmail storeToken addReadTokenRoleOnCreate authenticateByDefault
    linkOnly hideOnLogin firstBrokerLoginFlowAlias postBrokerLoginFlowAlias config""",
    maps={"config": IDP_CONFIG},
)
IDP_MAPPER = shape(
    "identity provider mapper",
    "name identityProviderAlias identityProviderMapper",
    "config",
    maps={"config": MapShape(keys("syncMode claim claim.value attribute group role"))},
)
USER = shape(
    "service-account user",
    "username enabled",
    "requiredActions emailVerified serviceAccountClientId attributes",
    maps={"attributes": MapShape()},
)
COMPONENT = shape(
    "component",
    "providerId providerType",
    "subType name config",
    maps={"config": MapShape(all_secret=True)},
)


# --- Coverage ---------------------------------------------------------------------------------


@dataclass(frozen=True)
class Read:
    """Covered: the observer reads this."""

    what: str


@dataclass(frozen=True)
class Gap:
    """Named and not read; a change here does not show."""

    why: str


Coverage = Read | Gap
SETTINGS = Read("realm settings (the realm shape's allow-list, other keys as digests)")
# Every top-level key of keycloak/master.yaml and keycloak/realm.yaml, and every
# keycloak-config-cli 6.5.1 import type, mapped to a read or a named gap, plus each named gap
# inside a read type as its dotted field path (`clients.secret`). The realm settings
# the realm shape lists are covered as they stand; tests/test_stack_realm_observe.py fails when a
# YAML gains a key neither names.
COVERAGE: dict[str, Coverage] = {
    **dict.fromkeys(REALM.listed, SETTINGS),
    "users": Read("service-account users: fields, realm and client role mappings, groups"),
    "groups": Read("the group tree: path, attributes, roles, member count and member digest"),
    "roles": Read("realm roles and client roles with their composites"),
    "clients": Read("clients with protocol mappers, client roles, default and optional scopes"),
    "clientScopes": Read("client scopes and their protocol mappers"),
    "defaultDefaultClientScopes": Read("the realm's default client scopes"),
    "defaultOptionalClientScopes": Read("the realm's optional client scopes"),
    "authenticationFlows": Read("flows with their steps (alias, ordinal, place, requirement)"),
    "authenticatorConfig": Read("authenticator configs by alias with their config"),
    "requiredActions": Read("required actions"),
    "identityProviders": Read("identity providers"),
    "identityProviderMappers": Read("identity provider mappers"),
    "components": Read("components by providerType/providerId/subType/name only"),
    "organizations": Gap("organizations"),
    "workflows": Gap("workflows"),
    "subComponents": Gap("component config and sub-components: component config never leaves"),
    "scopeMappings": Gap("scope mappings"),
    "clientScopeMappings": Gap("client scope mappings"),
    "defaultGroups": Gap("default groups"),
    "clientPolicies": Gap("client policies"),
    "clientProfiles": Gap("client profiles"),
    "authorizationSettings": Gap("client authorization settings (resources, policies, scopes)"),
    "userFederationProviders": Gap("user federation"),
    "messageBundles": Gap("message bundles"),
    "userProfile": Gap("the user profile"),
    "clients.secret": Gap(
        "client secrets never leave, so a rotated config-cli secret is invisible"
    ),
}


# --- Projection -------------------------------------------------------------------------------


def canonical(value: Any) -> Any:
    """Keycloak returns its sets (redirect URIs, event types, locales) in no fixed order."""
    if isinstance(value, list):
        items = [canonical(item) for item in value]
        if all(not isinstance(item, (dict, list)) for item in items):
            return sorted(items, key=json.dumps)
        return items
    if isinstance(value, dict):
        return {key: canonical(item) for key, item in value.items()}
    return value


@dataclass(frozen=True)
class Digester:
    key: bytes

    def __call__(self, value: Any) -> str:
        text = json.dumps(canonical(value), sort_keys=True, ensure_ascii=False)
        return hmac.new(self.key, text.encode(), hashlib.sha256).hexdigest()


def project(form: Shape, representation: Representation, digest: Digester) -> Entity:
    """The allow-listed fields of one representation, every other key as a digest."""
    if missing := sorted(name for name in form.required if name not in representation):
        raise ObserveError(f"a {form.name} representation lacks {', '.join(missing)}")
    fields: dict[str, Any] = dict.fromkeys(form.listed - form.maps.keys())
    digests: dict[str, str] = {}
    for key, value in representation.items():
        if key in VOLATILE or key in form.elsewhere or key in form.secret:
            continue
        if key in form.maps:
            mapped = project_map(key, form.maps[key], value or {}, digest)
            fields, digests = fields | mapped["fields"], digests | mapped["digests"]
        elif key in form.listed:
            fields[key] = canonical(value)
        else:
            digests[key] = digest(without_volatile(value))
    return {"fields": fields, "digests": digests}


def without_volatile(value: Any) -> Any:
    """A UUID nested in a digested value (the realm's defaultRole) is no identity either."""
    if isinstance(value, dict):
        return {key: without_volatile(item) for key, item in value.items() if key not in VOLATILE}
    if isinstance(value, list):
        return [without_volatile(item) for item in value]
    return value


def project_map(name: str, form: MapShape, values: Mapping[str, Any], digest: Digester) -> Entity:
    projected = empty()
    for key, value in values.items():
        if key.startswith(CONFIG_CLI_STATE) or form.is_secret(key):
            continue
        if key in form.allowed:
            projected["fields"][f"{name}.{key}"] = canonical(value)
        else:
            projected["digests"][f"{name}.{key}"] = digest(value)
    return projected


# --- Reading ----------------------------------------------------------------------------------


class RefuseRedirects(HTTPRedirectHandler):
    """urllib follows a 30x with the Authorization header, even to another host or a path outside
    /admin/realms; refused, the 30x surfaces as its status."""

    def redirect_request(self, *_: Any) -> None:
        return None


# No proxy either: Docker can inject HTTP(S)_PROXY into the container's environment.
OPENER = build_opener(ProxyHandler({}), RefuseRedirects)


@dataclass
class Session:
    """The admin API as config-cli sees it: one token POST, then GET only."""

    base_url: str
    secret: str
    client_id: str = CLIENT_ID
    timeout: float = REQUEST_SECONDS
    token: str = field(default="", repr=False)

    def sign_in(self) -> None:
        credentials = {"client_id": self.client_id, "client_secret": self.secret}
        form = urlencode({"grant_type": "client_credentials", **credentials}).encode()
        status, body = self.send(Request(self.base_url + TOKEN_PATH, data=form, method="POST"))  # noqa: S310 - the base URL is the observer own --base-url argument
        if status in (400, 401):
            raise ObserveError(f"sign-in refused (status {status} at {TOKEN_PATH})")
        if status != 200:
            raise ObserveError(f"sign-in answered status {status} at {TOKEN_PATH}")
        self.token = parsed(body, TOKEN_PATH)["access_token"]

    def get(self, path: str, **query: Any) -> Any:
        """GET under /admin/realms; a 401 (master tokens live 60 s) signs in again once."""
        target = ADMIN_PATH + path + (f"?{urlencode(query)}" if query else "")
        status, body = self.send_get(target)
        if status == 401:
            self.sign_in()
            status, body = self.send_get(target)
        if status != 200:
            raise ObserveError(f"status {status} at {ADMIN_PATH}{path}")
        return parsed(body, ADMIN_PATH + path)

    def send_get(self, target: str) -> tuple[int, bytes]:
        headers = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        return self.send(Request(self.base_url + target, headers=headers, method="GET"))  # noqa: S310 - the base URL is the observer own --base-url argument

    def public(self, path: str) -> Any:
        """A GET with no token, of a document Keycloak serves to anyone."""
        request = Request(self.base_url + path, headers={"Accept": "application/json"})  # noqa: S310 - the base URL is the observer own --base-url argument
        status, body = self.send(request)
        if status != 200:
            raise ObserveError(f"status {status} at {path}")
        return parsed(body, path)

    def send(self, request: Request) -> tuple[int, bytes]:
        path = request.selector.split("?", 1)[0]
        try:
            with OPENER.open(request, timeout=self.timeout) as reply:
                return reply.status, reply.read()
        except HTTPError as error:
            error.close()
            return error.code, b""
        except OSError as error:
            cause = getattr(error, "reason", None)
            timed_out = isinstance(error, TimeoutError) or isinstance(cause, TimeoutError)
            reason = "timed out" if timed_out else "unreachable"
            raise ObserveError(f"Keycloak does not answer {path} ({reason})") from error

    def paged(self, path: str, identity: str = "id", **query: Any) -> list[Any]:
        """Every page of a first/max endpoint; a page that repeats an earlier item fails."""
        items: list[Any] = []
        seen: set[Any] = set()
        while True:
            page = self.get(path, first=len(items), max=PAGE, **query)
            for item in page:
                if item[identity] in seen:
                    raise ObserveError(f"{ADMIN_PATH}{path} repeats an item across pages")
                seen.add(item[identity])
            items += page
            if len(page) < PAGE:
                return items


def parsed(body: bytes, path: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as error:
        raise ObserveError(f"no JSON at {path}") from error


def counted(path: str, items: list[Any], expected: int) -> list[Any]:
    if len(items) != expected:
        raise ObserveError(f"{ADMIN_PATH}{path} returned {len(items)} of {expected}")
    return items


def groups(session: Session, realm: str) -> Iterator[Representation]:
    """Every group of a realm; a group's subgroups are read once it was handed on."""
    top = session.paged(f"/{realm}/groups", briefRepresentation="false")
    pending = counted("/groups", top, session.get(f"/{realm}/groups/count", top="true")["count"])
    while pending:
        yield (group := pending.pop())
        if group["subGroupCount"]:
            children_path = f"/groups/{group['id']}/children"
            children = session.paged(f"/{realm}{children_path}", briefRepresentation="false")
            pending += counted(children_path, children, group["subGroupCount"])


def members(session: Session, realm: str, group: Representation) -> list[Any]:
    return session.paged(f"/{realm}/groups/{group['id']}/members", briefRepresentation="true")


@dataclass
class RealmReader:
    """Reads one realm into {type: {identity: entity}}."""

    session: Session
    realm: str
    digest: Digester
    found: dict[str, dict[str, Entity]] = field(default_factory=dict)
    client_ids: dict[str, str] = field(default_factory=dict)

    def keep(self, kind: str, identity: str, entity: Entity) -> None:
        bucket = self.found.setdefault(kind, {})
        if identity in bucket:
            raise ObserveError(f"two {kind} objects in {self.realm} share one identity")
        bucket[identity] = entity

    def keep_shaped(
        self, form: Shape, identity: str, representation: Representation, kind: str = ""
    ) -> Entity:
        entity = project(form, representation, self.digest)
        self.keep(kind or form.name, identity, entity)
        return entity

    def get(self, path: str, **query: Any) -> Any:
        return self.session.get(f"/{self.realm}{path}", **query)

    def paged(self, path: str, identity: str = "id", **query: Any) -> list[Any]:
        return self.session.paged(f"/{self.realm}{path}", identity, **query)

    def read(self) -> dict[str, dict[str, Entity]]:
        clients = self.paged("/clients")
        self.client_ids = {client["id"]: client["clientId"] for client in clients}
        self.read_realm()
        self.read_groups()
        self.read_roles("/roles", REALM_ROLE, "")
        self.read_clients(clients)
        self.read_client_scopes()
        self.read_flows()
        self.read_required_actions()
        self.read_identity_providers()
        self.read_components()
        return self.found

    def read_realm(self) -> None:
        entity = self.keep_shaped(REALM, self.realm, self.get(""))
        for name, path in REALM_SCOPES.items():
            entity["fields"][name] = sorted(scope["name"] for scope in self.get(path))

    def read_groups(self) -> None:
        for group in groups(self.session, self.realm):
            entity = self.keep_shaped(GROUP, group["path"], group)
            entity["fields"].pop("subGroupCount")
            entity["fields"]["realmRoles"] = sorted(group.get("realmRoles", []))
            entity["fields"]["clientRoles"] = sorted(
                f"{client}/{role}"
                for client, roles in group.get("clientRoles", {}).items()
                for role in roles
            )
            direct = members(self.session, self.realm, group)
            entity["fields"]["members"] = len(direct)
            entity["digests"]["members"] = self.digest(sorted(m["id"] for m in direct))

    def read_roles(self, path: str, kind: str, owner: str) -> None:
        for role in self.paged(path, briefRepresentation="false"):
            entity = self.keep_shaped(ROLE, f"{owner}{role['name']}", role, kind)
            if role["composite"]:
                composites = self.get(f"/roles-by-id/{role['id']}/composites")
                entity["fields"]["composites"] = sorted(map(self.role_name, composites))

    def role_name(self, role: Representation) -> str:
        if role.get("clientRole"):
            return f"{self.client_ids[role['containerId']]}/{role['name']}"
        return role["name"]

    def read_clients(self, clients: list[Any]) -> None:
        for client in clients:
            client_id = client["clientId"]
            self.keep_shaped(CLIENT, client_id, client)
            self.read_mappers(f"client {client_id}", client.get("protocolMappers", []))
            self.read_roles(f"/clients/{client['id']}/roles", CLIENT_ROLE, f"{client_id}/")
            if client.get("serviceAccountsEnabled"):
                self.read_service_account(client["id"])

    def read_mappers(self, owner: str, mappers: list[Any]) -> None:
        for mapper in mappers:
            self.keep_shaped(PROTOCOL_MAPPER, f"{owner}/{mapper['name']}", mapper)

    def read_service_account(self, client_uuid: str) -> None:
        user = self.get(f"/clients/{client_uuid}/service-account-user")
        username = user["username"]
        self.keep_shaped(USER, username, user)
        mappings = self.get(f"/users/{user['id']}/role-mappings")
        for role in mappings.get("realmMappings", []):
            self.keep("service-account realm role", f"{username}/{role['name']}", empty())
        for client_id, client in mappings.get("clientMappings", {}).items():
            for role in client.get("mappings", []):
                identity = f"{username}/{client_id}/{role['name']}"
                self.keep("service-account client role", identity, empty())
        for group in self.paged(f"/users/{user['id']}/groups", briefRepresentation="true"):
            self.keep("service-account group", f"{username}{group['path']}", empty())

    def read_client_scopes(self) -> None:
        for scope in self.get("/client-scopes"):
            self.keep_shaped(CLIENT_SCOPE, scope["name"], scope)
            self.read_mappers(f"scope {scope['name']}", scope.get("protocolMappers", []))

    def read_flows(self) -> None:
        config_aliases: dict[str, str] = {}
        for flow in self.get("/authentication/flows"):
            self.keep_shaped(FLOW, flow["alias"], flow)
            steps = self.get(f"/authentication/flows/{quote(flow['alias'], safe='')}/executions")
            for identity, step in step_identities(flow["alias"], steps):
                self.read_step(identity, step, config_aliases)

    def read_step(
        self, identity: str, step: Representation, config_aliases: dict[str, str]
    ) -> None:
        entity = project(FLOW_STEP, step, self.digest)
        fields = entity["fields"]
        fields["place"] = fields.pop("index")
        fields.pop("level")
        config_id = fields.pop("authenticationConfig")
        fields["config"] = self.config_alias(config_id, config_aliases) if config_id else None
        self.keep(FLOW_STEP.name, identity, entity)
        if step.get("authenticationFlow"):
            sub_flow = {
                "alias": step["displayName"],
                "description": step.get("description"),
                "providerId": step.get("providerId"),
                "topLevel": False,
            }
            self.keep_shaped(FLOW, step["displayName"], sub_flow)

    def config_alias(self, config_id: str, config_aliases: dict[str, str]) -> str:
        if config_id not in config_aliases:
            config = self.get(f"/authentication/config/{config_id}")
            self.keep_shaped(AUTHENTICATOR_CONFIG, config["alias"], config)
            config_aliases[config_id] = config["alias"]
        return config_aliases[config_id]

    def read_required_actions(self) -> None:
        for action in self.get("/authentication/required-actions"):
            self.keep_shaped(REQUIRED_ACTION, action["alias"], action)

    def read_identity_providers(self) -> None:
        instances = "/identity-provider/instances"
        for provider in self.paged(instances, identity="alias", briefRepresentation="false"):
            alias = provider["alias"]
            self.keep_shaped(IDP, alias, provider)
            for mapper in self.get(f"{instances}/{quote(alias, safe='')}/mappers"):
                self.keep_shaped(IDP_MAPPER, f"{alias}/{mapper['name']}", mapper)

    def read_components(self) -> None:
        for component in self.get("/components"):
            project(COMPONENT, component, self.digest)  # fails loudly on a missing identity part
            identity = [component["providerType"], component["providerId"]]
            identity += [component.get(part) or "" for part in ("subType", "name")]
            self.keep(COMPONENT.name, "/".join(identity), empty())


REALM_SCOPES = {
    "defaultDefaultClientScopes": "/default-default-client-scopes",
    "defaultOptionalClientScopes": "/default-optional-client-scopes",
}


def empty() -> Entity:
    return {"fields": {}, "digests": {}}


def step_identities(flow: str, steps: list[Any]) -> Iterator[tuple[str, Representation]]:
    """Each step of a flow's flattened execution list with its identity: the flow it sits in,
    its authenticator or sub-flow alias, and its ordinal among equals there."""
    parents = [flow]
    ordinals: dict[str, Counter[str]] = {}
    for step in steps:
        level = step["level"]
        del parents[level + 1 :]
        parent = parents[level]
        name = step["displayName"] if step.get("authenticationFlow") else step["providerId"]
        counter = ordinals.setdefault(parent, Counter())
        counter[name] += 1
        yield f"{parent}/{name}#{counter[name]}", step
        if step.get("authenticationFlow"):
            parents.append(step["displayName"])


def observe(session: Session, digest: Digester) -> Inventory:
    try:
        session.sign_in()
        return {realm: RealmReader(session, realm, digest).read() for realm in REALMS}
    except KeyError as error:
        # An identity or a UUID read before its representation is projected and checked.
        raise ObserveError(f"a reply lacks the key {error}") from error


def import_checksums(session: Session) -> dict[str, dict[str, str]]:
    """Each realm's import-checksum attributes, and nothing else of it."""
    try:
        session.sign_in()
        return {
            realm: {
                name: value
                for name, value in session.get(f"/{realm}").get("attributes", {}).items()
                if name.startswith(IMPORT_CHECKSUM)
            }
            for realm in REALMS
        }
    except (KeyError, AttributeError) as error:
        raise ObserveError(f"a reply lacks the realm attributes ({error})") from error


def group_members(session: Session, path: str) -> dict[str, Any]:
    """The people realm's issuer and the ids of one group's direct members."""
    session.sign_in()
    found = (group for group in groups(session, PEOPLE_REALM) if group["path"] == path)
    if (group := next(found, None)) is None:
        raise ObserveError(f"{PEOPLE_REALM} has no group {path}")
    issuer = session.public(f"/realms/{PEOPLE_REALM}/.well-known/openid-configuration")["issuer"]
    direct = members(session, PEOPLE_REALM, group)
    return {"issuer": issuer, "members": [member["id"] for member in direct]}


# --- The command ------------------------------------------------------------------------------


def stop(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(
    argv: list[str] | None = None, stdin: TextIO | None = None, secret_file: Path = SECRET_FILE
) -> int:
    """The command; `stdin` carries the digest key line, which only the inventory reads, and
    defaults to the process's stdin."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="Keycloak, e.g. http://keycloak:8080")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--import-checksums",
        action="store_true",
        help="print the realms' import-checksum attributes instead of the inventory",
    )
    mode.add_argument("--members", metavar="PATH", help="print the issuer and the group's members")
    arguments = parser.parse_args(argv)
    # PID 1 in a container ignores SIGTERM unless it handles it.
    signal.signal(signal.SIGTERM, stop)
    reads_key = not (arguments.import_checksums or arguments.members)
    try:
        key = digest_key((stdin or sys.stdin).readline()) if reads_key else None
        session = Session(arguments.base_url.rstrip("/"), read_secret(secret_file))
        if arguments.members:
            found: Any = group_members(session, arguments.members)
        else:
            found = import_checksums(session) if key is None else observe(session, Digester(key))
    except ObserveError as error:
        print(f"realm-observer: {error}", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 1
    except KeyboardInterrupt:
        print("realm-observer: stopped", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 130
    except Exception as error:  # its text may quote a reply; only its type is printed
        print(f"realm-observer: unexpected {type(error).__name__}", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 1
    json.dump(found, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def read_secret(path: Path) -> str:
    try:
        return path.read_text().strip()
    except OSError as error:
        raise ObserveError(f"cannot read the secret file {path}") from error


def digest_key(line: str) -> bytes:
    try:
        key = bytes.fromhex(line.strip())
    except ValueError:
        key = b""
    if len(key) < 32:
        raise ObserveError("no digest key of 32 bytes or more in hex on stdin")
    return key


if __name__ == "__main__":
    sys.exit(main())
