"""Cloudflare, read directly for the host check (#138): GET only, the read token only.

The one documented wire shape, from Cloudflare's published OpenAPI schema
(github.com/cloudflare/api-schemas, `openapi.json`, 19.10.2026):

- Every answer is `{"success": bool, "errors": [{"code": int, "message": str}], "result": ...}`.
  The lists are paged with `page` and `per_page` and answer `result_info` with `page`,
  `per_page`, `count`, `total_count` and, but for the tunnel list, `total_pages`.
- `GET /zones?name=`: `result[].id`, `result[].account.id`.
- `GET /zones/{id}/dns_records`: `result[].name`, `type`, `content`, `proxied`.
- `GET /accounts/{id}/cfd_tunnel?is_deleted=false&uuid=`: `result[].id`, at most hal's own live
  tunnel, so the account's other tunnels never answer; with `name=` instead of `uuid=`,
  `result[].id` and `result[].name` of the live tunnels a host names. Its `result_info` documents
  no `total_pages`, which is derived from `total_count` and the page size.
- `GET /accounts/{id}/access/groups`: `result[].id`, `result[].name` (an include rule names a
  group by id only).
- `GET /accounts/{id}/access/apps`: `result[].type`, `options_preflight_bypass` and the embedded
  `policies[]` (`decision`, `include[]`), so no policies read exists. A rule of `include[]` is a
  map with the one key `everyone` or `group` (`{"id": ...}`). Of every app `destinations[]`: a
  `public` destination is `{type, uri, overrides[]}` and an override is
  `{behavior: "public", path_pattern}`, "each rule can make a matching path public, bypassing
  Access authentication". A `destination` is one of the types of `DESTINATION_TYPES`; an app with
  one of `WORKER_DESTINATIONS` is refused, since a Worker route can protect a public host and this
  check does not judge it. `domain` is the primary hostname of the apps of `HOSTNAME_APP_TYPES`;
  it and the deprecated `self_hosted_domains` are not read as destinations but must each be one of
  the public destinations' hosts, so no secured hostname hides outside `destinations`.
- The schema lists `access_page` and `access_per_page` (default 1000, maximum 1000) for the apps
  and the groups; `page` and `per_page` are sent and answered. Paging fails closed: `result_info`
  must name the requested page and page size, the same `total_pages` and `total_count` on every
  page, a `total_pages` that is `ceil(total_count / per_page)` (0 or 1 when empty, which the schema
  leaves open) and a `count` equal to the page's results, and every page but the last must be full.
- An app that secures hostnames may carry only the fields of `UNDERSTOOD_APP_FIELDS`, the union of
  the response properties of every app variant in the published schema; a policy only those of
  `UNDERSTOOD_POLICY_FIELDS`. A field beyond them, and any key of a public destination or of an
  override beyond the documented ones, is refused (fail closed) instead of ignored. The refusal
  gives the level and the count of such fields, never a name: a response is not quoted.

Schema revision: cloudflare/api-schemas commit 8e378c74caeffd3cf8b458dc215b1c2e9bd48b9f
(19.10.2026), `openapi.json` (git blob b3375cb4e6e8caa4c318b3ae0d305159ddd20b46), the 200 answer
of `GET /accounts/{account_id}/access/apps`; the same shape is cloudflare-python's
`types/zero_trust/access/application_list_response.py`.

The token travels only in the `Authorization` header, set as an unredirected header on an opener
that follows no redirect and uses no environment proxy. No message names a body or the token.
"""

import http.client
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

BASE_URL = "https://api.cloudflare.com/client/v4"
ZONES_PATH = "/zones"
PAGE_SIZE = 50
MAXIMUM_PAGES = 200
TIMEOUT_SECONDS = 20.0
MAXIMUM_BODY_BYTES = 16 * 1024 * 1024
LOOPBACK_HOSTNAMES = frozenset({"127.0.0.1", "localhost", "::1"})
SELF_HOSTED = "self_hosted"
PUBLIC_DESTINATION = "public"
WORKER_DESTINATIONS = frozenset({"worker", "all_workers", "preview_worker", "all_preview_workers"})
DESTINATION_TYPES = frozenset(
    {PUBLIC_DESTINATION, "private", "via_mcp_server_portal"} | WORKER_DESTINATIONS
)
HOSTNAME_APP_TYPES = frozenset({SELF_HOSTED, "ssh", "vnc", "rdp", "mcp_portal", "end_user"})
# Every property of the app variants in the response schema of the revision named above.
UNDERSTOOD_APP_FIELDS = frozenset(
    {
        "allow_authenticate_via_warp", "allow_iframe", "allowed_idps", "app_launcher_logo_url",
        "app_launcher_visible", "aud", "auto_redirect_to_identity", "bg_color", "cors_headers",
        "created_at", "custom_deny_message", "custom_deny_url", "custom_non_identity_deny_url",
        "custom_pages", "destinations", "domain", "eager_redirect_cookie_setting",
        "enable_binding_cookie", "footer_links", "header_bg_color", "http_only_cookie_attribute",
        "id", "landing_page_design", "logo_url", "mfa_config", "name", "oauth_configuration",
        "options_preflight_bypass", "path_cookie_attribute", "policies",
        "read_service_tokens_from_header", "saas_app", "same_site_cookie_attribute", "scim_config",
        "self_hosted_domains", "service_auth_401_redirect", "session_duration",
        "skip_app_launcher_login_page", "skip_interstitial", "tags", "target_criteria", "type",
        "updated_at", "use_clientless_isolation_app_launcher_url", "user_populations",
    }
)  # fmt: skip
UNDERSTOOD_POLICY_FIELDS = frozenset(
    {
        "account_id", "approval_groups", "approval_required", "connection_rules", "created_at",
        "decision", "exclude", "id", "include", "isolation_required", "mfa_config", "name",
        "precedence", "purpose_justification_prompt", "purpose_justification_required", "require",
        "session_duration", "updated_at",
    }
)  # fmt: skip
CONDITION_FLAGS = ("approval_required", "isolation_required", "purpose_justification_required")
PUBLIC_DESTINATION_FIELDS = frozenset({"type", "uri", "overrides"})
OVERRIDE_FIELDS = frozenset({"behavior", "path_pattern"})
PLAIN_HOSTNAME = re.compile(
    r"(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*"
)
IDENTIFIER = re.compile(r"[0-9a-f]{32}")
ACCESS_NOT_ENABLED = (403, 9999, "access.api.error.not_enabled")


def _message_key(message: Any) -> str | None:
    """Cloudflare writes a key, then a human sentence after the first colon."""
    return message.split(":", 1)[0] if isinstance(message, str) else None


class CloudflareReadError(Exception):
    """A read failed; the message names the path, the status and the first Cloudflare error code."""


@dataclass(frozen=True)
class Record:
    name: str
    type: str
    content: str
    proxied: bool


@dataclass(frozen=True)
class Include:
    """One rule of a policy's `include`: `everyone`, a `group` with its id, or another kind."""

    kind: str
    group_id: str | None = None


@dataclass(frozen=True)
class Policy:
    """`extra_conditions`: it also restricts by exclude, require, approval, isolation, a purpose
    justification or connection rules."""

    decision: str
    include: tuple[Include, ...]
    extra_conditions: bool = False


@dataclass(frozen=True)
class Override:
    """A rule that makes a path of a public destination public, bypassing Access."""

    destination: str
    path_pattern: str


@dataclass(frozen=True)
class App:
    type: str
    destinations: tuple[str, ...]
    policies: tuple[Policy, ...]
    overrides: tuple[Override, ...] = ()
    options_preflight_bypass: bool = False


@dataclass(frozen=True)
class AccessGroup:
    id: str
    name: str


@dataclass(frozen=True)
class Snapshot:
    """What the account holds. `apps` is None when Access is not enabled on it;
    `named_tunnel_ids` holds the id of each other tunnel a host names, by its name."""

    tunnel_id: str
    records: tuple[Record, ...]
    groups: tuple[AccessGroup, ...]
    apps: tuple[App, ...] | None
    named_tunnel_ids: Mapping[str, str] = field(default_factory=dict)

    def tunnel_id_of(self, tunnel: str | None) -> str:
        """The id of the tunnel a host names; None is hal's own."""
        return self.tunnel_id if tunnel is None else self.named_tunnel_ids[tunnel]


@dataclass(frozen=True)
class OwnTunnel:
    """hal's tunnel: the id the machine's tunnel config names, and that config, which a lookup
    that finds no live tunnel by the id names."""

    id: str
    config: Path


class OwnTunnelUnknown(Exception):
    """The machine's tunnel config names no usable tunnel id; the message names the config."""


class CloudflareRead(Protocol):
    def read(self, zone: str, tunnel_names: Collection[str]) -> Snapshot: ...


class _Refusal(CloudflareReadError):
    def __init__(self, message: str, *, access_not_enabled: bool) -> None:
        super().__init__(message)
        self.access_not_enabled = access_not_enabled


class _DoNotFollow(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_arguments: Any, **_keywords: Any) -> None:
        return None


class CloudflareClient:
    def __init__(
        self,
        token: str,
        tunnel: OwnTunnel,
        base_url: str = BASE_URL,
        timeout_seconds: float = TIMEOUT_SECONDS,
    ) -> None:
        """`tunnel` is hal's own, the only one the account is asked for."""
        _require_cloudflare_or_loopback(base_url)
        self._token = token
        self._tunnel = tunnel
        self._base_url = base_url.rstrip("/")
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _DoNotFollow)

    def read(self, zone: str, tunnel_names: Collection[str]) -> Snapshot:
        """`tunnel_names` are the other tunnels the hosts name; each is looked up by its name."""
        zone_answer = self._one(ZONES_PATH, {"name": zone}, "zone")
        account_id = _identifier(zone_answer.get("account"), ZONES_PATH)
        zone_id = _identifier(zone_answer, ZONES_PATH)
        tunnels_path = f"/accounts/{account_id}/cfd_tunnel"
        tunnel_id = self._live_tunnel_id(tunnels_path)
        named_tunnel_ids = {
            name: self._named_tunnel_id(tunnels_path, name) for name in sorted(tunnel_names)
        }
        records_path = f"/zones/{zone_id}/dns_records"
        access = self._access(f"/accounts/{account_id}/access")
        apps, groups = access if access is not None else (None, ())
        return Snapshot(
            tunnel_id=tunnel_id,
            records=tuple(_record(item, records_path) for item in self._pages(records_path)),
            groups=groups,
            apps=apps,
            named_tunnel_ids=named_tunnel_ids,
        )

    def _access(self, path: str) -> tuple[tuple[App, ...], tuple[AccessGroup, ...]] | None:
        """The apps and the groups, or None when Access is off at the apps read. The same answer
        at the groups read, after the apps answered, is a contradiction and stays an error."""
        try:
            apps = tuple(_app(item, f"{path}/apps") for item in self._pages(f"{path}/apps"))
        except _Refusal as refusal:
            if refusal.access_not_enabled:
                return None
            raise
        groups = tuple(_group(item, f"{path}/groups") for item in self._pages(f"{path}/groups"))
        return apps, groups

    def _one(self, path: str, query: Mapping[str, str], what: str) -> dict:
        items = self._pages(path, query)
        if len(items) != 1:
            raise CloudflareReadError(f"{path}: expected exactly one {what}, found {len(items)}")
        return items[0]

    def _live_tunnel_id(self, path: str) -> str:
        """Only hal's id is asked for; an answer with any other tunnel is refused, so a list that
        ignored the filter never hands over another tunnel."""
        tunnel = self._tunnel
        found = self._pages(
            path, {"is_deleted": "false", "uuid": tunnel.id}, announces_total_pages=False
        )
        if not found:
            raise CloudflareReadError(
                f"{path}: no live tunnel has the id {tunnel.id} that {tunnel.config} names"
            )
        if any(_text(item, "id", path) != tunnel.id for item in found):
            raise CloudflareReadError(f"{path}: the answer holds a tunnel other than {tunnel.id}")
        return tunnel.id

    def _named_tunnel_id(self, path: str, name: str) -> str:
        """The one live tunnel by that name. A list that ignored the filter holds hal's own tunnel
        too, so it is refused for its count."""
        found = self._pages(
            path, {"is_deleted": "false", "name": name}, announces_total_pages=False
        )
        if len(found) != 1:
            raise CloudflareReadError(f"{path}: not one but {len(found)} live tunnels named {name}")
        return _text(found[0], "id", path)

    def _pages(
        self,
        path: str,
        query: Mapping[str, str] | None = None,
        *,
        announces_total_pages: bool = True,
    ) -> list[dict]:
        items: list[dict] = []
        page, announced = 1, None
        while True:
            try:
                answer = self._get(
                    path, {**(query or {}), "page": str(page), "per_page": PAGE_SIZE}
                )
            except _Refusal as refusal:
                # Access off answers page 1 only; on a later page the read contradicts itself.
                refusal.access_not_enabled = refusal.access_not_enabled and page == 1
                raise
            page_items, totals = _checked_page(path, answer, page, announces_total_pages)
            if announced not in (None, totals):
                raise CloudflareReadError(f"{path}: the pages announce different totals")
            announced = totals
            total_pages, total_count = totals
            items += page_items
            if page >= total_pages:
                break
            page += 1
        if len(items) != total_count:
            raise CloudflareReadError(f"{path}: {len(items)} results of {total_count} announced")
        if len({_text(item, "id", path) for item in items}) != len(items):
            raise CloudflareReadError(f"{path}: the results repeat an object")
        return items

    def _get(self, path: str, query: Mapping[str, str | int]) -> dict:
        request = urllib.request.Request(  # noqa: S310 - the base URL is checked to be the Cloudflare API or http on loopback
            f"{self._base_url}{path}?{urllib.parse.urlencode(query)}", method="GET"
        )
        request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        try:
            try:
                with self._opener.open(request, timeout=self._timeout_seconds) as response:
                    status, body = response.status, response.read(MAXIMUM_BODY_BYTES + 1)
            except urllib.error.HTTPError as refused:
                with refused:
                    status, body = refused.code, refused.read(MAXIMUM_BODY_BYTES + 1)
        except (OSError, ValueError, http.client.HTTPException) as failure:
            # Only the type: the text of a transport error can quote the request.
            raise CloudflareReadError(f"{path}: {type(failure).__name__}") from None
        return _answer(path, status, body)


def _require_cloudflare_or_loopback(base_url: str) -> None:
    """The bearer token goes to Cloudflare's own API or, in a test, to http on loopback."""
    parts = urllib.parse.urlsplit(base_url)
    on_loopback = parts.scheme == "http" and parts.hostname in LOOPBACK_HOSTNAMES
    if base_url != BASE_URL and not on_loopback:
        raise ValueError(f"the Cloudflare base URL must be {BASE_URL} (or http on loopback)")


def _consistent_page_counts(total_count: int) -> set[int]:
    """The `total_pages` an honest answer gives; the schema is silent on an empty list (0 or 1)."""
    pages = _pages_for(total_count)
    return {pages, 1} if total_count == 0 else {pages}


def _pages_for(total_count: int) -> int:
    return -(-total_count // PAGE_SIZE)


def _checked_page(
    path: str, answer: dict, page: int, announces_total_pages: bool
) -> tuple[list[dict], tuple[int, int]]:
    """The results of one page and the (total_pages, total_count) it announces or implies."""
    page_items = answer.get("result")
    info = answer.get("result_info")
    if not isinstance(page_items, list) or not isinstance(info, dict):
        raise CloudflareReadError(f"{path}: the answer is not a paged list")
    if info.get("page") != page:
        raise CloudflareReadError(f"{path}: the answer is not page {page}")
    if info.get("per_page") != PAGE_SIZE:
        raise CloudflareReadError(f"{path}: the answer does not keep the page size {PAGE_SIZE}")
    total_count = _count(info, "total_count", path)
    if announces_total_pages:
        total_pages = _count(info, "total_pages", path)
    else:
        total_pages = max(1, _pages_for(total_count))
    if total_pages not in _consistent_page_counts(total_count):
        raise CloudflareReadError(f"{path}: total_pages contradicts total_count")
    if total_pages > MAXIMUM_PAGES:
        raise CloudflareReadError(f"{path}: more than {MAXIMUM_PAGES} pages")
    if _count(info, "count", path) != len(page_items) or len(page_items) > PAGE_SIZE:
        raise CloudflareReadError(f"{path}: page {page} holds other than the counted results")
    if page < total_pages and len(page_items) != PAGE_SIZE:
        raise CloudflareReadError(f"{path}: page {page} is not full but is not the last")
    if not all(isinstance(item, dict) for item in page_items):
        raise CloudflareReadError(f"{path}: the list holds something but maps")
    return page_items, (total_pages, total_count)


def _answer(path: str, status: int, body: bytes) -> dict:
    if len(body) > MAXIMUM_BODY_BYTES:
        raise CloudflareReadError(f"{path}: HTTP {status}, the answer is too large")
    try:
        payload = json.loads(body)
    except ValueError, RecursionError:
        payload = None
    errors = payload.get("errors") if isinstance(payload, dict) else None
    first = errors[0] if isinstance(errors, list) and errors and isinstance(errors[0], dict) else {}
    code = first.get("code") if isinstance(first.get("code"), int) else None
    if 200 <= status < 300 and isinstance(payload, dict) and payload.get("success") is True:
        return payload
    detail = f"Cloudflare error code {code}" if code is not None else "no Cloudflare error code"
    if not isinstance(payload, dict):
        detail = "malformed JSON answer"
    raise _Refusal(
        f"{path}: HTTP {status}, {detail}",
        access_not_enabled=(status, code, _message_key(first.get("message"))) == ACCESS_NOT_ENABLED,
    )


def _identifier(item: Any, path: str) -> str:
    """An id that goes into a request path: Cloudflare's 32 lower-case hex characters."""
    value = _text(item, "id", path)
    if not IDENTIFIER.fullmatch(value):
        raise CloudflareReadError(f"{path}: an id is not 32 lower-case hex characters")
    return value


def _count(info: dict, key: str, path: str) -> int:
    value = info.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise CloudflareReadError(f"{path}: result_info.{key} is missing or not a count")
    return value


def _text(item: Any, key: str, path: str) -> str:
    value = item.get(key) if isinstance(item, dict) else None
    if not isinstance(value, str) or not value:
        raise CloudflareReadError(f"{path}: a result lacks its {key}")
    return value


def _list(item: dict, key: str, path: str) -> list:
    value = item.get(key)
    if not isinstance(value, list):
        raise CloudflareReadError(f"{path}: a result lacks its {key} list")
    return value


def _record(item: dict, path: str) -> Record:
    return Record(
        name=_text(item, "name", path).lower(),
        type=_text(item, "type", path),
        content=_text(item, "content", path),
        proxied=item.get("proxied") is True,
    )


def _group(item: dict, path: str) -> AccessGroup:
    return AccessGroup(id=_text(item, "id", path), name=_text(item, "name", path))


def _app(item: dict, path: str) -> App:
    app_type = _text(item, "type", path)
    secures_hostnames = app_type in HOSTNAME_APP_TYPES
    destinations = _optional_list(item, "destinations", path, app_type == SELF_HOSTED)
    public = _public_destinations(destinations, path)
    if secures_hostnames or public:
        _require_only_fields(item, UNDERSTOOD_APP_FIELDS, "an Access app", path)
    for destination in public:
        _require_only_fields(destination, PUBLIC_DESTINATION_FIELDS, "a public destination", path)
    uris = [_with_lower_case_host(_text(destination, "uri", path)) for destination in public]
    if not all(PLAIN_HOSTNAME.fullmatch(destination_host(uri)) for uri in uris):
        raise CloudflareReadError(f"{path}: a destination host is not a plain lower-case hostname")
    if secures_hostnames:
        _require_secured_hosts_among(item, {destination_host(uri) for uri in uris}, path)
    return App(
        type=app_type,
        destinations=tuple(uris),
        policies=tuple(
            _policy(policy, path)
            for policy in _optional_list(item, "policies", path, app_type == SELF_HOSTED)
        ),
        overrides=tuple(
            _override(uri, override, path)
            for uri, destination in zip(uris, public, strict=True)
            for override in _optional_list(destination, "overrides", path, False)
        ),
        options_preflight_bypass=_flag(item, "options_preflight_bypass", path),
    )


def destination_host(destination: str) -> str:
    """The host of a destination uri, its path removed."""
    return destination.split("/", 1)[0]


def _with_lower_case_host(destination: str) -> str:
    """Hostnames are case-insensitive, paths are not."""
    host = destination_host(destination)
    return host.lower() + destination.removeprefix(host)


def _public_destinations(destinations: list, path: str) -> list[dict]:
    for destination in destinations:
        kind = destination.get("type") if isinstance(destination, dict) else None
        if not isinstance(kind, str) or kind not in DESTINATION_TYPES:
            raise CloudflareReadError(f"{path}: a destination is not of a published type")
        if kind in WORKER_DESTINATIONS:
            raise CloudflareReadError(
                f"{path}: an Access app has a Worker destination, which this check does not judge"
            )
    return [d for d in destinations if d["type"] == PUBLIC_DESTINATION]


def _require_secured_hosts_among(item: dict, public_hosts: set[str], path: str) -> None:
    """`domain` and `self_hosted_domains` secure hostnames too; none may be hidden from us."""
    secured = [item["domain"]] if "domain" in item else []
    secured += _optional_list(item, "self_hosted_domains", path, False)
    for domain in secured:
        if not isinstance(domain, str) or destination_host(domain).lower() not in public_hosts:
            raise CloudflareReadError(f"{path}: a secured domain is not among the destinations")


def _flag(item: dict, key: str, path: str) -> bool:
    value = item.get(key, False)
    if not isinstance(value, bool):
        raise CloudflareReadError(f"{path}: {key} is not a boolean")
    return value


def _optional_list(item: dict, key: str, path: str, required: bool) -> list:
    return _list(item, key, path) if required or key in item else []


def _override(destination: str, override: Any, path: str) -> Override:
    if not isinstance(override, dict):
        raise CloudflareReadError(f"{path}: an override is not a map")
    _require_only_fields(override, OVERRIDE_FIELDS, "an override", path)
    return Override(destination, _text(override, "path_pattern", path))


def _require_only_fields(item: dict, understood: frozenset[str], what: str, path: str) -> None:
    """Refuse a field beyond `understood`, by count only: a response is never quoted."""
    unknown = set(item) - understood
    if unknown:
        raise CloudflareReadError(
            f"{path}: {what} carries {len(unknown)} fields this check does not understand"
        )


def _policy(policy: Any, path: str) -> Policy:
    if not isinstance(policy, dict):
        raise CloudflareReadError(f"{path}: a policy is not embedded in its app")
    _require_only_fields(policy, UNDERSTOOD_POLICY_FIELDS, "a policy", path)
    restricting_lists = [_optional_list(policy, key, path, False) for key in ("exclude", "require")]
    required_flags = [_flag(policy, key, path) for key in CONDITION_FLAGS]
    connection_rules = policy.get("connection_rules", {})
    if not isinstance(connection_rules, dict):
        raise CloudflareReadError(f"{path}: connection_rules is not a map")
    return Policy(
        decision=_text(policy, "decision", path),
        include=tuple(_include(rule, path) for rule in _list(policy, "include", path)),
        extra_conditions=any([*restricting_lists, connection_rules, *required_flags]),
    )


def _include(rule: Any, path: str) -> Include:
    if not isinstance(rule, dict) or len(rule) != 1:
        raise CloudflareReadError(f"{path}: an include rule is not a map with one key")
    (kind, body), *_ = rule.items()
    return Include(kind=kind, group_id=_text(body, "id", path) if kind == "group" else None)
