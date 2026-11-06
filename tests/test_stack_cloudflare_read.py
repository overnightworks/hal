"""The Cloudflare read client (#138 cells R, rules 11-13): a loopback server, no network."""

import contextlib
import json
import socket
import socketserver
import threading
import urllib.parse
from collections.abc import Callable, Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from hal.stack.external import cloudflare_read
from hal.stack.external.cloudflare_read import (
    AccessGroup,
    App,
    CloudflareClient,
    CloudflareReadError,
    Include,
    Override,
    OwnTunnel,
    Policy,
    Record,
    Snapshot,
)

TOKEN = "sentinel-token-4b1d-never-print-me"
ZONE = "example.test"
ZONE_ID = "a1" * 16
ACCOUNT_ID = "b2" * 16
TUNNEL_ID = "11111111-2222-3333-4444-555555555555"
OWN_TUNNEL = OwnTunnel(TUNNEL_ID, Path("/scenario/cloudflared/config.yml"))
PAGE = 2
APPS_PATH = f"/accounts/{ACCOUNT_ID}/access/apps"
RECORDS_PATH = f"/zones/{ZONE_ID}/dns_records"
TUNNELS_PATH = f"/accounts/{ACCOUNT_ID}/cfd_tunnel"
GROUPS_PATH = f"/accounts/{ACCOUNT_ID}/access/groups"

pytestmark = pytest.mark.usefixtures("loopback_only")

Answer = tuple[int, dict | bytes]
Route = Callable[[dict[str, str]], Answer]


@pytest.fixture(autouse=True)
def small_pages(monkeypatch):
    monkeypatch.setattr(cloudflare_read, "PAGE_SIZE", PAGE)


class FakeCloudflare:
    def __init__(self) -> None:
        self.routes: dict[str, Route] = {}
        self.requests: list[tuple[str, dict[str, str], str | None]] = []
        self.release = threading.Event()
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                parts = urllib.parse.urlsplit(self.path)
                query = dict(urllib.parse.parse_qsl(parts.query))
                outer.requests.append((parts.path, query, self.headers.get("Authorization")))
                status, body = outer.routes[parts.path](query)
                payload = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(status)
                if status in (301, 302):
                    self.send_header("Location", outer.redirect_to)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                with contextlib.suppress(BrokenPipeError):  # the client timed out and left
                    self.wfile.write(payload)

            def log_message(self, *_arguments) -> None:
                pass

        self.redirect_to = ""
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_port}"
        threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
        ).start()

    def client(self, **keywords) -> CloudflareClient:
        return CloudflareClient(TOKEN, OWN_TUNNEL, base_url=self.url, **keywords)

    def serve_tunnels(self, live: list[str], deleted: tuple[str, ...] = ()) -> None:
        """The account's tunnels, filtered by `uuid` and `is_deleted` as the list documents."""

        def answer(query: dict[str, str]) -> Answer:
            pool = deleted if query["is_deleted"] == "true" else live
            matching = [{"id": tunnel} for tunnel in pool if tunnel == query["uuid"]]
            return 200, page_of(matching, int(query["page"]), PAGE, TUNNELS_PATH)

        self.routes[TUNNELS_PATH] = answer

    def serve(self, path: str, items: list) -> None:
        items = [{"id": f"object-{number}", **item} for number, item in enumerate(items)]
        self.routes[path] = lambda query: (200, page_of(items, int(query["page"]), PAGE, path))

    def close(self) -> None:
        self.release.set()
        self.server.shutdown()
        self.server.server_close()


def page_of(items: list, page: int, page_size: int, path: str) -> dict:
    """A page in the shape the schema documents for `path`: the tunnel list has no total_pages."""
    total_pages = None if path == TUNNELS_PATH else max(1, -(-len(items) // page_size))
    return listing(
        items[(page - 1) * page_size : page * page_size],
        page,
        total_pages=total_pages,
        total_count=len(items),
    )


def listing(result: list, page: int, **changes: int | None) -> dict:
    """A complete page; a change of None leaves that `result_info` key out."""
    info = {
        "page": page,
        "per_page": PAGE,
        "count": len(result),
        "total_pages": 1,
        "total_count": len(result),
        **changes,
    }
    return ok(result, **{key: value for key, value in info.items() if value is not None})


def ok(result: list, **info) -> dict:
    return {"success": True, "errors": [], "result": result, "result_info": info}


def failure(code: int, message: str = "no") -> dict:
    return {"success": False, "errors": [{"code": code, "message": message}], "result": None}


def self_hosted(domain: str, decision: str, include: list) -> dict:
    return {
        "type": "self_hosted",
        "domain": domain,
        "destinations": [{"type": "public", "uri": domain}, {"type": "private", "cidr": "10/8"}],
        "policies": [{"id": "p", "decision": decision, "include": include}],
    }


VALID_APP = {"type": "app_launcher"}
RECORDS = [
    {"name": f"{label}.{ZONE}", "type": "CNAME", "content": "x", "proxied": True}
    for label in ("a", "b", "c")
]
APPS = [
    self_hosted(f"www.{ZONE}", "bypass", [{"everyone": {}}]),
    self_hosted(f"*.{ZONE}", "allow", [{"group": {"id": "g1"}}]),
    {
        "type": "ssh",
        "destinations": [{"type": "public", "uri": f"ssh.{ZONE}"}],
        "policies": [],
    },
    {"type": "app_launcher"},
]
GROUPS = [{"id": "g1", "name": "operator"}]


@pytest.fixture
def cloudflare() -> Iterator[FakeCloudflare]:
    fake = FakeCloudflare()
    fake.serve("/zones", [{"id": ZONE_ID, "name": ZONE, "account": {"id": ACCOUNT_ID}}])
    fake.serve_tunnels(live=[TUNNEL_ID])
    fake.serve(RECORDS_PATH, RECORDS)
    fake.serve(GROUPS_PATH, GROUPS)
    fake.serve(APPS_PATH, APPS)
    yield fake
    fake.close()


def read_error(cloudflare: FakeCloudflare, **client_keywords) -> str:
    client = cloudflare.client(**client_keywords)
    with pytest.raises(CloudflareReadError) as raised:
        client.read(ZONE)
    return str(raised.value)


def test_the_snapshot_holds_every_page_and_each_request_carries_the_token_in_the_header_only(
    cloudflare,
):
    """R1."""
    assert cloudflare.client().read(ZONE) == Snapshot(
        tunnel_id=TUNNEL_ID,
        records=tuple(Record(f"{label}.{ZONE}", "CNAME", "x", True) for label in "abc"),
        groups=(AccessGroup("g1", "operator"),),
        apps=(
            App("self_hosted", (f"www.{ZONE}",), (Policy("bypass", (Include("everyone"),)),)),
            App("self_hosted", (f"*.{ZONE}",), (Policy("allow", (Include("group", "g1"),)),)),
            App("ssh", (f"ssh.{ZONE}",), ()),
            App("app_launcher", (), ()),
        ),
    )
    paths = [path for path, _, _ in cloudflare.requests]
    assert paths.count(RECORDS_PATH) == 2
    assert {header for _, _, header in cloudflare.requests} == {f"Bearer {TOKEN}"}
    assert TOKEN not in json.dumps([query for _, query, _ in cloudflare.requests])


ACCESS_OFF_KEY = "access.api.error.not_enabled"
ACCESS_OFF_LIVE_MESSAGE = (
    f"{ACCESS_OFF_KEY}: Access is not enabled. Visit the Access dashboard at "
    "https://dash.cloudflare.com/ and click the 'Enable Access' button."
)


@pytest.mark.parametrize(
    "message", [ACCESS_OFF_LIVE_MESSAGE, ACCESS_OFF_KEY], ids=["live message", "bare key"]
)
def test_access_off_at_the_apps_read_is_a_typed_answer_not_an_error(cloudflare, message):
    """R2: Access off at the apps read is a typed answer, and the groups are not asked for."""
    cloudflare.routes[APPS_PATH] = lambda _query: (403, failure(9999, message))
    snapshot = cloudflare.client().read(ZONE)
    assert (snapshot.apps, snapshot.groups) == (None, ())
    assert len(snapshot.records) == len(RECORDS)
    assert GROUPS_PATH not in {path for path, _query, _header in cloudflare.requests}


@pytest.mark.parametrize(
    "message",
    [
        f"{ACCESS_OFF_KEY}_x: Access is not enabled.",
        f"x {ACCESS_OFF_KEY}: Access is not enabled.",
        "Access is not enabled",
        ["access.api.error.not_enabled"],
    ],
    ids=["longer key", "prefixed key", "sentence only", "not a string"],
)
def test_a_message_whose_key_differs_is_never_access_off(cloudflare, message):
    """R2b: only the exact key before the first colon is Access off."""
    cloudflare.routes[APPS_PATH] = lambda _query: (403, failure(9999, message))
    assert read_error(cloudflare) == f"{APPS_PATH}: HTTP 403, Cloudflare error code 9999"


ACCESS_OFF = (403, failure(9999, ACCESS_OFF_LIVE_MESSAGE))


def apps_page_one_then_access_off(query: dict[str, str]) -> Answer:
    if query["page"] == "1":
        return 200, listing([VALID_APP] * 2, 1, total_pages=2, total_count=4)
    return ACCESS_OFF


@pytest.mark.parametrize(
    ("refused_path", "routes"),
    [
        (APPS_PATH, {APPS_PATH: apps_page_one_then_access_off}),
        (
            GROUPS_PATH,
            {
                APPS_PATH: lambda _query: (200, page_of([], 1, PAGE, APPS_PATH)),
                GROUPS_PATH: lambda _query: ACCESS_OFF,
            },
        ),
    ],
    ids=["apps page 2", "groups"],
)
def test_access_off_after_the_apps_began_to_answer_is_a_contradiction(
    cloudflare, refused_path, routes
):
    """R8: only the first page of the apps read may answer Access off."""
    cloudflare.routes.update(routes)
    assert read_error(cloudflare).startswith(
        f"{refused_path}: HTTP 403, Cloudflare error code 9999"
    )


@pytest.mark.parametrize(
    ("status", "body", "expected_in_message"),
    [
        pytest.param(
            403,
            failure(9999, "something else"),
            "HTTP 403, Cloudflare error code 9999",
            id="9999 but another message",
        ),
        pytest.param(
            403,
            failure(10000, "access.api.error.not_enabled"),
            "HTTP 403, Cloudflare error code 10000",
            id="the message under another code",
        ),
        pytest.param(
            401,
            failure(10000, "Authentication error"),
            "HTTP 401, Cloudflare error code 10000",
            id="401",
        ),
        pytest.param(500, failure(1000), "HTTP 500, Cloudflare error code 1000", id="500"),
        pytest.param(
            200, failure(7003), "HTTP 200, Cloudflare error code 7003", id="success false"
        ),
        pytest.param(200, b"{not json", "HTTP 200, malformed JSON answer", id="malformed JSON"),
        pytest.param(
            500,
            failure(1, f"echoes {TOKEN}"),
            "HTTP 500, Cloudflare error code 1",
            id="a body with the token",
        ),
        pytest.param(302, b"", "HTTP 302", id="a redirect status"),
    ],
)
def test_a_refused_apps_read_raises_naming_path_status_and_code_but_never_body_or_token(
    cloudflare, status, body, expected_in_message
):
    """R3 (and rule 7: only the exact 9999 answer is Access off)."""
    cloudflare.routes[APPS_PATH] = lambda _query: (status, body)
    message = read_error(cloudflare)
    assert message.startswith(f"{APPS_PATH}: {expected_in_message}")
    assert TOKEN not in message
    assert "echoes" not in message


@pytest.mark.parametrize("zones", [[], [{"id": "z"}, {"id": "y"}]], ids=["no zone", "two zones"])
def test_zero_or_several_zones_are_an_error(cloudflare, zones):
    """R3."""
    cloudflare.serve("/zones", zones)
    assert f"exactly one zone, found {len(zones)}" in read_error(cloudflare)


def test_a_timeout_is_an_error_without_a_body(cloudflare):
    """R3."""

    def hang(_query: dict[str, str]) -> Answer:
        cloudflare.release.wait(10)
        return 200, {}

    cloudflare.routes["/zones"] = hang
    message = read_error(cloudflare, timeout_seconds=0.2)
    assert message.startswith("/zones: ")
    assert TOKEN not in message


def test_a_redirect_is_not_followed_and_the_token_never_reaches_its_target(cloudflare):
    """R4."""
    elsewhere = FakeCloudflare()
    elsewhere.routes["/zones"] = lambda _query: (200, ok([]))
    cloudflare.redirect_to = f"{elsewhere.url}/zones"
    cloudflare.routes["/zones"] = lambda _query: (302, b"")
    try:
        message = read_error(cloudflare)
    finally:
        elsewhere.close()
    assert message.startswith("/zones: HTTP 302")
    assert elsewhere.requests == []


def test_the_environment_proxy_is_not_used(cloudflare, monkeypatch):
    """R4: the fake is http, so only HTTP_PROXY is driven; HTTPS_PROXY is not claimed."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    assert cloudflare.client().read(ZONE).tunnel_id == TUNNEL_ID
    assert cloudflare.requests


def test_the_https_environment_proxy_is_not_used_for_the_production_url(monkeypatch):
    """R4: the fake proxy sees nothing; the direct connection ends at the loopback backstop."""
    seen_by_proxy: list[bytes] = []

    class Proxy(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            seen_by_proxy.append(self.request.recv(1024))

    proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Proxy)
    threading.Thread(
        target=proxy.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True
    ).start()
    address = f"http://127.0.0.1:{proxy.server_address[1]}"
    for variable in ("HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.setenv(variable, address)
    monkeypatch.setenv("NO_PROXY", "")
    real_getaddrinfo = socket.getaddrinfo
    unroutable = (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 443))
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, *rest, **keywords: (
            [unroutable]
            if host == "api.cloudflare.com"
            else real_getaddrinfo(host, *rest, **keywords)
        ),
    )
    client = CloudflareClient(TOKEN, OWN_TUNNEL)
    try:
        with pytest.raises(AssertionError, match=r"leaves loopback: 192\.0\.2\.1"):
            client.read(ZONE)
    finally:
        proxy.shutdown()
        proxy.server_close()
    assert seen_by_proxy == []


@pytest.mark.parametrize(
    ("answer", "expected"),
    [
        pytest.param(
            lambda page: {"success": True, "errors": [], "result": []},
            "the answer is not a paged list",
            id="no result_info",
        ),
        *[
            pytest.param(
                lambda page, key=key: listing([VALID_APP], page, **{key: None}),
                f"result_info.{key} is missing or not a count"
                if key != "per_page"
                else "the answer does not keep the page size",
                id=f"no {key}",
            )
            for key in ("total_pages", "total_count", "count", "per_page")
        ],
        pytest.param(
            lambda page: listing(
                [VALID_APP] * 2 if page == 1 else [], page, total_pages=2, total_count=3
            ),
            "2 results of 3 announced",
            id="fewer than counted",
        ),
        pytest.param(
            lambda page: listing([VALID_APP] * 2, 1, total_pages=2, total_count=4),
            "the answer is not page 2",
            id="same page",
        ),
        pytest.param(
            lambda page: listing([VALID_APP] * 2, page, count=1),
            "holds other than the counted results",
            id="count is not the results",
        ),
        pytest.param(
            lambda page: listing([VALID_APP], page, per_page=PAGE + 1),
            "does not keep the page size",
            id="another page size",
        ),
        pytest.param(
            lambda page: listing([VALID_APP], page, total_pages=2, total_count=3),
            "is not full but is not the last",
            id="a short page that is not the last",
        ),
        pytest.param(
            lambda page: listing(
                [VALID_APP] * 2, page, total_pages=1 + page, total_count=2 + 2 * page
            ),
            "the pages announce different totals",
            id="a page count that changes between pages",
        ),
        pytest.param(
            lambda page: listing([VALID_APP] * 2, page, total_pages=2, total_count=2 + page),
            "the pages announce different totals",
            id="an object count that changes between pages",
        ),
        pytest.param(
            lambda page: listing([VALID_APP], page, total_pages=0, total_count=1),
            "total_pages contradicts total_count",
            id="no pages for a counted object",
        ),
        pytest.param(
            lambda page: listing([VALID_APP] * 2, page, total_pages=2, total_count=2),
            "total_pages contradicts total_count",
            id="more pages than the count fills",
        ),
        pytest.param(
            lambda page: listing([], page, total_pages=2, total_count=0),
            "total_pages contradicts total_count",
            id="two pages for no object",
        ),
    ],
)
def test_pagination_fails_closed(cloudflare, answer, expected):
    """R5: each case ends at its own check."""
    cloudflare.routes[APPS_PATH] = lambda query: (200, answer(int(query["page"])))
    message = read_error(cloudflare)
    assert message.startswith(f"{APPS_PATH}: ")
    assert expected in message


REPEATED_ID = "secret-object-id"
LISTINGS = {
    RECORDS_PATH: {"name": f"a.{ZONE}", "type": "CNAME", "content": "x"},
    APPS_PATH: VALID_APP,
    GROUPS_PATH: {"name": "operator"},
    TUNNELS_PATH: {},
}


@pytest.mark.parametrize("path", LISTINGS)
@pytest.mark.parametrize(
    "ids",
    [[REPEATED_ID, REPEATED_ID], [REPEATED_ID, "other", REPEATED_ID]],
    ids=["within a page", "across pages"],
)
def test_a_repeated_object_id_fails_closed_without_naming_the_id(cloudflare, path, ids):
    """R7: a repeat can fill the announced count while an object is left out."""
    cloudflare.serve(path, [{**LISTINGS[path], "id": object_id} for object_id in ids])
    assert read_error(cloudflare) == f"{path}: the results repeat an object"


@pytest.mark.parametrize("total_pages", [0, 1])
def test_an_empty_list_may_announce_zero_or_one_page(cloudflare, total_pages):
    """R5: the schema leaves open how many pages nothing fills."""
    cloudflare.routes[APPS_PATH] = lambda query: (
        200,
        listing([], int(query["page"]), total_pages=total_pages, total_count=0),
    )
    assert cloudflare.client().read(ZONE).apps == ()


def test_a_failing_middle_page_is_an_error_not_a_short_snapshot(cloudflare):
    """R5."""

    def third_pages(query: dict[str, str]) -> Answer:
        if query["page"] == "2":
            return 500, failure(1000)
        return 200, listing(
            [{"type": "app_launcher"}] * 2, int(query["page"]), total_pages=3, total_count=5
        )

    cloudflare.routes[APPS_PATH] = third_pages
    assert "HTTP 500" in read_error(cloudflare)


def test_hals_tunnel_is_found_by_its_id_beside_another_live_tunnel(cloudflare):
    """R6."""
    cloudflare.serve_tunnels(live=["another-live-tunnel", TUNNEL_ID])
    assert cloudflare.client().read(ZONE).tunnel_id == TUNNEL_ID


@pytest.mark.parametrize(
    ("live", "deleted"), [(["another"], ()), ([], (TUNNEL_ID,))], ids=["unknown id", "deleted"]
)
def test_no_live_tunnel_with_hals_id_fails_naming_the_tunnel_config(cloudflare, live, deleted):
    """R6."""
    cloudflare.serve_tunnels(live, deleted)
    assert {TUNNEL_ID, str(OWN_TUNNEL.config)} <= set(read_error(cloudflare).split())


@pytest.mark.parametrize(
    "base_url",
    [
        "http://example.com",
        "ftp://127.0.0.1",
        "http://127.0.0.1.example.com",
        "https://example.com/client/v4",
        "https://api.cloudflare.com.evil.test/client/v4",
        "https://api.cloudflare.com/client/v4/",
        "https://127.0.0.1",
    ],
)
def test_the_token_goes_only_to_cloudflares_api_or_to_http_on_loopback(base_url):
    """R4."""
    with pytest.raises(ValueError):
        CloudflareClient(TOKEN, OWN_TUNNEL, base_url=base_url)


@pytest.mark.parametrize(
    "base_url", [cloudflare_read.BASE_URL, "http://127.0.0.1:8080", "http://localhost"]
)
def test_cloudflares_api_and_loopback_are_accepted(base_url):
    """R4."""
    CloudflareClient(TOKEN, OWN_TUNNEL, base_url=base_url)


def test_the_default_base_url_is_cloudflares_https_api():
    """R4."""
    assert cloudflare_read.BASE_URL == "https://api.cloudflare.com/client/v4"


def test_the_backstop_refuses_a_connection_beyond_loopback():
    """R4."""
    with pytest.raises(AssertionError, match="leaves loopback"):
        socket.create_connection(("192.0.2.1", 9), timeout=0.1)


def test_a_deeply_nested_answer_is_a_malformed_answer_not_a_crash(cloudflare):
    """R3."""
    cloudflare.routes[APPS_PATH] = lambda _query: (200, b"[" * 200_000)
    assert "HTTP 200, malformed JSON answer" in read_error(cloudflare)


def public_app(**changes) -> dict:
    return {**self_hosted(f"www.{ZONE}", "bypass", [{"everyone": {}}]), **changes}


def with_destination(**changes) -> dict:
    return public_app(destinations=[{"type": "public", "uri": f"www.{ZONE}", **changes}])


@pytest.mark.parametrize("app_type", ["self_hosted", "ssh"])
def test_an_app_with_a_field_the_published_schema_lacks_is_refused_by_count(cloudflare, app_type):
    """R3."""
    cloudflare.serve(APPS_PATH, [public_app(type=app_type, path_rules=[])])
    message = read_error(cloudflare)
    assert message == f"{APPS_PATH}: an Access app carries 1 fields this check does not understand"


@pytest.mark.parametrize("field", ["eager_redirect_cookie_setting", "user_populations"])
@pytest.mark.parametrize("app_type", ["self_hosted", "ssh", "vnc", "rdp"])
def test_a_documented_field_beyond_the_ones_the_check_judges_is_accepted(
    cloudflare, app_type, field
):
    """R1: the whitelist is the published response schema, not the provider's resource."""
    cloudflare.serve(APPS_PATH, [public_app(type=app_type, **{field: True})])
    assert cloudflare.client().read(ZONE).apps[0].type == app_type


@pytest.mark.parametrize("name", [TOKEN, "q" * 40, "Capital", "x" * 41, "has space"], ids=str)
def test_unknown_fields_are_counted_per_level_but_never_named(cloudflare, name):
    """R3: rule 12, a response is never quoted, not even a plain-looking 40 character name."""
    cloudflare.serve(
        APPS_PATH,
        [
            public_app(
                **{name: 1, "other": 1},
                policies=[{"decision": "bypass", "include": [{"everyone": {}}], name: 1}],
            )
        ],
    )
    assert read_error(cloudflare) == (
        f"{APPS_PATH}: an Access app carries 2 fields this check does not understand"
    )
    cloudflare.serve(
        APPS_PATH, [public_app(policies=[{"decision": "bypass", "include": [], name: 1}])]
    )
    assert read_error(cloudflare) == (
        f"{APPS_PATH}: a policy carries 1 fields this check does not understand"
    )


def test_the_overrides_of_a_public_destination_are_read_with_their_path_patterns(cloudflare):
    """R1: the schema's shape, destinations[].overrides[] = {behavior, path_pattern}."""
    overrides = [{"behavior": "public", "path_pattern": "/admin/*"}]
    cloudflare.serve(APPS_PATH, [with_destination(overrides=overrides)])
    (app,) = cloudflare.client().read(ZONE).apps
    assert app.overrides == (Override(f"www.{ZONE}", "/admin/*"),)


@pytest.mark.parametrize(
    ("uri", "kept"),
    [
        (f"WWW.{ZONE.upper()}/Admin/Path", f"www.{ZONE}/Admin/Path"),
        (f"Www.{ZONE}", f"www.{ZONE}"),
        (f"www.{ZONE}/ADMIN/*", f"www.{ZONE}/ADMIN/*"),
    ],
    ids=["host and path", "host only", "path pattern"],
)
def test_only_the_host_of_a_destination_is_lower_cased_the_path_is_kept(cloudflare, uri, kept):
    """C10: the destination, and the override that names it, keep the path byte for byte."""
    overrides = [{"behavior": "public", "path_pattern": "/Admin/*"}]
    cloudflare.serve(
        APPS_PATH,
        [public_app(destinations=[{"type": "public", "uri": uri, "overrides": overrides}])],
    )
    (app,) = cloudflare.client().read(ZONE).apps
    assert (app.destinations, app.overrides) == ((kept,), (Override(kept, "/Admin/*"),))


@pytest.mark.parametrize("preflight", [True, False])
def test_options_preflight_bypass_is_read(cloudflare, preflight):
    """R1."""
    cloudflare.serve(APPS_PATH, [public_app(options_preflight_bypass=preflight)])
    assert cloudflare.client().read(ZONE).apps[0].options_preflight_bypass is preflight


@pytest.mark.parametrize(
    ("destination", "expected"),
    [
        pytest.param(
            with_destination(extra=1)["destinations"][0],
            "a public destination carries 1 fields this check does not understand",
            id="a public destination with another key",
        ),
        pytest.param(
            {
                "type": "public",
                "uri": f"www.{ZONE}",
                "overrides": [{"behavior": "public", "path_pattern": "/x", "more": 1}],
            },
            "an override carries 1 fields this check does not understand",
            id="an override with another key",
        ),
        pytest.param(
            {"type": "public", "uri": f"www.{ZONE}", "overrides": ["/x"]},
            "an override is not a map",
            id="an override that is not a map",
        ),
    ],
)
def test_a_destination_or_override_beyond_the_documented_shape_is_refused(
    cloudflare, destination, expected
):
    """R3."""
    cloudflare.serve(APPS_PATH, [public_app(destinations=[destination])])
    assert expected in read_error(cloudflare)


def test_an_app_that_secures_no_hostname_may_carry_any_field(cloudflare):
    """R1."""
    cloudflare.serve(APPS_PATH, [{"type": "app_launcher", "something_new": 1}])
    assert cloudflare.client().read(ZONE).apps == (App("app_launcher", (), ()),)


FOO = f"foo.{ZONE}"


@pytest.mark.parametrize(
    "app",
    [
        pytest.param({"type": "ssh", "domain": FOO}, id="ssh with its domain only"),
        pytest.param(
            {"type": "vnc", "domain": FOO, "whatever": 1}, id="vnc, domain, unknown field"
        ),
        pytest.param({"type": "mcp_portal", "domain": FOO}, id="mcp_portal with its domain only"),
        pytest.param({"type": "self_hosted", "domain": FOO, "destinations": []}, id="empty list"),
        pytest.param({"type": "self_hosted", "domain": FOO}, id="no destinations list"),
        pytest.param(
            {
                "type": "ssh",
                "self_hosted_domains": [FOO],
                "destinations": [{"type": "public", "uri": f"bar.{ZONE}"}],
            },
            id="a deprecated domain beside other destinations",
        ),
        pytest.param(
            {
                "type": "rdp",
                "domain": FOO,
                "destinations": [{"type": "private", "hostname": FOO}],
            },
            id="a private destination is not the domain's host",
        ),
        pytest.param({"type": "ssh", "domain": 7}, id="a domain that is no text"),
    ],
)
def test_a_secured_hostname_outside_the_public_destinations_is_refused(cloudflare, app):
    """R3: `domain` is required for these apps and not deprecated; nothing may hide in it."""
    cloudflare.serve(APPS_PATH, [{**app, "policies": []}])
    assert read_error(cloudflare).startswith(APPS_PATH)


@pytest.mark.parametrize("domain", [FOO, f"{FOO}/admin", FOO.upper()])
def test_a_domain_among_the_public_destinations_is_accepted(cloudflare, domain):
    """R1."""
    app = {"type": "ssh", "domain": domain, "destinations": [{"type": "public", "uri": FOO}]}
    cloudflare.serve(APPS_PATH, [{**app, "policies": []}])
    assert cloudflare.client().read(ZONE).apps == (App("ssh", (FOO,), ()),)


@pytest.mark.parametrize(
    "destination",
    [
        pytest.param(f"foo.{ZONE}", id="a string"),
        pytest.param({"type": "public_v2", "uri": f"foo.{ZONE}"}, id="an unknown type"),
        pytest.param({"uri": f"foo.{ZONE}"}, id="no type"),
        pytest.param({"type": ["public"], "uri": f"foo.{ZONE}"}, id="a type that is no text"),
    ],
)
def test_a_destination_that_is_no_map_of_a_published_type_is_refused(cloudflare, destination):
    """R3."""
    cloudflare.serve(APPS_PATH, [public_app(destinations=[destination])])
    assert read_error(cloudflare) == f"{APPS_PATH}: a destination is not of a published type"


@pytest.mark.parametrize(
    "destination",
    [
        {"type": "private", "cidr": "10.0.0.0/8"},
        {"type": "via_mcp_server_portal", "mcp_server_id": "m"},
    ],
)
def test_destinations_of_the_other_published_types_are_not_public_hosts(cloudflare, destination):
    """R1."""
    app = public_app(destinations=[{"type": "public", "uri": f"www.{ZONE}"}, destination])
    cloudflare.serve(APPS_PATH, [app])
    assert cloudflare.client().read(ZONE).apps[0].destinations == (f"www.{ZONE}",)


@pytest.mark.parametrize(
    "destination",
    [
        {"type": "worker", "worker_id": "w"},
        {"type": "all_workers"},
        {"type": "preview_worker", "worker_id": "w"},
        {"type": "all_preview_workers"},
    ],
)
def test_an_app_with_a_worker_destination_is_refused_as_not_judged(cloudflare, destination):
    """R3: a Worker route can protect a public host, which the check cannot see."""
    app = public_app(destinations=[{"type": "public", "uri": f"www.{ZONE}"}, destination])
    cloudflare.serve(APPS_PATH, [app])
    assert read_error(cloudflare) == (
        f"{APPS_PATH}: an Access app has a Worker destination, which this check does not judge"
    )


@pytest.mark.parametrize(
    "uri",
    [f"{FOO}.", f"{FOO}:443", f"https://{FOO}", f"/{FOO}", f"a..{ZONE}", f"*{ZONE}", f"a b.{ZONE}"],
)
def test_a_destination_host_that_is_no_plain_hostname_is_refused(cloudflare, uri):
    """R3."""
    cloudflare.serve(APPS_PATH, [public_app(destinations=[{"type": "public", "uri": uri}])])
    assert read_error(cloudflare) == (
        f"{APPS_PATH}: a destination host is not a plain lower-case hostname"
    )


@pytest.mark.parametrize("uri", [f"*.{ZONE}", f"{FOO}/admin/*", ZONE])
def test_a_wildcard_or_a_path_after_the_host_is_accepted(cloudflare, uri):
    """R1."""
    app = public_app(domain=uri, destinations=[{"type": "public", "uri": uri}])
    cloudflare.serve(APPS_PATH, [app])
    assert cloudflare.client().read(ZONE).apps[0].destinations == (uri,)


@pytest.mark.parametrize("value", ["true", "false", 1, 0, None, []])
def test_a_malformed_options_preflight_bypass_is_refused(cloudflare, value):
    """R3."""
    cloudflare.serve(APPS_PATH, [public_app(options_preflight_bypass=value)])
    assert read_error(cloudflare) == f"{APPS_PATH}: options_preflight_bypass is not a boolean"


@pytest.mark.parametrize(
    "condition",
    [
        pytest.param({"exclude": [{"email": {"email": "a@b.c"}}]}, id="exclude"),
        pytest.param({"require": [{"everyone": {}}]}, id="require"),
        pytest.param({"approval_required": True}, id="approval"),
        pytest.param({"isolation_required": True}, id="isolation"),
        pytest.param({"purpose_justification_required": True}, id="purpose justification"),
        pytest.param({"connection_rules": {"ssh": {"usernames": ["root"]}}}, id="connection rules"),
    ],
)
def test_a_policy_restricted_beyond_its_include_is_marked_with_extra_conditions(
    cloudflare, condition
):
    """R1."""
    policy = {"decision": "bypass", "include": [{"everyone": {}}], **condition}
    cloudflare.serve(APPS_PATH, [public_app(policies=[policy])])
    assert cloudflare.client().read(ZONE).apps[0].policies[0].extra_conditions is True


@pytest.mark.parametrize(
    "idle",
    [
        {"exclude": [], "require": []},
        {"approval_required": False, "isolation_required": False},
        {"purpose_justification_required": False, "connection_rules": {}},
        {"name": "p", "precedence": 1, "session_duration": "24h", "approval_groups": []},
    ],
)
def test_a_policy_with_empty_or_unset_restrictions_has_no_extra_conditions(cloudflare, idle):
    """R1."""
    policy = {"decision": "bypass", "include": [{"everyone": {}}], **idle}
    cloudflare.serve(APPS_PATH, [public_app(policies=[policy])])
    assert cloudflare.client().read(ZONE).apps[0].policies[0].extra_conditions is False


@pytest.mark.parametrize(
    "malformed",
    [{"exclude": "x"}, {"require": {}}, {"approval_required": "true"}, {"connection_rules": []}],
)
def test_a_malformed_policy_restriction_is_refused(cloudflare, malformed):
    """R3."""
    policy = {"decision": "bypass", "include": [{"everyone": {}}], **malformed}
    cloudflare.serve(APPS_PATH, [public_app(policies=[policy])])
    assert read_error(cloudflare).startswith(APPS_PATH)


@pytest.mark.parametrize(
    "identifier", ["z", "A" * 32, "a" * 31, "a" * 33, TOKEN, "../" + "a" * 29], ids=repr
)
@pytest.mark.parametrize("where", ["zone", "account"])
def test_an_id_that_is_not_32_lower_case_hex_never_enters_a_request_path(
    cloudflare, where, identifier
):
    """R3."""
    zone = {"id": ZONE_ID, "name": ZONE, "account": {"id": ACCOUNT_ID}}
    if where == "zone":
        zone["id"] = identifier
    else:
        zone["account"]["id"] = identifier
    cloudflare.serve("/zones", [zone])
    assert read_error(cloudflare).startswith("/zones: a")
    assert {path for path, _, _ in cloudflare.requests} == {"/zones"}


def test_the_tunnel_list_is_paged_by_its_documented_shape_without_total_pages(cloudflare):
    """R5."""
    tunnels = [{"id": f"tunnel-{number}"} for number in range(3)]
    cloudflare.serve(TUNNELS_PATH, tunnels)
    assert "a tunnel other than" in read_error(cloudflare)
    assert [q["page"] for path, q, _ in cloudflare.requests if path == TUNNELS_PATH] == ["1", "2"]


def test_the_tunnel_list_fails_closed_when_its_total_count_is_not_met(cloudflare):
    """R5."""
    cloudflare.routes[TUNNELS_PATH] = lambda query: (
        200,
        listing([{"id": TUNNEL_ID}], int(query["page"]), total_pages=None, total_count=3),
    )
    assert read_error(cloudflare).startswith(TUNNELS_PATH)
