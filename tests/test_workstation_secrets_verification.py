from __future__ import annotations

import http.server
import json
import os
import threading
import urllib.request
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from support.workstation_secrets_support import FakeTerminal, run_wizard, squeezed
from support import workstation_secrets_wizard
from support.workstation_secrets_wizard import PASSPHRASE_FILE, PASTED_VALUE, files_under

from hal.workstation.secrets_setup import UNSENDABLE_PASTE, Boundaries, Outcome, Response, Verdict, WalkEnd, http_fetch, verify_token
from hal.workstation.secrets_view import Provider, TokenSource

home, terminal = workstation_secrets_wizard.home, workstation_secrets_wizard.terminal

GITHUB = TokenSource(Provider.GITHUB, "example-org", ("metadata:read",), 366)
CLOUDFLARE = TokenSource(Provider.CLOUDFLARE, "example.invalid", ("Zone › DNS › Read",), 30)


CLOUDFLARE_DISABLED = "Cloudflare reports the token as disabled, not active"
CLOUDFLARE_UNREADABLE = "Cloudflare reports the token as unknown, not active"


def cloudflare_answer(status: object, not_before: object = None, *, with_start: bool = False) -> bytes:
    result = {"id": "0", "status": status, **({"not_before": not_before} if with_start or not_before else {})}
    return json.dumps({"success": True, "result": result}).encode()


CLOUDFLARE_START = "2026-12-30T23:00:00Z"


def not_yet_valid(start_in_utc: str) -> str:
    return (
        f"Cloudflare reports the token as active, but it is not valid before {start_in_utc} UTC; "
        "clear the start date on the token's Edit page in Cloudflare, then paste again"
    )


CLOUDFLARE_NOT_YET_VALID = not_yet_valid("30.12.2026 23:00")


@pytest.mark.parametrize(
    ("source", "response", "expected"),
    [
        (GITHUB, Response(200, b"{}"), Verdict(Outcome.ACCEPTED)),
        (GITHUB, Response(401, b""), Verdict(Outcome.REFUSED, "GitHub answers 401")),
        (CLOUDFLARE, Response(200, cloudflare_answer("active")), Verdict(Outcome.ACCEPTED)),
        (CLOUDFLARE, Response(200, cloudflare_answer("disabled")), Verdict(Outcome.REFUSED, CLOUDFLARE_DISABLED)),
        (CLOUDFLARE, Response(200, b"[]"), Verdict(Outcome.REFUSED, CLOUDFLARE_UNREADABLE)),
        (CLOUDFLARE, Response(200, b"not json"), Verdict(Outcome.REFUSED, CLOUDFLARE_UNREADABLE)),
        (CLOUDFLARE, Response(403, b""), Verdict(Outcome.REFUSED, "Cloudflare answers 403")),
        (CLOUDFLARE, None, Verdict(Outcome.UNREACHABLE, "Cloudflare unreachable; try again later")),
    ],
)
def test_a_token_counts_only_once_its_provider_confirms_it(source: TokenSource, response: Response | None, expected: Verdict) -> None:
    """#36 rule 2.4 / #10 line 4: a token counts only once its provider confirms it."""
    assert verify_token(source, PASTED_VALUE, lambda _request: response) == expected


CLOUDFLARE_UNREADABLE_START = (
    "Cloudflare's answer has a start date that cannot be read; check the token's TTL on its Edit page, then paste again"
)
CLOUDFLARE_START_INSTANT = datetime(2026, 12, 30, 23, 0, tzinfo=UTC)
REFUSED_UNTIL_START = Verdict(Outcome.REFUSED, CLOUDFLARE_NOT_YET_VALID)
ACCEPTED = Verdict(Outcome.ACCEPTED)


@pytest.mark.parametrize(
    ("start", "now", "expected"),
    [
        (CLOUDFLARE_START, datetime(2026, 10, 19, tzinfo=UTC), REFUSED_UNTIL_START),
        (CLOUDFLARE_START, CLOUDFLARE_START_INSTANT + timedelta(seconds=1), ACCEPTED),
        (CLOUDFLARE_START, CLOUDFLARE_START_INSTANT, ACCEPTED),
        ("2026-12-31T00:00:00+01:00", CLOUDFLARE_START_INSTANT, ACCEPTED),
        ("2026-12-30T22:30:00-01:00", CLOUDFLARE_START_INSTANT, Verdict(Outcome.REFUSED, not_yet_valid("30.12.2026 23:30"))),
        ("2026-12-31T00:00:01+01:00", CLOUDFLARE_START_INSTANT, REFUSED_UNTIL_START),
        ("2026-12-30T23:00:00", CLOUDFLARE_START_INSTANT - timedelta(seconds=1), REFUSED_UNTIL_START),
        ("2026-12-30T23:00:00", CLOUDFLARE_START_INSTANT, ACCEPTED),
        (None, CLOUDFLARE_START_INSTANT, ACCEPTED),
        ("invalid", CLOUDFLARE_START_INSTANT, Verdict(Outcome.REFUSED, CLOUDFLARE_UNREADABLE_START)),
        (1767222000, CLOUDFLARE_START_INSTANT, Verdict(Outcome.REFUSED, CLOUDFLARE_UNREADABLE_START)),
    ],
    ids=[
        "start in the future",
        "start in the past",
        "start exactly now",
        "positive offset, exactly now",
        "negative offset, still ahead",
        "positive offset, one second ahead",
        "no offset is read as UTC, ahead",
        "no offset is read as UTC, exactly now",
        "null start",
        "unreadable text",
        "not text",
    ],
)
def test_a_cloudflare_token_counts_only_from_its_start_date(start: object, now: datetime, expected: Verdict) -> None:
    """#54 rule 1: an active token whose start date lies ahead or cannot be read is refused; one without or past it passes."""
    response = Response(200, cloudflare_answer("active", start, with_start=True))

    assert verify_token(CLOUDFLARE, PASTED_VALUE, lambda _request: response, lambda: now) == expected


def test_the_default_clock_refuses_a_start_date_far_in_the_future() -> None:
    response = Response(200, cloudflare_answer("active", "9999-01-01T00:00:00Z"))

    assert verify_token(CLOUDFLARE, PASTED_VALUE, lambda _request: response).outcome is Outcome.REFUSED


@pytest.mark.parametrize(
    ("source", "url"),
    [
        (GITHUB, "https://api.github.com/orgs/example-org/actions/secrets?per_page=1"),
        (CLOUDFLARE, "https://api.cloudflare.com/client/v4/user/tokens/verify"),
    ],
)
def test_the_check_asks_the_provider_with_the_token_as_a_bearer(source: TokenSource, url: str) -> None:
    """#36 rule 2.4: the check asks the provider's address with the token as a bearer."""
    sent: list[urllib.request.Request] = []

    verify_token(source, PASTED_VALUE, lambda request: sent.append(request))

    (request,) = sent
    assert (request.get_method(), request.full_url) == ("GET", url)
    assert request.get_header("Authorization") == f"Bearer {PASTED_VALUE}"


class _Answers(http.server.BaseHTTPRequestHandler):
    """Answers /ok, sends /redirect on to /ok, and notes the Authorization each path received."""

    seen: list[tuple[str, str | None]]

    def do_GET(self) -> None:  # noqa: N802 - the name http.server calls
        self.seen.append((self.path, self.headers.get("Authorization")))
        if self.path == "/not-yet-valid":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(cloudflare_answer("active", CLOUDFLARE_START))
            return
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return
        status = 200 if self.path == "/ok" else 404
        self.send_response(status)
        self.end_headers()
        self.wfile.write(b"ok" if status == 200 else b"")

    def log_message(self, *_args: object) -> None:
        """Silent: a test server never writes to stderr."""


@dataclass(frozen=True)
class LocalServer:
    url: str
    seen: list[tuple[str, str | None]]

    def fetch(self, path: str) -> Callable[[urllib.request.Request], Response | None]:
        """The real fetch, sent here instead of to the provider: the request verify_token built, headers and all."""

        def fetch(request: urllib.request.Request) -> Response | None:
            request.full_url = f"{self.url}{path}"
            return http_fetch(request)

        return fetch


@pytest.fixture
def local_server() -> Iterator[LocalServer]:
    seen: list[tuple[str, str | None]] = []
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("Answers", (_Answers,), {"seen": seen}))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield LocalServer(f"http://127.0.0.1:{server.server_address[1]}", seen)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_a_fetch_returns_the_status_and_body_or_none_when_nothing_answers(local_server: LocalServer) -> None:
    """#36 rule 2.4: an answer is told apart from no answer, so an unreachable provider is never a refusal."""
    closed_port = local_server.url.rsplit(":", 1)[0] + ":1"

    assert http_fetch(urllib.request.Request(f"{local_server.url}/ok")) == Response(200, b"ok")  # noqa: S310 - the URL is that of the loopback test server or a closed port of it
    assert http_fetch(urllib.request.Request(f"{local_server.url}/missing")) == Response(404, b"")  # noqa: S310 - the URL is that of the loopback test server or a closed port of it
    assert http_fetch(urllib.request.Request(f"{closed_port}/ok")) is None  # noqa: S310 - the URL is that of the loopback test server or a closed port of it


def test_a_redirect_never_carries_the_token_on(local_server: LocalServer) -> None:
    """#36 rule 3: the bearer reaches the provider's address only; the place a redirect names never receives it."""
    verify_token(GITHUB, PASTED_VALUE, local_server.fetch("/redirect"))

    assert local_server.seen == [("/redirect", f"Bearer {PASTED_VALUE}"), ("/ok", None)]


UNSENDABLE_CHARACTERS = {"carriage return": "\r", "line feed": "\n", "nul": "\x00", "tab": "\t", "space": " ", "euro sign": "€"}


def canary_with(character: str) -> str:
    return f"FAKE-CANARY-HEAD{character}FAKE-CANARY-TAIL"


@pytest.mark.parametrize("character", UNSENDABLE_CHARACTERS.values(), ids=UNSENDABLE_CHARACTERS.keys())
def test_a_paste_that_is_not_visible_ascii_is_refused_unsent_unshown_and_unwritten(
    home: Path, terminal: FakeTerminal, local_server: LocalServer, capsys, character: str
) -> None:
    """#36 rule 3 / #10 line 2: a paste no token can be is refused with a fixed line; it is never sent, shown or written."""
    canary = canary_with(character)
    real_check = Boundaries(terminal.boundary(), lambda source, value: verify_token(source, value, local_server.fetch("/ok")), os.fsync)
    terminal.pastes = [canary, "", canary, ""]

    end = run_wizard(home, real_check)

    captured = capsys.readouterr()
    assert end is WalkEnd.STILL_OPEN
    rejection = f"rejected {UNSENDABLE_PASTE} · paste again or leave empty"
    assert sorted(line.split(" ", 2)[1] for line in squeezed(captured.out) if line.endswith(rejection)) == ["cloudflare/read", "github/read"]
    for part in (canary, "FAKE-CANARY-HEAD", "FAKE-CANARY-TAIL"):
        assert part not in captured.out + captured.err
    assert local_server.seen == []
    assert files_under(home) == {PASSPHRASE_FILE}


def test_the_walk_refuses_a_token_with_a_future_start_date_and_writes_nothing(
    home: Path, terminal: FakeTerminal, local_server: LocalServer, capsys
) -> None:
    """#54 rule 1 / #10 line 22: a rejected value is refused with one line naming the start date and is never written."""
    now = datetime(2026, 10, 19, tzinfo=UTC)
    real_check = Boundaries(
        terminal.boundary(), lambda source, value: verify_token(source, value, local_server.fetch("/not-yet-valid"), lambda: now), os.fsync
    )
    terminal.pastes = [PASTED_VALUE, "", ""]

    end = run_wizard(home, real_check)

    captured = capsys.readouterr()
    assert end is WalkEnd.STILL_OPEN
    assert f"✗ cloudflare/read rejected {CLOUDFLARE_NOT_YET_VALID} · paste again or leave empty" in squeezed(captured.out)
    assert PASTED_VALUE not in captured.out + captured.err
    assert files_under(home) == {PASSPHRASE_FILE}


@pytest.mark.parametrize("character", ["\r", "\n", "€"], ids=["carriage return", "line feed", "euro sign"])
def test_a_value_http_cannot_send_is_refused_without_quoting_it(local_server: LocalServer, character: str) -> None:
    """#36 rule 3 / #10 line 2: a value the HTTP layer refuses to send is a refusal whose detail never quotes the value."""
    verdict = verify_token(GITHUB, canary_with(character), local_server.fetch("/ok"))

    assert verdict == Verdict(Outcome.REFUSED, "the value cannot be sent to GitHub as a token")
