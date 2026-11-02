"""The live smoke's sign-in: the person confirms a link and a code (OAuth device grant, RFC 8628)
and the smoke carries on by itself, so nothing is copied back (edge#297, after edge#184 D6).

Keycloak accepts a device request for the `songmaker` client only with its client secret, which
lives on the operator's machine alone. No token and no secret is printed. Only the standard
library is used.
"""

from __future__ import annotations

import base64
import hashlib
import http
import http.client
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from collections.abc import Callable, Mapping
from dataclasses import dataclass

from smoke import Tokens

OIDC = "https://auth.hallucinai.de/realms/hallucinai/protocol/openid-connect"
CLIENT = "songmaker"
TOKEN_TIMEOUT_SECONDS = 30
# Cloudflare in front of the token endpoint refuses the default Python-urllib agent (error 1010)
USER_AGENT = "edge-live-smoke/1"
DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"
SLOW_DOWN_SECONDS = 5  # RFC 8628, 3.5: the interval grows by at least five seconds
DEFAULT_INTERVAL_SECONDS = 5  # RFC 8628, 3.2: the interval when the server names none
MAX_LIFETIME_SECONDS = 3600
MAX_INTERVAL_SECONDS = 60
READ_CHUNK_BYTES = 4096
MAX_ANSWER_BYTES = 64 * 1024  # a real answer is a few hundred bytes


class SignInFailed(Exception):
    """The sign-in cannot go on; the message is the one line to print, free of any secret."""


def read_answer(answer, deadline: float, clock: Callable[[], float]) -> object:
    """The JSON of a response read within the deadline and the size cap; anything else raises.

    Each `read1` waits on one socket operation, which the request timeout bounds.
    """
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = answer.read1(READ_CHUNK_BYTES)
        if clock() > deadline:
            raise TimeoutError("the answer arrived after its deadline")
        if not chunk:
            return json.loads(b"".join(chunks))
        size += len(chunk)
        if size > MAX_ANSWER_BYTES:
            raise ValueError("the answer is larger than any real one")
        chunks.append(chunk)


def post_form(
    path: str,
    form: Mapping[str, str],
    client_secret: str,
    urlopen,
    deadline: float,
    clock: Callable[[], float],
) -> tuple[int, object]:
    """The status and the JSON Keycloak answered, whether it accepted or refused, by `deadline`."""
    timeout = min(TOKEN_TIMEOUT_SECONDS, deadline - clock())
    if timeout <= 0:
        raise SignInFailed(f"the {path} endpoint gave no answer to read")
    body = urllib.parse.urlencode({**form, "client_id": CLIENT, "client_secret": client_secret})
    request = urllib.request.Request(  # noqa: S310 - the URL is the fixed https issuer address of the service
        f"{OIDC}/{path}", body.encode(), headers={"User-Agent": USER_AGENT}
    )
    try:
        try:
            with urlopen(request, timeout=timeout) as answer:
                status, document = http.HTTPStatus.OK, read_answer(answer, deadline, clock)
        except urllib.error.HTTPError as refusal:
            status, document = refusal.code, read_answer(refusal, deadline, clock)
    except OSError, http.client.HTTPException, ValueError:
        raise SignInFailed(f"the {path} endpoint gave no answer to read") from None
    if not isinstance(document, dict):
        raise SignInFailed(f"the {path} endpoint gave no answer to read")
    return status, document


def access_token(
    form: Mapping[str, str],
    client_secret: str,
    urlopen,
    clock: Callable[[], float],
) -> str:
    deadline = clock() + TOKEN_TIMEOUT_SECONDS
    status, document = post_form("token", form, client_secret, urlopen, deadline, clock)
    if status != 200:
        raise SignInFailed(f"the token endpoint answered {status}")
    token = document.get("access_token")
    if not isinstance(token, str):
        raise SignInFailed("the token endpoint gave no access token")
    return token


def pkce_pair() -> tuple[str, str]:
    """The client requires PKCE (S256) for every flow, the device grant included."""
    verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


@dataclass(frozen=True)
class DeviceAuthorization:
    device_code: str
    user_code: str
    link: str
    expires_in: int
    interval: int


def within(value: object, upper_bound: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 < value <= upper_bound


def device_authorization(
    client_secret: str, challenge: str, urlopen, clock: Callable[[], float]
) -> DeviceAuthorization:
    form = {"scope": "openid", "code_challenge": challenge, "code_challenge_method": "S256"}
    deadline = clock() + TOKEN_TIMEOUT_SECONDS
    status, document = post_form("auth/device", form, client_secret, urlopen, deadline, clock)
    link = document.get("verification_uri_complete") or document.get("verification_uri")
    interval = document.get("interval", DEFAULT_INTERVAL_SECONDS)
    strings = (document.get("device_code"), document.get("user_code"), link)
    if (
        status != 200
        or not all(isinstance(text, str) and text for text in strings)
        or not within(document.get("expires_in"), MAX_LIFETIME_SECONDS)
        or not within(interval, MAX_INTERVAL_SECONDS)
    ):
        raise SignInFailed(f"the device endpoint answered {status} and started no sign-in")
    return DeviceAuthorization(
        document["device_code"], document["user_code"], link, document["expires_in"], interval
    )


def person_token(
    authorization: DeviceAuthorization,
    expiry: float,
    verifier: str,
    client_secret: str,
    urlopen,
    pause: Callable[[float], None],
    clock: Callable[[], float],
) -> str:
    """Polls until the person confirms; `expiry` is absolute and no poll or token follows it."""
    interval = authorization.interval
    while (remaining := expiry - clock()) > 0:
        pause(min(interval, remaining))
        if clock() >= expiry:
            break
        status, document = post_form(
            "token",
            {
                "grant_type": DEVICE_GRANT,
                "device_code": authorization.device_code,
                "code_verifier": verifier,
            },
            client_secret,
            urlopen,
            expiry,
            clock,
        )
        if clock() > expiry:
            break
        if status == 200 and isinstance(document.get("access_token"), str):
            return document["access_token"]
        match document.get("error"):
            case "authorization_pending":
                continue
            case "slow_down":
                interval += SLOW_DOWN_SECONDS
            case "access_denied":
                raise SignInFailed("the sign-in was refused in the browser (access_denied)")
            case "expired_token":
                break
            case _:
                raise SignInFailed(f"the token endpoint answered {status}")
    raise SignInFailed("the code ran out before it was confirmed; run the smoke again")


def open_in_graphical_session(link: str) -> None:
    """A browser opens only where a display is; a console browser would take the terminal."""
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        webbrowser.open(link)


def sign_in(
    client_secret: str,
    urlopen=urllib.request.urlopen,
    pause: Callable[[float], None] = time.sleep,
    open_link: Callable[[str], object] = open_in_graphical_session,
    clock: Callable[[], float] = time.monotonic,
) -> Tokens:
    verifier, challenge = pkce_pair()
    authorization = device_authorization(client_secret, challenge, urlopen, clock)
    expiry = clock() + authorization.expires_in
    print(  # noqa: T201 - the sign-in prompt for the person at the terminal
        f"Open {authorization.link} and confirm the code {authorization.user_code}",
        file=sys.stderr,
    )
    # best effort and off the poll loop: no opener can delay the polling or outlast the code
    threading.Thread(target=open_link, args=(authorization.link,), daemon=True).start()
    person = person_token(authorization, expiry, verifier, client_secret, urlopen, pause, clock)
    workload = access_token({"grant_type": "client_credentials"}, client_secret, urlopen, clock)
    return Tokens(person=person, workload=workload)
