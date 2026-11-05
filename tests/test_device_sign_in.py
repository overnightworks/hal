"""The live smoke's sign-in (`agent-service/device_sign_in.py`, #297): the device grant against a
scripted Keycloak.
"""

import base64
import hashlib
import http.client
import io
import json
import threading
import urllib.error
import urllib.parse
import urllib.request
import webbrowser

import device_sign_in
import pytest
from smoke import Tokens


class FakeKeycloak:
    """Answers each request in turn (an HTTPError is a 400 refusal) and keeps what was asked."""

    def __init__(self, *answers: dict, clock: FakeClock | None = None, latency: float = 0) -> None:
        self.answers = list(answers)
        self.requests: list[tuple[str, dict[str, str]]] = []
        self.timeouts: list[float] = []
        self.clock = clock
        self.latency = latency

    def __call__(self, request: urllib.request.Request, timeout: float):
        self.timeouts.append(timeout)
        if self.clock:
            self.clock.now += self.latency
        assert request.get_header("User-agent") == device_sign_in.USER_AGENT
        path = request.full_url.removeprefix(f"{device_sign_in.OIDC}/")
        form = {k: v[0] for k, v in urllib.parse.parse_qs(request.data.decode()).items()}
        self.requests.append((path, form))
        answer = self.answers.pop(0)
        if "error" in answer:
            raise urllib.error.HTTPError(
                request.full_url, 400, "refused", {}, io.BytesIO(json.dumps(answer).encode())
            )
        return io.BytesIO(json.dumps(answer).encode())


class FakeClock:
    """A monotonic clock that only the fake pause, the fake answers and the fake browser advance."""

    def __init__(self) -> None:
        self.now = 1000.0
        self.pauses: list[float] = []

    def __call__(self) -> float:
        return self.now

    def pause(self, seconds: float) -> None:
        self.pauses.append(seconds)
        self.now += seconds


AUTHORIZATION = {
    "device_code": "the-device-code",
    "user_code": "ABCD-EFGH",
    "verification_uri_complete": "https://auth.example/device?user_code=ABCD-EFGH",
    "expires_in": 300,
    "interval": 5,
}
PENDING = {"error": "authorization_pending"}


def signed_in(*answers: dict, authorization: dict = AUTHORIZATION, latency: float = 0):
    clock = FakeClock()
    keycloak = FakeKeycloak(authorization, *answers, clock=clock, latency=latency)
    opened: list[str] = []
    opener_ran = threading.Event()

    def opener(link: str) -> None:
        opened.append(link)
        opener_ran.set()

    outcome = device_sign_in.sign_in("the-secret", keycloak, clock.pause, opener, clock)
    assert opener_ran.wait(timeout=10)
    return outcome, keycloak, clock.pauses, opened


def test_the_sign_in_waits_for_the_confirmation_and_asks_for_the_workload_token(capsys):
    tokens, keycloak, pauses, opened = signed_in(
        PENDING, {"access_token": "person"}, {"access_token": "workload"}
    )

    assert tokens == Tokens(person="person", workload="workload")
    assert pauses == [5, 5]
    assert opened == [AUTHORIZATION["verification_uri_complete"]]
    shown = capsys.readouterr().err
    assert AUTHORIZATION["verification_uri_complete"] in shown
    assert "ABCD-EFGH" in shown
    assert all(form["client_secret"] == "the-secret" for _, form in keycloak.requests)
    assert keycloak.requests[1][1]["device_code"] == "the-device-code"
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(keycloak.requests[1][1]["code_verifier"].encode()).digest()
    ).rstrip(b"=")
    assert keycloak.requests[0][1]["code_challenge"] == challenge.decode()
    assert keycloak.requests[3][1]["grant_type"] == "client_credentials"
    assert not any(text in shown for text in ("person", "the-secret", "the-device-code"))


def test_slow_down_makes_the_sign_in_wait_longer_between_asks():
    _, _, pauses, _ = signed_in(
        {"error": "slow_down"}, PENDING, {"access_token": "p"}, {"access_token": "w"}
    )

    assert pauses == [5, 10, 10]


def test_a_refusal_in_the_browser_ends_the_sign_in_with_one_sentence():
    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        signed_in({"error": "access_denied"})

    assert str(stopped.value) == "the sign-in was refused in the browser (access_denied)"


def test_an_expired_code_ends_the_sign_in_with_one_sentence():
    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        signed_in(PENDING, {"error": "expired_token"})

    assert str(stopped.value) == "the code ran out before it was confirmed; run the smoke again"


def test_request_time_counts_against_the_lifetime_and_no_poll_follows_the_deadline():
    clock = FakeClock()
    keycloak = FakeKeycloak(
        {**AUTHORIZATION, "expires_in": 12}, *[PENDING] * 5, clock=clock, latency=3
    )
    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.sign_in("s", keycloak, clock.pause, lambda _link: None, clock)

    assert str(stopped.value) == "the code ran out before it was confirmed; run the smoke again"
    polls = [path for path, _ in keycloak.requests if path == "token"]
    assert len(polls) == 1  # 5 s wait and a 3 s answer leave 4 s, which the last wait spends
    assert clock.now == 1015  # the deadline set when the code arrived, never past it


def test_a_poll_never_waits_longer_than_the_code_has_left():
    clock = FakeClock()
    keycloak = FakeKeycloak(
        {**AUTHORIZATION, "expires_in": 7}, *[PENDING] * 5, clock=clock, latency=0
    )
    with pytest.raises(device_sign_in.SignInFailed):
        device_sign_in.sign_in("s", keycloak, clock.pause, lambda _link: None, clock)

    assert clock.pauses == [5, 2]
    assert len(keycloak.requests) == 2  # the authorization and one poll, none at the deadline
    assert keycloak.timeouts[1] == 2


def test_an_opener_that_never_returns_does_not_delay_the_polling():
    clock = FakeClock()
    keycloak = FakeKeycloak(
        AUTHORIZATION, {"access_token": "p"}, {"access_token": "w"}, clock=clock
    )
    release = threading.Event()

    tokens = device_sign_in.sign_in("s", keycloak, clock.pause, lambda _link: release.wait(), clock)
    release.set()

    assert tokens == Tokens(person="p", workload="w")


def test_a_poll_is_given_at_most_the_time_left_as_its_request_timeout():
    clock = FakeClock()
    keycloak = FakeKeycloak(
        {**AUTHORIZATION, "expires_in": 20},
        PENDING,
        {"access_token": "p"},
        {"access_token": "w"},
        clock=clock,
        latency=1,
    )
    device_sign_in.sign_in("s", keycloak, clock.pause, lambda _link: None, clock)

    assert keycloak.timeouts[1] == 15  # 20 s of life, 5 s of waiting


def test_an_omitted_interval_defaults_to_five_seconds():
    without_interval = {k: v for k, v in AUTHORIZATION.items() if k != "interval"}

    _, _, pauses, _ = signed_in(
        {"access_token": "p"}, {"access_token": "w"}, authorization=without_interval
    )

    assert pauses == [5]


def test_without_a_complete_link_the_plain_link_opens_and_the_code_is_shown(capsys):
    plain = {k: v for k, v in AUTHORIZATION.items() if k != "verification_uri_complete"}
    plain["verification_uri"] = "https://auth.example/device"

    _, _, _, opened = signed_in({"access_token": "p"}, {"access_token": "w"}, authorization=plain)

    assert opened == ["https://auth.example/device"]
    shown = capsys.readouterr().err
    assert "https://auth.example/device" in shown
    assert "ABCD-EFGH" in shown


@pytest.mark.parametrize(
    "malformed",
    [
        {"expires_in": 0},
        {"expires_in": -1},
        {"expires_in": "300"},
        {"expires_in": 300.5},
        {"expires_in": True},
        {"expires_in": 10**9},
        {"expires_in": None},
        {"interval": 0},
        {"interval": -5},
        {"interval": "5"},
        {"interval": 1.5},
        {"interval": 10**6},
        {"interval": None},
        {"device_code": ""},
        {"device_code": 7},
        {"user_code": None},
        {"verification_uri_complete": None},
    ],
)
def test_a_malformed_device_authorization_ends_the_sign_in_without_naming_a_value(malformed):
    authorization = {**AUTHORIZATION, **malformed}

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        signed_in(authorization=authorization)

    assert str(stopped.value) == "the device endpoint answered 200 and started no sign-in"


@pytest.mark.parametrize(
    ("environment", "opened"),
    [({}, []), ({"DISPLAY": ":0"}, ["link"]), ({"WAYLAND_DISPLAY": "wayland-0"}, ["link"])],
)
def test_the_link_opens_only_in_a_graphical_session(monkeypatch, environment, opened):
    for name in ("DISPLAY", "WAYLAND_DISPLAY"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    seen: list[str] = []
    monkeypatch.setattr(webbrowser, "open", seen.append)

    device_sign_in.open_in_graphical_session("link")

    assert seen == opened


class TrickledAnswer:
    """Hands out a chunk per read and lets the clock move on by `delay` with each."""

    def __init__(
        self, clock: FakeClock, chunks: list[bytes], delay: float = 0, closing: float = 0
    ) -> None:
        self.clock, self.chunks, self.delay, self.closing = clock, chunks, delay, closing

    def __enter__(self):
        return self

    def __exit__(self, *_exc) -> None:
        self.clock.now += self.closing

    def read1(self, _size: int) -> bytes:
        self.clock.now += self.delay
        return self.chunks.pop(0) if self.chunks else b""


def trickling(clock: FakeClock, chunks: list[bytes], delay: float = 0, closing: float = 0):
    def urlopen(_request, timeout):
        return TrickledAnswer(clock, chunks, delay, closing)

    return urlopen


def test_a_response_that_trickles_past_its_deadline_is_no_answer_and_is_read_no_further():
    clock = FakeClock()
    chunks = [b"{"] + [b" "] * 50 + [b"}"]  # a few bytes per read, each read one second

    slow = trickling(clock, chunks, 1)

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.post_form("token", {}, "s", slow, clock.now + 5, clock)

    assert str(stopped.value) == "the token endpoint gave no answer to read"
    assert len(chunks) > 40  # it stopped at the deadline, not at the end of the stream


def test_valid_json_over_the_size_cap_is_refused_only_because_of_the_cap(monkeypatch):
    padding = "a" * (device_sign_in.MAX_ANSWER_BYTES + 1)
    document = json.dumps({"padding": padding}).encode()
    chunks = [document[at : at + 4096] for at in range(0, len(document), 4096)]
    clock = FakeClock()
    capped = trickling(clock, list(chunks))

    with pytest.raises(device_sign_in.SignInFailed):
        device_sign_in.post_form("token", {}, "s", capped, 2000, clock)

    monkeypatch.setattr(device_sign_in, "MAX_ANSWER_BYTES", 2 * len(document))
    status, answer = device_sign_in.post_form(
        "token", {}, "s", trickling(clock, list(chunks)), 2000, clock
    )
    assert (status, answer) == (200, {"padding": padding})


def test_a_token_that_arrives_after_the_code_expired_is_refused():
    clock = FakeClock()
    expiry = clock.now + 10
    late = trickling(clock, [b'{"access_token": "late"}'], closing=11)
    authorization = device_sign_in.DeviceAuthorization("code", "user", "link", 10, 5)

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.person_token(
            authorization,
            expiry,
            "verifier",
            "s",
            late,
            clock.pause,
            clock,
        )

    assert str(stopped.value) == "the code ran out before it was confirmed; run the smoke again"


def test_a_token_after_the_original_expiry_is_refused_though_a_rebuilt_deadline_would_allow_it():
    class SlowClock(FakeClock):
        """Until the request goes out, each look at the clock costs `delay` seconds."""

        delay = 0.25

        def __call__(self) -> float:
            self.now += self.delay
            return self.now

    clock = SlowClock()
    expiry = clock.now + 6
    arrival = expiry + 0.1  # after the expiry, before the expiry plus the time lost on the way
    answer = TrickledAnswer(clock, [b'{"access_token": "late"}'])

    def urlopen(_request, timeout):
        clock.delay = 0
        clock.now = arrival
        return answer

    authorization = device_sign_in.DeviceAuthorization("code", "user", "link", 6, 5)

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.person_token(
            authorization,
            expiry,
            "verifier",
            "s",
            urlopen,
            clock.pause,
            clock,
        )

    assert str(stopped.value) == "the token endpoint gave no answer to read"


def test_a_device_request_keycloak_refuses_starts_no_sign_in():
    keycloak = FakeKeycloak({"error": "unauthorized_client"})

    clock = FakeClock()

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.sign_in("wrong", keycloak, lambda _seconds: None, lambda _link: None, clock)

    assert str(stopped.value) == "the device endpoint answered 400 and started no sign-in"


@pytest.mark.parametrize(
    "answer",
    [http.client.IncompleteRead(b"partial"), http.client.BadStatusLine("junk")],
)
def test_a_broken_answer_ends_as_one_line_without_its_content(answer):
    def broken(_request, timeout):
        raise answer

    clock = FakeClock()

    with pytest.raises(device_sign_in.SignInFailed) as stopped:
        device_sign_in.access_token({}, "the-secret", broken, clock)

    assert str(stopped.value) == "the token endpoint gave no answer to read"
    assert stopped.value.__cause__ is None


def test_a_token_answer_without_an_access_token_is_refused():
    keycloak = FakeKeycloak({"other": 1})

    clock = FakeClock()

    with pytest.raises(device_sign_in.SignInFailed, match="no access token"):
        device_sign_in.access_token({}, "the-secret", keycloak, clock)
