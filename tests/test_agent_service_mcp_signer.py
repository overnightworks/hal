"""The capture verifier (`agent-service/mcp_signer.py`): its own decisions on a request,
with the verifier injected. The cryptography is agent-runtime's, driven in the service image."""

import base64
import http.client
import io
import json
import threading
from dataclasses import dataclass

import mcp_signer
import pytest
from mcp_signer import CaptureServer, Expectation

TOOL = "capability_check"
KEY_ID = "trusted-key-id"
ORIGIN_HOST = "songmaker.mcp.internal"
SIGNATURE = "SignatureSegment0123456789"


@dataclass(frozen=True)
class Claims:
    tools: tuple[str, ...]


def segment(document: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(document).encode()).rstrip(b"=").decode()


def capability(key_id: str = KEY_ID) -> str:
    header = {"alg": "RS256", "kid": key_id, "typ": "agent-run-capability"}
    return f"{segment(header)}.{segment({'sub': 'run'})}.{SIGNATURE}"


def accepting(tools: tuple[str, ...] = (TOOL,)):
    return lambda token: Claims(tools)


def refusing(reason: str):
    return lambda token: reason


@dataclass
class Standin:
    server: CaptureServer
    thread: threading.Thread
    out: io.StringIO

    def request(self, method="POST", path="/mcp", headers=None, host=ORIGIN_HOST) -> int:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        try:
            connection.putrequest(method, path, skip_host=True)
            connection.putheader("Host", host)
            for name, value in (headers or {}).items():
                connection.putheader(name, value)
            connection.putheader("Content-Length", "0")
            connection.endheaders()
            response = connection.getresponse()
            assert response.read() == b""
            return response.status
        finally:
            connection.close()

    def verdicts(self) -> list[str]:
        self.thread.join(timeout=5)
        return self.out.getvalue().splitlines()


@pytest.fixture
def standin():
    started: list[Standin] = []

    def start(verify=None) -> Standin:
        expected = Expectation(verify or accepting(), KEY_ID, ORIGIN_HOST, TOOL)
        server = CaptureServer(("127.0.0.1", 0), expected)
        out = io.StringIO()
        thread = threading.Thread(target=mcp_signer.serve, args=(server, out), daemon=True)
        thread.start()
        started.append(Standin(server, thread, out))
        return started[-1]

    yield start
    for each in started:
        each.server.server_close()


def bearer(token: str | None = None) -> dict[str, str]:
    return {"Authorization": f"Bearer {token or capability()}"}


def test_p37a_a_sound_capability_is_verified_with_an_empty_401_and_the_server_ends(standin):
    running = standin()

    assert running.request(headers=bearer()) == 401
    assert running.verdicts() == ["verified"]
    assert not running.thread.is_alive()


def test_p37b_a_capability_the_verifier_refuses_is_refused_with_its_reason(standin):
    running = standin(refusing("wrong_audience"))

    assert running.request(headers=bearer()) == 401
    assert running.verdicts() == ["refused: wrong_audience"]


def test_p37c_a_header_kid_other_than_the_trusted_key_id_is_refused(standin):
    running = standin()

    assert running.request(headers=bearer(capability("another-key"))) == 401
    assert running.verdicts() == ["refused: kid"]


@pytest.mark.parametrize("tools", [(), ("other_tool",), (TOOL, "other_tool")])
def test_p37d_tools_other_than_exactly_the_named_one_are_refused(standin, tools):
    running = standin(accepting(tools))

    assert running.request(headers=bearer()) == 401
    assert running.verdicts() == ["refused: tools"]


@pytest.mark.parametrize("host", ["other.mcp.internal", f"{ORIGIN_HOST}:443", ORIGIN_HOST.upper()])
def test_p37e_a_host_other_than_the_origins_host_byte_for_byte_is_refused(standin, host):
    running = standin()

    assert running.request(headers=bearer(), host=host) == 401
    assert running.verdicts() == ["refused: host"]


@pytest.mark.parametrize(
    "headers", [{}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"}]
)
def test_p37f_a_post_without_a_bearer_is_refused_with_no_bearer(standin, headers):
    running = standin()

    assert running.request(headers=headers) == 401
    assert running.verdicts() == ["refused: no bearer"]


@pytest.mark.parametrize(
    ("method", "path"),
    [("GET", "/mcp"), ("POST", "/other"), ("PUT", "/mcp"), ("TRACE", "/mcp"), ("CONNECT", "/mcp")],
)
def test_p37f_any_other_request_gets_404_and_is_not_judged_and_the_server_goes_on(
    standin, method, path
):
    running = standin()

    assert running.request(method=method, path=path, headers=bearer()) == 404
    assert running.thread.is_alive()
    assert running.out.getvalue() == ""

    assert running.request(headers=bearer()) == 401
    assert running.verdicts() == ["verified"]


@pytest.mark.parametrize(
    "case", ["verified", "refused", "kid", "tools", "host", "no bearer", "other path"]
)
def test_p37g_no_byte_of_the_signature_reaches_stdout_or_stderr(standin, capsys, case):
    running = standin(
        accepting((TOOL, "x") if case == "tools" else (TOOL,))
        if case != "refused"
        else refusing("invalid_signature")
    )
    token = capability("another-key" if case == "kid" else KEY_ID)

    running.request(
        path="/other" if case == "other path" else "/mcp",
        headers={} if case == "no bearer" else bearer(token),
        host="elsewhere" if case == "host" else ORIGIN_HOST,
    )
    if case == "other path":
        running.request(headers=bearer(token))
    shown = running.verdicts()

    captured = capsys.readouterr()
    assert SIGNATURE not in "".join([*shown, captured.out, captured.err])
