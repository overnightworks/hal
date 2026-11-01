"""The fake provider of the LiteLLM probe (probe/agent-service/litellm.py): a TLS server that
stands in for api.anthropic.com or auth.hallucinai.de behind the gateway, inside the probe's
internal `internet` network. Standard library only; it runs in the service image.

    python -I -B fake_anthropic.py {provider|issuer}

It reads `/fake/cert.pem`, `/fake/key.pem` and `/fake/expect.json` (the scratch provider key, the
scratch service credential, the scratch identity strings and the answer marker; all of them
throwaway values). The `issuer` role answers `{}` to anything. The `provider` role answers an
Anthropic message with the marker and prints one JSON line per request on standard output: the
model, whether the key matched, and counts of what must not arrive here. It prints a verdict and
never a value of the request, and its answer holds only values it builds itself.

The `provider` role re-reads `/fake/control.json` on every request, so one container serves every
cell of the failure probe (probe/agent-service/litellm_failures.py). The file holds `mode`:
`answer` (the default), `status` (with `status`: 500 or 529), `billing`, `low_credit`, `broken` (a
200 whose body is no JSON), `reset` (the connection is reset), `hold` (the request is held until
the client disconnects or `hold_seconds` (at most 120, the default) have passed, and the log gets
`held disconnected` or `held timed out` afterwards; the held request is then answered) or `echo`
(an error of `status` whose message is `request_canary` when the request holds it, as an upstream
that quotes its input); and optionally `provider_key`, `credential` and `marker`, which stand in
for the values of `expect.json`, and `request_canary`, whose occurrences in a request the log line
counts.
The error bodies are Anthropic's own shapes, https://docs.anthropic.com/en/api/errors: 500
`api_error`, 529 `overloaded_error`, 402 `billing_error`; `low_credit` is the other answer a
used-up balance gets, as clients report it: 400 `invalid_request_error` saying the credit balance
is too low.
"""

import http.server
import json
import re
import select
import socket
import ssl
import struct
import sys
import time

PORT = 443
JWT = re.compile(rb"eyJ[\w-]+\.[\w-]+\.[\w-]+")
UUID = re.compile(rb"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
ANSWER_MODEL = "claude-probe"
CONTROL = "/fake/control.json"
HOLD_SECONDS = 120
HOLD_POLL_SECONDS = 0.2
ERRORS = {
    400: "invalid_request_error", 402: "billing_error", 500: "api_error", 529: "overloaded_error",
}  # fmt: skip
LOW_CREDIT = (
    "Your credit balance is too low to access the Anthropic API. "
    "Please go to Plans & Billing to upgrade or purchase credits."
)


def control() -> dict:
    try:
        with open(CONTROL, encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def error_body(status: int, text: str = "probe") -> bytes:
    return json.dumps({
        "type": "error", "error": {"type": ERRORS[status], "message": text},
    }).encode()  # fmt: skip


def quoted(steering: dict, body: bytes) -> str:
    """The canary the request holds, taken from the control file: the bytes of a request never
    go back out."""
    canary = steering["request_canary"]
    return canary if canary.encode() in body else "probe"


def wait_for_disconnect(connection: socket.socket, seconds: float) -> str:
    """Holds until the client closes its side, and says so; gives up after `seconds`."""
    deadline = time.monotonic() + min(seconds, HOLD_SECONDS)
    while time.monotonic() < deadline:
        readable, _, _ = select.select([connection], [], [], HOLD_POLL_SECONDS)
        if readable:
            try:
                if connection.recv(1) == b"":
                    return "disconnected"
            except OSError:
                return "disconnected"
    return "timed out"


def provider_record(expect: dict, request: http.server.BaseHTTPRequestHandler, body: bytes) -> dict:
    raw = str(request.headers).encode() + body
    try:
        model = json.loads(body)["model"]
    except (ValueError, KeyError, TypeError):
        model = None
    return {
        "path": request.path,
        "model": model,
        "key_ok": request.headers.get("x-api-key") == expect["provider_key"],
        "authorization": "authorization" in request.headers,
        "credential_bytes": expect["credential"].encode() in raw,
        "identity_hits": sum(raw.count(value.encode()) for value in expect["identity"]),
        "jwt_hits": len(JWT.findall(raw)),
        "uuid_hits": len(UUID.findall(raw)),
        "request_canary_hits": raw.count(expect.get("request_canary", "").encode() or b"\0"),
    }


def message(expect: dict) -> bytes:
    return json.dumps({
        "id": "msg_probe", "type": "message", "role": "assistant", "model": ANSWER_MODEL,
        "content": [{"type": "text", "text": expect["marker"]}],
        "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }).encode()  # fmt: skip


def handler(role: str, expect: dict) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            status, reply = 200, b"{}"
            if role == "provider":
                steering = control()
                record = provider_record({**expect, **steering}, self, body)
                print(json.dumps(record), flush=True)  # noqa: T201 - this in-container program prints its own request log
                status, reply = self.provider_answer(steering, body)
            if status:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                # The request's bytes no longer come back; what remains is the probe's own control
                # file in JSON for LiteLLM, which HTML escaping would only corrupt.
                self.wfile.write(reply)  # NOSONAR(S5131) JSON from the probe's control file

        def provider_answer(self, steering: dict, body: bytes) -> tuple[int, bytes]:
            """The status and body of the mode; status 0 means the connection was reset instead."""
            mode = steering.get("mode", "answer")
            if mode == "status":
                return steering["status"], error_body(steering["status"])
            if mode == "echo":
                return steering["status"], error_body(steering["status"], quoted(steering, body))
            if mode == "billing":
                return 402, error_body(402)
            if mode == "low_credit":
                return 400, error_body(400, LOW_CREDIT)
            if mode == "broken":
                return 200, b"{not json"
            if mode == "reset":
                self.connection.setsockopt(
                    socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                )
                self.connection.close()
                return 0, b""
            if mode == "hold":
                seconds = steering.get("hold_seconds", HOLD_SECONDS)
                print(f"held {wait_for_disconnect(self.connection, seconds)}", flush=True)  # noqa: T201 - this in-container program prints its own request log
            return 200, message({**expect, **steering})

        do_GET = do_POST

        def log_message(self, *_: object) -> None:
            return

    return Handler


def main(role: str) -> None:
    with open("/fake/expect.json", encoding="utf-8") as file:
        expect = json.load(file)
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), handler(role, expect))  # noqa: S104 - a container-internal listener on an internal network
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain("/fake/cert.pem", "/fake/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()  # NOSONAR(S5332) TLS: the context above wraps the socket


if __name__ == "__main__":
    main(sys.argv[1])
