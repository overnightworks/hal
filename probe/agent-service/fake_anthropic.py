"""The fake providers of the LiteLLM probe (probe/agent-service/litellm.py): a TLS server that
stands in for api.anthropic.com or api.openai.com behind the gateway, inside the probe's internal
`internet` network. Standard library only; it runs in the key step's plain Python image.

    python -I -B fake_anthropic.py {provider|pictures}

It reads `/fake/cert.pem`, `/fake/key.pem` and `/fake/expect.json` (the scratch provider key, the
scratch identity strings and the answer marker; all of them
throwaway values). The `provider` role answers an
Anthropic message with the marker and prints one JSON line per request on standard output: the
model, `max_tokens`, `metadata.user_id` (the fingerprint, which must arrive), whether the key
matched, and counts of what must not arrive here. It prints a verdict and no other value of the
request, and its answer holds only values it builds itself. The `pictures` role answers OpenAI's
picture call (https://platform.openai.com/docs/api-reference/images/create) with the marker as
`b64_json` and the `usage` the control file steers (mode `hold` holds it as above, mode
`moderation` refuses it as OpenAI's safety system does, mode `status` with `status` 401 refuses
the key as OpenAI does, naming it masked to its first 3 and last 4 characters), and prints one
JSON line per request: the path, the model, the `user` that arrived (None when none did), whether
`Authorization` carried the key, and the same counts.

The `provider` role re-reads `/fake/control.json` on every request, so one container serves every
cell of the failure probe (probe/agent-service/litellm_failures.py). The file holds `mode`:
`answer` (the default), `status` (with `status`: 500 or 529), `billing`, `low_credit`, `broken` (a
200 whose body is no JSON), `reset` (the connection is reset), `hold` (the request is held until
the client disconnects, the control file no longer says `hold`, or `hold_seconds` (at most 120, the
default) have passed, and the log gets `held disconnected`, `held released` or `held timed out`
afterwards; the held request is then answered) or `echo`
(an error of `status` whose message is `request_canary` when the request holds it, as an upstream
that quotes its input); and optionally `tool_use` (`name` and `input`: the answer then also holds a
tool call of that name, as a model that calls a tool absent from the request's `tools`;
with `tool_use_once` only while no message of the request holds a `tool_result` block, so a
client that runs the tool and sends its result gets the closing answer, and the log line says
whether a `tool_result` arrived),
`usage` (the answer's `input_tokens` and `output_tokens`, which LiteLLM prices), `provider_key`
and `marker`, which stand in for the values of `expect.json`, `secrets` (keys that
must not arrive, counted as `secret_hits`) and `request_canary`, whose occurrences in a request the
log line counts. `declares` (a tool name) and `arrivals` (labels with values) make the log line
say whether `tools` declares that tool and how often each value occurs in the request body.
A request with `"stream": true` in mode `answer`, `stream_hold`, `stream_cut` or
`stream_cut_chunked` gets Anthropic's event stream as server-sent events, ended by closing the
connection: `message_start`, `content_block_start`, one `text_delta` `content_block_delta` per
text of `texts` (a single text, or the marker, goes out in two pieces), `content_block_stop`,
then, when the steered answer holds a tool call as the non-streamed answer does, a `tool_use`
`content_block_start` (empty `input`), its arguments' JSON in two `input_json_delta` pieces and
`content_block_stop`, then `message_delta` with the usage (`stop_reason` `tool_use` after a tool
call) and `message_stop`.
`stream_hold` writes up to the first delta, then holds as `hold` does while the control file says
`stream_hold`, logs the same `held` line, and writes the rest. `stream_cut` closes the connection
after the last `content_block_stop`, before `message_delta`, in the unframed HTTP/1.0 body of the
other modes; `stream_cut_chunked` does the same in a chunked HTTP/1.1 body (one chunk per event)
and sends no terminating zero-length chunk.
The error bodies are Anthropic's own shapes, https://docs.anthropic.com/en/api/errors: 401
`authentication_error`, 500 `api_error`, 529 `overloaded_error`, 402 `billing_error`;
`low_credit` is the other answer a used-up balance gets, as clients report it: 400
`invalid_request_error` saying the credit balance is too low.
"""

import contextlib
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
STREAM_HOLD = "stream_hold"
STREAM_CUT = "stream_cut"
STREAM_CUT_CHUNKED = "stream_cut_chunked"
STREAM_CUTS = frozenset({STREAM_CUT, STREAM_CUT_CHUNKED})
STREAM_MODES = frozenset({"answer", STREAM_HOLD, *STREAM_CUTS})
FIRST_DELTA = 3  # message_start, content_block_start and the first delta
TEXT_BLOCK = {"type": "text", "text": ""}
ERRORS = {
    400: "invalid_request_error", 401: "authentication_error", 402: "billing_error",
    500: "api_error", 529: "overloaded_error",
}  # fmt: skip
# OpenAI's refusal of a key it does not know: https://platform.openai.com/docs/guides/error-codes
OPENAI_ERRORS = {401: ("invalid_request_error", "invalid_api_key")}
# OpenAI's refusal of a picture prompt by its safety system, as clients report it: a 400 whose
# error code is `moderation_blocked`.
MODERATION = json.dumps({"error": {
    "message": "Your request was rejected as a result of our safety system.",
    "type": "image_generation_user_error", "param": None, "code": "moderation_blocked",
}}).encode()  # fmt: skip
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


def wait_for_disconnect(connection: socket.socket, seconds: float, mode: str = "hold") -> str:
    """Holds until the client closes its side or the control file stops saying `mode`, and says
    so; gives up after `seconds`."""
    deadline = time.monotonic() + min(seconds, HOLD_SECONDS)
    while time.monotonic() < deadline:
        if control().get("mode") != mode:
            return "released"
        readable, _, _ = select.select([connection], [], [], HOLD_POLL_SECONDS)
        if readable:
            try:
                if connection.recv(1) == b"":
                    return "disconnected"
            except OSError:
                return "disconnected"
    return "timed out"


def document_of(body: bytes) -> dict:
    try:
        document = json.loads(body)
    except ValueError:
        return {}
    return document if isinstance(document, dict) else {}


def counts(expect: dict, raw: bytes) -> dict:
    """What must not arrive at a provider, and the canary that must."""
    return {
        "secret_hits": sum(raw.count(value.encode()) for value in expect.get("secrets", [])),
        "identity_hits": sum(raw.count(value.encode()) for value in expect["identity"]),
        "jwt_hits": len(JWT.findall(raw)),
        "uuid_hits": len(UUID.findall(raw)),
        "request_canary_hits": raw.count(expect.get("request_canary", "").encode() or b"\0"),
    }


def holds_tool_result(document: dict) -> bool:
    """Whether a message of an Anthropic request holds a `tool_result` block."""
    messages = document.get("messages")
    return isinstance(messages, list) and any(
        isinstance(block, dict) and block.get("type") == "tool_result"
        for item in messages if isinstance(item, dict) and isinstance(item.get("content"), list)
        for block in item["content"]
    )  # fmt: skip


def arrivals(expect: dict, document: dict, body: bytes) -> dict:
    """What the request body shows of the client's turn: whether `tools` declares the tool named
    by `declares`, and how often each value of `arrivals` occurs in the body; counts and
    booleans, never the bytes."""
    tools = document.get("tools")
    return {
        "declared_tool": isinstance(tools, list) and any(
            isinstance(tool, dict) and tool.get("name") == expect["declares"] for tool in tools
        ) if "declares" in expect else False,
        "arrivals": {
            label: body.count(value.encode()) for label, value in expect.get("arrivals", {}).items()
        },
    }  # fmt: skip


def provider_record(expect: dict, request: http.server.BaseHTTPRequestHandler, body: bytes) -> dict:
    document = document_of(body)
    metadata = document.get("metadata")
    return {
        "path": request.path,
        "model": document.get("model"),
        "max_tokens": document.get("max_tokens"),
        "user_id": metadata.get("user_id") if isinstance(metadata, dict) else None,
        "key_ok": request.headers.get("x-api-key") == expect["provider_key"],
        "authorization": "authorization" in request.headers,
        "tool_result": holds_tool_result(document),
        **arrivals(expect, document, body),
        **counts(expect, str(request.headers).encode() + body),
    }


def picture_record(expect: dict, request: http.server.BaseHTTPRequestHandler, body: bytes) -> dict:
    document = document_of(body)
    return {
        "path": request.path,
        "model": document.get("model"),
        "user": document.get("user"),
        "key_ok": request.headers.get("authorization") == f"Bearer {expect['provider_key']}",
        **counts(expect, str(request.headers).encode() + body),
    }


def picture(expect: dict) -> bytes:
    """OpenAI's answer of a gpt-image model: the picture's bytes in base64 and the token usage."""
    usage = expect.get("usage", {"input_tokens": 1, "output_tokens": 1})
    return json.dumps({
        "created": int(time.time()), "data": [{"b64_json": expect["marker"]}],
        "usage": {
            **usage, "total_tokens": usage["input_tokens"] + usage["output_tokens"],
            "input_tokens_details": {"text_tokens": usage["input_tokens"], "image_tokens": 0},
        },
    }).encode()  # fmt: skip


def steered_call(expect: dict, body: bytes) -> dict | None:
    """The tool call the answer holds: steered by `tool_use`, and with `tool_use_once` only while
    the request holds no `tool_result` block."""
    if expect.get("tool_use_once") and holds_tool_result(document_of(body)):
        return None
    return expect.get("tool_use")


def message(expect: dict, body: bytes) -> bytes:
    call = steered_call(expect, body)
    content = [{"type": "text", "text": expect["marker"]}]
    if call:
        content.append({"type": "tool_use", "id": "toolu_probe", **call})
    return json.dumps({
        "id": "msg_probe", "type": "message", "role": "assistant", "model": ANSWER_MODEL,
        "content": content,
        "stop_reason": "tool_use" if call else "end_turn", "stop_sequence": None,
        "usage": expect.get("usage", {"input_tokens": 1, "output_tokens": 1}),
    }).encode()  # fmt: skip


def openai_error(status: int, key: str) -> bytes:
    """OpenAI's error body of `status`, which names the key as OpenAI masks it."""
    kind, code = OPENAI_ERRORS[status]
    masked = f"{key[:3]}{'*' * max(len(key) - 7, 0)}{key[-4:]}"
    return json.dumps({"error": {
        "message": f"Incorrect API key provided: {masked}. You can find your API key at "
                   "https://platform.openai.com/account/api-keys.",
        "type": kind, "param": None, "code": code,
    }}).encode()  # fmt: skip


def picture_answer(connection: socket.socket, steering: dict) -> tuple[int, bytes]:
    """`moderation` refuses as OpenAI's safety system does, `status` as OpenAI refuses a key;
    `hold` holds as the provider's does, then answers the picture."""
    mode = steering.get("mode", "answer")
    if mode == "moderation":
        return 400, MODERATION
    if mode == "status":
        return steering["status"], openai_error(steering["status"], steering["provider_key"])
    if mode == "hold":
        seconds = steering.get("hold_seconds", HOLD_SECONDS)
        print(f"held {wait_for_disconnect(connection, seconds)}", flush=True)  # noqa: T201 - this in-container program prints its own request log
    return 200, picture(steering)


def server_sent(kind: str, data: dict) -> bytes:
    return f"event: {kind}\ndata: {json.dumps({'type': kind, **data})}\n\n".encode()


def in_two(text: str) -> list[str]:
    middle = len(text) // 2
    return [text[:middle], text[middle:]]


def text_pieces(expect: dict) -> list[str]:
    """One piece per steered text; a single text (or the marker) goes out in two pieces."""
    texts = expect.get("texts") or [expect["marker"]]
    return in_two(texts[0]) if len(texts) == 1 else texts


def tool_use_events(call: dict) -> list[bytes]:
    """The content block of a tool call: its arguments' JSON arrives in two pieces."""
    block = {"type": "tool_use", "id": "toolu_probe", "name": call["name"], "input": {}}
    pieces = in_two(json.dumps(call.get("input", {})))
    return [
        server_sent("content_block_start", {"index": 1, "content_block": block}),
        *(
            server_sent("content_block_delta", {
                "index": 1, "delta": {"type": "input_json_delta", "partial_json": piece},
            })
            for piece in pieces
        ),
        server_sent("content_block_stop", {"index": 1}),
    ]  # fmt: skip


def stream_events(expect: dict, call: dict | None = None) -> list[bytes]:
    """Anthropic's event stream of an answer: text pieces, then the tool call's block when `call`
    is given; the cut modes end it before `message_delta`."""
    usage = expect.get("usage", {"input_tokens": 1, "output_tokens": 1})
    started = {
        "id": "msg_probe", "type": "message", "role": "assistant", "model": ANSWER_MODEL,
        "content": [], "stop_reason": None, "stop_sequence": None,
        "usage": {"input_tokens": usage["input_tokens"], "output_tokens": 0},
    }  # fmt: skip
    deltas = [
        server_sent("content_block_delta", {"index": 0, "delta": {"type": "text_delta", "text": t}})
        for t in text_pieces(expect)
    ]  # fmt: skip
    opening = [
        server_sent("message_start", {"message": started}),
        server_sent("content_block_start", {"index": 0, "content_block": TEXT_BLOCK}),
        *deltas,
        server_sent("content_block_stop", {"index": 0}),
        *(tool_use_events(call) if call else []),
    ]  # fmt: skip
    if expect.get("mode") in STREAM_CUTS:
        return opening
    return [
        *opening,
        server_sent("message_delta", {
            "delta": {"stop_reason": "tool_use" if call else "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": usage["output_tokens"]},
        }),
        server_sent("message_stop", {}),
    ]  # fmt: skip


def asks_for_stream(body: bytes) -> bool:
    try:
        document = json.loads(body)
    except ValueError:
        return False
    return isinstance(document, dict) and document.get("stream") is True


def framed(data: bytes, chunked: bool) -> bytes:
    """`data` as one HTTP/1.1 chunk when `chunked`, else unchanged."""
    return f"{len(data):x}\r\n".encode() + data + b"\r\n" if chunked else data


def stream(request: http.server.BaseHTTPRequestHandler, answer: dict, call: dict | None) -> None:
    """The event stream; the first delta goes out before a `stream_hold` holds the rest."""
    chunked = answer.get("mode") == STREAM_CUT_CHUNKED
    if chunked:
        request.protocol_version = "HTTP/1.1"
    request.send_response(200)
    request.send_header("Content-Type", "text/event-stream")
    if chunked:
        request.send_header("Transfer-Encoding", "chunked")
        request.send_header("Connection", "close")  # the cut ends the connection, not a chunk
    request.end_headers()
    events = [framed(event, chunked) for event in stream_events(answer, call)]
    request.wfile.write(b"".join(events[:FIRST_DELTA]))
    if answer.get("mode") == STREAM_HOLD:
        seconds = answer.get("hold_seconds", HOLD_SECONDS)
        held = wait_for_disconnect(request.connection, seconds, STREAM_HOLD)
        print(f"held {held}", flush=True)  # noqa: T201 - this in-container program prints its own request log
    with contextlib.suppress(OSError):  # a client that left gets no rest
        request.wfile.write(b"".join(events[FIRST_DELTA:]))


def handler(role: str, expect: dict) -> type[http.server.BaseHTTPRequestHandler]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            status, reply = 200, b"{}"
            if role == "pictures":
                steering = {**expect, **control()}
                print(json.dumps(picture_record(steering, self, body)), flush=True)  # noqa: T201 - this in-container program prints its own request log
                status, reply = picture_answer(self.connection, steering)
            if role == "provider":
                steering = control()
                record = provider_record({**expect, **steering}, self, body)
                print(json.dumps(record), flush=True)  # noqa: T201 - this in-container program prints its own request log
                if asks_for_stream(body) and steering.get("mode", "answer") in STREAM_MODES:
                    stream(self, {**expect, **steering}, steered_call({**expect, **steering}, body))
                    return
                status, reply = self.provider_answer(steering, body)
            if status:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(reply)))
                self.end_headers()
                # A reply holds only the probe's own values: its control file in JSON for LiteLLM,
                # which HTML escaping would only corrupt.
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
            return 200, message({**expect, **steering}, body)

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
