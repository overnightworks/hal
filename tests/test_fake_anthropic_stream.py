"""The fake Anthropic's streamed answers: text pieces, tool-call blocks and the two ways a stream is
cut, and the plain answer that holds the same tool call."""

import http.server
import json
import socket
import threading

import pytest


def sent(fake_provider, steering: dict, call: dict | None = None) -> list[dict]:
    """The data of each server-sent event of the fake's stream, named as its `type`."""
    frames = b"".join(fake_provider.stream_events(steering, call)).decode()
    lines = [block.splitlines() for block in frames.split("\n\n") if block]
    events = [json.loads(data.removeprefix("data: ")) for _, data in lines]
    assert [name for name, _ in lines] == [f"event: {e['type']}" for e in events]
    assert steering.get("request_canary", "\0") not in frames
    return events


def joined(events: list[dict], kind: str, field: str) -> str:
    deltas = [e["delta"] for e in events if e["type"] == "content_block_delta"]
    return "".join(d[field] for d in deltas if d["type"] == kind)


STOP = ["message_delta", "message_stop"]
RESULT_SENT = {"messages": [{"role": "user", "content": [{"type": "tool_result"}]}]}


@pytest.mark.parametrize(
    ("steering", "pieces", "ending"),
    [
        pytest.param({"marker": "answer-3e5a"}, 2, STOP, id="the marker"),
        pytest.param({"texts": ["one-8d2c"], "marker": "m"}, 2, STOP, id="a single text"),
        pytest.param({"texts": ["a-7c1d", "b-2b9e", "c-4f60"]}, 3, STOP, id="one per text"),
        pytest.param({"texts": ["a-7c1d", "b-2b9e"], "mode": "stream_cut"}, 2, [], id="cut"),
    ],
)  # fmt: skip
def test_the_fakes_stream_cuts_text_into_pieces_that_join_to_the_steered_text(
    fake_provider, steering, pieces, ending
):
    events = sent(fake_provider, {"request_canary": "request-5a0f", **steering})

    assert [e["type"] for e in events] == [
        "message_start", "content_block_start", *["content_block_delta"] * pieces,
        "content_block_stop", *ending,
    ]  # fmt: skip
    assert joined(events, "text_delta", "text") == "".join(
        steering.get("texts") or [steering["marker"]]
    )


@pytest.mark.parametrize("mode", ["answer", "stream_cut"])
def test_the_fakes_stream_of_a_tool_call_holds_a_tool_use_block_with_the_arguments_in_pieces(
    fake_provider, mode
):
    call = {"name": "lookup", "input": {"q": "needle-61b7"}}

    events = sent(fake_provider, {"marker": "answer-3e5a", "mode": mode}, call)

    kinds = [e["type"] for e in events]
    block = events[kinds.index("content_block_start", 2)]["content_block"]
    assert block == {"type": "tool_use", "id": "toolu_probe", "name": "lookup", "input": {}}
    assert kinds.count("content_block_delta") >= 4  # two text pieces, two argument pieces
    assert json.loads(joined(events, "input_json_delta", "partial_json")) == call["input"]
    stops = [e["delta"]["stop_reason"] for e in events if e["type"] == "message_delta"]
    assert (kinds[-1], stops) == (
        ("message_stop", ["tool_use"]) if mode == "answer" else ("content_block_stop", [])
    )


@pytest.mark.parametrize(
    ("steering", "body", "called"),
    [
        ({"tool_use": {"name": "lookup"}}, {}, True),
        ({}, {}, False),
        ({"tool_use": {"name": "lookup"}, "tool_use_once": True}, {}, True),
        ({"tool_use": {"name": "lookup"}, "tool_use_once": True}, RESULT_SENT, False),
    ],
)
def test_the_plain_answer_holds_the_tool_call_the_stream_would_hold(
    fake_provider, steering, body, called
):
    raw = json.dumps(body).encode()

    plain = json.loads(fake_provider.message({"marker": "m", **steering}, raw))

    assert [b["type"] for b in plain["content"]] == ["text", *["tool_use"] * called]
    assert (fake_provider.steered_call(steering, raw) is not None) == called
    assert plain["stop_reason"] == ("tool_use" if called else "end_turn")


def wire_of_a_cut_stream(fake_provider, tmp_path, monkeypatch, mode: str) -> bytes:
    """Every byte the fake sends a streaming request in `mode` before it closes the connection."""
    control = tmp_path / "control.json"
    control.write_text(json.dumps({"mode": mode}))
    monkeypatch.setattr(fake_provider, "CONTROL", str(control))
    expect = {"marker": "answer-3e5a", "identity": [], "provider_key": "k"}
    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), fake_provider.handler("provider", expect)
    )
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with socket.create_connection(server.server_address, timeout=10) as client:
            client.sendall(b'POST / HTTP/1.1\r\nContent-Length: 16\r\n\r\n{"stream": true}')
            return b"".join(iter(lambda: client.recv(4096), b""))
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    ("mode", "status_line", "framing"),
    [("stream_cut", b"HTTP/1.0 200", False), ("stream_cut_chunked", b"HTTP/1.1 200", True)],
)
def test_the_fakes_cut_streams_close_before_message_delta_unframed_or_inside_a_chunked_body(
    fake_provider, tmp_path, monkeypatch, mode, status_line, framing
):
    wire = wire_of_a_cut_stream(fake_provider, tmp_path, monkeypatch, mode)

    head, body = wire.split(b"\r\n\r\n", 1)
    chunked = b"transfer-encoding: chunked" in head.lower()
    chunks = []
    while chunked and body:
        size, body = body.split(b"\r\n", 1)
        chunks.append(body[: int(size, 16)])
        assert body[int(size, 16) :].startswith(b"\r\n")
        body = body[int(size, 16) + 2 :]
    events = b"".join(chunks) if chunked else body
    assert (head.startswith(status_line), chunked) == (True, framing)
    assert all(chunks)  # a zero-length chunk would end the body; none is sent
    assert [event.split(b"\n")[0] for event in events.split(b"\n\n") if event][-1:] == [
        b"event: content_block_stop"
    ]
    assert b"message_delta" not in events
