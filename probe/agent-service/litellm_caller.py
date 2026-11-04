"""The throwaway caller's programs of the LiteLLM probes (probe/agent-service/litellm.py): one
request through the front or straight at LiteLLM, run as `python -I -` in a throwaway container.

Each program's standard input starts with `BEARER = ...` (a key, or None), `BODY = ...` (the
request's JSON, or None), `HIDDEN = [...]` (the keys its output shows as `<key>`) and
`HEADERS = {...}` (more request headers), so no key and no header reaches argv or the output. argv:
host, port, method, path. Both send one HTTP/1.0 request, so no answer is chunked.
"""

from __future__ import annotations

import json

# Prints {"status", "retry_after", "seconds", "document"}, the answer's JSON or None.
CALL_PROGRAM = """\
import json, socket, sys, time
host, port, method, path = sys.argv[1:5]
payload = b"" if BODY is None else BODY.encode()
head = f"{method} {path} HTTP/1.0\\r\\nHost: {host}:{port}\\r\\n"
if BEARER:
    head += f"Authorization: Bearer {BEARER}\\r\\n"
for name, value in HEADERS.items():
    head += f"{name}: {value}\\r\\n"
head += f"Content-Type: application/json\\r\\nContent-Length: {len(payload)}\\r\\n\\r\\n"
started = time.monotonic()
with socket.create_connection((host, int(port)), timeout=150) as raw:
    raw.sendall(head.encode() + payload)
    reply = b""
    while chunk := raw.recv(65536):
        reply += chunk
top, _, content = reply.partition(b"\\r\\n\\r\\n")
lines = top.decode().splitlines()
headers = {k.lower(): v for k, _, v in (line.partition(": ") for line in lines[1:])}
try:
    document = json.loads(content)
except ValueError:
    document = None
shown = json.dumps({
    "status": int(lines[0].split(" ", 2)[1]), "retry_after": headers.get("retry-after"),
    "seconds": time.monotonic() - started, "document": document,
})
for key in HIDDEN:
    shown = shown.replace(key, "<key>")
print(shown, flush=True)
"""
# Sends the body with `"stream": true`; prints {"status", "seconds"}, then per server-sent `data:`
# event, as it arrives, {"seconds", "text"}: the first choice's delta text, or None.
STREAM_PROGRAM = """\
import json, socket, sys, time
host, port, method, path = sys.argv[1:5]
payload = json.dumps({**json.loads(BODY), "stream": True}).encode()
head = f"{method} {path} HTTP/1.0\\r\\nHost: {host}:{port}\\r\\n"
if BEARER:
    head += f"Authorization: Bearer {BEARER}\\r\\n"
for name, value in HEADERS.items():
    head += f"{name}: {value}\\r\\n"
head += f"Content-Type: application/json\\r\\nContent-Length: {len(payload)}\\r\\n\\r\\n"
started = time.monotonic()
def show(record):
    shown = json.dumps({**record, "seconds": time.monotonic() - started})
    for key in HIDDEN:
        shown = shown.replace(key, "<key>")
    print(shown, flush=True)
def delta_text(data):
    try:
        return json.loads(data)["choices"][0]["delta"].get("content")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        return None
with socket.create_connection((host, int(port)), timeout=150) as raw:
    raw.sendall(head.encode() + payload)
    reply = raw.makefile("rb")
    show({"status": int(reply.readline().split(b" ", 2)[1])})
    while reply.readline().strip():
        pass
    for line in reply:
        if line.startswith(b"data:"):
            show({"text": delta_text(line[5:].strip())})
"""


def caller_input(
    program: str,
    bearer: str | None,
    body: dict | None,
    hidden: list[str],
    headers: dict[str, str] | None = None,
) -> str:
    """The standard input of a throwaway caller: the program behind its preamble."""
    payload = None if body is None else json.dumps(body)
    preamble = f"BEARER = {bearer!r}\nBODY = {payload!r}\nHIDDEN = {hidden!r}\n"
    return f"{preamble}HEADERS = {headers or {}!r}\n{program}"
