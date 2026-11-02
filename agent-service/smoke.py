"""The operator's smoke of the agent service: one run, its event types and its text on stdout.

    docker compose run --rm -T agent-smoke [--cancel] [--tool NAME:EFFECT ...]

Stdin holds exactly two lines, the person's token and then the workload's, and nothing else
supplies one: there is no option, no environment variable and no file for a token. Both tokens
are removed from everything the smoke prints, errors included. Without options it starts one
run and prints each event's type and the text of the answer; exit 0 when the run succeeded.
`--cancel` starts a long answer, holds the stream open a few seconds after `run_started` so
the CLI run behind it can be seen, then closes it before any answer, to see that the service
ends that run; it fails when the run succeeded (docs/agent-service.md, "Proofs"). Each `--tool`
lists a tool of the app in the request, with the effect the service judges (the probes' option).
After `event: run_started` it prints which model and route the service named, as one line that
starts with `SERVED_BY`.
`live_smoke.py` runs it with the sign-in.

Only the standard library of the service image is used.
"""

from __future__ import annotations

import argparse
import http.client
import json
import re
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import IO, NamedTuple, NoReturn

PROTOCOL_VERSION = 4
AGENT = "chat"
EVENT_PREFIX = "event: "
SERVED_BY = "served by"
SERVED_AFTER_RUN_STARTED = re.compile(
    rf"^{EVENT_PREFIX}run_started\n{SERVED_BY} (?P<model>\S+) on route (?P<route>\S+)$",
    re.MULTILINE,
)
ROLES = ["admin", "user"]
WORKLOAD_TOKEN_HEADER = "Agent-Workload-Token"  # noqa: S105 - a header name and no credential
SYSTEM_PROMPT = "You answer a smoke test of the agent service. Follow the instruction exactly."
ANSWER_PROMPT = "Reply with the single word: ok"
LONG_ANSWER_PROMPT = "Count from 1 to 2000, one number per line, and write nothing else."
CANCEL_HOLD_SECONDS = 3.0
CANCEL_PROBE_SECONDS = 0.5
HOLDING_MESSAGE = "holding the stream open"
RUN_END_EVENTS = {"succeeded", "failed", "cancelled"}
SERVICE_HOST = "agent-service"
SERVICE_PORT = 8080
DEFAULT_TIMEOUT_SECONDS = 300.0
TEXT_EVENTS = {"assistant_text", "succeeded"}
MAX_REFUSAL_BYTES = 65536
MAX_RECORD_BYTES = 65536
RUN_ID = re.compile(r"[0-9a-f-]{36}")
REDACTED = "[token]"


class SmokeFailed(Exception):
    """The smoke cannot go on; the message is the one line to print, free of any token."""


class QuietParser(argparse.ArgumentParser):
    """A rejected argument is never printed: a token typed as an option must not reach a log."""

    def error(self, message: str) -> NoReturn:
        self.exit(2, "smoke: unusable arguments; the options: --timeout, --cancel, --tool\n")


@dataclass(frozen=True)
class Tokens:
    person: str
    workload: str


@dataclass(frozen=True)
class Frame:
    event: str
    data: dict


class RecordAnswer(NamedTuple):
    """One answer to `GET /runs/{id}`: the status, and the run's record (agent-runtime's
    `RunStatus`) when it is OK, else the refusal's object or an empty one."""

    status: int
    document: dict


Connect = Callable[[str, int, float], http.client.HTTPConnection]


def read_tokens(stream: IO[str]) -> Tokens:
    lines = [line.strip() for line in stream.read().splitlines()]
    if len(lines) != 2 or not all(lines) or any(" " in line for line in lines):
        raise SmokeFailed("stdin must hold two lines: the person's token, then the workload's")
    return Tokens(person=lines[0], workload=lines[1])


def request_body(prompt: str, tools: dict[str, str] | None = None) -> bytes:
    document = {
        "v": PROTOCOL_VERSION,
        "agent": AGENT,
        "roles": ROLES,
        "tools": tools or {},
        "turn": {"system": SYSTEM_PROMPT, "messages": [{"role": "user", "text": prompt}]},
    }
    return json.dumps(document).encode("utf-8")


def frames(response: http.client.HTTPResponse) -> Iterator[Frame]:
    """The server-sent events of a run; a frame ends at its blank line."""
    fields: dict[str, str] = {}
    for raw in iter(response.readline, b""):
        line = raw.decode("utf-8").rstrip("\r\n")
        if line:
            name, _, value = line.partition(":")
            fields[name] = value.removeprefix(" ")
        elif "data" in fields:
            data = json.loads(fields["data"])
            if not isinstance(data, dict):
                raise ValueError("a frame whose data is no object")
            if data.get("v") != PROTOCOL_VERSION:
                raise ValueError(f"a frame of version {data.get('v')}, not {PROTOCOL_VERSION}")
            yield Frame(fields.get("event", ""), data)
            fields = {}


def text_of(frame: Frame, key: str) -> str:
    value = frame.data.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"a {frame.event} frame whose {key} is no text")
    return value


def refusal_line(response: http.client.HTTPResponse) -> str:
    """The service's typed refusal, or the bare status when the body is not one."""
    body = response.read(MAX_REFUSAL_BYTES)
    try:
        document = json.loads(body)
        return f"refused with {response.status} {document['code']}: {document['message']}"
    except ValueError, KeyError, TypeError:
        return f"refused with {response.status}"


def read_run_record(
    connection: http.client.HTTPConnection, run_id: object, headers: dict[str, str]
) -> RecordAnswer:
    """One read of the run's record on `connection`, which it closes. A run id not of the
    service's shape is never sent; a body over MAX_RECORD_BYTES and an OK body that is no JSON
    object raise ValueError, whose message holds no value of the answer."""
    if not (isinstance(run_id, str) and RUN_ID.fullmatch(run_id)):
        raise ValueError("a run id not of the service's shape")
    try:
        connection.request("GET", f"/runs/{run_id}", None, headers)
        response = connection.getresponse()
        body = response.read(MAX_RECORD_BYTES + 1)
    finally:
        connection.close()
    if len(body) > MAX_RECORD_BYTES:
        raise ValueError(f"a run record over {MAX_RECORD_BYTES} bytes")
    try:
        document = json.loads(body)
    except ValueError:
        document = None
    if isinstance(document, dict):
        return RecordAnswer(response.status, document)
    if response.status == http.HTTPStatus.OK:
        raise ValueError("a run record that is no JSON object")
    return RecordAnswer(response.status, {})


class Smoke:
    def __init__(
        self,
        tokens: Tokens,
        out: IO[str],
        connect: Connect,
        pause: Callable[[float], None],
        tools: dict[str, str],
    ) -> None:
        self.tokens = tokens
        self.tools = tools
        self.out = out
        self.connect = connect
        self.pause = pause

    def say(self, line: str) -> None:
        for token in (self.tokens.person, self.tokens.workload):
            line = line.replace(token, REDACTED)
        print(line, file=self.out, flush=True)

    def run(self, timeout_seconds: float, prompt: str, cancel: bool) -> int:
        connection = self.connect(SERVICE_HOST, SERVICE_PORT, timeout_seconds)
        try:
            connection.request("POST", "/runs", request_body(prompt, self.tools), self.headers())
            response = connection.getresponse()
            if response.status != http.HTTPStatus.OK:
                self.say(refusal_line(response))
                return 1
            return self.read_run(response, connection, cancel)
        except (OSError, http.client.HTTPException, ValueError) as error:
            self.say(f"the run broke off: {type(error).__name__}")
            return 1
        finally:
            connection.close()

    def headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.tokens.person}",
            WORKLOAD_TOKEN_HEADER: self.tokens.workload,
        }

    def read_run(
        self,
        response: http.client.HTTPResponse,
        connection: http.client.HTTPConnection,
        cancel: bool,
    ) -> int:
        last = ""
        for frame in frames(response):
            last = frame.event
            self.say(f"{EVENT_PREFIX}{frame.event}")
            self.say_text(frame)
            if cancel and frame.event == "run_started":
                self.say(f"{HOLDING_MESSAGE} {CANCEL_HOLD_SECONDS:g} s")
                self.pause(CANCEL_HOLD_SECONDS)
                return self.close_while_running(response, connection)
        if cancel:
            self.say("the run ended before the stream could be closed")
            return 1
        return 0 if last == "succeeded" else 1

    def close_while_running(
        self, response: http.client.HTTPResponse, connection: http.client.HTTPConnection
    ) -> int:
        """A frame already waiting after the hold that ends the run, or a stream the service
        closed, means there was nothing left to cancel."""
        connection.sock.settimeout(CANCEL_PROBE_SECONDS)
        ended = ""
        try:
            for waiting in frames(response):
                if waiting.event in RUN_END_EVENTS:
                    ended = f"sent {waiting.event}"
                    break
            else:
                ended = "closed its stream"
        except TimeoutError:
            pass
        if ended:
            self.say(f"the run ended before the close ({ended}); L4 is not proven")
            return 1
        self.say("closing the stream before the answer")
        return 0

    def say_text(self, frame: Frame) -> None:
        if frame.event == "succeeded" and not isinstance(frame.data.get("files"), list):
            raise ValueError("a succeeded frame whose files is no list")
        if frame.event in TEXT_EVENTS:
            self.say(text_of(frame, "text"))
        elif frame.event == "run_started":
            model, route = text_of(frame, "model"), text_of(frame, "route")
            self.say(served_line(model, route))
        elif frame.event == "failed":
            self.say(f"{text_of(frame, 'code')}: {text_of(frame, 'message')}")


def served_line(model: str, route: str) -> str:
    """The line under `event: run_started`; `SERVED_AFTER_RUN_STARTED` reads it back."""
    return f"{SERVED_BY} {model} on route {route}"


def tool_option(text: str) -> tuple[str, str]:
    name, separator, effect = text.partition(":")
    if not (name and separator and effect):
        raise argparse.ArgumentTypeError("a tool is NAME:EFFECT")
    return name, effect


def main(
    argv: list[str],
    stdin: IO[str] = sys.stdin,
    out: IO[str] = sys.stdout,
    connect: Connect = http.client.HTTPConnection,
    pause: Callable[[float], None] = time.sleep,
) -> int:
    parser = QuietParser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS)
    parser.add_argument("--cancel", action="store_true")
    parser.add_argument("--tool", type=tool_option, action="append", default=[])
    arguments = parser.parse_args(argv)
    tools = dict(arguments.tool)
    if len(tools) != len(arguments.tool):
        parser.error("a tool named twice")
    try:
        tokens = read_tokens(stdin)
    except SmokeFailed as failure:
        print(f"smoke: {failure}", file=sys.stderr)  # noqa: T201 - the failure line of the smoke on standard error
        return 1
    prompt = LONG_ANSWER_PROMPT if arguments.cancel else ANSWER_PROMPT
    smoke = Smoke(tokens, out, connect, pause, tools)
    return smoke.run(arguments.timeout, prompt, arguments.cancel)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
