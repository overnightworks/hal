"""The API route's canary: one run of a person on the API route, and only verdict lines on stdout.

    python -B /opt/canary/api_canary.py --marker TEXT [--request-marker TEXT] [--cancel]

Stdin holds the person's token and then the workload's, as smoke.py reads them. It prints
`answer <status>`, one `event <name>` per frame, `route <word>` for the route `run_started` names,
`code <code>` for a failed run and `marker yes|no`: whether the text of the answer holds TEXT. It
never prints a message, a token or a run id. `--request-marker` adds its text to the prompt, so a
retention census can look for the request's content. Exit 0 when the run succeeded and the answer
held the marker.

With `--cancel` it holds the stream open for smoke.py's hold, then closes it, reads the run's record
(`GET /runs/{id}`) until it has ended and prints `status <state>`: a client that closes its stream
sees no terminal frame. A refused or unusable record prints `status other`, and no ended record
within the polls `status not_ended`. Exit 0 when the ended record's state is `cancelled`.
"""

import argparse
import http.client
import re
import sys
import time
from collections.abc import Iterable

from smoke import (
    ANSWER_PROMPT,
    CANCEL_HOLD_SECONDS,
    SERVICE_HOST,
    SERVICE_PORT,
    WORKLOAD_TOKEN_HEADER,
    Frame,
    frames,
    read_run_record,
    read_tokens,
    request_body,
    text_of,
)

TIMEOUT_SECONDS = 120
STATUS_POLLS = 60
STATUS_POLL_SECONDS = 0.5
CANCELLED = "cancelled"
NOT_ENDED = "not_ended"
OTHER = "other"
CLOSED_WORD = re.compile(r"[a-z_]{1,40}")


def closed(word: object) -> str:
    return word if isinstance(word, str) and CLOSED_WORD.fullmatch(word) else OTHER


def ended_state(headers: dict[str, str], run_id: object) -> str:
    """The state of the run's record once it has ended; `other` for a refused or unusable
    record, NOT_ENDED when no record ended within the polls."""
    for _ in range(STATUS_POLLS):
        connection = http.client.HTTPConnection(SERVICE_HOST, SERVICE_PORT, timeout=TIMEOUT_SECONDS)
        try:
            status, record = read_run_record(connection, run_id, headers)
        except ValueError:
            return OTHER
        if status != http.HTTPStatus.OK:
            return OTHER
        if record.get("ended_at") is not None:
            return closed(record.get("state"))
        time.sleep(STATUS_POLL_SECONDS)
    return NOT_ENDED


def cancel_after_start(
    connection: http.client.HTTPConnection, headers: dict[str, str], run_id: object, out
) -> int:
    time.sleep(CANCEL_HOLD_SECONDS)
    connection.close()
    state = ended_state(headers, run_id)
    print(f"status {state}", file=out, flush=True)
    return 0 if state == CANCELLED else 1


def read_answer(
    answer: Iterable[Frame],
    connection: http.client.HTTPConnection,
    headers: dict[str, str],
    arguments: argparse.Namespace,
    out,
) -> int:
    """The verdict lines of one answer's frames, then the exit code of the run."""
    seen, ended = False, ""
    for frame in answer:
        ended = frame.event
        print(f"event {closed(frame.event)}", file=out, flush=True)
        if frame.event == "run_started":
            print(f"route {closed(frame.data.get('route'))}", file=out, flush=True)
            if arguments.cancel:
                return cancel_after_start(connection, headers, frame.data.get("run_id"), out)
        if frame.event == "failed":
            print(f"code {closed(frame.data.get('code'))}", file=out, flush=True)
        if frame.event in {"assistant_text", "succeeded"}:
            seen = seen or arguments.marker in text_of(frame, "text")
    print(f"marker {'yes' if seen else 'no'}", file=out, flush=True)
    return 0 if ended == "succeeded" and seen else 1


def main(argv: list[str], stdin=sys.stdin, out=sys.stdout) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--marker", required=True)
    parser.add_argument("--request-marker", default="")
    parser.add_argument("--cancel", action="store_true")
    arguments = parser.parse_args(argv)
    tokens = read_tokens(stdin)
    connection = http.client.HTTPConnection(SERVICE_HOST, SERVICE_PORT, timeout=TIMEOUT_SECONDS)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {tokens.person}",
        WORKLOAD_TOKEN_HEADER: tokens.workload,
    }
    connection.request(
        "POST",
        "/runs",
        request_body(f"{ANSWER_PROMPT} {arguments.request_marker}".strip()),
        headers,
    )
    response = connection.getresponse()
    print(f"answer {response.status}", file=out, flush=True)
    answer = frames(response) if response.status == http.HTTPStatus.OK else ()
    return read_answer(answer, connection, headers, arguments, out)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
