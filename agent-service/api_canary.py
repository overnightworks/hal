"""The canary of the direct route: one completion an app would ask, through the front with the app's
key, and only verdict lines on stdout.

    python -I -B /opt/canary/api_canary.py --key-file PATH --model NAME --marker TEXT

It reads the key from PATH and posts one buffered OpenAI chat completion to the front, at the
address docs/agent-service.md gives apps, with the key as bearer. The body is `model`, one user
message asking for exactly TEXT, and `user`, a fresh random fingerprint; no other field and no
`x-litellm-*` or `anthropic-*` header. It prints `answer <status>` and `marker yes|no`: whether the
first choice's content holds TEXT. Exit 0 only for a 200 whose answer held it. An exception ends
the run with the one line `crashed <ExceptionName>` and exit 1: the type's name only, never its
text. It never prints the key, the message or the answer. Standard library only.
"""

import argparse
import http
import http.client
import json
import re
import secrets
import sys
from pathlib import Path

FRONT_HOST, FRONT_PORT, COMPLETIONS_PATH = "litellm-front", 4000, "/v1/chat/completions"
TIMEOUT_SECONDS = 300
PROMPT = "Reply with exactly this text and nothing else:"
FINGERPRINT_BYTES = 32  # the recipe's form: `fp-` and 64 hex digits
EXCEPTION_NAME = re.compile(r"[A-Za-z]{1,60}")
# The value each line of the canary's stdout may carry, by the line's name.
LINE_VALUES = {
    "answer": re.compile(r"\d{1,3}"),
    "marker": re.compile(r"yes|no"),
    "crashed": EXCEPTION_NAME,
}


def verdicts(stdout: str, exit_code: int) -> dict[str, str]:
    """The canary's verdict lines by name (the last of a repeated name), its exit code as `exit`
    and the count of lines outside the grammar as `unknown`; such a line's text is dropped."""
    found: dict[str, str] = {}
    unknown = 0
    for line in stdout.splitlines():
        name, _, value = line.partition(" ")
        if name in LINE_VALUES and LINE_VALUES[name].fullmatch(value):
            found[name] = value
        else:
            unknown += 1
    return {**found, "exit": str(exit_code), "unknown": str(unknown)}


def crashed_line(failure: BaseException) -> str:
    """The one line a crash prints: the type's name only, never its text."""
    name = type(failure).__name__
    return f"crashed {name if EXCEPTION_NAME.fullmatch(name) else 'Exception'}"


def request_body(model: str, marker: str) -> bytes:
    return json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": f"{PROMPT} {marker}"}],
        "user": f"fp-{secrets.token_hex(FINGERPRINT_BYTES)}",
    }).encode()  # fmt: skip


def answer_content(body: bytes) -> object:
    """The first choice's content, or None for an answer without one."""
    try:
        return json.loads(body)["choices"][0]["message"]["content"]
    except ValueError, KeyError, IndexError, TypeError:
        return None


def run(argv: list[str], out) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--marker", required=True)
    arguments = parser.parse_args(argv)
    key = arguments.key_file.read_text(encoding="utf-8").strip()
    connection = http.client.HTTPConnection(FRONT_HOST, FRONT_PORT, timeout=TIMEOUT_SECONDS)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {key}"}
    connection.request(
        "POST", COMPLETIONS_PATH, request_body(arguments.model, arguments.marker), headers
    )
    response = connection.getresponse()
    content = answer_content(response.read())
    connection.close()
    held = response.status == http.HTTPStatus.OK and isinstance(content, str)
    held = held and arguments.marker in content
    print(f"answer {response.status}", file=out, flush=True)
    print(f"marker {'yes' if held else 'no'}", file=out, flush=True)
    return 0 if held else 1


def main(argv: list[str], out=sys.stdout) -> int:
    try:
        return run(argv, out)
    except Exception as failure:
        print(crashed_line(failure), file=out)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
