"""The key step's one-off: reads and writes each app's LiteLLM key, the person budget and the
admin budget with its customer rows through LiteLLM's admin routes with the master key.

It runs inside the `litellm-keys` compose service (compose.yaml) on `litellm-backend`, standard
library only, so it imports with `python -I` and nothing beside it:

    docker compose run -T --rm --no-deps litellm-keys --read <budget id> < members
    docker compose run -T --rm --no-deps litellm-keys --write < changes

The service's entrypoint carries `--base-url http://litellm:4000`. The apps are the key files
compose mounts into APP_KEYS_DIRECTORY, one per app, named after it; the master key is a file
too. A key and its SHA-256 travel only in a request body, never in a URL, an argument or a line
this program prints.

`--read` prints one JSON object: per app the settings of the live key whose hash is its file's, or
null, and `name_taken` when no live key has that hash while another holds the app's name; the
person budget's row or null; and the names `/v1/models` lists. `/v2/key/info` reads only live
keys, so a deleted key is absent, and it drops each row's `token`, so it is asked once per hash.
Its stdin is JSON null, or the admin budget's id and its members' fingerprints; then `admin` holds
that budget's row or null, each member's customer row in the order given (null when absent, else
its budget link and spend), and each row on the admin budget that is no member's with its
fingerprint and spend, all from one `/customer/list`; no other customer row leaves.

`--write` reads the host's changes as JSON on stdin and makes them in their given order. A new
key is generated with the file's key, an update names the key by its hash; only the given fields
are sent. A customer change links a row to a budget, by `/customer/new` for a new row; one to a
null budget unlinks it by the pair `unlink` describes. The first failed write stops the rest; it
prints, per change, done, failed with its cause, or not made. A refusal with status 400 whose
`error.param` is `key_alias` is the cause `name taken`; any other is its status or `timed out`,
never a reply body.

Output is printed only once the command ran to its end, with exit 0. A failure before that is one
line on stderr, stdout stays empty, and the exit is 1; a stop by SIGINT or SIGTERM exits 130.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import signal
import sys
from dataclasses import dataclass, field
from http.client import HTTPException
from pathlib import Path
from typing import Any, TextIO
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

PROGRAM = "litellm-keys"
REQUEST_SECONDS = 15.0
# compose.yaml mounts the secrets here; fixed paths, never ones an argument names.
MASTER_KEY_FILE = Path("/run/secrets/litellm_master_key")
APP_KEYS_DIRECTORY = Path("/run/secrets/apps")
KEY_FIELDS = (
    "key_alias", "max_budget", "budget_duration", "models", "allowed_routes",
    "max_parallel_requests", "rpm_limit", "tpm_limit",
)  # fmt: skip
BUDGET_FIELDS = ("max_budget", "budget_duration")
NAME_TAKEN = "name taken"
ALIAS_PARAMETER = "key_alias"  # the `param` of LiteLLM's unique-alias refusal
WRITES = {  # (target, new) -> the route that makes it
    ("budget", True): "/budget/new",
    ("budget", False): "/budget/update",
    ("key", True): "/key/generate",
    ("key", False): "/key/update",
    ("customer", True): "/customer/new",
    ("customer", False): "/customer/update",
}
UNLINK = "unlink"  # a customer change to a null budget, which LiteLLM's update cannot make
# The fields of a customer row that `/customer/new` takes back as they are: none of a budget's,
# any of which makes it a budget of its own.
CUSTOMER_FIELDS = (
    "user_id", "spend", "blocked", "alias", "allowed_model_region", "default_model", "models",
)  # fmt: skip


class AdminError(Exception):
    """One line naming what failed, never a reply body or a key."""


class Unanswered(AdminError):
    def __init__(self, path: str, reason: str) -> None:
        super().__init__(f"LiteLLM does not answer {path} ({reason})")
        self.reason = reason


class RefuseRedirects(HTTPRedirectHandler):
    """urllib follows a 30x with the Authorization header; refused, the 30x is its status."""

    def redirect_request(self, *_: Any) -> None:
        return None


# No proxy either: Docker can inject HTTP(S)_PROXY into the container's environment.
OPENER = build_opener(ProxyHandler({}), RefuseRedirects)


def hashed(key: str) -> str:
    """A key as LiteLLM stores it and matches it on its admin routes."""
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class Admin:
    """LiteLLM's admin routes with the master key."""

    base_url: str
    master_key: str = field(repr=False)
    timeout: float = REQUEST_SECONDS

    def asked(self, path: str, body: dict[str, Any] | None = None) -> Any:
        """The parsed answer of a read; any status but 200 fails it."""
        status, document = self.send(path, body)
        if status != 200:
            raise AdminError(f"status {status} at {path}")
        return document

    def send(self, path: str, body: dict[str, Any] | None = None) -> tuple[int, Any]:
        """A POST of `body`, or a GET without one; the status and the parsed answer, None when it
        is no JSON."""
        headers = {"Authorization": f"Bearer {self.master_key}", "Accept": "application/json"}
        data = None
        if body is not None:
            data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
        request = Request(self.base_url + path, data=data, headers=headers)  # noqa: S310 - the base URL is the program's own --base-url argument
        try:
            with OPENER.open(request, timeout=self.timeout) as reply:
                return reply.status, parsed(reply.read())
        except HTTPError as error:
            try:
                return error.code, parsed(error.read())
            finally:
                error.close()
        except (OSError, HTTPException) as error:
            timed_out = isinstance(error, TimeoutError) or isinstance(
                getattr(error, "reason", None), TimeoutError
            )
            raise Unanswered(path, "timed out" if timed_out else "unreachable") from error


def parsed(body: bytes) -> Any:
    try:
        return json.loads(body)
    except ValueError:
        return None


# --- --read -----------------------------------------------------------------------------------


def read(
    admin: Admin, app_keys: dict[str, str], budget_id: str, asked: dict[str, Any] | None
) -> dict[str, Any]:
    found = {
        app: _only_row(admin.asked("/v2/key/info", {"keys": [hashed(key)]}), app)
        for app, key in sorted(app_keys.items())
    }
    named = admin.asked("/v2/key/info", {"key_aliases": sorted(app_keys)})
    holders = {row.get("key_alias") for row in _info(named)}
    wanted = [budget_id] if asked is None else [budget_id, asked["budget"]]
    budgets = _listed(admin.asked("/budget/info", {"budgets": wanted}))
    return {
        "apps": {
            app: {"key": _settings(row, KEY_FIELDS), "name_taken": row is None and app in holders}
            for app, row in found.items()
        },
        "budget": _settings(_budget(budgets, budget_id), BUDGET_FIELDS),
        "models": listed_models(admin),
        "admin": None if asked is None else read_customers(admin, asked, budgets),
    }


def read_customers(
    admin: Admin, asked: dict[str, Any], budgets: list[dict[str, Any]]
) -> dict[str, Any]:
    """The admin budget's row, each member's customer row in the order asked and the rows on the
    admin budget that are no member's."""
    budget_id, members = asked["budget"], asked["members"]
    rows = {row["user_id"]: row for row in customer_rows(admin)}
    asked_for = set(members)
    return {
        "budget": _settings(_budget(budgets, budget_id), BUDGET_FIELDS),
        "members": [_customer_state(rows.get(member)) for member in members],
        "others": [
            {"fingerprint": user_id, "spend": row.get("spend")}
            for user_id, row in rows.items()
            if row.get("budget_id") == budget_id and user_id not in asked_for
        ],
    }


def customer_rows(admin: Admin) -> list[dict[str, Any]]:
    answer = admin.asked("/customer/list")
    if not isinstance(answer, list) or not all(
        isinstance(row, dict) and isinstance(row.get("user_id"), str) for row in answer
    ):
        raise AdminError("no customer rows at /customer/list")
    return answer


def _customer_state(row: dict[str, Any] | None) -> dict[str, Any] | None:
    return None if row is None else {"budget_id": row.get("budget_id"), "spend": row.get("spend")}


def _budget(rows: list[dict[str, Any]], budget_id: str) -> dict[str, Any] | None:
    return next((row for row in rows if row.get("budget_id") == budget_id), None)


def _info(answer: Any) -> list[dict[str, Any]]:
    rows = answer.get("info") if isinstance(answer, dict) else None
    if not isinstance(rows, list) or not all(isinstance(row, dict) for row in rows):
        raise AdminError("no key rows at /v2/key/info")
    return rows


def _only_row(answer: Any, app: str) -> dict[str, Any] | None:
    rows = _info(answer)
    if len(rows) > 1:
        raise AdminError(f"/v2/key/info answers {len(rows)} keys for the hash of {app}")
    return rows[0] if rows else None


def _listed(answer: Any) -> list[dict[str, Any]]:
    if not isinstance(answer, list) or not all(isinstance(row, dict) for row in answer):
        raise AdminError("no budget rows at /budget/info")
    return answer


def _settings(row: dict[str, Any] | None, names: tuple[str, ...]) -> dict[str, Any] | None:
    """Only the fields the host compares: never the token, the key name or anything echoed."""
    return None if row is None else {name: row.get(name) for name in names}


def listed_models(admin: Admin) -> list[str]:
    answer = admin.asked("/v1/models")
    entries = answer.get("data") if isinstance(answer, dict) else None
    if not isinstance(entries, list):
        raise AdminError("no model list at /v1/models")
    models = [entry["id"] for entry in entries if isinstance(entry, dict) and "id" in entry]
    if not models:
        raise AdminError("/v1/models lists no model")
    return models


# --- --write ----------------------------------------------------------------------------------


def write(admin: Admin, app_keys: dict[str, str], changes: list[dict[str, Any]]) -> list[dict]:
    requests = [_request(change, app_keys) for change in changes]  # all refused before any write
    outcomes: list[dict[str, Any]] = []
    for change, (path, body) in zip(changes, requests, strict=True):
        named = {"target": change["target"], "subject": change["subject"]}
        if outcomes and outcomes[-1]["outcome"] != "done":
            outcomes.append(named | {"outcome": "not made"})
            continue
        if path == UNLINK:
            cause = unlink(admin, body["user_id"], body["leaves"])
        else:
            cause = _cause_of(admin, path, body)
        outcomes.append(
            named
            | ({"outcome": "done"} if cause is None else {"outcome": "failed", "cause": cause})
        )
    return outcomes


def _request(change: Any, app_keys: dict[str, str]) -> tuple[str, dict[str, Any]]:
    """The route and body of one change; the file's key is sent only to generate its row."""
    try:
        target, subject, new, fields = (
            change[name] for name in ("target", "subject", "new", "fields")
        )
        path = WRITES[(target, new)]
    except (KeyError, TypeError) as error:
        raise AdminError("a change of an unknown kind") from error
    if not isinstance(fields, dict):
        raise AdminError("a change of an unknown kind")
    if target == "budget":
        return path, {"budget_id": subject, **fields}
    if target == "customer":
        if not isinstance(subject, str) or fields.keys() != {"budget_id"}:
            raise AdminError("a change of an unknown kind")
        if new or fields["budget_id"] is not None:
            return path, {"user_id": subject, **fields}
        if not isinstance(leaves := change.get("leaves"), str):
            raise AdminError("a change of an unknown kind")
        return UNLINK, {"user_id": subject, "leaves": leaves}
    if subject not in app_keys:
        raise AdminError(f"no key file for {subject}")
    key = app_keys[subject]
    return path, {"key": key if new else hashed(key), **fields}


def unlink(admin: Admin, user_id: str, leaves: str) -> str | None:
    """Unlinks a customer row from the budget it leaves. LiteLLM's update drops a null budget, so
    the row is deleted and made again from a read taken right before, with its own fields. A row
    absent or off that budget by then is done untouched; a lost answer between the two calls loses
    the row."""
    try:
        row = next((row for row in customer_rows(admin) if row["user_id"] == user_id), None)
    except AdminError as error:
        return str(error)
    if row is None or row.get("budget_id") != leaves:
        return None
    if cause := _cause_of(admin, "/customer/delete", {"user_ids": [user_id]}):
        return f"{cause} at /customer/delete"
    if cause := _cause_of(admin, "/customer/new", remade(row)):
        return f"{cause} at /customer/new after the delete"
    return None


def remade(row: dict[str, Any]) -> dict[str, Any]:
    """The row's own fields as `/customer/new` takes them, its permission's contents without the
    id LiteLLM gives anew."""
    body = {name: row[name] for name in CUSTOMER_FIELDS if row.get(name) is not None}
    if isinstance(permission := row.get("object_permission"), dict):
        body["object_permission"] = {
            name: value for name, value in permission.items() if name != "object_permission_id"
        }
    return body


def _cause_of(admin: Admin, path: str, body: dict[str, Any]) -> str | None:
    """None when the write was made; else its cause, never the reply's words."""
    try:
        status, document = admin.send(path, body)
    except Unanswered as error:
        return error.reason
    if status == 200:
        return None
    error = document.get("error") if isinstance(document, dict) else None
    if status == 400 and isinstance(error, dict) and error.get("param") == ALIAS_PARAMETER:
        return NAME_TAKEN
    return f"status {status}"


# --- The command ------------------------------------------------------------------------------


def stop(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(
    argv: list[str] | None = None,
    stdin: TextIO | None = None,
    master_key_file: Path = MASTER_KEY_FILE,
    app_keys_directory: Path = APP_KEYS_DIRECTORY,
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="LiteLLM, e.g. http://litellm:4000")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--read", metavar="BUDGET_ID", help="print what LiteLLM holds")
    mode.add_argument("--write", action="store_true", help="make the changes on stdin")
    arguments = parser.parse_args(argv)
    # PID 1 in a container ignores SIGTERM unless it handles it.
    signal.signal(signal.SIGTERM, stop)
    try:
        master_key = read_secret(master_key_file)
        admin = Admin(arguments.base_url.rstrip("/"), master_key, REQUEST_SECONDS)
        app_keys = read_app_keys(app_keys_directory)
        if arguments.write:
            result: Any = write(admin, app_keys, read_changes(stdin or sys.stdin))
        else:
            result = read(admin, app_keys, arguments.read, read_members(stdin or sys.stdin))
    except AdminError as error:
        print(f"{PROGRAM}: {error}", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 1
    except KeyboardInterrupt:
        print(f"{PROGRAM}: stopped", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 130
    except Exception as error:  # its text may quote the master key; only its type is printed
        print(f"{PROGRAM}: unexpected {type(error).__name__}", file=sys.stderr, flush=True)  # noqa: T201 - this container program imports nothing of hal and prints itself
        return 1
    json.dump(result, sys.stdout, sort_keys=True)
    sys.stdout.write("\n")
    return 0


def read_secret(path: Path) -> str:
    try:
        value = path.read_text().strip()
    except OSError as error:
        raise AdminError(f"cannot read the key file {path}") from error
    if not value.isprintable():  # a line break or control character cannot be a header value
        raise AdminError(f"the key file {path} holds no single printable line")
    return value


def read_app_keys(directory: Path) -> dict[str, str]:
    """Each app's key, by the name of its file."""
    try:
        files = sorted(entry for entry in directory.iterdir() if not entry.name.startswith("."))
    except OSError as error:
        raise AdminError(f"cannot list {directory}") from error
    return {file.name: read_secret(file) for file in files}


def read_changes(stdin: TextIO) -> list[dict[str, Any]]:
    changes = _from_stdin(stdin, "changes")
    if not isinstance(changes, list):
        raise AdminError("no changes as JSON on stdin")
    return changes


def read_members(stdin: TextIO) -> dict[str, Any] | None:
    """The admin budget's id and its members' fingerprints the host asks about; None for none."""
    asked = _from_stdin(stdin, "members")
    if asked is None:
        return None
    members = asked.get("members") if isinstance(asked, dict) else None
    if not isinstance(members, list) or not all(isinstance(member, str) for member in members):
        raise AdminError("no members as JSON on stdin")
    if not isinstance(asked.get("budget"), str):
        raise AdminError("no members as JSON on stdin")
    return asked


def _from_stdin(stdin: TextIO, what: str) -> Any:
    try:
        return json.loads(stdin.read())
    except ValueError as error:
        raise AdminError(f"no {what} as JSON on stdin") from error


if __name__ == "__main__":
    sys.exit(main())
