"""A fake LiteLLM admin API for the key step's one-off (#964, #965): the rows it holds, the faults
it injects, the server that runs it, and the scene a test drives `litellm_admin.py` in."""

import hashlib
import io
import json
import secrets
import signal
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType

import pytest

from hal.stack import litellm_admin as admin

APPS = ("hopin", "presentator", "songmaker")
MODELS = ("text/haiku", "text/opus", "text/sonnet")
NAME_TAKEN_BODY = {
    "error": {
        "message": "Key with alias 'x' already exists.",
        "type": "bad_request_error",
        "param": "key_alias",
        "code": "400",
    }
}
# The fields `NewCustomerRequest` inherits from `BudgetNewRequest` in LiteLLM 1.106.6: any of them
# makes `/customer/new` create a budget for the row and link the row to it.
NEW_BUDGET_FIELDS = frozenset({
    "max_budget", "soft_budget", "max_parallel_requests", "tpm_limit", "rpm_limit", "tpd_limit",
    "budget_duration", "model_max_budget", "budget_reset_at",
})  # fmt: skip


def hashed(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class FakeLitellm:
    """The admin routes the one-off sends to, over rows of `LiteLLM_VerificationToken`,
    `LiteLLM_BudgetTable` and `LiteLLM_EndUserTable`; `statuses` answer a path with a status and
    `body`, `slow` holds a path's answer until `release` is set, `redirects` answer a path with a
    302 to a location, `lost` makes a path's change and loses its answer."""

    master_key: str
    keys: dict[str, dict] = field(default_factory=dict)  # token -> row
    budgets: dict[str, dict] = field(default_factory=dict)
    customers: dict[str, dict] = field(default_factory=dict)  # user_id -> row
    models: tuple[str, ...] = MODELS
    statuses: dict[str, tuple[int, dict]] = field(default_factory=dict)
    slow: set[str] = field(default_factory=set)
    release: threading.Event = field(default_factory=threading.Event)
    redirects: dict[str, str] = field(default_factory=dict)
    garbage: set[str] = field(default_factory=set)  # paths answered with no HTTP at all
    lost: set[str] = field(default_factory=set)  # paths answered with no HTTP once made
    interrupt: set[str] = field(default_factory=set)  # paths whose request SIGTERMs the program
    arrivals: list[tuple[str, str]] = field(default_factory=list)  # every request, answered or not
    requests: list[tuple[str, str, dict | None]] = field(default_factory=list)

    def answer(self, method: str, path: str, body: dict | None) -> tuple[int, object]:
        self.requests.append((method, path, body))
        if path in self.slow:
            self.release.wait(timeout=30)
        if path in self.interrupt:
            signal.pthread_kill(threading.main_thread().ident, signal.SIGTERM)
            self.release.wait(timeout=30)
        if path in self.statuses:
            return self.statuses[path]
        if (method, path) == ("GET", "/v1/models"):
            return 200, {
                "object": "list",
                "data": [{"id": name, "object": "model"} for name in self.models],
            }
        if (method, path) == ("GET", "/customer/list"):
            return 200, [self.customer_answer(row) for row in self.customers.values()]
        handler = {
            "/v2/key/info": self.key_info,
            "/budget/info": self.budget_info,
            "/budget/new": self.budget_new,
            "/budget/update": self.budget_update,
            "/key/generate": self.generate,
            "/key/update": self.update,
            "/customer/new": self.customer_new,
            "/customer/update": self.customer_update,
            "/customer/delete": self.customer_delete,
        }[path]
        return handler(body or {})

    def key_info(self, body: dict) -> tuple[int, object]:
        tokens = [token for token in body.get("keys") or [] if token in self.keys]
        tokens += [
            token
            for token, row in self.keys.items()
            if row.get("key_alias") in (body.get("key_aliases") or [])
        ]
        rows = [
            {name: value for name, value in self.keys[token].items()} | {"key_name": "sk-...abcd"}
            for token in tokens
        ]
        return 200, {"key": body.get("keys"), "info": rows}

    def budget_info(self, body: dict) -> tuple[int, object]:
        return 200, [row for budget_id, row in self.budgets.items() if budget_id in body["budgets"]]

    def budget_new(self, body: dict) -> tuple[int, object]:
        self.budgets[body["budget_id"]] = dict(body)
        return 200, body

    def budget_update(self, body: dict) -> tuple[int, object]:
        self.budgets[body["budget_id"]] |= body
        return 200, body

    def generate(self, body: dict) -> tuple[int, object]:
        if any(row.get("key_alias") == body.get("key_alias") for row in self.keys.values()):
            return 400, NAME_TAKEN_BODY
        row = {name: value for name, value in body.items() if name != "key"}
        self.keys[hashed(body["key"])] = row
        return 200, {"key": body["key"], "token": hashed(body["key"])}

    def update(self, body: dict) -> tuple[int, object]:
        token = body["key"]
        if token not in self.keys:
            return 404, {"error": {"message": "not found"}}
        self.keys[token] |= {name: value for name, value in body.items() if name != "key"}
        return 200, {"key": token}

    def customer_answer(self, row: dict) -> dict:
        """A row as `/customer/list` answers it: its budget and its permission joined in."""
        return row | {"litellm_budget_table": self.budgets.get(row["budget_id"] or "")}

    def customer_new(self, body: dict) -> tuple[int, object]:
        """As LiteLLM makes a row: a budget field makes a new budget for it, and the permission
        gets a new id."""
        user_id = body["user_id"]
        if user_id in self.customers:
            return 400, {"error": {"message": f"Customer already exists, user_id={user_id}"}}
        budget_id = body.get("budget_id")
        if budget := {name: body[name] for name in NEW_BUDGET_FIELDS & body.keys()}:
            budget_id = f"budget-{len(self.budgets)}"
            self.budgets[budget_id] = {"budget_id": budget_id, **budget}
        permission = body.get("object_permission")
        self.customers[user_id] = {
            "user_id": user_id,
            "blocked": body.get("blocked", False),
            "alias": body.get("alias"),
            "spend": body.get("spend") or 0.0,
            "allowed_model_region": body.get("allowed_model_region"),
            "default_model": body.get("default_model"),
            "models": body.get("models") or [],
            "budget_id": budget_id,
            "object_permission_id": None if permission is None else secrets.token_hex(4),
            "object_permission": permission and {"object_permission_id": "new", **permission},
        }
        return 200, self.customers[user_id]

    def customer_update(self, body: dict) -> tuple[int, object]:
        """As LiteLLM updates a row: a null field is dropped, so a link cannot be cleared."""
        row = self.customers.get(body["user_id"])
        if row is None:
            return 404, {"error": {"message": f"End User Id={body['user_id']} does not exist"}}
        row |= {name: value for name, value in body.items() if value is not None}
        return 200, row

    def customer_delete(self, body: dict) -> tuple[int, object]:
        missing = [user_id for user_id in body["user_ids"] if user_id not in self.customers]
        if missing:
            return 404, {"error": {"message": f"End User Id(s)={', '.join(missing)} do not exist"}}
        for user_id in body["user_ids"]:
            del self.customers[user_id]
        return 200, {"deleted_customers": len(body["user_ids"])}


class Handler(BaseHTTPRequestHandler):
    server: Server

    def do_GET(self) -> None:
        self.reply(None)

    def do_POST(self) -> None:
        self.reply(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def reply(self, body: dict | None) -> None:
        fake = self.server.fake
        fake.arrivals.append((self.command, self.path))
        if self.headers.get("Authorization") != f"Bearer {fake.master_key}":
            status, document = 401, {"error": {"message": "no"}}
        elif self.path in fake.garbage:
            self.wfile.write(b"not http\r\n\r\n")
            return
        elif self.path in fake.redirects:
            self.send_response(302)
            self.send_header("Location", fake.redirects[self.path])
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        else:
            status, document = fake.answer(self.command, self.path, body)
        if self.path in fake.lost:
            self.wfile.write(b"not http\r\n\r\n")
            return
        encoded = json.dumps(document).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_: object) -> None:
        return None


class Server(ThreadingHTTPServer):
    fake: FakeLitellm
    # server_close() then joins every handler, so a released one writes before the next test runs.
    daemon_threads = False


@dataclass(frozen=True)
class Run:
    exit_code: int
    stdout: str
    stderr: str

    @property
    def document(self) -> dict:
        return json.loads(self.stdout)


@dataclass
class Scene:
    fake: FakeLitellm
    base_url: str
    master_file: Path
    apps_directory: Path
    app_keys: dict[str, str]
    run: Callable[..., Run]

    @property
    def everything_secret(self) -> list[str]:
        return [
            self.fake.master_key,
            *self.app_keys.values(),
            *(hashed(key) for key in self.app_keys.values()),
        ]


@contextmanager
def serving(fake: FakeLitellm) -> Iterator[str]:
    """The fake on a loopback port; a held answer is released before the server stops."""
    server = Server(("127.0.0.1", 0), Handler)
    server.fake = fake
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        fake.release.set()
        server.shutdown()
        server.server_close()


@pytest.fixture(name="bystander")
def bystander_fixture() -> Iterator[tuple[FakeLitellm, str]]:
    """A second fake that stands in for a proxy Docker injects, or the other origin of a redirect:
    whatever reaches it is logged."""
    fake = FakeLitellm(master_key="sk-bystander")
    with serving(fake) as url:
        yield fake, url


@pytest.fixture(name="short_requests")
def short_requests_fixture(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(admin, "REQUEST_SECONDS", 0.2)


@pytest.fixture(name="scene")
def scene_fixture(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> Iterator[Scene]:
    terminate = signal.getsignal(signal.SIGTERM)  # the program handles SIGTERM as PID 1 does
    fake = FakeLitellm(master_key=f"sk-{secrets.token_hex(16)}")
    with serving(fake) as base_url:
        yield from scene_on(fake, base_url, tmp_path, capsys, terminate)


def scene_on(
    fake: FakeLitellm,
    base_url: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    terminate: object,
) -> Iterator[Scene]:
    master_file = tmp_path / "litellm_master_key"
    master_file.write_text(fake.master_key + "\n")
    apps_directory = tmp_path / "apps"
    apps_directory.mkdir()
    app_keys = {app: f"sk-{secrets.token_urlsafe(24)}" for app in APPS}
    for app, key in app_keys.items():
        (apps_directory / app).write_text(key + "\n")

    def run(
        *flags: str, changes: object = None, at: str = base_url, program: ModuleType = admin
    ) -> Run:
        """`changes` is the program's standard input: a string as it is, anything else as JSON,
        so a read is told no members by default."""
        stdin = io.StringIO(changes if isinstance(changes, str) else json.dumps(changes))
        code = program.main(["--base-url", at, *flags], stdin, master_file, apps_directory)
        captured = capsys.readouterr()
        return Run(code, captured.out, captured.err)

    yield Scene(fake, base_url, master_file, apps_directory, app_keys, run)
    signal.signal(signal.SIGTERM, terminate)
