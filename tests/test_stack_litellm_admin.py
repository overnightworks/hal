"""The key step's one-off (#964): `src/hal/stack/litellm_admin.py` against a local fake LiteLLM
admin API, as the realm observer's tests drive it, and the compose service that runs it."""

import hashlib
import io
import json
import re
import secrets
import signal
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path, PurePosixPath

import pytest
import yaml

from hal.stack import litellm_admin as admin
from hal.stack import litellm_keys

ROOT = Path(__file__).resolve().parents[1]
APPS = ("hopin", "presentator", "songmaker")
MODELS = ("text/haiku", "text/opus", "text/sonnet")
BUDGET_ID = "scenario-budget"
NAME_TAKEN_BODY = {
    "error": {
        "message": "Key with alias 'x' already exists.",
        "type": "bad_request_error",
        "param": "key_alias",
        "code": "400",
    }
}


def hashed(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class FakeLitellm:
    """The admin routes the one-off sends to, over rows of `LiteLLM_VerificationToken` and
    `LiteLLM_BudgetTable`; `statuses` answer a path with a status and `body`, `slow` holds a path's
    answer longer than the one-off waits."""

    master_key: str
    keys: dict[str, dict] = field(default_factory=dict)  # token -> row
    budgets: dict[str, dict] = field(default_factory=dict)
    models: tuple[str, ...] = MODELS
    statuses: dict[str, tuple[int, dict]] = field(default_factory=dict)
    slow: set[str] = field(default_factory=set)
    requests: list[tuple[str, str, dict | None]] = field(default_factory=list)

    def answer(self, method: str, path: str, body: dict | None) -> tuple[int, object]:
        self.requests.append((method, path, body))
        if path in self.slow:
            time.sleep(0.5)
        if path in self.statuses:
            return self.statuses[path]
        if (method, path) == ("GET", "/v1/models"):
            return 200, {
                "object": "list",
                "data": [{"id": name, "object": "model"} for name in self.models],
            }
        handler = {
            "/v2/key/info": self.key_info,
            "/budget/info": self.budget_info,
            "/budget/new": self.budget_new,
            "/budget/update": self.budget_update,
            "/key/generate": self.generate,
            "/key/update": self.update,
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


class Handler(BaseHTTPRequestHandler):
    server: Server

    def do_GET(self) -> None:
        self.reply(None)

    def do_POST(self) -> None:
        self.reply(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))

    def reply(self, body: dict | None) -> None:
        fake = self.server.fake
        if self.headers.get("Authorization") != f"Bearer {fake.master_key}":
            status, document = 401, {"error": {"message": "no"}}
        else:
            status, document = fake.answer(self.command, self.path, body)
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


@pytest.fixture
def scene(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> Iterator[Scene]:
    monkeypatch.setattr(admin, "REQUEST_SECONDS", 0.2)
    terminate = signal.getsignal(signal.SIGTERM)  # the program handles SIGTERM as PID 1 does
    fake = FakeLitellm(master_key=f"sk-{secrets.token_hex(16)}")
    server = Server(("127.0.0.1", 0), Handler)
    server.fake = fake
    threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True).start()
    master_file = tmp_path / "litellm_master_key"
    master_file.write_text(fake.master_key + "\n")
    apps_directory = tmp_path / "apps"
    apps_directory.mkdir()
    app_keys = {app: f"sk-{secrets.token_urlsafe(24)}" for app in APPS}
    for app, key in app_keys.items():
        (apps_directory / app).write_text(key + "\n")
    base_url = f"http://127.0.0.1:{server.server_address[1]}"

    def run(*flags: str, changes: object = None, at: str = base_url) -> Run:
        stdin = io.StringIO(
            changes if isinstance(changes, str) else "" if changes is None else json.dumps(changes)
        )
        code = admin.main(["--base-url", at, *flags], stdin, master_file, apps_directory)
        captured = capsys.readouterr()
        return Run(code, captured.out, captured.err)

    yield Scene(fake, base_url, master_file, apps_directory, app_keys, run)
    signal.signal(signal.SIGTERM, terminate)
    server.shutdown()
    server.server_close()


def desired_row(app: str) -> dict:
    return {
        name: list(value) if isinstance(value, tuple) else value
        for name, value in litellm_keys.desired_key(app, MODELS).items()
    }


def plant_keys(scene: Scene, **overrides: dict) -> None:
    for app, key in scene.app_keys.items():
        scene.fake.keys[hashed(key)] = (
            desired_row(app) | overrides.get(app, {}) | {"spend": 3.0, "user_id": None}
        )


def key_change(app: str, new: bool, **fields: object) -> dict:
    return {"target": "key", "subject": app, "new": new, "fields": fields}


def budget_change(new: bool, **fields: object) -> dict:
    return {"target": "budget", "subject": BUDGET_ID, "new": new, "fields": fields}


def assert_nothing_secret_in(scene: Scene, run: Run) -> None:
    for secret in scene.everything_secret:
        assert secret not in run.stdout + run.stderr


# --- the read ---------------------------------------------------------------------------------


def test_the_read_reports_each_apps_live_key_by_its_hash_the_person_budget_and_the_models(
    scene: Scene,
) -> None:
    plant_keys(scene, hopin={"max_budget": 7.0})
    scene.fake.budgets[BUDGET_ID] = {
        "budget_id": BUDGET_ID,
        "max_budget": 1.5,
        "budget_duration": "1mo",
        "budget_reset_at": "2026-12-01T00:00:00Z",
    }
    run = scene.run("--read", BUDGET_ID)

    assert run.exit_code == 0, run.stderr
    assert run.document == {
        "apps": {
            app: {
                "key": {name: value for name, value in desired_row(app).items()}
                | ({"max_budget": 7.0} if app == "hopin" else {}),
                "name_taken": False,
            }
            for app in APPS
        },
        "budget": {"max_budget": 1.5, "budget_duration": "1mo"},
        "models": list(MODELS),
    }


def test_the_read_asks_by_hash_in_the_body_one_app_at_a_time_and_by_every_name_at_once(
    scene: Scene,
) -> None:
    scene.run("--read", BUDGET_ID)

    asked = [body for method, path, body in scene.fake.requests if path == "/v2/key/info"]
    assert asked == [
        *({"keys": [hashed(scene.app_keys[app])]} for app in APPS),
        {"key_aliases": list(APPS)},
    ]
    assert all(method == "POST" for method, path, _ in scene.fake.requests if path != "/v1/models")
    assert ("POST", "/budget/info", {"budgets": [BUDGET_ID]}) in scene.fake.requests


def test_an_app_whose_hash_no_live_key_has_while_another_key_holds_its_name_is_name_taken(
    scene: Scene,
) -> None:
    plant_keys(scene)
    scene.fake.keys[hashed("sk-the-old-file")] = scene.fake.keys.pop(
        hashed(scene.app_keys["hopin"])
    )
    run = scene.run("--read", BUDGET_ID)

    assert run.document["apps"]["hopin"] == {"key": None, "name_taken": True}
    assert run.document["apps"]["songmaker"]["name_taken"] is False


def test_an_empty_database_reads_every_key_and_the_budget_as_absent(scene: Scene) -> None:
    run = scene.run("--read", BUDGET_ID)

    assert run.document["apps"] == {app: {"key": None, "name_taken": False} for app in APPS}
    assert run.document["budget"] is None


def test_the_read_carries_no_token_hash_key_name_or_echoed_request(scene: Scene) -> None:
    plant_keys(scene)
    run = scene.run("--read", BUDGET_ID)

    assert_nothing_secret_in(scene, run)
    assert not re.search(r'"(token|key_name|spend|user_id)"', run.stdout)
    rows = [entry["key"] for entry in run.document["apps"].values()]
    assert all(set(row) == set(admin.KEY_FIELDS) for row in rows)


@pytest.mark.parametrize(
    ("arrange", "line"),
    [
        pytest.param(
            lambda fake: setattr(fake, "models", ()),
            "/v1/models lists no model",
            id="an empty model list",
        ),
        pytest.param(
            lambda fake: fake.statuses.update({"/v2/key/info": (502, {"error": "migrating"})}),
            "status 502 at /v2/key/info",
            id="502 while LiteLLM migrates",
        ),
        pytest.param(
            lambda fake: fake.slow.add("/budget/info"),
            "LiteLLM does not answer /budget/info (timed out)",
            id="a timed-out request",
        ),
    ],
)
def test_a_failed_read_is_one_named_line_on_stderr_nothing_on_stdout_and_exit_1(
    scene: Scene, arrange: Callable[[FakeLitellm], None], line: str
) -> None:
    plant_keys(scene)
    arrange(scene.fake)
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (1, "", f"litellm-keys: {line}\n")


def test_a_master_key_litellm_refuses_is_its_status_alone(scene: Scene) -> None:
    scene.master_file.write_text("sk-wrong\n")
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: status 401 at /v2/key/info\n",
    )


def test_litellm_that_does_not_answer_is_one_line(scene: Scene) -> None:
    run = scene.run("--read", BUDGET_ID, at="http://127.0.0.1:9")

    assert (run.exit_code, run.stdout, run.stderr) == (
        1,
        "",
        "litellm-keys: LiteLLM does not answer /v2/key/info (unreachable)\n",
    )


# --- the write --------------------------------------------------------------------------------


def test_the_write_makes_the_changes_in_their_given_order_and_reports_each_done(
    scene: Scene,
) -> None:
    changes = [
        budget_change(True, max_budget=2.0, budget_duration="1mo"),
        *(
            key_change(app, True, **{n: v for n, v in desired_row(app).items() if v is not None})
            for app in APPS
        ),
    ]
    run = scene.run("--write", changes=changes)

    assert run.exit_code == 0, run.stderr
    assert run.document == [
        {"target": change["target"], "subject": change["subject"], "outcome": "done"}
        for change in changes
    ]
    assert [path for _, path, _ in scene.fake.requests] == [
        "/budget/new",
        "/key/generate",
        "/key/generate",
        "/key/generate",
    ]
    assert {hashed(key) for key in scene.app_keys.values()} == set(scene.fake.keys)
    assert all(
        scene.fake.keys[hashed(key)]["key_alias"] == app for app, key in scene.app_keys.items()
    )
    assert_nothing_secret_in(scene, run)


def test_an_update_names_the_key_by_its_hash_and_sends_only_the_given_fields(scene: Scene) -> None:
    plant_keys(scene, songmaker={"max_budget": 7.0, "rpm_limit": 60})
    scene.fake.budgets[BUDGET_ID] = {
        "budget_id": BUDGET_ID,
        "max_budget": 1.5,
        "budget_duration": "1mo",
    }
    run = scene.run(
        "--write",
        changes=[
            budget_change(False, max_budget=2.0),
            key_change("songmaker", False, max_budget=10.0, rpm_limit=None),
        ],
    )

    assert run.exit_code == 0, run.stderr
    assert [(path, body) for _, path, body in scene.fake.requests] == [
        ("/budget/update", {"budget_id": BUDGET_ID, "max_budget": 2.0}),
        (
            "/key/update",
            {"key": hashed(scene.app_keys["songmaker"]), "max_budget": 10.0, "rpm_limit": None},
        ),
    ]


def test_the_first_failed_write_stops_the_rest_which_are_not_made(scene: Scene) -> None:
    scene.fake.statuses["/budget/new"] = (
        500,
        {"error": {"message": f"db down {scene.app_keys['hopin']}"}},
    )
    changes = [
        budget_change(True, max_budget=2.0),
        key_change("hopin", True, key_alias="hopin"),
        key_change("songmaker", True, key_alias="songmaker"),
    ]
    run = scene.run("--write", changes=changes)

    assert run.exit_code == 0
    assert [entry["outcome"] for entry in run.document] == ["failed", "not made", "not made"]
    assert run.document[0]["cause"] == "status 500"
    assert [path for _, path, _ in scene.fake.requests] == ["/budget/new"]
    assert_nothing_secret_in(scene, run)


def test_a_name_another_live_key_holds_is_the_cause_name_taken(scene: Scene) -> None:
    scene.fake.keys[hashed("sk-the-old-file")] = {"key_alias": "hopin"}
    run = scene.run(
        "--write",
        changes=[
            key_change("hopin", True, key_alias="hopin"),
            key_change("songmaker", True, key_alias="songmaker"),
        ],
    )

    assert run.document == [
        {"target": "key", "subject": "hopin", "outcome": "failed", "cause": "name taken"},
        {"target": "key", "subject": "songmaker", "outcome": "not made"},
    ]
    assert "already exists" not in run.stdout + run.stderr


@pytest.mark.parametrize(
    ("status", "body"),
    [
        pytest.param(400, {"error": {"param": "max_budget"}}, id="another parameter"),
        pytest.param(400, {"detail": "key_alias"}, id="no error object"),
        pytest.param(409, NAME_TAKEN_BODY["error"], id="the parameter at another status"),
    ],
)
def test_a_refusal_that_is_not_the_alias_rule_is_its_status_alone(
    scene: Scene, status: int, body: dict
) -> None:
    scene.fake.statuses["/key/generate"] = (status, body)
    run = scene.run("--write", changes=[key_change("hopin", True, key_alias="hopin")])

    assert run.document[0]["cause"] == f"status {status}"


def test_a_timed_out_write_is_the_cause_timed_out(scene: Scene) -> None:
    scene.fake.slow.add("/key/generate")
    run = scene.run(
        "--write",
        changes=[
            key_change("hopin", True, key_alias="hopin"),
            key_change("songmaker", True, key_alias="songmaker"),
        ],
    )

    assert [(entry["outcome"], entry.get("cause")) for entry in run.document] == [
        ("failed", "timed out"),
        ("not made", None),
    ]


@pytest.mark.parametrize(
    ("changes", "line"),
    [
        pytest.param(
            [key_change("stranger", True, key_alias="stranger")],
            "no key file for stranger",
            id="an app with no key file",
        ),
        pytest.param(
            [{"target": "team", "subject": "x", "new": True, "fields": {}}],
            "a change of an unknown kind",
            id="an unknown target",
        ),
        pytest.param("not json", "no changes as JSON on stdin", id="no JSON"),
    ],
)
def test_a_change_list_it_cannot_make_is_refused_before_any_write(
    scene: Scene, changes: object, line: str
) -> None:
    run = scene.run("--write", changes=changes)

    assert (run.exit_code, run.stdout, run.stderr) == (1, "", f"litellm-keys: {line}\n")
    assert scene.fake.requests == []


def test_an_unreadable_master_key_is_one_line_before_any_request(scene: Scene) -> None:
    scene.master_file.unlink()
    run = scene.run("--read", BUDGET_ID)

    assert (run.exit_code, run.stdout) == (1, "")
    assert run.stderr == f"litellm-keys: cannot read the key file {scene.master_file}\n"
    assert scene.fake.requests == []


# --- the compose service ----------------------------------------------------------------------


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


@pytest.fixture(scope="module")
def secrets_declared() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["secrets"]


def test_the_one_off_shares_the_realm_observers_profile_image_logging_and_hardening(
    services: dict,
) -> None:
    one_off, observer = services[litellm_keys.KEYS_SERVICE], services["realm-observer"]

    for key in ("profiles", "image", "logging", "read_only", "cap_drop", "security_opt"):
        assert one_off[key] == observer[key]
    assert one_off["user"] == services[litellm_keys.LITELLM_SERVICE]["user"]


def test_the_one_off_is_on_litellm_backend_alone_with_no_port_dependency_or_other_environment(
    services: dict,
) -> None:
    one_off = services[litellm_keys.KEYS_SERVICE]

    assert one_off["networks"] == ["litellm-backend"]
    assert (
        not {"ports", "expose", "depends_on", "extra_hosts", "network_mode", "cap_add", "restart"}
        & one_off.keys()
    )
    assert one_off["environment"] == {"PYTHONDONTWRITEBYTECODE": "1"}


def test_the_one_off_runs_the_mounted_program_against_litellms_own_port(services: dict) -> None:
    one_off = services[litellm_keys.KEYS_SERVICE]
    (mount,) = one_off["volumes"]
    source, target, mode = mount.split(":")
    port = re.search(r"--port (\d+)", (ROOT / "agent-service/litellm/start.sh").read_text()).group(
        1
    )

    assert (ROOT / source).resolve() == Path(admin.__file__).resolve()
    assert mode == "ro"
    assert one_off["entrypoint"] == [
        "python",
        "-I",
        "-B",
        target,
        "--base-url",
        f"http://{litellm_keys.LITELLM_SERVICE}:{port}",
    ]


def test_the_one_off_reads_the_master_key_and_one_secret_per_app_key_file_where_the_program_looks(
    services: dict, secrets_declared: dict
) -> None:
    mounted = services[litellm_keys.KEYS_SERVICE]["secrets"]
    master = [entry for entry in mounted if isinstance(entry, str)]
    apps = {
        PurePosixPath("/run/secrets", entry["target"]): secrets_declared[entry["source"]]["file"]
        for entry in mounted
        if isinstance(entry, dict)
    }

    assert [PurePosixPath("/run/secrets", name) for name in master] == [
        PurePosixPath(admin.MASTER_KEY_FILE)
    ]
    assert {path.parent for path in apps} == {PurePosixPath(admin.APP_KEYS_DIRECTORY)}
    assert all(path.name == PurePosixPath(file).name for path, file in apps.items())
    assert len(apps) == len(mounted) - 1
