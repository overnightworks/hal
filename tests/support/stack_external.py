"""What the `test_stack_external` tests share with other test modules."""

import json
import os
import pty
import select
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from support.live_stack import LIVE_STACK_PORTS

from hal.stack import checkout
from hal.stack.external import apply as external_apply
from hal.stack.external import cli as external_cli
from hal.stack.external import cloudflare_read, host_probe, tofu

PROJECT_ROOT = Path(__file__).resolve().parents[2]


TOKEN_FILES = {
    ".secrets/cloudflare/fleet-read": "cloudflare-token",
    ".secrets/opentofu/state-passphrase": "file-passphrase",
}


WRITE_TOKEN_FILES = {
    ".secrets/cloudflare/fleet-write": "cloudflare-write-token",
}


PLANS_DIRECTORY = ".secrets/opentofu/plans"


FAKE_TOFU = f"""#!{sys.executable}
import json, os, signal, sys, time
from pathlib import Path

here = Path(__file__).parent
config = json.loads((here / "fake.json").read_text())
command = sys.argv[1]
with (here / "calls.jsonl").open("a") as calls:
    calls.write(json.dumps({{
        "argv": sys.argv[1:],
        "env": dict(os.environ),
        "plan_file_existed": Path(sys.argv[-1]).exists(),
        "tmpdir_mode": os.stat(os.environ["TMPDIR"]).st_mode & 0o777,
    }}) + "\\n")
(here / "made-by-tofu").write_text("a file tofu creates")
for line in config["output_lines"].get(command, []):
    print(line, flush=True)
plan_file = next((a[5:] for a in sys.argv[1:] if a.startswith("-out=")), None)
if plan_file:
    Path(plan_file).write_text("encrypted plan")
if command == config["lock_plans_in"]:
    Path(plan_file or sys.argv[-1]).parent.chmod(0o500)
if command == config["hang_in"]:
    def stop_gracefully(*_):
        with (here / "sigints").open("a") as received:
            received.write("x")
        while config["drain_until_released"] and not (here / "released").exists():
            time.sleep(0.05)
        (here / "stopped gracefully").write_text("stopped")
        print("tofu stopped gracefully", flush=True)
        sys.exit(130)
    signal.signal(signal.SIGINT, stop_gracefully)
    with open(here / "applying", "w") as started:
        started.write("applying")
    time.sleep(60)
locked = Path(os.environ["TMPDIR"]) / config["locked_name"]
if config["leave_undeletable"] and not locked.exists():
    locked.mkdir()
    (locked / config["locked_name"]).write_text("x")
    locked.chmod(0o500)
if command == "version":
    print("OpenTofu v" + config["version"])
if config["echo_environment"]:
    print(json.dumps(dict(os.environ)))
if command == "apply":
    sys.stdout.buffer.write(bytes.fromhex(config["apply_output_hex"]))
    sys.stdout.buffer.flush()
sys.exit(config["exit_codes"].get(command, 0))
"""


@dataclass
class FakeTofu:
    directory: Path

    def configure(
        self,
        *,
        version=None,
        echo_environment=False,
        leave_undeletable=False,
        locked_name="locked",
        hang_in=None,
        drain_until_released=False,
        lock_plans_in=None,
        apply_output=b"",
        output_lines=None,
        **exit_codes,
    ) -> None:
        config = {
            "lock_plans_in": lock_plans_in,
            "apply_output_hex": apply_output.hex(),
            "output_lines": output_lines or {},
            "version": version or tofu.pinned_version(),
            "echo_environment": echo_environment,
            "leave_undeletable": leave_undeletable,
            "locked_name": locked_name,
            "hang_in": hang_in,
            "drain_until_released": drain_until_released,
            "exit_codes": exit_codes,
        }
        (self.directory / "fake.json").write_text(json.dumps(config))

    def calls(self) -> list[dict]:
        log = self.directory / "calls.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    @contextmanager
    def watch_hang(self) -> Iterator[Callable[[], None]]:
        """Yield a wait that returns once the hanging tofu run has installed its SIGINT handler."""
        descriptor = os.open(self.directory / "applying", os.O_RDONLY | os.O_NONBLOCK)

        def wait_until_hanging() -> None:
            ready, _, _ = select.select([descriptor], [], [], 20)
            assert ready, "hanging tofu command never started"

        try:
            yield wait_until_hanging
        finally:
            os.close(descriptor)

    @property
    def sigints_received(self) -> int:
        received = self.directory / "sigints"
        return len(received.read_text()) if received.exists() else 0

    def release_draining_apply(self) -> None:
        (self.directory / "released").write_text("go")

    @property
    def stopped_gracefully(self) -> bool:
        return (self.directory / "stopped gracefully").exists()

    def call(self, command: str) -> dict:
        return next(call for call in self.calls() if call["argv"][0] == command)


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    home = tmp_path / "home"
    for relative, value in TOKEN_FILES.items():
        token_file = home / relative
        token_file.parent.mkdir(parents=True, exist_ok=True)
        token_file.write_text(value + "\n")
        token_file.chmod(0o600)
    for relative, value in WRITE_TOKEN_FILES.items():
        (home / relative).write_text(value + "\n")
        (home / relative).chmod(0o600)
    monkeypatch.setenv("HOME", str(home))
    return home


@pytest.fixture
def fake_tofu(tmp_path, monkeypatch) -> FakeTofu:
    directory = tmp_path / "bin"
    directory.mkdir()
    executable = directory / "tofu"
    executable.write_text(FAKE_TOFU)
    executable.chmod(0o755)
    os.mkfifo(directory / "applying")
    monkeypatch.setenv("PATH", f"{directory}:/usr/bin:/bin")
    fake = FakeTofu(directory)
    fake.configure()
    return fake


def plain_git(tree: Path, *arguments: str) -> None:
    identity = ["-c", "user.name=edge test", "-c", "user.email=test@edge.invalid"]
    environment = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    subprocess.run(
        ["git", "-C", str(tree), *identity, "-c", "core.hooksPath=/dev/null", *arguments],
        check=True, capture_output=True, stdin=subprocess.DEVNULL, env=environment,
    )  # fmt: skip


@pytest.fixture
def live_checkout(home) -> Path:
    """`~/srv/hal` as the operator has it: the main worktree, a clean `main` with one commit."""
    tree = checkout.live_checkout(home)
    (tree / "external").mkdir(parents=True)
    (tree / "external" / "main.tf").write_text("# catalog\n")
    (tree / ".gitignore").write_text((PROJECT_ROOT / ".gitignore").read_text())
    (tree / "fleet.yaml").write_text((PROJECT_ROOT / "fleet.yaml").read_text())
    plain_git(tree, "init", "--quiet", "--initial-branch", "main")
    plain_git(tree, "add", "--all")
    plain_git(tree, "commit", "--quiet", "--message", "init")
    return tree


@pytest.fixture
def publish(home, live_checkout, monkeypatch) -> Callable[[], int]:
    """`apply_command` in process: terminal refusal lifted, host check clean, hosts answering."""
    monkeypatch.setattr(external_apply, "refusal_without_terminal", lambda: None)
    monkeypatch.setattr(external_cli, "check_command", lambda _home, **_keywords: 0)
    ready = RecordingReadyProber()
    return lambda: publish_on_stand_in(home, live_checkout, prober_for=ready)


@dataclass
class Terminal:
    """`apply_command` as a child on a pty, the way the operator runs it."""

    process: subprocess.Popen
    master: int
    scratch: Path
    output: str = ""

    def checks(self) -> list[dict]:
        """What the child's fake host check saw each time it was called, in order."""
        log = self.scratch / "checks.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def ready_asked(self) -> list[dict]:
        """What the child's fake ready prober was asked, in order."""
        log = self.scratch / "ready-asked.jsonl"
        return [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []

    def wait_until_probing(self, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while not (self.scratch / "probing").exists():
            assert time.monotonic() < deadline, "the ready probe never started"
            time.sleep(0.05)

    @property
    def guard_marker(self) -> Path:
        return self.scratch / "left-loopback"

    def read_until(self, text: str, timeout: float = 20) -> None:
        deadline = time.monotonic() + timeout
        while text not in self.output:
            assert time.monotonic() < deadline, f"never saw {text!r} in {self.output!r}"
            if select.select([self.master], [], [], 0.2)[0]:
                self.output += self._read()

    def _read(self) -> str:
        try:
            return os.read(self.master, 65536).decode(errors="replace")
        except OSError:
            return ""

    def type(self, text: str) -> None:
        os.write(self.master, text.encode())

    def signal(self, number: int) -> None:
        self.process.send_signal(number)

    def finish(self) -> int:
        code = self.process.wait(timeout=20)
        while chunk := self._read():
            self.output += chunk
        return code


CHILD_PROGRAM = """
import functools, json, socket, sys, time
from pathlib import Path
from hal.stack.external import cli as external_cli
from hal.stack.external import host_probe, tofu
from hal.stack.external.cloudflare_read import OwnTunnel

config = json.loads(Path(sys.argv.pop(1)).read_text())
scratch = Path(config["scratch"])
tofu.PROJECT_ROOT = Path(config["tree"])

real_connect = socket.socket.connect
if config["connect_attempt"]:
    def real_connect(self, address):
        (scratch / "reached-the-network").write_text(f"{address[0]}:{address[1]}")
        raise ConnectionRefusedError("the stubbed connect")
def refuse_beyond_loopback(self, address):
    if self.family in (socket.AF_INET, socket.AF_INET6):
        if address[0] not in ("127.0.0.1", "::1"):
            (scratch / "left-loopback").write_text(address[0])
            raise ConnectionRefusedError("beyond loopback: " + address[0])
        if address[1] in config["live_stack_ports"]:
            (scratch / "left-loopback").write_text(f"{address[0]}:{address[1]}")
            raise ConnectionRefusedError("the live stack: " + address[0])
    return real_connect(self, address)
socket.socket.connect = refuse_beyond_loopback

if config["connect_attempt"]:
    address, port = config["connect_attempt"]
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family) as attempt:
        try:
            attempt.connect((address, port))
        except ConnectionRefusedError:
            pass
    sys.exit(0)

if config["resolver_stub"]:
    def resolve_to_a_public_address(host, port, *_, **__):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.7", port))]
    socket.getaddrinfo = resolve_to_a_public_address

if config["fake_check_exit"] is not None:
    def fake_check(home, **_):
        calls = (Path(config["bin"]) / "calls.jsonl").read_text().splitlines()
        left_in = lambda name: sorted(p.name for p in (home / ".secrets/opentofu" / name).glob("*"))
        record = {
            "tofu_commands": [json.loads(line)["argv"][0] for line in calls],
            "plans_left": left_in("plans"),
            "tmp_left": left_in("tmp"),
        }
        with (scratch / "checks.jsonl").open("a") as log:
            log.write(json.dumps(record) + "\\n")
        print("fake host check: exit", config["fake_check_exit"])
        return config["fake_check_exit"]
    external_cli.check_command = fake_check

if not config["real_ready_prober"]:
    class RecordingReadyProber:
        def __init__(self, target):
            self.target = target

        def ask(self, name, path="/"):
            record = {"fqdn": name, "path": path, "target": self.target}
            with (scratch / "ready-asked.jsonl").open("a") as log:
                log.write(json.dumps(record) + "\\n")
            if config["ready_hangs"]:
                (scratch / "probing").write_text("probing")
                time.sleep(60)
            return host_probe.Answer(200, None, True, False)
    external_cli.apply_command = functools.partial(
        external_cli.apply_command, prober_for=RecordingReadyProber
    )

own_tunnel = OwnTunnel(config["own_tunnel"][0], Path(config["own_tunnel"][1]))
sys.exit(external_cli.apply_command(Path.home(), own_tunnel=lambda: own_tunnel))
"""


def write_child_configuration(
    scratch: Path,
    *,
    tree: Path,
    tools: Path,
    fake_check_exit: int | None,
    resolver_stub: bool,
    real_ready_prober: bool,
    ready_hangs: bool,
    connect_attempt: tuple[str, int] | None,
) -> None:
    """The settings `CHILD_PROGRAM` reads from `child.json`."""
    (scratch / "child.json").write_text(
        json.dumps(
            {
                "tree": str(tree),
                "bin": str(tools),
                "scratch": str(scratch),
                "fake_check_exit": fake_check_exit,
                "resolver_stub": resolver_stub,
                "live_stack_ports": list(LIVE_STACK_PORTS),
                "real_ready_prober": real_ready_prober,
                "ready_hangs": ready_hangs,
                "connect_attempt": connect_attempt,
                "own_tunnel": [OWN_TUNNEL.id, str(OWN_TUNNEL.config)],
            }
        )
    )


def child_environment(home: Path, tools: Path, extra: dict[str, str] | None) -> dict[str, str]:
    return {
        "HOME": str(home),
        "PATH": f"{tools}:/usr/bin:/bin",
        "PYTHONPATH": os.pathsep.join(path for path in sys.path if path),
        **(extra or {}),
    }


def stop_child(process: subprocess.Popen, child: Terminal, guard_refusal_expected: bool) -> None:
    process.kill()
    process.wait()
    assert child.guard_marker.exists() is guard_refusal_expected, (
        "the child's loopback guard disagrees with the cell"
    )


@pytest.fixture
def terminal(home, fake_tofu, live_checkout, tmp_path):
    """Start `apply` on a pty with a minimal environment and no session bus.

    The child never reaches a live service: its host check is a recording fake that returns
    `check_exit` (or the real one, `real_check`), its ready prober is a recording fake that
    answers 200 (or hangs, `ready_hangs`; or the real one, `real_ready_prober`), and a loopback
    guard refuses any other address and the live stack's ports. A cell that expects the guard to
    refuse says so with `guard_refusal_expected`. A cell that tests the guard itself gives the
    `connect_attempt` (address, port): the child connects there and exits, with the connect under
    the guard replaced by a recorder, so a broken guard cannot reach a real listener.
    """
    started = []

    def start(
        *,
        stdin_is_terminal=True,
        stdout_is_terminal=True,
        tree=None,
        check_exit=0,
        real_check=False,
        real_ready_prober=False,
        ready_hangs=False,
        connect_attempt=None,
        resolver_stub=False,
        guard_refusal_expected=False,
        environment=None,
    ) -> Terminal:
        """`tree` is the checkout whose code runs; the live checkout unless a test says another."""
        master, slave = pty.openpty()
        scratch = tmp_path / f"child-{len(started)}"
        scratch.mkdir()
        write_child_configuration(
            scratch,
            tree=tree or live_checkout,
            tools=fake_tofu.directory,
            fake_check_exit=None if real_check else check_exit,
            resolver_stub=resolver_stub,
            real_ready_prober=real_ready_prober,
            ready_hangs=ready_hangs,
            connect_attempt=connect_attempt,
        )
        process = subprocess.Popen(
            [sys.executable, "-c", CHILD_PROGRAM, str(scratch / "child.json")],
            stdin=slave if stdin_is_terminal else subprocess.DEVNULL,
            stdout=slave if stdout_is_terminal else subprocess.DEVNULL,
            stderr=slave,
            env=child_environment(home, fake_tofu.directory, environment),
            start_new_session=True,
        )
        os.close(slave)
        child = Terminal(process, master, scratch)
        started.append((process, child, guard_refusal_expected))
        return child

    yield start
    for process, child, guard_refusal_expected in started:
        stop_child(process, child, guard_refusal_expected)


def commit_catalog(tree: Path, text: str) -> None:
    (tree / "fleet.yaml").write_text(text)
    plain_git(tree, "commit", "--quiet", "--all", "--message", "catalog")


OWN_TUNNEL = cloudflare_read.OwnTunnel("t-1", Path("/scenario/cloudflared/config.yml"))


def stand_in_tunnel() -> cloudflare_read.OwnTunnel:
    """Reads hal's tunnel in place of the machine's tunnel config."""
    return OWN_TUNNEL


def publish_on_stand_in(*arguments, **keywords) -> int:
    """`apply_command` with hal's tunnel read from the stand-in."""
    return external_cli.apply_command(*arguments, own_tunnel=stand_in_tunnel, **keywords)


def check_on_stand_in(home: Path, **keywords) -> external_cli.HostCheckOutcome:
    """`run_host_check` with hal's tunnel read from the stand-in."""
    return external_cli.run_host_check(home, own_tunnel=stand_in_tunnel, **keywords)


TUNNEL_TARGET = f"{OWN_TUNNEL.id}.cfargotunnel.com"


CLEAN_SNAPSHOT = cloudflare_read.Snapshot(
    OWN_TUNNEL.id, (cloudflare_read.Record("example.test", "CNAME", TUNNEL_TARGET, True),), (), ()
)


STRAY_SNAPSHOT = cloudflare_read.Snapshot(
    OWN_TUNNEL.id,
    (
        cloudflare_read.Record("example.test", "A", "192.0.2.1", True),
        cloudflare_read.Record("stray.example.test", "CNAME", TUNNEL_TARGET, True),
    ),
    (),
    (),
)


class FakeReader:
    """The injected port: answers a snapshot, raises an exception, or runs a callable first."""

    def __init__(self, outcome) -> None:
        self.outcome = outcome
        self.tokens: list[str] = []
        self.reads = 0

    def __call__(self, token: str, _tunnel: cloudflare_read.OwnTunnel):
        self.tokens.append(token)
        return self

    def read(self, _zone: str):
        self.reads += 1
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        if callable(self.outcome):
            self.outcome()
            return CLEAN_SNAPSHOT
        return self.outcome


CLEAN_ANSWER = host_probe.Answer(200, None, True, False)


class FakeProber:
    """The injected second port: answers every name the same way, or runs a callable first."""

    def __init__(self, outcome=CLEAN_ANSWER) -> None:
        self.outcome = outcome
        self.asked: list[str] = []
        self.paths: list[str] = []

    def __call__(self) -> FakeProber:
        return self

    def ask(self, name: str, path: str = "/"):
        self.asked.append(name)
        self.paths.append(path)
        if callable(self.outcome):
            self.outcome()
            return CLEAN_ANSWER
        return self.outcome


EMPTY_PLAN = {"plan": 0}


CHANGING_PLAN = {"plan": 2}


FAILING_APPLY = {"plan": 2, "apply": 1}


def said(output: str) -> str:
    return " ".join(output.split())


class RecordingReadyProber:
    """The injected `prober_for`: records what each target was asked and answers by name."""

    def __init__(self, answers: dict[str, object] | None = None, *, otherwise=CLEAN_ANSWER) -> None:
        self.answers = answers or {}
        self.otherwise = otherwise
        self.asked: list[tuple[str, str, str]] = []  # (name, path, target)

    def __call__(self, target: str) -> _AskingTarget:
        return _AskingTarget(self, target)

    @property
    def names(self) -> list[str]:
        return [name for name, _, _ in self.asked]


@dataclass
class _AskingTarget:
    prober: RecordingReadyProber
    target: str

    def ask(self, name: str, path: str = "/"):
        self.prober.asked.append((name, path, self.target))
        answer = self.prober.answers.get(name, self.prober.otherwise)
        if callable(answer):
            return answer()
        return answer
