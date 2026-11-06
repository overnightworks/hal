"""What the tests of agent-service/setup share: the scripted Docker host, terminal and openssl, the
throwaway home with its token and signing pair, and the fixtures that hand them out."""

import functools
import json
import os
import stat
import subprocess
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType

import pytest
from support.script_module import loaded_script

SETUP = Path(__file__).resolve().parents[2] / "agent-service" / "setup"
IMAGE = "edge-agent-service:0.0.0-test"
DUMMY_TOKEN = "dummy-setup-token-0123456789"
SECOND_TOKEN = "second-dummy-token-9876543210"


@pytest.fixture(scope="module")
def setup_module() -> Iterator[ModuleType]:
    yield from loaded_script("agent_service_setup", SETUP)


@dataclass
class DockerHost:
    """Docker as the setup meets it: compose names the image, `image inspect` the built ones."""

    images: set[str] = field(default_factory=set)
    commands: list[list[str]] = field(default_factory=list)
    answers: bool = True
    tags_builds: bool = True

    def __call__(self, command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if not self.answers:
            return subprocess.CompletedProcess(
                command, 1, "[]", "Cannot connect to the Docker daemon"
            )
        if command[:2] == ["docker", "compose"]:
            config = {"services": {"agent-service": {"image": IMAGE}}}
            return subprocess.CompletedProcess(command, 0, json.dumps(config), "")
        if command[:3] == ["docker", "image", "inspect"]:
            if command[3] in self.images:
                return subprocess.CompletedProcess(command, 0, "[]", "")
            return subprocess.CompletedProcess(
                command, 1, "[]", f"Error: No such image: {command[3]}"
            )
        assert command[:2] == ["docker", "build"], command
        if self.tags_builds:
            self.images.add(command[command.index("-t") + 1])
        return subprocess.CompletedProcess(command, 0, "", "")

    def builds(self) -> list[list[str]]:
        return [command for command in self.commands if command[:2] == ["docker", "build"]]


@dataclass
class Terminal:
    """The operator's terminal: what the script says, and the lines he pastes in turn."""

    pastes: list[str] = field(default_factory=list)
    said: list[str] = field(default_factory=list)
    prompts: list[str] = field(default_factory=list)
    answers: list[str] = field(default_factory=lambda: ["yes"])
    interactive: bool = True

    def say(self, line: str) -> None:
        self.said.append(line)

    def read_secret(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.pastes.pop(0)

    def confirm(self, prompt: str) -> str:
        self.prompts.append(prompt)
        return self.answers.pop(0)

    def has_terminal(self) -> bool:
        return self.interactive


def generate_key(*options: str) -> bytes:
    """A throwaway RSA key made by host openssl; the tests own every key they use."""
    command = ["openssl", "genpkey", "-algorithm", "RSA", *options]
    return subprocess.run(command, capture_output=True, check=True).stdout


@functools.cache
def sample_pair(index: int) -> tuple[bytes, bytes]:
    """A (private, public) pair of 3072 bits; each index is another key."""
    private = generate_key("-pkeyopt", "rsa_keygen_bits:3072")
    public = subprocess.run(
        ["openssl", "pkey", "-pubout"], input=private, capture_output=True, check=True
    )
    return private, public.stdout


@dataclass
class Openssl:
    """Host openssl, except that `genpkey` hands out the sample keys in turn and named subcommands
    exit with a code or answer exit 0 with forged output; the argument lists are kept so a test can
    look for key bytes in them."""

    generated: list[bytes] = field(default_factory=lambda: [sample_pair(i)[0] for i in (1, 2, 3)])
    failing: dict[str, int] = field(default_factory=dict)
    forged: dict[str, bytes] = field(default_factory=dict)
    calls: list[list[str]] = field(default_factory=list)

    def __call__(self, arguments: list[str], stdin: bytes) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(arguments)
        for name in (arguments[0], " ".join(arguments[:2])):
            if name in self.failing:
                return subprocess.CompletedProcess(arguments, self.failing[name], b"", b"failed")
            if name in self.forged:
                return subprocess.CompletedProcess(arguments, 0, self.forged[name], b"")
        if arguments[0] == "genpkey":
            return subprocess.CompletedProcess(arguments, 0, self.generated.pop(0), b"")
        return subprocess.run(
            ["openssl", *arguments], input=stdin, capture_output=True, check=False
        )


@pytest.fixture
def openssl() -> Openssl:
    return Openssl()


@pytest.fixture
def docker() -> DockerHost:
    return DockerHost(images={IMAGE})


@pytest.fixture
def terminal() -> Terminal:
    return Terminal(pastes=[DUMMY_TOKEN])


@pytest.fixture
def home(tmp_path: Path) -> Path:
    (tmp_path / "home").mkdir()
    return tmp_path / "home"


@pytest.fixture
def make_setup(setup_module, docker, terminal, home, openssl) -> Callable[..., object]:
    def build(service_uid: int | None = None, read_secret=None):
        tools = setup_module.Tools(
            run=docker,
            say=terminal.say,
            read_secret=read_secret or terminal.read_secret,
            service_uid=os.getuid() if service_uid is None else service_uid,
            openssl=openssl,
            has_terminal=terminal.has_terminal,
            confirm=terminal.confirm,
        )
        return setup_module.AgentServiceSetup(tools, home)

    return build


def login_directory(home: Path) -> Path:
    return home / ".secrets" / "agent-service" / "claude"


def token_path(home: Path) -> Path:
    return login_directory(home) / "token"


def make_login_directory(home: Path) -> None:
    for directory in (
        home / ".secrets",
        home / ".secrets" / "agent-service",
        login_directory(home),
    ):
        directory.mkdir(mode=0o700, exist_ok=True)


def signing_directory(home: Path) -> Path:
    return home / ".secrets" / "agent-service" / "signing"


def lay_signing_pair(home: Path, index: int = 0) -> None:
    directory = signing_directory(home)
    directory.mkdir(mode=0o700, exist_ok=True)
    for name, contents, mode in zip(
        ("private.pem", "public.pem"), sample_pair(index), (0o600, 0o644), strict=True
    ):
        (directory / name).write_bytes(contents)
        (directory / name).chmod(mode)


def write_token(home: Path, contents: bytes | str, mode: int = 0o600) -> None:
    """The login of a set-up host, with the signing pair beside it."""
    make_login_directory(home)
    lay_signing_pair(home)
    path = token_path(home)
    path.write_bytes(contents if isinstance(contents, bytes) else contents.encode())
    path.chmod(mode)


def mode_of(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)
