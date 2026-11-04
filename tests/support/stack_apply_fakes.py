"""Scripted boundaries of the stack apply tests: compose, git, ingress, setup and terminal."""

import hashlib
import io
import json
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from hal.stack import (
    barrier,
    checkout,
    compose,
    setup,
    switches,
)
from hal.stack.litellm_keys import ADMIN_BUDGET_ID, KEYS_SERVICE
from hal.stack.realm import reconcile

PROJECT_PREFIX = 6  # docker compose --project-directory D --file F


NOT_FOUND = barrier.Answer(404, b"404 page not found\n", "probe")  # the barrier of unit `probe`


PLAIN_NOT_FOUND = barrier.Answer(404, b"404 page not found\n")  # Traefik's no-route answer


WHOAMI = barrier.Answer(200, b"Hostname: abc\n")


NEVER_RUN = {"down", "-v", "--volumes", "-V", "--renew-anon-volumes"}


LABELLED_IMAGE_ID = "sha256:cd370f99dbfb63a9541c3787c576352d0d22e78fa33ef9d831f97cbeee9667e9"


OTHER_LABELS = (
    f"com.docker.compose.image={LABELLED_IMAGE_ID},"
    "com.docker.compose.oneoff=False,edge.note=x,y=z,com.docker.compose.depends_on="
)


IMAGE = (
    "traefik/whoami:v1.12.0@sha256:c4717a8d1f0134a7444e24f881160e033991f23027c6c5a9a3f8fd22e70d1d44"
)


TRAEFIK_IMAGE = (
    "traefik:v3.7.14@sha256:575fa15b135078fe5e50aa847987d96dbddd7b093c172429618404df73f3fa7c"
)


SOCKET_PROXY_IMAGE = (
    "wollomatic/socket-proxy:1.13.1"
    "@sha256:3935b709275e4ec35d6ed5a5c4a1f0d01ed31eec5e7234efc3357ecd47689002"
)


KEYCLOAK_IMAGE = (
    "quay.io/keycloak/keycloak:26.8.1"
    "@sha256:79c623a22abacf3fe6c00a5fb30f5b7843d717b234033b80995891c06116d244"
)


STEP_CA_IMAGE = (
    "smallstep/step-ca:0.30.2"
    "@sha256:a2b17872915c193259b75a5474c398326f41bd199f0842093e52cf4182bc8270"
)


def definition_hash(service: str, version: int = 1) -> str:
    """A `docker compose config --hash` value: 64 hex digits per service definition."""
    return hashlib.sha256(f"{service} v{version}".encode()).hexdigest()


def resolved_configuration() -> dict:
    def volume(name: str) -> list[dict]:
        return [{"type": "volume", "source": name, "target": "/data"}]

    return {
        "services": {
            "socket-proxy": {"image": SOCKET_PROXY_IMAGE, "restart": "unless-stopped"},
            "traefik": {
                "image": TRAEFIK_IMAGE,
                "restart": "unless-stopped",
                "environment": {"EDGE_DOMAIN": "probe.test"},
                "depends_on": {"socket-proxy": {"condition": "service_started", "required": True}},
            },
            "hello": {
                "image": IMAGE,
                "profiles": ["probe"],
                "labels": {"traefik.enable": "true", "edge.name": "hello"},
            },
            "keycloak": {
                "image": KEYCLOAK_IMAGE,
                "restart": "unless-stopped",
                "profiles": ["keycloak"],
            },
            "step-ca": {
                "image": STEP_CA_IMAGE,
                "restart": "unless-stopped",
                "profiles": ["step-ca"],
                "volumes": volume("step-ca"),
            },
            "traefik-mcp-acme-owner": {
                "image": TRAEFIK_IMAGE,
                "restart": "no",
                "profiles": ["step-ca"],
                "volumes": volume("traefik-mcp-acme"),
            },
            "traefik-mcp": {
                "image": TRAEFIK_IMAGE,
                "restart": "unless-stopped",
                "profiles": ["step-ca"],
                "volumes": volume("traefik-mcp-acme"),
                "depends_on": {
                    "traefik-mcp-acme-owner": {"condition": "service_completed_successfully"}
                },
            },
        }
    }


@dataclass
class ScriptedKeys:
    """The key step's one-off: its read reports `rows` (app -> its live key's settings, None when
    absent), the apps whose name another key holds, `budget`, `models` and, when asked for the
    admin group's members, `admin_budget` with each member's row of `customers` and the rows on
    the admin budget that are no member's; its write makes each change into them in turn until
    the change at `fail_at`, which fails with `cause`, so the next plan sees what the run made."""

    rows: dict[str, dict | None] = field(default_factory=dict)
    taken: set[str] = field(default_factory=set)
    budget: dict | None = None
    models: tuple[str, ...] = ("text/opus", "text/sonnet")
    admin_budget: dict | None = None
    customers: dict[str, dict] = field(default_factory=dict)  # fingerprint -> budget_id, spend
    read_fails: bool = False
    fail_at: int | None = None
    cause: str = "status 500"
    writes: list[list[dict]] = field(default_factory=list)  # each write's changes, from stdin

    def run(
        self, command: list[str], arguments: list[str], stdin: str | None
    ) -> subprocess.CompletedProcess[str]:
        if "--read" in arguments:
            if self.read_fails:
                failure = "litellm-keys: status 502 at /v2/key/info\n"
                return subprocess.CompletedProcess(command, 1, "", failure)
            answer = self.read(json.loads(stdin or ""))
            return subprocess.CompletedProcess(command, 0, json.dumps(answer), "")
        changes = json.loads(stdin or "")
        self.writes.append(changes)
        return subprocess.CompletedProcess(command, 0, json.dumps(self.write(changes)), "")

    def read(self, asked: dict | None) -> dict:
        apps = {
            app: {"key": row, "name_taken": app in self.taken} for app, row in self.rows.items()
        }
        found = {"apps": apps, "budget": self.budget, "models": list(self.models)}
        return found | {"admin": None if asked is None else self.admin_rows(asked["members"])}

    def admin_rows(self, members: list[str]) -> dict:
        others = (
            {"fingerprint": fingerprint, "spend": row["spend"]}
            for fingerprint, row in self.customers.items()
            if row["budget_id"] == ADMIN_BUDGET_ID and fingerprint not in members
        )
        return {
            "budget": self.admin_budget,
            "members": [self.customers.get(member) for member in members],
            "others": list(others),
        }

    def write(self, changes: list[dict]) -> list[dict]:
        outcomes = []
        for index, change in enumerate(changes):
            named = {"target": change["target"], "subject": change["subject"]}
            if self.fail_at is not None and index > self.fail_at:
                outcomes.append(named | {"outcome": "not made"})
            elif index == self.fail_at:
                outcomes.append(named | {"outcome": "failed", "cause": self.cause})
            else:
                self.make(change)
                outcomes.append(named | {"outcome": "done"})
        return outcomes

    def make(self, change: dict) -> None:
        if change["target"] == "customer":
            row = self.customers.setdefault(change["subject"], {"spend": 0.0})
            row["budget_id"] = change["fields"]["budget_id"]
        elif change["subject"] == ADMIN_BUDGET_ID:
            self.admin_budget = (self.admin_budget or {}) | change["fields"]
        elif change["target"] == "budget":
            self.budget = (self.budget or {}) | change["fields"]
        else:
            self.rows[change["subject"]] = (self.rows[change["subject"]] or {}) | change["fields"]


@dataclass
class ScriptedCompose:
    """Compose over a table of service -> container state; records every call.

    Each service has a definition hash, as `config --hash` answers it, and each container the
    hash it was created from as its config-hash label and the image it was created from as its
    `Image`; a container put in directly carries the current ones. Like Compose, `up` recreates a
    container whose label differs from its service's hash (it gets a new id) unless
    `--no-recreate` is given, and always with `--force-recreate`. Edge never takes a project down
    or renews its volumes, so `down`, `-v` and `--renew-anon-volumes` fail the test that runs them
    (#85 P13, cell U14, #87 D15)."""

    containers: dict[str, str] = field(default_factory=dict)
    container_ids: dict[str, int] = field(default_factory=dict)
    definitions: dict[str, str] = field(default_factory=dict)  # service -> hash, if not v1
    labels: dict[str, str | None] = field(default_factory=dict)  # service -> its container's
    # service -> the image its container was created from; None: its ps line names no `Image`
    images: dict[str, str | None] = field(default_factory=dict)
    # reference -> the id Docker gives it now, if not the one of OTHER_LABELS' image label; "" is a
    # tag that is not built (`image ls` answers nothing), None a lookup that exits 1
    image_ids: dict[str, str | None] = field(default_factory=dict)
    hash_answer: str | None = None  # what `config --hash` answers instead of the hashes
    containers_created: int = 0
    volumes: dict[str, str] = field(default_factory=dict)  # volume key -> what it holds
    failing_verb: str | None = None
    failure_line: str = "last line"  # the last line a failing verb writes
    # `up` creates a new container of these but cannot start it: it stays created, `up` exits 1
    unstartable: set[str] = field(default_factory=set)
    starts_nothing: bool = False
    after_up: Callable[[], None] | None = None  # what changes in the world once `up` returned
    # a container of these dies right after `up` starts it and Docker restarts it: the first `ps`
    # after the `up` still sees it running, every later one restarting
    crash_loops: set[str] = field(default_factory=set)
    just_started: set[str] = field(default_factory=set)
    calls: list[list[str]] = field(default_factory=list)
    config: dict = field(default_factory=lambda: {"name": "edge", **resolved_configuration()})
    realm_checksums: dict = field(default_factory=lambda: {"master": {}, "hallucinai": {}})
    realm_applies: int = 0  # how often config-cli ran
    config_cli_fails: bool = False
    keys: ScriptedKeys = field(default_factory=ScriptedKeys)
    # the observer's members mode: hallucinai's issuer and the group's members; None: no group
    realm_issuer: str = "https://auth.edge-fixture.invalid/realms/hallucinai"
    realm_members: list[str] | None = field(default_factory=list)

    def run(
        self, command: list[str], _timeout: int, stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        if command[:2] == ["docker", "image"]:
            image_id = self.image_ids.get(command[-1].removeprefix("reference="), LABELLED_IMAGE_ID)
            return subprocess.CompletedProcess(command, int(image_id is None), image_id or "", "")
        self.calls.append(command[PROJECT_PREFIX:])
        _, profile, verb, *arguments = command[PROJECT_PREFIX:]
        refused = NEVER_RUN & {verb, *arguments}
        assert not refused, f"edge ran docker compose {verb} {' '.join(arguments)}"
        if verb == self.failing_verb:
            return subprocess.CompletedProcess(
                command, 1, "", f"{verb} broke\n{self.failure_line}\n\n"
            )
        if verb == "run" and KEYS_SERVICE in arguments:
            return self.keys.run(command, arguments, stdin)
        if verb == "run" and "--members" in arguments:
            return self.members(command, arguments[-1])
        if verb == "run" and self.config_cli_fails and "realm-observer" not in arguments:
            return subprocess.CompletedProcess(command, 1, "", "config-cli broke\n")
        output = getattr(self, f"verb_{verb}")(profile, arguments)
        if verb == "up" and self.unstartable & set(arguments):
            return subprocess.CompletedProcess(command, 1, output, "up broke\ncannot start")
        return subprocess.CompletedProcess(command, 0, output, "")

    def members(self, command: list[str], group: str) -> subprocess.CompletedProcess[str]:
        if self.realm_members is None:
            failure = f"realm-observer: hallucinai has no group {group}\n"
            return subprocess.CompletedProcess(command, 1, "", failure)
        answer = {"issuer": self.realm_issuer, "members": self.realm_members}
        return subprocess.CompletedProcess(command, 0, json.dumps(answer), "")

    def verb_config(self, _profile: str, arguments: list[str]) -> str:
        if arguments[0] != "--hash":
            return json.dumps(self.config)
        if self.hash_answer is not None:
            return self.hash_answer
        return "".join(
            f"{service} {self.definition(service)}\n" for service in arguments[1].split(",")
        )

    def verb_ps(self, _profile: str, _arguments: list[str]) -> str:
        output = "\n".join(
            json.dumps(self.ps_line(service, state)) for service, state in self.containers.items()
        )
        for service in self.just_started & self.crash_loops:
            self.containers[service] = "restarting"
        self.just_started.clear()
        return output

    def verb_run(self, _profile: str, arguments: list[str]) -> str:
        """The realm's one-off containers: the observer's two answers and config-cli's run."""
        if "realm-observer" not in arguments:
            self.realm_applies += 1
            return ""
        if "--import-checksums" in arguments:
            return json.dumps(self.realm_checksums)
        return json.dumps({"hallucinai": {}})

    def verb_up(self, _profile: str, arguments: list[str]) -> str:
        if self.starts_nothing:
            return ""
        one_shots = compose.one_shot_services(self.config)
        flags = {argument for argument in arguments if argument.startswith("-")}
        for service in (argument for argument in arguments if argument not in flags):
            if self.containers.get(service) == "restarting" and "--no-recreate" in flags:
                continue  # Docker leaves a container that restarts in a loop as it is
            if self.needs_a_new_container(service, flags):
                self.create_container(service)
            if service in self.unstartable:
                self.containers[service] = "created"
                continue
            self.containers[service] = "exited" if service in one_shots else "running"
            self.just_started.add(service)
            for volume in compose.named_volumes(self.config["services"][service]):
                self.volumes.setdefault(volume, "created by up")
        if self.after_up:
            self.after_up()
        return ""

    def ps_line(self, service: str, state: str) -> dict:
        line = {"Service": service, "State": state, "ExitCode": 0}
        if (image := self.image_of(service)) is not None:
            line["Image"] = image
        return line | {"Labels": self.labels_of(service)}

    def definition(self, service: str) -> str:
        return self.definitions.get(service, definition_hash(service))

    def configured_image(self, service: str) -> str | None:
        return self.config["services"][service].get("image")

    def image_of(self, service: str) -> str | None:
        return self.images.get(service, self.configured_image(service))

    def change_image(self, service: str, reference: str) -> None:
        """compose.yaml now names another image for the service, which changes its definition as
        in Compose; its container keeps the image it was created from."""
        if service in self.containers:
            self.images[service] = self.image_of(service)
        self.config["services"][service]["image"] = reference
        self.definitions[service] = hashlib.sha256(f"{service} {reference}".encode()).hexdigest()

    def change_definition(self, service: str) -> None:
        """The checkout now defines the service otherwise than its container was created."""
        self.definitions[service] = definition_hash(service, version=2)

    def labels_of(self, service: str) -> str:
        config_hash = self.labels.get(service, self.definition(service))
        if config_hash is None:
            return OTHER_LABELS
        return f"{OTHER_LABELS},com.docker.compose.config-hash={config_hash}"

    def create_container(self, service: str) -> None:
        self.containers_created += 1
        self.container_ids[service] = self.containers_created
        self.labels[service] = self.definition(service)
        self.images[service] = self.configured_image(service)

    def put_containers(self, states: dict[str, str]) -> None:
        """Containers that exist before the command, each with its own id."""
        for service, container_state in states.items():
            self.create_container(service)
            self.containers[service] = container_state

    def needs_a_new_container(self, service: str, flags: set[str]) -> bool:
        if service not in self.containers or "--force-recreate" in flags:
            return True
        changed = self.labels.get(service, self.definition(service)) != self.definition(service)
        return changed and "--no-recreate" not in flags

    def verb_stop(self, _profile: str, arguments: list[str]) -> str:
        for service in arguments:
            if self.containers.get(service) == "running":
                self.containers[service] = "exited"
        return ""

    def verb_rm(self, _profile: str, arguments: list[str]) -> str:
        for service in arguments[1:]:
            self.containers.pop(service, None)
            self.container_ids.pop(service, None)
            self.labels.pop(service, None)
            self.images.pop(service, None)
        return ""

    def changing_verbs(self) -> list[str]:
        return [call[2] for call in self.calls if call[2] not in {"config", "ps"}]


@dataclass
class RealmBackup:
    """hal as the realm step calls it: what it was asked, and the part that fails."""

    asked: list[str] = field(default_factory=list)
    failing: str | None = None

    def pre_apply(self) -> str:
        return self._ask("backup")

    def restore_test(self, snapshot: str) -> None:
        assert snapshot == "ab12cd34"
        self._ask("restore test")

    def _ask(self, part: str) -> str:
        self.asked.append(part)
        if part == self.failing:
            raise reconcile.RealmError(f"{part} broke")
        return "ab12cd34"


@dataclass
class Setup:
    """The scripted `<setup> --check`: its exit code and line."""

    exit_code: int = 0
    line: str = "step-ca/init --check: set up"
    commands: list[list[str]] = field(default_factory=list)
    failing_command: str | None = None  # this command's check exits 1, whatever `exit_code` says

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.commands.append(command)
        if self.failing_command and command[0].endswith(self.failing_command):
            return subprocess.CompletedProcess(
                command, 1, f"{self.failing_command}: not set up", ""
            )
        return subprocess.CompletedProcess(command, self.exit_code, self.line, "")


@dataclass
class SetupRun:
    """The scripted run of a setup in the terminal: a successful run makes `--check` pass."""

    checks: Setup
    exit_code: int = 0
    interrupted: bool = False
    cannot_start: bool = False
    check_afterwards: tuple[int, str] = (0, "step-ca/init --check: set up")
    commands: list[tuple[Path, Path]] = field(default_factory=list)
    meanwhile: Callable[[], None] | None = None  # what changes while the setup runs

    def __call__(self, command: Path, working_directory: Path) -> setup.SetupRun:
        self.commands.append((command, working_directory))
        if self.meanwhile:
            self.meanwhile()
        if self.cannot_start:
            raise PermissionError("not executable")
        if self.exit_code == 0 and not self.interrupted:
            self.checks.exit_code, self.checks.line = self.check_afterwards
        return setup.SetupRun(self.exit_code, self.interrupted)


class Terminal(io.StringIO):
    """A terminal; `while_prompt_waits` runs when the operator's answer is read, which it echoes."""

    while_prompt_waits: Callable[[], None] | None = None

    def isatty(self) -> bool:
        return True

    def readline(self, *arguments) -> str:
        if self.while_prompt_waits:
            self.while_prompt_waits()
        answer = super().readline(*arguments)
        sys.stdout.write(answer)  # the terminal echoes what the operator typed
        return answer


class InterruptedWaitForLock(switches.Switches):
    """Switches whose lock is taken by a Ctrl-C while it waits."""

    def lock(self):
        raise KeyboardInterrupt


@dataclass
class Ingress:
    """Traefik as the barrier tests see it: it answers a marked 404 for `hello` while the unit's
    barrier file is in `dynamic/`; a file it is `rejecting` leaves its plain no-route 404; `down`
    refuses the connection. Time is a counter."""

    repository: Path
    rejecting: bool = False
    down: bool = False
    asked: list[str] = field(default_factory=list)  # what the world looked like at each request
    on_fetch: Callable[[], None] | None = None  # a look at the world as each request arrives
    now: float = 0.0

    def barrier_file(self) -> Path:
        return self.repository / "dynamic" / "switch-probe.yml"

    def fetch(
        self, _address: str, _host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        self.asked.append("barrier" if self.barrier_file().exists() else "no barrier")
        if self.on_fetch:
            self.on_fetch()
        if self.down:
            raise ConnectionRefusedError
        if not self.barrier_file().exists():
            return WHOAMI
        return PLAIN_NOT_FOUND if self.rejecting else NOT_FOUND

    def sleep(self, seconds: float) -> None:
        self.now += seconds

    @property
    def verifier(self) -> barrier.Verifier:
        return barrier.Verifier(self.fetch, lambda: self.now, self.sleep)

    @property
    def watch(self) -> compose.Watch:
        """How a recreated Traefik is watched, on the same counter."""
        return compose.Watch(lambda: self.now, self.sleep)


SCRIPTED_SHA = b"5" * 40


@dataclass
class ScriptedGit:
    """Git as the guards and the fetch ask it: a clean `main` equal to origin's unless told
    otherwise; the fetch raises `fetch_error` when one is set; `calls` records each. HEAD tracks
    each path `ls-tree` is asked about as the tree holds it, a directory or else a file."""

    reference: bytes = b"refs/heads/main\n"
    status: bytes = b""
    fetch_error: Exception | None = None
    calls: list[list[str]] = field(default_factory=list)

    def __call__(
        self, tree: Path, arguments: list[str], _profile: checkout.Profile
    ) -> subprocess.CompletedProcess[bytes]:
        self.calls.append(list(arguments))
        verb = next(argument for argument in arguments if not argument.startswith("-"))
        if verb == "fetch" and self.fetch_error:
            raise self.fetch_error
        stdout = {
            "symbolic-ref": self.reference,
            "rev-parse": SCRIPTED_SHA,
            "status": self.status,
            "fetch": b"",
            "rev-list": b"0\t0\n",
        }.get(verb)
        if stdout is None:
            stdout = self._listing(tree, arguments)
        return subprocess.CompletedProcess(arguments, 0, stdout, b"")

    def _listing(self, tree: Path, arguments: list[str]) -> bytes:
        return "".join(
            f"{'040000 tree' if (tree / path).is_dir() else '100644 blob'} {'0' * 40}\t{path}\0"
            for path in arguments[arguments.index("--") + 1 :]
        ).encode()
