"""step-ca/init and step-ca/ca.json against a scripted Docker host: no containers.

The key material is generated at run time; nothing PEM-shaped is committed (the quality gate scans
the history for secrets).
"""

import hashlib
import json
import os
import secrets as random_secrets
import signal
import stat
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
from support.script_module import loaded_script

STEP_CA = Path(__file__).resolve().parents[1] / "step-ca"
PROBE = Path(__file__).resolve().parents[1] / "probe" / "step-ca" / "probe.py"
IMAGE = "smallstep/step-ca:0.30.2@sha256:" + "ab" * 32
PROJECT = "operators-project"
VOLUME = f"{PROJECT}_step-ca"
ACME_VOLUME = f"{PROJECT}_traefik-mcp-acme"
PRIVATE_KEY_HEADER = "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----"
ROOT_KEY, ROOT_CERT, PASSWORD = "root_ca_key", "root_ca.crt", "password"
INTERMEDIATE_FILES = {"certs/intermediate_ca.crt", "secrets/intermediate_ca_key"}


@pytest.fixture(scope="module")
def init_module() -> Iterator[ModuleType]:
    yield from loaded_script("step_ca_init", STEP_CA / "init")


@dataclass
class DockerHost:
    """Docker with the step-ca image: runs the one-off containers' tools on two host directories."""

    secrets_dir: Path
    volume_dir: Path
    commands: list[list[str]] = field(default_factory=list)
    failing_tool: str | None = None
    failure_text: str = ""
    volumes: dict[str, dict[str, str]] = field(default_factory=dict)  # name -> labels

    def container_path(self, command: list[str], path: str) -> Path:
        for index, argument in enumerate(command):
            if argument == "--volume":
                source, target = command[index + 1].split(":")[:2]
                host = Path(source) if source.startswith("/") else self.volume_dir
                if path == target or path.startswith(target + "/"):
                    return host / path.removeprefix(target).lstrip("/")
        return self.volume_dir / path  # relative to --workdir /home/step

    @staticmethod
    def done(stdout: str = "", returncode: int = 0, stderr: str = ""):
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    @staticmethod
    def entrypoint(command: list[str]) -> str:
        return command[command.index("--entrypoint") + 1]

    def run(self, command: list[str], _timeout: int):
        self.commands.append(command)
        if command[1] == "compose":
            if self.failing_tool == "compose":
                return self.done(returncode=1, stderr=self.failure_text)
            config = {
                "name": PROJECT,
                "services": {"step-ca": {"image": IMAGE}},
                "volumes": {"step-ca": {"name": VOLUME}, "traefik-mcp-acme": {"name": ACME_VOLUME}},
            }
            return self.done(json.dumps(config))
        if command[1:3] == ["volume", "inspect"]:
            if self.failing_tool == "volume inspect":
                return self.done(returncode=1, stderr=self.failure_text)
            if command[-1] in self.volumes:
                return self.done("[]")
            return self.done(
                returncode=1,
                stderr=f"Error response from daemon: get {command[-1]}: no such volume",
            )
        if command[1] == "volume":
            self.volumes[command[-1]] = dict(
                argument.split("=", 1) for argument in command[2:-1] if "=" in argument
            )
            return self.done()
        tool = self.entrypoint(command)
        arguments = command[command.index(IMAGE) + 1 :]
        if tool == self.failing_tool:
            return self.done(returncode=1, stderr=self.failure_text)
        return getattr(self, f"tool_{tool}")(command, arguments)

    def tool_find(self, command: list[str], _arguments: list[str]):
        files = (path for path in self.volume_dir.rglob("*") if path.is_file())
        return self.done("\n".join(f"/home/step/{p.relative_to(self.volume_dir)}" for p in files))

    def tool_mkdir(self, command: list[str], arguments: list[str]):
        for directory in arguments[1:]:
            self.container_path(command, directory).mkdir(parents=True, exist_ok=True)
        return self.done()

    def tool_cp(self, command: list[str], arguments: list[str]):
        source, target = (self.container_path(command, path) for path in arguments)
        target.write_bytes(source.read_bytes())
        return self.done()

    def tool_step(self, command: list[str], arguments: list[str]):
        """`step certificate create`: refuses to overwrite and checks the passwords like step."""
        _, _, name, certificate, key, *options = arguments
        certificate, key = (
            self.container_path(command, certificate),
            self.container_path(command, key),
        )
        flags = dict(zip(options[::2], options[1::2], strict=True))
        if certificate.exists() or key.exists():
            return self.done(returncode=1, stderr="file already exists, use --force to overwrite")
        password = self.container_path(command, flags["--password-file"]).read_text()
        if "--ca-key" in flags:
            ca_key = self.container_path(command, flags["--ca-key"]).read_text()
            ca_password = self.container_path(command, flags["--ca-password-file"]).read_text()
            if self.key_fingerprint(ca_password) not in ca_key:
                return self.done(returncode=1, stderr="error decrypting the root key")
        certificate.write_text(f"certificate of {name}\n")
        key.write_text(
            f"{PRIVATE_KEY_HEADER}\n{self.key_fingerprint(password)}\n{random_secrets.token_hex(16)}\n"
        )
        key.chmod(0o600)
        return self.done()

    @staticmethod
    def key_fingerprint(password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()


@pytest.fixture
def secrets_dir(tmp_path: Path) -> Path:
    return tmp_path / ".secrets" / "step-ca"


@pytest.fixture
def docker(tmp_path: Path, secrets_dir: Path) -> DockerHost:
    volume_dir = tmp_path / "volume"
    volume_dir.mkdir()
    secrets_dir.parent.mkdir()
    return DockerHost(secrets_dir, volume_dir)


class Session:
    def __init__(self) -> None:
        self.printed: list[str] = []
        self.uid = 1000

    @property
    def output(self) -> str:
        return "\n".join(self.printed)


@pytest.fixture
def session() -> Session:
    return Session()


@pytest.fixture
def make_init(init_module, docker: DockerHost, session: Session, secrets_dir: Path):
    tools = init_module.Tools(
        run=docker.run, say=session.printed.append, host_uid=lambda: session.uid
    )
    return lambda read_only, at=secrets_dir: init_module.StepCaInit(tools, at, read_only=read_only)


@pytest.fixture
def init(make_init):
    return make_init(read_only=False)


@pytest.fixture
def check(make_init):
    return make_init(read_only=True).check


def mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def volume_files(docker: DockerHost) -> set[str]:
    return {
        str(p.relative_to(docker.volume_dir)) for p in docker.volume_dir.rglob("*") if p.is_file()
    }


def fingerprint_of_files(directory: Path) -> dict[str, bytes]:
    return {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    }


def test_a_fresh_run_makes_the_files_with_their_modes(init, docker, secrets_dir, session):
    """#38 rule 3 / proof 1: the files and their modes."""
    assert init.run() == 0

    assert mode(secrets_dir) == 0o700
    assert mode(secrets_dir / ROOT_KEY) == 0o600
    assert mode(secrets_dir / ROOT_CERT) == 0o644
    assert mode(secrets_dir / PASSWORD) == 0o644
    assert volume_files(docker) == INTERMEDIATE_FILES | {"certs/root_ca.crt"}
    assert not (secrets_dir / ".pending-root").exists()
    assert "`hal apply` starts step-ca while the catalog enables it." in session.output


def test_the_output_holds_neither_the_password_nor_a_private_key(
    init, docker, secrets_dir, session
):
    """#38 rule 3 / proof 1: nothing secret is printed."""
    init.run()
    init.run()

    assert (secrets_dir / PASSWORD).read_text() not in session.output
    assert "PRIVATE KEY" not in session.output


def test_the_root_key_is_never_written_into_the_volume(init, docker, secrets_dir):
    """#38 rule 3 / proof 3: the root key stays out of the volume."""
    init.run()

    root_key = (secrets_dir / ROOT_KEY).read_bytes()
    assert root_key not in fingerprint_of_files(docker.volume_dir).values()


def test_every_container_runs_without_a_network_from_the_composed_image(init, docker):
    """#38 rule 3: one-off containers have no network and use the pinned image."""
    init.run()

    runs = [command for command in docker.commands if command[1] == "run"]
    assert runs
    assert all(command[command.index("--network") + 1] == "none" for command in runs)
    assert all(command[command.index("--log-driver") + 1] == "none" for command in runs)
    assert all(IMAGE in command for command in runs)
    assert all(not argument.startswith("DOCKER_STEPCA_INIT") for c in runs for argument in c)


def test_the_intermediate_is_made_with_the_password_of_the_root(init, docker, secrets_dir):
    """#38 rule 3: one password protects root and intermediate."""
    init.run()

    key = (docker.volume_dir / "secrets/intermediate_ca_key").read_text()
    password = (secrets_dir / PASSWORD).read_text()
    assert key.count(docker.key_fingerprint(password)) == 1


def test_a_second_run_changes_nothing(init, docker, secrets_dir, session):
    """#38 rule 3 / proof 1: a second run changes nothing."""
    init.run()
    before = (fingerprint_of_files(secrets_dir), fingerprint_of_files(docker.volume_dir))
    first_run_commands = len(docker.commands)
    session.printed.clear()

    assert init.run() == 0

    assert fingerprint_of_files(secrets_dir) == before[0]
    assert fingerprint_of_files(docker.volume_dir) == before[1]
    changing = {"mkdir", "cp", "step"}
    assert not changing & {
        docker.entrypoint(c) for c in docker.commands[first_run_commands:] if c[1] == "run"
    }
    assert session.printed == ["step-ca/init: nothing changed, the key material is all in place."]


def test_a_partial_state_with_a_root_gets_its_intermediate_and_keeps_the_root_key(
    init, docker, secrets_dir
):
    """#38 rule 3 / proof 5: a partial state is completed, the root key kept."""
    init.run()
    for path in (docker.volume_dir / "certs").iterdir():
        path.unlink()
    for path in (docker.volume_dir / "secrets").iterdir():
        path.unlink()
    root_key = (secrets_dir / ROOT_KEY).read_bytes()

    assert init.run() == 0

    assert (secrets_dir / ROOT_KEY).read_bytes() == root_key
    assert volume_files(docker) == INTERMEDIATE_FILES | {"certs/root_ca.crt"}


def test_a_missing_root_copy_in_the_volume_is_copied_without_touching_the_intermediate(
    init, docker, secrets_dir
):
    """#38 rule 3: a missing piece is completed, nothing else is touched."""
    init.run()
    (docker.volume_dir / "certs/root_ca.crt").unlink()
    intermediate = (docker.volume_dir / "secrets/intermediate_ca_key").read_bytes()

    assert init.run() == 0

    restored_root = (docker.volume_dir / "certs/root_ca.crt").read_bytes()
    assert restored_root == (secrets_dir / ROOT_CERT).read_bytes()
    assert (docker.volume_dir / "secrets/intermediate_ca_key").read_bytes() == intermediate


@pytest.mark.parametrize("lost", ["certs/intermediate_ca.crt", "secrets/intermediate_ca_key"])
def test_half_an_intermediate_is_refused_and_nothing_is_overwritten(
    init, docker, secrets_dir, session, lost
):
    """#38 rule 3: never overwrite an existing key."""
    init.run()
    (docker.volume_dir / lost).unlink()
    before = fingerprint_of_files(docker.volume_dir)

    assert init.run() == 1

    assert fingerprint_of_files(docker.volume_dir) == before
    assert "FAILED at intermediate" in session.printed[-1]


@pytest.mark.parametrize("lost", [ROOT_KEY, ROOT_CERT])
def test_half_a_root_is_refused_by_name_and_the_survivor_is_untouched(
    init, docker, secrets_dir, session, lost
):
    """#38 rule 3: never overwrite an existing key."""
    init.run()
    (secrets_dir / lost).unlink()
    survivor = ROOT_CERT if lost == ROOT_KEY else ROOT_KEY
    content = (secrets_dir / survivor).read_bytes()

    assert init.run() == 1

    assert (secrets_dir / survivor).read_bytes() == content
    assert session.printed[-1].count(survivor) == 1
    assert "restore" in session.printed[-1]


def test_a_missing_password_next_to_a_root_key_is_refused_and_not_replaced(
    init, secrets_dir, session
):
    """#38 rule 3: never overwrite an existing key."""
    init.run()
    (secrets_dir / PASSWORD).unlink()

    assert init.run() == 1

    assert not (secrets_dir / PASSWORD).exists()
    assert "restore password" in session.printed[-1]


def test_a_volume_with_an_intermediate_but_no_root_does_not_get_a_new_root(
    init, docker, secrets_dir, session
):
    """defect:#38 PR 39 finding 1: a refusal comes before any write."""
    init.run()
    for name in (ROOT_KEY, ROOT_CERT, PASSWORD):
        (secrets_dir / name).unlink()
    session.printed.clear()

    assert init.run() == 1

    assert sorted(p.name for p in secrets_dir.iterdir()) == []
    assert "FAILED at password" in session.printed[-1]


def test_a_lone_root_certificate_without_password_is_refused_before_any_write(
    init, secrets_dir, session
):
    """defect:#38 PR 39 finding 1: a restored root must meet its own password."""
    init.run()
    for name in (ROOT_KEY, PASSWORD):
        (secrets_dir / name).unlink()
    content = (secrets_dir / ROOT_CERT).read_bytes()

    assert init.run() == 1

    assert sorted(p.name for p in secrets_dir.iterdir()) == [ROOT_CERT]
    assert (secrets_dir / ROOT_CERT).read_bytes() == content
    assert "restore password" in session.printed[-1]


def test_an_empty_password_file_is_refused(init, secrets_dir, session):
    """#38 rule 3: an empty password is no password; a key is never made under it."""
    init.run()
    (secrets_dir / PASSWORD).write_text("")

    assert init.run() == 1

    assert "password is empty" in session.printed[-1]


def test_a_root_pair_cut_between_its_two_renames_is_finished_without_a_new_key(init, secrets_dir):
    """defect:#38 PR 39 finding 7: an interrupted run resumes; the key is not replaced."""
    init.run()
    pending = secrets_dir / ".pending-root"
    pending.mkdir()
    (secrets_dir / ROOT_CERT).rename(pending / ROOT_CERT)
    root_key = (secrets_dir / ROOT_KEY).read_bytes()
    root_certificate = (pending / ROOT_CERT).read_bytes()

    assert init.run() == 0

    assert (secrets_dir / ROOT_KEY).read_bytes() == root_key
    assert (secrets_dir / ROOT_CERT).read_bytes() == root_certificate
    assert not pending.exists()


def test_the_password_reaches_the_containers_only_through_run_secrets(init, docker, secrets_dir):
    """defect:#38 PR 39 finding 6: password only via /run/secrets."""
    init.run()

    runs = [c for c in docker.commands if c[1] == "run"]
    password_mounts = [a for c in runs for a in c if a.endswith("/run/secrets/password:ro")]
    assert password_mounts
    assert set(password_mounts) == {f"{secrets_dir / PASSWORD}:/run/secrets/password:ro"}
    assert not any("/secrets/password" in a and "/run" not in a for c in runs for a in c)


def test_the_volume_is_created_with_compose_labels_before_any_container_mounts_it(init, docker):
    """defect:#38 PR 39 finding 2: the backup finds the volume by its compose labels."""
    init.run()

    assert docker.volumes == {
        VOLUME: {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.volume": "step-ca",
        },
        ACME_VOLUME: {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.volume": "traefik-mcp-acme",
        },
    }
    first_mount = next(
        i for i, c in enumerate(docker.commands) if c[1] == "run" and VOLUME in " ".join(c)
    )
    created = next(i for i, c in enumerate(docker.commands) if c[1] == "volume")
    assert first_mount > created


@pytest.mark.parametrize(
    ("name", "wrong", "right"),
    [(ROOT_KEY, 0o644, 0o600), (ROOT_CERT, 0o600, 0o644), (PASSWORD, 0o600, 0o644)],
)
def test_a_file_with_the_wrong_mode_gets_its_mode_back(
    init, secrets_dir, session, name, wrong, right
):
    """#38 rule 3 / proof 1: modes are restored."""
    init.run()
    (secrets_dir / name).chmod(wrong)
    content = (secrets_dir / name).read_bytes()

    assert init.run() == 0

    assert mode(secrets_dir / name) == right
    assert (secrets_dir / name).read_bytes() == content
    assert "file modes" in session.output


def test_a_directory_with_the_wrong_mode_becomes_private(init, secrets_dir):
    """#38 rule 3 / proof 1: the directory becomes private."""
    init.run()
    secrets_dir.chmod(0o755)

    assert init.run() == 0

    assert mode(secrets_dir) == 0o700


def test_a_failing_tool_shows_one_line_without_the_password_or_a_key(
    init, docker, secrets_dir, session
):
    """#38 rule 3: a failure is one scrubbed line."""
    init.run()
    for relative in INTERMEDIATE_FILES:
        (docker.volume_dir / relative).unlink()
    password = (secrets_dir / PASSWORD).read_text()
    docker.failing_tool = "step"
    docker.failure_text = f"first line\nbad password {password}"

    assert init.run() == 1

    assert session.printed[-1].endswith("bad password ***")
    docker.failure_text = f"{PRIVATE_KEY_HEADER}"
    session.printed.clear()
    assert init.run() == 1
    assert "PRIVATE KEY" not in session.output


@pytest.mark.parametrize(("read_only", "exit_code"), [(False, 1), (True, 2)])
def test_another_user_than_the_images_is_refused_before_anything_is_made(
    make_init, secrets_dir, session, read_only, exit_code
):
    """#38 rule 3, #52 rule 8: the image's user must run the tool; --check cannot tell (2)."""
    session.uid = 1001
    init = make_init(read_only=read_only)

    assert (init.check() if read_only else init.run()) == exit_code
    assert not secrets_dir.exists()
    assert "uid 1000" in session.printed[-1]


def test_a_docker_failure_while_reading_compose_is_one_line(init, docker, session):
    """#38 rule 3: a failure is one scrubbed line."""
    docker.failing_tool = "compose"
    docker.failure_text = "no docker daemon"

    assert init.run() == 1

    assert session.printed[-1].endswith("`docker compose config` exited 1: no docker daemon")


@pytest.mark.parametrize(
    ("read_only", "exit_code", "last_line"),
    [
        (True, 2, "unexpected answer at secrets directory (KeyError)"),
        (False, 1, "step-ca/init FAILED at secrets directory: unexpected answer (KeyError)"),
    ],
)
def test_an_unexpected_exception_is_one_line_in_both_modes(
    make_init, session, read_only, exit_code, last_line
):
    """#628 cell 5: --check says the fact bare with its step, a plain run prints as before."""
    init = make_init(read_only, SimpleNamespace(is_dir=lambda: {}[0]))

    assert (init.check() if read_only else init.run()) == exit_code
    assert session.printed[-1] == last_line


# --- ca.json: the one config owner (#38 rule 2) -----------------------------------------------


@pytest.fixture(scope="module")
def ca_config() -> dict:
    return json.loads((STEP_CA / "ca.json").read_text())


def test_the_ca_has_one_acme_provisioner_without_its_own_policy(ca_config):
    """#38 rule 2: policy on the authority only."""
    provisioners = ca_config["authority"]["provisioners"]
    assert [provisioner["type"] for provisioner in provisioners] == ["ACME"]
    assert not [p for p in provisioners if "policy" in p]


def test_the_ca_allows_only_wildcards_under_never_public_names(ca_config):
    """#38 rule 2: `*.` under a never-public name (ICANN, RFC 6761/6762)."""
    never_public = {"internal", "test", "invalid", "localhost", "local"}
    allowed = ca_config["authority"]["policy"]["x509"]["allow"]["dns"]
    assert allowed
    assert all(pattern.startswith("*.") for pattern in allowed)
    assert all(pattern.rsplit(".", 1)[-1] in never_public for pattern in allowed)


def test_the_ca_has_no_remote_management(ca_config):
    """#38 rule 2: no admin API, no insecure listener."""
    assert not ca_config["authority"].get("enableAdmin")
    assert "insecureAddress" not in ca_config or not ca_config["insecureAddress"]


@pytest.fixture(scope="module")
def probe() -> Iterator[ModuleType]:
    yield from loaded_script("step_ca_probe", PROBE)


@pytest.mark.parametrize("stop_signal", ["TERM", "INT"])
def test_teardown_finishes_when_a_stop_signal_arrives_during_cleanup(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    stop_signal: str,
) -> None:
    """defect:#38 PR 39 round-2 finding 2: teardown finishes when SIGTERM or Ctrl-C hits cleanup."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    down_finished = tmp_path / "down-finished"
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f'  *" down "*) kill -{stop_signal} $PPID; touch "{down_finished}" ;;\n'
        f"  *\" config \"*) echo '{json.dumps({'name': probe.PROJECT})}' ;;\n"
        "  ps*|volume*|network*) ;;\n"
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")
    handlers_before = {
        number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)
    }

    (tmp_path / "scratch").mkdir()
    try:
        exit_code = probe.main(["--scratch", str(tmp_path / "scratch")])
    finally:
        for number, handler in handlers_before.items():
            signal.signal(number, handler)

    assert down_finished.exists()
    assert f"teardown: project {probe.PROJECT} removed" in capsys.readouterr().out
    assert exit_code == 1
    assert not any((tmp_path / "scratch").iterdir())


@pytest.mark.parametrize("stop_signal", [signal.SIGTERM, signal.SIGINT])
def test_teardown_commands_survive_a_stop_signal_to_the_probe_process_group(
    probe: ModuleType, tmp_path: Path, stop_signal: signal.Signals
) -> None:
    """defect:#38 PR 39 follow-up 1: cleanup commands run in their own session, so a signal to
    the probe's process group (Ctrl-C, timeout) cannot kill them half-way."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    down_finished = tmp_path / "down-finished"
    docker = bin_dir / "docker"
    docker.write_text(
        f"#!{sys.executable}\n"
        "import os, signal, sys\n"
        "args = ' '.join(sys.argv[1:]) + ' '\n"
        "if ' down ' in ' ' + args:\n"
        "    for number in (signal.SIGTERM, signal.SIGINT):\n"
        "        signal.signal(number, signal.SIG_DFL)  # Go resets SIGTERM like this\n"
        f"    os.killpg(os.getpgid(os.getppid()), {int(stop_signal)})\n"
        f"    open({str(down_finished)!r}, 'w').close()\n"
        "elif ' config ' in ' ' + args:\n"
        f"    print({json.dumps({'name': probe.PROJECT})!r})\n"
        "elif sys.argv[1:2] in (['ps'], ['network']) or sys.argv[1:3] == ['volume', 'ls']:\n"
        "    pass\n"
        "else:\n"
        "    sys.exit(1)\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)

    (tmp_path / "scratch").mkdir()
    probe_run = subprocess.run(
        [sys.executable, str(PROBE), "--scratch", str(tmp_path / "scratch")],
        env={**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=60,
        start_new_session=True,
        check=False,
    )

    assert down_finished.exists()
    assert "teardown: project edge-stepca-probe removed" in probe_run.stdout
    assert not any((tmp_path / "scratch").iterdir())


def fake_uv_on_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uv_script: str) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    uv = bin_dir / "uv"
    uv.write_text(f"#!/bin/sh\n{uv_script}\n")
    uv.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")


@pytest.mark.parametrize(
    ("uv_script", "findings"),
    [
        ("echo '{\"exposure\": []}'; exit 0", []),
        (
            'echo \'{"exposure": [{"kind": "listener"}]}\'; exit 1',
            [{"kind": "listener"}],
        ),
    ],
)
def test_the_probe_reads_the_exposure_findings(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    uv_script: str,
    findings: list,
) -> None:
    """#34 finding 19: the exposure findings are read from the JSON of `hal check exposure`."""
    fake_uv_on_path(tmp_path, monkeypatch, uv_script)

    assert probe.Probe(tmp_path / "scratch").exposure_findings() == findings


@pytest.mark.parametrize(
    "uv_script",
    [
        "echo 'no such command' >&2; exit 1",
        "echo 'not json'; exit 0",
        "echo '[]'; exit 0",
        "echo '{\"exposure\": []}'; exit 3",
    ],
)
def test_the_probe_fails_loud_when_the_exposure_check_cannot_run(
    probe: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, uv_script: str
) -> None:
    """defect:#48 proof (e): a missing exposure check is a failure, not 'no findings'."""
    fake_uv_on_path(tmp_path, monkeypatch, uv_script)

    scratch_probe = probe.Probe(tmp_path / "scratch")

    with pytest.raises(probe.ProbeFailed):
        scratch_probe.exposure_findings()


# --- step-ca/init --check: the setup contract of `hal apply` (#52 rule 8) ----------------------


def host_snapshot(docker: DockerHost, secrets_dir: Path) -> tuple[dict, dict, set]:
    return (
        fingerprint_of_files(secrets_dir.parent) if secrets_dir.parent.exists() else {},
        fingerprint_of_files(docker.volume_dir),
        set(docker.volumes),
    )


def test_check_passes_after_init_and_changes_nothing(init, check, docker, secrets_dir, session):
    """#52 rule 8: after init, --check exits 0 and changes nothing."""
    init.run()
    before = host_snapshot(docker, secrets_dir)
    init_commands = len(docker.commands)
    session.printed.clear()

    assert check() == 0

    assert host_snapshot(docker, secrets_dir) == before
    assert not {"mkdir", "cp", "step"} & {
        docker.entrypoint(c) for c in docker.commands[init_commands:] if c[1] == "run"
    }
    assert (secrets_dir / PASSWORD).read_text() not in session.output


def test_check_on_a_fresh_home_is_not_set_up_and_creates_nothing(
    check, docker, secrets_dir, session
):
    """#52 rule 8: a fresh home is exit 1 and --check creates no directory, file or volume."""
    assert check() == 1

    assert session.printed[-1] == "secrets directory is not done"
    assert "FAILED" not in session.output
    assert not secrets_dir.exists()
    assert docker.volumes == {}
    assert not [c for c in docker.commands if c[1:3] == ["volume", "create"]]


@pytest.mark.parametrize(
    ("deleted", "named"),
    [(None, "intermediate is not done"), (ACME_VOLUME, "ACME volume is not done")],
)
def test_check_without_a_volume_is_not_set_up_and_never_creates_it(
    init, check, docker, session, deleted, named
):
    """#52 rules 2 and 8: apply never creates a volume, so --check asks and names the gap."""
    init.run()
    kept = {} if deleted is None else {k: v for k, v in docker.volumes.items() if k != deleted}
    docker.volumes = dict(kept)
    session.printed.clear()

    assert check() == 1

    assert named in session.output
    assert docker.volumes == kept


def test_check_names_a_key_without_its_certificate_in_inits_own_words(
    init, check, secrets_dir, session
):
    """#52 rule 8: a broken partial state is exit 1 with init's own refusal line."""
    init.run()
    (secrets_dir / ROOT_CERT).unlink()
    session.printed.clear()

    assert check() == 1

    assert f"{ROOT_KEY} exists but {ROOT_CERT} is missing" in session.output


@pytest.mark.parametrize("failing_tool", ["compose", "volume inspect"])
def test_check_cannot_tell_when_docker_does_not_answer(init, check, docker, session, failing_tool):
    """#52 rule 8: Docker or Compose not answering is exit 2."""
    init.run()
    docker.failing_tool, docker.failure_text = failing_tool, "Cannot connect to the Docker daemon"
    session.printed.clear()

    assert check() == 2

    assert "Cannot connect to the Docker daemon" in session.output
