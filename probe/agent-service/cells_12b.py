"""The login command (#457, agent-runtime#440's 12b row): the real `agent-service` of compose.yaml
in a throwaway compose project, running the login directory it is given, read-only, with the
stand-in issuer, a bootstrapped entrypoint and `max_parallel_cli_runs = 1` in a scratch
service.toml. It drives the A1d conditions of agent-runtime#440 (config, U2, U3, U6, U7, U8 and I6
against the container's own image), the B8 S00 census of every writable mount and B9's R2: one
run on the default model through the run client (run_client.py), whose call of `step` the fake app
(fake_app.py) holds until the client closes its stream, watched from inside the container. It
prints only verdicts, counts and role names. An agent runs it only with a dummy login made with
`mktemp`.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/cells_12b.py --login-directory DIR

Measured teardown: 11 s (K 50 s, CAP 1780 s).

Exit 0: every cell held, 1: a cell failed or was not driven, 2: the arguments were refused.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))  # egress.py, importable by path too

import image
from census_client import WATCH_STOP_PATH, CensusClient, Watched
from containment import SERVICE_COMMAND
from egress import LABEL, REPO, ProbeFailed, expect
from fake_app import APP_HANDSHAKE, APP_SERVICE, FakeApp, Mode
from issuer import ISSUER_SERVICE, IssuerProbe
from login_checks import (
    CLIENT_READ_SECONDS,
    RELEASE_SECONDS,
    START_SECONDS,
    WATCH_SECONDS,
    B9Evidence,
    CallWait,
    ClientReport,
    Gate,
    Login,
    LoginFailed,
    Outcome,
    Verdict,
    app_call,
    b9_not_driven,
    b9_verdicts,
    begin_teardown,
    check_resolved,
    describe,
    failed_command,
    gating,
    guarded,
    mount_line,
    read_client_output,
    read_login,
    run_login,
    s00_verdicts,
    scratch_parent,
    start_time_bound,
    wait_for_call,
    wait_until,
)
from refusals import SMOKE_SERVICE
from run_client import CLOSE_COMMAND
from service_log import BOOTSTRAP, classify_log
from smoke import Tokens
from unit import SERVICE, ServiceConditions, login_directory

from hal.output import write_line

COMMAND_SECONDS = 1500  # the alarm: the drive stops here and the teardown still has time to run
GATEWAY = "agent-egress"
STARTED = (GATEWAY, ISSUER_SERVICE, APP_SERVICE, SERVICE)
CONFIGURATION_TARGET = "/etc/agent-service/service.toml"
PARALLEL_RUNS_SETTING = "\n[runs]\nmax_parallel_cli_runs = 1\n"
LOCAL_LOGGING = {"driver": "local"}
IMAGE_OPTIONS = ("--label", LABEL, "--log-driver=none")
CLIENT_PROGRAM = Path(__file__).resolve().with_name("run_client.py")
CLIENT_TARGET = "/opt/run_client.py"
WATCH_DIRECTORY = Path(WATCH_STOP_PATH).parent
CLIENT_JOIN_SECONDS = 5


class ClientProcess:
    """The run client in `agent-smoke`: its output is read as it comes, and the host's one
    `close` line is written on its stdin."""

    def __init__(self, process: subprocess.Popen) -> None:
        self.process = process
        self.lines: list[str] = []
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self) -> None:
        try:
            for line in self.process.stdout:
                self.lines.append(line.rstrip("\n"))
        except ValueError:  # `finish` closed the output while it was still being read
            return

    def alive(self) -> bool:
        return self.process.poll() is None

    def report(self) -> ClientReport:
        return read_client_output(list(self.lines))

    def say_close(self) -> None:
        """A client that already ended has nothing left to close: its output tells the rest."""
        with contextlib.suppress(BrokenPipeError):
            self.process.stdin.write(f"{CLOSE_COMMAND}\n")
            self.process.stdin.flush()

    def finish(self, seconds: float) -> None:
        """Reads the client's output to its end; a client that is still running after `seconds`
        is killed, and what it printed counts."""
        try:
            self.process.wait(timeout=seconds)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.reader.join(CLIENT_JOIN_SECONDS)
        self.process.stdout.close()
        with contextlib.suppress(BrokenPipeError):
            self.process.stdin.close()


class LoginProbe(ServiceConditions, FakeApp, IssuerProbe):
    """The service with the given login bound read-only. Nothing a command or the container
    prints reaches the output: a failed command is a `LoginFailed`, and `hold` names the cell."""

    def __init__(self, scratch: Path, login: Login, gate: Gate) -> None:
        self.texts: list[str] = []  # every command's output, in memory, for S1
        self.failed: list[str] = []
        self.not_driven: list[str] = []
        self.minted: list[Tokens] = []
        self.working_root_entries: int | None = None  # S00's count, B9 (c)'s baseline
        self.login = login
        self.gate = gate
        self.clock = time.monotonic  # the R2 waits read these, so a test runs them on a fake clock
        self.sleep = time.sleep
        super().__init__(scratch)
        text = self.configuration.read_text(encoding="utf-8")
        expect("[runs]" not in text, "service.toml has a [runs] table")
        self.configuration.write_text(text + PARALLEL_RUNS_SETTING, encoding="utf-8")
        self.watch_directory = scratch / "watch"
        self.watch_directory.mkdir()
        self.watch_directory.chmod(0o755)
        overlay = scratch / "compose.login.yaml"
        overlay.write_text(
            json.dumps({"services": {
                SERVICE: {
                    "entrypoint": ["python", "-I", "-c", BOOTSTRAP],
                    "command": SERVICE_COMMAND,
                    "logging": LOCAL_LOGGING,
                    "volumes": [
                        {"type": "bind", "source": str(login.directory), "read_only": True,
                         "target": login_directory(), "bind": {"create_host_path": False}},
                        {"type": "bind", "source": str(self.watch_directory), "read_only": True,
                         "target": str(WATCH_DIRECTORY)},
                    ],
                },
                APP_SERVICE: {"logging": LOCAL_LOGGING},
                GATEWAY: {"logging": LOCAL_LOGGING},
                ISSUER_SERVICE: {"logging": LOCAL_LOGGING},
            }}),
            encoding="utf-8",
        )  # fmt: skip
        self.overlays.append(overlay)

    def services_to_start(self) -> tuple[str, ...]:
        return STARTED

    def serves(self, command: list[str]) -> bool:
        return [Path(command[0]).name, *command[1:]] == [
            "python",
            "-I",
            "-c",
            BOOTSTRAP,
            *SERVICE_COMMAND,
        ]

    def run(self, command, *, stdin=None, check=True, timeout=300, own_session=False):
        result = super().run(
            command, stdin=stdin, check=False, timeout=timeout, own_session=own_session
        )
        self.texts.append(result.stdout + result.stderr)
        if check and result.returncode != 0:
            raise failed_command(command, result.returncode)
        return result

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held", flush=True)
        self.held.append(cell)

    def __enter__(self) -> LoginProbe:
        resolved = json.loads(self.compose("config", "--format", "json").stdout)
        check_resolved(
            resolved, service=SERVICE, started=STARTED,
            login=(login_directory(), self.login.directory),
            configuration=(CONFIGURATION_TARGET, self.configuration),
        )  # fmt: skip
        super().__enter__()
        return self

    def __exit__(self, *arguments: object) -> None:
        begin_teardown()  # also after a failed enter, whose signals are still armed
        super().__exit__(*arguments)

    def verdict(self, cell: str, evidence: str) -> None:
        """A cell of the command's own: its evidence is built from counts and role names."""
        write_line(f"{cell} held: {evidence}", flush=True)
        self.held.append(cell)

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        if not guarded("listen", self.wait_until_listening, self.failed):
            return
        for cell, step in (
            ("config", self.cell_config), ("U2", self.cell_u2), ("U3", self.cell_u3),
            ("U6", self.cell_u6), ("U7", self.cell_u7), ("U8", self.cell_u8),
            ("I6", self.cell_i6), ("S00", self.cell_s00), ("B9", self.cell_b9),
            ("S1", self.cell_s1),
        ):  # fmt: skip
            guarded(cell, step, self.failed)

    def cell_config(self) -> None:
        inside = self.inside("sha256", CONFIGURATION_TARGET)["sha256"]
        expect(inside == hashlib.sha256(self.configuration.read_bytes()).hexdigest(), "config")
        self.verdict(
            "config", "the service runs the scratch service.toml, max_parallel_cli_runs = 1"
        )

    def cell_i6(self) -> None:
        """The image the login container runs, in a container of its own without the login."""
        inspected = self.run(
            ["docker", "inspect", "--format", "{{.Image}}", self.container(SERVICE)]
        )
        image.cell_i6(inspected.stdout.strip(), IMAGE_OPTIONS)
        self.hold("I6", "")

    def census(self) -> CensusClient:
        return CensusClient(self, self.container(SERVICE), self.configuration)

    def cell_s00(self) -> None:
        """B8's S00 snapshot of every writable mount as an observation, then edge's two frame
        checks over it."""
        census = self.census()
        self.gate.add(census.key.hex())
        mounts = census.mounts()
        roles = {census.names.show_mount(census.working_root): "working root"}
        for shown, mount in sorted(mounts.items()):
            write_line(mount_line(roles.get(shown, shown), mount), flush=True)
        working_root = mounts.get(census.names.show_mount(census.working_root))
        self.working_root_entries = None if working_root is None else len(working_root.listings)
        for verdict in s00_verdicts(mounts):
            self.record(verdict)

    def record(self, verdict: Verdict) -> None:
        if verdict.outcome is Outcome.HELD:
            self.verdict(verdict.cell, verdict.evidence)
            return
        failures = self.failed if verdict.outcome is Outcome.FAILED else self.not_driven
        failures.append(verdict.cell)
        write_line(f"{verdict.cell} {verdict.outcome}: {verdict.evidence}", flush=True)

    def cell_b9(self) -> None:
        """R2: one run on the default model that calls `step` and is closed at t0. B9 (a)-(e) are
        not driven unless every frame cell held, and nothing is posted then."""
        if self.failed or self.not_driven:
            verdicts = b9_not_driven("a frame cell did not hold")
        else:
            verdicts = self.drive_r2()
        for verdict in verdicts:
            self.record(verdict)

    def start_client(self, tokens: Tokens) -> ClientProcess:
        command = self.compose_command(
            "run", "--rm", "-T", "--no-deps", "--label", LABEL, "--entrypoint", "python",
            "-v", f"{CLIENT_PROGRAM}:{CLIENT_TARGET}:ro", SMOKE_SERVICE,
            "-I", "-B", CLIENT_TARGET,
        )  # fmt: skip
        process = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, errors="replace", env=self.environment, cwd=REPO, close_fds=True,
        )  # fmt: skip
        self.windows.append(process)
        process.stdin.write(f"{tokens.person}\n{tokens.workload}\n")
        process.stdin.flush()
        return ClientProcess(process)

    def close_stream(self, client: ClientProcess) -> None:
        """The one place the host tells the client to close its stream."""
        client.say_close()

    def stop_watch(self) -> None:
        stop = self.watch_directory / Path(WATCH_STOP_PATH).name
        stop.touch()
        stop.chmod(0o644)

    def drive_r2(self) -> tuple[Verdict, ...]:
        tokens = self.tokens()
        self.minted.append(tokens)
        for token in (tokens.person, tokens.workload):
            self.gate.add(token)
        census = self.census()
        self.gate.add(census.key.hex())
        log_before = classify_log(self.container_log(SERVICE))
        app = self.container(APP_SERVICE)  # looked up once: its reads during the turn are bounded
        app_before = len(self.app_lines())
        self.write_mode(Mode.HOLD)

        def app_since(seconds: int) -> list[str]:
            return self.app_lines(seconds, app)[app_before:]

        client = self.start_client(tokens)
        watching: Future[Watched] | None = None
        called = False
        with ThreadPoolExecutor(max_workers=1) as pool:
            try:
                if self.wait_for_start(client):
                    watching = pool.submit(census.watch, WATCH_SECONDS)
                    outcome = wait_for_call(self.clock, self.sleep, app_since, client.alive)
                    called = outcome is CallWait.HELD
            finally:  # a failed read must not leave the stream open or the watch running
                try:
                    self.close_stream(client)
                    client.finish(CLIENT_READ_SECONDS)
                    if called:
                        wait_until(
                            lambda left: app_call(app_since(left)).released_at is not None,
                            RELEASE_SECONDS, self.clock, self.sleep,
                        )  # fmt: skip
                finally:
                    self.stop_watch()
            watched = self.collect(watching)
        report = client.report()
        self.texts.extend(["\n".join(client.lines), "\n".join(self.app_lines())])
        lines = self.app_lines()[app_before:]
        self.observe(lines, report, watched)
        if not called:
            return b9_not_driven(self.no_call_reason(report))
        result = b9_verdicts(B9Evidence(
            report, watched, app_call(lines),
            classify_log(self.container_log(SERVICE)).since(log_before),
            self.working_root_entries,
        ))  # fmt: skip
        if result.timing:
            write_line(result.timing, flush=True)
        return result.verdicts

    def wait_for_start(self, client: ClientProcess) -> bool:
        wait_until(
            lambda _left: client.report().started or not client.alive(),
            START_SECONDS, self.clock, self.sleep,
        )  # fmt: skip
        return client.report().started

    @staticmethod
    def collect(watching: Future[Watched] | None) -> Watched | None:
        if watching is None:
            return None
        try:
            return watching.result()
        except ProbeFailed:
            return None

    @staticmethod
    def no_call_reason(report: ClientReport) -> str:
        if report.started:
            return "no call reached the fake app"
        if report.answer not in (None, 200):
            return f"R2 was refused: {report.answer} {report.answer_code or 'no code'}"
        return "R2 reached no run_started"

    @staticmethod
    def observe(lines: list[str], report: ClientReport, watched: Watched | None) -> None:
        """What R2 did, as counts: the app's lines since R2 began and the watch's booleans."""
        handshake = sum(line in APP_HANDSHAKE for line in lines)
        listings = sum(line.startswith("method=tools/list") for line in lines)
        seen = "no watch" if watched is None else (
            f"group seen {watched.group_seen}, tree seen {watched.tree_seen}, "
            f"{watched.samples} samples"
        )  # fmt: skip
        write_line(
            f"R2 observed: the app logged {handshake} handshake lines and {listings} listings; "
            f"the client printed {len(report.events)} events, {report.unmatched} lines outside "
            f"its vocabulary; watch: {seen}",
            flush=True,
        )

    def cell_s1(self) -> None:
        """The no-token cell: the gate changed no line, and no text in memory holds the login
        token or a minted one."""
        tokens = [
            self.login.token,
            *(t for pair in self.minted for t in (pair.person, pair.workload)),
        ]
        in_log = self.container_log(SERVICE).count(self.login.token)
        in_texts = sum(text.count(token) for text in self.texts for token in tokens)
        counts = (
            f"{self.gate.hits} gate hits, {in_log} in the service log, "
            f"{in_texts} in all command outputs"
        )
        if self.gate.hits or in_log or in_texts:
            self.failed.append("S1")
            write_line(f"S1 FAILED: {counts}", flush=True)
        else:
            self.verdict("S1", counts)


def run_command(login: Login, environment: Mapping[str, str] = os.environ) -> int:
    try:
        parent = scratch_parent(login, environment)
        start_time_bound(COMMAND_SECONDS)
        scratch = Path(tempfile.mkdtemp(prefix="login-probe-", dir=parent)).resolve()
        try:
            with gating([login.token]) as gate:
                return run_login(lambda: LoginProbe(scratch, login, gate))
        finally:
            shutil.rmtree(scratch, ignore_errors=True)  # throwaway material only
    except KeyboardInterrupt:
        write_line("interrupted", flush=True)
        return 1
    except Exception as problem:  # the scratch directory: nothing but the type is printed
        write_line(describe("setup", problem), flush=True)
        write_line("PROBE FAILED: setup", flush=True)
        return 1


def main(
    arguments: Sequence[str] | None = None, start: Callable[[Login], int] = run_command
) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--login-directory", required=True)
    try:
        login = read_login(parser.parse_args(arguments).login_directory)
    except LoginFailed as refusal:
        write_line(f"PROBE FAILED: {refusal}", flush=True)
        return 1
    return start(login)


if __name__ == "__main__":
    sys.exit(main())
