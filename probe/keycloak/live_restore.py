"""Probe of `hal restore keycloak --live` (#974 cells K1, K2) on the stack that
`probe/keycloak/probe.py hold` keeps up in its throwaway project. Nothing live: it refuses to run
in the live project, and it holds the live project unchanged after its last cell.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/keycloak/live_restore.py --scratch DIR

Measured: 124 s whole, of which the hold's teardown is 10 s. `timeout`'s TERM reaches the hold in
the same process group.

The checkout's `hal` runs under a scratch HOME with its own restic repository and password, and
with `--apps` naming the shipped `keycloak` record with only `compose_project` replaced by the
hold's project. The probe never runs `hal stop` or `hal start`, which act on the live project: it
writes Keycloak's switch marker under the scratch HOME and stops and starts the hold's containers
itself. C is a user the probe makes through the admin API after the backup. Exit 0: every cell
held.
"""

from __future__ import annotations

import argparse
import dataclasses
import grp
import json
import os
import re
import secrets
import shlex
import signal
import subprocess
import sys
import time
import tomllib
from datetime import UTC, datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "src"), str(REPO / "probe"), str(REPO / "probe/keycloak")]
import edge_copy  # noqa: E402

import probe as keycloak  # noqa: E402
from hal.backup.apps import parse_apps  # noqa: E402
from hal.backup.cli import DEFAULT_APPS  # noqa: E402
from hal.backup.settings import Settings  # noqa: E402
from hal.grammar import ExitCode  # noqa: E402
from hal.output import write_line  # noqa: E402
from hal.output.command import Verb, command  # noqa: E402
from hal.stack import switches  # noqa: E402
from hal.stack.result_rows import RESTORE_GUIDE  # noqa: E402

APP = "keycloak"
DATABASE = "keycloak-db"
HAL = REPO / ".venv" / "bin" / "hal"
HAL_SECONDS = 300
READY_SECONDS = 240
BACKUP_DOC = REPO / "docs" / "backup.md"
WELL_KNOWN = f"{keycloak.REALM_PATH}/.well-known/openid-configuration"
GUIDE = re.compile(r'^(?P<file>\S+) "(?P<heading>[^"]+)"$')


class LiveRestoreProbe:
    def __init__(self, scratch: Path) -> None:
        self.scratch = scratch
        self.home = scratch / "home"
        self.home.mkdir(mode=0o700)
        self.settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        self.settings.password_file.parent.mkdir(mode=0o700, parents=True)
        self.settings.password_file.write_text(secrets.token_urlsafe(32))
        self.settings.password_file.chmod(0o600)
        self.apps_file = scratch / "apps.toml"
        self.write_scratch_record()
        state = self.home / switches.default_state_directory().relative_to(Path.home())
        self.switches = switches.Switches(state)
        self.environment = {
            **os.environ,
            "HOME": str(self.home),
            "NO_COLOR": "1",
            "EDGE_DOMAIN": keycloak.DOMAIN,
            "DOCKER_GID": os.environ.get("DOCKER_GID") or str(grp.getgrnam("docker").gr_gid),
        }
        self.environment.pop("LOG_FORMAT", None)
        self.held: list[str] = []

    def write_scratch_record(self) -> None:
        """The shipped record with the hold's project; it must parse to the shipped app with only
        that one field changed."""
        shipped_text = DEFAULT_APPS.read_text()
        section = re.search(rf"^\[app\.{APP}\]\n.*?(?=^\[app\.(?!{APP}\.)|\Z)", shipped_text,
                            re.MULTILINE | re.DOTALL)  # fmt: skip
        keycloak.expect(section is not None, "the shipped apps.toml has no keycloak record")
        shipped_project = tomllib.loads(shipped_text)["app"][APP]["compose_project"]
        text = section[0].replace(f'compose_project = "{shipped_project}"',
                                  f'compose_project = "{keycloak.PROJECT}"')  # fmt: skip
        self.apps_file.write_text(text)
        (declared,) = parse_apps(text)
        (shipped,) = (app for app in parse_apps(shipped_text) if app.name == APP)
        keycloak.expect(
            declared == dataclasses.replace(shipped, compose_project=keycloak.PROJECT),
            "the scratch record differs from the shipped one beyond its project",
        )

    # --- plumbing -----------------------------------------------------------------------------

    def hal(self, *arguments: str, typed: bytes = b"yes\n") -> tuple[int, str]:
        """`hal <arguments>` at a pty where the operator types `typed`; its exit and output."""
        line = shlex.join([str(HAL), *arguments, "--apps", str(self.apps_file)])
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["script", "-qec", line, "/dev/null"], input=typed, capture_output=True,  # noqa: S607 - script is found on PATH by design
            env=self.environment, cwd=REPO, check=False, timeout=HAL_SECONDS,
        )  # fmt: skip
        output = " ".join((result.stdout + result.stderr).decode(errors="replace").split())
        return result.returncode, output

    def docker(self, *arguments: str) -> str:
        return subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", *arguments], capture_output=True, text=True, check=True, timeout=120,  # noqa: S607 - docker is found on PATH by design
        ).stdout.strip()  # fmt: skip

    def container(self, service: str) -> str:
        (found,) = self.docker(
            "ps", "--all", "--quiet", "--filter", f"label={keycloak.PROJECT_LABEL}",
            "--filter", f"label=com.docker.compose.service={service}",
        ).split()  # fmt: skip
        return found

    def state_of(self, service: str) -> str:
        return self.docker("inspect", "--format", "{{.State.Status}}", self.container(service))

    def admin_token(self, ready: dict) -> str:
        secret = Path(ready["admin_client_secret_file"]).read_text().strip()
        answer = keycloak.http(
            "POST", f"{ready['admin_url']}/realms/master/protocol/openid-connect/token",
            form={"grant_type": "client_credentials", "client_id": ready["admin_client_id"],
                  "client_secret": secret},
        )  # fmt: skip
        keycloak.expect(answer.status == 200, f"the admin token answered {answer.status}")
        return answer.json()["access_token"]

    def users_named(self, ready: dict, name: str) -> list:
        answer = keycloak.http(
            "GET",
            f"{ready['admin_url']}/admin/realms/{keycloak.REALM}/users?exact=true&username={name}",
            bearer=self.admin_token(ready),
        )  # fmt: skip
        keycloak.expect(answer.status == 200, f"the user search answered {answer.status}")
        return answer.json()

    def wait_until_answering(self, ready: dict) -> int:
        deadline = time.monotonic() + READY_SECONDS
        while time.monotonic() < deadline:
            try:
                answer = keycloak.tunnel_request(ready["edge_url"], "GET", WELL_KNOWN)
            except OSError:
                answer = None
            if answer is not None and answer.status == 200:
                return answer.status
            time.sleep(2)
        raise keycloak.ProbeFailure(f"the realm's well-known did not answer in {READY_SECONDS} s")

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held: {how}", flush=True)
        self.held.append(cell)

    # --- the cells ----------------------------------------------------------------------------

    def cell_k1(self, ready: dict) -> None:
        code, output = self.hal("backup", "--init")
        keycloak.expect(code == 0, f"K1: hal backup --init exited {code}: {output[-300:]!r}")
        code, output = self.hal("backup", APP)
        keycloak.expect(code == 0, f"K1: hal backup exited {code}: {output[-300:]!r}")
        canary = f"probe-c-{secrets.token_hex(6)}"
        made = keycloak.http(
            "POST", f"{ready['admin_url']}/admin/realms/{keycloak.REALM}/users",
            json_body={"username": canary, "enabled": True}, bearer=self.admin_token(ready),
        )  # fmt: skip
        keycloak.expect(made.status == 201, f"K1: making C answered {made.status}")
        keycloak.expect(len(self.users_named(ready, canary)) == 1, "K1: C is not there")
        self.switches.record(APP, datetime.now(UTC))
        self.docker("stop", self.container(APP), self.container(DATABASE))
        code, output = self.hal("restore", APP, "--live")
        keycloak.expect(code == ExitCode.OK and f"✓ {APP} loaded" in output,
                        f"K1: exit {code}: {output[-300:]!r}")  # fmt: skip
        keycloak.expect(canary not in output, "K1: C in the output")
        keycloak.expect(f"next: {command(Verb.START, APP)}" in output, f"K1: {output[-300:]!r}")
        states = {service: self.state_of(service) for service in (APP, DATABASE)}
        keycloak.expect(states == {APP: "exited", DATABASE: "running"}, f"K1: {states}")
        self.docker("start", self.container(APP))
        status = self.wait_until_answering(ready)
        found = self.users_named(ready, canary)
        keycloak.expect(found == [], f"K1: C is still there ({len(found)} users)")
        self.hold("K1", f"exit 0, ✓ {APP} loaded; {states}; once the probe started keycloak, "
                  f"C is gone and the realm's well-known answers {status} on the edge "
                  "entrypoint")  # fmt: skip

    def cell_k2(self) -> None:
        guide = GUIDE.match(RESTORE_GUIDE)
        keycloak.expect(guide is not None, f"K2: RESTORE_GUIDE {RESTORE_GUIDE!r} names no heading")
        keycloak.expect(REPO / guide["file"] == BACKUP_DOC, f"K2: {RESTORE_GUIDE!r}")
        text = BACKUP_DOC.read_text()
        heading = f"### {guide['heading']}\n"
        keycloak.expect(text.count(heading) == 1, f"K2: {heading.strip()!r} is not one heading")
        section = text.split(heading, 1)[1].split("\n### ", 1)[0]
        commands = [command(Verb.STOP, APP), command(Verb.RESTORE, APP, "--live"),
                    command(Verb.START, APP)]  # fmt: skip
        missing = [line for line in commands if line not in section]
        keycloak.expect(not missing, f"K2: the section lacks {missing}")
        keycloak.expect("```" not in section, "K2: the section still holds a shell block")
        self.hold("K2", f"{heading.strip()!r} names {', '.join(commands)} and holds no shell "
                  f"block; RESTORE_GUIDE names that heading")  # fmt: skip

    def drive(self) -> None:
        live_name = edge_copy.compose_project_name((REPO / "compose.yaml").read_text())
        keycloak.expect(
            live_name != keycloak.PROJECT, "the probe must never run in the live project"
        )
        live_before = edge_copy.live_project(REPO)
        holding = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            [sys.executable, str(REPO / "probe/keycloak/probe.py"), "hold",
             "--scratch", str(self.scratch / "hold")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
        )  # fmt: skip
        try:
            ready = self.ready_of(holding)
            self.cell_k1(ready)
        finally:
            holding.stdin.close()
            try:
                ended = holding.stdout.read()
                holding.wait(timeout=HAL_SECONDS)
            finally:
                if holding.poll() is None:
                    holding.kill()
                    holding.wait()
            write_line(ended.strip().splitlines()[-1] if ended.strip() else "hold: no line")
        keycloak.expect(holding.returncode == 0, f"the hold ended with {holding.returncode}")
        self.cell_k2()
        write_line(edge_copy.expect_live_project_unchanged(live_before, REPO), flush=True)

    @staticmethod
    def ready_of(holding: subprocess.Popen) -> dict:
        for line in holding.stdout:
            if line.startswith(f"{keycloak.READY_MARK} "):
                return json.loads(line.split(" ", 1)[1])
        raise keycloak.ProbeFailure(f"the hold ended before READY with {holding.wait()}")


def stop(_signum: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=edge_copy.scratch_directory, required=True)
    scratch = parser.parse_args().scratch
    signal.signal(signal.SIGTERM, stop)
    started = time.monotonic()
    try:
        probe = LiveRestoreProbe(scratch)
        probe.drive()
    except (keycloak.ProbeFailure, edge_copy.ProbeFailed, subprocess.SubprocessError,
            KeyboardInterrupt) as problem:  # fmt: skip
        write_line(f"PROBE FAILED: {type(problem).__name__}: {problem}", flush=True)
        return 1
    write_line(f"PROBE PASSED: held {', '.join(probe.held)} in {time.monotonic() - started:.0f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
