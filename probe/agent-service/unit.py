"""Probe of the agent service unit (#201 U1-U11, #214 U15, #346 P09 and P11a): `agent-service` of
compose.yaml, with its real `service.toml`, in a throwaway compose project of its own and a
scratch HOME that holds a dummy login of each CLI (never a real token).

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/unit.py --scratch DIR

Measured teardown: 1 s (K 50 s, CAP 1780 s).

U12 is `egress.py --target service`, U13 is `tests/test_agent_service_unit.py`. `--cell smoke`
drives U14 instead (#214 S4): the operator's `agent-smoke` against the service with a stand-in
issuer on the `agent-songmaker` network, so the tokens verify and the CLI meets the real upstream
with the dummy login. U17 (refusals.py) asks the refusals before any run; U16 then runs the cells of
`agent-service/live_smoke.py` there, past its sign-in. `--cell containment` (containment.py) adds a
fake app that lists tools (app_tools.py), certified by the scratch CA of scratch_secrets.py, and
drives agent-runtime#440's cells B1 and B2 through `agent-smoke --tool`, B3 to B5 through a
transparent wrapper around the CLI. `--cell signer` (signer.py) drives #413's P12 and P28 against
a signing stand-in. The image
compose.yaml names must exist (docs/agent-service.md, "The image"). The probe
always removes its containers and networks, and never touches the live stack: the project name is
its own (egress.py) and is set on every command. Needs an existing, empty, writable --scratch
directory. Exit 0: every cell held, 1: a cell failed.

The container is asked through the `Inside` class below: the driver sends its source to
`python -I -` inside the container, which has the interpreter of the image and nothing else.
"""

from __future__ import annotations

import argparse
import errno
import hashlib
import inspect
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from enum import StrEnum
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))  # egress.py, importable by path too
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))  # edge's own observation
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "agent-service"))  # live_smoke.py

from containment import ContainmentProbe
from egress import (
    COMPOSE_FILE,
    LABEL,
    PROJECT,
    SERVICE_PORT,
    Probe,
    ProbeFailed,
    Target,
    cli_tables,
    expect,
    run_probe,
    scratch_directory,
    service_configuration,
    token_path,
)
from issuer import ISSUER_SERVICE, LISTENING, IssuerProbe, wait_for_listening
from live_smoke import Report, Secrets, Stack, Verdict, smoke_cells
from live_smoke import egress_cells as live_egress_cells
from refusals import SMOKE_SERVICE, check_refusals
from scratch_secrets import (
    DUMMY_LOGIN_WRITERS,
    SECRETS_DIRECTORY,
    login_file,
    login_values,
    write_incomplete_codex_login,
)
from signer import SignerProbe

from hal.output import write_line
from hal.stack import compose

SERVICE = Target.SERVICE.compose_service
REFUSAL_SECONDS = 60
UID = 1000
CONTAINER_TMP = "/tmp"  # NOSONAR(S5443) the service's tmpfs inside the container, not a host path  # noqa: S108 - the service tmpfs inside its container and no host path
SERVICE_COMMAND = "agent-runtime-service"
INIT_COMMAND = "docker-init"
OWNER_ONLY = 0o700
TOKEN_MODE = 0o600
LOOSE_TOKEN_MODE = 0o644
KEY_MODE = 0o600
LOOSE_KEY_MODE = 0o640
UNREADABLE_KEY_MODE = 0o000
LOOSE_WORKING_ROOT_MODE = "0750"
INSIDE_IMPORTS = "import errno, hashlib, json, os, re, shutil, signal, subprocess, sys, time\n"


class Inside:
    """What the probe asks inside the service container; every command prints one JSON line."""

    @staticmethod
    def processes() -> dict:
        found = []
        for name in os.listdir("/proc"):
            if not name.isdigit() or int(name) == os.getpid():
                continue
            try:
                with open(f"/proc/{name}/stat", encoding="utf-8") as stat:
                    parent = int(stat.read().rpartition(") ")[2].split()[1])
                with open(f"/proc/{name}/cmdline", "rb") as command:
                    arguments = command.read().decode("utf-8", "replace").rstrip("\0").split("\0")
            except OSError:
                continue  # it ended between the listing and the read
            found.append({"pid": int(name), "parent": parent, "command": arguments})
        return {"processes": found}

    @staticmethod
    def process(pid: str) -> dict:
        with open(f"/proc/{pid}/status", encoding="utf-8") as status:
            fields = {
                key: value
                for key, separator, value in (
                    line.partition(":\t") for line in status.read().splitlines()
                )
                if separator
            }
        with open(f"/proc/{pid}/limits", encoding="utf-8") as limits:
            core = re.search(r"Max core file size\s+(\S+)\s+(\S+)", limits.read())
        try:
            with open(f"/proc/{pid}/attr/current", encoding="utf-8") as label:
                confinement = label.read().strip()
        except OSError as error:
            confinement = f"unreadable: {errno.errorcode.get(error.errno or 0)}"
        return {
            "uid": fields["Uid"].split(),
            "gid": fields["Gid"].split(),
            "capabilities": fields["CapEff"].strip(),
            "no_new_privileges": fields["NoNewPrivs"].strip(),
            "core_limit": [core.group(1), core.group(2)],
            "environ_owner": os.stat(f"/proc/{pid}/environ").st_uid,
            "opens": {
                name: Inside.open_result(f"/proc/{pid}/{name}") for name in ("environ", "mem")
            },
            "label": confinement,
        }

    @staticmethod
    def open_result(path: str) -> str:
        try:
            with open(path, "rb"):
                return "opened"
        except OSError as error:
            return errno.errorcode.get(error.errno or 0, str(error.errno))

    @staticmethod
    def own_label() -> dict:
        with open("/proc/self/attr/current", encoding="utf-8") as label:
            return {"label": label.read().strip()}

    @staticmethod
    def mounts() -> dict:
        rows = []
        with open("/proc/self/mountinfo", encoding="utf-8") as table:
            for line in table:
                left, _, right = line.partition(" - ")
                fields, tail = left.split(), right.split()
                options = fields[5].split(",") + tail[2].split(",")
                rows.append({
                    "point": fields[4], "type": tail[0], "options": options,
                    "own_options": fields[5].split(","),
                })  # fmt: skip
        return {"mounts": rows}

    @staticmethod
    def stat(path: str) -> dict:
        status = os.stat(path)
        return {"mode": status.st_mode & 0o7777, "uid": status.st_uid, "gid": status.st_gid}

    @staticmethod
    def write(path: str) -> dict:
        try:
            with open(path, "w", encoding="utf-8"):
                return {"result": "written"}
        except OSError as error:
            return {"result": errno.errorcode.get(error.errno or 0, str(error.errno))}

    @staticmethod
    def sha256(path: str) -> dict:
        with open(path, "rb") as content:
            return {"sha256": hashlib.sha256(content.read()).hexdigest()}

    @staticmethod
    def run_copy(directory: str) -> dict:
        """A copy of a binary, started from a directory; `noexec` refuses it."""
        copy = os.path.join(directory, "copied-true")
        shutil.copy("/bin/true", copy)
        try:
            subprocess.run([copy], check=True)  # noqa: S603 - runs the copy of a system binary that the probe made
            return {"result": "ran"}
        except OSError as error:
            return {"result": errno.errorcode.get(error.errno or 0, str(error.errno))}
        finally:
            os.unlink(copy)

    @staticmethod
    def kill_group() -> dict:
        """A same-uid child in its own process group with a descendant of its own, SIGKILLed as a
        group: how long until both are gone from /proc (init reaps the orphan)."""
        child = subprocess.Popen(
            ["sh", "-c", "sleep 300 & echo $!; wait"], stdout=subprocess.PIPE, text=True,  # noqa: S607 - sh is found on PATH by design and the script is a literal
            start_new_session=True,
        )  # fmt: skip
        descendant = int(child.stdout.readline())
        before = [os.path.exists(f"/proc/{pid}") for pid in (child.pid, descendant)]
        started = time.monotonic()
        os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        while time.monotonic() - started < 3:
            if not any(os.path.exists(f"/proc/{pid}") for pid in (child.pid, descendant)):
                break
            time.sleep(0.01)
        gone = [not os.path.exists(f"/proc/{pid}") for pid in (child.pid, descendant)]
        return {"before": before, "gone": gone, "seconds": time.monotonic() - started}

    @staticmethod
    def main(arguments: list[str]) -> int:
        print(json.dumps(getattr(Inside, arguments[0])(*arguments[1:])), flush=True)  # noqa: T201 - this in-container program imports nothing of hal and prints itself
        return 0


INSIDE_PROGRAM = (
    INSIDE_IMPORTS + inspect.getsource(Inside) + "\nsys.exit(Inside.main(sys.argv[1:]))\n"
)


def working_root() -> str:
    return service_configuration()["cli"]["working_root"]


def login_directory() -> str:
    return str(Path(token_path()).parent)


def ended_unsuccessfully(state: dict) -> bool:
    """The container is not running, or waits between restarts, and its last exit was non-zero."""
    return (not state["Running"] or state["Restarting"]) and state["ExitCode"] != 0


def refusal_is_complete(cell: str, logs: str, fields: list[str]) -> bool:
    """The logs of an attempt that ended unsuccessfully name every field; one that listened
    fails the cell."""
    expect(LISTENING not in logs, f"{cell}: the service listened")
    return all(field in logs for field in fields)


class ServiceConditions:
    """The conditions of a started service that agent-runtime#440's A1d names (U2, U3, U6, U7 and
    U8), for the probes that start the service: `serves` says what its init's child runs."""

    def serves(self, command: list[str]) -> bool:
        raise NotImplementedError

    def inside(self, *arguments: str) -> dict:
        container = self.container(SERVICE)
        return self.client_with(["exec", "-i", container], arguments, INSIDE_PROGRAM)

    def service_process(self) -> dict:
        processes = self.inside("processes")["processes"]
        children = [found for found in processes if found["parent"] == 1]
        expect(len(children) == 1, f"U2: the init has children {children}")
        init = next(found for found in processes if found["pid"] == 1)
        expect(Path(init["command"][0]).name == INIT_COMMAND, f"U2: PID 1 is {init['command']}")
        return children[0]

    def cell_u2(self) -> None:
        listed = self.run(
            ["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}",
             "--filter", f"label=com.docker.compose.service={SERVICE}"],
        ).stdout.split()  # fmt: skip
        expect(len(listed) == 1, f"U2: {len(listed)} service containers")
        configured = json.loads(self.compose("config", "--format", "json").stdout)["services"]
        expect("deploy" not in configured[SERVICE], "U2: the service has a deploy section")
        service = self.service_process()
        expect(self.serves(service["command"]), f"U2: the init's child is {service['command']}")
        expect("--workers" not in service["command"], f"U2: {service['command']}")
        processes = self.inside("processes")["processes"]
        grandchildren = [found for found in processes if found["parent"] == service["pid"]]
        expect(not grandchildren, f"U2: the service has children {grandchildren}")
        self.hold(
            "U2",
            f"one container; PID 1 is docker-init and its one child {service['command'][-3:]} "
            "runs no worker",
        )

    def cell_u3(self) -> None:
        pid = str(self.service_process()["pid"])
        process = self.inside("process", pid)
        expect(
            set(process["uid"]) == {str(UID)} and set(process["gid"]) == {str(UID)},
            f"U3: {process['uid']} {process['gid']}",
        )
        expect(int(process["capabilities"], 16) == 0, f"U3: CapEff {process['capabilities']}")
        expect(process["no_new_privileges"] == "1", "U3: NoNewPrivs is not 1")
        expect(process["core_limit"] == ["0", "0"], f"U3: core limit {process['core_limit']}")
        expect(process["environ_owner"] == 0, f"U3: environ is owned by {process['environ_owner']}")
        expect(
            set(process["opens"].values()) == {"EACCES"},
            f"U3: a same-uid process opens {process['opens']}",
        )
        written = self.inside("write", "/probe-write")["result"]
        expect(written == "EROFS", f"U3: a write to / gave {written}")
        self.hold(
            "U3",
            f"uid:gid {UID}:{UID}, CapEff 0, NoNewPrivs 1, core 0:0, non-dumpable (environ owned "
            f"by root, environ and mem refused to a same-uid process: {process['opens']}), "
            f"a write to / gives {written}",
        )

    def cell_u6(self) -> None:
        mounts = {m["point"]: m for m in self.inside("mounts")["mounts"]}
        for directory in (CONTAINER_TMP, working_root()):
            mount = mounts[directory]
            owned = self.inside("stat", directory)
            expect(mount["type"] == "tmpfs", f"U6: {directory} is {mount['type']}")
            expect(
                owned["uid"] == UID and owned["mode"] == OWNER_ONLY,
                f"U6: {directory} is owned by {owned['uid']} with mode {owned['mode']:o}",
            )
        self.hold(
            "U6", f"{CONTAINER_TMP} and {working_root()} are tmpfs owned by {UID} with mode 0700"
        )

    def cell_u7(self) -> None:
        options = {m["point"]: m["options"] for m in self.inside("mounts")["mounts"]}
        for directory in (CONTAINER_TMP, working_root()):
            expect(
                {"nosuid", "nodev", "noexec"} <= set(options[directory]),
                f"U7: {directory} mounts with {options[directory]}",
            )
        ran = self.inside("run_copy", working_root())["result"]
        expect(ran == "EACCES", f"U7: a copied binary in the working root gave {ran}")
        versions = []
        for provider, table in cli_tables().items():
            said = self.run(
                ["docker", "exec", self.container(SERVICE), table["binary"], "--version"]
            ).stdout.strip()
            expect(table["version"] in said.split(), f"U7: the {provider} CLI says {said!r}")
            versions.append(said)
        self.hold(
            "U7",
            "nosuid,nodev,noexec on /tmp and the working root; a copied binary there gives "
            f"{ran}; the CLIs ({', '.join(versions)}) start",
        )

    def cell_u8(self) -> None:
        own_options = {m["point"]: m["own_options"] for m in self.inside("mounts")["mounts"]}
        for provider, table in cli_tables().items():
            options = own_options.get(str(PurePosixPath(table["token_file"]).parent)) or []
            expect(("rw" if provider == "openai" else "ro") in options, f"U8: {provider} {options}")
            login = self.inside("stat", table["token_file"])
            expect(
                login["uid"] == UID and login["mode"] == TOKEN_MODE,
                f"U8: the {provider} login is owned by {login['uid']} with mode {login['mode']:o}",
            )
        self.hold("U8", f"anthropic mount ro, openai mount rw; logins are 0600 owned by {UID}")


class UnitProbe(ServiceConditions, Probe):
    """The egress probe's stack with the service alone, driven cell by cell."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch, Target.SERVICE)
        self.logins = {
            provider: scratch / "home" / login_file(provider) for provider in DUMMY_LOGIN_WRITERS
        }

    def services_to_start(self) -> tuple[str, ...]:
        return (SERVICE,)

    def serves(self, command: list[str]) -> bool:
        return any(Path(part).name == SERVICE_COMMAND for part in command)

    def service_containers(self) -> list[str]:
        """The service's containers, stopped ones included."""
        return self.run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={PROJECT}",
             "--filter", f"label=com.docker.compose.service={SERVICE}"],
        ).stdout.split()  # fmt: skip

    def service_logs(self) -> str:
        containers = self.service_containers()
        logs = self.run(["docker", "logs", *containers[:1]]) if containers else None
        return (logs.stdout + logs.stderr) if logs else ""

    def service_state(self) -> dict | None:
        """The service container's State, or None while there is no container; a failed listing or
        inspection raises."""
        containers = self.service_containers()
        if not containers:
            return None
        inspected = self.run(["docker", "inspect", "--format", "{{json .State}}", containers[0]])
        try:
            return json.loads(inspected.stdout)
        except json.JSONDecodeError as problem:
            raise ProbeFailed(
                f"docker inspect gave no State: {inspected.stdout[:100]!r}"
            ) from problem

    # --- the cells of a started service -------------------------------------------------------

    def drive(self) -> None:
        self.cell_u1()
        self.cell_u2()
        self.cell_u3()
        self.cell_u4()
        self.cell_u5()
        self.cell_u6()
        self.cell_u7()
        self.cell_u8()
        self.cell_u9()
        self.compose("down", "--timeout", "10")
        self.cell_u6_refusal()
        self.cell_u10()
        self.cell_u11()
        self.cell_p09()
        self.cell_p11a()
        self.cell_u15()

    def wait_until_listening(self) -> None:
        wait_for_listening(self.service_logs, "U1: the service did not listen")

    def unauthenticated_status(self) -> int:
        image = json.loads(self.compose("config", "--format", "json").stdout)["services"][SERVICE][
            "image"
        ]
        program = (
            "import urllib.request, urllib.error\n"
            f"address = 'http://{SERVICE}:{SERVICE_PORT}/runs'\n"
            "request = urllib.request.Request(address, data=b'{}', method='POST',"
            " headers={'Content-Type': 'application/json'})\n"
            "try:\n"
            "    print(urllib.request.urlopen(request, timeout=10).status)\n"
            "except urllib.error.HTTPError as refusal:\n"
            "    print(refusal.code)\n"
        )
        asked = self.run(
            ["docker", "run", "--rm", "--label", LABEL, f"--network={PROJECT}_agent_songmaker",
             "--read-only", "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt",
             "no-new-privileges:true", "--entrypoint", "python", image, "-I", "-c", program],
        )  # fmt: skip
        return int(asked.stdout.strip())

    def cell_u1(self) -> None:
        self.wait_until_listening()
        status = self.unauthenticated_status()
        expect(status == 401, f"U1: an unauthenticated POST /runs answered {status}")
        self.hold(
            "U1",
            f"the service listens on :{SERVICE_PORT} after its version probe; "
            "an unauthenticated POST /runs answers 401",
        )

    def cell_u4(self) -> None:
        mounts = self.inside("mounts")["mounts"]
        over_proc = [
            m for m in mounts if m["point"] == "/proc" or re.match(r"/proc/\d", m["point"])
        ]
        expect(
            [m["type"] for m in over_proc] == ["proc"],
            f"U4: mounts over /proc or /proc/<pid>: {over_proc}",
        )
        self.hold("U4", "the only mount at /proc is procfs and none lies over /proc/<pid>")

    def cell_u5(self) -> None:
        pid = str(self.service_process()["pid"])
        label = self.inside("process", pid)["label"]
        own = self.inside("own_label")["label"]
        expect(own == "docker-default (enforce)", f"U5: an exec'd process is {own}")
        expect(label == "docker-default (enforce)", f"U5: the service is {label}")
        killed = self.inside("kill_group")
        expect(all(killed["before"]), f"U5: the group did not start: {killed}")
        expect(all(killed["gone"]) and killed["seconds"] < 1, f"U5: {killed}")
        self.hold(
            "U5",
            f"the service and an exec'd process run under {label}; a same-uid group with a "
            f"descendant is gone {killed['seconds']:.2f} s after SIGKILL",
        )

    def started_at(self) -> str:
        return self.run(
            ["docker", "inspect", "--format", "{{.State.StartedAt}}", self.container(SERVICE)]
        ).stdout.strip()

    def cell_u9(self) -> None:
        for provider, login in self.logins.items():
            token_file = cli_tables()[provider]["token_file"]
            before = self.inside("sha256", token_file)["sha256"]
            started = self.started_at()
            renewed = login.with_name(f"{login.name}.new")
            DUMMY_LOGIN_WRITERS[provider](renewed)
            self.run(["mv", "-T", str(renewed), str(login)])
            after = self.inside("sha256", token_file)["sha256"]
            expected = hashlib.sha256(login.read_bytes()).hexdigest()
            expect(after == expected and after != before, f"U9: the container sees {after}")
            expect(self.started_at() == started, "U9: the service restarted")
            self.hold(
                "U9",
                f"after {renewed.name} and mv -T the container reads the {provider} login as "
                f"sha256 {after[:12]} (was {before[:12]}) at once; StartedAt unchanged",
            )

    # --- the cells that stop a start ----------------------------------------------------------

    def refused_start(self, cell: str, fields: list[str]) -> str:
        """Starts the service as the current files and overlays have it and waits until one
        failed attempt is complete: the container is down with a non-zero exit, and its whole log,
        read after that state, names every field and never listens; returns the log."""
        self.compose("up", "--detach", SERVICE, check=False, timeout=300)
        deadline = time.monotonic() + REFUSAL_SECONDS
        logs = ""
        while time.monotonic() < deadline:
            state = self.service_state()
            if state is not None and ended_unsuccessfully(state):
                logs = self.service_logs()
                if refusal_is_complete(cell, logs, fields):
                    return logs
            time.sleep(1)
        raise ProbeFailed(
            f"{cell}: no refused start naming {fields} in the log of a failed attempt"
        )

    def cell_u6_refusal(self) -> None:
        overlay = self.compose_file.with_name("working-root-0750.yaml")
        overlay.write_text(
            "services:\n"
            f"  {SERVICE}:\n"
            "    tmpfs: !override\n"
            f"      - /tmp:uid={UID},gid={UID},mode=0700,size=16m,nosuid,nodev,noexec\n"
            f"      - {working_root()}:uid={UID},gid={UID},mode={LOOSE_WORKING_ROOT_MODE},"
            "size=64m,nosuid,nodev,noexec\n",
            encoding="utf-8",
        )
        self.overlays.append(overlay)
        try:
            logs = self.refused_start("U6", ["cli.working_root"])
        finally:
            self.overlays.remove(overlay)
            self.compose("down", "--timeout", "10")
        self.hold(
            "U6 refusal",
            f"a working root with mode {LOOSE_WORKING_ROOT_MODE} stops the start; the log names "
            f"cli.working_root ({logs.strip().splitlines()[-1][:160]!r})",
        )

    def refused_login(self, cell: str, provider: str) -> str:
        """A refused start that names the provider's `token_file` and its path and whose log
        holds no value of the login; returns the log."""
        logs = self.refused_start(
            cell, [f"cli.{provider}.token_file", cli_tables()[provider]["token_file"]]
        )
        leaked = [value for value in login_values(self.logins[provider]) if value in logs]
        expect(not leaked, f"{cell}: the log holds a value of the login")
        return logs

    def cell_u10(self) -> None:
        for provider, login in self.logins.items():
            directory = login.parent
            aside = directory.with_name(f"{directory.name}.aside")
            directory.rename(aside)
            try:
                started = self.compose("up", "--detach", SERVICE, check=False, timeout=300)
                expect(started.returncode != 0, f"U10: the service started without {directory}")
                expect(not directory.exists(), f"U10: the missing {directory} was created")
                strangers = self.paths_of_others()
                expect(not strangers, f"U10: paths not owned by the operator: {strangers}")
                reason = (started.stderr or started.stdout).strip().splitlines()[-1]
            finally:
                aside.rename(directory)
                self.compose("down", "--timeout", "10")
            self.hold(
                "U10",
                f"a missing {provider} login directory fails the start ({reason[:140]!r}); "
                "nothing was created under ~/.secrets",
            )

    def cell_u11(self) -> None:
        for provider, login in self.logins.items():
            login.chmod(LOOSE_TOKEN_MODE)
            try:
                self.refused_login(f"U11 {provider}", provider)
            finally:
                login.chmod(TOKEN_MODE)
                self.compose("down", "--timeout", "10")
            self.hold(
                "U11",
                f"a {provider} login at mode 0644 stops the start; the log names "
                f"cli.{provider}.token_file and its path, never a value of the login",
            )
        self.cell_u11_incomplete()

    def cell_u11_incomplete(self) -> None:
        login = self.logins["openai"]
        complete = login.read_bytes()
        login.unlink()
        write_incomplete_codex_login(login)
        try:
            self.refused_login("U11 incomplete", "openai")
        finally:
            login.unlink()
            login.write_bytes(complete)
            login.chmod(TOKEN_MODE)
            self.compose("down", "--timeout", "10")
        self.hold(
            "U11",
            "a Codex sign-in without its access token at mode 0600 stops the start; the log "
            "names cli.openai.token_file and its path, never a value of the login",
        )

    def paths_of_others(self) -> list[str]:
        """Paths under the scratch HOME's `.secrets` that the operator does not own."""
        secrets_directory = Path(self.environment["HOME"]) / SECRETS_DIRECTORY
        return [
            str(path)
            for path in (secrets_directory, *secrets_directory.rglob("*"))
            if path.lstat().st_uid != os.getuid()
        ]

    def cell_p09(self) -> None:
        """The key the service signs with, as uid 1000 reads it: a mode that group or others hold
        stops the start, and so does a mode nobody holds (0000), which the owner cannot read."""
        key = self.scratch_secrets.signing_private
        content = key.read_text(encoding="utf-8")
        body = [line for line in content.splitlines() if not line.startswith("-----")]
        for mode in (LOOSE_KEY_MODE, UNREADABLE_KEY_MODE):
            key.chmod(mode)
            try:
                logs = self.refused_start(f"P09 {mode:04o}", ["signing.key_file"])
            finally:
                key.chmod(KEY_MODE)
                self.compose("down", "--timeout", "10")
            expect(
                not any(line in logs for line in body), f"P09 {mode:04o}: the log holds key bytes"
            )
        self.hold(
            "P09",
            f"a signing key at mode {LOOSE_KEY_MODE:04o} or {UNREADABLE_KEY_MODE:04o} stops the "
            "start; the log names signing.key_file and holds no key byte "
            "(a wrong owner needs root: not driven)",
        )

    def cell_p11a(self) -> None:
        """A missing signing key or CA root source: no service is created, and nothing appears
        at the source or under `.secrets` that the operator does not own."""
        for source in (self.scratch_secrets.signing_private, self.scratch_secrets.root):
            aside = source.with_name(f"{source.name}.aside")
            source.rename(aside)
            try:
                self.compose("up", "--detach", SERVICE, check=False, timeout=300)
                created = self.service_containers()
                expect(not created, f"P11a: a service container exists without {source.name}")
                expect(not source.exists(), f"P11a: {source.name} appeared at its source")
                strangers = self.paths_of_others()
                expect(not strangers, f"P11a: paths not owned by the operator: {strangers}")
            finally:
                aside.rename(source)
                self.compose("down", "--timeout", "10")
        self.hold(
            "P11a",
            "with the signing key or the CA root moved aside, the service is not created; "
            "nothing appeared at either source or under ~/.secrets",
        )

    def cell_u15(self) -> None:
        """A login directory without its token: `up -d` exits 0 and the first look sees the
        service running, and `hal apply`'s own observation finds it not running."""
        token = self.logins["anthropic"]
        aside = token.with_name("token.aside")
        token.rename(aside)
        try:
            started = self.compose("up", "--detach", SERVICE, check=False, timeout=300)
            expect(started.returncode == 0, f"U15: up exited {started.returncode}")
            engine = self.edge_compose()
            down = engine.down_while_watched(
                engine.resolved_configuration(), (SERVICE,), compose.SETTLED
            )
            expect(down == (SERVICE,), f"U15: apply's observation found {down} not running")
            logs = self.service_logs()
            expect(LISTENING not in logs, "U15: the service listened without its token")
        finally:
            aside.rename(token)
            self.compose("down", "--timeout", "10")
        self.hold(
            "U15",
            f"with the login directory but no token, up exited 0 and apply's observation found "
            f"{', '.join(down)} not running",
        )

    def edge_compose(self) -> compose.Compose:
        """The engine `hal apply` uses, on this probe's project and its copy of compose.yaml."""

        def run(command: list[str], timeout: int):
            verb_and_arguments = command[command.index("--profile") + 2 :]
            return self.run(self.compose_command(*verb_and_arguments), check=False, timeout=timeout)

        return compose.Compose(run, COMPOSE_FILE.parent)


class SmokeProbe(IssuerProbe):
    """The service with a stand-in issuer, asked by the repository's own `agent-smoke`."""

    def services_to_start(self) -> tuple[str, ...]:
        return ("agent-egress", ISSUER_SERVICE, SERVICE)

    def drive(self) -> None:
        self.cell_u14()
        check_refusals(self.run, self.compose_command, self.tokens, self.held)
        self.cell_u16()

    def cell_u16(self) -> None:
        """`agent-service/live_smoke.py` after its sign-in, which needs the real realm and a
        browser: every cell but L2 holds with the dummy login, and L2 must fail, because the
        upstream refuses the dummy login."""
        stack = Stack(
            compose_prefix=tuple(self.compose_command(guard=True)), environment=self.environment,
            directory=COMPOSE_FILE.parent,
        )  # fmt: skip
        expect(stack.project == PROJECT, f"U16: compose names the project {stack.project}")
        expect(stack.gateway == self.address, f"U16: compose names the gateway {stack.gateway}")
        dummy = (self.token_path / "token").read_text(encoding="utf-8").strip()
        known = Secrets(self.tokens(), login_token=dummy, client_secret="probe-client-secret")  # noqa: S106 - a dummy secret of the throwaway probe client
        report = Report(known.values(), out=lambda line: write_line(f"  {line}", flush=True))
        smoke_cells(stack, known, report)
        report.add(*live_egress_cells(stack))
        failed = sorted(
            cell.name.split()[0] for cell in report.cells if cell.verdict is Verdict.FAILED
        )
        expect(failed == ["L2"], f"U16: the cells that failed were {failed}, not only L2")
        self.held.append("U16")
        write_line(
            "U16 held: the live smoke's cells ran; only L2 failed, as the dummy login must",
            flush=True,
        )

    def cell_u14(self) -> None:
        tokens = self.tokens()
        person, workload = tokens.person, tokens.workload
        dummy = (self.token_path / "token").read_text(encoding="utf-8").strip()
        self.wait_until_listening()
        smoke = self.run(
            self.compose_command(
                "run", "--rm", "-T", "--no-deps", "--label", LABEL, SMOKE_SERVICE,
                "--timeout", "180",
            ),
            stdin=f"{person}\n{workload}\n", check=False, timeout=240,
        )  # fmt: skip
        logs = self.container_log(SERVICE)
        shown = smoke.stdout + smoke.stderr
        lines = smoke.stdout.splitlines()
        expect(lines[:1] == ["event: run_started"], f"U14: the smoke began with {lines[:2]}")
        expect("event: failed" in lines, f"U14: no failed event for the dummy login: {lines}")
        expect(
            "CliLoginRefusedError" in logs,
            "U14: the service log does not name the upstream's refusal of the login",
        )
        for secret in (person, workload, dummy):
            expect(secret not in shown + logs, "U14: a token was printed")
        self.held.append("U14")
        write_line(
            f"U14 held: the smoke exited {smoke.returncode}; its output was {lines}; no token "
            "in it or in the service log; the log ends "
            f"{logs.strip().splitlines()[-3:]}",
            flush=True,
        )


class Cell(StrEnum):
    UNIT = "unit"
    SMOKE = "smoke"
    CONTAINMENT = "containment"
    SIGNER = "signer"


PROBES = {
    Cell.UNIT: UnitProbe,
    Cell.SMOKE: SmokeProbe,
    Cell.CONTAINMENT: ContainmentProbe,
    Cell.SIGNER: SignerProbe,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=scratch_directory, required=True)
    parser.add_argument("--cell", type=Cell, choices=list(Cell), default=Cell.UNIT)
    arguments = parser.parse_args()
    return run_probe(lambda: PROBES[arguments.cell](arguments.scratch))


if __name__ == "__main__":
    sys.exit(main())
