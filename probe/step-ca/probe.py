"""Probe of the internal CA and of traefik-mcp (#38 proofs 1-5, #48 proofs 6-9, #52 proof 10,
#60 proof 11, #69 proof 12, #89 proof 13, #346 cells P13-P27): a throwaway compose project and a
throwaway HOME.

It runs the real `step-ca/init` against the scratch HOME, starts the real `step-ca`, `traefik-mcp`
and `hello-mcp` services from compose.yaml and ca.json under their own compose project name, checks
the proofs and always removes its containers, networks and volumes. It never touches the live
stack: the project name and HOME are set in the environment of every command, and its compose
calls resolve only the project's networks (edge_copy.py, P26).

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/step-ca/probe.py --scratch DIR  # teardown measured 1 s (K 30 s, CAP 1800 s)

The CA and the gateway are only reachable on their internal compose networks, so every call to
them runs from a throwaway container on the network a client would sit on. Needs an empty or new
--scratch directory. Proof 9 waits for a renewal, 10 runs three applies, 11 drives the emergency
switch, 12 runs the setup from `hal apply`, 13 lets traefik-mcp follow its file and definition
through about ten applies (traefik_mcp_follows.py), and 14 drives songmaker's route (#346
P13-P27, mcp_networks.py): 13 to 20 minutes measured, 10 of them proof 9's renewal wait, bounded
by the 1800 s cap above, so a run that needs longer is cut, not given more. Needs `uv`: proof 8 runs
`hal check exposure` through it, proofs 10 to 13 `uv sync` in a copy of the repository. The copy
is a clean `main` with a bare remote under the scratch directory, and every edit a proof makes
there is published (committed and pushed) before the apply that follows it (#95 P3).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import cached_property
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "probe" / "step-ca"), str(REPO / "probe")]  # also when loaded by path
sys.path.insert(0, str(REPO / "src"))  # edge's own facts; its modules need only the stdlib

import edge_copy  # noqa: E402
import health  # noqa: E402
from edge_copy import (  # noqa: E402
    DISCARD_OUTPUT,
    GUARDED_COMPOSE_VERBS,
    HAL_FAILURE,
    ProbeFailed,
    expect,
    publish,
    run_hal,
)
from edge_copy import repository_copy as copy_repository  # noqa: E402
from mcp_networks import McpNetworks, print_verdict  # noqa: E402
from step_ca_names import (  # noqa: E402
    CA_URL,
    CERTIFICATE_UNVERIFIED,
    COMPOSE_FILE,
    CONTAINER_USER,
    CONTAINER_USER_ID,
    INTERMEDIATE_CERTIFICATE,
    INTERMEDIATE_IN_VOLUME,
    NOTHING_TO_CHANGE,
    ORIGIN,
    ORIGIN_ANSWER,
    ORIGIN_URL,
    PROJECT,
    READY_SECONDS,
    ROOT_CERTIFICATE,
    ROOT_IN_CLIENT,
    STEP_HOME,
)
from traefik_mcp_follows import TraefikMcpFollows  # noqa: E402

from hal.output import write_line  # noqa: E402

NETWORK = f"{PROJECT}_mcp-ca"
PROVISIONER = "acme"
DIRECTORY_URL = f"{CA_URL}/acme/{PROVISIONER}/directory"
INTERMEDIATE_KEY = "secrets/intermediate_ca_key"
WORK_DIRECTORY = "/work"  # private tmpfs for the ACME client, not world-writable
ALLOWED_FILES = {
    f"certs/{ROOT_CERTIFICATE}",
    INTERMEDIATE_CERTIFICATE,
    INTERMEDIATE_KEY,
}
ALLOWED_DIRECTORY = "db/"
OUTSIDE_NAME = "outside.example.com"
INSIDE_NAME = "probe.mcp.internal"
REFUSAL = "will not issue certificates for the identifier"  # ACME rejectedIdentifier
# Plain http is the point: proof 6 sends http to the TLS port and expects a refusal.
ORIGIN_PLAIN_URL = f"http://{ORIGIN}:443/"  # NOSONAR(S5332)
TRAEFIK_USER = "65534:65534"
TRAEFIK_UID = 65534
ACME_STORAGE = "/acme/acme.json"
EXPOSURE_CHECK = ["uv", "run", "--quiet", "hal", "check", "exposure", "--json"]
EXIT_AFTER_TERM = 143  # 128 + SIGTERM; a forced kill after the grace period is 137
BOOT_WITHOUT_CA_SECONDS = 10  # how long the gateway has to sit idle before the CA appears
LISTENER_PORTS_OF_THE_PROBE = (9000, 443)  # the CA and the gateway: container ports only
CA_DEFAULT_LIFETIME_SECONDS = 24 * 3600
CA_BACKDATE_SECONDS = 60  # step-ca starts a certificate one minute before it was issued
SHORT_LIFETIME_MINUTES = 20  # probe-only: renewal inside the poll
RENEWAL_POLL_SECONDS = 12 * 60
RENEWAL_POLL_INTERVAL = 15
FOREIGN_UID = 12345
STEP_CA_SWITCH = re.compile(r"( {2}step-ca:\n {4}run:\n {6}enabled: )(?:true|false)")
ASKING_SWITCHES = re.compile(r"( {2}(?:keycloak|agent-service):\n {4}run:\n {6}enabled: )\w+")
STAND_IN_OVERLAY = REPO / "probe" / "step-ca" / "compose.probe.yaml"
SHORT_LIVED_OVERLAY = REPO / "probe" / "step-ca" / "compose.short-lived.probe.yaml"


class Probe(McpNetworks, TraefikMcpFollows):
    def __init__(self, scratch: Path) -> None:
        self.home = scratch / "home"
        self.home.mkdir(parents=True)
        self.not_driven: list[str] = []  # cells that could not run: the verdict is incomplete
        self.secrets_dir = self.home / ".secrets" / "step-ca"
        self.environment = {
            **os.environ,
            "HOME": str(self.home),
            "COMPOSE_PROJECT_NAME": PROJECT,
            "EDGE_DOMAIN": "probe.invalid",
            "DOCKER_GID": "0",
        }
        self.environment.pop("DOCKER_STEPCA_INIT_PASSWORD", None)
        self.scratch = scratch
        self.compose_file = scratch / COMPOSE_FILE
        self.compose_file.write_text(
            edge_copy.namespaced_compose((REPO / COMPOSE_FILE).read_text(), PROJECT)
        )
        self.compose_files = [self.compose_file, STAND_IN_OVERLAY]
        self.guard = edge_copy.NetworkGuard(PROJECT, lambda command: self.run(command).stdout)
        self.listeners_before: set[str] = set()
        self.exposure_before: list[dict] = []
        self.intermediate_fingerprint = ""

    def run(
        self, command: list[str], *, stdin: bytes | None = None, check: bool = True,
        own_session: bool = False,
    ):  # fmt: skip
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            command, capture_output=True, input=stdin, env=self.environment, cwd=REPO,
            check=False, timeout=240, close_fds=True, start_new_session=own_session,
        )  # fmt: skip
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).decode(errors="replace").strip().splitlines()
            raise ProbeFailed(f"{' '.join(command[:4])} exited {result.returncode}: {tail[-1:]}")
        return result

    def compose(self, *args: str, check: bool = True, own_session: bool = False, all_units=False):
        command = [
            "docker", "compose", "--project-directory", str(REPO),
            *[flag for file in self.compose_files for flag in ("--file", str(file))],
            *(["--profile", "*"] if all_units else ["--profile", "probe", "--profile", "step-ca"]),
        ]  # fmt: skip
        if args[0] in GUARDED_COMPOSE_VERBS:
            self.guard.expect(command)
        return self.run([*command, *args], check=check, own_session=own_session)

    def container_id(self, service: str) -> str:
        return self.compose("ps", "--all", "-q", service).stdout.decode().strip()

    def init(self, *, check: bool = True) -> str:
        result = self.run([str(REPO / "step-ca" / "init")], check=check)
        return result.stdout.decode() + result.stderr.decode()

    @cached_property
    def composed(self) -> dict:
        """What compose resolves once per run: the images and the volumes' real names."""
        return json.loads(self.compose("config", "--format", "json").stdout)

    def image_and_volume(self) -> tuple[str, str]:
        return self.composed["services"]["step-ca"]["image"], self.composed["volumes"]["step-ca"][
            "name"
        ]

    def in_volume(self, *tool: str, writable: bool = False) -> bytes:
        image, volume = self.image_and_volume()
        mount = f"{volume}:{STEP_HOME}" + ("" if writable else ":ro")
        return self.run(
            ["docker", "run", "--rm", "--network", "none", "--user", CONTAINER_USER, "--entrypoint",
             tool[0], "--volume", mount, image, *tool[1:]]
        ).stdout  # fmt: skip

    def volume_files(self) -> set[str]:
        listing = self.in_volume("find", STEP_HOME, "-type", "f").decode().splitlines()
        return {line.removeprefix(f"{STEP_HOME}/") for line in listing}

    def expect_volume_has_compose_labels(self) -> None:
        _, volume = self.image_and_volume()
        labels = json.loads(
            self.run(["docker", "volume", "inspect", "--format", "{{json .Labels}}", volume]).stdout
        )
        expected = {"com.docker.compose.project": PROJECT, "com.docker.compose.volume": "step-ca"}
        expect(expected.items() <= labels.items(), f"the volume lacks its compose labels: {labels}")

    # --- the CA over TLS ----------------------------------------------------------------------

    def client(self, network: str, *curl_arguments: str, root: Path | None = None):
        """curl as a throwaway client on one of the project's networks; `root` is the only trust."""
        return self.curl(f"{PROJECT}_{network}", curl_arguments, root)

    def directory_status(self, cafile: Path | None) -> int:
        """The directory's HTTP status as a throwaway container on the CA's network sees it, or -1
        when the certificate does not verify; raises OSError while the CA is not answering."""
        result = self.client(
            "mcp-ca", "--output", DISCARD_OUTPUT, "--write-out", "%{http_code}", DIRECTORY_URL,
            root=cafile,
        )  # fmt: skip
        if result.returncode == CERTIFICATE_UNVERIFIED:
            return -1
        if result.returncode != 0:
            raise ConnectionError(f"curl exited {result.returncode}")
        return int(result.stdout)

    def order_outcome(self, name: str) -> tuple[int, str]:
        """Asks the CA for a certificate for `name` with the pinned image's own ACME client."""
        image, _ = self.image_and_volume()
        owner = f"uid={CONTAINER_USER_ID},gid={CONTAINER_USER_ID}"
        private_tmpfs = f"{WORK_DIRECTORY}:{owner},mode=0700"
        root_mount = f"{self.secrets_dir / ROOT_CERTIFICATE}:/root.crt:ro"
        certificate_path, key_path = f"{WORK_DIRECTORY}/c.crt", f"{WORK_DIRECTORY}/c.key"
        result = self.run(
            ["docker", "run", "--rm", "--network", NETWORK, "--tmpfs", private_tmpfs,
             "--read-only", "--user", CONTAINER_USER, "--volume", root_mount,
             "--entrypoint", "step", image, "ca", "certificate", name, certificate_path, key_path,
             "--acme", DIRECTORY_URL, "--root", "/root.crt", "--force"],
            check=False,
        )  # fmt: skip
        return result.returncode, (result.stderr + result.stdout).decode(errors="replace")

    def expect_outside_name_rejected(self) -> None:
        outside_code, outside_text = self.order_outcome(OUTSIDE_NAME)
        _, inside_text = self.order_outcome(INSIDE_NAME)
        expect(outside_code != 0, f"the CA ordered a certificate for {OUTSIDE_NAME}")
        expect(
            REFUSAL in outside_text,
            f"the refusal of {OUTSIDE_NAME} was not refused: {outside_text.strip()[-160:]}",
        )
        expect(
            REFUSAL not in inside_text,
            f"the CA refused {INSIDE_NAME}: {inside_text.strip()[-160:]}",
        )

    def poll_until(self, what: str, seconds: float, attempt: Callable[[], bool]) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                if attempt():
                    return
            except OSError:
                pass
            time.sleep(1)
        raise ProbeFailed(f"{what} did not happen within {seconds:.0f} s")

    def wait_until_answering(self) -> None:
        root = self.secrets_dir / ROOT_CERTIFICATE
        try:
            self.poll_until(
                "the CA answering", READY_SECONDS, lambda: self.directory_status(root) == 200
            )
        except ProbeFailed as failure:
            logs = self.compose("logs", "--no-color", "--tail", "5", "step-ca", check=False)
            raise ProbeFailed(f"{failure}: {logs.stdout.decode()[-300:]}") from failure

    def certificate_fingerprint(self, certificate: bytes) -> str:
        result = self.run(
            ["openssl", "x509", "-noout", "-fingerprint", "-sha256"], stdin=certificate
        )
        return result.stdout.decode().strip()

    def public_key(self, command: list[str], stdin: bytes) -> bytes:
        return self.run(command, stdin=stdin).stdout

    # --- the proofs ---------------------------------------------------------------------------

    def proof_1_init(self) -> None:
        first = self.init()
        password = (self.secrets_dir / "password").read_text()
        modes = {
            name: stat.S_IMODE((self.secrets_dir / name).stat().st_mode)
            for name in ("root_ca_key", ROOT_CERTIFICATE, "password")
        }
        directory_mode = stat.S_IMODE(self.secrets_dir.stat().st_mode)
        expect(directory_mode == 0o700, f"directory mode {oct(directory_mode)}")
        expect(
            modes == {"root_ca_key": 0o600, ROOT_CERTIFICATE: 0o644, "password": 0o644},
            f"modes {modes}",
        )
        self.expect_volume_has_compose_labels()
        second = self.init()
        expect("nothing changed" in second, f"second run: {second.strip()[-120:]}")
        for output in (first, second):
            expect(password not in output, "the output holds the password")
            expect("PRIVATE KEY" not in output, "the output holds a private key")
        write_line(
            "proof 1 held: modes 0700/0600/0644/0644; second run `nothing changed`; output silent"
        )

    def proof_2_directory(self) -> None:
        self.compose("up", "--detach", "step-ca")
        self.wait_until_answering()
        status = self.directory_status(self.secrets_dir / ROOT_CERTIFICATE)
        expect(status == 200, f"directory answered {status}")
        expect(self.directory_status(None) == -1, "the system trust store verified the CA")
        self.expect_outside_name_rejected()
        write_line(
            f"proof 2 held: {DIRECTORY_URL} -> 200 with the probe root; fails without it; "
            f"an order for {OUTSIDE_NAME} is refused by the policy"
        )

    def proof_3_volume(self) -> None:
        files = self.volume_files()
        stray = {f for f in files if f not in ALLOWED_FILES and not f.startswith(ALLOWED_DIRECTORY)}
        expect(not stray, f"files outside the allow-list: {sorted(stray)}")
        expect(files >= ALLOWED_FILES, f"missing: {sorted(ALLOWED_FILES - files)}")
        root_certificate = (self.secrets_dir / ROOT_CERTIFICATE).read_bytes()
        root_public = self.public_key(["openssl", "x509", "-noout", "-pubkey"], root_certificate)
        password = self.secrets_dir / "password"
        for name in sorted(files):
            content = self.in_volume("cat", f"{STEP_HOME}/{name}")
            if b"PRIVATE KEY" not in content:
                continue
            public = self.public_key(
                ["openssl", "pkey", "-pubout", "-passin", f"file:{password}"], content
            )
            expect(public != root_public, f"{name} is the root key")
        write_line(
            f"proof 3 held: {len(files)} files, all allow-listed; no key in it matches the root"
        )

    def proof_4_restart(self) -> None:
        intermediate = self.in_volume("cat", INTERMEDIATE_IN_VOLUME)
        before = (self.certificate_fingerprint(intermediate), self.volume_files())
        self.compose("restart", "step-ca")
        self.wait_until_answering()
        intermediate = self.in_volume("cat", INTERMEDIATE_IN_VOLUME)
        after = (self.certificate_fingerprint(intermediate), self.volume_files())
        expect(after[0] == before[0], f"intermediate changed: {before[0]} -> {after[0]}")
        expect(before[1] <= after[1], f"db files lost: {sorted(before[1] - after[1])}")
        write_line(f"proof 4 held after restart: {after[0]}; {len(after[1])} files, none lost")

    def chown_root_key(self, owner_id: int) -> None:
        image, _ = self.image_and_volume()
        self.run(
            ["docker", "run", "--rm", "--network", "none", "--user", "0", "--cap-drop", "ALL",
             "--cap-add", "CHOWN", "--cap-add", "DAC_OVERRIDE", "--volume",
             f"{self.secrets_dir}:/secrets", "--entrypoint", "chown", image,
             f"{owner_id}:{owner_id}", "/secrets/root_ca_key"]
        )  # fmt: skip

    def expect_foreign_owned_root_key_refused(self, root_key: bytes) -> None:
        """A root key the image's user cannot read ends init in one line, with the key untouched."""
        self.chown_root_key(FOREIGN_UID)
        try:
            output = self.init(check=False)
            owner = (self.secrets_dir / "root_ca_key").stat().st_uid
        finally:
            self.chown_root_key(os.getuid())
        expect(owner == FOREIGN_UID, "the foreign owner of the root key was changed")
        expect("FAILED" in output and "permission denied" in output, f"init said: {output[-160:]}")
        expect("PRIVATE KEY" not in output, "the refusal shows a private key")
        expect(len(output.strip().splitlines()) <= 2, f"more than one line: {output[-160:]}")
        expect((self.secrets_dir / "root_ca_key").read_bytes() == root_key, "root key changed")
        expect(INTERMEDIATE_CERTIFICATE not in self.volume_files(), "an intermediate was made")

    def proof_5_partial(self) -> None:
        self.compose("stop", "step-ca")
        root_key = (self.secrets_dir / "root_ca_key").read_bytes()
        self.in_volume(
            "rm", INTERMEDIATE_IN_VOLUME, f"{STEP_HOME}/{INTERMEDIATE_KEY}",
            writable=True,
        )  # fmt: skip
        expect(INTERMEDIATE_CERTIFICATE not in self.volume_files(), "the intermediate stayed")
        self.expect_foreign_owned_root_key_refused(root_key)
        output = self.init()
        expect("intermediate" in output, f"init did not report the intermediate: {output[-120:]}")
        expect((self.secrets_dir / "root_ca_key").read_bytes() == root_key, "root key changed")
        expect(self.volume_files() >= ALLOWED_FILES, "the intermediate was not completed")
        self.compose("start", "step-ca")
        self.wait_until_answering()
        write_line(
            "proof 5 held: init completed the intermediate; root key byte-for-byte unchanged"
        )

    # --- traefik-mcp ---------------------------------------------------------------------------

    def host_listeners(self) -> set[str]:
        lines = self.run(["ss", "-Hltn"]).stdout.decode().splitlines()
        return {line.split()[3] for line in lines}

    def exposure_findings(self) -> list[dict]:
        """What `hal check exposure` reports about the whole host; exit 1 only means findings."""
        result = self.run(EXPOSURE_CHECK, check=False)
        try:
            findings = json.loads(result.stdout)["exposure"]
        except (ValueError, KeyError, TypeError):
            findings = None
        stderr_tail = result.stderr.decode(errors="replace").strip().splitlines()[-1:]
        expect(
            result.returncode in (0, 1) and isinstance(findings, list),
            f"hal check exposure exited {result.returncode} without findings: {stderr_tail}",
        )
        return findings

    def intermediate_certificate(self) -> dict:
        output = self.in_volume(
            "step", "certificate", "inspect", "--format", "json", INTERMEDIATE_IN_VOLUME
        )  # fmt: skip
        return json.loads(output)

    def served_certificate(self) -> dict:
        """What a client on `mcp` is served for the origin, verified against the probe root."""
        image, _ = self.image_and_volume()
        root_mount = f"{self.secrets_dir / ROOT_CERTIFICATE}:{ROOT_IN_CLIENT}:ro"
        result = self.run(
            ["docker", "run", "--rm", "--network", f"{PROJECT}_mcp", "--read-only", "--user",
             CONTAINER_USER, "--volume", root_mount, "--entrypoint", "step", image,
             "certificate", "inspect", "--format", "json", "--roots", ROOT_IN_CLIENT, ORIGIN_URL],
            check=False,
        )  # fmt: skip
        if result.returncode != 0:
            raise ConnectionError(f"step exited {result.returncode}")
        return json.loads(result.stdout)

    def wait_until_served(self) -> dict:
        root = self.secrets_dir / ROOT_CERTIFICATE

        def answers() -> bool:
            result = self.client("mcp", ORIGIN_URL, root=root)
            return ORIGIN_ANSWER in result.stdout.decode(errors="replace")

        self.poll_until(f"{ORIGIN_URL} answering with the backend", READY_SECONDS, answers)
        return self.served_certificate()

    def expect_certificate_length(self, certificate: dict, lifetime_seconds: int) -> None:
        length = certificate["validity"]["length"]
        expected = lifetime_seconds + CA_BACKDATE_SECONDS
        expect(length == expected, f"the certificate is valid for {length} s, not {expected} s")

    def boot_gateway_before_the_ca(self) -> dict:
        """Traefik asks the CA once at start; the gateway must wait for the CA, not stay without."""
        self.compose("stop", "step-ca")
        self.compose("run", "--rm", "--no-deps", "traefik-mcp-acme-owner")
        self.compose("up", "--detach", "--no-deps", "traefik-mcp", "hello-mcp")
        time.sleep(BOOT_WITHOUT_CA_SECONDS)
        answer = self.client("mcp", ORIGIN_URL, root=self.secrets_dir / ROOT_CERTIFICATE)
        expect(ORIGIN_ANSWER not in answer.stdout.decode(errors="replace"), "served without a CA")
        self.expect_waiting_gateway_stops_on_term()
        self.compose("up", "--detach", "--no-deps", "traefik-mcp")
        self.compose("start", "step-ca")
        self.wait_until_answering()
        return self.wait_until_served()

    def expect_waiting_gateway_stops_on_term(self) -> None:
        """The wait is a shell, not Traefik: TERM must end it, not Docker's kill after the grace."""
        logs = self.compose("logs", "--no-color", "traefik-mcp").stdout
        expect(bool(logs.strip()), "the gateway waiting for the CA said nothing")
        self.compose("stop", "traefik-mcp")
        container = self.compose("ps", "--all", "--quiet", "traefik-mcp").stdout.decode().strip()
        code = self.run(["docker", "inspect", "--format", "{{.State.ExitCode}}", container])
        exit_code = int(code.stdout)
        expect(exit_code == EXIT_AFTER_TERM, f"the waiting gateway exited {exit_code} on stop")

    def acme_storage(self) -> tuple[int, int]:
        """Size and owner of the stored certificates in the volume; raises OSError until written."""
        traefik = self.composed["services"]["traefik-mcp"]["image"]
        volume = self.composed["volumes"]["traefik-mcp-acme"]["name"]
        result = self.run(
            ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", TRAEFIK_USER,
             "--volume", f"{volume}:{Path(ACME_STORAGE).parent}:ro", "--entrypoint", "stat",
             traefik, "-c", "%s %u", ACME_STORAGE],
            check=False,
        )  # fmt: skip
        if result.returncode != 0:
            raise FileNotFoundError(ACME_STORAGE)
        size, owner = result.stdout.split()
        return int(size), int(owner)

    def wait_until_stored(self) -> None:
        """The volume is persistent and uid 65534 can write it: Traefik only logs when it cannot."""

        def written() -> bool:
            size, owner = self.acme_storage()
            expect(owner == TRAEFIK_UID, f"{ACME_STORAGE} belongs to uid {owner}")
            return size > 0

        self.poll_until(f"{ACME_STORAGE} written", READY_SECONDS, written)

    def expect_certificate_survives_gateway_restart(self, served: dict) -> None:
        """A restart with the CA down serves the stored certificate; it is not issued again."""
        self.compose("stop", "step-ca")
        self.compose("restart", "traefik-mcp")
        restarted = self.wait_until_served()
        self.compose("start", "step-ca")
        self.wait_until_answering()
        expect(
            restarted["serial_number"] == served["serial_number"],
            "the restarted gateway served another certificate than the stored one",
        )

    def proof_6_gateway(self) -> None:
        self.listeners_before = self.host_listeners()
        self.exposure_before = self.exposure_findings()
        root = self.secrets_dir / ROOT_CERTIFICATE
        served = self.boot_gateway_before_the_ca()
        intermediate = self.intermediate_certificate()
        expect(served["issuer_dn"] == intermediate["subject_dn"], "not issued by the intermediate")
        self.expect_certificate_length(served, CA_DEFAULT_LIFETIME_SECONDS)
        unverified = self.client("mcp", ORIGIN_URL)
        expect(
            unverified.returncode == CERTIFICATE_UNVERIFIED,
            f"without the root: {unverified.returncode}",
        )
        plain = self.client("mcp", "--include", ORIGIN_PLAIN_URL, root=root)
        expect(
            ORIGIN_ANSWER not in plain.stdout.decode(errors="replace"),
            "plain HTTP reached the backend",
        )
        self.wait_until_stored()
        self.expect_certificate_survives_gateway_restart(served)
        length, issuer = served["validity"]["length"], intermediate["subject_dn"]
        write_line(
            f"proof 6 held: gateway booted before the CA and issued once it listened; {ORIGIN_URL} "
            f"-> backend answer with the probe root; certificate of {length} s from `{issuer}`; "
            f"without the root curl exit {unverified.returncode}; plain http on 443: exit "
            f"{plain.returncode}, no backend answer; acme.json kept by uid {TRAEFIK_UID} and "
            f"the same certificate served after a restart with the CA down"
        )

    def proof_8_no_host_listener(self) -> None:
        new_listeners = self.host_listeners() - self.listeners_before
        expect(not new_listeners, f"new host listeners: {sorted(new_listeners)}")
        ports = {listener.rsplit(":", 1)[1] for listener in self.host_listeners()}
        taken = ports & {str(port) for port in LISTENER_PORTS_OF_THE_PROBE}
        expect(not taken, f"the host listens on {sorted(taken)}")
        new_findings = [f for f in self.exposure_findings() if f not in self.exposure_before]
        expect(not new_findings, f"hal check exposure reports something new: {new_findings}")
        write_line(
            f"proof 8 held: ss -ltn unchanged ({len(self.listeners_before)} listeners), none on "
            f"{LISTENER_PORTS_OF_THE_PROBE}; hal check exposure reports nothing new"
        )

    def remove_stored_certificates(self) -> None:
        traefik = self.composed["services"]["traefik-mcp"]["image"]
        volume = self.composed["volumes"]["traefik-mcp-acme"]["name"]
        self.run(
            ["docker", "run", "--rm", "--network", "none", "--read-only", "--user", TRAEFIK_USER,
             "--volume", f"{volume}:{Path(ACME_STORAGE).parent}", "--entrypoint", "rm", traefik,
             "-f", ACME_STORAGE]
        )  # fmt: skip

    def use_short_lived_certificates(self) -> None:
        """Probe-only ca.json: the repository's, plus a 20 minute default certificate lifetime."""
        ca = json.loads((REPO / "step-ca" / "ca.json").read_text())
        ca["authority"]["provisioners"][0]["claims"] = {
            "defaultTLSCertDuration": f"{SHORT_LIFETIME_MINUTES}m"
        }
        short_ca = self.scratch / "ca-short-lived.json"
        short_ca.write_text(json.dumps(ca))
        self.environment["PROBE_CA_JSON"] = str(short_ca)
        self.compose_files = [self.compose_file, STAND_IN_OVERLAY, SHORT_LIVED_OVERLAY]

    @property
    def state_directory(self) -> Path:
        """Where edge keeps its markers and its applied record under the probe's HOME."""
        return self.home / ".local" / "state" / "edge"

    def traefik_started_at(self) -> str:
        container = self.compose("ps", "--quiet", "traefik-mcp").stdout.decode().strip()
        started = self.run(["docker", "inspect", "--format", "{{.State.StartedAt}}", container])
        return started.stdout.decode().strip()

    def proof_9_renewal(self) -> None:
        self.compose("stop", "traefik-mcp")
        self.remove_stored_certificates()
        self.use_short_lived_certificates()
        self.compose("up", "--detach", "step-ca")
        self.wait_until_answering()
        self.compose("up", "--detach", "traefik-mcp")
        first = self.wait_until_served()
        self.expect_certificate_length(first, SHORT_LIFETIME_MINUTES * 60)
        started_at = self.traefik_started_at()
        waited = time.monotonic()
        renewed = first
        while renewed["serial_number"] == first["serial_number"]:
            expect(time.monotonic() - waited < RENEWAL_POLL_SECONDS, "no renewal within 12 minutes")
            time.sleep(RENEWAL_POLL_INTERVAL)
            renewed = self.served_certificate()
        expiry = datetime.fromisoformat(first["validity"]["end"])
        expect(datetime.now(UTC) < expiry, "the old certificate had expired before the renewal")
        expect(self.traefik_started_at() == started_at, "traefik-mcp restarted")
        old, new = first["serial_number"][-8:], renewed["serial_number"][-8:]
        write_line(
            f"proof 9 held: serial ...{old} -> ...{new} after {time.monotonic() - waited:.0f} s, "
            f"the old one valid until {first['validity']['end']}, traefik-mcp not restarted"
        )

    # --- hal apply --local switches the unit and keeps its data (#52 rule 3) -----------------

    def repository_copy(self) -> Path:
        """The lane's files as the scratch HOME's live checkout; only its fleet.yaml is flipped."""
        return copy_repository(REPO, self.home, self.scratch, PROJECT)

    def set_enabled(self, copy: Path, enabled: bool) -> None:
        """Set step-ca's switch; keycloak and agent-service go off: their setups ask."""
        fleet = copy / "fleet.yaml"
        text, step_ca_matches = STEP_CA_SWITCH.subn(
            rf"\g<1>{str(enabled).lower()}", fleet.read_text()
        )
        text, asking_matches = ASKING_SWITCHES.subn(r"\g<1>false", text)
        expect(
            (step_ca_matches, asking_matches) == (1, 2),
            "fleet.yaml lacks exactly one step-ca, keycloak and agent-service switch",
        )
        fleet.write_text(text)
        publish(copy, f"probe: step-ca enabled {enabled}")

    def hal(
        self, copy: Path, *arguments: str, terminal: bool, fails: bool = False,
        typed: bytes = b"yes\n",
    ) -> str:  # fmt: skip
        if arguments[0] in ("apply", "start"):
            self.guard.expect(edge_copy.copy_compose_command(copy), once=False)
        exit_code = HAL_FAILURE if fails else 0
        return run_hal(
            copy, self.environment, *arguments, terminal=terminal, exit_code=exit_code, typed=typed
        )

    def hal_apply(self, copy: Path, enabled: bool) -> str:
        self.set_enabled(copy, enabled)
        return self.hal(copy, "apply", "--local", terminal=True)

    def volume_names(self) -> list[str]:
        return [self.composed["volumes"][key]["name"] for key in ("step-ca", "traefik-mcp-acme")]

    def proof_10_apply_cycle(self) -> None:
        copy = self.repository_copy()
        self.compose("up", "--detach", "--no-deps", "hello-mcp")  # the origin behind the gateway
        self.hal_apply(copy, enabled=True)
        served_before = self.wait_until_served()
        before = self.certificate_fingerprint(self.in_volume("cat", INTERMEDIATE_IN_VOLUME))
        self.hal_apply(copy, enabled=False)
        left = (
            self.compose("ps", "--all", "-q", "step-ca", "traefik-mcp", "traefik-mcp-acme-owner")
            .stdout.decode()
            .strip()
        )
        expect(not left, f"containers of the unit are left after off: {left}")
        for volume in self.volume_names():
            self.run(["docker", "volume", "inspect", volume])  # a missing volume exits 1
        self.hal_apply(copy, enabled=True)
        self.wait_until_answering()
        served_after = self.wait_until_served()
        after = self.certificate_fingerprint(self.in_volume("cat", INTERMEDIATE_IN_VOLUME))
        expect(after == before, f"intermediate changed across off and on: {before} -> {after}")
        intermediate = self.intermediate_certificate()
        expect(
            served_before["extensions"]["authority_key_id"]
            == served_after["extensions"]["authority_key_id"]
            == intermediate["extensions"]["subject_key_id"],
            "not served by the same intermediate",
        )
        again = self.hal_apply(copy, enabled=True)
        expect(NOTHING_TO_CHANGE in again, f"a repeated apply said: {again[-120:]}")
        self.intermediate_fingerprint = after
        write_line(
            f"proof 10 held: hal apply on/off/on keeps both volumes; same intermediate {after}"
        )

    # --- the emergency switch survives apply and keeps the data (#60) --------------------------

    def containers_of_unit(self, *, running_only: bool) -> list[str]:
        status = ["--status", "running"] if running_only else []
        return (
            self.compose("ps", "--all", "-q", *status, "step-ca", "traefik-mcp")
            .stdout.decode()
            .split()
        )

    def proof_11_emergency_switch(self) -> None:
        copy = self.repository_copy()
        marker = self.state_directory / "stopped" / "step-ca"
        self.set_enabled(copy, True)

        self.hal(copy, "stop", "step-ca", terminal=False)  # 1. A x stop: R4, no terminal
        expect(marker.is_file(), "stop wrote no marker")
        expect(not self.containers_of_unit(running_only=True), "a container runs after stop")
        expect(len(self.containers_of_unit(running_only=False)) == 2, "stop removed a container")
        self.volume_names_exist()
        written = marker.read_text()

        out = self.hal(copy, "stop", "step-ca", terminal=False)  # 2. B x stop
        expect("already off since" in out, f"a second stop said: {out[-120:]}")
        expect(marker.read_text() == written, "a second stop rewrote the marker")

        out = self.hal(copy, "apply", "--local", terminal=True)  # 3. B x apply, enabled
        expect("stays stopped" in out and NOTHING_TO_CHANGE in out, f"apply said: {out[-160:]}")
        expect("Type" not in out, "apply asked for `yes` with nothing to change")
        expect(not self.containers_of_unit(running_only=True), "apply started a switched-off unit")

        self.hal(copy, "start", "step-ca", terminal=False, fails=True)  # 4. B x start, no terminal
        expect(marker.read_text() == written, "a refused start touched the marker")

        self.set_enabled(copy, False)  # 5. B x apply, disabled: to E, marker and volumes stay
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect("its switch since" in out, f"apply to E said: {out[-160:]}")
        expect(not self.containers_of_unit(running_only=False), "off left containers")
        expect(marker.read_text() == written, "apply to E cleared the marker")
        self.volume_names_exist()

        out = self.hal(copy, "stop", "step-ca", terminal=False)  # 6. E x stop
        expect("nothing of it runs" in out, f"stop in E said: {out[-120:]}")
        expect(marker.read_text() == written, "stop in E touched the marker")

        out = self.hal(copy, "start", "step-ca", terminal=True, fails=True)  # 7. E x start
        expect("disabled in the catalog" in out, f"start in E said: {out[-120:]}")

        self.set_enabled(copy, True)  # 8. E x apply, enabled, marker present: to B
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect("stays stopped" in out, f"apply to B said: {out[-160:]}")
        expect(not self.containers_of_unit(running_only=False), "apply created a container")

        self.hal(copy, "start", "step-ca", terminal=True)  # 9. B x start, yes: to A
        expect(not marker.exists(), "start left the marker")
        self.wait_until_answering()
        expect(len(self.containers_of_unit(running_only=True)) == 2, "start did not run both")
        served = self.wait_until_served()
        after = self.certificate_fingerprint(self.in_volume("cat", INTERMEDIATE_IN_VOLUME))
        expect(after == self.intermediate_fingerprint, f"intermediate changed: {after}")
        expect(served["extensions"]["authority_key_id"], "nothing served after start")

        out = self.hal(copy, "start", "step-ca", terminal=True)  # 10. A x start
        expect("no change" in out, f"start in A said: {out[-120:]}")
        out = self.hal(copy, "apply", "--local", terminal=True)  # 11. A x apply
        expect(NOTHING_TO_CHANGE in out, f"apply in A said: {out[-120:]}")
        write_line(
            "proof 11 held: stop/start/apply cells A, B, E; switch kept across apply and off"
        )

    # --- hal apply asks for a missing setup and runs it in the terminal (#69) ------------------

    def start_without_keys(self) -> Path:
        """No keys, no volumes, no containers; an enabled copy of the repository."""
        self.compose(
            "down", "--volumes", "--remove-orphans", "--timeout", "10", own_session=True
        )  # fmt: skip
        shutil.rmtree(self.secrets_dir, ignore_errors=False)
        copy = self.repository_copy()
        self.set_enabled(copy, True)
        return copy

    def volumes_that_exist(self) -> list[str]:
        return [
            volume
            for volume in self.volume_names()
            if self.run(["docker", "volume", "inspect", volume], check=False).returncode == 0
        ]

    def proof_12_apply_runs_the_setup(self) -> None:
        copy = self.start_without_keys()

        out = self.hal(copy, "apply", "--local", terminal=True, fails=True, typed=b"no\n")
        expect("aborted, nothing changed" in out, f"a no said: {out[-160:]}")  # (i)
        expect(not self.secrets_dir.exists(), "keys exist after a no")
        expect(not self.volumes_that_exist(), "a volume exists after a no")
        expect(not self.containers_of_unit(running_only=False), "a container exists after a no")

        out = self.hal(copy, "apply", "--local", terminal=True, typed=b"yes\nyes\n")  # (ii)
        expect("is not set up" in out and "the plan" in out, f"yes, yes said: {out[-200:]}")
        expect(out.index("is not set up") < out.index("the plan"), "the plan came first")
        expect((self.secrets_dir / "root_ca_key").is_file(), "the setup made no root key")
        self.run([str(REPO / "step-ca" / "init"), "--check"])
        self.wait_until_answering()
        expect(len(self.containers_of_unit(running_only=True)) == 2, "step-ca is not on")
        again = self.hal(copy, "apply", "--local", terminal=True)
        expect(NOTHING_TO_CHANGE in again, f"a repeated apply said: {again[-120:]}")
        write_line(
            "proof 12 held: no changes nothing; yes, yes runs step-ca/init, re-checks, plans, on"
        )

    def volume_names_exist(self) -> None:
        for volume in self.volume_names():
            self.run(["docker", "volume", "inspect", volume])

    def teardown(self) -> None:
        # Own session: a signal to the probe's process group must not reach these.
        self.compose(
            "down", "--volumes", "--remove-orphans", "--timeout", "10", check=False,
            own_session=True, all_units=True,  # apply also starts the copy's units, e.g. legal
        )  # fmt: skip
        left = self.run(
            ["docker", "ps", "-a", "-q", "--filter", f"label=com.docker.compose.project={PROJECT}"],
            own_session=True,
        ).stdout.decode()
        volumes = self.run(
            ["docker", "volume", "ls", "-q", "--filter", f"name={PROJECT}_"], own_session=True
        ).stdout.decode()
        expect(
            not (left.strip() or volumes.strip()), f"left behind: {left.split()} {volumes.split()}"
        )
        self.guard.expect_clean_teardown()
        write_line(f"teardown: project {PROJECT} removed; the hal_ networks are unchanged (P26)")


@contextmanager
def stop_signals_ignored() -> Iterator[None]:
    """Teardown is what removes the containers and the volume, so a late SIGTERM or Ctrl-C must
    not cut it short."""
    stop_signals = (signal.SIGTERM, signal.SIGINT)
    previous = {number: signal.signal(number, signal.SIG_IGN) for number in stop_signals}
    try:
        yield
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=Path, required=True)
    arguments = parser.parse_args(argv)
    if arguments.scratch.exists() and any(arguments.scratch.iterdir()):
        write_line("PROBE FAILED: --scratch is not empty")
        return 3
    arguments.scratch.mkdir(parents=True, exist_ok=True)
    probe = Probe(arguments.scratch)
    signal.signal(signal.SIGTERM, raise_interrupt)  # `timeout` ends the probe with SIGTERM
    exit_code = 1
    try:
        exit_code = prove(probe)
    finally:
        with stop_signals_ignored():
            try:
                probe.teardown()
            except ProbeFailed as failure:
                write_line(f"PROBE FAILED: {failure}")
                exit_code = 1
    if exit_code == 0:
        exit_code = print_verdict(probe.not_driven)
    return exit_code


def raise_interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def prove(probe: Probe) -> int:
    try:
        probe.proof_1_init()
        probe.proof_2_directory()
        health.proof_2_health(probe)
        probe.proof_3_volume()
        probe.proof_4_restart()
        probe.proof_5_partial()
        probe.proof_6_gateway()
        probe.proof_7_network_split()
        probe.proof_8_no_host_listener()
        probe.proof_14_songmaker_route()
        probe.proof_9_renewal()
        probe.proof_10_apply_cycle()
        probe.proof_11_emergency_switch()
        probe.proof_12_apply_runs_the_setup()
        probe.proof_13_traefik_mcp_follows()
    except (ProbeFailed, subprocess.TimeoutExpired, OSError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
