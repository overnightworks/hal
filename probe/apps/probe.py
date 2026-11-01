"""Probe of deploy by tag (#255 P1, matrix block A): `hal apply --local` of a copy of the
repository switches on an app of a throwaway bare origin at its newest `vYYYY.MM.DD.N` tag, updates
it, and refuses or ends partial where block A says so.

Cells: A1 the first apply, A2 a second, A3 an update that keeps the volume's data, A4 a tag only on
a side branch, A7 a declined `yes`, A8 a tag never healthy, A9 a failed build, A12 containers
without a record, A18 a sentinel in an interpolation error, A23 an update interrupted midway, B5 an
image `VOLUME` that no named volume covers and covered, B8 a service with `pull_policy: always`, and
block C, `enabled: false` (`switched_off.py`): C1 an app switched off running, C2 on again at the
same tag, C3 off after a renamed service, a failed build, C4 off with `compose.yaml` unusable at
HEAD, C5 off with a leftover container. D and R: `emergency_switch.py`, `alias_routing.py`. hal's
exits: 0 or 3.

It never touches the live stack. It runs its own Traefik and socket proxy of a copy of the
repository under the compose project `edge-apps-probe`, on two free loopback ports instead of 8081
and 8090, constrained to a label key of its own (`probe-<random>.name`) instead of `edge.name`, so
the live Traefik's constraint never matches the probe's app and the probe's Traefik never matches a
live container; it sends no request to the live stack. The app, its checkout (`~/srv/<key>` under a
throwaway HOME) and its origin (a bare repository reached through `url.<file>.insteadOf`) are the
probe's own. The probe never runs `hal online`, `hal offline` or `--all`, so no tunnel is named. It
always removes its containers, volumes, networks and images, found by their compose project.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/apps/probe.py --scratch DIR [--switch-only]

Measured teardown: 2 s (K 50 s, CAP 1780 s).

Needs an empty or new --scratch directory, `uv` (it runs `uv sync` in the copy) and a Docker that
may pull busybox and Traefik.
"""

from __future__ import annotations

import argparse
import grp
import http.client
import json
import os
import re
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(REPO / "src"))  # edge's own facts; its modules need only the stdlib

import edge_copy  # noqa: E402
from alias_routing import AliasRouting  # noqa: E402
from edge_copy import HAL_FAILURE, HAL_OK, ProbeFailed, expect  # noqa: E402
from emergency_switch import EmergencySwitch  # noqa: E402
from switched_off import SwitchedOff  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import checkout  # noqa: E402

CORE_PROJECT = "edge-apps-probe"
DOMAIN = "probe.invalid"
ORGANISATION = "probe-org"
BUSYBOX = "busybox@sha256:bdf57e528e45e4433820e045b29b4597825a1c9e38353532d90a01445013f82e"
SENTINEL = "probe-sentinel-7c1e9b"  # a synthetic sensitive value that must never be printed
HEALTH_WAIT_SECONDS = 300
HAL_SECONDS = 900
COMPOSE_SECONDS = 300
READY_SECONDS = 90
REQUEST_SECONDS = 3
POLL_SECONDS = 0.5
NOT_RUNNABLE = 3
TAGS = {  # by cell, in the order they are cut: each is newer than the one before
    "a1": "v2026.10.22.1",
    "a3": "v2026.10.22.2",
    "a4_side": "v2026.10.22.9",
    "a7": "v2026.10.22.3",
    "a9": "v2026.10.22.4",
    "a8": "v2026.10.22.5",
    "fix": "v2026.10.22.6",
    "a18": "v2026.10.22.7",
    "a12": "v2026.10.22.8",
    "a23_first": "v2026.10.23.1",
    "a23_a": "v2026.10.23.2",
    "a23_b": "v2026.10.23.3",
    "b5_uncovered": "v2026.10.24.1",
    "b5_covered": "v2026.10.24.2",
    "b8": "v2026.10.24.3",
    "c3_renamed": "v2026.10.25.1",
    "c4_missing_ok": "v2026.10.25.3",
    "c4_missing": "v2026.10.25.4",
    "c4_invalid_ok": "v2026.10.25.5",
    "c4_invalid": "v2026.10.25.6",
    "d2": "v2026.10.24.4",
    "d4": "v2026.10.24.5",
    "c5_first": "v2026.10.26.1",
    "c5_second": "v2026.10.26.2",
    "h1": "v2026.10.26.3",
    "alias": "v2026.10.27.1",
    "alias_dropped": "v2026.10.27.2",
}
HEALTHCHECK = (
    '    healthcheck: {test: [CMD, wget, -q, -O, /dev/null, "http://127.0.0.1:8080/health"],\n'
    "      interval: 2s, timeout: 2s, retries: 3, start_period: 1s}\n"
)
HEALTHCHECKS = {"helper": "", "sealed": "    healthcheck: {disable: true}\n"}  # by service
# A service that no release of the app names
GHOST = f"services:\n  ghost:\n    image: {BUSYBOX}\n    command: [sleep, '3600']\n"
FORBIDDEN_VERBS = ("online", "offline", "--all")


def free_port() -> int:
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        return taken.getsockname()[1]


class Probe:
    def __init__(self, scratch: Path) -> None:
        self.scratch = scratch
        suffix = secrets.token_hex(3)
        self.key = f"apps-probe-{suffix}"
        self.label, self.alias_label = (f"probe-{suffix}.{field}" for field in ("name", "alias"))
        self.edge_port, self.admin_port = free_port(), free_port()
        self.home = scratch / "home"
        self.home.mkdir(parents=True)
        self.environment = {
            **os.environ,
            "HOME": str(self.home),
            "COMPOSE_PROJECT_NAME": CORE_PROJECT,
            "EDGE_DOMAIN": DOMAIN,
            "DOCKER_GID": str(grp.getgrnam("docker").gr_gid),
            "PROBE_SENTINEL": SENTINEL,
            "NO_COLOR": "1",
        }
        self.environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
        self.copy = checkout.live_checkout(self.home)
        self.srv = self.home / "srv" / self.key
        self.record = self.home / ".local" / "state" / "edge" / "deployed" / self.key
        self.origin = scratch / "app-origin.git"
        self.work = scratch / "app-work"
        self.shas: dict[str, str] = {}

    # --- docker ------------------------------------------------------------------------------

    def docker(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", *arguments], capture_output=True, env=self.environment,  # noqa: S607 - docker is found on PATH by design
            cwd=self.copy if self.copy.exists() else REPO, check=False, timeout=COMPOSE_SECONDS,
        )  # fmt: skip
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).decode(errors="replace").strip().splitlines()
            raise ProbeFailed(
                f"docker {' '.join(arguments[:2])} exited {result.returncode}: {tail[-1:]}"
            )
        return result

    def app_compose(
        self, *arguments: str, check: bool = True
    ) -> subprocess.CompletedProcess[bytes]:
        """Compose as `hal` calls it for the app: its project, bound to the checkout's file."""
        return self.docker(
            "compose", "-p", self.key, "--project-directory", str(self.srv), "--file",
            str(self.srv / "compose.yaml"), *arguments, check=check,
        )  # fmt: skip

    def containers(self) -> list[dict[str, str]]:
        """Every container of the app's project: id, name, state, health, service, tag label."""
        template = (
            '{{.ID}}|{{.Names}}|{{.State}}|{{.Status}}|{{.Label "com.docker.compose.service"}}'
            '|{{.Label "probe.tag"}}'
        )
        listed = self.docker(
            "ps", "--all", "--filter", f"label=com.docker.compose.project={self.key}",
            "--format", template,
        ).stdout.decode()  # fmt: skip
        rows = []
        for line in listed.splitlines():
            identity, name, state, status, service, tag = line.split("|")
            health = next((word for word in ("unhealthy", "healthy") if word in status), "")
            rows.append(dict(id=identity, name=name, state=state, health=health,
                             service=service, tag=tag))  # fmt: skip
        return rows

    def exec_cat(self, container: str, path: str) -> list[str]:
        return self.docker("exec", container, "cat", path).stdout.decode().split()

    def teardown(self) -> None:
        """Remove what the probe started, found by compose project: the app's and the core's."""
        project = f"label=com.docker.compose.project={self.key}"
        containers = self.docker("ps", "--all", "--quiet", "--filter", project, check=False)
        if ids := containers.stdout.decode().split():
            self.docker("rm", "--force", "--volumes", *ids, check=False)
        for kind in ("network", "volume"):
            listed = self.docker(kind, "ls", "--quiet", "--filter", project, check=False)
            if ids := listed.stdout.decode().split():
                self.docker(kind, "rm", *ids, check=False)
        images = self.docker(
            "image", "ls", "--quiet", "--filter", f"reference={self.key}-*", check=False
        )
        if ids := set(images.stdout.decode().split()):
            self.docker("image", "rm", "--force", *ids, check=False)
        if self.copy.exists():
            self.docker(
                "compose", "--profile", "*", "down", "--volumes", "--remove-orphans", check=False
            )

    # --- the origin of the app ---------------------------------------------------------------

    def start_origin(self) -> None:
        edge_copy.git(
            self.scratch,
            "init",
            "--quiet",
            "--bare",
            "--initial-branch",
            "master",
            str(self.origin),
        )
        edge_copy.git(self.scratch, "init", "--quiet", "--initial-branch", "master", str(self.work))
        edge_copy.git(self.work, "remote", "add", "origin", str(self.origin))
        for name, value in edge_copy.PROBE_IDENTITY.items():
            edge_copy.git(self.work, "config", name, value)
        url = f"https://github.com/{ORGANISATION}/{self.key}.git"
        (self.home / ".gitconfig").write_text(
            f'[url "{self.origin.as_uri()}"]\n\tinsteadOf = {url}\n'
        )

    def release(
        self, tag: str, *, healthy: bool = True, builds: bool = True, interpolates: bool = False,
        services: tuple[str, ...] = ("web",), on: str = "master", image_volume: str | None = None,
        covered: bool = True, pull_always: bool = False, compose_file: str | None = None,
        slow_build: int = 0,
    ) -> str:  # fmt: skip
        """A commit carrying the app at `tag`, pushed and tagged; its sha. `compose_file` replaces
        the generated compose.yaml with that text, or leaves it out when empty."""
        site = self.work / "site"
        site.mkdir(exist_ok=True)
        (site / "version").write_text(f"{tag}\n")
        health = site / "health"
        if healthy:
            health.write_text("ok\n")
        else:
            health.unlink(missing_ok=True)
        (self.work / "Dockerfile").write_text(
            f"FROM {BUSYBOX}\n{'' if builds else 'RUN false' + chr(10)}COPY site /www\n"
            # the key of this run makes the layer new, so the build never comes from the cache
            f"{f'RUN sleep {slow_build}; echo {self.key} > /built' + chr(10) if slow_build else ''}"
            f"{'VOLUME ' + image_volume + chr(10) if image_volume else ''}"
            'CMD ["sh", "-c", "cat /www/version >> /data/starts; exec httpd -f -p 8080 -h /www"]\n'
        )
        extra = ("    pull_policy: always\n" if pull_always else "") + (
            f"    volumes: [data:/data, vault:{image_volume}]\n"
            if image_volume and covered
            else "    volumes: [data:/data]\n"
        )
        text = self.compose_text(tag, services, interpolates, extra)
        if compose_file is None:
            (self.work / "compose.yaml").write_text(text)
        elif compose_file:
            (self.work / "compose.yaml").write_text(compose_file)
        else:
            (self.work / "compose.yaml").unlink(missing_ok=True)
        if on != "master":
            edge_copy.git(self.work, "switch", "--quiet", "--create", on)
        edge_copy.git(self.work, "add", "--all")
        edge_copy.git(self.work, "commit", "--quiet", "--message", f"release {tag}")
        sha = checkout.Git(self.work).call(["rev-parse", "HEAD"]).stdout.decode().strip()
        edge_copy.git(self.work, "tag", tag)
        edge_copy.git(self.work, "push", "--quiet", "origin", f"refs/tags/{tag}")
        if on == "master":
            edge_copy.git(self.work, "push", "--quiet", "origin", "master")
        else:
            edge_copy.git(self.work, "switch", "--quiet", "master")
        self.shas[tag] = sha
        return sha

    def compose_text(
        self, tag: str, services: tuple[str, ...], interpolates: bool, extra: str
    ) -> str:
        blocks = []
        for name in services:
            routing = (
                f'      traefik.enable: "true"\n      {self.label}: {self.key}\n'
                f'      traefik.http.services.{self.key}.loadbalancer.server.port: "8080"\n'
                if name == "web" else ""
            )  # fmt: skip
            environment = (
                '    environment:\n      PROBE_VALUE: "${PROBE_UNSET:?${PROBE_SENTINEL}}"\n'
                if interpolates and name == "web" else ""
            )  # fmt: skip
            blocks.append(
                f"  {name}:\n    build: .\n    restart: unless-stopped\n{environment}"
                f"{extra}    labels:\n{routing}      probe.tag: {tag}\n"
                f"{HEALTHCHECKS.get(name, HEALTHCHECK)}"
            )
        return "services:\n" + "".join(blocks) + "volumes:\n  data: {}\n  vault: {}\n"

    # --- the copy, its Traefik and hal -------------------------------------------------------

    def bring_up(self) -> None:
        self.copy = edge_copy.repository_copy(REPO, self.home, self.scratch, CORE_PROJECT)
        (self.copy / "fleet.yaml").write_text(
            f"cloudflare:\n  zone: {DOMAIN}\ngithub:\n  org: {ORGANISATION}\n\nservices:\n"
            f"  {self.key}:\n    repo: {{default_branch: master}}\n    run: {{enabled: true}}\n"
        )
        traefik = (self.copy / "traefik.yml").read_text()
        expect(
            traefik.count("edge.name") == 2
            and traefik.count("edge.alias") == 1
            and "127.0.0.1:8081" in traefik,
            "traefik.yml changed shape",
        )
        private = (
            traefik.replace("edge.name", self.label)
            .replace("edge.alias", self.alias_label)
            .replace("127.0.0.1:8081", f"127.0.0.1:{self.edge_port}")
            .replace("127.0.0.1:8090", f"127.0.0.1:{self.admin_port}")
        )
        (self.copy / "traefik.yml").write_text(private)
        edge_copy.publish(self.copy, "probe: a Traefik of its own")
        self.start_origin()
        self.docker("compose", "up", "--detach", "socket-proxy", "traefik")
        self.wait_until(
            "the probe's Traefik answers", lambda: self.ask("/", host="nobody")[0] == 404
        )

    def hal(self, *arguments: str, typed: bytes = b"yes\n", exit_code: int = HAL_OK) -> str:
        """`hal <arguments>` of the copy at a pty where the operator types `typed`; the
        whitespace-normalised output of a run that exits `exit_code`."""
        expect(not set(arguments) & set(FORBIDDEN_VERBS), f"hal {arguments} names a tunnel")
        command = shlex.join([str(self.copy / ".venv" / "bin" / "hal"), *arguments])
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["script", "-qec", command, "/dev/null"], input=typed, capture_output=True,  # noqa: S607 - script is found on PATH by design
            env=self.environment, cwd=self.copy, check=False, timeout=HAL_SECONDS,
        )  # fmt: skip
        output = " ".join((result.stdout + result.stderr).decode(errors="replace").split())
        expect(
            result.returncode == exit_code,
            f"hal {' '.join(arguments)} exited {result.returncode}, wanted {exit_code}: "
            f"{output[-300:]}",
        )
        return output

    def set_enabled(self, enabled: bool) -> None:
        """The catalog entry of the app switched on or off, published as a merged pull request
        and its pull would bring it."""
        fleet = self.copy / "fleet.yaml"
        wanted, unwanted = ("true", "false") if enabled else ("false", "true")
        fleet.write_text(fleet.read_text().replace(f"enabled: {unwanted}", f"enabled: {wanted}"))
        edge_copy.publish(self.copy, f"probe: {self.key} enabled {wanted}")

    def apply(self, typed: bytes = b"yes\n", exit_code: int = HAL_OK) -> str:
        return self.hal("apply", "--local", typed=typed, exit_code=exit_code)

    # --- what a client of the probe's Traefik sees -------------------------------------------

    def ask_with_headers(
        self, path: str, host: str | None = None
    ) -> tuple[int, str, http.client.HTTPMessage] | None:
        """(status, body, headers) of the probe's Traefik's answer; None when it gives none."""
        connection = http.client.HTTPConnection(
            "127.0.0.1", self.edge_port, timeout=REQUEST_SECONDS
        )
        try:
            connection.request("GET", path, headers={"Host": host or f"{self.key}.{DOMAIN}"})
            response = connection.getresponse()
            return response.status, response.read().decode().strip(), response.msg
        except OSError:
            return None
        finally:
            connection.close()

    def ask(self, path: str, host: str | None = None) -> tuple[int, str] | tuple[None, None]:
        answer = self.ask_with_headers(path, host)
        return (answer[0], answer[1]) if answer else (None, None)

    def wait_until(self, what: str, reached, seconds: int = READY_SECONDS) -> None:
        deadline = time.monotonic() + seconds
        while not reached():
            if time.monotonic() > deadline:
                raise ProbeFailed(f"{what} did not happen within {seconds} s")
            time.sleep(POLL_SECONDS)

    def serves(self, tag: str) -> None:
        self.wait_until(f"Traefik routes {tag}", lambda: self.ask("/version") == (200, tag))

    def git_in_srv(self, *arguments: str) -> None:
        """Git in the app's checkout as the operator would run it: the throwaway HOME's global
        configuration (the `insteadOf` of the origin), no `GIT_*` of the probe's own shell."""
        environment = {k: v for k, v in self.environment.items() if not k.startswith("GIT_")}
        subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["git", "-C", str(self.srv), *arguments], env=environment, capture_output=True,  # noqa: S607 - git is found on PATH by design
            check=True, timeout=COMPOSE_SECONDS,
        )  # fmt: skip

    def head(self) -> str:
        return checkout.Git(self.srv).call(["rev-parse", "HEAD"]).stdout.decode().strip()

    def deployed(self) -> dict[str, str]:
        return json.loads(self.record.read_text())

    def only(self) -> dict[str, str]:
        rows = self.containers()
        expect(len(rows) == 1, f"one container expected, found {[r['name'] for r in rows]}")
        return rows[0]

    def starts(self) -> list[str]:
        return self.exec_cat(self.only()["id"], "/data/starts")

    # --- the cells ---------------------------------------------------------------------------

    def cell_a1_first_apply(self) -> None:
        tag = TAGS["a1"]
        sha = self.release(tag)
        out = self.apply()
        expect(
            re.search(rf"{self.key}\s+switch on\s+{tag} · into ~/srv/{self.key}", out),
            f"the plan said: {out[-300:]}",
        )
        expect(f"{self.key} is on at {tag}" in out, f"the run said: {out[-300:]}")
        expect(self.head() == sha, "HEAD is not the tag's commit")
        expect(checkout.Git(self.srv).branch() is None, "HEAD is not detached")
        expect(self.deployed()["sha"] == sha, "the record names another sha")
        expect(self.only()["health"] == "healthy", "the container is not healthy")
        self.serves(tag)
        expect(self.starts() == [tag], "the volume does not hold the first start")
        write_line(
            "A1 held: on at the tag, detached, healthy, recorded after health, routed (hal 0)"
        )

    def cell_a2_second_apply(self) -> None:
        before = self.only()["id"]
        out = self.apply(typed=b"no\n")
        expect("nothing to change" in out, f"the second apply said: {out[-200:]}")
        expect(self.only()["id"] == before, "the second apply replaced the container")
        write_line("A2 held: a second apply changes nothing and keeps the container (hal 0)")

    def cell_a3_update(self) -> None:
        tag = TAGS["a3"]
        self.release(tag)
        out = self.apply()
        expect(
            f"update {TAGS['a1']} → {tag}" in out,
            out[-300:],
        )
        expect(self.deployed()["tag"] == tag, "the record is not the new tag")
        self.serves(tag)
        expect(self.starts() == [TAGS["a1"], tag], "the named volume lost the first tag's data")
        write_line(
            "A3 held: updated to the new tag, the named volume's data from the first tag present"
        )

    def cell_a4_side_branch(self) -> None:
        self.release(TAGS["a4_side"], on="side")
        out = self.apply(typed=b"no\n")
        expect(f"tag skipped {TAGS['a4_side']} · not on origin master" in out, out[-300:])
        expect(
            "nothing to change" in out and self.deployed()["tag"] == TAGS["a3"], "the newest moved"
        )
        write_line("A4 held: a tag only on a side branch is named and the newest stays")

    def cell_a7_declined(self) -> None:
        self.release(TAGS["a7"])
        before, head, record = self.only()["id"], self.head(), self.record.read_text()
        out = self.apply(typed=b"no\n", exit_code=HAL_FAILURE)
        expect("aborted, nothing changed" in out, out[-200:])
        expect(
            (self.only()["id"], self.head(), self.record.read_text()) == (before, head, record),
            "something changed",
        )
        write_line("A7 held: a declined yes leaves HEAD, the container and the record (hal 3)")

    def cell_a9_build_fails(self) -> None:
        tag = TAGS["a9"]
        self.release(tag, builds=False)
        before = self.only()["id"]
        out = self.apply(exit_code=HAL_FAILURE)
        expect(
            f"could not build at {tag}" in out and "exited" in out and "partial" in out, out[-300:]
        )
        expect(
            self.only()["id"] == before and self.deployed()["tag"] == TAGS["a3"],
            "the old state changed",
        )
        self.serves(TAGS["a3"])
        again = self.apply(typed=b"no\n", exit_code=HAL_FAILURE)
        expect(f"update to {tag} did not finish" in again, again[-300:])
        write_line("A9 held: a failed build keeps the old container and record; the plan says so")

    def cell_a8_never_healthy(self) -> None:
        tag = TAGS["a8"]
        self.release(tag, healthy=False)
        out = self.apply(exit_code=HAL_FAILURE)
        expect(f"is not healthy at {tag} after {HEALTH_WAIT_SECONDS}s" in out, out[-300:])
        expect(self.deployed()["tag"] == TAGS["a3"], "the record moved")
        expect(self.ask("/version")[0] == 404, "Traefik still routes an unhealthy container")
        again = self.apply(typed=b"no\n", exit_code=HAL_FAILURE)
        expect(
            f"update {TAGS['a3']} → {tag} · update to {tag} did not finish" in again,
            again[-300:],
        )
        write_line(
            "A8 held: partial (hal 3), record stays, Traefik routes nothing, plan says unfinished"
        )

    def cell_fix_forward(self) -> None:
        tag = TAGS["fix"]
        self.release(tag)
        self.apply()
        expect(self.deployed()["tag"] == tag, "the fix was not recorded")
        self.serves(tag)
        write_line("Q1 held: a newer tag fixes forward and Traefik routes it")

    def cell_a18_sentinel(self) -> None:
        tag = TAGS["a18"]
        self.release(tag, interpolates=True)
        out = self.apply(exit_code=HAL_FAILURE)
        expect(SENTINEL not in out, "the sentinel reached hal's output")
        expect(f"could not build at {tag}" in out and "exited" in out, out[-300:])
        control = self.app_compose("config", check=False)
        expect(
            SENTINEL in (control.stdout + control.stderr).decode(),
            "the positive control shows no sentinel",
        )
        expect(self.deployed()["tag"] == TAGS["fix"], "the record moved")
        write_line(
            "A18 held: compose's own error carries the sentinel (control), hal's output never does"
        )

    def cell_a12_no_record(self) -> None:
        tag = TAGS["a12"]
        self.release(tag)
        self.record.unlink()
        out = self.apply(typed=b"no\n", exit_code=HAL_FAILURE)
        expect(
            re.search(rf"\+ {self.key}\s+switch on\s+{tag} · into ~/srv/{self.key}", out),
            out[-300:],
        )
        self.apply()
        expect(self.deployed()["tag"] == tag, "the record was not written")
        expect(len(self.starts()) >= 3 and TAGS["a1"] in self.starts(), "the volume's data is gone")
        write_line(
            "A12 held: containers without a record are replaced, the named volume's data kept"
        )

    def interrupt_after_web(self, tag: str, *, second_web: bool) -> None:
        """What an apply interrupted at `create` leaves: HEAD at the new tag, `web` recreated and
        never started, `worker` still the old one; with `second_web` a second `web` as well."""
        self.git_in_srv(
            "fetch", "--quiet", "--no-tags", "origin", "+refs/tags/v*:refs/edge/releases/v*"
        )
        self.git_in_srv("checkout", "--quiet", "--detach", self.shas[tag])
        self.app_compose("create", "web")
        if second_web:
            self.app_compose("create", "--no-recreate", "--scale", "web=2", "web")

    def cell_a23_interrupted_update(self) -> None:
        services = ("web", "worker")
        first = TAGS["a23_first"]
        self.release(first, services=services)
        self.apply()
        for shape, second_web in (("a", False), ("b", True)):
            tag = TAGS[f"a23_{shape}"]
            self.release(tag, services=services)
            self.interrupt_after_web(tag, second_web=second_web)
            expect(
                len([r for r in self.containers() if r["service"] == "web"])
                == (2 if second_web else 1),
                "setup",
            )
            previous = self.deployed()["tag"]
            out = self.apply(typed=b"no\n", exit_code=HAL_FAILURE)
            expect(f"update to {tag} did not finish" in out, out[-400:])
            expect("nothing to change" not in out, out[-400:])
            expect(
                re.search(rf"~ {self.key}\s+update\s+{previous} → {tag} · update to", out),
                "the update row is not shown",
            )
            self.apply()
            rows = self.containers()
            expect(
                sorted(row["service"] for row in rows) == ["web", "worker"], f"containers: {rows}"
            )
            expect(
                all(row["tag"] == tag and row["health"] == "healthy" for row in rows),
                f"containers: {rows}",
            )
            expect(self.deployed()["tag"] == tag, "the record is not the new tag")
            expect(
                TAGS["a1"] in self.exec_cat(rows[0]["id"], "/data/starts"),
                "the volume's data is gone",
            )
        write_line(
            "A23 held: an update interrupted after part of the containers is repaired (also 2 webs)"
        )

    def cell_b5_image_volume(self) -> None:
        uncovered, covered = TAGS["b5_uncovered"], TAGS["b5_covered"]
        self.release(uncovered, image_volume="/vault", covered=False)
        before = [(r["id"], r["tag"]) for r in self.containers()]
        record = self.record.read_text()
        out = self.apply(exit_code=HAL_FAILURE)
        expect(
            f"image of service web at {uncovered} declares a volume that no named volume "
            "of the service covers" in out,
            out[-300:],
        )
        expect(
            [(r["id"], r["tag"]) for r in self.containers()] == before, "a container was replaced"
        )
        expect(self.record.read_text() == record, "the record moved")
        self.release(covered, image_volume="/vault")
        self.apply()
        expect(self.deployed()["tag"] == covered, "the covered release was not recorded")
        self.serves(covered)
        write_line(
            "B5 held: an uncovered image VOLUME is refused after build, before create (hal 3)"
        )

    def cell_b8_pull_policy_always(self) -> None:
        tag = TAGS["b8"]
        self.release(tag, pull_always=True)
        self.apply()
        expect(self.deployed()["tag"] == tag, "the record is not the tag")
        expect(self.only()["tag"] == tag, "the container is not from the tag")
        self.serves(tag)
        write_line("B8 held: pull_policy always starts healthy at the tag from the built image")

    def cell_h1_service_without_healthcheck(self) -> None:
        self.set_enabled(True)
        self.release(TAGS["h1"], services=("web", "helper", "sealed"))
        self.apply()
        seen = {row["service"]: (row["state"], row["health"]) for row in self.containers()}
        expect(seen["helper"] == seen["sealed"] == ("running", ""), f"H1: the helpers are {seen}")
        expect(self.deployed()["tag"] == TAGS["h1"], "H1: the app was not recorded")
        expect("nothing to change" in self.apply(typed=b"no\n"), "H1: plan not quiet")
        write_line(
            "H1 held: a running service without a healthcheck (absent, disabled) is recorded"
        )


def prove(probe: Probe, *, switch_only: bool) -> int:
    try:
        probe.bring_up()
        probe.cell_a1_first_apply()
        if switch_only:
            EmergencySwitch(probe, TAGS).prove()
            return 0
        probe.cell_a2_second_apply()
        probe.cell_a3_update()
        probe.cell_a4_side_branch()
        probe.cell_a7_declined()
        probe.cell_a9_build_fails()
        probe.cell_a8_never_healthy()
        probe.cell_fix_forward()
        probe.cell_a18_sentinel()
        probe.cell_a12_no_record()
        probe.cell_a23_interrupted_update()
        probe.cell_b5_image_volume()
        probe.cell_b8_pull_policy_always()
        EmergencySwitch(probe, TAGS).prove()
        SwitchedOff(probe, TAGS, GHOST).prove()
        probe.cell_h1_service_without_healthcheck()
        AliasRouting(probe, DOMAIN, TAGS).prove()
    except (ProbeFailed, subprocess.TimeoutExpired, OSError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


def raise_interrupt(_signal: int, _frame: object) -> None:
    raise KeyboardInterrupt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument(
        "--switch-only", action="store_true", help="only A1 and the emergency-switch cells D1-D7"
    )
    arguments = parser.parse_args(argv)
    if arguments.scratch.exists() and any(arguments.scratch.iterdir()):
        write_line("PROBE FAILED: --scratch is not empty")
        return NOT_RUNNABLE
    arguments.scratch.mkdir(parents=True, exist_ok=True)
    probe = Probe(arguments.scratch)
    signal.signal(signal.SIGTERM, raise_interrupt)  # `timeout` ends the probe with SIGTERM
    try:
        exit_code = prove(probe, switch_only=arguments.switch_only)
    except BaseException:
        probe.teardown()  # a failure the probe did not foresee must not leave its containers
        raise
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    try:
        probe.teardown()
    except (ProbeFailed, subprocess.TimeoutExpired) as failure:
        write_line(f"PROBE FAILED: teardown, {failure}")
        exit_code = 1
    if exit_code == 0 and arguments.switch_only:
        write_line("PROBE PASSED: #255 A1, D1, D2, D4, D7 hold")
    elif exit_code == 0:
        write_line(
            "PROBE PASSED: #255 A1-A4, A7-A9, A12, A18, A23, B5, B8, C1-C5, D1, D2, D4, D7 hold"
        )
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
