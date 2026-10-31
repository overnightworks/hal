"""Probe of the ingress barrier of `hal stop` (#61 proofs 1-7), of the Traefik that follows its
`traefik.yml` (#85 cells P1-P7), of the core that follows its compose definition (#87 cells
Q1-Q6) and of a running unit whose image is named, never swapped (#91 cells Z1-Z3): a throwaway
compose project, HOME and copy of the repository.

It starts the real Traefik, socket proxy and the `hello` whoami of compose.yaml under their own
project name, drives the real `hal stop`, `hal start` and `hal apply --local` of a copy, and
checks that `hello.<domain>` answers 404 with `X-Edge-Barrier: probe` on the copy's edge address
behind the barrier, also after a Traefik restart with the container up. It always removes its
containers, networks and volumes. Proof 8 (#70) drives `hal offline` and `hal online` on
a throwaway `systemctl --user` unit `edge-probe-tunnel-<random>.service` (`sleep infinity`) that
it removes again, with the real boot drop-in of `tunnel/`, and shows #76's boot skip: a start
while the global marker exists is skipped. The real `cloudflared.service` is never named.

The #85 cells: P7 prints traefik's volumes as `docker compose config --format json` resolves them
and checks that edge's core derives exactly `traefik.yml` from them; P1 the first apply recreates
traefik and writes `applied.json`; P2 a second apply changes nothing; P3 an edited `traefik.yml`
recreates traefik, which then serves `hello`; P4 the same with `probe` switched off proves its
barrier before the success line; P5 a stopped traefik is named and not started; P6 the volumes,
the marker and the barrier survive P3-P5.

The #87 cells: Q1 prints each core container's real ps fields (Labels, Image) and `config --hash`,
after the plain `up` and after edge's own recreates of traefik and of socket-proxy (a harmless
label), and requires label == hash for both after edge's recreate (else #87 rule 8 stops the
lane); Q2 a harmless label on socket-proxy in the copy's compose.yaml recreates socket-proxy,
then traefik, and `hello` answers through Traefik again; Q3 a label on traefik alone keeps
socket-proxy's container; Q4 a second apply changes nothing; Q5 with `probe` switched off a
socket-proxy change proves its barrier before the success line; Q6 the volumes, the marker and
the barrier survive Q2-Q5.

The #91 cells, after Q6's `hal start` of hello and hello-mcp: Z1 prints each one's resolved
`image` and ps `Image` and requires them equal (else #91 rule 5 stops the lane); Z2 hello's image
respelled in the copy with the same digest (a `docker.io/` prefix, nothing pulled) is named with
both strings, and the apply still changes nothing and asks nothing; Z3 reverted, nothing is named.

The copy is a clean `main` with a bare remote: every edit above is published (committed and
pushed) before the apply that follows it (#95 P1); the #95 cell P2, after P2, applies with one
unpublished `traefik.yml` edit and requires exit 3 naming it, with traefik's container kept. The
#783 cells P1-P4 (`checkout_update.py`) push commits to the remote from a work clone and drive
`hal update` and `hal apply --local` through the copy's `bin/hal`: apply refuses behind origin and
names `hal update`, the update syncs the new lock and the next apply runs the merged code, and a
lock that does not sync or code that fails at import is repaired by a hand pull. Every transcript
line names its item. It runs beside the live stack (#592): its Traefik listens on
`edge_copy.PROBE_HOST` and routes only its project, behind a network guard. Residual: the live
Traefik also routes the probe's `hello` until teardown.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 900 \\
        python3 probe/switches/probe.py --scratch DIR

Measured teardown: 2.8 s after a SIGTERM at 120 s (K 30 s, CAP 900 s; the full run took under
643 s with the lock wait). Needs an existing, empty --scratch directory, and `uv`: it runs
`uv sync` in the copy.
"""

from __future__ import annotations

import grp
import http.client
import json
import os
import re
import secrets
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(REPO / "probe" / "switches"))  # the cells of #783, beside this file
sys.path.insert(0, str(REPO / "src"))  # edge's own modules; hal.stack imports PyYAML too

import checkout_update  # noqa: E402
import edge_copy  # noqa: E402
from edge_copy import ProbeFailed, expect  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import barrier, checkout, compose, core, tunnel  # noqa: E402
from hal.stack.plan_rows import PlanEvent  # noqa: E402

PROJECT = "edge-switches-probe"
UNIT = "probe"
DOMAIN = "probe.invalid"
HOST = f"hello.{DOMAIN}"
FLEET = (
    f"cloudflare:\n  zone: {DOMAIN}\ngithub:\nservices:\n  probe:\n    run:\n      enabled: true\n"
)
NOT_FOUND = (404, b"404 page not found\n", UNIT)  # status, body, X-Edge-Barrier
UNCONFIGURED = (404, b"404 page not found\n", None)  # a Traefik that has loaded no router yet
WHOAMI_SEEN = b"Hostname:"
HELLO_ANSWERING = "hello answering"
NOTHING_TO_CHANGE = "nothing to change"
TRAEFIK_FILE = "traefik.yml"
RECREATED = "traefik is recreated and runs the checked-out traefik.yml"
TRAEFIK_KEPT = "the traefik container is the old one"
SOCKET_PROXY_RECREATED = "socket-proxy is recreated"  # also a fact of the plan: look from the end
CORE_CURRENT = "the core is current"
CORE = ("socket-proxy", "traefik")
COMPOSE_FILE = "compose.yaml"
HARMLESS_EDIT = "# an edit that changes no setting\n"
READY_SECONDS = 90
BEHIND_BARRIER_SECONDS = 10
REQUEST_SECONDS = 3
POLL_SECONDS = 0.2
COMPOSE_SECONDS = 300
SYSTEMCTL_SECONDS = 60
BOOT_DROP_IN_SOURCE = REPO / "tunnel" / f"{tunnel.CLOUDFLARED_UNIT}.d" / tunnel.BOOT_DROP_IN
TUNNEL_UNIT_TEXT = "[Service]\nExecStart=/usr/bin/sleep infinity\n"
PROBE_SERVICES = ("hello", "hello-mcp")
[WHOAMI_IMAGE] = re.findall(r"image: &whoami (\S+)", (REPO / "compose.yaml").read_text())
WHOAMI_ANCHOR = f"image: &whoami {WHOAMI_IMAGE}"
WHOAMI_ALIAS = "image: *whoami"
RESPELLED_WHOAMI = f"docker.io/{WHOAMI_IMAGE}"  # the same digest, so nothing is pulled
OLD_IMAGE = str(PlanEvent.OLD_IMAGE)


class Probe:
    def __init__(self, scratch: Path) -> None:
        self.scratch = scratch
        self.home = scratch / "home"
        self.home.mkdir(parents=True)
        self.environment = {
            **os.environ,
            "HOME": str(self.home),
            "COMPOSE_PROJECT_NAME": PROJECT,
            "EDGE_DOMAIN": DOMAIN,
            "DOCKER_GID": str(grp.getgrnam("docker").gr_gid),
            "NO_COLOR": "1",
        }
        self.environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
        self.live_before = edge_copy.live_project(REPO)
        self.guard: edge_copy.NetworkGuard | None = None
        self.copy = checkout.live_checkout(self.home)
        self.state = self.home / ".local" / "state" / "edge"
        self.marker = self.state / "stopped" / UNIT
        self.record = core.Record(self.state)
        self.volumes_before_p3: set[str] = set()
        self.volumes_before_q2: set[str] = set()
        self.compose_before_z2 = ""
        self.barrier = self.copy / "dynamic" / f"switch-{UNIT}.yml"

    # --- the stack ---------------------------------------------------------------------------

    def docker(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", *arguments], capture_output=True, env=self.environment,  # noqa: S607 - docker is found on PATH by design
            cwd=self.copy if self.copy.exists() else REPO, check=False, timeout=COMPOSE_SECONDS,
        )  # fmt: skip
        if result.returncode != 0:
            tail = (result.stderr or result.stdout).decode(errors="replace").strip().splitlines()
            raise ProbeFailed(
                f"docker {' '.join(arguments[:2])} exited {result.returncode}: {tail[-1:]}"
            )
        return result

    def compose(self, *arguments: str) -> subprocess.CompletedProcess[bytes]:
        return self.docker(*edge_copy.guarded_compose(self.copy, self.guard, arguments))

    def container_ids(self) -> dict[str, str]:
        """The container id of each service that has one."""
        listed = self.compose("--profile", "*", "ps", "--all", "--format", "json").stdout.decode()
        containers = [json.loads(line) for line in listed.strip().splitlines()]
        return {container["Service"]: container["ID"] for container in containers}

    def traefik_state(self) -> str:
        listed = self.compose("ps", "--all", "--format", "json", "traefik").stdout.decode()
        states = [json.loads(line)["State"] for line in listed.strip().splitlines()]
        return states[0] if states else "absent"

    def volumes(self) -> set[str]:
        """The project's named volumes, `socket-proxy-run` among them."""
        listed = self.docker(
            "volume", "ls", "--quiet", "--filter", f"label=com.docker.compose.project={PROJECT}"
        )
        return set(listed.stdout.decode().split())

    def engine(self) -> compose.Compose:
        """edge's own Compose reader, over the copy and the probe's project."""
        return edge_copy.compose_engine(self.environment, self.copy)

    def created(self, container_id: str) -> datetime:
        """When Docker created the container, to the microsecond."""
        inspected = self.docker("inspect", "--format", "{{.Created}}", container_id)
        return datetime.fromisoformat(inspected.stdout.decode().strip())

    def label_core_service(self, service: str, value: str) -> None:
        """Give the service a label that changes nothing it does, so only its definition changes."""
        path = self.copy / COMPOSE_FILE
        lines = path.read_text().splitlines(keepends=True)
        label = f"    labels: {{edge.probe-change: {value}}}\n"
        start = lines.index(f"  {service}:\n") + 1
        if lines[start].startswith("    labels: {edge.probe-change:"):
            lines[start] = label
        else:
            lines.insert(start, label)
        path.write_text("".join(lines))
        edge_copy.publish(self.copy, f"probe: label {service} {value}")

    def edit_traefik_yml(self) -> None:
        with (self.copy / TRAEFIK_FILE).open("a") as file:
            file.write(HARMLESS_EDIT)
        edge_copy.publish(self.copy, "probe: a harmless traefik.yml edit")

    def hello_state(self) -> str:
        containers = self.compose("--profile", "probe", "ps", "--all", "--format", "json", "hello")
        lines = containers.stdout.decode().strip()
        states = [json.loads(line)["State"] for line in lines.splitlines()]
        return states[0] if states else "absent"

    def hal(
        self,
        *arguments: str,
        terminal: bool,
        exit_code: int = 0,
        typed: bytes = b"yes\n",
        launcher: bool = False,
        extra_environment: dict[str, str] | None = None,
    ) -> str:
        return edge_copy.run_hal(
            self.copy,
            {**self.environment, **(extra_environment or {})},
            *arguments,
            terminal=terminal,
            exit_code=exit_code,
            typed=typed,
            launcher=launcher,
        )

    def teardown(self) -> None:
        if self.guard is None:
            return
        self.compose("--profile", "*", "down", "--volumes", "--remove-orphans")
        left = {"containers": self.container_ids(), "volumes": self.volumes()}
        expect(not any(left.values()), f"the teardown left {left}")
        self.guard.expect_clean_teardown()
        live = edge_copy.expect_live_project_unchanged(self.live_before, REPO)
        write_line(f"#592 V7 held: {PROJECT} left nothing, hal_ networks as before. V8: {live}")

    # --- what a client of the tunnel sees ----------------------------------------------------

    def ask(self) -> tuple[int, bytes, str | None] | None:
        """`GET /` with the unit's Host on the edge entrypoint: status, body and the barrier mark;
        None when nothing listens."""
        host, _, port = barrier.edge_address(self.copy).rpartition(":")
        connection = http.client.HTTPConnection(host, int(port), timeout=REQUEST_SECONDS)
        try:
            connection.request("GET", "/", headers={"Host": HOST})
            response = connection.getresponse()
            return response.status, response.read(), response.getheader("X-Edge-Barrier")
        except OSError:
            return None
        finally:
            connection.close()

    def wait_until(self, what: str, reached, seconds: int = READY_SECONDS) -> None:
        deadline = time.monotonic() + seconds
        while not reached():
            if time.monotonic() > deadline:
                raise ProbeFailed(
                    f"{what} did not happen within {seconds} s (last answer {self.ask()})"
                )
            time.sleep(POLL_SECONDS)

    def serves_whoami(self) -> bool:
        answer = self.ask()
        return bool(answer) and answer[0] == 200 and WHOAMI_SEEN in answer[1]

    def answers_the_barrier(self) -> bool:
        return self.ask() == NOT_FOUND

    def stays_behind_the_barrier(self, seconds: int, *, traefik_starting: bool = False) -> int:
        """Every request for `seconds` answers the barrier's 404, from the first one; the number of
        requests. With `traefik_starting` the answers of a starting Traefik before the
        first barrier answer do not count, and the window starts at that answer: nothing listens
        yet, or Traefik listens before its providers' first configuration and answers its plain
        404, which reaches no backend either. Whoami answering always fails."""
        asked = 0
        waiting_since = time.monotonic()
        end = waiting_since + seconds
        while time.monotonic() < end:
            answer = self.ask()
            if answer in (None, UNCONFIGURED) and traefik_starting:
                expect(
                    time.monotonic() - waiting_since < READY_SECONDS,
                    f"traefik never served the barrier (last answer {answer})",
                )
                end = time.monotonic() + seconds
                time.sleep(POLL_SECONDS)
                continue
            expect(answer == NOT_FOUND, f"a request behind the barrier answered {answer}")
            traefik_starting = False
            asked += 1
            time.sleep(POLL_SECONDS)
        return asked

    # --- the cells ---------------------------------------------------------------------------

    def bring_up(self) -> None:
        self.copy = edge_copy.repository_copy(REPO, self.home, self.scratch, PROJECT)
        self.guard = edge_copy.NetworkGuard(
            PROJECT, lambda command: self.docker(*command[1:]).stdout
        )
        traefik_yml = self.copy / TRAEFIK_FILE
        traefik_yml.write_text(edge_copy.beside_the_live_edge(traefik_yml.read_text(), PROJECT))
        (self.copy / "fleet.yaml").write_text(FLEET)
        edge_copy.publish(self.copy, "probe: the probe's fleet and its Traefik beside the live one")
        self.compose("up", "--detach", "socket-proxy", "traefik")  # the guard checks it first
        write_line(f"#592 V6 held: project {PROJECT}, Traefik on {barrier.edge_address(self.copy)}")

    def cell_p7_the_real_bind_shape(self) -> None:
        resolved = json.loads(self.compose("--profile", "*", "config", "--format", "json").stdout)
        write_line(
            f"#85 P7 traefik volumes: {json.dumps(resolved['services']['traefik']['volumes'])}"
        )
        tracked = core.Checkout.read(resolved, checkout.Git(self.copy))
        derived = {
            name: core.file_binds(resolved["services"][name], tracked)
            for name in core.core_services(resolved)
        }
        expect(
            derived == {"socket-proxy": (), "traefik": (self.copy / TRAEFIK_FILE,)},
            f"the core's file binds are {derived}",
        )
        write_line("#85 P7 held: the core's only file bind is the copy's traefik.yml, as derived")

    def cell_p1_first_apply(self) -> None:
        before = self.container_ids()["traefik"]
        out = self.hal("apply", "--local", terminal=True)  # also starts hello
        expect(
            "traefik recreate traefik.yml has no applied record" in out and RECREATED in out,
            f"the first apply said: {out[-200:]}",
        )
        expect(self.container_ids()["traefik"] != before, TRAEFIK_KEPT)
        expect(TRAEFIK_FILE in self.record.read().entries.get("traefik", {}), "no applied record")
        write_line("#85 P1 held: the first apply recreated traefik and wrote applied.json")

    def cell_p2_second_apply(self) -> None:
        before = self.container_ids()
        out = self.hal("apply", "--local", terminal=True, typed=b"no\n")
        expect(NOTHING_TO_CHANGE in out, f"the second apply said: {out[-200:]}")
        expect(self.container_ids() == before, "the second apply replaced a container")
        write_line("#85 P2 held: a second apply changes nothing and keeps every container id")

    def cell_95_p2_an_unpublished_edit(self) -> None:
        """#95 P2: an edit that was never published leaves the copy dirty; apply names it and
        recreates nothing."""
        traefik_yml = self.copy / TRAEFIK_FILE
        published = traefik_yml.read_text()
        before = self.container_ids()["traefik"]
        traefik_yml.write_text(published + HARMLESS_EDIT)
        try:
            out = self.hal("apply", "--local", terminal=True, exit_code=edge_copy.HAL_FAILURE)
        finally:
            traefik_yml.write_text(published)
        expect(
            "the live checkout has local changes" in out and TRAEFIK_FILE in out,
            f"apply with an unpublished edit said: {out[-200:]}",
        )
        expect(self.container_ids()["traefik"] == before, "an unpublished edit recreated traefik")
        write_line(
            f"#95 P2 held: an unpublished {TRAEFIK_FILE} edit is named, exit 3, traefik kept"
        )

    def cell_p3_edited_traefik_yml(self) -> None:
        self.volumes_before_p3 = self.volumes()
        before = self.container_ids()["traefik"]
        self.edit_traefik_yml()
        out = self.hal("apply", "--local", terminal=True)
        expect(
            "traefik recreate traefik.yml changed" in out and RECREATED in out,
            f"apply after the edit said: {out[-200:]}",
        )
        expect(self.container_ids()["traefik"] != before, TRAEFIK_KEPT)
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(f"#85 P3 held: the edit recreated traefik, and {HOST} answers through it")

    def cell_p4_barrier_proven_after_the_recreate(self) -> None:
        self.hal("stop", UNIT, terminal=False)
        self.compose("--profile", UNIT, "up", "--detach", "hello")
        self.edit_traefik_yml()
        out = self.hal("apply", "--local", terminal=True)
        proven = f"the barrier of {UNIT} is proven"
        expect(
            proven in out and RECREATED in out and out.index(proven) < out.index(RECREATED),
            f"apply with the barrier said: {out[-300:]}",
        )
        expect(self.answers_the_barrier(), f"{HOST} answers {self.ask()} after the recreate")
        expect(self.hello_state() == "running", "hello stopped across the recreate")
        write_line(
            "#85 P4 held: after the recreate the barrier answered 404, before the success line"
        )

    def cell_p5_stopped_traefik(self) -> None:
        self.compose("stop", "traefik")
        recorded = self.record.read().entries
        self.edit_traefik_yml()
        out = self.hal("apply", "--local", terminal=True, typed=b"no\n")
        expect(
            "traefik not started traefik.yml changed · not running" in out
            and NOTHING_TO_CHANGE in out,
            f"apply with traefik stopped said: {out[-200:]}",
        )
        expect(self.traefik_state() == "exited", f"traefik is {self.traefik_state()}")
        expect(self.record.read().entries == recorded, "the record changed")
        write_line(
            "#85 P5 held: a stopped traefik is named, stays exited, and the record stays old"
        )

    def cell_p6_what_survives(self) -> None:
        volumes = self.volumes()
        expect(volumes == self.volumes_before_p3, f"the volumes were {self.volumes_before_p3}")
        expect(f"{PROJECT}_socket-proxy-run" in volumes, f"no socket-proxy-run in {volumes}")
        expect(self.marker.is_file() and self.barrier.is_file(), "the marker or barrier is gone")
        self.compose("up", "--detach", "traefik")
        self.wait_until("the barrier answering", self.answers_the_barrier)
        self.hal("start", UNIT, terminal=True)
        write_line("#85 P6 held: the named volumes, the marker and the barrier survived P3-P5")

    def cell_q1_the_definition_fact(self, after: str, must_match: tuple[str, ...]) -> None:
        listed = self.compose("ps", "--all", "--format", "json").stdout.decode()
        for line in listed.strip().splitlines():
            container = json.loads(line)
            if container["Service"] in CORE:
                fields = {key: container[key] for key in ("Service", "Image", "Labels")}
                write_line(f"#87 Q1 {after}, ps: {json.dumps(fields)}")
        hashes = self.compose("--profile", "*", "config", "--hash", ",".join(CORE)).stdout
        write_line(f"#87 Q1 {after}, config --hash: {hashes.decode().strip()!r}")
        engine = self.engine()
        read = engine.config_hashes(CORE)
        labels = {c.service: c.config_hash for c in engine.containers() if c.service in CORE}
        for service in CORE:
            same = labels[service] == read[service]
            write_line(f"#87 Q1 {after}: {service} label == config --hash: {same}")
        for service in must_match:
            expect(
                labels[service] == read[service],
                f"#87 rule 8: {service}'s label differs from config --hash {after}; stop the lane",
            )
        required = ", ".join(must_match) or "none required"
        write_line(f"#87 Q1 held {after}: printed; label == hash for {required}")

    def recreate_socket_proxy_for_q1(self) -> None:
        """Edge's own recreate of socket-proxy, which also recreates traefik, so Q1 can compare
        both labels before any other cell runs (#87 rule 8)."""
        self.label_core_service("socket-proxy", "q1")
        before, after, out = self.apply_core_change()
        expect(
            SOCKET_PROXY_RECREATED in out and all(after[s] != before[s] for s in CORE),
            f"apply after the Q1 socket-proxy label said: {out[-400:]}",
        )

    def apply_core_change(self) -> tuple[dict[str, str], dict[str, str], str]:
        """The container ids before and after one `hal apply --local` with `yes`, and its out."""
        before = self.container_ids()
        out = self.hal("apply", "--local", terminal=True)
        return before, self.container_ids(), out

    def cell_q2_socket_proxy_definition(self) -> None:
        self.volumes_before_q2 = self.volumes()
        self.label_core_service("socket-proxy", "q2")
        before, after, out = self.apply_core_change()
        expect(
            "socket-proxy recreate definition changed" in out
            and "traefik recreate" in out
            and out.count("socket-proxy is recreated") == 2  # the fact of traefik's row, the result
            and out.rindex(SOCKET_PROXY_RECREATED) < out.index(RECREATED) < out.index(CORE_CURRENT),
            f"apply after the socket-proxy label said: {out[-400:]}",
        )
        expect(all(after[s] != before[s] for s in CORE), "a core container is the old one")
        expect(
            self.created(after["socket-proxy"]) < self.created(after["traefik"]),
            "traefik was created before socket-proxy",
        )
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(
            f"#87 Q2 held: socket-proxy, then traefik recreated; {HOST} answers through Traefik"
        )

    def cell_q3_traefik_definition(self) -> None:
        self.label_core_service("traefik", "q3")
        before, after, out = self.apply_core_change()
        expect(
            "traefik recreate definition changed" in out
            and "socket-proxy recreate" not in out
            and RECREATED in out,
            f"apply after the traefik label said: {out[-300:]}",
        )
        expect(after["socket-proxy"] == before["socket-proxy"], "socket-proxy was recreated")
        expect(after["traefik"] != before["traefik"], TRAEFIK_KEPT)
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(
            "#87 Q3 held: a traefik label recreated traefik alone; socket-proxy's id unchanged"
        )

    def cell_q4_second_run(self) -> None:
        before = self.container_ids()
        out = self.hal("apply", "--local", terminal=True, typed=b"no\n")
        expect(NOTHING_TO_CHANGE in out, f"the second apply said: {out[-200:]}")
        expect(self.container_ids() == before, "the second apply replaced a container")
        write_line("#87 Q4 held: a second apply changes nothing and keeps every container id")

    def cell_q5_barrier_after_a_socket_proxy_recreate(self) -> None:
        self.hal("stop", UNIT, terminal=False)
        self.compose("--profile", UNIT, "up", "--detach", "hello")
        self.label_core_service("socket-proxy", "q5")
        _, _, out = self.apply_core_change()
        proven = f"the barrier of {UNIT} is proven"
        expect(
            proven in out
            and SOCKET_PROXY_RECREATED in out
            and out.index(proven) < out.rindex(SOCKET_PROXY_RECREATED),
            f"apply with the barrier said: {out[-400:]}",
        )
        expect(self.answers_the_barrier(), f"{HOST} answers {self.ask()} after the recreate")
        expect(self.hello_state() == "running", "hello stopped across the recreate")
        write_line(
            "#87 Q5 held: the barrier answered 404 with X-Edge-Barrier before the success line"
        )

    def cell_q6_what_survives(self) -> None:
        volumes = self.volumes()
        expect(volumes == self.volumes_before_q2, f"the volumes were {self.volumes_before_q2}")
        expect(f"{PROJECT}_socket-proxy-run" in volumes, f"no socket-proxy-run in {volumes}")
        expect(self.marker.is_file() and self.barrier.is_file(), "the marker or barrier is gone")
        self.hal("start", UNIT, terminal=True)
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(
            "#87 Q6 held: socket-proxy-run, the named volumes, the marker and the barrier survived"
        )

    def images_of_the_unit(self) -> dict[str, tuple[str | None, str | None]]:
        """Each service of `probe` with its resolved `image` and its container's ps `Image`."""
        engine = self.engine()
        services = engine.resolved_configuration()["services"]
        running = {c.service: c.image for c in engine.containers()}
        return {name: (services[name].get("image"), running.get(name)) for name in PROBE_SERVICES}

    def cell_z1_the_image_fact(self) -> None:
        for service, (configured, running) in self.images_of_the_unit().items():
            write_line(f"#91 Z1 {service}: config image {configured!r}, ps Image {running!r}")
            expect(
                configured is not None and configured == running,
                f"#91 rule 5: {service}'s ps Image is not its resolved image; stop the lane",
            )
        write_line(
            "#91 Z1 held: after edge's own start, resolved image == ps Image of both services"
        )

    def respell_hello_image(self) -> None:
        """Respell hello's image and name hello-mcp's as before, without their shared anchor."""
        text = self.compose_before_z2.replace(WHOAMI_ANCHOR, f"image: {RESPELLED_WHOAMI}")
        (self.copy / COMPOSE_FILE).write_text(text.replace(WHOAMI_ALIAS, f"image: {WHOAMI_IMAGE}"))
        edge_copy.publish(self.copy, "probe: hello's image respelled")

    def cell_z2_a_respelled_image(self) -> None:
        self.compose_before_z2 = (self.copy / COMPOSE_FILE).read_text()
        self.respell_hello_image()
        before = self.container_ids()
        out = self.hal("apply", "--local", terminal=True, typed=b"no\n")
        named = f"compose.yaml {RESPELLED_WHOAMI.split('@')[0]}@"
        lines = [line for line in out.splitlines() if OLD_IMAGE in line and "hello" in line]
        write_line(f"#91 Z2 the line: {lines!r}")
        expect(
            len(lines) == 1 and named in lines[0] and NOTHING_TO_CHANGE in out,
            f"apply after the respelled image said: {out[-400:]}",
        )
        expect("Type" not in out, "the kept image asked a question")
        expect(self.container_ids() == before, "the kept image replaced a container")
        write_line("#91 Z2 held: hello and both images named; nothing to change; the same ids")

    def cell_z3_reverted(self) -> None:
        (self.copy / COMPOSE_FILE).write_text(self.compose_before_z2)
        edge_copy.publish(self.copy, "probe: hello's image as before")
        before = self.container_ids()
        out = self.hal("apply", "--local", terminal=True, typed=b"no\n")
        expect(
            OLD_IMAGE not in out and NOTHING_TO_CHANGE in out,
            f"apply after the revert said: {out[-400:]}",
        )
        expect(self.container_ids() == before, "the revert replaced a container")
        write_line("#91 Z3 held: reverted, no image is named; nothing to change; the same ids")

    def cell_1_control(self) -> None:
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(f"#61 proof 1 held: {HOST} answers whoami without a switch")

    def cell_2_stop(self) -> None:
        self.hal("stop", UNIT, terminal=False)
        expect(self.barrier.is_file(), "stop wrote no dynamic/switch-probe.yml")
        expect(self.marker.is_file(), "stop wrote no marker")
        expect(self.answers_the_barrier(), f"{HOST} answers {self.ask()} after stop")
        expect(self.hello_state() == "exited", f"hello is {self.hello_state()} after stop")
        write_line(
            "#61 proof 2 held: stop exits 0, wrote the barrier and the marker, 404, hello exited"
        )

    def cell_3_up_behind_the_barrier(self) -> None:
        self.compose("--profile", UNIT, "up", "--detach", "hello")
        asked = self.stays_behind_the_barrier(3)
        expect(self.hello_state() == "running", "hello is not running")
        write_line(f"#61 proof 3 held: hello up behind the barrier, {asked} requests answered 404")

    def cell_4_traefik_restart(self) -> None:
        expect(self.hello_state() == "running", "hello is not running before the restart")
        self.compose("restart", "traefik")
        asked = self.stays_behind_the_barrier(BEHIND_BARRIER_SECONDS, traefik_starting=True)
        expect(self.hello_state() == "running", "hello stopped across the restart")
        write_line(
            f"#61 proof 4 held: after restarting traefik {asked} requests in 10 s all answered 404"
        )

    def cell_5_apply(self) -> None:
        out = self.hal("apply", "--local", terminal=True)
        expect(
            "probe stays stopped" in out and NOTHING_TO_CHANGE in out, f"apply said: {out[-160:]}"
        )
        expect(self.hello_state() == "running", "apply stopped hello")
        expect(self.barrier.is_file() and self.answers_the_barrier(), "apply lifted the barrier")
        write_line(
            "#61 proof 5 held: apply says stays stopped / nothing to change; barrier and hello stay"
        )

    def cell_6_start(self) -> None:
        self.hal("start", UNIT, terminal=True)
        expect(not self.barrier.exists(), "start left the barrier")
        expect(not self.marker.exists(), "start left the marker")
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line(f"#61 proof 6 held: start removed barrier and marker; {HOST} answers whoami")

    def cell_8_global_stop(self) -> None:
        throwaway = ThrowawayTunnel(self.home)
        self.environment["EDGE_TUNNEL_UNIT"] = throwaway.name
        self.environment["EDGE_TUNNEL_MANAGER"] = "user"
        global_marker = self.home / ".local" / "state" / "edge" / "global-stop"
        try:
            self.hal("stop", UNIT, terminal=False)  # the unit barrier to be proven before reopening
            throwaway.install()
            stopped = self.hal("offline", terminal=False)
            expect("the tunnel is stopped" in stopped, f"offline said: {stopped[-160:]}")
            expect(
                throwaway.state() == "inactive",
                f"the tunnel is {throwaway.state()} after offline",
            )
            expect(global_marker.is_file(), "offline wrote no global marker")
            throwaway.start_is_skipped()
            self.barrier.unlink()  # online renders the barrier again before it proves it
            started = self.hal("online", terminal=True)
            expect(f"the barrier of {UNIT} is proven" in started, f"online said: {started[-200:]}")
            expect(
                throwaway.state() == "active",
                f"the tunnel is {throwaway.state()} after online",
            )
            expect(not global_marker.exists(), "online left the global marker")
            expect(self.marker.is_file() and self.answers_the_barrier(), "the unit switch fell")
        finally:
            throwaway.remove()
            self.environment.pop("EDGE_TUNNEL_UNIT")
            self.environment.pop("EDGE_TUNNEL_MANAGER")
        self.hal("start", UNIT, terminal=True)
        write_line(
            "#70 proof 8 held: offline left the throwaway unit inactive with the marker, and "
            "its boot drop-in skipped a start; online proved the unit barrier, reopened it "
            "and cleared only the marker"
        )

    def cell_7_traefik_down(self) -> None:
        self.compose("stop", "traefik")
        out = self.hal("stop", UNIT, terminal=False, exit_code=edge_copy.HAL_FAILURE)
        expect("partial" in out, f"the stop without traefik said: {out[-160:]}")
        expect(self.hello_state() == "exited", "hello still runs after the partial stop")
        expect(self.marker.is_file() and self.barrier.is_file(), "marker or barrier missing")
        self.compose("up", "--detach", "traefik")
        self.wait_until("the barrier answering", self.answers_the_barrier)
        self.hal("start", UNIT, terminal=True)
        self.wait_until(HELLO_ANSWERING, self.serves_whoami)
        write_line("#61 proof 7 held: traefik down: stop exits 3 partial, both kept; start reopens")


class ThrowawayTunnel:
    """A user unit that stands in for the tunnel, in the user manager's runtime directory (a tmpfs
    that is gone after a logout), with the real boot drop-in of `tunnel/` rendered for the
    probe's HOME, so proof 8 can show #76's boot skip."""

    def __init__(self, home: Path) -> None:
        self.name = f"edge-probe-tunnel-{secrets.token_hex(4)}.service"
        runtime = Path(os.environ["XDG_RUNTIME_DIR"]) / "systemd" / "user"
        self.unit_file = runtime / self.name
        self.drop_in = runtime / f"{self.name}.d" / tunnel.BOOT_DROP_IN
        self.drop_in_text = BOOT_DROP_IN_SOURCE.read_text().replace("@HOME@", str(home))

    def systemctl(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["systemctl", "--user", *arguments], capture_output=True, text=True, check=False,  # noqa: S607 - systemctl is found on PATH by design
            timeout=SYSTEMCTL_SECONDS,
        )  # fmt: skip

    def install(self) -> None:
        self.drop_in.parent.mkdir(parents=True)
        self.unit_file.write_text(TUNNEL_UNIT_TEXT)
        self.drop_in.write_text(self.drop_in_text)
        self.systemctl("daemon-reload")
        expect(
            self.systemctl("start", self.name).returncode == 0, "the throwaway unit did not start"
        )
        expect(self.state() == "active", f"without the marker the unit is {self.state()}")

    def start_is_skipped(self) -> None:
        """With the global marker present a start, as at boot, leaves the unit off."""
        started = self.systemctl("start", self.name)
        expect(started.returncode == 0, f"the skipped start failed: {started.stderr.strip()}")
        expect(self.state() == "inactive", f"with the marker the unit is {self.state()}")
        condition = self.systemctl("show", "--property=ConditionResult", "--value", self.name)
        expect(condition.stdout.strip() == "no", "the boot drop-in's condition was not checked")

    def state(self) -> str:
        return self.systemctl("is-active", self.name).stdout.strip()

    def remove(self) -> None:
        self.systemctl("stop", self.name)
        self.drop_in.unlink(missing_ok=True)
        if self.drop_in.parent.exists():
            self.drop_in.parent.rmdir()
        self.unit_file.unlink(missing_ok=True)
        self.systemctl("daemon-reload")


def prove(probe: Probe) -> int:
    try:
        probe.bring_up()
        probe.cell_q1_the_definition_fact("after the plain up", must_match=())
        probe.cell_p7_the_real_bind_shape()
        probe.cell_p1_first_apply()
        probe.cell_q1_the_definition_fact("after edge's traefik recreate", must_match=("traefik",))
        probe.recreate_socket_proxy_for_q1()
        probe.cell_q1_the_definition_fact("after edge's socket-proxy recreate", must_match=CORE)
        probe.cell_p2_second_apply()
        probe.cell_95_p2_an_unpublished_edit()
        probe.cell_1_control()
        probe.cell_2_stop()
        probe.cell_3_up_behind_the_barrier()
        probe.cell_4_traefik_restart()
        probe.cell_5_apply()
        probe.cell_6_start()
        probe.cell_7_traefik_down()
        probe.cell_8_global_stop()
        probe.cell_p3_edited_traefik_yml()
        probe.cell_p4_barrier_proven_after_the_recreate()
        probe.cell_p5_stopped_traefik()
        probe.cell_p6_what_survives()
        probe.cell_q2_socket_proxy_definition()
        probe.cell_q3_traefik_definition()
        probe.cell_q4_second_run()
        probe.cell_q5_barrier_after_a_socket_proxy_recreate()
        probe.cell_q6_what_survives()
        probe.cell_z1_the_image_fact()
        probe.cell_z2_a_respelled_image()
        probe.cell_z3_reverted()
        checkout_update.cells(probe)
    except (ProbeFailed, subprocess.TimeoutExpired, OSError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(
        __doc__.splitlines()[0],
        argv,
        Probe,
        prove,
        "PROBE PASSED: #61 proofs 1-7, #70 proof 8, #85 P1-P7, #87 Q1-Q6, #91 Z1-Z3, "
        "#95 P1-P2, #592 V1, V4, V6-V8, #783 P1-P4 hold",
    )


if __name__ == "__main__":
    sys.exit(main())
