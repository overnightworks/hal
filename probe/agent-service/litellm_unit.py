"""Probe of the unit `litellm` (#894 cells U0-U3, U5-U12, U14, R1): the copy's real `hal apply`
with the shipped `fleet.yaml` entry starts LiteLLM, its database and its front as one unit, and the
key step holds while the unit is off or stopped and waits while the run starts LiteLLM or its
database. Nothing live and nothing paid: no provider key, no egress, no app.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/litellm_unit.py --scratch DIR

Measured: a run takes about six minutes and its teardown a few seconds (K 50 s, CAP 1780 s).

The copy is edge_copy's: a scratch HOME whose live checkout runs the lane's files with every fixed
name moved into the probe's project, and every network of edge_copy.PINNED_NETWORKS moved to a free
/24 (the live project owns the shipped ones). Its catalog is the shipped one with the entry
`litellm` as shipped and Keycloak switched off, so no setup asks and the key step holds the admin
rows. Secrets are random scratch values under the scratch HOME's `~/.secrets/litellm/`, never a real
key; every network a service of profile `litellm` joins must be internal, and `agent-egress` is in
no unit, or the probe refuses to start. E counts the key step's one-off containers in `docker
events` of the project during a run (U5 is its control), D digests the key rows and the budgets
read by SQL in `litellm-db`. Exit 0: every cell held.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(Path(__file__).resolve().parent), str(REPO / "probe"), str(REPO / "src")]

import edge_copy  # noqa: E402
from edge_copy import HAL_DECLINED, HAL_FAILURE, HAL_OK, HAL_REFUSED, expect, publish  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import catalog, core, litellm_keys  # noqa: E402
from hal.stack.litellm_admin import hashed  # noqa: E402

PROJECT = "edge-litellm-unit-probe"
UNIT = litellm_keys.UNIT
SERVICES = ("litellm", "litellm-db", "litellm-front")  # Compose's resolved order, by name
FRONT = "litellm-front"
APPS = ("hopin", "presentator", "songmaker")
SECRETS = Path(".secrets/litellm")
PROVIDER, MASTER, PASSWORD = (SECRETS / name for name in ("anthropic", "master-key", "db-password"))
LISTEN_SECONDS = 240
LABEL = f"{PROJECT}.throwaway=1"
SUBNET_CANDIDATES = [f"172.31.{third}.0/24" for third in range(230, 210, -1)]
ENTRY = re.compile(r"^  litellm:\n(?: {4}.*\n)+", re.MULTILINE)
KEYCLOAK_OFF = "  keycloak:\n    run:\n      enabled: false\n"
DB_HEALTH = '"--username=litellm", "--dbname=litellm"]\n      interval: 5s\n'
LITELLM_TELEMETRY = '      LITELLM_TELEMETRY: "False"\n'
SWITCH_ON = "+ litellm switch on litellm, litellm-db, litellm-front"
STARTS_NOW = "· litellm keys later LiteLLM starts now · next apply checks them"
DB_RESTARTS = "· litellm keys later its database restarts now · next apply checks them"


class Probe:
    def __init__(self, scratch: Path) -> None:
        self.scratch, self.home = scratch, scratch / "home"
        self.home.mkdir()
        self.environment = {
            **os.environ, "HOME": str(self.home), "COMPOSE_PROJECT_NAME": PROJECT,
            "EDGE_DOMAIN": "probe.invalid", "DOCKER_GID": "0",
        }  # fmt: skip
        self.guard = edge_copy.NetworkGuard(PROJECT, lambda command: self.run(command).stdout)
        self.live_before = edge_copy.live_project(REPO)
        self.copy = Path()
        self.held: list[str] = []
        self.files: dict[Path, str] = {}

    # --- plumbing -----------------------------------------------------------------------------

    def run(self, command: list[str], *, check: bool = True, timeout: int = 300):
        result = edge_copy.run_command(command, text=True, env=self.environment, timeout=timeout)
        if check and result.returncode != 0:
            tail = (result.stderr or result.stdout).strip().splitlines()
            raise edge_copy.ProbeFailed(
                f"{' '.join(command[:6])} exited {result.returncode}: {tail[-1:]}"
            )
        return result

    def compose(self, *arguments: str, check: bool = True) -> str:
        command = [*edge_copy.copy_compose_command(self.copy), *arguments]
        self.guard.expect_call(command)
        return self.run(command, check=check).stdout

    def hal(self, *arguments: str, typed: bytes = b"yes\n") -> tuple[int, str, int]:
        """`hal <arguments>` in the copy at a pty: its exit, its normalised output and E, the
        key step's one-off containers created meanwhile."""
        if arguments[0] in ("apply", "start"):
            self.guard.expect(edge_copy.copy_compose_command(self.copy), once=False)
        since = time.time()
        program = self.copy / ".venv" / "bin" / "hal"
        command = ["script", "-qec", " ".join([str(program), *arguments]), edge_copy.DISCARD_OUTPUT]
        result = edge_copy.run_command(
            command,
            input=typed,
            env=self.environment,
            cwd=self.copy,
            timeout=edge_copy.APPLY_SECONDS,
        )
        text = (result.stdout + result.stderr).decode(errors="replace")
        output = " ".join(edge_copy.ANSI_ESCAPE.sub("", text).split())
        return result.returncode, output, self.one_offs(since)

    def apply(self, cell: str, exit_code: int, typed: bytes = b"yes\n") -> tuple[str, int]:
        code, output, created = self.hal("apply", "--local", typed=typed)
        expect(
            code == exit_code,
            f"{cell}: hal apply exited {code}, wanted {exit_code}: {output[-300:]}",
        )
        expect(not self.leaked(output), f"{cell}: a scratch secret is in hal's output")
        return output, created

    def one_offs(self, since: float) -> int:
        events = self.run([
            "docker", "events", "--since", f"{since:.3f}", "--until", f"{time.time() + 1:.3f}",
            "--filter", "type=container", "--filter", "event=create",
            "--filter", f"label=com.docker.compose.project={PROJECT}",
            "--filter", f"label=com.docker.compose.service={litellm_keys.KEYS_SERVICE}",
            "--format", "{{.Actor.ID}}",
        ]).stdout  # fmt: skip
        return len(events.split())

    def leaked(self, output: str) -> bool:
        return any(value in output or hashed(value) in output for value in self.files.values())

    def running(self) -> set[str]:
        return set(self.compose("ps", "--status", "running", "--services").split())

    def sql(self, statement: str) -> list[str]:
        out = self.compose("exec", "-T", "litellm-db", "psql", "-U", "litellm", "-d", "litellm",
                           "-At", "-v", "ON_ERROR_STOP=1", "-c", statement)  # fmt: skip
        return out.splitlines()

    def digest(self) -> str:
        """D: the key rows by alias and the budgets, never a hash."""
        rows = self.sql(
            "SELECT key_alias, max_budget, budget_duration, models, allowed_routes, "
            'max_parallel_requests, rpm_limit, tpm_limit FROM "LiteLLM_VerificationToken" '
            "ORDER BY key_alias;"
        ) + self.sql(
            'SELECT budget_id, max_budget, budget_duration FROM "LiteLLM_BudgetTable" '
            "ORDER BY budget_id;"
        )
        return hashlib.sha256("\n".join(rows).encode()).hexdigest()[:12]

    def set_budget(self, app: str, dollars: int) -> None:
        self.sql(
            f'UPDATE "LiteLLM_VerificationToken" SET max_budget = {dollars} '
            f"WHERE key_alias = '{app}';"
        )  # noqa: S608 - the probe's own app name and number

    def budget_of(self, app: str) -> str:
        return self.sql(
            f"SELECT max_budget FROM \"LiteLLM_VerificationToken\" WHERE key_alias = '{app}';"
        )[0]  # noqa: S608 - the probe's own app name

    def wait_until_listening(self, cell: str) -> None:
        """Until LiteLLM answers on litellm-backend, from a throwaway beside the key step."""
        image = json.loads(self.compose("config", "--format", "json"))["services"][
            litellm_keys.KEYS_SERVICE
        ]["image"]
        program = (
            "import urllib.request; "
            "urllib.request.urlopen('http://litellm:4000/health/liveliness', timeout=3)"
        )
        command = [
            "docker", "run", "--rm", "--label", LABEL, "--network", f"{PROJECT}_litellm-backend",
            "--read-only", "--user", "65534:65534", "--cap-drop", "ALL",
            image, "python", "-I", "-c", program,
        ]  # fmt: skip
        deadline = time.monotonic() + LISTEN_SECONDS
        while self.run(command, check=False, timeout=60).returncode != 0:
            expect(
                time.monotonic() < deadline, f"{cell}: LiteLLM did not listen in {LISTEN_SECONDS} s"
            )
            time.sleep(3)

    def write_secret(self, relative: Path, value: str) -> None:
        """A new file at `relative`, as `hal setup` writes one: 0644 in 0700 folders."""
        path = self.home / relative
        folder = self.home
        for part in relative.parent.parts:
            folder /= part
            folder.mkdir(mode=0o700, exist_ok=True)
        path.unlink(missing_ok=True)
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "w") as file:
            file.write(value + "\n")
        self.files[relative] = value

    def edit_compose(self, old: str, new: str, message: str) -> None:
        file = self.copy / "compose.yaml"
        text = file.read_text()
        expect(
            text.count(old) == 1, f"the copy's compose.yaml holds {old!r} {text.count(old)} times"
        )
        file.write_text(text.replace(old, new))
        publish(self.copy, message)

    def set_enabled(self, enabled: bool) -> None:
        fleet = self.copy / catalog.FLEET_FILE
        text, count = re.subn(
            r"(  litellm:\n    run:\n      enabled: )\w+",
            rf"\g<1>{str(enabled).lower()}",
            fleet.read_text(),
        )
        expect(count == 1, "the copy's fleet.yaml has no litellm switch")
        fleet.write_text(text)
        publish(self.copy, f"probe: litellm enabled {enabled}")

    def hold(self, cell: str, how: str) -> None:
        write_line(f"{cell} held: {how}", flush=True)
        self.held.append(cell)

    # --- the stack ----------------------------------------------------------------------------

    def prepare(self) -> tuple[str, str]:
        """The copy with its pinned networks moved and the scratch secrets; the catalog texts
        without and with the shipped entry."""
        self.copy = edge_copy.repository_copy(REPO, self.home, self.scratch, PROJECT)
        compose_file = self.copy / "compose.yaml"
        live = edge_copy.live_pinned_prefixes(compose_file.read_text())
        moved = edge_copy.free_probe_prefixes(live, SUBNET_CANDIDATES, edge_copy.daemon_subnets())
        compose_file.write_text(edge_copy.moved_to_probe_subnets(compose_file.read_text(), moved))
        shipped = (REPO / catalog.FLEET_FILE).read_text()
        without = shipped[: shipped.index("\nservices:\n")] + "\nservices:\n" + KEYCLOAK_OFF
        (self.copy / catalog.FLEET_FILE).write_text(without)
        publish(self.copy, "probe: the pinned networks moved, the catalog without litellm")
        self.expect_no_egress()
        for relative in (PROVIDER, MASTER):
            self.write_secret(relative, f"sk-{secrets.token_hex(32)}")
        self.write_secret(PASSWORD, secrets.token_hex(24))
        for app in APPS:
            self.write_secret(SECRETS / "apps" / app, f"sk-{secrets.token_urlsafe(32)}")
        entry = ENTRY.search(shipped)
        expect(entry is not None, "the shipped fleet.yaml has no litellm entry")
        return without, without + entry[0]

    def expect_no_egress(self) -> None:
        resolved = json.loads(self.compose("config", "--format", "json"))
        joined = {
            network
            for service in resolved["services"].values()
            if UNIT in service.get("profiles", [])
            for network in service.get("networks", {})
        }
        open_networks = sorted(n for n in joined if not resolved["networks"][n].get("internal"))
        expect(not open_networks, f"a litellm network is not internal: {open_networks}")
        expect(
            "agent-service" not in (self.copy / catalog.FLEET_FILE).read_text(),
            "agent-egress is in a unit",
        )

    def teardown(self) -> None:
        started = time.monotonic()
        stray = self.run(
            ["docker", "ps", "-aq", "--filter", f"label={LABEL}"], check=False
        ).stdout.split()
        if stray:
            self.run(["docker", "rm", "-f", *stray], check=False)
        if (self.copy / "compose.yaml").is_file():
            self.compose("down", "--volumes", "--remove-orphans", "--timeout", "10", check=False)
        filters = [f"label=com.docker.compose.project={PROJECT}"]
        left = self.run(["docker", "ps", "-aq", "--filter", filters[0]]).stdout.split()
        volumes = self.run(
            ["docker", "volume", "ls", "-q", "--filter", f"name={PROJECT}_"]
        ).stdout.split()
        expect(not (left or volumes), f"the teardown left {left} {volumes}")
        self.guard.expect_clean_teardown()
        write_line(
            f"teardown: project {PROJECT} removed in {time.monotonic() - started:.0f} s; "
            + edge_copy.expect_live_project_unchanged(self.live_before, REPO)
        )

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        without, with_entry = self.prepare()
        self.cell_u0(with_entry)
        self.cell_u1()
        self.cell_u2()
        self.cell_u3()
        self.cell_u5()
        self.cell_u6()
        self.cell_u14()
        self.cell_u7()
        self.cell_u12()
        self.cell_r1()
        self.cell_u8()
        self.cell_u9()
        self.cell_u10()
        self.cell_u11()
        expect(without != with_entry, "the entry changed nothing")

    def cell_u0(self, with_entry: str) -> None:
        output, _ = self.apply("U0", HAL_OK)
        expect("litellm" not in output, f"U0: a row names litellm: {output[-300:]}")
        expect(not self.running(), "U0: a container of the copy runs")
        (self.copy / catalog.FLEET_FILE).write_text(with_entry)
        publish(self.copy, "probe: the shipped litellm entry")
        self.hold(
            "U0", "without the entry no row names litellm and nothing runs; the entry published"
        )

    def cell_u1(self) -> None:
        for relative in (PROVIDER, MASTER, PASSWORD):
            path, value = self.home / relative, self.files[relative]
            path.unlink()
            output, created = self.apply("U1", HAL_REFUSED)
            wanted = f"error: litellm needs {path}; nothing switched next: hal setup"
            expect(wanted in output and "Type yes" not in output, f"U1 {relative}: {output[-300:]}")
            expect((self.running(), created) == (set(), 0), f"U1 {relative}: something started")
            self.write_secret(relative, value)
        self.hold(
            "U1",
            "each of the three files missing: `litellm needs <path>; nothing switched`, "
            "next: hal setup, exit 4, no question, nothing runs",
        )

    def cell_u2(self) -> None:
        output, created = self.apply("U2", HAL_DECLINED, typed=b"no\n")
        rows = (SWITCH_ON, f"~ {FRONT} starts later", STARTS_NOW, "aborted, nothing changed")
        expect(all(row in output for row in rows), f"U2: {output[-400:]}")
        expect((self.running(), created) == (set(), 0), "U2: something started")
        first = min(output.index(SWITCH_ON), output.index(f"~ {FRONT}"))
        plan = output[first : output.index("Type yes")]
        self.hold("U2", f"{plan}; aborted, exit 1, nothing runs")

    def cell_u3(self) -> None:
        output, created = self.apply("U3", HAL_OK)
        after = output.partition("to apply")[2]
        expect("litellm is on" in after and "next:" not in after, f"U3: {after[-300:]}")
        expect("litellm keys" not in after, f"U3: the key step printed after the yes: {after}")
        expect(self.running() == set(SERVICES), f"U3: running {self.running()}")
        record = json.loads((self.home / ".local/state/edge" / core.APPLIED_FILE).read_text())
        expect(FRONT in record, f"U3: {FRONT} is not recorded")
        expect(created == 0, f"U3: E saw {created} one-offs")
        self.hold(
            "U3", f"litellm is on, exit 0, the three containers run, {FRONT} recorded, E empty"
        )

    def cell_u5(self) -> None:
        self.wait_until_listening("U5")
        output, created = self.apply("U5", HAL_OK)
        plan = output.partition("to apply")[0]
        expect("new budget" in plan and plan.count("new key") == len(APPS), f"U5: {plan[-400:]}")
        for app in APPS:
            token = hashed(self.files[SECRETS / "apps" / app])
            row = self.sql(
                "SELECT key_alias, max_budget, budget_duration, max_parallel_requests FROM "
                f"\"LiteLLM_VerificationToken\" WHERE token = '{token}';"  # noqa: S608 - a hash of the probe's own key
            )
            defaults = (
                litellm_keys.APP_BUDGET_DOLLARS,
                litellm_keys.BUDGET_DURATION,
                litellm_keys.MAX_PARALLEL_REQUESTS,
            )
            wanted = "|".join(
                (
                    app,
                    *(
                        f"{value:g}" if isinstance(value, float) else str(value)
                        for value in defaults
                    ),
                )
            )
            expect(row == [wanted], f"U5: {app}'s key holds {row}")
        expect(created == 2, f"U5: E saw {created} one-offs, not the read and the write")
        self.hold(
            "U5",
            "the person budget and three keys planned new and made, each found by its hash with "
            "the defaults; E saw 2 one-offs (the control)",
        )

    def cell_u6(self) -> None:
        before = self.digest()
        output, _ = self.apply("U6", HAL_OK)
        expect(
            edge_copy.NOTHING_TO_CHANGE in output and "Type yes" not in output,
            f"U6: {output[-300:]}",
        )
        expect(self.digest() == before, "U6: D changed")
        self.hold("U6", f"nothing to change, exit 0, no question; D {before} unchanged")

    def cell_u14(self) -> None:
        before, master = self.digest(), self.home / MASTER
        master.unlink()
        output, _ = self.apply("U14 (a)", HAL_REFUSED)
        wanted = f"error: litellm-keys needs {master}; nothing switched next: hal setup"
        expect(wanted in output and "Type yes" not in output, f"U14 (a): {output[-300:]}")
        self.write_secret(MASTER, f"sk-{secrets.token_hex(32)}")
        output, _ = self.apply("U14 (b)", HAL_FAILURE)
        expect(
            "keys not read" in output and "next: hal apply" in output, f"U14 (b): {output[-300:]}"
        )
        for verb in ("stop", "start"):
            code, said, _ = self.hal(verb, UNIT)
            expect(code == HAL_OK, f"U14 (c): hal {verb} exited {code}: {said[-200:]}")
        self.wait_until_listening("U14 (c)")
        output, created = self.apply("U14 (c)", HAL_OK)
        expect(
            edge_copy.NOTHING_TO_CHANGE in output and created == 1,
            f"U14 (c): E {created}: {output[-300:]}",
        )
        app_key = self.home / SECRETS / "apps" / "hopin"
        aside = app_key.with_name("hopin.aside")
        app_key.rename(aside)
        output, _ = self.apply("U14 (d)", HAL_REFUSED)
        aside.rename(app_key)
        wanted = f"error: litellm-keys needs {app_key}; nothing switched next: hal setup"
        expect(wanted in output and "Type yes" not in output, f"U14 (d): {output[-300:]}")
        expect(self.digest() == before, "U14: D changed")
        self.hold(
            "U14",
            "(a) litellm-keys needs the master key, exit 4; (b) a new master key: keys not read, "
            "exit 3; (c) stop and start: nothing to change, one read; (d) as (a) for hopin's key; "
            "D unchanged",
        )

    def cell_u7(self) -> None:
        self.set_budget("hopin", 7)
        self.set_enabled(False)
        output, created = self.apply("U7", HAL_OK)
        plan, _, after = output.partition("to apply")
        expect(
            "- litellm switch off litellm, litellm-db, litellm-front · volumes litellm-db kept"
            in plan,
            f"U7: {plan[-300:]}",
        )
        expect(
            "litellm keys" not in output and "key changed" not in output,
            f"U7: the key step planned: {plan}",
        )
        expect("litellm is off" in after and created == 0, f"U7: E {created}: {after[-200:]}")
        self.run(
            ["docker", "volume", "inspect", f"{PROJECT}_litellm-db"]
        )  # a missing volume exits 1
        self.hold(
            "U7",
            "switch off with the volume kept, nothing under litellm, litellm is off, E empty, "
            "the volume exists",
        )

    def cell_u12(self) -> None:
        (self.home / PROVIDER).write_text("")
        self.set_enabled(True)
        output, created = self.apply("U12", HAL_FAILURE)
        expect(
            "partial, litellm is not on after the change" in output
            and "litellm is on" not in output,
            f"U12: {output[-300:]}",
        )
        expect({"litellm-db", FRONT} <= self.running(), f"U12: running {self.running()}")
        expect(created == 0, f"U12: E saw {created}")
        self.hold(
            "U12",
            "partial, litellm is not on after the change, exit 3; litellm-db and the front run",
        )

    def cell_r1(self) -> None:
        self.write_secret(PROVIDER, f"sk-{secrets.token_hex(32)}")
        said = []
        for _ in range(2):
            code, output, _ = self.hal("apply", "--local")
            said.append(f"exit {code}: {output.partition('to apply')[2][-160:] or output[-160:]}")
            if "litellm is on" in output:
                break
        else:
            raise edge_copy.ProbeFailed(f"R1: no `litellm is on` within two applies: {said}")
        self.hold("R1", f"{len(said)} applies; {' | '.join(said)}")

    def cell_u8(self) -> None:
        self.wait_until_listening("U8")
        output, _ = self.apply("U8", HAL_OK)
        expect("budget 7 → 10" in output.partition("to apply")[0], f"U8: {output[-300:]}")
        expect(
            float(self.budget_of("hopin")) == litellm_keys.APP_BUDGET_DOLLARS, "U8: hopin's budget"
        )
        self.hold("U8", "the kept volume's row planned `budget 7 → 10` and made; D shows 10")

    def cell_u9(self) -> None:
        code, said, _ = self.hal("stop", UNIT)
        expect(code == HAL_OK, f"U9: hal stop exited {code}: {said[-200:]}")
        self.compose("start", "litellm-db", "litellm")
        self.wait_until_listening("U9")
        self.set_budget("hopin", 8)
        output, created = self.apply("U9", HAL_OK)
        expect(
            "· litellm stays stopped" in output and edge_copy.NOTHING_TO_CHANGE in output,
            f"U9: {output[-300:]}",
        )
        expect("key changed" not in output and created == 0, f"U9: E {created}: {output[-300:]}")
        code, said, _ = self.hal("start", UNIT)
        expect(code == HAL_OK, f"U9: hal start exited {code}: {said[-200:]}")
        self.wait_until_listening("U9")
        output, _ = self.apply("U9", HAL_OK)
        expect(
            "budget 8 → 10" in output.partition("to apply")[0],
            f"U9: after the start {output[-300:]}",
        )
        self.hold(
            "U9",
            "stopped with its containers up by hand: stays stopped, nothing to change, E empty; "
            "after hal start the change planned",
        )

    def cell_u10(self) -> None:
        self.edit_compose(DB_HEALTH, DB_HEALTH.replace("5s", "6s"), "probe: litellm-db's interval")
        output, created = self.apply("U10", HAL_OK)
        expect(
            "~ litellm-db recreate definition changed" in output and DB_RESTARTS in output,
            f"U10: {output[-300:]}",
        )
        expect(created == 0, f"U10: E saw {created}")
        self.hold(
            "U10", "litellm-db recreated, `keys later its database restarts now`, exit 0, E empty"
        )

    def cell_u11(self) -> None:
        self.edit_compose(
            LITELLM_TELEMETRY,
            LITELLM_TELEMETRY + '      PROBE_MARK: "u11"\n',
            "probe: litellm's environment",
        )
        output, created = self.apply("U11", HAL_OK)
        expect(
            "~ litellm recreate definition changed" in output and STARTS_NOW in output,
            f"U11: {output[-300:]}",
        )
        expect(created == 0, f"U11: E saw {created}")
        self.hold("U11", "litellm recreated, `keys later LiteLLM starts now`, exit 0, E empty")


def prove(probe: Probe) -> int:
    try:
        probe.drive()
    except (edge_copy.ProbeFailed, subprocess.TimeoutExpired, OSError) as failure:
        write_line(f"PROBE FAILED: {failure}")
        return 1
    except KeyboardInterrupt:
        write_line("PROBE FAILED: interrupted")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(
        __doc__.splitlines()[0], argv, Probe, prove,
        lambda probe: edge_copy.passed_line(f"PASSED: {', '.join(probe.held)}"),
    )  # fmt: skip


if __name__ == "__main__":
    sys.exit(main())
