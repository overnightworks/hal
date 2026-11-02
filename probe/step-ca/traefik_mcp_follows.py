"""traefik-mcp follows its file and its definition while step-ca is on: proof 13 of #89, the cells
P13a-P13h. A mixin of the step-ca probe (probe.py): it uses the probe's compose, hal, volume and
container helpers, and drives `hal apply --local` on the copy of the repository the probe made."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import edge_copy
from edge_copy import GUARDED_COMPOSE_VERBS, expect, publish
from step_ca_names import COMPOSE_FILE, INTERMEDIATE_IN_VOLUME, NOTHING_TO_CHANGE

from hal.output import write_line
from hal.stack import checkout, core

FOLLOWER = "traefik-mcp"
STEP_CA_PROFILE = "step-ca"
FOLLOWER_FILE = "traefik-mcp.yml"
HARMLESS_EDIT = "# probe 13: a harmless edit\n"
PROBE_LABEL = '    labels: {edge.probe: "13"}\n'  # a definition change that changes nothing else
# Where the probe label goes in compose.yaml: after the follower's profile line. A label on step-ca
# would recreate it, as apply does for every unit whose definition changed.
LABEL_AFTER = "  traefik-mcp:\n    <<: *traefik\n    profiles: [step-ca]\n"


class TraefikMcpFollows:
    def copy_compose(self, copy: Path, *arguments: str) -> str:
        command = edge_copy.copy_compose_command(copy)
        if arguments[0] in GUARDED_COMPOSE_VERBS:
            self.guard.expect(command, once=False)
        return self.run([*command, *arguments]).stdout.decode()

    def ids(self) -> tuple[str, str]:
        return self.container_id(FOLLOWER), self.container_id("step-ca")

    def follower_entry(self) -> dict | None:
        record = self.state_directory / core.APPLIED_FILE
        return json.loads(record.read_text()).get(FOLLOWER) if record.exists() else None

    def follower_digest(self, copy: Path) -> dict:
        return core.digests([copy / FOLLOWER_FILE], copy)

    def intermediate_now(self) -> str:
        return self.certificate_fingerprint(self.in_volume("cat", INTERMEDIATE_IN_VOLUME))

    def apply_says_nothing_to_change(self, copy: Path, cell: str) -> str:
        out = self.hal(copy, "apply", "--local", terminal=True, typed=b"no\n")
        expect(NOTHING_TO_CHANGE in out, f"{cell}: apply said: {out[-200:]}")
        expect("Type" not in out, f"{cell}: apply asked for `yes` with nothing to change")
        return out

    def edit_follower_file(self, copy: Path) -> None:
        with (copy / FOLLOWER_FILE).open("a") as file:
            file.write(HARMLESS_EDIT)
        publish(copy, f"probe: a harmless {FOLLOWER_FILE} edit")

    def proof_13a_followers(self, copy: Path) -> None:
        config = json.loads(self.copy_compose(copy, "config", "--format", "json"))
        # Every profile is rendered, so the agent service's gateway is a follower here too.
        followers = tuple(
            name
            for name in core.followers(config)
            if STEP_CA_PROFILE in config["services"][name]["profiles"]
        )
        tracked = core.Checkout.read(config, checkout.Git(copy))
        binds = core.file_binds(config["services"][FOLLOWER], tracked)
        expect(followers == (FOLLOWER,), f"P13a: the followers are {followers}")
        expect(binds == (copy / FOLLOWER_FILE,), f"P13a: traefik-mcp's file binds are {binds}")
        write_line(f"P13a held: followers {followers}, file bind {binds[0]}")

    def proof_13b_file_follows(self, copy: Path) -> None:
        follower, step_ca = self.ids()
        intermediate, serial = self.intermediate_now(), self.wait_until_served()["serial_number"]
        self.edit_follower_file(copy)
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect("traefik-mcp recreate traefik-mcp.yml changed" in out, f"P13b: {out[-240:]}")
        expect(re.search(r"traefik-mcp +recreated\b", out) is not None, out)
        expect(self.container_id(FOLLOWER) != follower, "P13b: traefik-mcp kept its container")
        expect(self.container_id("step-ca") == step_ca, "P13b: step-ca was recreated")
        self.wait_until_answering()
        served = self.wait_until_served()["serial_number"]
        expect(self.intermediate_now() == intermediate, "P13b: the intermediate changed")
        expect(served == serial, f"P13b: served serial {serial[-8:]} -> {served[-8:]}")
        entry = self.follower_entry()
        expect(entry == self.follower_digest(copy), f"P13b: the entry is {entry}")
        write_line(
            f"P13b held: traefik-mcp {follower[:12]} -> {self.container_id(FOLLOWER)[:12]}, "
            f"step-ca {step_ca[:12]} kept, intermediate {intermediate}, serial ...{serial[-8:]} "
            f"kept, entry {entry}"
        )

    def proof_13c_second_run(self, copy: Path) -> None:
        ids = self.ids()
        self.apply_says_nothing_to_change(copy, "P13c")
        expect(self.ids() == ids, "P13c: a container was replaced")
        label = self.run(
            ["docker", "inspect", "--format",
             '{{index .Config.Labels "com.docker.compose.config-hash"}}', ids[0]]
        ).stdout.decode().strip()  # fmt: skip
        hashed = self.copy_compose(copy, "config", "--hash", FOLLOWER).split()
        expect(hashed == [FOLLOWER, label], f"P13c: label {label}, config --hash {hashed}")
        write_line(f"P13c held: nothing to change, same ids, label = config --hash = {label[:12]}")

    def proof_13d_definition_follows(self, copy: Path) -> None:
        follower, step_ca = self.ids()
        compose_file = copy / COMPOSE_FILE
        text = compose_file.read_text()
        text = text.replace(LABEL_AFTER, LABEL_AFTER + PROBE_LABEL, 1)
        compose_file.write_text(text)
        publish(copy, "probe: a label on traefik-mcp")
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect("traefik-mcp recreate definition changed" in out, out[-240:])
        expect("step-ca recreate" not in out, f"P13d: step-ca was named: {out[-240:]}")
        expect(self.container_id(FOLLOWER) != follower, "P13d: traefik-mcp kept its container")
        expect(self.container_id("step-ca") == step_ca, "P13d: step-ca was recreated")
        self.apply_says_nothing_to_change(copy, "P13d")
        write_line(f"P13d held: traefik-mcp recreated for its label, step-ca {step_ca[:12]} kept")
        self.answer_the_acme_owner_question(copy)

    def answer_the_acme_owner_question(self, copy: Path) -> None:
        """Whether `up --no-deps traefik-mcp` waits on the missing one-shot it depends on to
        complete: a fact of Compose, reported, not ruled."""
        self.compose("rm", "--force", "--stop", "traefik-mcp-acme-owner")
        started = time.monotonic()
        self.copy_compose(copy, "up", "-d", "--no-deps", "--force-recreate", FOLLOWER)
        seconds = time.monotonic() - started
        owner = self.container_id("traefik-mcp-acme-owner") or "none"
        running = self.compose("ps", "-q", "--status", "running", FOLLOWER).stdout.decode().strip()
        write_line(
            f"P13 acme owner: `up --no-deps --force-recreate traefik-mcp` without the owner "
            f"returned in {seconds:.1f} s; owner container: {owner[:12]}; traefik-mcp running: "
            f"{bool(running)}"
        )
        # A missing owner leaves the unit not up: this apply makes it again, else changes nothing.
        self.hal(copy, "apply", "--local", terminal=True)
        self.apply_says_nothing_to_change(copy, "P13 acme owner")

    def proof_13e_switched_off(self, copy: Path) -> None:
        marker = self.state_directory / "stopped" / "step-ca"
        recorded = (copy / FOLLOWER_FILE).read_text()
        self.hal(copy, "stop", "step-ca", terminal=False)
        written = marker.read_text()
        self.edit_follower_file(copy)
        out = self.apply_says_nothing_to_change(copy, "P13e")
        expect("step-ca stays stopped" in out, f"P13e: {out[-240:]}")
        held = "traefik-mcp not started traefik-mcp.yml changed · step-ca is switched off"
        expect(held in out, f"P13e: {out[-240:]}")
        expect(not self.containers_of_unit(running_only=True), "P13e: a container runs")
        expect(marker.read_text() == written, "P13e: apply touched the marker")
        self.volume_names_exist()
        (copy / FOLLOWER_FILE).write_text(recorded)
        publish(copy, f"probe: {FOLLOWER_FILE} as recorded")
        self.hal(copy, "start", "step-ca", terminal=True)
        self.wait_until_answering()
        self.apply_says_nothing_to_change(copy, "P13e after start")
        write_line("P13e held: switched off, the held line, nothing to change, nothing running")

    def proof_13f_disabled(self, copy: Path) -> None:
        held = "traefik-mcp not started traefik-mcp.yml changed · step-ca is off"
        self.set_enabled(copy, False)
        self.edit_follower_file(copy)
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect(held in out and "step-ca switch off" in out, f"P13f: {out[-240:]}")
        expect(not self.containers_of_unit(running_only=False), "P13f: containers are left")
        out = self.apply_says_nothing_to_change(copy, "P13f")
        expect(held in out, f"P13f: a second apply said {out[-240:]}")
        self.volume_names_exist()
        write_line("P13f held: disabled, the held line twice, no container")

    def proof_13g_switch_on_record(self, copy: Path) -> None:
        self.set_enabled(copy, True)
        out = self.hal(copy, "apply", "--local", terminal=True)
        expect("traefik-mcp starts later" in out and "with step-ca" in out, f"P13g: {out[-240:]}")
        expect("traefik-mcp recreate" not in out, f"P13g: {out[-240:]}")
        self.wait_until_answering()
        self.wait_until_served()
        entry = self.follower_entry()
        expect(entry == self.follower_digest(copy), f"P13g: the entry is {entry}")
        self.apply_says_nothing_to_change(copy, "P13g")
        write_line(
            f"P13g held: switched on, entry {entry} recorded, the next apply changes nothing"
        )

    def proof_13_traefik_mcp_follows(self) -> None:
        copy = self.repository_copy()
        self.set_enabled(copy, True)
        self.compose("up", "--detach", "--no-deps", "hello-mcp")  # proof 12 took it down
        intermediate = self.intermediate_now()
        self.proof_13a_followers(copy)
        self.proof_13b_file_follows(copy)
        self.proof_13c_second_run(copy)
        self.proof_13d_definition_follows(copy)
        self.proof_13e_switched_off(copy)
        self.proof_13f_disabled(copy)
        self.proof_13g_switch_on_record(copy)
        self.volume_names_exist()
        expect(self.intermediate_now() == intermediate, "P13h: the intermediate changed")
        write_line(
            "P13h held: both volumes and the intermediate kept, the marker kept across apply"
        )
