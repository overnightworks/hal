"""Probe of #995's cell: the copy's real `hal apply` moves LiteLLM from the image it runs to the one
compose.yaml pins, after the unit's pre-apply snapshot is taken and proven. Nothing live and nothing
paid: no provider key, no egress, no app.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        uv run --frozen python3 probe/agent-service/litellm_move.py --scratch DIR

The copy, its secrets and its `hal apply` are litellm_unit.py's. Before any `hal apply` the copy's
`backup/apps.toml` gets litellm_backup.py's change: the shipped `litellm` record with only
`compose_project` replaced by the probe's project; the probe refuses to start unless it parses so,
since the shipped record would point the pre-apply backup at the live `litellm-db`. The restic
repository and its password are the scratch HOME's. The copy starts LiteLLM, and its database
where a local image of the pinned major exists, on an image `docker image ls` shows locally with
another digest than the pin; publishing the shipped pin is then the move. The fake provider is
litellm.py's `fake_anthropic.py` at the address compose.yaml gives api.anthropic.com, on the
internal `litellm-egress`, with a certificate of a scratch CA that the copy's LiteLLM trusts through
SSL_CERT_FILE. C is every docker call, behind its caller's command line (litellm_unit.py's stand-in
writes it): the order of the backup's dump, the restore test's server and the recreate, and the
proof that no call of `hal backup` or `hal restore` names the live project. Exit 0: every cell held.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import secrets
import sys
import tomllib
from collections.abc import Callable
from pathlib import Path
from types import SimpleNamespace

sys.path[:0] = [str(Path(__file__).resolve().parent), str(Path(__file__).resolve().parents[1])]

import edge_copy  # noqa: E402
import yaml  # noqa: E402
from edge_copy import HAL_OK, expect, publish  # noqa: E402
from litellm import (  # noqa: E402
    DEFAULT_MODEL,
    PROVIDER_HOST,
    ROUTE,
    START_LISTENER,
    LitellmProbe,
    answer_text,
    shipped_models,
    wire_body,
)
from litellm_caller import CALL_PROGRAM, caller_input  # noqa: E402
from litellm_unit import (  # noqa: E402
    APPS,
    COMPOSE_FILE,
    LABEL,
    PICTURES,
    PLAN_END,
    PROJECT,
    PROVIDER,
    REPO,
    SECRETS,
    YES_PROMPT,
    Probe,
    run,
)
from scratch_secrets import write_new, write_scratch_secrets  # noqa: E402

from hal.backup.apps import parse_apps  # noqa: E402
from hal.backup.cli import DEFAULT_APPS  # noqa: E402
from hal.backup.docker import RESTORE_SERVER_PREFIX  # noqa: E402
from hal.backup.settings import Settings  # noqa: E402
from hal.output import write_line  # noqa: E402
from hal.stack import catalog, litellm_keys  # noqa: E402

APP = litellm_keys.LITELLM.key
LITELLM, DATABASE = litellm_keys.LITELLM.service, litellm_keys.LITELLM.database
MOVABLE = (LITELLM, DATABASE)
CA_IN_LITELLM = "/probe/ca.crt"
FAKE_DIRECTORY = "/fake"
FAKE_NAME = f"{PROJECT}-fake-provider"
BACKUP_CALLERS = re.compile(r"/hal (?:backup|restore) ")
SERVICE_BLOCK = r"^  {service}:\n(?: {{4}}.*\n|\n)+"
MOVE_ROW = re.compile(rf"~ {LITELLM} recreate image (\S+) → (\S+) · snapshot first")
PROVEN_ROW = re.compile(rf"{LITELLM} recreated snapshot ([0-9a-f]+) proven")
SHOWN_DIGEST = re.compile(r"@([0-9a-f]+)…")  # the first hex digits of a digest, as hal shows it


@dataclasses.dataclass(frozen=True)
class Move:
    """One service's move: the local image it starts on and the image compose.yaml pins."""

    service: str
    local: str
    pinned: str


def digest_of(reference: str) -> str:
    return reference.rpartition("@")[2]


class MoveProbe(Probe):
    """litellm_unit.py's copy, its LiteLLM moved by `hal apply` from a local image to the pin."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.calls = scratch / "docker-calls"
        self.calls.touch()
        self.environment["DOCKER_CALLS"] = str(self.calls)
        self.settings = Settings.for_home(self.home, os.getuid(), os.getgid())
        (self.home / ".secrets").mkdir(mode=0o700)
        self.settings.password_file.parent.mkdir(mode=0o700)
        write_new(self.settings.password_file, secrets.token_urlsafe(32).encode(), 0o600)
        self.marker = secrets.token_hex(8)
        self.moves: list[Move] = []
        self.proven = ""  # the short ID of the snapshot the move's result row names
        self.live_name = edge_copy.compose_project_name((REPO / COMPOSE_FILE).read_text())

    # --- the copy -----------------------------------------------------------------------------

    def point_backup_at_probe(self) -> None:
        """The copy's `litellm` record with the probe's project; refuses to go on unless it parses
        to the shipped records with only that one field changed and names no live project."""
        apps_file = self.copy / DEFAULT_APPS.relative_to(REPO)
        shipped_text = apps_file.read_text()
        live = tomllib.loads(shipped_text)["app"][APP]["compose_project"]
        section = re.compile(
            rf'(^\[app\.{APP}\]\n(?:[^\[\n].*\n|\n)*?compose_project = )"[^"]*"', re.MULTILINE
        )
        text, count = section.subn(rf'\g<1>"{PROJECT}"', shipped_text)
        expect(count == 1, f"the copy's apps.toml has no {APP} record with a compose_project")
        apps_file.write_text(text)
        declared = parse_apps(apps_file.read_text())
        wanted = tuple(
            dataclasses.replace(app, compose_project=PROJECT) if app.name == APP else app
            for app in parse_apps(shipped_text)
        )
        expect(declared == wanted, "the copy's apps.toml differs beyond litellm's project")
        named = next(app.compose_project for app in declared if app.name == APP)
        expect(
            named not in {live, self.live_name}, f"the copy's {APP} record names the live project"
        )

    def edit_service(self, service: str, edit: Callable[[str], str]) -> None:
        """The copy's compose.yaml with `service`'s block replaced by `edit(block)`."""
        file = self.copy / COMPOSE_FILE
        text = file.read_text()
        block = re.search(SERVICE_BLOCK.format(service=re.escape(service)), text, re.MULTILINE)
        expect(block is not None, f"the copy's compose.yaml has no service {service}")
        file.write_text(text[: block.start()] + edit(block[0]) + text[block.end() :])

    def trust_the_fake(self) -> None:
        """litellm.py's fake files for a scratch CA, and LiteLLM trusting that CA alone."""
        (self.scratch / "ca-home").mkdir()
        authority = write_scratch_secrets(self.scratch / "ca-home", self.scratch / "ca")
        authority.ca_certificate.chmod(0o644)
        LitellmProbe.write_fakes(
            SimpleNamespace(
                provider_key=self.files[PROVIDER],
                picture_key=self.files[PICTURES],
                identity={},
                marker=self.marker,
                scratch_secrets=authority,
            ),
            self.scratch / "fake",
        )
        additions = {
            "    environment:\n": f"      SSL_CERT_FILE: {CA_IN_LITELLM}\n",
            "    volumes:\n": f"      - {authority.ca_certificate}:{CA_IN_LITELLM}:ro\n",
        }

        def trusting(block: str) -> str:
            for key, added in additions.items():
                expect(block.count(key) == 1, f"{LITELLM} has no single {key.strip()}")
                block = block.replace(key, key + added)
            return block

        self.edit_service(LITELLM, trusting)

    def local_image(self, pinned: str) -> str | None:
        """An image of the pinned repository and major that `docker image ls` lists locally with
        another digest, by its tag and digest."""
        name, _, digest = pinned.partition("@")
        repository, _, tag = name.rpartition(":")
        listing = self.run(
            ["docker", "image", "ls", "--digests", "--format", "{{json .}}", repository]
        ).stdout.splitlines()
        for row in map(json.loads, listing):
            same_major = row["Tag"].split(".")[0] == tag.split(".")[0]
            if same_major and row["Digest"].startswith("sha256:") and row["Digest"] != digest:
                return f"{repository}:{row['Tag']}@{row['Digest']}"
        return None

    def pin(self, move: Move, reference: str) -> None:
        """Every use of the service's image in the copy's compose.yaml, an anchor's too."""
        current = move.pinned if reference == move.local else move.local
        file = self.copy / COMPOSE_FILE
        text = file.read_text()
        expect(current in text, f"the copy's compose.yaml does not name {current}")
        file.write_text(text.replace(current, reference))

    def start_on_local_images(self) -> None:
        resolved = json.loads(self.compose("config", "--format", "json"))["services"]
        for service in MOVABLE:
            pinned = resolved[service]["image"]
            local = self.local_image(pinned)
            if local is None:
                write_line(f"{service}: no local image of {pinned.partition('@')[0]}'s major")
                continue
            self.moves.append(Move(service, local, pinned))
            self.pin(self.moves[-1], local)
        expect(any(move.service == LITELLM for move in self.moves), "no local LiteLLM image")

    # --- evidence -----------------------------------------------------------------------------

    def call_lines(self, since: int = 0) -> list[tuple[str, str]]:
        """C from line `since`: each docker call as (its caller's command line, its argv)."""
        lines = self.calls.read_text().splitlines()[since:]
        return [tuple(line.split("\t", 1)) for line in lines]

    def container_of(self, service: str) -> dict:
        (found,) = self.compose("ps", "--all", "--quiet", service).split()
        return json.loads(self.run(["docker", "inspect", found]).stdout)[0]

    def image_identity(self, reference: str) -> str:
        return self.run(
            ["docker", "image", "inspect", "--format", "{{.Id}}", reference]
        ).stdout.strip()

    def start_fake(self) -> None:
        resolved = json.loads(self.compose("config", "--format", "json"))["services"][LITELLM]
        hosts = resolved["extra_hosts"]
        entries = hosts if isinstance(hosts, list) else [f"{k}={v}" for k, v in hosts.items()]
        (address,) = (
            re.split("[=:]", e, maxsplit=1)[1] for e in entries if e.startswith(PROVIDER_HOST)
        )
        self.run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                FAKE_NAME,
                "--label",
                LABEL,
                "--network",
                f"{PROJECT}_litellm-egress",
                "--ip",
                address,
                "--user",
                "65534:65534",
                "--read-only",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--sysctl",
                "net.ipv4.ip_unprivileged_port_start=0",
                "--mount",
                f"type=bind,source={self.scratch / 'fake' / PROVIDER_HOST},"
                f"target={FAKE_DIRECTORY},readonly",
                self.keys_image(),
                "python",
                "-I",
                "-B",
                f"{FAKE_DIRECTORY}/fake_anthropic.py",
                "provider",
            ]
        )

    def provider_requests(self) -> list[dict]:
        log = self.run(["docker", "logs", FAKE_NAME]).stdout
        return [json.loads(line) for line in log.splitlines() if line.startswith("{")]

    def complete(self, cell: str, key: str) -> None:
        """One chat request with `key` straight at LiteLLM: served with the fake's marker, and the
        fake saw one more request, with the scratch provider key and the model config.yaml names."""
        start = (self.copy / "agent-service" / "litellm" / "start.sh").read_text()
        listener = START_LISTENER.search(start)
        expect(listener is not None, "start.sh names no LiteLLM port")
        before = len(self.provider_requests())
        argv = [
            "docker",
            "run",
            "--rm",
            "-i",
            "--label",
            LABEL,
            "--network",
            f"{PROJECT}_litellm-backend",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            self.keys_image(),
            "python",
            "-I",
            "-",
            LITELLM,
            listener[2],
            "POST",
            ROUTE,
        ]
        body = wire_body(DEFAULT_MODEL, f"fp-{secrets.token_hex(8)}")
        program = caller_input(CALL_PROGRAM, key, body, [key])
        called = edge_copy.run_command(
            argv, input=program.encode(), env=self.environment, timeout=240
        )
        expect(called.returncode == 0, f"{cell}: the caller exited {called.returncode}")
        answer = json.loads(called.stdout.decode().strip().splitlines()[-1])
        expect(answer["status"] == 200, f"{cell}: LiteLLM answered {answer['status']}")
        expect(answer_text(answer) == self.marker, f"{cell}: the marker is not in the answer")
        sent = self.provider_requests()[before:]
        wanted = shipped_models()[DEFAULT_MODEL]["model"].split("/", 1)[1]
        expect([(r["model"], r["key_ok"]) for r in sent] == [(wanted, True)], f"{cell}: F {sent}")

    # --- the cell -----------------------------------------------------------------------------

    def drive(self) -> None:
        _, with_entry = self.prepare()
        self.point_backup_at_probe()
        self.trust_the_fake()
        self.start_on_local_images()
        (self.copy / catalog.FLEET_FILE).write_text(with_entry)
        publish(self.copy, "probe: litellm on the local images, its backup at the probe's project")
        self.cell_m0()
        since, before = self.cell_m1()
        self.cell_m2(since)
        self.cell_m3(before)
        self.cell_m4()
        self.cell_m5()

    def cell_m0(self) -> None:
        code, said, _ = self.hal("backup", "--init")
        expect(code == HAL_OK, f"M0: hal backup --init exited {code}: {said[-200:]}")
        self.apply("M0", HAL_OK)
        self.wait_until_listening("M0")
        self.start_fake()
        self.apply("M0", HAL_OK)
        self.complete("M0", self.files[SECRETS / "apps" / APPS[0]])
        for move in self.moves:
            running = self.container_of(move.service)["Image"]
            expect(running == self.image_identity(move.local), f"M0: {move.service} runs {running}")
        self.hold(
            "M0",
            "on the local images: "
            + "; ".join(f"{move.service} {digest_of(move.local)[:19]}" for move in self.moves)
            + f"; {APPS[0]}'s key, made by the key step, served through the fake",
        )

    def cell_m1(self) -> tuple[int, dict[str, dict]]:
        """The plan names the move and the snapshot; after the yes it ran."""
        before = {move.service: self.container_of(move.service) for move in self.moves}
        for move in self.moves:
            self.pin(move, move.pinned)
        publish(self.copy, "probe: compose.yaml's pins again")
        since = len(self.call_lines())
        output, _ = self.apply("M1", HAL_OK)
        plan, _, after = output.partition(PLAN_END)
        row = MOVE_ROW.search(plan)
        expect(row is not None and YES_PROMPT in output, f"M1: no move row: {plan[-400:]}")
        (litellm,) = (move for move in self.moves if move.service == LITELLM)
        shown = [SHOWN_DIGEST.search(text) for text in row.groups()]
        expect(
            all(shown)
            and digest_of(litellm.local).removeprefix("sha256:").startswith(shown[0][1])
            and digest_of(litellm.pinned).removeprefix("sha256:").startswith(shown[1][1]),
            f"M1: the row names other images: {row[0]}",
        )
        proven = PROVEN_ROW.search(after)
        expect(proven is not None, f"M1: no proven snapshot after the yes: {after[-400:]}")
        self.proven = proven[1]
        self.hold("M1", f"`{row[0]}`; after the yes `{proven[0]}`, exit 0")
        return since, before

    def cell_m2(self, since: int) -> None:
        """C: the dump, then the restore test's server reading the named snapshot, then the
        recreate; no call of hal backup or hal restore names the live project."""
        argvs = [argv for _, argv in self.call_lines(since)]

        def first(what: str, matches: Callable[[str], bool]) -> int:
            found = next((i for i, argv in enumerate(argvs) if matches(argv)), None)
            expect(found is not None, f"M2: C holds no {what}")
            return found

        dump = first("dump", lambda argv: argv.startswith("exec ") and " pg_dump " in argv)
        server = first("restore test", lambda argv: f"--name {RESTORE_SERVER_PREFIX}-" in argv)
        recreate = first("recreate", lambda argv: argv.endswith(f"--force-recreate {LITELLM}"))
        expect(
            dump < server < recreate, f"M2: dump {dump}, restore test {server}, recreate {recreate}"
        )
        short = self.proven
        expect(
            any(short in argv for argv in argvs[dump:recreate]), "M2: no call reads the snapshot"
        )
        self.hold(
            "M2",
            f"C: pg_dump at call {dump}, the restore test's server at {server}, a call "
            f"naming snapshot {short} between, `up --force-recreate {LITELLM}` at {recreate}",
        )

    def cell_m3(self, before: dict[str, dict]) -> None:
        for move in self.moves:
            now = self.container_of(move.service)
            pinned = self.image_identity(move.pinned)
            expect(now["Id"] != before[move.service]["Id"], f"M3: {move.service} not recreated")
            expect(now["Image"] == pinned, f"M3: {move.service} runs {now['Image']}, not the pin")
        self.hold(
            "M3",
            "; ".join(
                f"{move.service} {digest_of(move.local)[:19]} → {digest_of(move.pinned)[:19]}, "
                "a new container on the pinned image"
                for move in self.moves
            ),
        )

    def cell_m4(self) -> None:
        self.wait_until_listening("M4")
        self.complete("M4", self.files[SECRETS / "apps" / APPS[0]])
        self.hold(
            "M4",
            f"{APPS[0]}'s key from before the move authenticates; LiteLLM answers "
            "with the fake's marker, F saw the scratch provider key",
        )

    def cell_m5(self) -> None:
        output, _ = self.apply("M5", HAL_OK)
        expect(
            edge_copy.NOTHING_TO_CHANGE in output and YES_PROMPT not in output,
            f"M5: {output[-300:]}",
        )
        self.hold("M5", "the next hal apply: nothing to change, no question, exit 0")
        self.expect_no_live_call("M6")

    def expect_no_live_call(self, cell: str) -> None:
        """No call of hal backup or hal restore names the live project: by its Compose label or
        project option, a container `<project>-<service>-<n>`, or a volume or network
        `<project>_<name>`. restic's fixed host name is no project and is not counted."""
        services = yaml.safe_load((REPO / COMPOSE_FILE).read_text())["services"]
        alternatives = "|".join(map(re.escape, services))
        live = re.escape(self.live_name)
        naming = re.compile(
            rf"(?:com\.docker\.compose\.project=|(?:^|\s)(?:-p|--project-name)[ =]){live}(?:\s|$)"
            rf"|(?:^|[\s=/]){live}-(?:{alternatives})-\d|(?:^|[\s=]){live}_"
        )
        backup = [argv for caller, argv in self.call_lines() if BACKUP_CALLERS.search(caller)]
        own = f"com.docker.compose.project={PROJECT}"
        expect(any(own in argv for argv in backup), f"{cell}: no backup call names {own}")
        named = sorted({found[0].strip() for argv in backup for found in naming.finditer(argv)})
        expect(not named, f"{cell}: calls of hal backup or restore name the live project: {named}")
        self.hold(
            cell,
            f"C: none of {len(backup)} calls of hal backup and hal restore names the "
            f"live project {self.live_name}; they name {own}",
        )


def main(argv: list[str] | None = None) -> int:
    return run(MoveProbe, argv)


if __name__ == "__main__":
    sys.exit(main())
