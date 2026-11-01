"""Probe of the image swap of a built service (#482 D1a-D1d, #91): a throwaway compose project,
HOME and copy of the repository, and a unit `built-probe` with `run.build` whose one service has
`pull_policy: never`. Its tags are made with `docker tag` from busybox images that are already
local; nothing is built or pulled, and the core is never started.

D1a: a bumped tag is recreated under one yes, with a new id and the new image; a second apply
changes nothing. D1b: a container that restarts on the old tag is recreated onto the new tag by
one apply, which leaves it running. D1c: the unchanged tag is removed with `docker rmi -f`; the
drive prints what `docker compose ps` shows as Image (U9) and whether `docker image ls --filter
reference=` matches exactly the tag (U8); the plan gives no recreate line and no planning failure.
D1d: the unchanged reference is re-tagged to another image; the drive prints the `ps` Image (U9);
one yes gives the "rebuilt" line and a recreate onto the new id. A `ps` Image that is neither the
reference nor the container's full image-id label stops the drive.

It removes its containers, networks, volumes and tags. It never names the project `edge`.

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 900 \\
        python3 probe/switches/built_image.py --scratch DIR

Measured teardown: 11 s (K 30 s, CAP 900 s).

Needs an existing, empty --scratch directory, `uv` (it runs `uv sync` in the copy) and the local
images busybox:1.36 and busybox:1.37.0. It leaves --scratch empty, passed or failed (`edge_copy`).
"""

from __future__ import annotations

import grp
import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "probe"))  # the helper of the probes, importable by path too
sys.path.insert(0, str(REPO / "src"))  # edge's own facts; its modules need only the stdlib

import edge_copy  # noqa: E402
from edge_copy import ProbeFailed, expect  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import compose  # noqa: E402
from hal.stack.built_image import ENDS_RUNS  # noqa: E402

PROJECT = "edge-built-image-probe"
UNIT = "built-probe"
RECIPE = f"{UNIT}/image"
ZONE = "built-image.invalid"
FLEET = (
    f"cloudflare:\n  zone: {ZONE}\ngithub:\nservices:\n"
    f"  {UNIT}:\n    run:\n      enabled: true\n      build: {RECIPE}\n"
)
TAG_REPOSITORY = "edge-built-probe"
IMAGE_WORKS = "busybox:1.36"
IMAGE_OTHER = "busybox:1.37.0"
KEEPS_RUNNING = '["sleep", "100000"]'
EXITS_AT_ONCE = '["false"]'
SERVICE_TEXT = """\
  built-probe:
    image: {tag}
    pull_policy: never
    profiles: [built-probe]
    restart: unless-stopped
    command: {command}

"""
COMPOSE_FILE = "compose.yaml"
NOTHING_TO_CHANGE = "nothing to change"
COMPOSE_SECONDS = 300
STOP_THE_LANE = "stop the lane (body, Acceptance): ps Image is neither the reference nor the id"


class Drive:
    def __init__(self, scratch: Path) -> None:
        self.scratch = scratch
        self.home = scratch / "home"
        self.home.mkdir(parents=True)
        self.environment = {
            **os.environ,
            "HOME": str(self.home),
            "COMPOSE_PROJECT_NAME": PROJECT,
            "EDGE_DOMAIN": ZONE,
            "DOCKER_GID": str(grp.getgrnam("docker").gr_gid),
            "NO_COLOR": "1",
        }
        self.environment.pop("DBUS_SESSION_BUS_ADDRESS", None)
        self.copy = self.home
        self.tags: list[str] = []
        self.guard: edge_copy.NetworkGuard | None = None

    # --- Docker -----------------------------------------------------------------------------

    def docker(self, *arguments: str) -> str:
        result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["docker", *arguments], capture_output=True, text=True, env=self.environment,  # noqa: S607 - docker is found on PATH by design
            cwd=self.copy if self.copy.exists() else REPO, check=False, timeout=COMPOSE_SECONDS,
        )  # fmt: skip
        if result.returncode != 0:
            tail = (result.stderr or result.stdout).strip().splitlines()
            raise ProbeFailed(
                f"docker {' '.join(arguments[:2])} exited {result.returncode}: {tail[-1:]}"
            )
        return result.stdout

    def compose(self, *arguments: str) -> str:
        every_profile = ("--profile", "*", *arguments)
        return self.docker(*edge_copy.guarded_compose(self.copy, self.guard, every_profile))

    def engine(self) -> compose.Compose:
        """edge's own Compose reader, over the copy and the drive's project."""
        return edge_copy.compose_engine(self.environment, self.copy)

    def container(self) -> dict:
        """The unit's container as `docker compose ps` shows it, and as Docker inspects it."""
        listed = self.compose("ps", "--all", "--format", "json", UNIT).strip().splitlines()
        expect(len(listed) == 1, f"expected one {UNIT} container, found {len(listed)}")
        shown = json.loads(listed[0])
        inspected = json.loads(self.docker("inspect", shown["ID"]))[0]
        return {
            "id": shown["ID"],
            "state": shown["State"],
            "ps_image": shown["Image"],
            "image_id": inspected["Image"],
            "label_id": inspected["Config"]["Labels"]["com.docker.compose.image"],
        }

    def tag(self, source: str, tag: str) -> str:
        """`docker tag source TAG_REPOSITORY:tag`; the reference."""
        reference = f"{TAG_REPOSITORY}:{tag}"
        self.docker("tag", source, reference)
        if reference not in self.tags:
            self.tags.append(reference)
        return reference

    def image_id_of(self, reference: str) -> str:
        return self.docker("image", "inspect", "--format", "{{.Id}}", reference).strip()

    # --- the copy ---------------------------------------------------------------------------

    def use_service(self, reference: str, command: str = KEEPS_RUNNING) -> None:
        """compose.yaml of the copy names `reference` for the unit's service, published."""
        path = self.copy / COMPOSE_FILE
        lines = path.read_text().splitlines(keepends=True)
        for index, line in enumerate(lines):
            if line.startswith(f"  {UNIT}:"):
                end = next(
                    i for i in range(index + 1, len(lines)) if not lines[i].startswith("   ")
                )
                del lines[index:end]
                break
        text = "".join(lines)
        services_end = text.index("\nvolumes:\n") + 1
        text = (
            text[:services_end]
            + SERVICE_TEXT.format(tag=reference, command=command)
            + text[services_end:]
        )
        path.write_text(text)
        edge_copy.publish(self.copy, f"probe: {UNIT} names {reference}")
        assert self.guard  # noqa: S101 - narrows the type of the guard that the setup sets
        self.guard.expect(edge_copy.copy_compose_command(self.copy), once=False)

    def hal(self, typed: bytes = b"yes\n", exit_code: int = 0) -> str:
        return edge_copy.run_hal(
            self.copy, self.environment, "apply", "--local",
            terminal=True, exit_code=exit_code, typed=typed,
        )  # fmt: skip

    def start_container(self) -> None:
        """A container from compose.yaml as it is, made by Compose itself and not by apply."""
        self.compose("up", "--detach", "--force-recreate", "--no-deps", UNIT)

    # --- the cells --------------------------------------------------------------------------

    def bring_up(self) -> None:
        self.copy = edge_copy.repository_copy(REPO, self.home, self.scratch, PROJECT)
        self.guard = edge_copy.NetworkGuard(PROJECT, lambda command: self.docker(*command[1:]))
        recipe = self.copy / RECIPE
        recipe.mkdir(parents=True)
        (recipe / "Dockerfile").write_text(f"FROM {IMAGE_WORKS}\n")
        (self.copy / "fleet.yaml").write_text(FLEET)
        first = self.tag(IMAGE_WORKS, "d1a-old")
        self.use_service(first)
        resolved = json.loads(self.compose("config", "--format", "json"))
        expect(resolved["name"] == PROJECT, f"the project is {resolved['name']!r}, not {PROJECT}")
        write_line(f"setup: project {PROJECT}, unit {UNIT} names {first}; the core is not started")

    def d1a_a_bumped_tag(self) -> None:
        first = f"{TAG_REPOSITORY}:d1a-old"
        out = self.hal()
        expect(f"{UNIT} is on" in out, f"the first apply said: {out[-300:]}")
        before = self.container()
        bumped = self.tag(IMAGE_OTHER, "d1a-new")
        self.use_service(bumped)
        out = self.hal()
        moved = f"image {first} \N{RIGHTWARDS ARROW} {bumped}"
        line = f"{UNIT} recreate {moved} \N{MIDDLE DOT} {ENDS_RUNS}"
        expect(line in out, f"D1a the plan lacks {line!r}: {out[-400:]}")
        after = self.container()
        write_line(f"D1a apply line: {line!r}")
        write_line(f"D1a before {before}\nD1a after  {after}")
        expect(after["id"] != before["id"], "D1a the container id did not change")
        expect(after["ps_image"] == bumped, f"D1a ps Image is {after['ps_image']}")
        expect(
            after["image_id"] == self.image_id_of(bumped), "D1a the container runs another image"
        )
        expect(after["state"] == "running", f"D1a the container is {after['state']}")
        again = self.hal(typed=b"no\n")
        expect(NOTHING_TO_CHANGE in again, f"D1a a second apply said: {again[-300:]}")
        expect(self.container()["id"] == after["id"], "D1a the second apply replaced the container")
        write_line(
            "D1a held: one yes recreated onto the bumped tag; a second apply changes nothing"
        )

    def d1b_a_restarting_container(self) -> None:
        old = self.tag(IMAGE_WORKS, "d1b-old")
        self.use_service(old, EXITS_AT_ONCE)
        self.start_container()
        self.wait_until_restarting()
        new = self.tag(IMAGE_OTHER, "d1b-new")
        self.use_service(new)
        out = self.hal()
        expect(f"{UNIT} recreate image {old} \N{RIGHTWARDS ARROW} {new}" in out, out[-400:])
        after = self.container()
        write_line(f"D1b after one apply: {after}")
        expect(after["state"] == "running" and after["ps_image"] == new, "D1b not running new")
        write_line("D1b held: one apply replaced the restarting container and left it running")

    def wait_until_restarting(self) -> None:
        for _ in range(100):
            if self.container()["state"] in {"restarting", "exited"}:
                return
            time.sleep(0.2)
        raise ProbeFailed("the container that exits at once never restarted")

    def d1c_a_removed_tag(self) -> None:
        reference = self.tag(IMAGE_WORKS, "d1c")
        sibling = self.tag(IMAGE_OTHER, "d1c-sibling")
        self.use_service(reference)
        self.start_container()
        before = self.container()
        self.docker("rmi", "--force", reference)
        shown = self.container()
        write_line(
            f"D1c ps Image after `docker rmi -f {reference}`: {shown['ps_image']!r} "
            f"(label {shown['label_id']})"
        )
        expect(shown["ps_image"] in (reference, shown["label_id"]), STOP_THE_LANE)
        found = self.engine().built_image_id(reference)
        sibling_found = self.engine().built_image_id(sibling)
        write_line(
            f"D1c U8: image ls for the removed tag -> {found!r}; its sibling {sibling} -> "
            f"{sibling_found!r}"
        )
        expect(found is None and sibling_found == self.image_id_of(sibling), "D1c U8 inexact")
        out = self.hal(typed=b"no\n")
        expect(f"{UNIT} recreate" not in out and "cannot plan" not in out, out[-400:])
        expect(NOTHING_TO_CHANGE in out, f"D1c the apply said: {out[-300:]}")
        expect(self.container()["id"] == before["id"], "D1c a container was replaced")
        write_line("D1c held: no recreate line and no planning failure for a tag removed by hand")

    def d1d_a_moved_tag(self) -> None:
        reference = self.tag(IMAGE_WORKS, "d1d")
        self.use_service(reference)
        self.start_container()
        before = self.container()
        moved = self.tag(IMAGE_OTHER, "d1d")
        shown = self.container()
        write_line(
            f"D1d ps Image after the tag moved: {shown['ps_image']!r} (label {shown['label_id']})"
        )
        expect(shown["ps_image"] in (reference, shown["label_id"]), STOP_THE_LANE)
        out = self.hal()
        line = f"{UNIT} recreate image {moved} rebuilt \N{MIDDLE DOT} {ENDS_RUNS}"
        expect(line in out, f"D1d the plan lacks {line!r}: {out[-400:]}")
        after = self.container()
        write_line(f"D1d apply line: {line!r}\nD1d before {before}\nD1d after  {after}")
        expect(after["id"] != before["id"], "D1d the container id did not change")
        expect(after["image_id"] == self.image_id_of(moved), "D1d the container is not on the tag")
        write_line("D1d held: one yes recreated onto the moved tag's new id")

    def teardown(self) -> None:
        if self.guard is not None:
            self.compose("down", "--volumes", "--remove-orphans")
        for reference in self.tags:
            subprocess.run(["docker", "rmi", reference], capture_output=True, check=False)  # noqa: S603, S607 - argv is built by the program itself and docker is found on PATH by design
        if self.guard is not None:
            self.guard.expect_clean_teardown()


def prove(drive: Drive) -> int:
    try:
        drive.bring_up()
        drive.d1a_a_bumped_tag()
        drive.d1b_a_restarting_container()
        drive.d1c_a_removed_tag()
        drive.d1d_a_moved_tag()
    except (ProbeFailed, subprocess.TimeoutExpired, KeyboardInterrupt) as failure:
        write_line(f"PROBE FAILED: {failure!r}")
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    return edge_copy.run_main(
        __doc__.splitlines()[0], argv, Drive, prove, "PROBE PASSED: #482 D1a-D1d hold"
    )


if __name__ == "__main__":
    sys.exit(main())
