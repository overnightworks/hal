"""An app switched off, `enabled: false` (#255 block C), driven on a running `Probe` of `probe.py`:
C1 an app switched off running, C2 on again at the same tag, C3 off after a renamed service and a
failed build, C4 off with `compose.yaml` unusable at HEAD, C5 off with a leftover container."""

from __future__ import annotations

import re
from collections.abc import Mapping

from edge_copy import HAL_FAILURE, expect

from hal.output import write_line


class SwitchedOff:
    def __init__(self, probe, tags: Mapping[str, str], ghost: str) -> None:
        self.probe, self.tags, self.ghost = probe, tags, ghost

    def prove(self) -> None:
        self.cell_c1_c2_off_and_on_again()
        self.cell_c3_renamed_service()
        self.cell_c4_compose_file_unusable()
        self.cell_c5_dropped_service_and_leftover()

    def volumes(self) -> list[str]:
        """The names of the volumes of the app's project."""
        project = f"label=com.docker.compose.project={self.probe.key}"
        listed = self.probe.docker("volume", "ls", "--quiet", "--filter", project).stdout.decode()
        return sorted(listed.split())

    def switch_off(self, cell: str) -> str:
        """`enabled: false` applied while containers run: the plan's output, after which no
        container of the project is left, every volume is still there, and the checkout and the
        record stay."""
        volumes, head, record = self.volumes(), self.probe.head(), self.probe.record.read_text()
        expect(
            len(volumes) >= 1 and self.probe.containers() != [], f"{cell}: nothing to switch off"
        )
        self.probe.set_enabled(False)
        out = self.probe.apply()
        expect(
            re.search(
                rf"- {self.probe.key}\s+switch off\s+volumes kept · ~/srv/{self.probe.key} kept",
                out,
            )
            is not None
            and not any(name in out for name in volumes),
            f"{cell}: the plan said: {out[-400:]}",
        )
        expect(self.probe.containers() == [], f"{cell}: containers left: {self.probe.containers()}")
        expect(self.volumes() == volumes, f"{cell}: the volumes changed: {self.volumes()}")
        expect(
            self.probe.head() == head and self.probe.record.read_text() == record,
            f"{cell}: the checkout or the record moved",
        )
        expect(self.probe.ask("/version")[0] == 404, f"{cell}: Traefik still routes the app")
        return out

    def cell_c1_c2_off_and_on_again(self) -> None:
        tag, before = self.probe.deployed()["tag"], self.probe.starts()
        out = self.switch_off("C1")
        expect(
            re.search(
                rf"✓ {self.probe.key}\s+switched off\s+volumes and ~/srv/{self.probe.key} kept", out
            )
            is not None
            and "partial" not in out,
            f"C1: {out[-300:]}",
        )
        again = self.probe.apply(typed=b"no\n")
        expect("nothing to change" in again, f"C1: a second apply said: {again[-200:]}")
        write_line(
            "C1 held: off removes every container, the named volumes, checkout and record stay"
        )
        self.probe.set_enabled(True)
        out = self.probe.apply()
        expect(f"start again {tag} · recorded" in out, f"C2: the plan said: {out[-300:]}")
        self.probe.serves(tag)
        after = self.probe.starts()
        expect(after[: len(before)] == before and len(after) > len(before), f"C2: {after}")
        write_line(f"C2 held: on again at {tag} finds the same named volume with its data")

    def cell_c3_renamed_service(self) -> None:
        self.probe.release(self.tags["c3_renamed"], services=("app",), builds=False)
        out = self.probe.apply(exit_code=HAL_FAILURE)
        expect(f"could not build at {self.tags['c3_renamed']}" in out, f"C3: {out[-300:]}")
        expect([r["service"] for r in self.probe.containers()] == ["web"], "C3: setup")
        expect(
            self.probe.head() == self.probe.shas[self.tags["c3_renamed"]],
            "C3: HEAD is not the failed tag",
        )
        self.switch_off("C3")
        write_line("C3 held: off after a renamed service and a failed build removes the old web")

    def cell_c4_compose_file_unusable(self) -> None:
        for shape, text in (("missing", ""), ("invalid", "services: [unclosed\n")):
            self.probe.release(self.tags[f"c4_{shape}_ok"])
            self.probe.set_enabled(True)
            self.probe.apply()
            self.probe.release(self.tags[f"c4_{shape}"], compose_file=text)
            self.probe.git_in_srv(
                "fetch", "--quiet", "--no-tags", "origin", "+refs/tags/v*:refs/edge/releases/v*"
            )
            self.probe.git_in_srv(
                "checkout", "--quiet", "--detach", self.probe.shas[self.tags[f"c4_{shape}"]]
            )
            control = self.probe.app_compose("config", check=False)
            expect(control.returncode != 0, f"C4: the compose file at HEAD loads ({shape})")
            self.switch_off(f"C4 {shape}")
        write_line("C4 held: with compose.yaml missing or invalid at HEAD, off still removes")

    def cell_c5_dropped_service_and_leftover(self) -> None:
        self.probe.release(self.tags["c5_first"], services=("web", "worker"))
        self.probe.set_enabled(True)
        self.probe.apply()
        expect(
            sorted(r["service"] for r in self.probe.containers()) == ["web", "worker"], "C5: setup"
        )
        self.probe.release(self.tags["c5_second"])
        self.probe.apply()
        expect(
            [r["service"] for r in self.probe.containers()] == ["web"], "C5: worker was not removed"
        )
        side = self.probe.scratch / "ghost.yaml"
        side.write_text(self.ghost)
        self.probe.docker("compose", "-p", self.probe.key, "--file", str(side), "up", "--detach")
        expect(
            sorted(r["service"] for r in self.probe.containers()) == ["ghost", "web"],
            f"C5: setup, {self.probe.containers()}",
        )
        self.probe.docker(
            "compose", "-p", self.probe.key, "--file", str(side), "run", "--detach",
            "--name", f"{self.probe.key}-oneoff", "ghost",
        )  # fmt: skip
        expect(
            len(self.probe.containers()) == 3, f"C5: setup, no one-off in {self.probe.containers()}"
        )
        self.switch_off("C5")
        write_line("C5 held: the update removed worker, off removed web, a leftover and a one-off")
