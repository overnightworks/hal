"""The emergency switch of an app, driven through `hal` (#255 P5) on a running `Probe` of
`probe.py`: D1 `hal stop` without a terminal (twice), D2 a stopped app with a newer tag waiting
stays stopped, D7 `hal start` and its refusal while disabled, D4 a stop during the build.

D10, a stop while apply holds the switch lock, is a unit test.
"""

from __future__ import annotations

import shlex
import subprocess
import time
from collections.abc import Mapping

import edge_copy
from edge_copy import HAL_FAILURE, HAL_OK, expect

from hal.output import write_line
from hal.stack import checkout


def squeezed(text: str) -> str:
    """The text with every run of blanks as one space, so a check names no column width."""
    return " ".join(text.split())


BARRIER_HEADER = "X-Edge-Barrier"
SLOW_BUILD_SECONDS = 120  # long enough for `hal stop` to record while the build runs
STOP_SECONDS = 60
APPLY_SECONDS = 900


class EmergencySwitch:
    def __init__(self, probe, tags: Mapping[str, str]) -> None:
        self.probe, self.tags = probe, tags

    def prove(self) -> None:
        self.stop_without_a_terminal()
        self.stopped_app_stays_stopped()
        self.start()
        self.stop_during_the_build()

    # --- hal, as an agent and as the operator run it -------------------------------------------

    def hal_without_terminal(self, *arguments: str) -> str:
        """`hal <arguments>` of the copy with stdin and stdout that are no terminal, which must
        exit 0; its whitespace-normalised output."""
        probe = self.probe
        result = subprocess.run(  # noqa: S603 - argv is the probe copy of hal and no shell runs
            [str(probe.copy / ".venv" / "bin" / "hal"), *arguments], stdin=subprocess.DEVNULL,
            capture_output=True, env=probe.environment, cwd=probe.copy, check=False,
            timeout=STOP_SECONDS,
        )  # fmt: skip
        output = " ".join((result.stdout + result.stderr).decode(errors="replace").split())
        expect(
            result.returncode == HAL_OK,
            f"hal {' '.join(arguments)} exited {result.returncode}: {output[-300:]}",
        )
        return output

    def apply_in_background(self) -> subprocess.Popen[bytes]:
        """`hal apply --local` at a pty where the operator has typed `yes`."""
        probe = self.probe
        command = shlex.join([str(probe.copy / ".venv" / "bin" / "hal"), "apply", "--local"])
        running = subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["script", "-qec", command, "/dev/null"], stdin=subprocess.PIPE,  # noqa: S607 - script is found on PATH by design
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=probe.environment,
            cwd=probe.copy,
        )  # fmt: skip
        running.stdin.write(b"yes\n")
        running.stdin.close()
        return running

    @staticmethod
    def failed(running: subprocess.Popen[bytes]) -> str:
        """The whitespace-normalised output of the background apply, which must have exited 3."""
        output = running.stdout.read()
        running.wait(timeout=APPLY_SECONDS)
        text = " ".join(output.decode(errors="replace").split())
        expect(
            running.returncode == HAL_FAILURE,
            f"the background apply exited {running.returncode}, wanted {HAL_FAILURE}: "
            f"{text[-300:]}",
        )
        return text

    # --- what the switch leaves ----------------------------------------------------------------

    def set_hosts(self, listed: bool) -> None:
        """The app's one host in the catalog (no `edge.name` label stands behind it: the barrier
        reads only the catalog) or none, published as a merged pull request."""
        probe = self.probe
        fleet = probe.copy / "fleet.yaml"
        entry = f"{{name: {probe.key}, exposure: public, reason: probe, ready: /version}}"
        host = f"    hosts: [{entry}]\n"
        lines = [
            line for line in fleet.read_text().splitlines(keepends=True) if "hosts:" not in line
        ]
        if listed:
            lines.append(host)
        fleet.write_text("".join(lines))
        edge_copy.publish(probe.copy, f"probe: {probe.key} hosts {listed}")

    @property
    def marker(self):
        return self.probe.home / ".local" / "state" / "hal" / "stopped" / self.probe.key

    @property
    def barrier_file(self):
        return self.probe.copy / "dynamic" / f"switch-{self.probe.key}.yml"

    def barrier_mark(self) -> str | None:
        """The `X-Edge-Barrier` of the probe's Traefik's 404 for the app's host."""
        answer = self.probe.ask_with_headers("/")
        if answer is None or answer[0] != 404:
            return None
        return answer[2].get(BARRIER_HEADER)

    # --- the cells -----------------------------------------------------------------------------

    def stop_without_a_terminal(self) -> None:
        probe = self.probe
        self.set_hosts(True)
        before = probe.only()["id"]
        out = self.hal_without_terminal("stop", probe.key)
        expect(f"✓ {probe.key} switched off" in squeezed(out), out[-300:])
        expect(self.marker.exists() and self.barrier_file.exists(), "D1: marker or barrier missing")
        expect(self.barrier_mark() == probe.key, "D1: Traefik does not answer the barrier's 404")
        rows = probe.containers()
        expect([r["id"] for r in rows] == [before] and rows[0]["state"] == "exited", f"D1: {rows}")
        again = self.hal_without_terminal("stop", probe.key)
        expect(f"· {probe.key} already off since" in squeezed(again), f"D1 again: {again[-300:]}")
        expect(self.barrier_mark() == probe.key, "D1: the repeated stop lost the barrier")
        write_line(
            "D1 held: hal stop without a terminal wrote the marker and a proven barrier, stopped"
        )

    def stopped_app_stays_stopped(self) -> None:
        probe = self.probe
        tag = self.tags["d2"]
        probe.release(tag)
        marker, barrier_bytes = self.marker.read_bytes(), self.barrier_file.read_bytes()
        out = probe.apply(typed=b"no\n")
        expect("stays stopped switched off since" in out, f"D2: {out[-300:]}")
        expect("nothing to change" in out, f"D2: {out[-300:]}")
        fetched = checkout.Git(probe.srv).call(
            ["for-each-ref", "--format=%(refname)", f"refs/edge/releases/{tag}"]
        )
        expect(fetched.stdout.decode().strip() == "", "D2: the new tag was fetched")
        expect(
            self.marker.read_bytes() == marker and self.barrier_file.read_bytes() == barrier_bytes,
            "D2: the marker or the barrier changed",
        )
        write_line("D2 held: a stopped app with a newer tag waiting stays stopped, nothing fetched")

    def start(self) -> None:
        probe = self.probe
        probe.set_enabled(False)
        out = probe.hal("start", probe.key, exit_code=HAL_FAILURE)
        expect("refused" in out and "disabled in the catalog" in out, f"D7: {out[-300:]}")
        expect(self.marker.exists(), "D7: the refused start cleared the marker")
        probe.set_enabled(True)
        out = probe.hal("start", probe.key)
        expect(f"{probe.key} is on" in out, f"D7: {out[-300:]}")
        expect(not self.marker.exists() and not self.barrier_file.exists(), "D7: switch remains")
        expect(probe.only()["health"] == "healthy", "D7: not healthy")
        probe.serves(probe.deployed()["tag"])
        self.set_hosts(False)
        write_line(
            "D7 held: hal start (yes) started, waited for health, opened; refused while disabled"
        )

    def stop_during_the_build(self) -> None:
        probe = self.probe
        probe.apply()  # the tag of D2 is deployed
        tag = self.tags["d4"]
        sha = probe.release(tag, slow_build=SLOW_BUILD_SECONDS)
        before, record = probe.only()["id"], probe.record.read_text()
        running = self.apply_in_background()
        probe.wait_until("the checkout is at the new tag", lambda: probe.head() == sha)
        # listed only once apply has planned: at plan time its contract would want an `edge.name`
        # label, which the live Traefik would see
        self.set_hosts(True)
        asked = time.monotonic()
        out = self.hal_without_terminal("stop", probe.key)
        stopped_in = time.monotonic() - asked
        expect(f"✓ {probe.key} switched off" in squeezed(out), f"D4: {out[-300:]}")
        expect(self.barrier_mark() == probe.key, "D4: Traefik does not answer the barrier's 404")
        barrier_bytes = self.barrier_file.read_bytes()
        text = self.failed(running)
        expect("switched off meanwhile" in text and "not started" in text, f"D4: {text[-300:]}")
        rows = probe.containers()
        expect(
            [r["id"] for r in rows] == [before] and rows[0]["state"] == "exited",
            f"D4: containers {rows}, before {before}; the apply said: {text[-700:]}",
        )
        expect(probe.record.read_text() == record, "D4: the record moved")
        expect(self.marker.exists(), "D4: the marker is gone")
        expect(self.barrier_file.read_bytes() == barrier_bytes, "D4: the barrier changed")
        expect(self.barrier_mark() == probe.key, "D4: Traefik no longer answers the barrier's 404")
        out = probe.hal("start", probe.key)
        expect(f"{probe.key} is on" in out, f"D4: {out[-300:]}")
        self.set_hosts(False)
        probe.apply()
        expect(probe.deployed()["tag"] == tag, "D4: the app was not updated after the start")
        write_line(
            "D4 held: a stop during the build ran no create, kept the record and the barrier "
            f"Traefik answers (hal 3); hal stop took {stopped_in:.0f} s"
        )
