"""Probe of the speech app in H's edge copy through `hal apply --local` (#872).

    probe-run \\
        uv run --frozen python3 probe/speech/probe.py {transition|lifecycle} --scratch DIR

Both modes first establish H's stand at the lane's base (`git show <merge-base>:<path>` for every
path the lane changes, through H's `install`), run H's cells on it, then install the candidate
(every changed path at HEAD) with the speech app in the copy's fleet under a probe key, from a
scratch origin of speech (release_origin), and `hal apply` it (D5a/b). `transition` then
drives D2, D3, N1-N5, E1-E3, K1-K6, A1-A10, A12, S1 and M1; `lifecycle` drives R1, R2 and D4. The
app's compose configuration is checked before each apply (release_origin's SpeechApp with
app_isolation's rule, through H's fleet), and its project is in every label sweep and check of the
live edge's view. Exit 0: every cell held.
"""

from __future__ import annotations

import re
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path

PROBE_DIRECTORY = Path(__file__).resolve().parent
sys.path[:0] = [
    str(PROBE_DIRECTORY.parent),
    str(PROBE_DIRECTORY.parents[1] / "src"),
    str(PROBE_DIRECTORY.parent / "keycloak"),
]
sys.path.append(str(PROBE_DIRECTORY))

import edge_copy  # noqa: E402
import in_copy  # noqa: E402
import yaml  # noqa: E402
from admission_cells import AdmissionCells, error_code  # noqa: E402
from app_isolation import speech_prefix  # noqa: E402
from copy_isolation import (  # noqa: E402
    COMPOSE_FILE,
    FLEET_FILE,
    REPO,
    CopyStand,
    Fleet,
    install,
    keycloak,
    live_project_name,
    resolution,
)
from edge_copy import HAL_FAILURE, HAL_OK, NOTHING_TO_CHANGE, expect  # noqa: E402
from network_cells import HostListener, NetworkCells, Topology  # noqa: E402
from release_origin import SpeechApp, app_entry, build_origin, expect_app_guards_refuse  # noqa: E402
from speech_docker import (  # noqa: E402
    Curl,
    addresses_of,
    containers_of,
    docker,
    inspected,
    networks_of,
    one_container,
    wait_healthy,
)

from hal.backup.docker import PROJECT_LABEL  # noqa: E402
from hal.output import Glyph, write_line  # noqa: E402
from hal.stack import deploy_checkout, releases  # noqa: E402
from hal.stack.plan_rows import PlanEvent  # noqa: E402
from hal.stack.realm.reconcile import KEYCLOAK, KEYCLOAK_SERVICE, REALM_UNIT  # noqa: E402
from hal.stack.result_rows import ResultEvent  # noqa: E402

PROJECT = in_copy.PROJECT
APP_KEY = f"{PROJECT}-speech"  # never the shipped key: the live app's project is its key
STEP_CA_UNIT = in_copy.STEP_CA_UNIT
UNITS = frozenset({REALM_UNIT, STEP_CA_UNIT})
MODES = ("transition", "lifecycle")
LISTENER_PORT = 18972
ADMITTED_SECONDS = 90
# A row of hal's plan that changes something, by its subject: no other row starts with these glyphs.
CHANGE_GLYPHS = "|".join(re.escape(g.value) for g in (Glyph.CHANGE, Glyph.ADD, Glyph.REMOVE))
CHANGE_ROW = re.compile(rf"(?<!\S)(?:{CHANGE_GLYPHS}) (?P<subject>\S+)")


def git_text(*arguments: str) -> str:
    result = edge_copy.run_command(["git", *arguments], text=True, cwd=REPO, timeout=60)
    expect(result.returncode == 0, f"git {arguments[0]} exited {result.returncode}")
    return result.stdout


def lane_files() -> tuple[dict[str, str | None], dict[str, str | None]]:
    """Every path the lane changes, as the lane's merge-base and as HEAD have it (None: absent)."""
    base = git_text("merge-base", "HEAD", "origin/main").strip()
    names = git_text("diff", "--name-only", base, "HEAD").split()

    def at(commit: str, name: str) -> str | None:
        listed = git_text("ls-tree", "--name-only", commit, "--", name).strip()
        return git_text("show", f"{commit}:{name}") if listed else None

    return {n: at(base, n) for n in names}, {n: at("HEAD", n) for n in names}


def moment(stamp: str) -> datetime:
    """A Docker timestamp (nanoseconds, `Z` or an offset) as an aware datetime, for ordering."""
    return datetime.fromisoformat(re.sub(r"(\.\d{6})\d+", r"\1", stamp))


def networks_named_by_create(stand: CopyStand, networks: list[str]) -> list[str]:
    """Which of `networks` the app step's `docker compose create` names when run by hand in the
    app's checkout, as hal's failure line asks, since hal withholds Compose's output. Only the
    names are read from that output, which may echo interpolated values."""
    checkout = stand.home / "srv" / APP_KEY
    command = ["docker", "compose", "-p", APP_KEY, "--project-directory", str(checkout)]
    command += ["--file", str(checkout / deploy_checkout.COMPOSE_FILE), "create", "--no-build"]
    result = edge_copy.run_command(
        [*command, "--pull", "never"], text=True, env=stand.environment, cwd=checkout, timeout=120
    )
    expect(result.returncode != 0, f"D4: the create of {APP_KEY} in its checkout succeeded")
    return [name for name in networks if name in result.stdout + result.stderr]


def row_pattern(subject: str, event: str, fact: str = "") -> str:
    """A row of hal's plan or result in its whitespace-normalised output."""
    return rf"\b{re.escape(subject)}\s+{re.escape(event)}\b" + (
        rf"\s+{re.escape(fact)}" if fact else ""
    )


class SpeechProbe(in_copy.Probe, NetworkCells, AdmissionCells):
    def __init__(self, scratch: Path, mode: str) -> None:
        super().__init__(scratch)
        self.mode, self.keycloak = mode, keycloak
        self.base_files, self.candidate_files = lane_files()
        self.app: SpeechApp | None = None

    # --- the stand ---------------------------------------------------------------------------

    def drive(self) -> None:
        self.cell_h1()
        self.cell_h2()
        self.cell_h3()
        self.cell_h4()
        self.cell_d5()
        if self.mode == MODES[0]:
            self.drive_transition()
        else:
            self.cell_r1()
            self.cell_r2()
            self.cell_d4()
        self.cell_h5()

    def drive_transition(self) -> None:
        self.cell_d2()
        self.cell_d3(self.app.entry)
        self.cell_n1()
        self.cell_n2_n3()
        self.cell_n4()
        self.cell_n5()
        self.cell_e1()
        listener = HostListener(self.scratch, LISTENER_PORT)
        try:
            self.cell_e2(listener)
        finally:
            listener.stop()
        self.cell_e3()
        for cell in (self.cell_k1, self.cell_k2, self.cell_k3, self.cell_k4, self.cell_k5):
            cell()
        self.cell_k6()
        self.drive_admission()
        self.cell_s1()
        self.cell_m1()

    def cell_h1(self) -> None:
        self.prepare(Fleet(UNITS))
        line = install(self.stand, self.base_files, "probe: the lane's base")
        first = self.rewritten_digests()
        install(self.stand, self.base_files, "probe: the lane's base again")
        changed = sorted(
            name for name, digest in self.rewritten_digests().items() if first[name] != digest
        )
        expect(not changed, f"H1: a reinstall changed {changed}")
        self.hold(
            "H1",
            f"at the lane's base ({len(self.base_files)} paths): {line}; installed "
            f"again byte-identical; {self.self_checks} self-checks held",
        )

    def copy_resolved(self) -> dict:
        return resolution(self.stand, edge_copy.copy_compose_prefix(self.stand.copy))

    def project_container(self, service: str) -> str:
        return one_container(PROJECT, service)

    def copy_kids(self) -> set[str]:
        jwks = self.kc.through_tunnel("GET", f"{keycloak.REALM_PATH}/protocol/openid-connect/certs")
        expect(jwks.status == 200, f"the copy's key set answered {jwks.status}")
        return {key["kid"] for key in jwks.json()["keys"]}

    def switch(
        self,
        message: str,
        *,
        units: frozenset[str] = UNITS,
        app: bool | None = True,
        files: dict[str, str | None] | None = None,
        exit_code: int = HAL_OK,
    ) -> str:
        """The copy's fleet with `units` on and the app on, off or (None) absent, `files` (or the
        candidate's fleet.yaml) installed and `hal apply` run."""
        apps = {}
        if app is not None:
            fleet = self.candidate_files[FLEET_FILE]
            apps[APP_KEY] = self.app.with_entry(app_entry(fleet, APP_KEY, enabled=app))
        self.stand = replace(self.stand, fleet=Fleet(units, apps))
        install(self.stand, files or {FLEET_FILE: self.candidate_files[FLEET_FILE]}, message)
        output = in_copy.apply(self.stand, exit_code=exit_code)
        self.expect_hidden_from_live_edge(message)
        return output

    # --- D5a/b, D2 ---------------------------------------------------------------------------

    def establish_release(self) -> None:
        fleet = self.candidate_files[FLEET_FILE]
        release = build_origin(self.scratch, self.home, fleet, APP_KEY, PROJECT)
        self.release = release
        self.app = SpeechApp(
            APP_KEY, app_entry(fleet, APP_KEY, enabled=True), release.compose, release.tag
        )
        self.release_compose = release.compose
        (self.speech_service,) = yaml.safe_load(release.compose)["services"]
        shipped = yaml.safe_load((REPO / COMPOSE_FILE).read_text())["networks"]
        live_prefix = speech_prefix(live_project_name())
        live = next(
            n["name"] for n in shipped.values() if n.get("name", "").startswith(live_prefix)
        )
        for line in expect_app_guards_refuse(self.app, self.stand, live):
            write_line(line, flush=True)
        self.projects.append(APP_KEY)

    def cell_d5(self) -> None:
        self.establish_release()
        self.stand = replace(self.stand, fleet=Fleet(UNITS, {APP_KEY: self.app}))
        install(self.stand, self.candidate_files, "probe: the lane's candidate")
        resolved = self.copy_resolved()
        self.topology = t = Topology.of(resolved, PROJECT)
        self.copy = self.stand.copy
        kept = (KEYCLOAK.database, STEP_CA_UNIT)
        before = {s: self.project_container(s) for s in (t.gateway, KEYCLOAK_SERVICE, *kept)}
        out = in_copy.apply(self.stand)
        self.expect_hidden_from_live_edge("the candidate's apply")
        skipped = [tag for tag in self.release.skipped if releases.parse(tag) is None]
        tag = self.app.tag
        rows = [
            (t.gateway, PlanEvent.RECREATE, ""),
            (KEYCLOAK_SERVICE, PlanEvent.RECREATE, ""),
            (STEP_CA_UNIT, PlanEvent.SWITCH_ON, ""),
            (APP_KEY, PlanEvent.SWITCH_ON, tag),
            *((APP_KEY, PlanEvent.TAG_SKIPPED, skipped_tag) for skipped_tag in skipped),
            (APP_KEY, "switched on", f"{tag} · running"),
        ]
        missing = [" ".join(row) for row in rows if not re.search(row_pattern(*row), out)]
        expect(not missing, f"D5a: no {missing} in {out[-1500:]}")
        changes = sorted(CHANGE_ROW.findall(out))
        wanted = sorted({subject for subject, event, _ in rows if event != PlanEvent.TAG_SKIPPED})
        expect(changes == wanted, f"D5a: the plan changes {changes}, not exactly {wanted}")
        self.hold(
            "D5a",
            f"the plan changes exactly {changes}; rows {[' '.join(row) for row in rows]}; "
            f"the plan: {out[:900]}",
        )
        self.cell_d5b(before, kept)

    def cell_d5b(self, before: dict[str, str], kept: tuple[str, ...]) -> None:
        t = self.topology
        after = {service: self.project_container(service) for service in before}
        changed = {s for s in before if before[s] != after[s]}
        expect(changed == {t.gateway, KEYCLOAK_SERVICE}, f"D5b: replaced {sorted(changed)}")
        self.gateway_id = after[t.gateway]
        helper = inspected("container", self.project_container(t.helper))["State"]
        expect(helper["Status"] == "exited" and helper["ExitCode"] == 0, f"D5b: helper {helper}")
        self.speech_id = one_container(APP_KEY, self.speech_service)
        wait_healthy(self.speech_id, 300)
        speech = inspected("container", self.speech_id)
        joined = set(speech["NetworkSettings"]["Networks"])
        expect(joined == {t.issuer, *t.callers.values()}, f"D5b: the app joins {sorted(joined)}")
        created = {
            n: moment(inspected("network", n)["Created"]) for n in (t.issuer, *t.callers.values())
        }
        gateway_created = moment(inspected("container", self.gateway_id)["Created"])
        expect(
            all(c < moment(speech["Created"]) for c in created.values())
            and moment(helper["FinishedAt"]) < moment(speech["Created"]),
            f"D5b: networks {created}, helper {helper['FinishedAt']}, app {speech['Created']}",
        )
        self.app_image = speech["Config"]["Image"]
        root = self.app.resolved(self.stand, self.app.release_compose)["secrets"]
        self.curl = Curl(
            self.copy_resolved()["services"][STEP_CA_UNIT]["image"],
            PROJECT,
            Path(next(iter(root.values()))["file"]),
        )
        self.hold(
            "D5b",
            f"{sorted(changed)} replaced (gateway created {gateway_created}), "
            f"{list(kept)} kept; networks created {created}; helper exited 0 at "
            f"{moment(helper['FinishedAt']):%H:%M:%S.%f}; app {self.app_image} created "
            f"{moment(speech['Created']):%H:%M:%S.%f}, healthy, on {sorted(joined)}",
        )

    def cell_d2(self) -> None:
        quiet = in_copy.apply(self.stand)
        expect(NOTHING_TO_CHANGE in quiet, f"D2: the second apply said {quiet[-400:]}")
        expect(one_container(APP_KEY, self.speech_service) == self.speech_id, "D2: app replaced")
        self.hold("D2", f"the second apply: {NOTHING_TO_CHANGE}, the app container kept")

    # --- S1 ----------------------------------------------------------------------------------

    def admitted_within(self, seconds: int) -> int:
        deadline = time.monotonic() + seconds
        while True:
            answer = self.speak("hopin", self.admitted_tokens, "Hallo wieder")
            if answer.status == 200 or time.monotonic() > deadline:
                return answer.status
            time.sleep(3)

    def cell_s1(self) -> None:
        t, speech = self.topology, self.speech_id
        self.switch("probe: S1, step-ca off", units=UNITS - {STEP_CA_UNIT})
        left = [s for s in (STEP_CA_UNIT, t.gateway, t.helper) if containers_of(PROJECT, s)]
        expect(not left, f"S1: {left} still have containers")
        names = networks_of(PROJECT)
        expect({t.issuer, *t.callers.values()} <= set(names), f"S1: networks {sorted(names)}")
        expect(one_container(APP_KEY, self.speech_service) == speech, "S1: the app was replaced")
        cached = self.speak("hopin", self.admitted_tokens, "Hallo noch einmal")
        expect(cached.status == 200, f"S1: on cached keys {cached.status} {error_code(cached)}")
        docker("restart", speech)
        wait_healthy(speech, 300)
        refused = self.speak("hopin", self.admitted_tokens, "Hallo noch einmal")
        expect(
            refused.status == 503 and error_code(refused) == "unavailable",
            f"S1: after the restart {refused.status} {error_code(refused)}",
        )
        self.switch("probe: S1, step-ca on again")
        helper = inspected("container", self.project_container(t.helper))["State"]
        expect(helper["ExitCode"] == 0 and helper["Status"] == "exited", f"S1: helper {helper}")
        self.gateway_id = self.project_container(t.gateway)
        status = self.admitted_within(ADMITTED_SECONDS)
        expect(status == 200, f"S1: step-ca on again, the request got {status}")
        self.hold(
            "S1",
            f"step-ca off: {STEP_CA_UNIT}, {t.gateway} and {t.helper} gone, networks "
            "kept, the app kept and admitting on cached keys (200); restarted: 503 "
            "unavailable; step-ca on: the helper exited 0 again and requests are "
            "admitted (200)",
        )

    # --- R1, R2, D4 --------------------------------------------------------------------------

    def speech_containers(self) -> list[str]:
        return containers_of(APP_KEY, self.speech_service)

    def cell_r1(self) -> None:
        t = self.topology
        self.switch("probe: R1, the app off", app=False)
        expect(not self.speech_containers(), f"R1: the app left {self.speech_containers()}")
        names = set(networks_of(PROJECT))
        expect({t.issuer, *t.callers.values()} <= names, f"R1: networks {sorted(names)}")
        self.switch("probe: R1, the app on again")
        (again,) = self.speech_containers()
        wait_healthy(again, 300)
        self.switch("probe: R1, the app off before R2", app=False)
        expect(not self.speech_containers(), "R1: the app's containers are not gone before R2")
        self.hold(
            "R1",
            "off: the app's containers gone, its networks kept; on again: healthy; off again: gone",
        )

    def cell_r2(self) -> None:
        t = self.topology
        out = self.switch("probe: R2, the base files back", app=None, files=self.base_files)
        recreated = [
            s
            for s in (t.gateway, KEYCLOAK_SERVICE)
            if not re.search(row_pattern(s, PlanEvent.RECREATE), out)
        ]
        expect(not recreated, f"R2: no recreate of {recreated} in {out[-800:]}")
        gateway = addresses_of(self.project_container(t.gateway))
        keycloak_on = addresses_of(self.project_container(KEYCLOAK_SERVICE))
        expect(
            not {t.issuer, t.keys} & set(gateway) and t.keys not in keycloak_on,
            f"R2: {t.gateway} on {sorted(gateway)}, keycloak on {sorted(keycloak_on)}",
        )
        orphans = containers_of(PROJECT, t.helper)
        expect(len(orphans) == 1, f"R2: the helper left {len(orphans)} containers")
        docker("rm", orphans[0])
        names = set(networks_of(PROJECT))
        expect({t.issuer, t.keys, *t.callers.values()} <= names, f"R2: networks {sorted(names)}")
        self.keycloak.wait_until_ready(self.stand.isolation.admin_url)  # its realm: next apply
        quiet = in_copy.apply(self.stand)
        expect(NOTHING_TO_CHANGE in quiet, f"R2: the next apply said {quiet[-400:]}")
        self.hold(
            "R2",
            f"{t.gateway} and {KEYCLOAK_SERVICE} recreated without the new networks; "
            f"the exited {t.helper} left as an orphan and removed; the networks stay; "
            f"the next apply: {NOTHING_TO_CHANGE}",
        )

    def cell_d4(self) -> None:
        t = self.topology
        speech_networks = [t.issuer, *t.callers.values()]
        docker("network", "rm", *speech_networks)
        expect(not set(speech_networks) & set(networks_of(PROJECT)), "D4: the networks stay")
        out = self.switch(
            "probe: D4, the candidate with step-ca off",
            units=UNITS - {STEP_CA_UNIT},
            files=self.candidate_files,
            exit_code=HAL_FAILURE,
        )
        failed = re.search(row_pattern(APP_KEY, ResultEvent.FAILED), out)
        expect(failed is not None, f"D4: no failed row of {APP_KEY} in {out[-600:]}")
        named = networks_named_by_create(self.stand, speech_networks)
        expect(bool(named), f"D4: the app's create in its checkout names none of {speech_networks}")
        expect(not self.speech_containers(), f"D4: the app has {self.speech_containers()}")
        left = set(speech_networks) & set(networks_of(PROJECT))
        expect(not left, f"D4: the apply created {sorted(left)}")
        self.hold(
            "D4",
            f"exit {HAL_FAILURE}, `{failed[0]}` with Compose's output withheld; the app's create "
            f"in its checkout names {named}; no app container; {speech_networks} still absent",
        )

    # --- teardown ----------------------------------------------------------------------------

    def teardown(self) -> None:
        super().teardown()
        label = f"label={PROJECT_LABEL}={APP_KEY}"
        if images := docker("image", "ls", "--quiet", "--filter", label).decode().split():
            docker("image", "rm", "--force", *set(images))
        left = docker("image", "ls", "--quiet", "--filter", label).decode().split()
        expect(not left, f"the teardown left the app images {left}")


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in MODES:
        write_line(f"PROBE FAILED: the first argument is one of {', '.join(MODES)}")
        return edge_copy.NOT_RUNNABLE
    mode = arguments.pop(0)
    return edge_copy.run_main(
        __doc__.splitlines()[0],
        arguments,
        lambda scratch: SpeechProbe(scratch, mode),
        in_copy.prove,
        lambda probe: edge_copy.passed_line(f"PASSED: {', '.join(probe.held)}"),
    )


if __name__ == "__main__":
    sys.exit(main())
