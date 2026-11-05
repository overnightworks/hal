"""speech-runtime's release as hal clones it in H's copy, and the app hal deploys from it.

The origin is a bare clone in the scratch of speech-runtime's public repository, with every branch
and tag. Its newest dated tag (hal's grammar) is re-pointed at one commit on top of it that rewrites
only the compose.yaml lines `name: hal_speech_*` to the copy's `<project>_speech_*`, and that commit
is the origin's default branch, so hal plans that tag and skips the others. The scratch HOME's
`.gitconfig` sends hal's clone URL of the probe's app key to this origin; nothing of the public
repository changes.

`SpeechApp` is the copy fleet's app (copy_isolation's `FleetApp`): `expect_isolated` resolves what
hal would start it from, the release's compose.yaml at its tag and the checkout's once it exists,
with the copy's environment, and checks each with app_isolation's rule;
`expect_app_guards_refuse` shows that rule refusing the release changed as another tag could
change it.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import edge_copy
import yaml
from app_isolation import SPEECH_NETWORK, expect_app_config_isolated, speech_prefix
from copy_isolation import (
    COMPOSE_FILE,
    DOCKER_SOCKET_BIND,
    HOST_NAMESPACE,
    REPO,
    CopyStand,
    run_checked,
)
from edge_copy import ProbeFailed, expect

from hal.exposure.docker import EDGE_NAME_LABEL
from hal.stack import catalog, checkout, deploy_checkout, releases
from hal.stack.realm.reconcile import KEYCLOAK, KEYCLOAK_SERVICE

SPEECH_APP = "speech-runtime"  # fleet.yaml's key of the speech service: its repository's name
ORIGIN = "speech-origin.git"
WORK = "speech-work"
SPEECH_NAME_LINE = re.compile(
    rf"^(?P<head>\s+name: ){re.escape(edge_copy.LIVE_NETWORK_PREFIX)}"
    rf"(?P<rest>{SPEECH_NETWORK}\w+)\s*$",
    re.M,
)
CHECK_DIRECTORY = ".probe-app-check"  # under the scratch HOME, beside the app's checkout


@dataclass(frozen=True)
class Release:
    tag: str  # the newest dated tag, re-pointed in the scratch origin
    compose: str  # its compose.yaml as hal checks it out
    skipped: tuple[str, ...]  # every other tag of the origin


def app_entry(fleet_text: str, key: str, *, enabled: bool) -> str:
    """fleet.yaml's lines of the speech app under `key`, with `enabled` as its switch: the
    shipped entry, re-keyed, so its shape is read from its owner."""
    lines = fleet_text.splitlines(keepends=True)
    head = f"  {SPEECH_APP}:\n"
    expect(lines.count(head) == 1, f"fleet.yaml holds {head.strip()!r} {lines.count(head)} times")
    start = lines.index(head)
    end = start + 1
    while end < len(lines) and lines[end].startswith("   "):  # the entry's deeper lines
        end += 1
    entry = "".join([f"  {key}:\n", *lines[start + 1 : end]])
    expect(entry.count("enabled: true") == 1, f"the shipped {SPEECH_APP} entry is not on once")
    return entry.replace("enabled: true", f"enabled: {str(enabled).lower()}")


def clone_url(fleet_text: str, key: str) -> str:
    """The URL hal clones the app `key` from (apps.py), in fleet.yaml's GitHub organisation."""
    organisation = catalog.github_org(catalog.parse(fleet_text.encode()))
    return f"https://github.com/{organisation}/{key}.git"


def tags_of(tree: Path) -> list[str]:
    listed = checkout.run_git(tree, ("tag", "--list"), checkout.Profile.LOCAL)
    expect(listed.returncode == 0, "git tag --list failed in the speech origin")
    return listed.stdout.decode().split()


def build_origin(scratch: Path, home: Path, fleet_text: str, key: str, project: str) -> Release:
    """The scratch origin of the app `key`, its newest dated tag moved onto the copy's networks,
    reached through the scratch HOME's `.gitconfig`; the release hal will plan."""
    origin, work = scratch / ORIGIN, scratch / WORK
    public = clone_url(fleet_text, SPEECH_APP)
    edge_copy.git(scratch, "clone", "--quiet", "--bare", public, str(origin))
    edge_copy.git(scratch, "clone", "--quiet", str(origin), str(work))
    for name, value in edge_copy.PROBE_IDENTITY.items():
        edge_copy.git(work, "config", name, value)
    tags = tags_of(work)
    newest = max(filter(None, map(releases.parse, tags)), default=None)
    expect(newest is not None, f"{public} has no dated tag: {tags}")
    tag = newest.tag
    edge_copy.git(work, "switch", "--quiet", "--detach", tag)
    file = work / deploy_checkout.COMPOSE_FILE
    moved, count = SPEECH_NAME_LINE.subn(rf"\g<head>{project}_\g<rest>", file.read_text())
    expect(count > 0, f"{SPEECH_APP}'s compose.yaml at {tag} names no hal_speech_* network")
    file.write_text(moved)
    edge_copy.git(work, "commit", "--quiet", "--all", "--message", f"probe: {tag} on {project}")
    edge_copy.git(work, "tag", "--force", tag)
    shipped = catalog.parse(fleet_text.encode())["services"][SPEECH_APP]
    branch = f"refs/heads/{shipped['repo']['default_branch']}"
    edge_copy.git(
        work, "push", "--quiet", "--force", "origin", f"HEAD:{branch}", f"refs/tags/{tag}"
    )
    with (home / ".gitconfig").open("a") as config:
        config.write(f'[url "{origin.as_uri()}"]\n\tinsteadOf = {clone_url(fleet_text, key)}\n')
    return Release(tag, moved, tuple(sorted(set(tags) - {tag})))


@dataclass(frozen=True)
class SpeechApp:
    """The speech app in the copy's fleet: its key (its compose project), its fleet.yaml entry and
    the compose.yaml of the release hal deploys, as the probe's origin carries it at its tag."""

    key: str
    entry: str
    release_compose: str
    tag: str

    def expect_isolated(self, stand: CopyStand) -> str:
        """Every compose.yaml hal would create or start the app from, resolved as hal resolves it
        and checked; the line that says what holds."""
        checkout_file = stand.home / "srv" / self.key / deploy_checkout.COMPOSE_FILE
        texts = {f"the release at {self.tag}": self.release_compose}
        if checkout_file.is_file():
            texts[f"~/srv/{self.key}"] = checkout_file.read_text()
        counted = [
            f"{where}: {self.services_checked(stand, text)} service"
            for where, text in texts.items()
        ]
        return (
            f"app {self.key} ({', '.join(counted)}): no route of the live edge, port, host "
            "namespace, network_mode, socket, device or privilege, no source outside the scratch "
            f"HOME, no volume named outside the app, only the copy's external "
            f"{speech_prefix(stand.isolation.project)}* networks"
        )

    def resolved(self, stand: CopyStand, text: str) -> dict[str, Any]:
        """`text` resolved under the app's project, from the app's checkout directory, with the
        environment hal's apply in the copy runs with."""
        directory = stand.home / CHECK_DIRECTORY / self.key
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / deploy_checkout.COMPOSE_FILE
        file.write_text(text)
        command = ["docker", "compose", "-p", self.key, "--project-directory"]
        command += [str(stand.home / "srv" / self.key), "--file", str(file)]
        return json.loads(run_checked([*command, "config", "--format", "json"], stand.environment))

    def services_checked(self, stand: CopyStand, text: str) -> int:
        return expect_app_config_isolated(
            self.resolved(stand, text), self.key, stand.isolation.project, stand.home
        )

    def with_entry(self, entry: str) -> SpeechApp:
        return SpeechApp(self.key, entry, self.release_compose, self.tag)


def with_service(resolved: Mapping[str, Any], **changes: object) -> dict[str, Any]:
    """A deep copy of `resolved` whose every service takes `changes`."""
    changed = json.loads(json.dumps(resolved))
    for service in changed["services"].values():
        service.update(changes)
    return changed


def on_network_mode(resolved: Mapping[str, Any], mode: str) -> dict[str, Any]:
    """A deep copy of `resolved` whose every service takes `mode` instead of its networks."""
    changed = with_service(resolved, network_mode=mode)
    for service in changed["services"].values():
        service.pop("networks", None)
    return changed


def with_volume(resolved: Mapping[str, Any], declared: dict[str, object]) -> dict[str, Any]:
    """A deep copy of `resolved` whose every service mounts the top-level volume `declared`."""
    changed = with_service(
        resolved, volumes=[{"type": "volume", "source": "probe", "target": "/p"}]
    )
    changed["volumes"] = {"probe": declared}
    return changed


def refusal_cases(resolved: Mapping[str, Any], live_network: str) -> dict[str, tuple[dict, str]]:
    """The release's resolved configuration changed as a compose.yaml at another tag could change
    it, by case, with the reason its refusal names."""
    on_live = json.loads(json.dumps(resolved))
    first = next(iter(on_live["networks"].values()))
    first["name"] = live_network
    with_default = json.loads(json.dumps(resolved))
    with_default["networks"]["default"] = {"name": "speech_default"}
    socket = {"type": "bind", "source": DOCKER_SOCKET_BIND[1], "target": DOCKER_SOCKET_BIND[1]}
    shipped = yaml.safe_load((REPO / COMPOSE_FILE).read_text())
    live_name = shipped["services"][KEYCLOAK_SERVICE]["labels"][EDGE_NAME_LABEL]
    (database_mount,) = shipped["services"][KEYCLOAK.database]["volumes"]
    live_volume = shipped["volumes"][database_mount.partition(":")[0]]["name"]
    return {
        "a label the live Traefik routes": (
            with_service(resolved, labels={EDGE_NAME_LABEL: live_name}),
            "would route",
        ),
        "a published port": (
            with_service(resolved, ports=[{"target": 8080}]),
            "publish a host port",
        ),
        "the host network": (with_service(resolved, network_mode=HOST_NAMESPACE), "host network"),
        "the default bridge by network_mode": (on_network_mode(resolved, "bridge"), "network_mode"),
        "the docker socket": (with_service(resolved, volumes=[socket]), "mount the docker socket"),
        "privileged": (with_service(resolved, privileged=True), "widen the container"),
        f"the live network {live_network}": (on_live, "networks not the copy's"),
        "a network compose would create": (with_default, "networks not the copy's"),
        f"the live external volume {live_volume}": (
            with_volume(resolved, {"name": live_volume, "external": True}),
            "volumes outside",
        ),
    }


def expect_app_guards_refuse(app: SpeechApp, stand: CopyStand, live_network: str) -> list[str]:
    """Each refusal case of the release's configuration refused for its reason, once the release
    itself passes: one `self-check:` line each."""
    resolved = app.resolved(stand, app.release_compose)
    project, home = stand.isolation.project, stand.home
    expect_app_config_isolated(resolved, app.key, project, home)
    lines = []
    for case, (changed, reason) in refusal_cases(resolved, live_network).items():
        try:
            expect_app_config_isolated(changed, app.key, project, home)
        except ProbeFailed as failure:
            expect(reason in str(failure), f"self-check: {case} refused for another reason")
            lines.append(f"self-check: the app's {case} refused: {failure}")
        else:
            raise ProbeFailed(f"self-check: the app's {case} was accepted")
    return lines
