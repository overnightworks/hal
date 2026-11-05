"""The check of the speech app's compose configuration before hal creates or starts it in H's copy.

An app runs through hal's app compose (`docker compose -p <key>` over its checkout's compose.yaml),
not through the copy's compose file, so copy_isolation's checks never see it. `SpeechApp` is the
copy fleet's app (copy_isolation's `FleetApp`): `expect_isolated` resolves what hal would start it
from, the release's compose.yaml at its tag and the checkout's once it exists, with the copy's
environment, and refuses it when it could reach the live stack. `expect_app_config_isolated` is
that check over one resolved configuration.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from copy_isolation import (
    COMPOSE_FILE,
    DOCKER_SOCKET_BIND,
    HOST_NAMESPACE,
    REPO,
    CopyStand,
    expect_namespaces_in_project,
    expect_sources_in_scratch,
    routable_by_live_edge,
    run_checked,
)
from edge_copy import ProbeFailed, expect

from hal.exposure.docker import EDGE_NAME_LABEL
from hal.stack import deploy_checkout
from hal.stack.realm.reconcile import KEYCLOAK_SERVICE

SPEECH_NETWORK = "_speech_"  # `<project>_speech_<caller>`: the speech networks the copy creates
HOST_MODES = ("uts", "userns_mode", "cgroup")
DEVICE_KEYS = ("privileged", "devices", "cap_add")
CHECK_DIRECTORY = ".probe-app-check"  # under the scratch HOME, beside the app's checkout


def expect_app_config_isolated(
    resolved: Mapping[str, Any], key: str, copy_project: str, home: Path
) -> int:
    """Refuses the app's resolved configuration when a service could reach the live stack or the
    host: a label the live Traefik routes, a published port, a namespace of the host or of a
    container outside the app, a bind, secret file or volume backing outside the scratch HOME, the
    docker socket, a device or a privilege; or when it joins any network but an external one the
    copy names `<copy project>_speech_*`. The number of services."""
    services = resolved["services"]
    routable = sorted(n for n, s in services.items() if routable_by_live_edge(s.get("labels")))
    expect(not routable, f"the live Traefik would route {routable}")
    published = sorted(name for name, service in services.items() if service.get("ports"))
    expect(not published, f"{published} publish a host port")
    on_host = sorted(n for n, s in services.items() if s.get("network_mode") == HOST_NAMESPACE)
    expect(not on_host, f"{on_host} run on the host network")
    socket = sorted(
        name
        for name, service in services.items()
        for mount in service.get("volumes") or []
        if mount.get("source") == DOCKER_SOCKET_BIND[1]
    )
    expect(not socket, f"{socket} mount the docker socket")
    expect_sources_in_scratch(resolved, services, home)
    expect_namespaces_in_project(services, services, key)
    widened = sorted(
        [f"{n}.{k}" for n, s in services.items() for k in DEVICE_KEYS if s.get(k)]
        + [
            f"{n}.{k}: host"
            for n, s in services.items()
            for k in HOST_MODES
            if s.get(k) == HOST_NAMESPACE
        ]
    )
    expect(not widened, f"{widened} widen the container")
    prefix = f"{copy_project}{SPEECH_NETWORK}"
    networks = resolved.get("networks") or {}
    foreign = sorted(
        f"{key}: {network.get('name')}"
        for key, network in networks.items()
        if not network.get("external") or not str(network.get("name")).startswith(prefix)
    )
    expect(not foreign, f"networks not the copy's external {prefix}*: {foreign}")
    return len(services)


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
        checkout = stand.home / "srv" / self.key / deploy_checkout.COMPOSE_FILE
        texts = {f"the release at {self.tag}": self.release_compose}
        if checkout.is_file():
            texts[f"~/srv/{self.key}"] = checkout.read_text()
        counted = [
            f"{where}: {self.services_checked(stand, text)} service"
            for where, text in texts.items()
        ]
        return (
            f"app {self.key} ({', '.join(counted)}): no route of the live edge, port, host "
            "namespace, socket, device or privilege, no source outside the scratch HOME, only the "
            f"copy's external {stand.isolation.project}{SPEECH_NETWORK}* networks"
        )

    def resolved(self, stand: CopyStand, text: str) -> dict[str, Any]:
        """`text` resolved under the app's project, from the app's checkout directory, with the
        environment hal's apply in the copy runs with."""
        directory = stand.home / CHECK_DIRECTORY / self.key
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / deploy_checkout.COMPOSE_FILE
        file.write_text(text)
        command = [
            "docker",
            "compose",
            "-p",
            self.key,
            "--project-directory",
            str(stand.home / "srv" / self.key),
            "--file",
            str(file),
            "config",
            "--format",
            "json",
        ]
        return json.loads(run_checked(command, stand.environment))

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


def refusal_cases(resolved: Mapping[str, Any], live_network: str) -> dict[str, tuple[dict, str]]:
    """The release's resolved configuration changed as a compose.yaml at another tag could change
    it, by case, with the reason its refusal names."""
    on_live = json.loads(json.dumps(resolved))
    first = next(iter(on_live["networks"].values()))
    first["name"] = live_network
    with_default = json.loads(json.dumps(resolved))
    with_default["networks"]["default"] = {"name": "speech_default"}
    socket = {"type": "bind", "source": DOCKER_SOCKET_BIND[1], "target": DOCKER_SOCKET_BIND[1]}
    shipped = yaml.safe_load((REPO / COMPOSE_FILE).read_text())["services"][KEYCLOAK_SERVICE]
    live_name = shipped["labels"][EDGE_NAME_LABEL]  # a name the live constraint routes
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
        "the docker socket": (with_service(resolved, volumes=[socket]), "mount the docker socket"),
        "privileged": (with_service(resolved, privileged=True), "widen the container"),
        f"the live network {live_network}": (on_live, "networks not the copy's"),
        "a network compose would create": (with_default, "networks not the copy's"),
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
