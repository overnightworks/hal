"""The rule of the speech app's compose configuration before hal creates or starts it in H's copy.

An app runs through hal's app compose (`docker compose -p <key>` over its checkout's compose.yaml),
not through the copy's compose file, so copy_isolation's checks never see it.
`expect_app_config_isolated` refuses one resolved configuration of the app when it could reach the
live stack or the host; release_origin's `SpeechApp` resolves what hal would start the app from and
runs it. Pure: the caller passes what Compose resolved.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from copy_isolation import (
    DOCKER_SOCKET_BIND,
    HOST_NAMESPACE,
    expect_namespaces_in_project,
    expect_sources_in_scratch,
    routable_by_live_edge,
)
from edge_copy import expect

SPEECH_NETWORK = "speech_"  # `<project>_speech_<caller>`: the speech networks a project names
HOST_MODES = ("uts", "userns_mode", "cgroup")
DEVICE_KEYS = ("privileged", "devices", "cap_add")


def speech_prefix(project: str) -> str:
    """The start of every speech network name of the compose `project`."""
    return f"{project}_{SPEECH_NETWORK}"


def expect_exposure_refused(services: Mapping[str, Any]) -> None:
    """Refuses a label the live Traefik routes, a published port and the host network."""
    routable = sorted(n for n, s in services.items() if routable_by_live_edge(s.get("labels")))
    expect(not routable, f"the live Traefik would route {routable}")
    published = sorted(name for name, service in services.items() if service.get("ports"))
    expect(not published, f"{published} publish a host port")
    on_host = sorted(n for n, s in services.items() if s.get("network_mode") == HOST_NAMESPACE)
    expect(not on_host, f"{on_host} run on the host network")


def expect_widening_refused(services: Mapping[str, Any]) -> None:
    """Refuses the docker socket, a device, a privilege and a host uts, user or cgroup namespace."""
    socket = sorted(
        name
        for name, service in services.items()
        for mount in service.get("volumes") or []
        if mount.get("source") == DOCKER_SOCKET_BIND[1]
    )
    expect(not socket, f"{socket} mount the docker socket")
    widened = sorted(
        [f"{n}.{k}" for n, s in services.items() for k in DEVICE_KEYS if s.get(k)]
        + [f"{n}.{k}: host" for n, s in services.items() for k in HOST_MODES
           if s.get(k) == HOST_NAMESPACE]
    )  # fmt: skip
    expect(not widened, f"{widened} widen the container")


def expect_networks_in_copy(
    resolved: Mapping[str, Any], services: Mapping[str, Any], prefix: str
) -> None:
    """Refuses a network but an external one named `prefix*`, a `network_mode` (bridge, host,
    none, `container:`, `service:` or a network's name) that names none of them, and a service
    that joins no network, which Docker puts on the default bridge."""
    foreign = sorted(
        f"{key}: {network.get('name')}"
        for key, network in (resolved.get("networks") or {}).items()
        if not network.get("external") or not str(network.get("name")).startswith(prefix)
    )
    expect(not foreign, f"networks not the copy's external {prefix}*: {foreign}")
    modes = sorted(
        f"{name}: {service['network_mode']}"
        for name, service in services.items()
        if "network_mode" in service and not str(service["network_mode"]).startswith(prefix)
    )
    expect(not modes, f"{modes} take a network_mode outside the copy's {prefix}* networks")
    unattached = sorted(
        name for name, service in services.items()
        if "network_mode" not in service and not service.get("networks")
    )  # fmt: skip
    expect(not unattached, f"{unattached} join no network and would land on the default bridge")


def volume_named_in_app(volume: Mapping[str, Any], key: str, prefix: str) -> bool:
    """Whether a resolved volume's name is in the app's project `key`, or is an external one of
    the copy's `prefix*` names."""
    name = str(volume.get("name"))
    return name.startswith(f"{key}_") or (bool(volume.get("external")) and name.startswith(prefix))


def expect_volume_names_in_app(volumes: Mapping[str, Any], key: str, prefix: str) -> None:
    """Refuses a volume `volume_named_in_app` refuses, so no volume of the live stack is mounted."""
    outside = sorted(
        f"{volume_key}: {volume.get('name')}"
        for volume_key, volume in volumes.items()
        if not volume_named_in_app(volume, key, prefix)
    )
    expect(not outside, f"volumes outside {key}_* and the external {prefix}*: {outside}")


def expect_app_config_isolated(
    resolved: Mapping[str, Any], key: str, copy_project: str, home: Path
) -> int:
    """Refuses the app's resolved configuration when a service could reach the live stack or the
    host: a label the live Traefik routes, a published port, a namespace of the host or of a
    container outside the app, a bind, secret file or volume backing outside the scratch HOME, a
    volume named outside the app, the docker socket, a device or a privilege; or when it reaches
    any network but an external one the copy names `<copy project>_speech_*`. The number of
    services."""
    services = resolved["services"]
    expect_exposure_refused(services)
    expect_widening_refused(services)  # before the source check, which spares the socket proxy's
    expect_sources_in_scratch(resolved, services, home)
    expect_namespaces_in_project(services, services, key)
    prefix = speech_prefix(copy_project)
    expect_networks_in_copy(resolved, services, prefix)
    expect_volume_names_in_app(resolved.get("volumes") or {}, key, prefix)
    return len(services)
