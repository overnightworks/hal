"""The /24s compose.yaml pins and their move to free ones. Docker refuses a second network on a /24
the live stack holds, so a probe's copy or overlay of compose.yaml takes a free /24 for every
network that pins one, and every address in it follows: the services' `ipv4_address`, the
`extra_hosts` that name them, and the anchors that carry them (Keycloak's trusted addresses).

Pure text and arithmetic: the caller passes the subnets the daemon holds (edge_copy.probe_prefixes).
A refusal is a ValueError naming the value.
"""

from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Mapping, Sequence

import yaml

# The /24s a probe takes; the shipped ones and every one the daemon holds are skipped.
PROBE_SUBNETS = tuple(f"172.31.{third}.0/24" for third in range(200, 252))
SUBNET_SUFFIX = "0/24"


def subnet_prefix(subnet: str) -> str:
    """The first three octets, with the trailing dot, of the /24 `subnet`."""
    if not subnet.endswith(f".{SUBNET_SUFFIX}"):
        raise ValueError(f"{subnet} is no /24")
    return subnet.removesuffix(SUBNET_SUFFIX)


def pinned_prefixes(text: str) -> dict[str, str]:
    """The prefix (subnet_prefix) of the /24 each network of compose.yaml `text` pins, by network;
    refuses a pin that is no /24."""
    networks = (yaml.safe_load(text) or {}).get("networks") or {}
    return {
        name: subnet_prefix(config["subnet"])
        for name, network in networks.items()
        for config in ((network or {}).get("ipam") or {}).get("config") or []
        if "subnet" in config
    }


def free_subnet(candidates: Sequence[str], occupied: Sequence[str]) -> ipaddress.IPv4Network:
    """The first candidate /24 that overlaps none of the `occupied` subnets."""
    used = [ipaddress.ip_network(subnet) for subnet in occupied]
    for candidate in map(ipaddress.IPv4Network, candidates):
        if not any(candidate.overlaps(other) for other in used if other.version == 4):
            return candidate
    raise ValueError(f"no free /24 among {candidates[0]} ... {candidates[-1]}")


def free_probe_prefixes(live: Mapping[str, str], occupied: Sequence[str]) -> dict[str, str]:
    """For each prefix of `live` (pinned_prefixes) a free one of `PROBE_SUBNETS`, none of them
    twice, overlapping no `occupied` subnet and no /24 of `live`."""
    taken, moved = [*occupied, *(f"{prefix}{SUBNET_SUFFIX}" for prefix in live.values())], {}
    for prefix in live.values():
        subnet = free_subnet(PROBE_SUBNETS, taken)
        taken.append(str(subnet))
        moved[prefix] = str(subnet.network_address).removesuffix("0")
    return moved


def moved_to_probe_subnets(text: str, moved: Mapping[str, str]) -> str:
    """`text` with every live prefix of `moved` replaced by its probe prefix, in one pass; refuses a
    text that names one of them nowhere."""
    for live in moved:
        if live not in text:
            raise ValueError(f"the file does not name {live}")
    if not moved:
        return text
    return re.sub("|".join(map(re.escape, moved)), lambda found: moved[found[0]], text)


def subnet_overlay(text: str, subnets: Mapping[str, str]) -> str:
    """A compose overlay over `text` of compose.yaml that moves each network of `subnets` off its
    one /24 onto the given one, with every service's attachment to it and every extra_hosts mapping
    that name an address there (moved_to_probe_subnets). A compose file cannot replace the base
    file's lists, so the overlay drops each with compose's own `!override` tag."""
    shipped = yaml.safe_load(text)
    configs = {network: shipped["networks"][network]["ipam"]["config"] for network in subnets}
    moves = {subnet_prefix(c["subnet"]): subnet_prefix(subnets[n]) for n, (c,) in configs.items()}

    def pinned(value: object) -> bool:
        return any(live in json.dumps(value) for live in moves)

    def moved(value: object) -> str:
        found = json.dumps(value)
        return moved_to_probe_subnets(
            found, {old: new for old, new in moves.items() if old in found}
        )

    lines = ["networks:"]
    lines += [f"  {n}:\n    ipam:\n      config: !override {moved(c)}" for n, c in configs.items()]
    lines.append("services:")
    for name, service in shipped["services"].items():
        joined = service.get("networks") if isinstance(service.get("networks"), dict) else {}
        attached = [f"      {n}: {moved(joined[n])}" for n in subnets if pinned(joined.get(n))]
        hosts = service.get("extra_hosts")
        entry = ["    networks:", *attached] if attached else []
        entry += [f"    extra_hosts: !override {moved(hosts)}"] if pinned(hosts) else []
        lines += [f"  {name}:", *entry] if entry else []
    return "\n".join(lines) + "\n"
