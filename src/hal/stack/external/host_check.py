"""The host check (#138): what Cloudflare actually holds against each host's declared exposure.

Pure over a `Snapshot`; `check_hosts` is the entry for callers (the command, later `apply` and
`hal online`). The `problem` values and the four finding keys are a contract for `hal`.
"""

import json
from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from typing import Any

from hal.output.command import Verb, command
from hal.stack import catalog
from hal.stack.external import host_probe
from hal.stack.external.cloudflare_read import (
    SELF_HOSTED,
    App,
    CloudflareRead,
    Include,
    Policy,
    Record,
    Snapshot,
    destination_host,
)

OPERATOR_GROUP_NAME = "operator"
ADDRESS_RECORD_TYPES = ("A", "AAAA", "CNAME")
TUNNEL_TARGET_SUFFIX = ".cfargotunnel.com"
ACCOUNT = "account"
ACCESS_NOT_ENABLED_NOTE = "note: Access is not enabled on the account (no declared host needs it)"


class CheckExit(IntEnum):
    CLEAN = 0
    FINDINGS = 1
    CANNOT_CHECK = 2


class Problem(StrEnum):
    """In report order."""

    ACCESS_NOT_ENABLED = "access-not-enabled"
    RECORD_MISSING = "record-missing"
    RECORD_WRONG = "record-wrong"
    APP_MISSING = "app-missing"
    POLICY_WRONG = "policy-wrong"
    APP_UNEXPECTED = "app-unexpected"
    UNDECLARED_RECORD = "undeclared-record"
    UNDECLARED_APP = "undeclared-app"
    ANSWER_WRONG = "answer-wrong"
    UNREACHABLE = "unreachable"


_APPLY = command(Verb.APPLY)
_NEXT = {
    Problem.ACCESS_NOT_ENABLED: (
        "enable Zero Trust on the account in the Cloudflare dashboard and create the Access "
        f"group `{OPERATOR_GROUP_NAME}` (X8a's operator step); then `{_APPLY}`"
    ),
    Problem.RECORD_MISSING: f"`{_APPLY}`",
    Problem.RECORD_WRONG: (
        f"`{_APPLY}` shows the Cloudflare plan before its yes; nothing is converted (D12), "
        "so fix a foreign type by hand"
    ),
    Problem.APP_MISSING: f"`{_APPLY}`",
    Problem.POLICY_WRONG: f"`{_APPLY}`",
    Problem.APP_UNEXPECTED: ("remove the app, or declare the host `bypass` or `protected`"),
    Problem.UNDECLARED_RECORD: (
        "declare the host in `fleet.yaml`, or delete the record in the dashboard "
        "(`apply` never deletes it, #30 rule 7)"
    ),
    Problem.UNDECLARED_APP: "declare it, or delete the app in the dashboard",
    Problem.ANSWER_WRONG: f"`{_APPLY}` shows the Cloudflare plan before its yes",
    Problem.UNREACHABLE: "check that the tunnel and cloudflared run",
}
_ORDER = {problem: position for position, problem in enumerate(Problem)}


@dataclass(frozen=True)
class Finding:
    problem: Problem
    subject: str
    detail: str

    @property
    def next(self) -> str:
        return _NEXT[self.problem]

    def as_json(self) -> dict[str, str]:
        return {
            "problem": self.problem.value,
            "subject": self.subject,
            "detail": self.detail,
            "next": self.next,
        }


@dataclass(frozen=True)
class HostCheck:
    findings: tuple[Finding, ...]
    host_count: int
    access_unused: bool = False

    @property
    def exit_code(self) -> CheckExit:
        return CheckExit.FINDINGS if self.findings else CheckExit.CLEAN


Answers = Mapping[str, host_probe.Answer | host_probe.Unreachable]


def check_hosts(document: Any, cloudflare: CloudflareRead, prober: host_probe.Prober) -> HostCheck:
    """Read the account once, ask the declared hosts once each, and compare with the catalog."""
    zone = catalog.zone(document)
    hosts = catalog.hosts(document)
    snapshot = cloudflare.read(zone, {host.tunnel for host in hosts if host.tunnel is not None})
    answers = {name: prober.ask(name) for name in names_to_probe(hosts, snapshot)}
    return compare(zone, hosts, snapshot, answers, catalog.redirected_fqdns(document))


def names_to_probe(hosts: Sequence[catalog.Host], snapshot: Snapshot) -> dict[str, catalog.Host]:
    """The name to ask for each declared host that has an address record. The protected wildcard
    is asked at the reserved probe name, and not at all while Access is off."""
    with_record = {record.name for record in _address_records(snapshot.records)}
    return {
        _probe_name(host): host
        for host in hosts
        if host.fqdn in with_record and not (snapshot.apps is None and _is_wildcard(host))
    }


def _is_wildcard(host: catalog.Host) -> bool:
    return host.name == catalog.WILDCARD


def _probe_name(host: catalog.Host) -> str:
    return (
        f"{catalog.PROBE_NAME}.{host.fqdn.removeprefix('*.')}" if _is_wildcard(host) else host.fqdn
    )


def compare(
    zone: str,
    hosts: Sequence[catalog.Host],
    snapshot: Snapshot,
    answers: Answers,
    redirected: frozenset[str] = frozenset(),
) -> HostCheck:
    declared = {host.fqdn: host for host in hosts}
    # A record's tunnel is its host's; a redirect-only name has no host and keeps hal's.
    record_tunnels = {host.fqdn: host.tunnel for host in hosts} | dict.fromkeys(
        sorted(redirected - declared.keys())
    )
    findings = [
        finding
        for fqdn, tunnel in record_tunnels.items()
        for finding in _record_findings(fqdn, snapshot.tunnel_id_of(tunnel), snapshot)
    ]
    hosts_without_record = {f.subject for f in findings if f.problem is Problem.RECORD_MISSING}
    findings += _undeclared_records(declared.keys() | redirected, snapshot.records)
    access_unused = False
    if snapshot.apps is None:
        needs_access = any(host.exposure is not catalog.Exposure.PUBLIC for host in hosts)
        access_unused = not needs_access
        if needs_access:
            findings.append(
                Finding(Problem.ACCESS_NOT_ENABLED, ACCOUNT, "Access is not enabled on the account")
            )
    else:
        findings += [
            finding
            for host in hosts
            if host.fqdn not in hosts_without_record
            for finding in _app_findings(zone, host, snapshot.apps, snapshot)
        ]
        findings += _undeclared_apps(zone, declared, snapshot.apps)
    findings += [
        finding
        for name, host in names_to_probe(hosts, snapshot).items()
        if (finding := _answer_finding(host, name, answers[name]))
    ]
    ordered = sorted(findings, key=lambda f: (_ORDER[f.problem], f.subject, f.detail))
    return HostCheck(tuple(ordered), len(hosts), access_unused)


def _record_findings(fqdn: str, tunnel_id: str, snapshot: Snapshot) -> list[Finding]:
    records = [record for record in _address_records(snapshot.records) if record.name == fqdn]
    if not records:
        return [Finding(Problem.RECORD_MISSING, fqdn, "no A, AAAA or CNAME record")]
    target = f"{tunnel_id}{TUNNEL_TARGET_SUFFIX}"
    if len(records) == 1 and _is_proxied_cname_to(records[0], target):
        return []
    held = ", ".join(_describe_record(record) for record in sorted(records, key=_describe_record))
    return [
        Finding(Problem.RECORD_WRONG, fqdn, f"holds {held}; expected a proxied CNAME to {target}")
    ]


def _is_proxied_cname_to(record: Record, target: str) -> bool:
    return (
        record.type == "CNAME"
        and record.proxied
        and record.content.lower().rstrip(".") == target.lower()
    )


def _describe_record(record: Record) -> str:
    proxy = "proxied" if record.proxied else "not proxied"
    return f"{record.type} {record.content} ({proxy})"


def _address_records(records: Sequence[Record]) -> list[Record]:
    return [record for record in records if record.type in ADDRESS_RECORD_TYPES]


def _undeclared_records(declared: Collection[str], records: Sequence[Record]) -> list[Finding]:
    return [
        Finding(Problem.UNDECLARED_RECORD, record.name, f"{record.type} {record.content}")
        for record in _address_records(records)
        if record.name not in declared and not _is_service_label(record.name)
    ]


def _is_service_label(name: str) -> bool:
    return any(label.startswith("_") for label in name.split("."))


def _app_findings(
    zone: str, host: catalog.Host, apps: Sequence[App], snapshot: Snapshot
) -> list[Finding]:
    if host.exposure is catalog.Exposure.PUBLIC:
        covering = _covering_destinations(zone, host.fqdn, apps)
        if not covering:
            return []
        return [
            Finding(
                Problem.APP_UNEXPECTED, host.fqdn, f"covered by the Access app at {covering[0]}"
            )
        ]
    apps_here = [app for app in apps if _destinations_at(app, host.fqdn)]
    if not apps_here:
        return [Finding(Problem.APP_MISSING, host.fqdn, "no Access app has this host")]
    if len(apps_here) > 1:
        return [Finding(Problem.POLICY_WRONG, host.fqdn, "several apps have this host")]
    (own_app,) = apps_here
    if own_app.type != SELF_HOSTED:
        detail = "the app at this host is not a self-hosted app"
        return [Finding(Problem.POLICY_WRONG, host.fqdn, detail)]
    destinations_here = _destinations_at(own_app, host.fqdn)
    if host.fqdn not in destinations_here:
        detail = f"the app is scoped to the path {destinations_here[0].removeprefix(host.fqdn)}"
        return [Finding(Problem.POLICY_WRONG, host.fqdn, detail)]
    faults = [
        f"a path rule makes {override.path_pattern} public, bypassing Access"
        for override in own_app.overrides
        if destination_host(override.destination) == host.fqdn
    ]
    if own_app.options_preflight_bypass:
        faults.append("OPTIONS requests bypass Access")
    if policy_fault := _policy_fault(host.exposure, own_app.policies, snapshot):
        faults.append(policy_fault)
    return [Finding(Problem.POLICY_WRONG, host.fqdn, fault) for fault in faults]


def _answer_finding(
    host: catalog.Host, name: str, outcome: host_probe.Answer | host_probe.Unreachable
) -> Finding | None:
    where = "" if name == host.fqdn else f"asked at {name}: "
    if isinstance(outcome, host_probe.Unreachable):
        return Finding(Problem.UNREACHABLE, host.fqdn, f"{where}request failed: {outcome.kind}")
    if not outcome.has_cf_ray:
        return Finding(
            Problem.ANSWER_WRONG, host.fqdn, f"{where}status {outcome.status}, no cf-ray"
        )
    to_access = host_probe.is_access_redirect(outcome, name)
    if host.exposure is catalog.Exposure.PROTECTED:
        if to_access:
            return None
        verdict = ", a challenge" if outcome.challenge else ""
        detail = f"{where}status {outcome.status}{verdict}, not an Access redirect"
    elif to_access:
        detail = f"{where}status {outcome.status}, redirects to Access"
    else:
        return None
    return Finding(Problem.ANSWER_WRONG, host.fqdn, detail)


def _destinations_at(app: App, fqdn: str) -> list[str]:
    return [d for d in app.destinations if destination_host(d) == fqdn]


def _covering_destinations(zone: str, fqdn: str, apps: Sequence[App]) -> list[str]:
    return [
        destination
        for app in apps
        for destination in app.destinations
        if _covers(zone, destination_host(destination), fqdn)
    ]


def _covers(zone: str, covering_host: str, fqdn: str) -> bool:
    if covering_host == fqdn:
        return True
    one_label_under_zone = fqdn.endswith(f".{zone}") and "." not in fqdn.removesuffix(f".{zone}")
    return covering_host == f"*.{zone}" and one_label_under_zone


def _policy_fault(
    exposure: catalog.Exposure, policies: Sequence[Policy], snapshot: Snapshot
) -> str | None:
    if len(policies) != 1:
        return f"the app has {len(policies)} policies, expected exactly one"
    (policy,) = policies
    if exposure is catalog.Exposure.BYPASS:
        holds = policy.decision == "bypass" and policy.include == (Include("everyone"),)
        expected = "one bypass policy including everyone"
    else:
        holds = policy.decision == "allow" and _includes_only_the_operator_group(policy, snapshot)
        expected = f"one allow policy including only the group {OPERATOR_GROUP_NAME}"
    if not holds:
        return _describe_policy(expected, policy)
    return "the policy has extra conditions" if policy.extra_conditions else None


def _includes_only_the_operator_group(policy: Policy, snapshot: Snapshot) -> bool:
    operator_ids = [group.id for group in snapshot.groups if group.name == OPERATOR_GROUP_NAME]
    return (
        len(operator_ids) == 1
        and len(policy.include) == 1
        and policy.include[0] == Include("group", operator_ids[0])
    )


def _describe_policy(expected: str, policy: Policy) -> str:
    kinds = ", ".join(rule.kind for rule in policy.include) or "nothing"
    return f"the app's policy is {policy.decision} including {kinds}; expected {expected}"


def _undeclared_apps(
    zone: str, declared: dict[str, catalog.Host], apps: Sequence[App]
) -> list[Finding]:
    """Every in-zone destination that is neither a declared Access host nor a public host's."""
    access_hosts = {
        fqdn for fqdn, host in declared.items() if host.exposure is not catalog.Exposure.PUBLIC
    }
    public_hosts = [
        host.fqdn for host in declared.values() if host.exposure is catalog.Exposure.PUBLIC
    ]
    return [
        Finding(Problem.UNDECLARED_APP, destination, "an Access app nobody declared")
        for app in apps
        for destination in app.destinations
        if _in_zone(zone, destination_host(destination))
        and destination_host(destination) not in access_hosts
        and not any(_covers(zone, destination_host(destination), fqdn) for fqdn in public_hosts)
    ]


def _in_zone(zone: str, host: str) -> bool:
    return host == zone or host.endswith(f".{zone}")


def as_json(check: HostCheck) -> str:
    return json.dumps([finding.as_json() for finding in check.findings], indent=2)


def as_text(check: HostCheck) -> str:
    lines = [f"no findings ({check.host_count} hosts)"] if not check.findings else []
    for finding in check.findings:
        lines += [f"{finding.problem.value} {finding.subject}: {finding.detail}"]
        lines += [f"  next: {finding.next}"]
    if check.access_unused:
        lines.append(ACCESS_NOT_ENABLED_NOTE)
    return "\n".join(lines)
