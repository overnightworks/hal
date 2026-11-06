"""The host check's comparison (#138 cells C and P1): dataclass fixtures, no network."""

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from hal.stack import catalog
from hal.stack.catalog import Exposure
from hal.stack.external import host_check
from hal.stack.external.cloudflare_read import (
    SELF_HOSTED,
    AccessGroup,
    App,
    Include,
    Override,
    Policy,
    Record,
    Snapshot,
)
from hal.stack.external.host_check import Problem
from hal.stack.external.host_probe import Answer, FailureKind, Unreachable

ZONE = "example.test"
TUNNEL = "t-1"
TARGET = f"{TUNNEL}.cfargotunnel.com"
OPERATOR = AccessGroup("g-operator", "operator")
GROUPS = (OPERATOR, AccessGroup("g-staff", "staff"))
EXTERNAL = Path(__file__).resolve().parents[1] / "external"


def declared(name: str, exposure: Exposure) -> catalog.Host:
    fqdn = ZONE if name == "@" else f"{name}.{ZONE}"
    return catalog.Host("svc", name, fqdn, exposure, None, None, catalog.DEFAULT_TARGET)


def public(name: str) -> catalog.Host:
    return declared(name, Exposure.PUBLIC)


def bypass(name: str) -> catalog.Host:
    return declared(name, Exposure.BYPASS)


def protected_wildcard() -> catalog.Host:
    return declared("*", Exposure.PROTECTED)


def fqdn(label: str) -> str:
    return ZONE if label == "@" else f"{label}.{ZONE}"


def tunnel_record(label: str, content: str = TARGET, proxied: bool = True) -> Record:
    return Record(fqdn(label), "CNAME", content, proxied)


def address_record(label: str, kind: str = "A", content: str = "192.0.2.1") -> Record:
    return Record(fqdn(label), kind, content, True)


def policy(decision: str, *include: Include) -> Policy:
    return Policy(decision, include)


BYPASS_POLICY = policy("bypass", Include("everyone"))
OPERATOR_POLICY = policy("allow", Include("group", OPERATOR.id))


def app(
    *destinations: str,
    policies: tuple[Policy, ...] = (),
    kind: str = SELF_HOSTED,
    **exposure_facts,
) -> App:
    return App(kind, destinations, policies, **exposure_facts)


def bypass_app(label: str) -> App:
    return app(fqdn(label), policies=(BYPASS_POLICY,))


def operator_app() -> App:
    return app(f"*.{ZONE}", policies=(OPERATOR_POLICY,))


def snapshot(*records: Record, apps: tuple[App, ...] | None = (), groups=GROUPS) -> Snapshot:
    return Snapshot(TUNNEL, records, groups, apps)


CLEAN_PUBLIC_ANSWER = Answer(200, None, True, False)
ACCESS_ANSWER = Answer(302, "https://team.cloudflareaccess.com/cdn-cgi/access/login/x", True, False)


def right_answers(hosts, current: Snapshot) -> dict[str, Answer]:
    """What every probed name answers when its host is exposed as declared."""
    return {
        name: ACCESS_ANSWER if host.exposure is Exposure.PROTECTED else CLEAN_PUBLIC_ANSWER
        for name, host in host_check.names_to_probe(hosts, current).items()
    }


def compared(hosts, current: Snapshot, answers: dict | None = None) -> host_check.HostCheck:
    """`compare` over the declared zone; without `answers` every probed name answers rightly."""
    return host_check.compare(
        ZONE, hosts, current, right_answers(hosts, current) if answers is None else answers
    )


def found(hosts, current: Snapshot) -> list[tuple[str, str]]:
    check = compared(hosts, current)
    return [(finding.problem.value, finding.subject) for finding in check.findings]


LIVE_HOSTS = [public("@"), bypass("www"), protected_wildcard()]
LIVE = snapshot(
    tunnel_record("@"),
    tunnel_record("www"),
    tunnel_record("*"),
    apps=(bypass_app("www"), operator_app()),
)


def test_a_state_that_matches_the_catalog_has_no_findings_in_any_order():
    """C1."""
    reordered = snapshot(
        *reversed(LIVE.records), apps=tuple(reversed(LIVE.apps)), groups=tuple(reversed(GROUPS))
    )
    forward = compared(LIVE_HOSTS, LIVE)
    backward = compared(list(reversed(LIVE_HOSTS)), reordered)
    assert forward.findings == () == backward.findings
    assert host_check.as_text(forward) == host_check.as_text(backward) == "no findings (3 hosts)"
    assert host_check.as_json(forward) == host_check.as_json(backward) == "[]"


def test_todays_live_state_reports_the_www_record_and_the_stray_one_and_notes_access_off():
    """#134 L1: www is a CNAME to the apex, presentator is a leftover, Access is off."""
    hosts = [public("@"), public("www")]
    live = snapshot(
        tunnel_record("@"),
        tunnel_record("www", content=ZONE),
        tunnel_record("presentator"),
        apps=None,
    )
    check = compared(hosts, live)
    assert [(f.problem.value, f.subject) for f in check.findings] == [
        ("record-wrong", fqdn("www")),
        ("undeclared-record", fqdn("presentator")),
    ]
    assert host_check.ACCESS_NOT_ENABLED_NOTE in host_check.as_text(check)
    assert host_check.ACCESS_NOT_ENABLED_NOTE not in host_check.as_json(check)


WWW_RECORD_CASES = [
    pytest.param([], [Problem.RECORD_MISSING], id="no record"),
    pytest.param([tunnel_record("www", proxied=False)], [Problem.RECORD_WRONG], id="unproxied"),
    pytest.param(
        [tunnel_record("www", "t-2.cfargotunnel.com")], [Problem.RECORD_WRONG], id="other tunnel"
    ),
    pytest.param([tunnel_record("www")], [], id="the right tunnel"),
]


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        *WWW_RECORD_CASES,
        pytest.param(
            [tunnel_record("www"), tunnel_record("www", "t-2.cfargotunnel.com")],
            [Problem.RECORD_WRONG],
            id="two records",
        ),
        pytest.param([address_record("www")], [Problem.RECORD_WRONG], id="an A record"),
        pytest.param([tunnel_record("www", ZONE)], [Problem.RECORD_WRONG], id="a foreign name"),
    ],
)
def test_a_declared_host_needs_exactly_one_proxied_cname_to_the_tunnel(records, expected):
    """C3."""
    result = found([public("www")], snapshot(*records))
    assert result == [(problem.value, fqdn("www")) for problem in expected]


@pytest.mark.parametrize(
    ("apps", "expected"),
    [
        pytest.param((), [Problem.APP_MISSING], id="no app"),
        pytest.param(
            (app(fqdn("www"), policies=(policy("allow", Include("everyone")),)),),
            [Problem.POLICY_WRONG],
            id="an allow policy",
        ),
        pytest.param(
            (app(fqdn("www"), policies=(BYPASS_POLICY, BYPASS_POLICY)),),
            [Problem.POLICY_WRONG],
            id="two policies",
        ),
        pytest.param(
            (app(fqdn("www"), policies=(policy("bypass", Include("everyone"), Include("x")),)),),
            [Problem.POLICY_WRONG],
            id="more than everyone",
        ),
        pytest.param((bypass_app("www"),), [], id="a bypass app"),
    ],
)
def test_a_bypass_host_needs_its_own_app_with_one_bypass_policy_for_everyone(apps, expected):
    """C4."""
    result = found([bypass("www")], snapshot(tunnel_record("www"), apps=apps))
    assert result == [(problem.value, fqdn("www")) for problem in expected]


@pytest.mark.parametrize(
    ("wildcard_policies", "groups", "expected"),
    [
        pytest.param((BYPASS_POLICY,), GROUPS, [Problem.POLICY_WRONG], id="a bypass policy"),
        pytest.param(
            (policy("allow", Include("group", "g-staff")),),
            GROUPS,
            [Problem.POLICY_WRONG],
            id="another group",
        ),
        pytest.param(
            (policy("allow", Include("group", "g-operator"), Include("group", "g-staff")),),
            GROUPS,
            [Problem.POLICY_WRONG],
            id="two groups",
        ),
        pytest.param(
            (OPERATOR_POLICY,), GROUPS[1:], [Problem.POLICY_WRONG], id="no operator group"
        ),
        pytest.param(
            (OPERATOR_POLICY,),
            (*GROUPS, AccessGroup("g-twin", "operator")),
            [Problem.POLICY_WRONG],
            id="two operator groups",
        ),
        pytest.param((OPERATOR_POLICY,), GROUPS, [], id="the operator group only"),
    ],
)
def test_a_protected_host_needs_one_allow_policy_for_the_operator_group_only(
    wildcard_policies, groups, expected
):
    """C4."""
    wildcard = app(f"*.{ZONE}", policies=wildcard_policies)
    current = snapshot(tunnel_record("*"), apps=(wildcard,), groups=groups)
    result = found([protected_wildcard()], current)
    assert result == [(problem.value, fqdn("*")) for problem in expected]


@pytest.mark.parametrize(
    ("apps", "expected"),
    [
        pytest.param((bypass_app("www"),), 1, id="its own app"),
        pytest.param((app(f"*.{ZONE}", policies=(OPERATOR_POLICY,)),), 1, id="the wildcard app"),
        pytest.param((app("other." + ZONE, fqdn("www")),), 1, id="one of several destinations"),
        pytest.param((app(fqdn("www") + "/admin"),), 1, id="a path-scoped destination"),
        pytest.param((app(f"*.sub.{ZONE}"),), 0, id="a deeper wildcard"),
    ],
)
def test_a_public_host_must_not_be_covered_by_an_access_app(apps, expected):
    """C5."""
    result = found([public("www")], snapshot(tunnel_record("www"), apps=apps))
    assert [problem for problem, _ in result if problem == "app-unexpected"] == [
        "app-unexpected"
    ] * expected


def test_the_public_apex_is_not_covered_by_the_wildcard_app():
    """C5."""
    current = snapshot(tunnel_record("@"), apps=(operator_app(),))
    assert found([public("@"), protected_wildcard()], current) == [("record-missing", fqdn("*"))]


def test_two_apps_for_one_host_make_its_policy_undecidable():
    """C6."""
    apps = (bypass_app("www"), bypass_app("www"))
    findings = compared([bypass("www")], snapshot(tunnel_record("www"), apps=apps))
    assert [(f.problem, "several apps" in f.detail) for f in findings.findings] == [
        (Problem.POLICY_WRONG, True)
    ]


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param((), id="no override"),
        pytest.param((Override(fqdn("other"), "/x"),), id="an override on it"),
    ],
)
def test_an_app_with_a_second_destination_is_the_hosts_own_app_and_the_second_is_undeclared(
    overrides,
):
    """C6, C4: an override on the other host's destination does not taint this host."""
    own = app(fqdn("www"), fqdn("other"), policies=(BYPASS_POLICY,), overrides=overrides)
    assert found([bypass("www")], snapshot(tunnel_record("www"), apps=(own,))) == [
        ("undeclared-app", fqdn("other"))
    ]


@pytest.mark.parametrize(
    ("extra_app", "label"),
    [
        pytest.param(
            app(f"*.{ZONE}/admin", policies=(BYPASS_POLICY,)),
            "*",
            id="a bypass app at a path of the protected wildcard",
        ),
        pytest.param(
            app(fqdn("www") + "/admin", policies=(OPERATOR_POLICY,)),
            "www",
            id="a second app at a path of the bypass host",
        ),
    ],
)
def test_a_path_scoped_app_on_a_host_that_needs_access_is_never_clean(extra_app, label):
    """C6."""
    current = snapshot(*LIVE.records, apps=(*LIVE.apps, extra_app))
    check = compared(LIVE_HOSTS, current)
    assert [(f.problem, f.subject, f.detail) for f in check.findings] == [
        (Problem.POLICY_WRONG, fqdn(label), "several apps have this host")
    ]


def test_an_own_app_may_carry_a_path_destination_beside_the_whole_host():
    """C6: the same policy covers the whole host, so the extra path changes nothing."""
    own = app(fqdn("www"), fqdn("www") + "/admin", policies=(BYPASS_POLICY,))
    check = compared([bypass("www")], snapshot(tunnel_record("www"), apps=(own,)))
    assert not check.findings


def test_the_only_app_of_a_host_scoped_to_a_path_names_the_path():
    """C6."""
    only = app(fqdn("www") + "/admin", policies=(BYPASS_POLICY,))
    check = compared([bypass("www")], snapshot(tunnel_record("www"), apps=(only,)))
    assert [(f.problem, f.detail) for f in check.findings] == [
        (Problem.POLICY_WRONG, "the app is scoped to the path /admin")
    ]


NEEDS_ACCESS_HOSTS = pytest.mark.parametrize(
    ("host", "label", "policies", "destination"),
    [
        pytest.param(bypass("www"), "www", (BYPASS_POLICY,), fqdn("www"), id="a bypass host"),
        pytest.param(
            protected_wildcard(), "*", (OPERATOR_POLICY,), f"*.{ZONE}", id="a protected host"
        ),
    ],
)


@NEEDS_ACCESS_HOSTS
@pytest.mark.parametrize(
    ("facts_at", "expected_detail"),
    [
        pytest.param(
            lambda destination: {"overrides": (Override(destination, "/admin/*"),)},
            "a path rule makes /admin/* public, bypassing Access",
            id="a public path override",
        ),
        pytest.param(
            lambda _destination: {"options_preflight_bypass": True},
            "OPTIONS requests bypass Access",
            id="OPTIONS requests bypass Access",
        ),
    ],
)
def test_an_app_that_lets_requests_past_access_on_a_host_that_needs_it_is_policy_wrong(
    host, label, policies, destination, facts_at, expected_detail
):
    """C4: the policy is right, but a path or a method still reaches the origin without Access."""
    leaky = app(destination, policies=policies, **facts_at(destination))
    current = snapshot(tunnel_record(label), apps=(leaky,))
    check = compared([host], current)
    assert [(f.problem, f.subject, f.detail) for f in check.findings] == [
        (Problem.POLICY_WRONG, fqdn(label), expected_detail)
    ]


@NEEDS_ACCESS_HOSTS
def test_a_policy_with_extra_conditions_does_not_match_the_declared_one(
    host, label, policies, destination
):
    """C4: exclude, require, approval, isolation, a justification or connection rules only narrow
    access, but the check compares with the declaration."""
    restricted = replace(policies[0], extra_conditions=True)
    current = snapshot(tunnel_record(label), apps=(app(destination, policies=(restricted,)),))
    check = compared([host], current)
    assert [(f.problem, f.subject, f.detail) for f in check.findings] == [
        (Problem.POLICY_WRONG, host.fqdn, "the policy has extra conditions")
    ]


@NEEDS_ACCESS_HOSTS
@pytest.mark.parametrize("kind", ["ssh", "vnc", "rdp"])
def test_a_host_that_needs_access_needs_a_self_hosted_app_not_another_type(
    host, label, policies, destination, kind
):
    """C6: an app of another type at the host is wrong however right its policy looks."""
    other = app(destination, policies=policies, kind=kind)
    current = snapshot(tunnel_record(label), apps=(other,))
    check = compared([host], current)
    assert [(f.problem, f.subject, f.detail) for f in check.findings] == [
        (Problem.POLICY_WRONG, fqdn(label), "the app at this host is not a self-hosted app")
    ]


@pytest.mark.parametrize(
    ("extra", "expected"),
    [
        pytest.param(
            [address_record("stray"), tunnel_record("other")],
            [("undeclared-record", fqdn("other")), ("undeclared-record", fqdn("stray"))],
            id="an A and a CNAME",
        ),
        pytest.param([Record(fqdn("stray"), "TXT", "v=spf1", False)], [], id="a TXT"),
        pytest.param([Record(fqdn("@"), "MX", "mail.example", False)], [], id="an MX"),
        pytest.param([tunnel_record("_dmarc")], [], id="an underscore label"),
        pytest.param(
            [tunnel_record("disabled")],
            [("undeclared-record", fqdn("disabled"))],
            id="the host of a disabled entry",
        ),
    ],
)
def test_records_at_undeclared_names_are_reported_unless_they_are_not_hosts(extra, expected):
    """C7."""
    result = found([public("@")], snapshot(tunnel_record("@"), *extra))
    assert result == expected


def test_a_name_hosted_and_redirected_is_judged_once_and_stray_names_stay_undeclared():
    """#379 cell 6: the host check judges the apex once."""
    current, hosts = snapshot(tunnel_record("www"), tunnel_record("stray")), [public("@")]
    answers, redirected = right_answers(hosts, current), frozenset({fqdn("@"), fqdn("www")})
    check = host_check.compare(ZONE, hosts, current, answers, redirected)
    assert [f.subject for f in check.findings] == [fqdn("@"), fqdn("stray")]


@pytest.mark.parametrize(("records", "expected"), WWW_RECORD_CASES)
def test_a_redirected_name_needs_the_same_proxied_cname_without_being_asked(records, expected):
    document = catalog_document(host_entry("app", "public"))
    document["cloudflare"]["redirect"] = {
        "hosts": ["www"],
        "target": "https://auth.example.test/",
    }
    prober = CountingProber()
    check = host_check.check_hosts(
        document, FakeCloudflare(snapshot(tunnel_record("app"), *records)), prober
    )
    assert [(f.problem.value, f.subject) for f in check.findings] == [
        (problem.value, fqdn("www")) for problem in expected
    ]
    assert prober.asked == [fqdn("app")]


@pytest.mark.parametrize(
    ("stray_app", "expected"),
    [
        pytest.param(
            app("tool." + ZONE), [("undeclared-app", "tool." + ZONE)], id="in-zone domain"
        ),
        pytest.param(app(), [], id="no domain"),
        pytest.param(app(kind="app_launcher"), [], id="app launcher"),
        pytest.param(app(kind="warp"), [], id="warp"),
        *[
            pytest.param(
                app("tool." + ZONE, kind=kind),
                [("undeclared-app", "tool." + ZONE)],
                id=f"a {kind} app with a public destination",
            )
            for kind in ("ssh", "vnc", "rdp")
        ],
        pytest.param(
            app("tool." + ZONE + "/x"),
            [("undeclared-app", "tool." + ZONE + "/x")],
            id="a path-scoped destination",
        ),
        pytest.param(
            app("tool." + ZONE + "/Admin"),
            [("undeclared-app", "tool." + ZONE + "/Admin")],
            id="C10: the path keeps its case",
        ),
        pytest.param(app("elsewhere.invalid"), [], id="outside the zone"),
        pytest.param(app(fqdn("www"), policies=(BYPASS_POLICY,)), [], id="a declared host"),
    ],
)
def test_apps_with_destinations_nobody_declared_are_reported(stray_app, expected):
    """C7."""
    current = snapshot(tunnel_record("www"), apps=(stray_app,))
    result = [item for item in found([bypass("www")], current) if item[0] == "undeclared-app"]
    assert result == expected


def test_a_host_without_an_address_record_gets_no_app_findings():
    """C9."""
    wrong_app = app(fqdn("www"), policies=(OPERATOR_POLICY,))
    assert found([bypass("www")], snapshot(apps=(wrong_app,))) == [("record-missing", fqdn("www"))]


def test_access_off_is_one_finding_when_a_declared_host_needs_access():
    """C8."""
    hosts = [bypass("www"), protected_wildcard(), public("@")]
    current = snapshot(tunnel_record("@"), address_record("stray"), apps=None)
    assert found(hosts, current) == [
        ("access-not-enabled", "account"),
        ("record-missing", fqdn("*")),
        ("record-missing", fqdn("www")),
        ("undeclared-record", fqdn("stray")),
    ]


def test_access_off_is_only_a_note_when_every_declared_host_is_public():
    """C8."""
    check = compared([public("@")], snapshot(tunnel_record("@"), apps=None))
    assert (check.findings, check.access_unused) == ((), True)


def test_one_host_with_several_faults_is_sorted_with_one_finding_per_cause():
    """C9."""
    hosts = [bypass("www"), public("@")]
    current = snapshot(
        address_record("zzz"), address_record("aaa"), tunnel_record("@", proxied=False), apps=()
    )
    assert found(hosts, current) == [
        ("record-missing", fqdn("www")),
        ("record-wrong", fqdn("@")),
        ("undeclared-record", fqdn("aaa")),
        ("undeclared-record", fqdn("zzz")),
    ]


def test_every_finding_serialises_as_four_string_values():
    """K1."""
    result = compared([public("www")], snapshot())
    document = json.loads(host_check.as_json(result))
    assert [set(item) for item in document] == [{"problem", "subject", "detail", "next"}]
    assert all(isinstance(value, str) for value in document[0].values())


def test_the_operator_group_and_address_types_are_those_of_the_tofu_root():
    """P1: one fact, two homes (#138 rule 14)."""
    locals_block = (EXTERNAL / "cloudflare.tf").read_text()
    group = re.search(r'operator_group_name\s*=\s*"([^"]+)"', locals_block)
    types = re.search(r"address_record_types\s*=\s*\[([^\]]*)\]", locals_block)
    assert group
    assert types
    assert group.group(1) == host_check.OPERATOR_GROUP_NAME
    assert re.findall(r'"(\w+)"', types.group(1)) == list(host_check.ADDRESS_RECORD_TYPES)


PROBE_FAULTS = (Problem.ANSWER_WRONG, Problem.UNREACHABLE)
TEAM_LOGIN = "https://team.cloudflareaccess.com/cdn-cgi/access/login/x"


def probe_findings(host: catalog.Host, outcome) -> list[tuple[str, str, str]]:
    """What the probe alone says about one host whose probed name answers `outcome`."""
    current = snapshot(tunnel_record("*" if host.name == "*" else host.name))
    names = host_check.names_to_probe([host], current)
    check = compared([host], current, {name: outcome for name in names})
    return [
        (f.problem.value, f.subject, f.detail) for f in check.findings if f.problem in PROBE_FAULTS
    ]


def redirect(location: str, status: int = 302, cf_ray: bool = True, challenge: bool = False):
    return Answer(status, location, cf_ray, challenge)


FAILED = Unreachable(FailureKind.TIMEOUT)
ANSWERS = {
    "access-redirect": redirect(TEAM_LOGIN),
    "200": Answer(200, None, True, False),
    "404": Answer(404, None, True, False),
    "502": Answer(502, None, True, False),
    "challenge": Answer(403, None, True, True),
    "no-cf-ray": Answer(200, None, False, False),
    "redirect-without-cf-ray": redirect(TEAM_LOGIN, cf_ray=False),
    "redirect-with-challenge": redirect(TEAM_LOGIN, challenge=True),
    "failed": FAILED,
}
# None: the probe adds nothing. Open hosts must not redirect to Access; the wildcard must.
NOT_REACHED = (Problem.UNREACHABLE, "request failed: the request timed out")
NO_CF_RAY = (Problem.ANSWER_WRONG, "status 200, no cf-ray")
REDIRECT_NO_CF_RAY = (Problem.ANSWER_WRONG, "status 302, no cf-ray")
OPEN_VERDICTS = {
    "access-redirect": (Problem.ANSWER_WRONG, "status 302, redirects to Access"),
    **dict.fromkeys(("200", "404", "502", "challenge")),
    "no-cf-ray": NO_CF_RAY,
    "redirect-without-cf-ray": REDIRECT_NO_CF_RAY,
    "redirect-with-challenge": None,
    "failed": NOT_REACHED,
}
PROTECTED_VERDICTS = {
    "access-redirect": None,
    **{
        status: (Problem.ANSWER_WRONG, f"status {status}, not an Access redirect")
        for status in ("200", "404", "502")
    },
    "challenge": (Problem.ANSWER_WRONG, "status 403, a challenge, not an Access redirect"),
    "no-cf-ray": NO_CF_RAY,
    "redirect-without-cf-ray": REDIRECT_NO_CF_RAY,
    "redirect-with-challenge": (
        Problem.ANSWER_WRONG,
        "status 302, a challenge, not an Access redirect",
    ),
    "failed": NOT_REACHED,
}
ASKED_AT_PROBE_NAME = f"asked at edge-host-check.{ZONE}: "


@pytest.mark.parametrize("answer", ANSWERS)
@pytest.mark.parametrize(
    ("host", "verdicts", "where"),
    [
        pytest.param(public("www"), OPEN_VERDICTS, "", id="public"),
        pytest.param(bypass("www"), OPEN_VERDICTS, "", id="bypass"),
        pytest.param(protected_wildcard(), PROTECTED_VERDICTS, ASKED_AT_PROBE_NAME, id="protected"),
    ],
)
def test_the_answer_is_judged_against_the_declared_exposure(host, verdicts, where, answer):
    """PB4: one finding per failed probe, the declared FQDN as subject, its detail in full."""
    expected = verdicts[answer]
    wanted = [] if expected is None else [(expected[0].value, host.fqdn, where + expected[1])]
    assert probe_findings(host, ANSWERS[answer]) == wanted


ACCESS_PATH_FORMS = [
    ("https://{host}/cdn-cgi/access/login", True),
    ("/cdn-cgi/access/login", True),
    ("https://{host}:443/cdn-cgi/access/authorized", True),
    ("https://{host}./cdn-cgi/access/login", True),
    ("https://{HOST}:443/cdn-cgi/access/login", True),
    ("https://team.cloudflareaccess.com./x", True),
    ("https://TEAM.cloudflareaccess.com./x", True),
    # A dot segment is never canonical, whatever it would resolve to.
    ("/other/../cdn-cgi/access/login", False),
    ("https://{host}/other/../cdn-cgi/access/login", False),
    ("//{host}/other/../cdn-cgi/access/login", False),
    # Parser differentials (Codex round 3): none of these is a canonical form.
    ("https://evil.example\\@team.cloudflareaccess.com/", False),
    ("//evil.example\\@{host}/cdn-cgi/access/login", False),
    ("///evil.example/../cdn-cgi/access/login", False),
    ("https:///evil.example/../cdn-cgi/access/login", False),
    ("https://team.cloudflareaccess.com/cdn-cgi/access/login/x", True),
    ("/cdn-cgi/access/..\\..\\public", False),
    ("/cdn-cgi/access/..%2fpublic", False),
    ("/cdn-cgi/access/x%5Cy", False),
    ("/x%2f/../cdn-cgi/access/login", False),
    ("/x%5C/../cdn-cgi/access/login", False),
    ("/x\\/../cdn-cgi/access/login", False),
    ("/cdn-cgi/access/..%%32F..%%32Fpublic", False),
    ("https://team.cloudflareaccess.com/cdn-cgi/access/login/{host}?kid=k&redirect_url=%2F", True),
    ("/cdn-cgi/access/../../public", False),
    ("https://{host}/cdn-cgi/access/../../public", False),
    ("//{host}/cdn-cgi/access/../../public", False),
    ("https://{host}/cdn-cgi/access/%2e%2e/%2e%2e/public", False),
    ("//{host}/cdn-cgi/access/%2E%2E/public", False),
    ("https://x@team.cloudflareaccess.com.evil/", False),
    ("https://{host}:bad/cdn-cgi/access/login", False),
    ("https://team.cloudflareaccess.com:bad/", False),
    ("https://{host}:8443/cdn-cgi/access/login", False),
    ("http://team.cloudflareaccess.com/x", False),
    ("//evil.example/cdn-cgi/access/", False),
    ("https://evil.example/cdn-cgi/access/", False),
    ("https://[::1/cdn-cgi/access/", False),
    # Authority characters, each refused on its own (Opus O4-1, Grok G4-1).
    ("https://evil.example\\team.cloudflareaccess.com/", False),
    ("https://evil.example\\.cloudflareaccess.com/x", False),
    ("https://x@team.cloudflareaccess.com/", False),
    ("https://evil\\.cloudflareaccess.com/x", False),
    # The query and fragment are never inspected, newlines included; the path stays strict.
    ("/cdn-cgi/access?x=\nfoo", True),
    ("/cdn-cgi/access#\nfoo", True),
    ("https://team.cloudflareaccess.com/cdn-cgi/access/login?x=\nfoo", True),
    ("/cdn-cgi/acc\ness", False),
    ("", False),
]


@pytest.mark.parametrize(("location", "is_access"), ACCESS_PATH_FORMS)
@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize("protected", [False, True], ids=["open-host", "protected-wildcard"])
def test_only_a_real_access_redirect_counts_as_one(location, is_access, status, protected):
    """PB4: open hosts fail on it, the wildcard needs it; the redirect is only classified."""
    host = protected_wildcard() if protected else public("www")
    probed = f"edge-host-check.{ZONE}" if protected else host.fqdn
    answer = redirect(location.format(host=probed, HOST=probed.upper()), status)
    wrong = bool(probe_findings(host, answer))
    assert wrong is (not is_access if protected else is_access)


@pytest.mark.parametrize("status", [200, 404, 502])
def test_a_location_on_a_non_redirect_status_is_not_access(status):
    """PB4."""
    assert probe_findings(public("www"), redirect(TEAM_LOGIN, status)) == []


class FakeCloudflare:
    def __init__(self, current: Snapshot) -> None:
        self.current = current

    def read(self, _zone: str, _tunnel_names: object) -> Snapshot:
        return self.current


class CountingProber:
    def __init__(self, outcome=ANSWERS["200"], wildcard_outcome=ACCESS_ANSWER) -> None:
        self.outcome, self.wildcard_outcome = outcome, wildcard_outcome
        self.asked: list[str] = []

    def ask(self, name: str):
        self.asked.append(name)
        return self.wildcard_outcome if name.startswith(catalog.PROBE_NAME) else self.outcome


def catalog_document(*hosts: dict, enabled: bool = True) -> dict:
    run = {} if enabled else {"run": {"enabled": False}}
    return {"cloudflare": {"zone": ZONE}, "services": {"svc": {"hosts": list(hosts), **run}}}


def host_entry(name: str, exposure: str) -> dict:
    return {"name": name, "exposure": exposure, "reason": "test"}


@pytest.mark.parametrize(
    ("records", "document", "asked"),
    [
        pytest.param([], catalog_document(host_entry("www", "public")), [], id="no-record"),
        pytest.param(
            [tunnel_record("www", content=ZONE)],
            catalog_document(host_entry("www", "public")),
            [fqdn("www")],
            id="record-wrong-host",
        ),
        pytest.param(
            [tunnel_record("www")],
            catalog_document(host_entry("www", "public"), enabled=False),
            [],
            id="disabled-entry",
        ),
        pytest.param(
            [tunnel_record("*"), tunnel_record("stray")],
            catalog_document({"name": "*", "exposure": "protected"}),
            [f"edge-host-check.{ZONE}"],
            id="wildcard-only-at-the-probe-name",
        ),
    ],
)
def test_only_declared_hosts_with_a_record_are_asked(records, document, asked):
    """PB5."""
    prober = CountingProber()
    host_check.check_hosts(
        document, FakeCloudflare(snapshot(*records, apps=(operator_app(),))), prober
    )
    assert prober.asked == asked


@pytest.mark.parametrize("with_public_host", [True, False], ids=["public-host", "wildcard-only"])
def test_while_access_is_off_the_wildcard_is_not_asked_at_all(with_public_host):
    """PB6: no request and no finding for `*`; public hosts are still asked and judged."""
    entries = [{"name": "*", "exposure": "protected"}]
    records = [tunnel_record("*")]
    if with_public_host:
        entries.append(host_entry("@", "public"))
        records.append(tunnel_record("@"))
    prober = CountingProber(outcome=FAILED, wildcard_outcome=ANSWERS["200"])
    check = host_check.check_hosts(
        catalog_document(*entries), FakeCloudflare(snapshot(*records, apps=None)), prober
    )
    found_here = [(f.problem.value, f.subject) for f in check.findings]
    assert prober.asked == ([ZONE] if with_public_host else [])
    assert found_here == [("access-not-enabled", "account")] + (
        [("unreachable", ZONE)] if with_public_host else []
    )


def test_only_public_hosts_with_access_off_is_a_note_and_the_hosts_are_asked():
    """PB6."""
    prober = CountingProber()
    check = host_check.check_hosts(
        catalog_document(host_entry("www", "public")),
        FakeCloudflare(snapshot(tunnel_record("www"), apps=None)),
        prober,
    )
    assert check.findings == ()
    assert check.access_unused
    assert prober.asked == [fqdn("www")]


def test_nothing_response_controlled_is_quoted_in_a_finding():
    """PB10: a hostile Location is never repeated, in text or JSON."""
    hostile = "https://x/\r\n\x1b[31m" + "sentinel-" * 200
    check = compared(
        [protected_wildcard()],
        snapshot(tunnel_record("*")),
        {f"edge-host-check.{ZONE}": redirect(hostile)},
    )
    assert [f.problem for f in check.findings if f.problem in PROBE_FAULTS] == [
        Problem.ANSWER_WRONG
    ]
    assert "sentinel" not in host_check.as_text(check) + host_check.as_json(check)


def test_the_probe_problems_sort_after_every_app_and_record_problem():
    """PB11."""
    stray_app = app("stray." + ZONE, policies=(BYPASS_POLICY,))
    check = compared(
        [public("www")],
        snapshot(tunnel_record("www"), tunnel_record("stray"), apps=(stray_app,)),
        {fqdn("www"): ACCESS_ANSWER},
    )
    assert [f.problem for f in check.findings] == [
        Problem.UNDECLARED_RECORD,
        Problem.UNDECLARED_APP,
        Problem.ANSWER_WRONG,
    ]
    assert [p.value for p in list(Problem)[-2:]] == ["answer-wrong", "unreachable"]
