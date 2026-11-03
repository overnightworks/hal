"""The ingress barrier (#61 proof a): rendering, atomic write, verification and the git rules.
Nothing here starts a container; the checkout is always a `tmp_path`. Sockets appear only in the
last section, where `http_fetch` meets a real local TCP server that misbehaves."""

import http.client
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest
import yaml

from hal.stack import barrier, catalog, switches

REPOSITORY = Path(__file__).resolve().parents[1]
ADDRESS = "127.0.0.1:8081"
NOT_FOUND = barrier.Answer(404, b"404 page not found\n", "probe")  # the barrier of unit `probe`
PLAIN_NOT_FOUND = barrier.Answer(404, b"404 page not found\n")  # Traefik's ordinary no-route answer
WHOAMI = barrier.Answer(200, b"Hostname: abc\n")
TIME_ALLOWED = 0.3  # cut-off tests: slowness only makes them fail sooner
GENEROUS_TIME = 10.0  # success tests return as soon as the answer is in
HOST = "hello.probe.invalid"
Script = Callable[[socket.socket, threading.Event], None]
KEYCLOAK_RULE = "Host(`auth.probe.invalid`) && PathPrefix(`/realms`)"


def config() -> dict:
    return {
        "services": {
            "traefik": {"environment": {"EDGE_DOMAIN": "probe.invalid"}},
            "keycloak": {
                "labels": {
                    "traefik.enable": "true",
                    "edge.name": "auth",
                    "traefik.http.routers.auth.rule": KEYCLOAK_RULE,
                }
            },
            "keycloak-db": {},
            "hello": {"labels": {"traefik.enable": "true", "edge.name": "hello"}},
            "hello-twin": {"labels": {"traefik.enable": "true", "edge.name": "hello"}},
            "internal": {"labels": {"traefik.enable": "false", "edge.name": "internal"}},
            "stray": {"labels": {"traefik.enable": "true", "edge.name": "Not_Valid"}},
            "unnamed": {"labels": {"traefik.enable": "true"}},
            "talker": {
                "labels": {"traefik.enable": "true", "edge.name": "talk", "edge.alias": "speak"}
            },
            "bad-alias": {
                "labels": {"traefik.enable": "true", "edge.name": "ok", "edge.alias": "Bad_Alias"}
            },
            "bad-name-alias": {
                "labels": {"traefik.enable": "true", "edge.name": "Bad", "edge.alias": "fine"}
            },
        }
    }


class Clock:
    """Time that only moves when the verifier sleeps, so a 15 s wait costs nothing."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.now += seconds


def verifier(fetch: Callable[..., barrier.Answer]) -> barrier.Verifier:
    clock = Clock()
    return barrier.Verifier(fetch=fetch, clock=clock, sleep=clock.sleep)


def refused(
    _address: str, _host: str, _seconds: float, _clock: Callable[[], float]
) -> barrier.Answer:
    raise ConnectionRefusedError


def garbled(
    _address: str, _host: str, _seconds: float, _clock: Callable[[], float]
) -> barrier.Answer:
    raise http.client.IncompleteRead(b"404 page")


@pytest.fixture
def checkout(tmp_path: Path) -> Path:
    (tmp_path / "dynamic").mkdir()
    (tmp_path / "traefik.yml").write_text(f'entryPoints:\n  edge:\n    address: "{ADDRESS}"\n')
    return tmp_path


def probe_unit(*hosts: str, enabled: bool = True) -> catalog.Unit:
    return catalog.Unit("probe", enabled=enabled, setup=None, hosts=hosts)


def barrier_of(
    checkout: Path, *services: str, hosts: tuple[str, ...] = (), fetch=lambda *_: NOT_FOUND
) -> barrier.Barrier:
    return barrier.Barrier.of_unit(
        config(), services, checkout, probe_unit(*hosts), verifier(fetch)
    )


def parsed(checkout: Path) -> dict:
    return yaml.safe_load((checkout / "dynamic" / "switch-probe.yml").read_text())


def test_one_router_per_routed_host_on_the_edge_entrypoint_only(checkout):
    """#61 rule 1 / proof a: one router per routed host, on `edge` only."""
    barrier_of(checkout, "keycloak", "hello", "hello-twin", "keycloak-db").close()

    document = parsed(checkout)

    assert sorted(document["http"]["routers"]) == ["switch-probe-auth", "switch-probe-hello"]
    for name, router in document["http"]["routers"].items():
        assert router["entryPoints"] == ["edge"]
        assert router["priority"] == 1_000_000
        assert router["service"] == "switch-probe-deny"
        assert router["middlewares"] == ["switch-probe-mark"]
        host = name.removeprefix("switch-probe-")
        assert router["rule"] == f'Host(`{host}.{{{{ env "EDGE_DOMAIN" }}}}`)'


def test_the_deny_service_sends_the_request_back_to_traefik_without_its_host(checkout):
    """#61 rule 1 / proof a: the deny service sits in the file and drops the Host."""
    barrier_of(checkout, "hello").close()

    deny = parsed(checkout)["http"]["services"]["switch-probe-deny"]["loadBalancer"]

    assert deny["passHostHeader"] is False
    assert deny["servers"] == [{"url": f"http://{ADDRESS}"}]


def test_the_barrier_marks_its_answer_with_the_unit_by_a_middleware_in_the_same_file(checkout):
    """#61 rule 1 / proof a: the same-file middleware adds `X-Edge-Barrier: <unit>`."""
    barrier_of(checkout, "hello").close()

    mark = parsed(checkout)["http"]["middlewares"]["switch-probe-mark"]

    assert mark == {"headers": {"customResponseHeaders": {"X-Edge-Barrier": "probe"}}}


def test_an_explicit_label_router_is_barred_by_its_host_alone(checkout):
    """#61 rule 1 / proof a: keycloak's PathPrefix label router is barred by Host alone."""
    barrier_of(checkout, "keycloak").close()

    rule = parsed(checkout)["http"]["routers"]["switch-probe-auth"]["rule"]

    assert "PathPrefix" not in rule
    assert rule.startswith("Host(`auth.")


@pytest.mark.parametrize("spelling", ["1", "t", "T", "TRUE", "True"])
def test_every_spelling_traefik_reads_as_true_gets_a_barrier(checkout, spelling):
    """#61 rule 1: Traefik parses `traefik.enable` with Go's ParseBool, and so does the barrier."""
    services = {"labels": {"traefik.enable": spelling, "edge.name": "hello"}}
    ingress = barrier.Barrier.of_unit(
        {"services": {**config()["services"], "spelled": services}},
        ["spelled"],
        checkout,
        probe_unit(),
        verifier(lambda *_: NOT_FOUND),
    )

    ingress.close()

    assert "switch-probe-hello" in parsed(checkout)["http"]["routers"]


@pytest.mark.parametrize("service", ["keycloak-db", "internal", "stray", "unnamed"])
def test_a_unit_without_a_routed_host_gets_no_file_and_is_never_asked(checkout, service):
    """#61 rule 1 / proof a: no routed service, no file and no request."""
    ingress = barrier_of(checkout, service, fetch=refused)

    ingress.close()
    ingress.open()

    assert not list((checkout / "dynamic").iterdir())


def test_the_file_is_flat_and_leaves_no_temporary_name(checkout):
    """#61 rule 1 / proof a: the atomic write leaves no `.tmp`."""
    barrier_of(checkout, "hello").close()

    assert [path.name for path in (checkout / "dynamic").iterdir()] == ["switch-probe.yml"]


def test_closing_twice_renders_the_same_file(checkout):
    """#61 rule 3 / proof a: a second close renders the same file."""
    ingress = barrier_of(checkout, "hello")
    ingress.close()
    first = ingress.path.read_text()

    ingress.close()

    assert ingress.path.read_text() == first


def test_opening_removes_the_file_and_is_idempotent(checkout):
    """#61 rule 4 / proof a: removal is idempotent."""
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: WHOAMI)
    ingress.path.write_text("leftover")

    ingress.open()
    ingress.open()

    assert not ingress.present()


def test_a_write_that_fails_leaves_no_temporary_file(checkout):
    """#61 rule 1 / proof a: a failed write leaves no `.tmp`."""
    ingress = barrier_of(checkout, "hello")
    ingress.path.mkdir()  # the rename onto a directory fails

    with pytest.raises(barrier.BarrierError, match=r"cannot write switch-probe\.yml"):
        ingress.close()

    assert not ingress.path.with_name("switch-probe.yml.tmp").exists()


def test_the_barrier_is_verified_for_every_host_at_the_address_of_traefik_yml(checkout):
    """#61 rule 3 / proof a: every host is asked at the address of traefik.yml."""
    asked = []

    def fetch(
        address: str, host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        asked.append((address, host))
        return NOT_FOUND

    barrier_of(checkout, "keycloak", "hello", fetch=fetch).close()

    assert asked == [(ADDRESS, "auth.probe.invalid"), (ADDRESS, "hello.probe.invalid")]


def test_a_barrier_that_answers_404_only_after_a_while_is_verified(checkout):
    """#61 rule 3 / proof a: the verification polls until Traefik answers 404."""
    answers = iter([WHOAMI, refused, garbled, NOT_FOUND])

    def fetch(
        address: str, host: str, seconds: float, clock: Callable[[], float]
    ) -> barrier.Answer:
        answer = next(answers)
        return answer(address, host, seconds, clock) if callable(answer) else answer

    barrier_of(checkout, "hello", fetch=fetch).close()


@pytest.mark.parametrize(
    "fetch", [lambda *_: WHOAMI, refused, garbled], ids=["answers 200", "refused", "garbled"]
)
def test_a_barrier_traefik_does_not_answer_404_for_is_not_verified_after_15_seconds(
    checkout, fetch
):
    """#61 rule 3 / proof a: 200, refused or a broken answer for 15 s is not verified."""
    ingress = barrier_of(checkout, "hello", fetch=fetch)

    with pytest.raises(barrier.BarrierError) as failure:
        ingress.close()

    assert str(failure.value) == (
        "the barrier is written but Traefik did not answer the barrier's 404 "
        "(X-Edge-Barrier: probe) for hello.probe.invalid within 15 s"
    )
    assert ingress.present()


def test_a_404_with_another_body_is_no_proof_of_the_barrier(checkout):
    """#61 rule 3 / proof a: only Traefik's own 404 body proves the barrier."""
    other = barrier.Answer(404, b'{"error":"not found"}', "probe")
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: other)

    with pytest.raises(barrier.BarrierError):
        ingress.close()


def test_a_marked_answer_with_another_status_is_no_proof_of_the_barrier(checkout):
    """#61 rule 3 / proof a: only status 404 proves the barrier, mark and body notwithstanding."""
    other = barrier.Answer(200, PLAIN_NOT_FOUND.body, "probe")
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: other)

    with pytest.raises(barrier.BarrierError):
        ingress.close()


def test_a_plain_404_without_the_mark_is_no_proof_of_the_barrier(checkout):
    """#61 rule 3 / proof a: Traefik's no-route 404 is what a rejected file leaves, not proof."""
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: PLAIN_NOT_FOUND)

    with pytest.raises(barrier.BarrierError):
        ingress.close()


def test_the_mark_of_another_unit_is_no_proof_of_this_barrier(checkout):
    """#61 rule 3 / proof a: the mark must name this unit."""
    other = barrier.Answer(404, PLAIN_NOT_FOUND.body, "other")
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: other)

    with pytest.raises(barrier.BarrierError):
        ingress.close()


def test_opening_is_verified_only_once_the_host_stops_answering_the_barriers_404(checkout):
    """#61 rule 4 / proof a: opening is verified once the mark is gone."""
    ingress = barrier_of(checkout, "hello", fetch=lambda *_: NOT_FOUND)

    with pytest.raises(barrier.BarrierError, match=r"did not open hello\.probe\.invalid"):
        ingress.open()


@pytest.mark.parametrize(
    "answer",
    [PLAIN_NOT_FOUND, WHOAMI, barrier.Answer(302, b"")],
    ids=["a path-prefixed router's plain 404", "whoami", "a redirect"],
)
def test_opening_is_verified_by_any_answer_without_the_mark(checkout, answer):
    """#61 rule 4 / proof a: keycloak's `auth` answers `/` with a plain 404 once opened."""
    barrier_of(checkout, "keycloak", fetch=lambda *_: answer).open()


def test_the_host_domain_is_the_one_compose_gives_traefik():
    """#61 rule 1 / proof a: the domain is the one Compose gives traefik."""
    broken = {"services": {"traefik": {}, **{"hello": config()["services"]["hello"]}}}

    unit = probe_unit()

    with pytest.raises(barrier.BarrierError, match="no EDGE_DOMAIN"):
        barrier.Barrier.of_unit(broken, ["hello"], REPOSITORY, unit)


def test_the_real_traefik_yml_yields_an_address_with_a_host_and_a_port():
    host, _, port = barrier.edge_address(REPOSITORY).rpartition(":")

    assert host
    assert port.isdigit()


def test_the_barrier_names_are_ignored_by_git_but_the_directory_stays_tracked():
    """#61 rule 2 / proof a: `switch-*` and its `.tmp` are ignored; `.gitkeep` stays."""
    for name in ("switch-keycloak.yml", "switch-keycloak.yml.tmp"):
        ignored = subprocess.run(
            ["git", "check-ignore", "-q", f"dynamic/{name}"], cwd=REPOSITORY, check=False
        )
        assert ignored.returncode == 0, name
    tracked = subprocess.run(
        ["git", "ls-files", "--error-unmatch", "dynamic/.gitkeep"],
        cwd=REPOSITORY, capture_output=True, check=False,
    )  # fmt: skip
    assert tracked.returncode == 0
    hand_written = subprocess.run(
        ["git", "check-ignore", "-q", "dynamic/routes.yml"], cwd=REPOSITORY, check=False
    )
    assert hand_written.returncode == 1


def test_no_request_is_given_more_time_than_the_15_seconds_leave(checkout):
    """#61 rule 3: the verification ends within 15 s, whatever one request would take."""
    allowed = []
    clock = Clock()

    def slow(
        _address: str, _host: str, seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        allowed.append(seconds)
        clock.now += seconds  # a request that uses all the time it is given
        raise TimeoutError

    ingress = barrier.Barrier.of_unit(
        config(),
        ["hello"],
        checkout,
        probe_unit(),
        barrier.Verifier(fetch=slow, clock=clock, sleep=clock.sleep),
    )

    with pytest.raises(barrier.BarrierError):
        ingress.close()

    assert clock.now <= barrier.VERIFY_SECONDS + 0.5
    assert max(allowed) <= 3.0


KEYCLOAK_BARRIER = (
    "# Written by `hal stop keycloak` from ~/.local/state/hal/stopped/keycloak; "
    "removed by `hal start keycloak`. Generated, git-ignored.\n"
    """\
http:
  routers:
    switch-keycloak-auth:
      entryPoints: [edge]
      rule: Host(`auth.{{ env "EDGE_DOMAIN" }}`)
      priority: 1000000
      middlewares: [switch-keycloak-mark]
      service: switch-keycloak-deny
  middlewares:
    switch-keycloak-mark:
      headers:
        customResponseHeaders:
          X-Edge-Barrier: keycloak
  services:
    switch-keycloak-deny:
      loadBalancer:
        passHostHeader: false
        servers:
          - url: http://127.0.0.1:8081
"""
)


def asked_hosts(checkout: Path, *services: str, hosts: tuple[str, ...]) -> list[str]:
    asked = []

    def fetch(
        _address: str, host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        asked.append(host)
        return NOT_FOUND

    barrier_of(checkout, *services, hosts=hosts, fetch=fetch).close()
    return asked


def test_a_declared_host_that_keycloak_also_routes_leaves_its_barrier_byte_identical(checkout):
    """#325 B1: keycloak declares `auth` and routes `edge.name: auth`: one router, today's file."""
    asked = []

    def fetch(
        _address: str, host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        asked.append(host)
        return barrier.Answer(404, b"404 page not found\n", "keycloak")

    unit = catalog.Unit("keycloak", enabled=True, setup=None, hosts=("auth",))
    barrier.Barrier.of_unit(
        config(), ("keycloak", "keycloak-db"), checkout, unit, verifier(fetch)
    ).close()

    assert (checkout / "dynamic" / "switch-keycloak.yml").read_text() == KEYCLOAK_BARRIER
    assert asked == ["auth.probe.invalid"]


def test_the_apex_gets_a_router_on_the_bare_domain_that_no_label_can_take(checkout):
    """#325 B2: the rule is the bare domain, the proof asks the bare domain, the name is safe."""
    asked = asked_hosts(checkout, "hello", hosts=("@", "hello"))

    routers = parsed(checkout)["http"]["routers"]
    assert routers["switch-probe-_apex"]["rule"] == 'Host(`{{ env "EDGE_DOMAIN" }}`)'
    assert sorted(routers) == ["switch-probe-_apex", "switch-probe-hello"]
    assert asked == ["probe.invalid", "hello.probe.invalid"]


def test_a_routed_unit_with_an_alias_gets_a_router_for_the_alias_host_too(checkout):
    """#445 R6."""
    barrier_of(checkout, "talker").close()

    assert sorted(parsed(checkout)["http"]["routers"]) == [
        "switch-probe-speak",
        "switch-probe-talk",
    ]


def test_an_alias_the_provider_would_not_route_gets_no_router(checkout):
    """#445 R6."""
    barrier_of(checkout, "bad-alias", "bad-name-alias", "hello").close()

    assert sorted(parsed(checkout)["http"]["routers"]) == ["switch-probe-hello", "switch-probe-ok"]


def test_a_declared_host_without_a_routed_service_gets_a_barrier_of_its_own(checkout):
    """#325 B2/B4: a unit that routes nothing but declares the apex is still barred."""
    ingress = barrier_of(checkout, "keycloak-db", hosts=("@",), fetch=refused)

    assert ingress.names == ("@",)
    assert ingress.hosts == ("probe.invalid",)


def test_a_routed_name_no_declared_host_names_stays_covered(checkout):
    """#325 B3: the union keeps `hello`, which the catalog does not list."""
    barrier_of(checkout, "hello", hosts=("@",)).close()

    assert sorted(parsed(checkout)["http"]["routers"]) == [
        "switch-probe-_apex",
        "switch-probe-hello",
    ]


def test_a_wildcard_line_adds_no_router_of_its_own(checkout):
    """#325: a `*` name has no `Host` rule; the services it reaches are covered by `edge.name`."""
    barrier_of(checkout, "hello", hosts=("*",)).close()

    assert sorted(parsed(checkout)["http"]["routers"]) == ["switch-probe-hello"]


# prove_active: the one owner that re-proves every active barrier (#80)

MOVED_ADDRESS = "127.0.0.1:9091"
NOW = datetime(2026, 10, 17, 12, 0, tzinfo=UTC)


@pytest.fixture
def marks(tmp_path: Path) -> switches.Switches:
    return switches.Switches(tmp_path / "state")


def proofs(
    checkout: Path,
    marks: switches.Switches,
    fetch=lambda *_: NOT_FOUND,
    hosts: Mapping[str, tuple[str, ...]] = MappingProxyType({}),
    enabled: bool = True,
    **units: tuple[str, ...],
) -> Iterator[barrier.ActiveProof]:
    return barrier.prove_active(
        [catalog.Unit(key, enabled=enabled, setup=None, hosts=hosts.get(key, ())) for key in units],
        units,
        config(),
        marks,
        checkout,
        verifier(fetch),
    )


def test_a_switched_off_unit_with_a_routed_host_has_its_barrier_proven(checkout, marks):
    """#80 rule 1: the barrier is written and proven, and the unit's outcome is proven."""
    marks.record("probe", NOW)

    assert list(proofs(checkout, marks, probe=("hello",))) == [barrier.Proven("probe")]
    assert parsed(checkout)["http"]["routers"]["switch-probe-hello"]


def test_a_switched_off_unit_with_a_disabled_apex_has_the_apex_barrier_proven_again(
    checkout, marks
):
    """#325 B8: `hal apply --local` re-proves through here; a disabled unit counts."""
    marks.record("probe", NOW)
    asked = []

    def fetch(
        _address: str, host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        asked.append(host)
        return NOT_FOUND

    outcome = list(
        proofs(checkout, marks, fetch=fetch, hosts={"probe": ("@",)}, enabled=False, probe=())
    )

    assert outcome == [barrier.Proven("probe")]
    assert asked == ["probe.invalid"]


def test_a_switched_off_unit_without_a_routed_host_has_no_host_and_no_file(checkout, marks):
    """#80 rule 1: no host behind Traefik is its own outcome, never asked over HTTP."""
    marks.record("probe", NOW)

    outcome = list(proofs(checkout, marks, fetch=refused, probe=("keycloak-db",)))

    assert outcome == [barrier.NoHost("probe")]
    assert not (checkout / "dynamic" / "switch-probe.yml").exists()


def test_a_barrier_traefik_does_not_answer_for_is_unproven_with_its_line(checkout, marks):
    """#80 rule 1: the failure carries the one line of the proof that failed."""
    marks.record("probe", NOW)

    (outcome,) = proofs(checkout, marks, fetch=lambda *_: PLAIN_NOT_FOUND, probe=("hello",))

    assert outcome == barrier.Unproven(
        "probe",
        f"the barrier is written but Traefik did not answer the barrier's 404 "
        f"({barrier.MARK_HEADER}: probe) for {HOST} within 15 s",
    )


def test_a_moved_edge_address_is_rendered_into_the_barrier_and_proven_there(checkout, marks):
    """#80 rule 1: re-render and prove, at the edge address traefik.yml gives now."""
    marks.record("probe", NOW)
    barrier_of(checkout, "hello").close()
    (checkout / "traefik.yml").write_text(f"entryPoints:\n  edge:\n    address: {MOVED_ADDRESS}\n")
    asked = []

    def fetch(
        address: str, _host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        asked.append(address)
        return NOT_FOUND

    assert list(proofs(checkout, marks, fetch=fetch, probe=("hello",))) == [barrier.Proven("probe")]
    deny = parsed(checkout)["http"]["services"]["switch-probe-deny"]["loadBalancer"]
    assert deny["servers"] == [{"url": f"http://{MOVED_ADDRESS}"}]
    assert asked == [MOVED_ADDRESS]


@pytest.mark.parametrize(
    ("marked", "standing", "active"),
    [(True, False, True), (False, True, True), (False, False, False)],
    ids=["marker only", "barrier a stop left", "neither"],
)
def test_a_barrier_is_active_by_its_marker_or_by_a_barrier_left_standing(
    checkout, marks, marked, standing, active
):
    """#80 rule 2: switched off means the marker or the barrier a stop left standing."""
    if marked:
        marks.record("probe", NOW)
    if standing:
        barrier_of(checkout, "hello").close()

    outcome = list(proofs(checkout, marks, probe=("hello",)))

    assert outcome == ([barrier.Proven("probe")] if active else [])
    assert (checkout / "dynamic" / "switch-probe.yml").exists() is active


def test_outcomes_come_one_by_one_so_a_caller_that_stops_leaves_the_next_untouched(checkout, marks):
    """#80 rule 1: each active barrier has its own outcome, yielded once its proof ends."""
    marks.record("hello", NOW)
    marks.record("auth", NOW)

    def only_auth_is_barred(
        _address: str, host: str, _seconds: float, _clock: Callable[[], float]
    ) -> barrier.Answer:
        return (
            barrier.Answer(404, b"404 page not found\n", "auth")
            if host.startswith("auth.")
            else WHOAMI
        )

    outcomes = proofs(checkout, marks, only_auth_is_barred, hello=("hello",), auth=("keycloak",))

    assert isinstance(next(outcomes), barrier.Unproven)
    assert not (checkout / "dynamic" / "switch-auth.yml").exists()
    assert list(outcomes) == [barrier.Proven("auth")]


@pytest.fixture
def serve() -> Iterator[Callable[[Script], str]]:
    """Start a server that runs `script` on its first connection; teardown ends and joins it."""
    server = socket.create_server(("127.0.0.1", 0))
    ended = threading.Event()
    workers: list[threading.Thread] = []

    def start(script: Script) -> str:
        def work() -> None:
            connection, _ = server.accept()
            with connection:
                script(connection, ended)

        workers.append(threading.Thread(target=work, daemon=True))
        workers[-1].start()
        return f"127.0.0.1:{server.getsockname()[1]}"

    yield start
    ended.set()
    # shutdown wakes an accept still waiting, which fails and ends its worker
    server.shutdown(socket.SHUT_RDWR)
    server.close()
    for worker in workers:
        worker.join(timeout=5)
        assert not worker.is_alive()


class TickingClock:
    """Every look at the clock costs 0.1 s, so a deadline passes after a few reads however fast
    the bytes arrive."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 0.1
        return self.now


def barely_buffered(address: tuple[str, int], seconds: float) -> socket.socket:
    """Connect with the smallest receive buffer, so a read never returns more than a few KB and
    the deadline, not the parser's line limit, ends the read."""
    opened = socket.socket()
    opened.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1)
    opened.settimeout(seconds)
    opened.connect(address)
    return opened


def flood(head: bytes) -> Script:
    """Send `head`, then bytes for as long as the client takes them; the send blocks while the
    client does not read and fails once the client has closed."""

    def script(connection: socket.socket, ended: threading.Event) -> None:
        connection.recv(4096)
        try:
            connection.sendall(head)
            while not ended.is_set():
                connection.sendall(b"x" * 64)
        except OSError:
            return

    return script


def test_headers_that_keep_coming_are_cut_off_at_the_time_allowed(serve):
    """#61 rule 3: endless headers cannot hold the stop past its deadline."""
    address = serve(flood(b"HTTP/1.1 200 OK\r\nX: "))

    clock = TickingClock()
    with pytest.raises(OSError):
        barrier.http_fetch(address, HOST, TIME_ALLOWED, clock, barely_buffered)


def test_a_body_that_stalls_is_cut_off_at_the_time_allowed(serve):
    """#61 rule 3: a marked answer whose body stops short cannot hold the stop either."""

    def stalls(connection: socket.socket, ended: threading.Event) -> None:
        connection.recv(4096)
        connection.sendall(
            b"HTTP/1.1 404 Not Found\r\nX-Edge-Barrier: probe\r\nContent-Length: 1000000\r\n\r\nabc"
        )
        ended.wait()

    address = serve(stalls)

    with pytest.raises(OSError):
        barrier.http_fetch(address, HOST, TIME_ALLOWED, lambda: 0.0)


def test_chunk_framing_that_keeps_coming_is_cut_off_at_the_time_allowed(serve):
    """#61 rule 3: the framing of a chunked body is read within the deadline too."""
    head = b"HTTP/1.1 404 Not Found\r\nX-Edge-Barrier: probe\r\nTransfer-Encoding: chunked\r\n\r\n"
    address = serve(flood(head))

    clock = TickingClock()
    with pytest.raises(OSError):
        barrier.http_fetch(address, HOST, TIME_ALLOWED, clock, barely_buffered)


def test_a_time_allowed_used_up_by_connecting_sends_no_request(serve):
    """#61 rule 3: what connecting used up is gone from the budget, so nothing is sent."""
    heard: list[bytes] = []
    done = threading.Event()

    def listens(connection: socket.socket, _ended: threading.Event) -> None:
        heard.append(connection.recv(4096))
        done.set()

    address = serve(listens)
    clock = TickingClock()

    def connecting_takes_the_whole_time(*args) -> socket.socket:
        opened = socket.create_connection(*args)
        clock.now += GENEROUS_TIME * 2
        return opened

    with pytest.raises(OSError):
        barrier.http_fetch(address, HOST, GENEROUS_TIME, clock, connecting_takes_the_whole_time)

    assert done.wait(timeout=5)
    assert heard == [b""]


def test_an_unmarked_answer_is_complete_once_its_headers_are_in(serve):
    """#61 rule 4: a streaming 200 whose body never comes still shows the mark is absent."""

    def headers_only(connection: socket.socket, ended: threading.Event) -> None:
        connection.recv(4096)
        connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\n\r\n")
        ended.wait()

    answer = barrier.http_fetch(serve(headers_only), HOST, GENEROUS_TIME, time.monotonic)

    assert answer.status == 200
    assert answer.is_unmarked


def test_a_marked_answer_carries_its_status_body_and_mark(serve):
    """#61 rule 3: the barrier's own answer is read whole."""

    def barrier_answer(connection: socket.socket, ended: threading.Event) -> None:
        connection.recv(4096)
        connection.sendall(
            b"HTTP/1.1 404 Not Found\r\nX-Edge-Barrier: probe\r\nContent-Length: 19\r\n\r\n"
            b"404 page not found\n"
        )
        ended.wait()

    answer = barrier.http_fetch(serve(barrier_answer), HOST, GENEROUS_TIME, time.monotonic)

    assert answer.is_barrier_of("probe")
