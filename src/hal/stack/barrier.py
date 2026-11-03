"""The ingress barrier of `hal stop`: a flat file under `dynamic/` that makes Traefik answer 404.

Traefik's file provider watches `dynamic/` but not its subdirectories, so the barrier is
`dynamic/switch-<unit>.yml`, written through a `.tmp` name the provider never reads. One router per
host the unit declares in the catalog, enabled or not, or routes, on the `edge` entrypoint only,
beats any label router by its priority and sends the request back to Traefik's own `edge`
entrypoint without its `Host`; no router matches that, so Traefik itself answers
`404 page not found`. That 404 is also Traefik's ordinary no-route
answer, so a same-file middleware marks the barrier's answer with `X-Edge-Barrier: <unit>`; only
the mark proves Traefik loaded the file. The checkout is an argument; only the CLI
entry resolves the real one.
"""

import http.client
import os
import socket
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import Any, Self

import yaml

from hal.exposure.docker import EDGE_ALIAS_LABEL, EDGE_NAME_LABEL, TRAEFIK_NAME, is_routed
from hal.stack import catalog, switches

DYNAMIC_DIRECTORY = "dynamic"
TRAEFIK_FILE = "traefik.yml"
_NOT_FOUND_BODY = b"404 page not found\n"
_NOT_FOUND = 404
_APEX_ROUTER = "_apex"  # `_` is no part of a DNS label, so no host name can take it
_DOMAIN_TEMPLATE = '{{ env "EDGE_DOMAIN" }}'
MARK_HEADER = "X-Edge-Barrier"
_PRIORITY = 1_000_000
VERIFY_SECONDS = 15.0
_POLL_SECONDS = 0.5
_REQUEST_SECONDS = 3.0
_TEMPLATE = (
    "# Written by `hal stop {unit}` from ~/.local/state/hal/stopped/{unit}; "
    "removed by `hal start {unit}`. Generated, git-ignored.\n"
    """\
http:
  routers:
{routers}  middlewares:
    switch-{unit}-mark:
      headers:
        customResponseHeaders:
          {header}: {unit}
  services:
    switch-{unit}-deny:
      loadBalancer:
        passHostHeader: false
        servers:
          - url: http://{address}
"""
)
_ROUTER = """\
    switch-{unit}-{router}:
      entryPoints: [edge]
      rule: Host(`{host}`)
      priority: {priority}
      middlewares: [switch-{unit}-mark]
      service: switch-{unit}-deny
"""


class BarrierError(Exception):
    """The barrier cannot be written, removed or proven; the message is one line."""


@dataclass(frozen=True)
class Answer:
    status: int
    body: bytes
    mark: str | None = None  # the `X-Edge-Barrier` header, None when the answer has none

    def is_barrier_of(self, unit: str) -> bool:
        return self.status == _NOT_FOUND and self.body == _NOT_FOUND_BODY and self.mark == unit

    @property
    def is_unmarked(self) -> bool:
        return self.mark is None


Fetch = Callable[
    [str, str, float, Callable[[], float]], Answer
]  # (address, Host, seconds allowed, clock) -> GET / answer

Connect = Callable[[tuple[str, int], float], socket.socket]  # (address, seconds) -> open socket


class _DeadlineSocket(socket.socket):
    """A socket whose every read, whatever http.client's parser asks for, ends at one deadline."""

    deadline: float
    clock: Callable[[], float]

    def time_left(self) -> float:
        remaining = self.deadline - self.clock()
        if remaining <= 0:
            raise TimeoutError("the answer took longer than the time allowed")
        return remaining

    def recv_into(self, buffer, nbytes=0, flags=0):
        self.settimeout(self.time_left())
        return super().recv_into(buffer, nbytes, flags)


class _DeadlineConnection(http.client.HTTPConnection):
    def __init__(self, *args, clock: Callable[[], float], connect: Connect, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.clock = clock
        self.open_socket = connect

    def connect(self) -> None:
        deadline = self.clock() + self.timeout
        opened = self.open_socket((self.host, self.port), self.timeout)
        bounded = _DeadlineSocket(fileno=opened.detach())
        bounded.clock = self.clock
        bounded.deadline = deadline
        self.sock = bounded
        bounded.settimeout(bounded.time_left())


def http_fetch(
    address: str,
    host: str,
    seconds: float,
    clock: Callable[[], float],
    connect: Connect = socket.create_connection,
) -> Answer:
    """`GET /` within `seconds` in all, connect and every read together. Only a marked answer has
    its first body bytes read, which is all the comparison with Traefik's 404 needs; the headers
    alone show that a mark is absent."""
    connection = _DeadlineConnection(address, timeout=seconds, clock=clock, connect=connect)
    try:
        connection.request("GET", "/", headers={"Host": host})
        response = connection.getresponse()
        mark = response.getheader(MARK_HEADER)
        body = response.read(len(_NOT_FOUND_BODY) + 1) if mark is not None else b""
        return Answer(response.status, body, mark)
    finally:
        connection.close()


@dataclass(frozen=True)
class Verifier:
    """How a barrier is proven: the request, and how long it is polled."""

    fetch: Fetch = http_fetch
    clock: Callable[[], float] = time.monotonic
    sleep: Callable[[float], None] = time.sleep
    seconds: float = VERIFY_SECONDS

    def unreached(
        self, address: str, hosts: Iterable[str], wanted: Callable[[Answer], bool]
    ) -> str | None:
        """The first host whose answer is not `wanted` when the time is up; None when every host
        answers as wanted."""
        deadline = self.clock() + self.seconds
        for host in hosts:
            while not self._reached(address, host, wanted, deadline):
                if self.clock() >= deadline:
                    return host
                self.sleep(_POLL_SECONDS)
        return None

    def _reached(
        self, address: str, host: str, wanted: Callable[[Answer], bool], deadline: float
    ) -> bool:
        """One request within the time the deadline leaves; a broken answer is no answer."""
        allowed = min(_REQUEST_SECONDS, deadline - self.clock())
        if allowed <= 0:
            return False
        try:
            return wanted(self.fetch(address, host, allowed, self.clock))
        except OSError, http.client.HTTPException:
            return False


def routed_names(config: Mapping[str, Any], services: Iterable[str]) -> tuple[str, ...]:
    """The `edge.name` and `edge.alias` of each service Traefik routes, as Compose resolved it,
    once each; an alias counts only beside a name the provider constraint accepts."""
    names: dict[str, None] = {}
    for service in services:
        labels = config["services"][service].get("labels", {})
        name = labels.get(EDGE_NAME_LABEL, "")
        if is_routed(labels) and TRAEFIK_NAME.fullmatch(name):
            names[name] = None
            if TRAEFIK_NAME.fullmatch(alias := labels.get(EDGE_ALIAS_LABEL, "")):
                names[alias] = None
    return tuple(names)


def _declared_names(hosts: Iterable[str]) -> tuple[str, ...]:
    """The declared names a `Host` rule can match: a wildcard line has no such rule, so its
    routed `edge.name` stands for it."""
    return tuple(name for name in hosts if name != catalog.WILDCARD)


def _domain(config: Mapping[str, Any]) -> str:
    """`EDGE_DOMAIN` as Compose resolves it for Traefik, so the barrier follows Traefik's own."""
    try:
        return config["services"]["traefik"]["environment"]["EDGE_DOMAIN"]
    except (KeyError, TypeError) as error:
        raise BarrierError("compose.yaml gives traefik no EDGE_DOMAIN") from error


def edge_address(checkout: Path) -> str:
    """`entryPoints.edge.address` of `traefik.yml`, the one owner of where Traefik listens."""
    try:
        document = yaml.safe_load((checkout / TRAEFIK_FILE).read_text())
        return document["entryPoints"]["edge"]["address"]
    except (OSError, yaml.YAMLError, KeyError, TypeError) as error:
        raise BarrierError(f"cannot read the edge address of {TRAEFIK_FILE}") from error


def _is_unmarked(answer: Answer) -> bool:
    return answer.is_unmarked


PROVEN_OVER_HTTP = Verifier()


@dataclass(frozen=True)
class Barrier:
    """The barrier of one unit; with no host behind Traefik it has no file and does nothing."""

    checkout: Path
    unit: str
    names: tuple[str, ...]
    domain: str
    verifier: Verifier = PROVEN_OVER_HTTP

    @classmethod
    def of_unit(
        cls,
        config: Mapping[str, Any],
        services: Iterable[str],
        checkout: Path,
        unit: catalog.Unit,
        verifier: Verifier = PROVEN_OVER_HTTP,
    ) -> Self:
        """The barrier over the names the unit declares and the ones Traefik routes, once each."""
        names = dict.fromkeys((*_declared_names(unit.hosts), *routed_names(config, services)))
        return cls(checkout, unit.key, tuple(names), _domain(config) if names else "", verifier)

    @classmethod
    def of_app(
        cls,
        config: Mapping[str, Any],
        checkout: Path,
        app: catalog.App,
        verifier: Verifier = PROVEN_OVER_HTTP,
    ) -> Self:
        """The barrier over the names the app declares in the catalog; its compose file is not
        read, so nothing of the release decides what is shut."""
        names = _declared_names(app.hosts)
        return cls(checkout, app.key, names, _domain(config) if names else "", verifier)

    @property
    def path(self) -> Path:
        return self.checkout / DYNAMIC_DIRECTORY / f"switch-{self.unit}.yml"

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(self._host(name) for name in self.names)

    def _host(self, name: str) -> str:
        return catalog.fqdn_of(name, self.domain)

    def close(self) -> bool:
        """Write the barrier and prove that every host answers 404 for it.

        True when the file was missing or differed, so this close repaired it.
        """
        if not self.names:
            return False
        address = edge_address(self.checkout)
        standing = self._standing()
        written = self._write(address)
        self._prove(address, barrier=True)
        return written.encode() != standing

    def _standing(self) -> bytes | None:
        """The bytes on disk; a file that cannot be read counts as a rejected one."""
        try:
            return self.path.read_bytes()
        except FileNotFoundError:
            return None
        except OSError:
            return b""

    def open(self) -> None:
        """Remove the barrier and prove that no host answers its 404 any more."""
        self._remove()
        if self.names:
            self._prove(edge_address(self.checkout), barrier=False)

    def present(self) -> bool:
        return self.path.exists()

    def _prove(self, address: str, *, barrier: bool) -> None:
        wanted = (lambda answer: answer.is_barrier_of(self.unit)) if barrier else _is_unmarked
        unreached = self.verifier.unreached(address, self.hosts, wanted)
        if unreached:
            within = f"within {self.verifier.seconds:g} s"
            if barrier:
                raise BarrierError(
                    f"the barrier is written but Traefik did not answer the barrier's 404 "
                    f"({MARK_HEADER}: {self.unit}) for {unreached} {within}"
                )
            raise BarrierError(
                f"Traefik did not open {unreached} {within} (the barrier is removed)"
            )

    def _write(self, address: str) -> str:
        routers = "".join(self._router(name) for name in self.names)
        text = _TEMPLATE.format(
            unit=self.unit, routers=routers, address=address, header=MARK_HEADER
        )
        temporary = self.path.with_name(f"{self.path.name}.tmp")
        try:
            temporary.write_text(text)
            os.replace(temporary, self.path)
        except OSError as error:
            temporary.unlink(missing_ok=True)
            raise BarrierError(f"cannot write {self.path.name} ({error.strerror})") from error
        return text

    def _router(self, name: str) -> str:
        return _ROUTER.format(
            unit=self.unit,
            router=_APEX_ROUTER if name == catalog.APEX else name,
            host=catalog.fqdn_of(name, _DOMAIN_TEMPLATE),
            priority=_PRIORITY,
        )

    def _remove(self) -> None:
        try:
            self.path.unlink(missing_ok=True)
        except OSError as error:
            raise BarrierError(f"cannot remove {self.path.name} ({error.strerror})") from error


def switched_off(read: switches.Mark | None, ingress: Barrier) -> bool:
    """A unit is switched off by its marker or by the barrier a stop left standing."""
    return read is not None or ingress.present()


@dataclass(frozen=True)
class Proven:
    unit: str


@dataclass(frozen=True)
class NoHost:
    """The unit is switched off, but Traefik routes no host of it, so it has no barrier."""

    unit: str


@dataclass(frozen=True)
class Unproven:
    unit: str
    failure: str


@dataclass(frozen=True)
class BarriersUnproven:
    """Every barrier that was active and not proven after a core recreate, in the order tried."""

    proofs: tuple[Unproven, ...]


type ActiveProof = Proven | NoHost | Unproven


def prove_active(
    units: Iterable[catalog.Unit],
    profile_services: Mapping[str, tuple[str, ...]],
    config: Mapping[str, Any],
    marks: switches.Switches,
    checkout: Path,
    verifier: Verifier = PROVEN_OVER_HTTP,
    apps: Iterable[catalog.App] = (),
) -> Iterator[ActiveProof]:
    """Re-render and prove the barrier of every unit and app that is switched off or still has one.

    One outcome per active barrier, yielded as its proof ends, so a caller that stops at the
    first unproven barrier leaves the later ones untouched.
    """
    ingresses = (
        *(
            (unit.key, partial(Barrier.of_unit, config, profile_services[unit.key], checkout, unit))
            for unit in units
        ),
        *((app.key, partial(Barrier.of_app, config, checkout, app)) for app in apps),
    )
    for key, build in ingresses:
        proof = _proof_of(key, build, marks, verifier)
        if proof is not None:
            yield proof


def _proof_of(
    key: str,
    build: Callable[[Verifier], Barrier],
    marks: switches.Switches,
    verifier: Verifier,
) -> ActiveProof | None:
    """The outcome for one unit or app; None when its barrier is not active."""
    try:
        ingress = build(verifier)
        if not switched_off(marks.mark(key), ingress):
            return None
        if not ingress.names:
            return NoHost(key)
        ingress.close()
    except (BarrierError, switches.SwitchError) as error:
        return Unproven(key, str(error))
    return Proven(key)
