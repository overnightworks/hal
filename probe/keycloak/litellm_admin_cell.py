"""Cell A1 of probe.py (#965): the realm observer's members mode against the probe's Keycloak, as
`hal apply` runs it. Person P, proof 10's member of hopin, joins the LiteLLM admin group and Q its
parent group: the mode lists P's id and not Q's, its issuer is the `iss` of P's access token and
P's id that token's `sub`. The held line prints counts and the issuer, never an id."""

from __future__ import annotations

import json
import secrets
import subprocess
from collections.abc import Callable
from typing import Protocol

from test_rp import token_claims

from hal.stack.litellm_keys import ADMIN_GROUP
from hal.stack.realm import OBSERVER_SERVICE

REALM = "hallucinai"
PROOF_CLIENT = "hopin"  # the one client whose member sign-in also runs this cell
PARENT_GROUP = ADMIN_GROUP.rpartition("/")[0]
OUTSIDER = "probe-litellm-outsider"


class Admin(Protocol):
    def create_user(self, realm: str, username: str, password: str) -> str: ...

    def join_group(self, user_id: str, group_path: str) -> None: ...


class Stack(Protocol):
    def compose(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess[str]: ...


class Probe(Protocol):
    admin: Admin
    stack: Stack

    def held(self, proof: str, detail: str) -> None: ...

    def keep_secret(self, name: str, value: str) -> str: ...


def members_mode(stack: Stack) -> dict:
    """The observer's members mode as the key step runs it; a failure is its exit and last
    standard error line, never its standard output."""
    read = stack.compose(
        "run", "-T", "--rm", "--no-deps", OBSERVER_SERVICE, "--members", ADMIN_GROUP, stdin=""
    )
    if read.returncode != 0:
        last = (read.stderr.strip().splitlines() or [""])[-1]
        raise AssertionError(f"A1: the members mode exited {read.returncode}: {last}")
    return json.loads(read.stdout)


def prove(
    probe: Probe,
    expect: Callable[[bool, str], None],
    client_id: str,
    member_id: str,
    access_token: str,
) -> None:
    if client_id != PROOF_CLIENT:
        return
    password = probe.keep_secret(f"{OUTSIDER} password", secrets.token_urlsafe(16))
    outsider = probe.admin.create_user(REALM, OUTSIDER, password)
    probe.admin.join_group(outsider, PARENT_GROUP)
    probe.admin.join_group(member_id, ADMIN_GROUP)
    answer, access = members_mode(probe.stack), token_claims(access_token)
    members = answer["members"]
    expect(
        member_id in members and outsider not in members,
        f"A1: P listed {member_id in members}, Q listed {outsider in members}",
    )
    expect(answer["issuer"] == access["iss"], "A1: the issuer is not the iss of P's access token")
    expect(access["sub"] == member_id, "A1: P's id is not the sub of P's access token")
    probe.held(
        "A1",
        f"the members mode of {ADMIN_GROUP} lists P and not Q of {PARENT_GROUP} "
        f"({len(members)} member); its issuer {answer['issuer']} is the iss of P's access token "
        f"from {client_id}, and P's id its sub",
    )
