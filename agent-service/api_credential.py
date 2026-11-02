"""The agent service's API credential for agent-service/setup: judged, made and replaced through
the verified descriptor of ~/.secrets/agent-service/api. `setup` is the only caller.

The setup contract is docs/agent-service.md, "The API credential". The file is the JSON document
agent-runtime's reader accepts, `{"shared_key": ...}`. The rules of that reader live once on the
hal side, in agent-service/litellm/gate.py, and this module judges the bytes it read through them.
Reading the file, its leftovers and the folder's lock are secret_entry.py's, as they are for the
signing key. The key is never printed.
"""

from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import secrets
import stat
import sys
from enum import Enum
from functools import cache
from pathlib import Path
from types import ModuleType
from typing import Protocol

from secret_entry import SecretFolder, SecretHost, StepFailure, size_refusal

API_DIRECTORY = "api"
CREDENTIAL_FILE = "credential.json"
CANDIDATE = "credential.json.new"
NEXT_FILE = "credential.next.json"
LEFTOVERS = (CANDIDATE, NEXT_FILE)
CREDENTIAL_MODE = 0o600
KEY_BYTES = 32
GATE = Path(__file__).resolve().parent / "litellm" / "gate.py"
REPLACE_FLAG = "agent-service/setup --replace-api-credential"
RECREATES = (
    "recreate litellm; while service.toml has an [api] table, recreate agent-service as well"
)


@cache
def gate() -> ModuleType:
    """The credential reader's rules, loaded from the file LiteLLM mounts: one hal-side copy."""
    name = "agent_service_credential_gate"
    spec = importlib.util.spec_from_file_location(name, GATE)
    assert spec is not None and spec.loader is not None  # noqa: S101 - narrows the type and a fixed .py path always has a loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # its dataclass resolves annotations through it
    try:
        spec.loader.exec_module(module)
    finally:
        del sys.modules[name]
    return module


class CredentialState(Enum):
    SOUND = "sound"
    MISSING = "no credential yet"
    REFUSED = "needs --replace-api-credential"
    OPERATOR_FIX = "needs the operator"


UNUSABLE = {CredentialState.REFUSED, CredentialState.OPERATOR_FIX}


class ApiHost(SecretHost, Protocol):
    """What `setup` lends the credential beyond any secret file's needs: the folder chain."""

    api_chain: tuple[Path, ...]


class ApiCredential:
    """The service credential, judged and written through the api folder's verified descriptor."""

    def __init__(self, setup: ApiHost) -> None:
        self.setup = setup
        self.folder = SecretFolder(setup, setup.api_chain)

    def preflight(self) -> None:
        self.folder.preflight(self.judge, UNUSABLE)

    def check(self) -> None:
        self.folder.check(self.judge, CredentialState.SOUND, (CANDIDATE,))

    def judge(self, directory: int) -> tuple[CredentialState, str]:
        """The first thing wrong with the credential, in the order a fix can follow."""
        credential = self.folder.read_entry(directory, CREDENTIAL_FILE)
        leftovers = self.folder.leftover_statuses(directory, LEFTOVERS)
        if problem := self.folder.operator_problem((credential,), leftovers):
            return CredentialState.OPERATOR_FIX, problem
        if credential is None:
            return CredentialState.MISSING, f"{self.folder.path / CREDENTIAL_FILE} does not exist"
        mode = stat.S_IMODE(credential.status.st_mode)
        if mode != CREDENTIAL_MODE:
            line = f"{credential.path} has mode {mode:04o}, not 0600; fix it yourself"
            return CredentialState.OPERATOR_FIX, line
        if reason := self.refusal(credential.contents):
            return CredentialState.REFUSED, f"{credential.path} {reason}: {REPLACE_FLAG}"
        return CredentialState.SOUND, ""

    @staticmethod
    def refusal(contents: bytes) -> str | None:
        """Why the service's reader refuses these bytes, else None; says nothing of them."""
        if too_large := size_refusal(contents):
            return too_large
        if gate().shared_key_of(contents) is None:
            return "is refused by the service's credential reader"
        return None

    def ensure(self) -> None:
        """Make the credential when there is none and clear a leftover `.new`; one that is present
        but refused is never replaced here."""
        with self.folder.opened(locked=True) as directory:
            self.make_missing(directory)

    def make_missing(self, directory: int) -> None:
        state, line = self.judge(directory)
        if state in UNUSABLE:
            raise StepFailure(line)
        if state is CredentialState.MISSING:
            self.new_candidate(directory, CANDIDATE)
            self.folder.link_into_place(directory, CANDIDATE, CREDENTIAL_FILE)
            self.setup.tools.say(f"made the API credential in {self.folder.path}; nothing is shown")
        elif self.folder.leftover_statuses(directory, (CANDIDATE,)):
            os.unlink(CANDIDATE, dir_fd=directory)
            os.fsync(directory)
            self.setup.tools.say(f"removed leftovers: {CANDIDATE}")

    def new_candidate(self, directory: int, name: str) -> None:
        """A new credential in `name`, kept only if the reader accepts what was written."""
        document = json.dumps({"shared_key": secrets.token_urlsafe(KEY_BYTES)}).encode()
        try:
            self.setup.write_pending(directory, document, name, CREDENTIAL_MODE)
            entry = self.folder.read_entry(directory, name)
            if entry is None or entry.problem or self.refusal(entry.contents):
                raise StepFailure("the new credential failed its check; the old one is unchanged")
        except BaseException:
            with contextlib.suppress(OSError):  # the failure being reported is the first one
                os.unlink(name, dir_fd=directory)
            raise

    def replace(self) -> None:
        """A new credential over the old one after a typed yes at a terminal."""
        self.folder.confirm_replacement(
            "--replace-api-credential",
            "--replace-api-credential replaces the shared key and deletes the old one; "
            "replacement alone revokes nothing: the old key stays accepted until litellm and, "
            "while service.toml has an [api] table, agent-service are recreated",
            "type yes to replace the API credential: ",
        )
        with self.folder.opened(locked=True) as directory:
            state, line = self.judge(directory)
            if state is CredentialState.OPERATOR_FIX:
                raise StepFailure(line)
            self.folder.unlink_all(directory, LEFTOVERS)
            self.new_candidate(directory, NEXT_FILE)
            self.folder.rename_into_place(directory, NEXT_FILE, CREDENTIAL_FILE)
        self.setup.tools.say(f"replaced the API credential; nothing is shown. Now {RECREATES}")
