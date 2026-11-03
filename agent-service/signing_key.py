"""The agent service's signing key pair for agent-service/setup: judged, made and replaced
through the signing folder's verified descriptor. `setup` is the only caller.

The setup contract is docs/agent-service.md, "The signing key". Key bytes travel only over pipes to
openssl and are never printed. Reading the files, their leftovers and the folder's lock are
secret_entry.py's.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from collections.abc import Callable
from enum import Enum
from pathlib import Path
from typing import Protocol

from secret_entry import (
    CannotTell,
    Entry,
    SecretFolder,
    SecretHost,
    SecretTools,
    StepFailure,
    size_refusal,
)

SIGNING_DIRECTORY = "signing"
PRIVATE_FILE, PUBLIC_FILE = "private.pem", "public.pem"
PRIVATE_CANDIDATE, PUBLIC_CANDIDATE = "private.pem.new", "public.pem.new"
PRIVATE_NEXT, PUBLIC_NEXT = "private.next.pem", "public.next.pem"
PRIVATE_KEY_MODE, PUBLIC_KEY_MODE = 0o600, 0o644
CREATION_LEFTOVERS = (PRIVATE_CANDIDATE, PUBLIC_CANDIDATE)
LEFTOVERS = (*CREATION_LEFTOVERS, PRIVATE_NEXT, PUBLIC_NEXT)
RSA_BITS, OPENSSL_SECONDS = 3072, 120


def pem_block(label: bytes) -> re.Pattern[bytes]:
    """Exactly one PEM block of this label and nothing around it."""
    return re.compile(
        rb"\A-----BEGIN " + label + rb"-----\n[A-Za-z0-9+/=\n]+\n-----END " + label + rb"-----\n\Z"
    )


PRIVATE_KEY_BLOCK = pem_block(b"PRIVATE KEY")
PUBLIC_KEY_BLOCK = pem_block(b"PUBLIC KEY")
PUBLIC_KEY_DETAILS = re.compile(
    rb"\APublic-Key: \(%d bit\)\n.*\nExponent: 65537 \(0x10001\)\n\Z" % RSA_BITS, re.DOTALL
)
DERIVE_PUBLIC_KEY = ["pkey", "-pubout"]
CHECK_PRIVATE_KEY = ["pkey", "-noout", "-check"]
PUBLIC_DETAILS_OF_PRIVATE = ["pkey", "-noout", "-text_pub"]
PUBLIC_DETAILS_OF_PUBLIC = ["pkey", "-pubin", "-noout", "-text_pub"]
GENERATE_PRIVATE_KEY = [
    *("genpkey", "-algorithm", "RSA", "-pkeyopt", f"rsa_keygen_bits:{RSA_BITS}"),
    *("-pkeyopt", "rsa_keygen_pubexp:65537"),
]
REPLACE_COMMAND = (
    "`agent-service/setup --replace-signing-key` makes a new pair; "
    "then recreate agent-service and songmaker-web"
)


class SigningState(Enum):
    SOUND = "sound"
    EMPTY = "no key yet"
    PUBLIC_REWRITE = "public half missing or with another mode"
    BROKEN = "needs --replace-signing-key"
    OPERATOR_FIX = "needs the operator, replaceable"
    FOREIGN = "needs the operator"


UNUSABLE = {SigningState.BROKEN, SigningState.OPERATOR_FIX, SigningState.FOREIGN}


def run_openssl(arguments: list[str], stdin: bytes) -> subprocess.CompletedProcess[bytes]:
    """Key bytes go in and out over pipes only; the caller never prints either stream."""
    try:
        return subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
            ["openssl", *arguments], input=stdin, capture_output=True, check=False,  # noqa: S607 - openssl is found on PATH by design
            timeout=OPENSSL_SECONDS,
        )  # fmt: skip
    except subprocess.TimeoutExpired as error:
        raise CannotTell(f"`openssl {arguments[0]}` took longer than {OPENSSL_SECONDS}s") from error
    except OSError as error:
        raise CannotTell(f"cannot run openssl: {error.strerror}") from error


class SigningTools(SecretTools, Protocol):
    openssl: Callable[[list[str], bytes], subprocess.CompletedProcess[bytes]]


class SigningHost(SecretHost, Protocol):
    """What `setup` lends the key beyond any secret file's needs: openssl and the folder chain."""

    tools: SigningTools
    signing_chain: tuple[Path, ...]


class SigningKey:
    """The signing key pair, judged and written through the signing folder's verified descriptor."""

    def __init__(self, setup: SigningHost) -> None:
        self.setup = setup
        self.folder = SecretFolder(setup, setup.signing_chain)

    def preflight(self) -> None:
        self.folder.preflight(self.judge, UNUSABLE)

    def check(self) -> None:
        self.folder.check(self.judge, SigningState.SOUND, LEFTOVERS)

    def judge(self, directory: int) -> tuple[SigningState, str]:
        """The first thing wrong with the pair, in the order a fix can follow."""
        folder = self.folder.path
        private = self.folder.read_entry(directory, PRIVATE_FILE)
        public = self.folder.read_entry(directory, PUBLIC_FILE)
        leftovers = self.folder.leftover_statuses(directory, LEFTOVERS)
        if problem := self.folder.operator_problem((private, public), leftovers):
            return SigningState.FOREIGN, problem
        if private is None:
            if public is None:
                return SigningState.EMPTY, f"{folder / PRIVATE_FILE} does not exist"
            line = f"signing/{PRIVATE_FILE} is missing but {PUBLIC_FILE} is still there: "
            return SigningState.BROKEN, line + REPLACE_COMMAND
        mode = stat.S_IMODE(private.status.st_mode)
        if mode != PRIVATE_KEY_MODE:
            line = f"{private.path} has mode {mode:04o}, not 0600; fix it yourself"
            return SigningState.OPERATOR_FIX, line
        if reason := self.private_refusal(private.contents):
            return SigningState.BROKEN, f"{private.path} {reason}: {REPLACE_COMMAND}"
        candidate = leftovers.get(PRIVATE_CANDIDATE, private.status)
        if candidate.st_ino != private.status.st_ino:
            line = (
                f"{folder / PRIVATE_CANDIDATE} is another file than {private.path}; remove it, "
                "or run `agent-service/setup --replace-signing-key`, which clears it"
            )
            return SigningState.OPERATOR_FIX, line
        if public is None:
            return SigningState.PUBLIC_REWRITE, f"{folder / PUBLIC_FILE} does not exist"
        mode = stat.S_IMODE(public.status.st_mode)
        if public.unreadable:
            line = f"{public.path} has mode {mode:04o} and cannot be read; fix it yourself"
            return SigningState.OPERATOR_FIX, line
        if public.contents != self.openssl_output(DERIVE_PUBLIC_KEY, private.contents):
            line = f"{public.path} is malformed or not the private key's: {REPLACE_COMMAND}"
            return SigningState.BROKEN, line
        if mode != PUBLIC_KEY_MODE:
            return SigningState.PUBLIC_REWRITE, f"{public.path} has mode {mode:04o}, not 0644"
        return SigningState.SOUND, ""

    def private_refusal(self, contents: bytes) -> str | None:
        """Why this is not the key the service accepts, else None; says nothing of its bytes."""
        if too_large := size_refusal(contents):
            return too_large
        if not PRIVATE_KEY_BLOCK.match(contents):
            return "is not one unencrypted PKCS#8 PEM block"
        if self.openssl_verdict(CHECK_PRIVATE_KEY, contents) is None:
            return "is not a valid RSA private key"
        if not PUBLIC_KEY_DETAILS.match(self.openssl_output(PUBLIC_DETAILS_OF_PRIVATE, contents)):
            return f"is not an RSA-{RSA_BITS} key with exponent 65537"
        return None

    def public_refusal(self, public: bytes, private: bytes) -> str | None:
        """Why this is not a public key of this private key, else None."""
        if not PUBLIC_KEY_BLOCK.match(public):
            return "is not one PEM public key block"
        if self.openssl_verdict(PUBLIC_DETAILS_OF_PUBLIC, public) is None:
            return "is not a readable public key"
        if self.openssl_output(PUBLIC_DETAILS_OF_PUBLIC, public) != self.openssl_output(
            PUBLIC_DETAILS_OF_PRIVATE, private
        ):
            return "is not the private key's"
        return None

    def openssl_output(self, arguments: list[str], stdin: bytes = b"") -> bytes:
        result = self.setup.tools.openssl(arguments, stdin)
        if result.returncode != 0:
            raise CannotTell(f"`openssl {arguments[0]}` exited {result.returncode}")
        return result.stdout

    def openssl_verdict(
        self, arguments: list[str], stdin: bytes
    ) -> subprocess.CompletedProcess[bytes] | None:
        """openssl's answer when it accepts the key, None when it refuses it. Exit 1 is how it
        refuses a key, and also how a host that cannot run it properly fails; only a throwaway key
        that passes the same operation proves the first, and anything else is "cannot tell"."""
        result = self.setup.tools.openssl(arguments, stdin)
        if result.returncode == 0:
            return result
        if result.returncode == 1 and self.openssl_passes_a_throwaway_key(arguments):
            return None
        raise CannotTell(f"`openssl {arguments[0]}` exited {result.returncode}")

    def openssl_passes_a_throwaway_key(self, arguments: list[str]) -> bool:
        """The failed operation, repeated on a key made in memory for it."""
        throwaway = self.openssl_output(GENERATE_PRIVATE_KEY)
        if arguments == PUBLIC_DETAILS_OF_PUBLIC:
            throwaway = self.openssl_output(DERIVE_PUBLIC_KEY, throwaway)
            return self.setup.tools.openssl(PUBLIC_DETAILS_OF_PUBLIC, throwaway).returncode == 0
        return self.setup.tools.openssl(CHECK_PRIVATE_KEY, throwaway).returncode == 0

    def ensure(self) -> None:
        """Make the pair when there is none, derive a missing public half, clear leftovers; a pair
        that is unusable is refused and left as it is. The leftovers of a replacement stay unless
        the pair is sound already: they belong to `--replace-signing-key`."""
        with self.folder.opened(locked=True) as directory:
            state, line = self.judge(directory)
            if state in UNUSABLE:
                raise StepFailure(line)
            clearable = LEFTOVERS if state is SigningState.SOUND else CREATION_LEFTOVERS
            leftovers = list(self.folder.leftover_statuses(directory, clearable))
            if state is SigningState.EMPTY:
                self.create_private(directory)
            if state is not SigningState.SOUND:
                self.write_public(directory, PUBLIC_CANDIDATE, PRIVATE_FILE)
                self.folder.rename_into_place(directory, PUBLIC_CANDIDATE, PUBLIC_FILE)
            self.folder.unlink_all(directory, clearable)
            if leftovers:
                self.setup.tools.say(f"removed leftovers: {', '.join(leftovers)}")
                os.fsync(directory)

    def create_private(self, directory: int) -> None:
        """Exclusive twice: the candidate is created with O_EXCL, and link(2) refuses any entry."""
        self.write_checked(directory, PRIVATE_CANDIDATE)
        self.folder.link_into_place(directory, PRIVATE_CANDIDATE, PRIVATE_FILE)
        self.setup.tools.say(f"made the key pair in {self.folder.path}; nothing is shown")

    def write_checked(self, directory: int, name: str) -> Entry:
        """A new private key in `name`, kept only if it passes the same check as an active one."""
        self.setup.write_pending(
            directory, self.openssl_output(GENERATE_PRIVATE_KEY), name, PRIVATE_KEY_MODE
        )
        entry = self.folder.read_entry(directory, name)
        if entry is None or entry.problem or self.private_refusal(entry.contents):
            raise StepFailure("the new key failed its check; the active pair is unchanged")
        return entry

    def write_public(self, directory: int, name: str, source: str) -> None:
        """The public half of the key in `source`, kept only if it reads back as a public key of
        that private key."""
        private = self.folder.read_entry(directory, source)
        public = self.openssl_output(DERIVE_PUBLIC_KEY, private.contents)
        self.setup.write_pending(directory, public, name, PUBLIC_KEY_MODE)
        entry = self.folder.read_entry(directory, name)
        if entry is None or entry.problem or self.public_refusal(entry.contents, private.contents):
            raise StepFailure("the new public key failed its check; the active pair is unchanged")

    def replace(self) -> None:
        """Both halves over the old pair (stages R0 to R2 of docs/agent-service.md), after a typed
        yes at a terminal."""
        self.folder.confirm_replacement(
            "--replace-signing-key",
            "--replace-signing-key replaces both halves and deletes the old private key; "
            "replacement alone revokes nothing: the old key keeps signing and stays trusted until "
            "agent-service and songmaker-web are both recreated, and tool calls fail with 401 "
            "while only one of them is",
            "type yes to replace the signing key: ",
        )
        with self.folder.opened(locked=True) as directory:
            if (judgement := self.judge(directory))[0] is SigningState.FOREIGN:
                raise StepFailure(judgement[1])
            self.folder.unlink_all(directory, LEFTOVERS)
            self.write_checked(directory, PRIVATE_NEXT)
            self.write_public(directory, PUBLIC_NEXT, PRIVATE_NEXT)
            os.fsync(directory)  # R0 ends here: nothing active has changed
            self.folder.rename_into_place(directory, PRIVATE_NEXT, PRIVATE_FILE)
            self.folder.rename_into_place(directory, PUBLIC_NEXT, PUBLIC_FILE)  # between: R1
        self.setup.tools.say(
            "replaced both halves; nothing is shown. Now recreate agent-service "
            "(`python3 agent-service/live_signer.py` while songmaker-web is not on "
            "the network, else as docs/agent-service.md says), then songmaker-web with "
            "songmaker's own deploy command"
        )
