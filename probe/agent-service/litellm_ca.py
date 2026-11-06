"""The throwaway CA of a LiteLLM probe's scratch directory and the certificates it issues to the
probe's fake hosts. Its key stays in the scratch directory, outside any HOME a container mounts, so
nothing mounted can sign a certificate. Nothing here prints a byte of a key."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from edge_copy import expect

CA_KEY_BITS = "2048"
DAYS = "1"
OPENSSL_SECONDS = 60


@dataclass(frozen=True)
class ScratchCa:
    """Where the scratch CA's certificate and key are."""

    ca_certificate: Path
    ca_key: Path


def openssl(*arguments: str, stdin: bytes = b"") -> bytes:
    """Key bytes go in and out over pipes only; a failure names the command and its exit code."""
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["openssl", *arguments],  # noqa: S607 - openssl is found on PATH by design
        input=stdin, capture_output=True, check=False, timeout=OPENSSL_SECONDS,
    )  # fmt: skip
    expect(result.returncode == 0, f"openssl {arguments[0]} exited {result.returncode}")
    return result.stdout


def write_new(path: Path, contents: bytes, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(contents)
    path.chmod(mode)


def write_scratch_ca(ca_directory: Path) -> ScratchCa:
    """A new CA in the new directory `ca_directory`."""
    ca_directory.mkdir()
    authority = ScratchCa(ca_directory / "ca.crt", ca_directory / "ca.key")
    openssl(
        "req", "-x509", "-newkey", f"rsa:{CA_KEY_BITS}", "-nodes", "-days", DAYS,
        "-keyout", str(authority.ca_key), "-out", str(authority.ca_certificate),
        "-subj", "/CN=probe-ca",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        "-addext", "subjectKeyIdentifier=hash",
    )  # fmt: skip
    return authority


def issue_certificate(authority: ScratchCa, host: str, directory: Path) -> tuple[Path, Path]:
    """A certificate of the scratch CA for the DNS name `host`, and its key, in `directory`."""
    directory.mkdir(exist_ok=True)
    certificate, key = directory / "cert.pem", directory / "key.pem"
    openssl(
        "req", "-x509", "-CA", str(authority.ca_certificate), "-CAkey", str(authority.ca_key),
        "-newkey", f"rsa:{CA_KEY_BITS}", "-nodes", "-days", DAYS,
        "-keyout", str(key), "-out", str(certificate), "-subj", f"/CN={host}",
        "-addext", f"subjectAltName=DNS:{host}",
        "-addext", "basicConstraints=critical,CA:FALSE",
        "-addext", "authorityKeyIdentifier=keyid",
    )  # fmt: skip
    return certificate, key
