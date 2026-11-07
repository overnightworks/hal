"""The pinned `tofu`: version check, `init` and `plan` with their exit codes, and the diagnostics
of the plan's machine stream."""

import json
import os
import re
import shutil
import signal
import subprocess
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from enum import IntEnum, StrEnum
from pathlib import Path

from hal.output import Stream, write_line
from hal.stack.external import secrets

# uv installs the project editable, so this file sits in the checkout:
# src/hal/stack/external/tofu.py.
PROJECT_ROOT = Path(__file__).resolve().parents[4]
EXTERNAL_ROOT = PROJECT_ROOT / "external"
TOFURC = EXTERNAL_ROOT / "tofurc"
_PIN = re.compile(r'required_version\s*=\s*"=\s*([\w.+-]+)"')
_VERSION_LINE = re.compile(r"^OpenTofu v(\S+)")
_STATE_FILE = secrets.OPENTOFU_DIRECTORY / "fleet.tfstate"


class TofuError(Exception):
    """tofu is missing, is not the pinned version, or failed in a step before the plan."""


class MalformedPlanStream(TofuError):
    """A diagnostic of the plan stream has no severity or summary; what it says is not guessed."""


class PlanExit(IntEnum):
    """What `tofu plan -detailed-exitcode` returns."""

    NO_CHANGES = 0
    FAILED = 1
    CHANGES = 2


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"


@dataclass(frozen=True)
class Diagnostic:
    severity: Severity
    summary: str
    detail: str


@dataclass(frozen=True)
class PlanStream:
    """What `tofu plan -json` said that hal shows: its diagnostics in order, and the lines that
    are no JSON object (a crash writes plain text)."""

    diagnostics: tuple[Diagnostic, ...]
    unparsed: tuple[str, ...]


@dataclass(frozen=True)
class Completed:
    exit_code: int
    output: str


class Interrupted(Exception):
    """The operator interrupted the wrapper; tofu was asked to stop and has exited."""

    def __init__(self, completed: Completed) -> None:
        super().__init__()
        self.completed = completed


def pinned_version() -> str:
    """The version `external/main.tf` requires: the pin is stated once, there."""
    match = _PIN.search((EXTERNAL_ROOT / "main.tf").read_text())
    if match is None:
        raise TofuError(f"{EXTERNAL_ROOT / 'main.tf'} has no required_version pin")
    return match.group(1)


def locate_tofu() -> Path:
    found = shutil.which("tofu")
    if found is None:
        raise TofuError("tofu is not on PATH")
    return Path(found).resolve()


def init_arguments(home: Path) -> list[str]:
    return [
        "init",
        "-input=false",
        "-lockfile=readonly",
        f"-backend-config=path={home / _STATE_FILE}",
    ]


_FORWARDED_SIGNALS = {signal.SIGINT, signal.SIGTERM}
PLAN_ARGUMENTS = ["plan", "-refresh=true", "-detailed-exitcode", "-json"]


def show_arguments(plan_file: Path) -> list[str]:
    """tofu's human rendering of the written plan; `-no-color` because tofu colours even a pipe."""
    return ["show", "-no-color", str(plan_file)]


def read_plan_stream(output: str, token_values: dict[str, str]) -> PlanStream:
    """The diagnostics of the stream; every other message type is ignored. Only severity, summary
    and detail are read: the snippet and difference objects of a diagnostic can carry values.

    A line is a stream object or not by the output as tofu wrote it; the lines that are not are
    shown with every secret masked, also where a secret spans several lines. Masking never decides
    what a line is, so no stream object can turn into shown text."""
    secret_spans = _secret_spans(output, token_values)
    diagnostics = []
    unparsed = []
    position = 0
    for raw in output.splitlines(keepends=True):
        line = raw.splitlines()[0]
        message = _json_object(line.strip())
        if message is None:
            shown = _masked(line, position, secret_spans).strip()
            if shown:
                unparsed.append(shown)
        elif message.get("type") == "diagnostic":
            diagnostics.append(_diagnostic_of(message.get("diagnostic")))
        position += len(raw)
    return PlanStream(tuple(diagnostics), tuple(unparsed))


def _secret_spans(output: str, token_values: dict[str, str]) -> list[tuple[int, int]]:
    """Where a secret stands in the output, overlapping or touching occurrences merged."""
    found = sorted(
        match.span()
        for value in token_values.values()
        for match in re.finditer(re.escape(value), output)
    )
    merged: list[tuple[int, int]] = []
    for start, end in found:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def _masked(line: str, position: int, secret_spans: list[tuple[int, int]]) -> str:
    """`line`, which starts at `position` of the output, with one `***` for each secret run."""
    shown = ""
    cursor = 0
    for start, end in secret_spans:
        first = max(start - position, 0)
        last = min(end - position, len(line))
        if first >= last:
            continue
        shown += line[cursor:first] + "***"
        cursor = last
    return shown + line[cursor:]


def _json_object(line: str) -> dict | None:
    try:
        message = json.loads(line)
    except ValueError:
        return None
    return message if isinstance(message, dict) else None


def _diagnostic_of(fields: object) -> Diagnostic:
    if not isinstance(fields, dict):
        raise MalformedPlanStream
    summary = fields.get("summary")
    detail = fields.get("detail", "")
    if not isinstance(summary, str) or not summary or not isinstance(detail, str):
        raise MalformedPlanStream
    try:
        severity = Severity(fields.get("severity"))
    except ValueError:
        raise MalformedPlanStream from None
    return Diagnostic(severity, summary, detail)


def run(tofu: Path, arguments: list[str], environment: dict[str, str]) -> Completed:
    """Run tofu to its end. An interrupt reaches tofu once, as SIGINT, and tofu is awaited.

    tofu leads its own session so a terminal Ctrl-C does not also reach it: a second SIGINT
    makes tofu abort instead of finishing its in-flight provider calls and writing its state.
    """
    # Between the fork and the try below an interrupt would find no tofu to forward to.
    outside_mask = signal.pthread_sigmask(signal.SIG_BLOCK, _FORWARDED_SIGNALS)
    try:
        with subprocess.Popen(  # noqa: S603 - argv is built by the program itself and no shell runs
            [str(tofu), *arguments],
            cwd=EXTERNAL_ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",  # a finished `tofu apply` never raises over undecodable output
            start_new_session=True,
            umask=0o077,
            preexec_fn=lambda: signal.pthread_sigmask(signal.SIG_SETMASK, outside_mask),
        ) as process:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, outside_mask)
                stdout, stderr = process.communicate()
            except KeyboardInterrupt:
                process.send_signal(signal.SIGINT)
                raise Interrupted(_finish_after_interrupt(process)) from None
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, outside_mask)
    return Completed(process.returncode, stdout + stderr)


def _finish_after_interrupt(process: subprocess.Popen) -> Completed:
    while True:
        try:
            stdout, stderr = process.communicate()
        except KeyboardInterrupt:
            continue  # tofu was told once; only its exit ends the wait
        return Completed(process.returncode, stdout + stderr)


def require_pinned_version(tofu: Path, environment: dict[str, str]) -> None:
    pinned = pinned_version()
    reported = run(tofu, ["version"], environment)
    match = _VERSION_LINE.match(reported.output)
    found = match.group(1) if match else None
    if reported.exit_code != 0 or found != pinned:
        raise TofuError(f"tofu is {found or 'of unknown version'}, the pin is {pinned}")


@dataclass(frozen=True)
class Session:
    tofu: Path
    environment: dict[str, str]
    temporary_directory: Path

    def plan_arguments(self, tunnel_id: str, catalog_bytes: bytes | None) -> list[str]:
        """The plan arguments that look up the tunnel with this id and, given catalog bytes, make
        tofu read exactly them, held in a private file that lives and dies with this session."""
        arguments = [*PLAN_ARGUMENTS, f"-var=tunnel_id={tunnel_id}"]
        if catalog_bytes is None:
            return arguments
        snapshot = self.temporary_directory / "fleet.yaml"
        descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as file:
            file.write(catalog_bytes)
        return [*arguments, f"-var=catalog_file={snapshot}"]


@contextmanager
def session(home: Path, token_values: dict[str, str]) -> Iterator[Session]:
    """The pinned, initialised tofu with its allowlisted environment; TMPDIR lives as long."""
    tofu_path = locate_tofu()
    with secrets.private_temporary_directory(home) as temporary_directory:
        environment = secrets.child_environment(
            tofu=tofu_path,
            home=home,
            temporary_directory=temporary_directory,
            tofurc=TOFURC,
            secrets=token_values,
        )
        try:
            require_pinned_version(tofu_path, environment)
        except TofuError as error:
            raise TofuError(secrets.redact(str(error), token_values)) from None
        init = run(tofu_path, init_arguments(home), environment)
        if init.exit_code != 0:
            write_line(secrets.redact(init.output, token_values), stream=Stream.STDERR)
            raise TofuError("tofu init failed")
        yield Session(tofu_path, environment, temporary_directory)
