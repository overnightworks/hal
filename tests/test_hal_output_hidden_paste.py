"""hal.output.hidden_paste on a real pty, the way a person pastes: each test starts one child whose
controlling terminal is a fresh pty, and writes the paste as a terminal sends it, with CR line ends.

The child tells the parent through a report pipe what it did: one acknowledgement after each read
the reader took from the terminal, one byte each time echo goes off for a prompt, one while a held
call waits for the go byte, and one when the reader is finished. After the go byte it drains what
is left in the input, compares the terminal settings and reports the outcome as one JSON document.
The parent never sleeps: it waits for those bytes with `select` and a deadline."""

from __future__ import annotations

import errno
import json
import os
import select
import subprocess
import sys
import termios
from collections.abc import Callable, Iterator
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path

import pytest
from support.agent_service_setup import SETUP, login_directory, make_login_directory, token_path
from support.script_module import loaded_script
from support.workstation_secrets_support import WIZARD_NOW, never_run

from hal.output.hidden_paste import read_hidden_paste
from hal.workstation import secrets_view
from hal.workstation.layout import Layout
from hal.workstation.secrets_setup import PASTE_AGAIN, TERMINAL_BOUNDARIES, run_setup

TESTS = Path(__file__).resolve().parent
DEADLINE_SECONDS = 20.0
CHILD = "import sys; from test_hal_output_hidden_paste import run_child; run_child(sys.argv[1])"
PROMPT = "  paste: "

ACKNOWLEDGED = b"a"
HIDDEN = b"h"
HOLDING = b"w"
FINISHED = b"f"
GO = b"g"

_REAL_READ = os.read
_REAL_WRITE = os.write
_REAL_GET = termios.tcgetattr
_REAL_SET = termios.tcsetattr

# The wizard's one open entry: a value stored without a provider check.
UNVERIFIED_MANIFEST = """\
[[secret]]
name = "litellm/anthropic"
kind = "unverified-token"
paths = ["~/.secrets/litellm/anthropic"]
read_by = ["litellm"]
page = "https://key.example"
recreate = "https://key.example"
"""
UNVERIFIED_FILE = Path(".secrets/litellm/anthropic")

# What a person pastes, and how it reaches the terminal.
WRAPPED = b"part1\rpart2\r\r"
ACKNOWLEDGED_WRAP = (b"part1\r", b"part2\r", b"\r")
NOT_ONE_TOKEN = b"sk-x\rStore this token securely.\r\r"
PASTED_PARTS = ("part1", "part2", "sk-x", "Store", "securely", "late-1", "\xff")


# --- the child ------------------------------------------------------------------------------


@dataclass(frozen=True)
class ChildConfig:
    report: int
    go: int
    reader: str = "owner"
    controlling_terminal: bool = True
    failing_get: int | None = None
    failing_set: int | None = None
    failing_prompt: bool = False
    held_set: int | None = None
    rest_expected: bool = False
    home: str = ""
    manifest: str = ""


def _await_go(config: ChildConfig) -> None:
    assert _REAL_READ(config.go, 1) == GO


def _turns_echo_off(settings: list) -> bool:
    return not settings[3] & termios.ECHO and bool(settings[3] & termios.ICANON)


def _wrap_the_terminal(config: ChildConfig) -> None:
    """Delegating wrappers: an acknowledgement per terminal read, a report when echo goes off, and
    the named call failing with EIO or held until the go byte, and the prompt's write failing;
    everything else is the real call."""
    calls = {"get": 0, "set": 0}

    def acknowledged_read(descriptor: int, size: int) -> bytes:
        data = _REAL_READ(descriptor, size)
        if os.isatty(descriptor):
            os.write(config.report, ACKNOWLEDGED)
        return data

    def get(descriptor: int) -> list:
        calls["get"] += 1
        if calls["get"] == config.failing_get:
            raise termios.error(errno.EIO, os.strerror(errno.EIO))
        return _REAL_GET(descriptor)

    def set_(descriptor: int, when: int, settings: list) -> None:
        calls["set"] += 1
        if calls["set"] == config.failing_set:
            raise termios.error(errno.EIO, os.strerror(errno.EIO))
        if calls["set"] == config.held_set:
            os.write(config.report, HOLDING)
            _await_go(config)
            assert select.select([descriptor], [], [], DEADLINE_SECONDS)[0], "nothing was typed"
        _REAL_SET(descriptor, when, settings)
        if _turns_echo_off(settings):
            os.write(config.report, HIDDEN)

    def prompt_failing_write(descriptor: int, data: bytes) -> int:
        if config.failing_prompt and os.isatty(descriptor) and data == PROMPT.encode():
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        return _REAL_WRITE(descriptor, data)

    os.read = acknowledged_read
    os.write = prompt_failing_write
    termios.tcgetattr = get
    termios.tcsetattr = set_


def _chain(error: BaseException) -> list[str]:
    """Every exception reachable through `__cause__` and `__context__`, as its type and its data."""
    seen: list[BaseException] = []
    pending: list[BaseException | None] = [error]
    while pending:
        current = pending.pop()
        if current is None or any(current is known for known in seen):
            continue
        seen.append(current)
        pending += [current.__cause__, current.__context__]
    return [f"{type(known).__name__} {known.args!r} {vars(known)!r}" for known in seen]


def _read_with(config: ChildConfig) -> str | None:
    """What the named reader returns: the owner's paste, setup's nothing, the wizard's walk end."""
    if config.reader == "owner":
        return read_hidden_paste(PROMPT)
    if config.reader == "setup":
        setup = next(loaded_script("agent_service_setup", SETUP))
        setup.AgentServiceSetup(
            setup.Tools(service_uid=os.getuid()), Path(config.home)
        ).paste_token()
        return None
    secrets_view.MANIFEST_PATH = Path(config.manifest)
    opened: list[str] = []

    def record_the_page(page: str) -> bool:
        """The page is recorded, never opened: no test reaches a browser."""
        opened.append(page)
        return True

    walk_terminal = replace(
        TERMINAL_BOUNDARIES.terminal, ask=lambda _prompt: "", open_page=record_the_page
    )
    boundaries = replace(TERMINAL_BOUNDARIES, terminal=walk_terminal, run_command=never_run)
    return run_setup(Layout(Path(config.home)), boundaries, WIZARD_NOW).name


def _outcome(config: ChildConfig) -> dict[str, object]:
    try:
        return {"value": _read_with(config)}
    except BaseException as error:  # Ctrl-C and Ctrl-D are outcomes here
        return {"error": type(error).__name__, "message": str(error), "chain": _chain(error)}


def _drained(terminal: int, settings: list, rest_expected: bool) -> bytes:
    """What is still in the input, read without waiting; first, when a rest is expected, until it
    is there."""
    if rest_expected:
        assert select.select([terminal], [], [], DEADLINE_SECONDS)[0], "no rest came"
    characters = list(settings[6])
    characters[termios.VMIN] = 0
    characters[termios.VTIME] = 0
    flags = settings[3] & ~(termios.ICANON | termios.ECHO)
    _REAL_SET(terminal, termios.TCSANOW, [*settings[:3], flags, *settings[4:6], characters])
    rest = b""
    while chunk := _REAL_READ(terminal, 65536):
        rest += chunk
    return rest


def run_child(arguments: str) -> None:
    config = ChildConfig(**json.loads(arguments))
    terminal = os.open(os.ttyname(0), os.O_RDWR) if config.controlling_terminal else None
    before = None if terminal is None else _REAL_GET(terminal)
    _wrap_the_terminal(config)
    outcome = _outcome(config)
    after = None if terminal is None else _REAL_GET(terminal)
    os.write(config.report, FINISHED)
    _await_go(config)
    rest = b"" if terminal is None else _drained(terminal, before, config.rest_expected)
    outcome |= {
        "rest": rest.decode("latin-1"),
        "settings_kept": before == after,
        "echo_on": bool(after and after[3] & termios.ECHO),
    }
    os.write(config.report, json.dumps(outcome).encode())


# --- the parent -----------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    shown: str
    rest: str
    settings_kept: bool
    echo_on: bool
    value: str | None = None
    error: str | None = None
    message: str = ""
    chain: list[str] = field(default_factory=list)

    def after_the_prompt(self) -> str:
        return self.shown.partition(PROMPT)[2]

    def holds_a_part(self, text: str) -> bool:
        return any(part in text for part in PASTED_PARTS)


@dataclass
class PtyChild:
    process: subprocess.Popen[bytes]
    master: int
    report: int
    go: int
    shown: bytes = b""
    finished: bool = False

    def paste(self, *writes: bytes, acknowledged: bool = False) -> None:
        """Each write once echo is off; when `acknowledged`, each only after the reader took the
        one before it, so every line end is a split in the delivery."""
        self.await_report(HIDDEN)
        for data in writes:
            os.write(self.master, data)
            if acknowledged:
                assert self._next_report() == ACKNOWLEDGED

    def type(self, data: bytes) -> None:
        os.write(self.master, data)

    def await_report(self, event: bytes) -> None:
        """`event`, passing the acknowledgements that come before it."""
        while (byte := self._next_report()) != event:
            assert byte == ACKNOWLEDGED, f"{byte!r} came before {event!r}; shown {self.shown!r}"
        self.finished = self.finished or event == FINISHED

    def send_go(self) -> None:
        os.write(self.go, GO)

    def finish(self) -> Outcome:
        if not self.finished:
            self.await_report(FINISHED)
        self.send_go()
        document = b""
        while chunk := self._next_report(65536):
            document += chunk
        assert self.process.wait(timeout=DEADLINE_SECONDS) == 0, self.shown
        while select.select([self.master], [], [], 0)[0] and self._show():
            pass
        return Outcome(shown=self.shown.decode(errors="replace"), **json.loads(document))

    def _next_report(self, size: int = 1) -> bytes:
        while True:
            ready = select.select([self.report, self.master], [], [], DEADLINE_SECONDS)[0]
            assert ready, f"the child went quiet; it showed {self.shown!r}"
            if self.master in ready:
                self._show()
            if self.report in ready:
                return _REAL_READ(self.report, size)

    def _show(self) -> bool:
        try:
            chunk = _REAL_READ(self.master, 65536)
        except OSError:  # EIO once the child has closed the pty
            return False
        self.shown += chunk
        return bool(chunk)


def child_environment() -> dict[str, str]:
    """The test's environment without a display and with a browser that opens nothing, so a child
    can never reach the operator's desktop."""
    kept = {
        name: value
        for name, value in os.environ.items()
        if name not in {"DISPLAY", "WAYLAND_DISPLAY"}
    }
    paths = os.pathsep.join([str(TESTS.parent / "src"), str(TESTS)])
    return {**kept, "PYTHONPATH": paths, "NO_COLOR": "1", "BROWSER": "true"}


@pytest.fixture
def spawn(tmp_path: Path) -> Iterator[Callable[..., PtyChild]]:
    """Starts a child on a fresh pty as its own session leader, so the pty becomes its terminal."""
    children: list[PtyChild] = []

    def start(**options: object) -> PtyChild:
        master, slave = os.openpty()
        report_read, report_write = os.pipe()
        go_read, go_write = os.pipe()
        config = ChildConfig(report=report_write, go=go_read, **options)
        process = subprocess.Popen(  # without -I, so coverage measures the child
            [sys.executable, "-c", CHILD, json.dumps(asdict(config))],
            stdin=slave if config.controlling_terminal else subprocess.PIPE,
            stdout=slave,
            stderr=slave,
            start_new_session=True,
            pass_fds=(report_write, go_read),
            cwd=tmp_path,
            env=child_environment(),
        )
        for descriptor in (slave, report_write, go_read):
            os.close(descriptor)
        children.append(PtyChild(process, master, report_read, go_write))
        return children[-1]

    yield start
    for child in children:
        if child.process.poll() is None:
            child.process.kill()
        child.process.wait(timeout=DEADLINE_SECONDS)
        if child.process.stdin:
            child.process.stdin.close()
        for descriptor in (child.master, child.report, child.go):
            os.close(descriptor)


def assert_nothing_left_and_restored(outcome: Outcome) -> None:
    """N1, E1 and E2: the input is empty, nothing pasted was shown, the settings are back."""
    assert outcome.rest == ""
    assert not outcome.holds_a_part(outcome.after_the_prompt())
    assert outcome.settings_kept
    assert outcome.echo_on


# --- the owner ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("writes", "acknowledged", "expected"),
    [
        pytest.param((WRAPPED,), False, "part1part2", id="P1 one write"),
        pytest.param(ACKNOWLEDGED_WRAP, True, "part1part2", id="P2 split at each line end"),
        pytest.param((b"  part1  \r  part2\r\r",), False, "part1part2", id="P3 wrap whitespace"),
        pytest.param((b"tok-1\r\r",), False, "tok-1", id="P4 one line"),
        pytest.param((b"\r",), False, "", id="P5 empty"),
        pytest.param((b"a" * 4094 + b"\r", b"\r"), True, "a" * 4094, id="C1 4094 bytes"),
    ],
)
def test_a_paste_without_an_empty_line_inside_is_returned_whole(
    spawn: Callable[..., PtyChild], writes: tuple[bytes, ...], acknowledged: bool, expected: str
) -> None:
    child = spawn()
    child.paste(*writes, acknowledged=acknowledged)

    outcome = child.finish()

    assert (outcome.error, outcome.value) == (None, expected)
    assert_nothing_left_and_restored(outcome)


@pytest.mark.parametrize(
    ("writes", "joined"),
    [pytest.param((WRAPPED,), True, id="J3 joined"), pytest.param((b"tok-1\r\r",), False, id="P4")],
)
def test_a_joined_paste_shows_a_note_without_the_value_or_its_length(
    spawn: Callable[..., PtyChild], writes: tuple[bytes, ...], joined: bool
) -> None:
    child = spawn()
    child.paste(*writes)

    note = child.finish().after_the_prompt().strip()

    assert bool(note) is joined
    assert not any(part in note for part in PASTED_PARTS)
    assert str(len("part1part2")) not in note
    assert not joined or "2" in note


@pytest.mark.parametrize(
    ("writes", "acknowledged"),
    [
        pytest.param((NOT_ONE_TOKEN,), False, id="J1 not one token"),
        pytest.param((b"\x1b[200~part1\rpart2\x1b[201~\r\r",), False, id="J2 control character"),
        pytest.param((b"part1\r\rlate-1\r",), False, id="J4 rest line after the empty one"),
        pytest.param((b"part1\r\rlate-1",), False, id="J4 rest without a line end"),
        pytest.param((b"part1\r \rpart2\r\r",), False, id="J5 whitespace-only line ends it"),
        pytest.param((b"a" * 4095 + b"\r", b"\r"), True, id="C1 4095 bytes"),
        pytest.param((b"a" * 5000 + b"\r", b"\r"), True, id="C1 5000 bytes"),
        pytest.param((b"\xff\r\r",), False, id="U1 not UTF-8"),
        pytest.param((b"\xff\r", b"part2\r", b"\r"), True, id="U1b refused only at the empty line"),
    ],
)
def test_a_paste_that_is_not_one_token_is_refused_and_leaves_nothing(
    spawn: Callable[..., PtyChild], writes: tuple[bytes, ...], acknowledged: bool
) -> None:
    child = spawn()
    child.paste(*writes, acknowledged=acknowledged)

    outcome = child.finish()

    assert (outcome.error, outcome.value) == ("PasteRefused", None)
    assert not outcome.holds_a_part(outcome.message)
    assert not any(
        "UnicodeDecodeError" in link or outcome.holds_a_part(link) for link in outcome.chain
    )
    assert_nothing_left_and_restored(outcome)


def test_a_refusal_of_lines_that_are_not_one_token_names_the_lines(
    spawn: Callable[..., PtyChild],
) -> None:
    child = spawn()
    child.paste(NOT_ONE_TOKEN)

    assert "lines" in child.finish().message


@pytest.mark.parametrize(
    ("ending", "error"),
    [
        pytest.param(b"\x03", "KeyboardInterrupt", id="K1 Ctrl-C"),
        pytest.param(b"\x04", "EOFError", id="K2 Ctrl-D"),
    ],
)
def test_a_paste_ended_by_the_person_raises_and_leaves_nothing(
    spawn: Callable[..., PtyChild], ending: bytes, error: str
) -> None:
    child = spawn()
    child.paste(b"part1\r", acknowledged=True)
    child.type(ending + b"late-1\r")

    outcome = child.finish()

    assert (outcome.error, outcome.value) == (error, None)
    assert_nothing_left_and_restored(outcome)


def test_a_prompt_that_cannot_be_written_surfaces_and_sets_the_terminal_back(
    spawn: Callable[..., PtyChild],
) -> None:
    """E2: the failure after echo went off is not a way out that skips the restore."""
    child = spawn(failing_prompt=True)
    child.await_report(HIDDEN)

    outcome = child.finish()

    assert (outcome.error, outcome.value) == ("OSError", None)
    assert outcome.settings_kept
    assert outcome.echo_on


def test_a_rest_typed_after_the_reader_returned_stays_in_the_input(
    spawn: Callable[..., PtyChild],
) -> None:
    """J6, the named limit: the reader returned the first part; the rest is the next reader's."""
    child = spawn(rest_expected=True)
    child.paste(b"part1\r\r")
    child.await_report(FINISHED)
    child.type(b"part2\r")

    outcome = child.finish()

    assert (outcome.value, outcome.rest) == ("part1", "part2\n")


def test_a_rest_typed_between_the_drain_and_the_restore_stays_in_the_input(
    spawn: Callable[..., PtyChild],
) -> None:
    """J7, the named limit: the restore discards nothing unseen."""
    child = spawn(held_set=3)
    child.paste(b"part1\r\r")
    child.await_report(HOLDING)
    child.type(b"late-1\r")
    child.send_go()

    outcome = child.finish()

    assert (outcome.value, outcome.rest) == ("part1", "late-1\n")


@pytest.mark.parametrize(
    "failure",
    [
        pytest.param({"controlling_terminal": False}, id="T1a no terminal"),
        pytest.param({"failing_get": 1}, id="T1b settings unreadable"),
        pytest.param({"failing_set": 1}, id="T1c echo stays on"),
    ],
)
def test_a_terminal_that_cannot_hide_is_refused_before_the_prompt(
    spawn: Callable[..., PtyChild], failure: dict[str, object]
) -> None:
    outcome = spawn(**failure).finish()

    assert (outcome.error, outcome.value) == ("TerminalCannotHide", None)
    assert PROMPT not in outcome.shown
    assert outcome.settings_kept


def test_a_failed_restore_discards_the_paste_and_never_claims_nothing_was_read(
    spawn: Callable[..., PtyChild],
) -> None:
    child = spawn(failing_set=3)
    child.paste(WRAPPED)

    outcome = child.finish()

    assert (outcome.error, outcome.value) == ("TerminalNotRestored", None)
    assert "stty sane" in outcome.message
    assert "nothing read" not in outcome.message
    assert not outcome.holds_a_part(outcome.message)


# --- the two callers ------------------------------------------------------------------------


def test_setup_stores_a_wrapped_token_whole(spawn: Callable[..., PtyChild], tmp_path: Path) -> None:
    """A1a: the token `claude setup-token` printed across two lines, pasted in two deliveries."""
    make_login_directory(tmp_path)
    token_path(tmp_path).write_text("old-token\n")
    child = spawn(reader="setup", home=str(tmp_path))
    child.paste(*ACKNOWLEDGED_WRAP, acknowledged=True)

    outcome = child.finish()

    assert outcome.error is None, outcome.shown
    assert token_path(tmp_path).read_text() == "part1part2\n"


@pytest.mark.parametrize(
    "writes",
    [
        pytest.param(NOT_ONE_TOKEN, id="A1b not one token"),
        pytest.param(b"\xff\r\r", id="U1 not UTF-8"),
    ],
)
def test_setup_never_writes_a_refused_paste(
    spawn: Callable[..., PtyChild], tmp_path: Path, writes: bytes
) -> None:
    make_login_directory(tmp_path)
    token_path(tmp_path).write_text("old-token\n")
    child = spawn(reader="setup", home=str(tmp_path))
    child.paste(writes)

    outcome = child.finish()

    assert outcome.error == "StepFailure"
    assert "nothing was written" in outcome.message
    assert not any(
        "UnicodeDecodeError" in link or outcome.holds_a_part(link) for link in outcome.chain
    )
    assert token_path(tmp_path).read_text() == "old-token\n"
    assert sorted(path.name for path in login_directory(tmp_path).iterdir()) == ["token"]


def test_the_wizard_stores_a_wrapped_token_whole(
    spawn: Callable[..., PtyChild], tmp_path: Path
) -> None:
    """W1a: the only open entry takes the paste in two deliveries, and the walk ends."""
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(UNVERIFIED_MANIFEST)
    child = spawn(reader="wizard", home=str(tmp_path), manifest=str(manifest))
    child.paste(*ACKNOWLEDGED_WRAP, acknowledged=True)

    outcome = child.finish()

    assert outcome.value == "DONE", outcome.shown
    assert (tmp_path / UNVERIFIED_FILE).read_text() == "part1part2"


def test_the_wizard_rejects_a_paste_that_is_not_one_token_and_asks_again(
    spawn: Callable[..., PtyChild], tmp_path: Path
) -> None:
    """W1b: a rejected row with the refusal and `paste again`, then the empty line skips."""
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(UNVERIFIED_MANIFEST)
    child = spawn(reader="wizard", home=str(tmp_path), manifest=str(manifest))
    child.paste(NOT_ONE_TOKEN)
    child.paste(b"\r")

    outcome = child.finish()

    rows = [" ".join(line.split()) for line in outcome.shown.splitlines()]
    rejected = [row for row in rows if "litellm/anthropic rejected" in row]
    assert outcome.value == "STILL_OPEN"
    assert len(rejected) == 1
    assert rejected[0].endswith(PASTE_AGAIN)
    assert any("litellm/anthropic skipped" in row for row in rows)
    assert not any(part in outcome.shown for part in ("sk-x", "Store", "securely"))
    assert not (tmp_path / UNVERIFIED_FILE).exists()
