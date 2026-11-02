"""The secrets the packaged manifest has `hal setup` generate for an app: the entry, and a setup run against the packaged manifest."""

from __future__ import annotations

import re
import stat
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path, PurePosixPath

import pytest
from support.workstation_support import FakeProbe, Sandbox, lines_of_the_run, plant_secrets, run_captured_hal_setup, run_hal_secrets, run_hal_setup
from support.workstation_secrets_support import never_run, FakeSync, FakeTerminal, guided_boundaries, secrets_terminal
from support.workstation_secrets_report import findings_of, report_of

from support.terminal_support import put_stdout_on_a_terminal
from hal.grammar import ExitCode
from hal.output.hidden_paste import TerminalCannotHide
from hal.workstation import ports as home_ports
from hal.workstation import secrets_view
from hal.workstation.secrets_setup import OPEN_PROMPT, PASTE_PROMPT, UNSENDABLE_PASTE, UNVERIFIED_FACT, Boundaries, Verdict
from hal.workstation.setup import RERUN
from hal.workstation.secrets_view import ManifestError, SecretEntry, TokenSource, load_manifest

PACKAGED_MANIFEST = secrets_view.MANIFEST_PATH
HOPIN_SESSION_SECRET = ".secrets/hopin/session-secret"
URL_SAFE_48_BYTES = re.compile(r"[A-Za-z0-9_-]{64}")
TURN_KEY_ID = ".secrets/cloudflare/turn-hopin/key-id"
TURN_API_TOKEN = ".secrets/cloudflare/turn-hopin/api-token"
NOW = datetime(2026, 10, 15, 9, 0)


def packaged_entry(name: str) -> SecretEntry:
    return next(entry for entry in load_manifest(PACKAGED_MANIFEST) if entry.name == name)


def _anthropic_key_place() -> PurePosixPath:
    (place,) = packaged_entry("litellm/anthropic").paths
    return place


@pytest.fixture
def packaged_home(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch) -> Sandbox:
    """The sandbox home under the packaged manifest with every entry in place but hopin's session secret."""
    monkeypatch.setattr(secrets_view, "MANIFEST_PATH", PACKAGED_MANIFEST)
    plant_secrets(sandbox.home)
    (sandbox.home / HOPIN_SESSION_SECRET).unlink()
    return sandbox


def run_packaged_setup(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], *flags: str) -> str:
    run_hal_setup(*flags, home=sandbox.home, secrets_setup_boundaries=secrets_terminal(True))
    captured = capsys.readouterr()
    return captured.out + captured.err


def test_the_dry_run_lists_hopins_session_secret_as_missing_and_writes_nothing(
    packaged_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    output = run_packaged_setup(packaged_home, capsys, "--dry-run")

    assert ["!", "secrets", "missing", "hopin/session-secret"] in [
        line.split() for line in output.splitlines()
    ]
    assert not (packaged_home.home / HOPIN_SESSION_SECRET).exists()


def test_apply_generates_hopins_session_secret_unseen_at_0644_in_a_0700_folder_and_a_rerun_keeps_it(
    packaged_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    output = run_packaged_setup(packaged_home, capsys)

    secret = packaged_home.home / HOPIN_SESSION_SECRET
    value = secret.read_text()
    assert URL_SAFE_48_BYTES.fullmatch(value)
    assert (stat.S_IMODE(secret.stat().st_mode), stat.S_IMODE(secret.parent.stat().st_mode)) == (
        0o644,
        0o700,
    )
    assert value not in output

    assert value not in run_packaged_setup(packaged_home, capsys)
    assert secret.read_text() == value


@pytest.mark.parametrize(
    ("mode", "loose_subjects"),
    [(0o644, set()), (0o666, {f"~/{HOPIN_SESSION_SECRET}"})],
    ids=["0644 is the declared loosest mode", "0666 is loose"],
)
def test_hopins_session_secret_is_loose_only_beyond_0644(
    packaged_home: Sandbox, probe: FakeProbe, capsys: pytest.CaptureFixture[str], mode: int, loose_subjects: set[str]
) -> None:
    secret = packaged_home.home / HOPIN_SESSION_SECRET
    secret.write_text("planted")
    secret.chmod(mode)

    run_hal_secrets(packaged_home.home, probe, now=NOW)

    assert set(findings_of(report_of(packaged_home.home), "loose-mode")) == loose_subjects


def test_the_packaged_manifest_holds_no_value_of_hopins_session_secret() -> None:
    assert not re.search(r"[A-Za-z0-9_-]{43,}", PACKAGED_MANIFEST.read_text())


def test_the_packaged_manifest_names_its_readers_in_english() -> None:
    reader_names = [name for entry in load_manifest(PACKAGED_MANIFEST) for name in entry.read_by]

    assert all(name.isascii() for name in reader_names)


# --- HopIn's TURN key: asked hidden, stored unverified (O6) ---------------------------------------------------------


@pytest.fixture
def turn_home(packaged_home: Sandbox) -> Sandbox:
    """The packaged manifest with every entry in place but HopIn's TURN key ID and API token."""
    (packaged_home.home / HOPIN_SESSION_SECRET).write_text("planted")
    for relative in (TURN_KEY_ID, TURN_API_TOKEN):
        (packaged_home.home / relative).unlink()
    return packaged_home


def never_verified(_source: object, _value: str) -> Verdict:
    pytest.fail("a TURN value is stored unverified and never sent to a provider")


def run_turn_setup(sandbox: Sandbox, capsys: pytest.CaptureFixture[str], terminal: FakeTerminal, disk: FakeSync | None = None) -> tuple[int, str]:
    boundaries = Boundaries(terminal.boundary(), never_verified, (disk or FakeSync()).sync, never_run)
    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=boundaries, now=NOW)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


UNVERIFIED_ENTRY = '[[secret]]\nname = "turn"\nkind = "unverified-token"\nread_by = []\nrecreate = "r"\n'
PAGE = 'page = "https://example.invalid/keys"\n'


@pytest.mark.parametrize(
    ("keys", "refusal"),
    [
        (PAGE + 'paths = ["~/.secrets/turn/a"]\nprovider = "cloudflare"\nresource = "zone"\nscope = ["a"]\nexpires_in_days = 30\npurpose = "p"\n', "on a token entry only"),
        (PAGE + 'paths = ["~/.secrets/turn/a", "~/.secrets/turn/b"]\n', "exactly one place without a wildcard"),
    ],
    ids=["a provider source", "two paths"],
)
def test_an_unverified_token_cannot_name_a_provider_to_verify_with_nor_two_files(tmp_path: Path, keys: str, refusal: str) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(UNVERIFIED_ENTRY + keys)

    with pytest.raises(ManifestError, match=refusal):
        load_manifest(manifest)


def test_apply_asks_the_turn_values_hidden_in_order_and_stores_them_at_0644_in_a_0700_folder_unseen(
    turn_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = FakeTerminal(pastes=["FAKE-TURN-KEY-ID-0001", "FAKE-TURN-API-TOKEN-0002"])

    code, output = run_turn_setup(turn_home, capsys, terminal)

    key_id, api_token = (turn_home.home / relative for relative in (TURN_KEY_ID, TURN_API_TOKEN))
    assert code == 0
    assert (key_id.read_text(), api_token.read_text()) == ("FAKE-TURN-KEY-ID-0001", "FAKE-TURN-API-TOKEN-0002")
    assert [stat.S_IMODE(path.stat().st_mode) for path in (key_id, api_token, key_id.parent)] == [0o644, 0o644, 0o700]
    assert terminal.prompts.count(PASTE_PROMPT) == 2
    assert "FAKE-TURN" not in output
    assert [" ".join(line.split()) for line in output.splitlines() if "turn-hopin" in line and "✓" in line] == [
        f"✓ {name} stored not verified · ~/{relative} (644)" for name, relative in (("cloudflare/turn-hopin/key-id", TURN_KEY_ID), ("cloudflare/turn-hopin/api-token", TURN_API_TOKEN))
    ]


def test_the_wizard_names_where_the_turn_key_is_made_and_offers_only_the_dashboard(
    turn_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = FakeTerminal(pastes=["FAKE-TURN-KEY-ID-0001", "FAKE-TURN-API-TOKEN-0002"], browser_opens=False)

    _, output = run_turn_setup(turn_home, capsys, terminal)

    key_id = packaged_entry("cloudflare/turn-hopin/key-id")
    lines = [" ".join(line.split()) for line in output.splitlines()]
    assert f"› cloudflare/turn-hopin/key-id new token {UNVERIFIED_FACT}" in lines
    assert f"why: {key_id.purpose}" in lines
    assert f"create: {key_id.recreate}" in lines
    assert OPEN_PROMPT in terminal.prompts
    assert set(terminal.opened) == {key_id.page}
    assert f"no browser opened · open it yourself: {key_id.page}" in lines
    assert not any(line.startswith("opened ") for line in lines)


PAGE_REFUSALS = [
    (UNVERIFIED_ENTRY + 'paths = ["~/.secrets/turn/a"]\n', "page"),
    (UNVERIFIED_ENTRY + 'paths = ["~/.secrets/turn/a"]\npage = "http://example.invalid"\n', "page"),
    ('[[secret]]\nname = "t"\nkind = "token"\nread_by = []\nrecreate = "r"\npaths = ["~/.secrets/t"]\n' + PAGE, "page"),
    ('[[secret]]\nname = "t"\nkind = "service-password"\nread_by = []\nrecreate = "r"\npaths = ["~/.secrets/t"]\n' + PAGE, "page"),
    ('[[secret]]\nname = "t"\nkind = "configuration"\nread_by = []\nrecreate = "r"\npaths = ["~/.secrets/t"]\n' + PAGE, "page"),
]


@pytest.mark.parametrize(("text", "key"), PAGE_REFUSALS, ids=["no page", "page not https", "page on a token", "page on a service password", "page on a configuration"])
def test_the_manifest_refuses_a_missing_misplaced_or_insecure_page_naming_its_key(tmp_path: Path, text: str, key: str) -> None:
    manifest = tmp_path / "manifest.toml"
    manifest.write_text(text)

    with pytest.raises(ManifestError, match=key):
        load_manifest(manifest)


@pytest.fixture
def anthropic_home(packaged_home: Sandbox) -> Sandbox:
    """The packaged manifest with every entry in place but the provider key LiteLLM reads."""
    (packaged_home.home / _anthropic_key_place()).unlink()
    return packaged_home


def test_the_wizard_asks_the_provider_key_hidden_opens_its_page_and_stores_it_at_0600_unverified_and_unseen(
    anthropic_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    terminal = FakeTerminal(pastes=["FAKE-PROVIDER-KEY-0001"])

    code, output = run_turn_setup(anthropic_home, capsys, terminal)

    entry = packaged_entry("litellm/anthropic")
    stored = anthropic_home.home / _anthropic_key_place()
    lines = [" ".join(line.split()) for line in output.splitlines()]
    assert code == 0
    assert stored.read_text() == "FAKE-PROVIDER-KEY-0001"
    assert [stat.S_IMODE(path.stat().st_mode) for path in (stored, stored.parent)] == [0o600, 0o700]
    assert f"› litellm/anthropic new token {UNVERIFIED_FACT}" in lines
    assert f"why: {entry.purpose}" in lines
    assert f"create: {entry.recreate}" in lines
    assert terminal.opened == [entry.page]
    assert terminal.prompts == [OPEN_PROMPT, PASTE_PROMPT]
    assert f"✓ litellm/anthropic stored not verified · ~/{_anthropic_key_place()} (600)" in lines
    assert "FAKE-PROVIDER" not in output


def test_a_declined_open_prompt_opens_nothing_and_asks_for_no_paste(turn_home: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    """#388 matrix cell 15a: cancelling at the open prompt opens nothing and writes no value."""
    terminal = FakeTerminal(enter=KeyboardInterrupt)

    code, _ = run_turn_setup(turn_home, capsys, terminal)

    assert code == 130
    assert terminal.opened == []
    assert PASTE_PROMPT not in terminal.prompts
    assert not any((turn_home.home / relative).exists() for relative in (TURN_KEY_ID, TURN_API_TOKEN))


def test_an_empty_turn_paste_skips_the_value_and_leaves_it_open(turn_home: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    code, output = run_turn_setup(turn_home, capsys, FakeTerminal())

    assert code == ExitCode.FAILURE
    assert "noch offen" not in output
    assert "· cloudflare/turn-hopin/key-id skipped nothing stored" in [" ".join(line.split()) for line in output.splitlines()]
    assert not any((turn_home.home / relative).exists() for relative in (TURN_KEY_ID, TURN_API_TOKEN))


def test_a_non_ascii_turn_paste_is_refused_unshown_and_unwritten(turn_home: Sandbox, capsys: pytest.CaptureFixture[str]) -> None:
    canary = "FAKE-TURN-\u00e4-0003"

    code, output = run_turn_setup(turn_home, capsys, FakeTerminal(pastes=[canary]))

    assert code == ExitCode.FAILURE
    assert f"✗ cloudflare/turn-hopin/key-id rejected {UNSENDABLE_PASTE} · paste again or leave empty" in [" ".join(line.split()) for line in output.splitlines()]
    assert canary not in output
    assert not (turn_home.home / TURN_KEY_ID).exists()


def test_an_interrupt_between_the_two_turn_values_keeps_the_first_and_the_rerun_asks_only_the_second(
    turn_home: Sandbox, capsys: pytest.CaptureFixture[str]
) -> None:
    code, _ = run_turn_setup(turn_home, capsys, FakeTerminal(pastes=["FAKE-TURN-KEY-ID-0001", KeyboardInterrupt]))
    assert code == 130
    assert (turn_home.home / TURN_KEY_ID).read_text() == "FAKE-TURN-KEY-ID-0001"
    assert not (turn_home.home / TURN_API_TOKEN).exists()

    rerun = FakeTerminal(pastes=["FAKE-TURN-API-TOKEN-0002"])
    code, _ = run_turn_setup(turn_home, capsys, rerun)

    assert code == 0
    assert rerun.prompts.count(PASTE_PROMPT) == 1
    assert (turn_home.home / TURN_API_TOKEN).read_text() == "FAKE-TURN-API-TOKEN-0002"


def test_the_view_shows_the_stored_turn_values_as_not_verified(packaged_home: Sandbox, probe: FakeProbe, capsys: pytest.CaptureFixture[str]) -> None:
    run_hal_secrets(packaged_home.home, probe, now=NOW)

    rows = {line for line in report_of(packaged_home.home).splitlines() if line.startswith(("| cloudflare/turn-hopin/", "cloudflare/turn-hopin/"))}
    assert len(rows) == 2
    assert all("token, unverified" in row and "not checked" in row for row in rows)


SECRETS_MANIFEST = """\
[[secret]]
name = "opentofu/passphrase"
kind = "service-password"
paths = ["~/.secrets/opentofu/passphrase"]
read_by = []
recreate = "hal setup"

[[secret]]
name = "hopin/session-secret"
kind = "service-password"
paths = ["~/.secrets/hopin/session-secret"]
read_by = []
recreate = "hal setup"
loosest_mode = 0o644
loosest_mode_reason = "der Container liest es als eigener Nutzer"
"""
SECRET_FILES = (".secrets/opentofu/passphrase", ".secrets/hopin/session-secret")


def run_setup_with_secrets(
    sandbox: Sandbox,
    use_manifest: Callable[[str], Path],
    capsys: pytest.CaptureFixture[str],
    *flags: str,
    at_a_terminal: bool = True,
) -> tuple[int, list[str], str]:
    use_manifest(SECRETS_MANIFEST)
    code = run_hal_setup(
        *flags,
        home=sandbox.home,
        secrets_setup_boundaries=secrets_terminal(at_a_terminal),
        now=datetime(2026, 10, 22, 9, 0),
    )
    captured = capsys.readouterr()
    return code, lines_of_the_run(captured.out), captured.err


def test_the_secrets_step_is_verified_when_the_manifest_has_no_missing_secret(
    sandbox: Sandbox, use_manifest: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    run_setup_with_secrets(sandbox, use_manifest, capsys)
    code, lines, _ = run_setup_with_secrets(sandbox, use_manifest, capsys, "--dry-run")

    assert (code, lines[-2]) == (0, "  · secrets         complete")


def test_the_dry_run_names_the_missing_secrets_and_writes_nothing(
    sandbox: Sandbox, use_manifest: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    code, lines, _ = run_setup_with_secrets(sandbox, use_manifest, capsys, "--dry-run")

    assert (code, lines[-2]) == (
        0,
        "  ! secrets         missing        opentofu/passphrase, hopin/session-secret",
    )
    assert not sandbox.layout.secrets_dir.exists()


def test_apply_names_the_missing_secrets_before_the_wizard_and_says_stored_after_it(
    sandbox: Sandbox, use_manifest: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    """#491 Lines: ! secrets missing before the wizard, ✓ secrets stored after it."""
    _, lines, _ = run_setup_with_secrets(sandbox, use_manifest, capsys)

    secrets_rows = [line for line in lines if "secrets  " in line]
    assert secrets_rows == [
        "  ! secrets         2 missing      opentofu/passphrase, hopin/session-secret",
        "  ✓ secrets         stored",
    ]
    assert lines.index(secrets_rows[0]) + 1 < lines.index(secrets_rows[1])  # the wizard spoke between them


def test_apply_walks_the_missing_secrets_through_the_wizard_and_a_loosest_mode_entry_lands_0644_in_a_0700_folder(
    sandbox: Sandbox, use_manifest: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    code, lines, _ = run_setup_with_secrets(sandbox, use_manifest, capsys)

    modes = {name: stat.S_IMODE((sandbox.home / name).stat().st_mode) for name in SECRET_FILES}
    folder_modes = {
        name: stat.S_IMODE((sandbox.home / name).parent.stat().st_mode) for name in SECRET_FILES
    }
    assert (code, lines[-3]) == (0, "  ✓ secrets         stored")
    assert modes == {SECRET_FILES[0]: 0o600, SECRET_FILES[1]: 0o644}
    assert folder_modes == {name: 0o700 for name in SECRET_FILES}
    assert "✓ hopin/session-secret generated ~/.secrets/hopin/session-secret (644) · never shown" in [" ".join(line.split()) for line in lines]


def test_apply_stops_at_secrets_with_the_open_count_when_the_wizard_leaves_a_secret_open(
    sandbox: Sandbox, use_manifest: Callable[[str], Path], capsys: pytest.CaptureFixture[str]
) -> None:
    by_hand = '[[secret]]\nname = "gitlab"\nkind = "token"\npaths = ["~/.secrets/gitlab"]\nread_by = []\nrecreate = "von Hand"\n'
    use_manifest(by_hand)
    code = run_hal_setup(home=sandbox.home, secrets_setup_boundaries=secrets_terminal(True))
    captured = capsys.readouterr()

    assert code == ExitCode.FAILURE
    assert captured.out.splitlines()[-1] == "  ! secrets         1 open         gitlab (by hand)"
    assert captured.err.splitlines() == ["error: setup stopped at secrets · 1 secret still open", f"next: {RERUN}"]


def secret_entry(name: str, *, kind: str = "service-password", extra: str = "") -> str:
    return f'[[secret]]\nname = "{name}"\nkind = "{kind}"\npaths = ["~/.secrets/{name}"]\nread_by = []\nrecreate = "hal setup"\n{extra}\n'


LIVE = secret_entry("live")
OPTIONAL = secret_entry("optional", extra="optional = true")
RETIRED = secret_entry(
    "retired", extra='retired_on = 2026-10-14\nrevoke_url = "https://example.invalid/revoke"'
)
BY_HAND = secret_entry("by-hand", kind="token")


@pytest.fixture
def hal_secrets(
    sandbox: Sandbox,
    use_manifest: Callable[[str], Path],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> Callable[..., tuple[int, list[str], str]]:
    """`hal setup` in process against a manifest written from the given entries; the wizard's terminal is the one `secrets_terminal` builds."""

    def run(
        entries: str, *flags: str, at_a_terminal: bool = True, boundaries: Boundaries | None = None
    ) -> tuple[int, list[str], str]:
        use_manifest(entries)
        monkeypatch.setattr(
            home_ports, "TERMINAL_BOUNDARIES", boundaries or secrets_terminal(at_a_terminal)
        )
        return run_captured_hal_setup(capsys, *flags)

    return run


def put_secret(sandbox: Sandbox, name: str, mode: int = 0o600) -> Path:
    path = sandbox.home / ".secrets" / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("a value no one may read")
    path.chmod(mode)
    return path


@pytest.mark.parametrize(
    ("entries", "present", "expected"),
    [
        pytest.param(
            LIVE, [], "  ! secrets         missing        live", id="a live entry that is absent"
        ),
        pytest.param(
            LIVE, ["live"], "  · secrets         complete", id="a live entry with its file"
        ),
        pytest.param(
            OPTIONAL, [], "  · secrets         complete", id="an optional entry that is absent"
        ),
        pytest.param(
            RETIRED, [], "  · secrets         complete", id="a retired entry that is absent"
        ),
        pytest.param(
            BY_HAND,
            [],
            "  ! secrets         missing        by-hand (by hand)",
            id="an entry only a person can create",
        ),
        pytest.param(
            LIVE + OPTIONAL + RETIRED,
            ["live"],
            "  · secrets         complete",
            id="every kind, the live one present",
        ),
        pytest.param(
            LIVE + BY_HAND,
            [],
            "  ! secrets         missing        live, by-hand (by hand)",
            id="a generated and a by-hand entry",
        ),
    ],
)
def test_hal_setup_dry_run_names_only_the_open_secrets(
    sandbox: Sandbox,
    hal_secrets: Callable[..., tuple[int, list[str], str]],
    entries: str,
    present: list[str],
    expected: str,
) -> None:
    for name in present:
        put_secret(sandbox, name)

    code, lines, _ = hal_secrets(entries, "--dry-run")

    assert (code, lines[-2]) == (ExitCode.OK, expected)


@pytest.fixture
def closed_folder(sandbox: Sandbox) -> Iterator[None]:
    """A folder its owner cannot open, so `stat` cannot tell whether the file inside exists."""
    put_secret(sandbox, "closed/entry")
    (sandbox.home / ".secrets").chmod(0o700)
    folder = sandbox.home / ".secrets" / "closed"
    folder.chmod(0)
    yield
    folder.chmod(0o700)


@pytest.mark.usefixtures("closed_folder")
@pytest.mark.parametrize(
    "entries",
    [secret_entry("closed/entry"), secret_entry("closed/entry", extra="optional = true")],
    ids=["live", "optional"],
)
def test_hal_setup_dry_run_names_an_entry_whose_presence_cannot_be_told_and_does_not_call_it_verified(
    hal_secrets: Callable[..., tuple[int, list[str], str]], entries: str
) -> None:
    code, lines, _ = hal_secrets(entries, "--dry-run")

    assert (code, lines[-2]) == (
        ExitCode.OK,
        "  ! secrets         missing        closed/entry (unknown)",
    )


@pytest.mark.usefixtures("closed_folder")
def test_hal_setup_apply_fails_the_secrets_step_when_an_entry_cannot_be_checked(
    hal_secrets: Callable[..., tuple[int, list[str], str]],
) -> None:
    code, lines, error = hal_secrets(secret_entry("closed/entry"))

    assert (
        code,
        "! closed/entry not checked its folder cannot be read" in [" ".join(line.split()) for line in lines],
    ) == (ExitCode.FAILURE, True)
    assert error.splitlines()[0] == "error: setup stopped at secrets · 1 secret still open"


def test_hal_setup_apply_counts_two_open_entries_in_the_row_and_the_error(
    hal_secrets: Callable[..., tuple[int, list[str], str]],
) -> None:
    code, lines, error = hal_secrets(secret_entry("first", kind="token") + secret_entry("second", kind="token"))

    assert (code, lines[-1], error.splitlines()[0]) == (
        ExitCode.FAILURE,
        "  ! secrets         2 open         first (by hand), second (by hand)",
        "error: setup stopped at secrets · 2 secrets still open",
    )


def test_hal_setup_apply_ends_a_refused_store_with_the_wizards_own_pair_and_no_still_open_pair(
    hal_secrets: Callable[..., tuple[int, list[str], str]], sandbox: Sandbox
) -> None:
    (sandbox.home / ".secrets").mkdir(mode=0o700)
    (sandbox.home / ".secrets").chmod(0o755)

    code, lines, error = hal_secrets(secret_entry("opentofu/passphrase"))

    assert code == ExitCode.FAILURE
    assert error.splitlines()[-2:] == ["error: setup stopped at secrets · nothing stored for opentofu/passphrase", "next: chmod 700 ~/.secrets"]
    assert [" ".join(line.split()) for line in lines if "✗" in line] == ["✗ opentofu/passphrase not stored ~/.secrets has mode 755; at most 700 allowed"]
    assert not [line for line in lines + error.splitlines() if "still open" in line]


GUIDED_TOKEN = secret_entry(
    "github/read",
    kind="token",
    extra='purpose = "liest GitHub"\nprovider = "github"\nresource = "example-org"\nscope = ["metadata:read"]\nexpires_in_days = 366',
)


def fail_to_verify(_source: TokenSource, _value: str) -> None:
    raise RuntimeError("the value stays out of the line")


def cannot_hide(_prompt: str) -> str:
    raise TerminalCannotHide("no terminal")


@pytest.mark.parametrize(
    ("boundaries", "expected_error"),
    [
        pytest.param(
            guided_boundaries(cannot_hide, fail_to_verify),
            [
                "error: this terminal cannot hide what you type · nothing read",
                "next: hal setup in another terminal window",
            ],
            id="cannot hide input",
        ),
        pytest.param(
            guided_boundaries(lambda _prompt: "pastedvalue", fail_to_verify),
            [
                "error: stopped at github/read · unexpected RuntimeError · github/read is not stored",
                "next: hal setup",
            ],
            id="entry failed",
        ),
    ],
)
def test_hal_setup_apply_ends_a_stop_the_wizard_told_with_the_wizards_pair_alone(
    hal_secrets: Callable[..., tuple[int, list[str], str]],
    boundaries: Boundaries,
    expected_error: list[str],
) -> None:
    code, lines, error = hal_secrets(GUIDED_TOKEN, boundaries=boundaries)

    assert (code, error.splitlines()[-2:]) == (ExitCode.FAILURE, expected_error)
    assert not [line for line in lines if "secrets" in line and "✗" in line]
    assert "setup stopped" not in error
    assert "pastedvalue" not in error
    assert not [line for line in lines if "pastedvalue" in line]


def test_hal_setup_dry_run_reads_no_secret_and_changes_no_mode(
    sandbox: Sandbox, hal_secrets: Callable[..., tuple[int, list[str], str]]
) -> None:
    unreadable = put_secret(
        sandbox, "live", mode=0
    )  # a read would fail with PermissionError, so the run proves it opened nothing
    modes_before = {
        path: stat.S_IMODE(path.stat().st_mode) for path in (unreadable, unreadable.parent)
    }

    code, lines, _ = hal_secrets(LIVE + secret_entry("absent"), "--dry-run")

    assert (code, lines[-2]) == (ExitCode.OK, "  ! secrets         missing        absent")
    assert {path: stat.S_IMODE(path.stat().st_mode) for path in modes_before} == modes_before
    assert not (unreadable.parent / "absent").exists()
    unreadable.chmod(0o600)


def test_hal_setup_apply_sets_up_the_missing_secrets_and_a_repeated_apply_changes_nothing(
    sandbox: Sandbox, hal_secrets: Callable[..., tuple[int, list[str], str]]
) -> None:
    entries = LIVE + secret_entry(
        "wide", extra='loosest_mode = 0o644\nloosest_mode_reason = "the container reads it"'
    )
    first_code, first_lines, _ = hal_secrets(entries)
    stored = [sandbox.home / ".secrets" / name for name in ("live", "wide")]
    after_first = [
        (
            path.stat().st_ino,
            path.stat().st_mtime_ns,
            stat.S_IMODE(path.stat().st_mode),
            path.read_bytes(),
        )
        for path in stored
    ]

    second_code, second_lines, _ = hal_secrets(entries)

    assert (first_code, first_lines[-3]) == (ExitCode.OK, "  ✓ secrets         stored")
    assert first_lines[-1] == "next: hal apply"
    assert [mode for _, _, mode, _ in after_first] == [0o600, 0o644]
    assert (second_code, second_lines[-2]) == (ExitCode.OK, "  · secrets         complete")
    assert [
        (
            path.stat().st_ino,
            path.stat().st_mtime_ns,
            stat.S_IMODE(path.stat().st_mode),
            path.read_bytes(),
        )
        for path in stored
    ] == after_first


def test_hal_setup_apply_ended_by_ctrl_c_exits_130_and_leaves_no_file(
    sandbox: Sandbox, hal_secrets: Callable[..., tuple[int, list[str], str]]
) -> None:
    def interrupted(_descriptor: int) -> None:
        raise KeyboardInterrupt

    terminal = secrets_terminal(True)
    code, _, error = hal_secrets(
        LIVE, boundaries=Boundaries(terminal.terminal, terminal.verify, interrupted, never_run)
    )

    assert code == ExitCode.INTERRUPTED
    assert "error: interrupted at live · no file half written\nnext: hal setup" in error
    assert "setup stopped" not in error
    assert "Traceback" not in error
    assert not (sandbox.home / ".secrets" / "live").exists()


def test_hal_setup_fails_the_secrets_step_by_name_when_the_manifest_cannot_be_read(
    hal_secrets: Callable[..., tuple[int, list[str], str]],
) -> None:
    code, lines, error = hal_secrets("secret = 5\n", "--dry-run")

    assert code == ExitCode.FAILURE
    assert lines[-1].startswith("  ✗ secrets         failed")
    assert error.splitlines()[0] == "error: setup stopped at secrets"
    assert "unexpected error" not in error


def test_on_a_terminal_the_walk_shows_an_opened_page_dim_and_short(
    turn_home: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The `opened` shows host and path, with `?\u2026` only for a page that has a query."""
    shown = walk_on_a_terminal(turn_home, monkeypatch, browser_opens=True)

    assert [line for line in shown if "opened" in line and "Enter opens" not in line] == [
        "\x1b[2m    opened github.com/settings/personal-access-tokens/new?\u2026\x1b[0m",
        "\x1b[2m    opened dash.cloudflare.com/\x1b[0m",
        "\x1b[2m    opened dash.cloudflare.com/\x1b[0m",
    ]


def test_on_a_terminal_the_walk_shows_a_page_nobody_opened_yellow_and_whole(
    turn_home: Sandbox, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator opens it by hand, so the whole address shows."""
    shown = walk_on_a_terminal(turn_home, monkeypatch, browser_opens=False)

    unopened = [line for line in shown if "no browser opened" in line]
    prefix = "\x1b[33m    no browser opened \u00b7 open it yourself: https://"
    assert len(unopened) == 3
    assert all(line.startswith(prefix) and line.endswith("\x1b[0m") for line in unopened)
    assert unopened[0].count("?") == 1
    assert unopened[1:] == [f"{prefix}dash.cloudflare.com/\x1b[0m"] * 2


def walk_on_a_terminal(sandbox: Sandbox, monkeypatch: pytest.MonkeyPatch, *, browser_opens: bool) -> list[str]:
    """The setup walk of the GitHub token and both TURN values with stdout on a terminal, nothing pasted."""
    (sandbox.home / ".secrets/github/fleet-read").unlink()
    stdout = put_stdout_on_a_terminal(monkeypatch)
    boundaries = Boundaries(FakeTerminal(browser_opens=browser_opens).boundary(), never_verified, FakeSync().sync, never_run)

    run_hal_setup(home=sandbox.home, secrets_setup_boundaries=boundaries, now=NOW)

    return stdout.getvalue().splitlines()
