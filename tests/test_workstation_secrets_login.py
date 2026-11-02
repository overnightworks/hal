"""The guided tool login of #666: the wizard has the CLI of a `create` entry make the secret and judges only its path and mode."""

from __future__ import annotations

import os
import stat
import sys
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import pytest
from support.workstation_secrets_report import findings_of, report_of
from support.workstation_secrets_support import (
    FakeCli,
    FakeSync,
    FakeTerminal,
    private_directory,
    run_wizard,
    squeezed,
)
from support.workstation_support import FakeProbe, run_hal_secrets

from hal.output.command import Verb, command
from hal.workstation import secrets_setup, secrets_view
from hal.workstation.secrets_setup import Boundaries, Outcome, Verdict, WalkEnd, run_command
from hal.workstation.secrets_view import load_manifest

CODEX_CREATE_LINE = 'create = { run = ["codex", "login"], home = ["CODEX_HOME"], label = "Codex" }'
CODEX_LOGIN_MANIFEST = f"""\
[[secret]]
name = "agent-service/codex"
kind = "tool-login"
paths = ["~/.secrets/agent-service/codex/auth.json"]
read_by = ["agent-service"]
{CODEX_CREATE_LINE}
purpose = "the agent service runs Codex for the apps"
"""
CODEX_FOLDER = ".secrets/agent-service/codex"
CODEX_FILE = f"{CODEX_FOLDER}/auth.json"


@pytest.fixture
def terminal() -> FakeTerminal:
    return FakeTerminal()


@pytest.fixture
def disk() -> FakeSync:
    return FakeSync()


@pytest.fixture
def cli() -> FakeCli:
    return FakeCli()


@dataclass
class HomeWatchingCli(FakeCli):
    """A FakeCli that records the home it was given and what stood there when it started; `then` acts on that home after it
    wrote, and `raises` ends the run the way a crash or Ctrl-C would."""

    homes: list[Path] = field(default_factory=list)
    found_at_start: list[tuple[int, list[str]]] = field(default_factory=list)
    then: Callable[[Path], None] | None = None
    raises: type[BaseException] | None = None

    def __call__(self, argv: Sequence[str], variables: Mapping[str, str]) -> int | None:
        home = Path(variables["CODEX_HOME"])
        self.homes.append(home)
        self.found_at_start.append((stat.S_IMODE(home.lstat().st_mode), sorted(path.name for path in home.iterdir())))
        exit_code = super().__call__(argv, variables)
        if self.then:
            self.then(home)
        if self.raises:
            raise self.raises
        return exit_code


def refusing_verifier(_source: object, _value: str) -> Verdict:
    return Verdict(Outcome.REFUSED, "no token is verified in a tool login")


@pytest.fixture
def boundaries(terminal: FakeTerminal, disk: FakeSync, cli: FakeCli) -> Boundaries:
    """The operator at the keyboard; the walk sees only these fakes, never a browser, a prompt or a CLI."""
    return Boundaries(terminal.boundary(), refusing_verifier, disk.sync, cli)


@pytest.fixture
def login_home(tmp_path: Path, use_manifest) -> Path:
    use_manifest(CODEX_LOGIN_MANIFEST)
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_a_missing_login_is_made_by_its_cli_and_stored_in_the_entrys_own_folder_with_the_ruled_rights(
    login_home: Path, boundaries: Boundaries, cli: FakeCli, capsys
) -> None:
    """#666 D1, D3: the CLI runs once; afterwards folder 0700 and file 0600, and the row never shows content."""
    end = run_wizard(login_home, boundaries)

    captured = capsys.readouterr()
    assert end is WalkEnd.DONE
    assert [argv for argv, _variables in cli.calls] == [("codex", "login")]
    assert stat.S_IMODE((login_home / CODEX_FOLDER).stat().st_mode) == 0o700
    assert stat.S_IMODE((login_home / CODEX_FILE).stat().st_mode) == 0o600
    assert squeezed(captured.out) == [
        "› agent-service/codex new login your Codex account, a login of its own",
        "why: the agent service runs Codex for the apps",
        "✓ agent-service/codex signed in ~/.secrets/agent-service/codex/auth.json (600) · never shown",
    ]
    assert cli.content not in captured.out + captured.err


def test_the_walk_offers_the_sign_in_before_it_runs_the_cli(
    login_home: Path, boundaries: Boundaries, terminal: FakeTerminal, cli: FakeCli
) -> None:
    """#666 rows: Enter opens the Codex sign-in; nothing runs before the operator pressed it."""
    terminal.enter = KeyboardInterrupt

    end = run_wizard(login_home, boundaries)

    assert end is WalkEnd.ABORTED
    assert terminal.prompts == [
        f"{secrets_setup.DETAIL_INDENT}Enter opens the Codex sign-in in your browser: "
    ]
    assert cli.calls == []
    assert not list((login_home / CODEX_FOLDER).glob("*"))


def test_a_login_already_present_is_left_untouched_and_the_cli_does_not_run(
    login_home: Path, boundaries: Boundaries, cli: FakeCli
) -> None:
    """#666 D2: a present auth.json stays as it is, whatever its mode."""
    folder = private_directory(login_home, CODEX_FOLDER)
    (folder / "auth.json").write_text("kept")
    (folder / "auth.json").chmod(0o640)

    end = run_wizard(login_home, boundaries)

    assert end is WalkEnd.DONE
    assert cli.calls == []
    assert (
        (folder / "auth.json").read_text(),
        stat.S_IMODE((folder / "auth.json").stat().st_mode),
    ) == ("kept", 0o640)


@pytest.mark.parametrize(
    ("cli_answer", "refusal"),
    [
        (FakeCli(exit_code=None), "codex is not installed · install it, then rerun"),
        (FakeCli(exit_code=1), "codex login ended with exit 1 · nothing stored"),
        (
            FakeCli(exit_code=0, leaves=""),
            "codex login ended without a login file · nothing stored",
        ),
        (
            FakeCli(exit_code=0, leaves="auth.json.tmp"),
            "codex login ended without a login file · nothing stored",
        ),
        (
            HomeWatchingCli(then=lambda home: ((home / "auth.json").unlink(), (home / "auth.json").symlink_to("/etc/hostname"))),
            "codex login ended without a login file · nothing stored",
        ),
        (
            HomeWatchingCli(then=lambda home: ((home / "auth.json").unlink(), (home / "auth.json").mkdir())),
            "codex login ended without a login file · nothing stored",
        ),
    ],
    ids=["not installed", "exit 1", "no file left", "only a sibling left", "a link as the login file", "a folder as the login file"],
)
def test_a_login_that_fails_is_refused_with_a_row_and_leaves_the_walk_open(
    login_home: Path,
    terminal: FakeTerminal,
    disk: FakeSync,
    capsys,
    cli_answer: FakeCli,
    refusal: str,
) -> None:
    """#666 D2, E1, #749: a refused sign-in names itself in one row and stores no auth.json, even when the CLI wrote one, left only a
    sibling, or left a link or a folder in its place."""
    end = run_wizard(
        login_home, Boundaries(terminal.boundary(), refusing_verifier, disk.sync, cli_answer)
    )

    assert end is WalkEnd.STILL_OPEN
    assert f"✗ agent-service/codex not signed in {refusal}" in squeezed(capsys.readouterr().out)
    assert not os.path.lexists(login_home / CODEX_FILE)


SIBLINGS_OF_CODEX_LOGIN = ("log/codex-login.log", "tmp/arg0-linux/lock", "config.toml")


def run_login(home: Path, terminal: FakeTerminal, disk: FakeSync, cli: FakeCli) -> WalkEnd:
    return run_wizard(home, Boundaries(terminal.boundary(), refusing_verifier, disk.sync, cli))


def test_the_cli_signs_in_inside_a_fresh_private_home_outside_the_entrys_folder(
    login_home: Path, terminal: FakeTerminal, disk: FakeSync
) -> None:
    """#749: the service can write the folder, so the host CLI never runs there; its home is an empty 0700 folder of its own."""
    folder = login_home / CODEX_FOLDER
    cli = HomeWatchingCli()

    assert run_login(login_home, terminal, disk, cli) is WalkEnd.DONE

    (home,) = cli.homes
    assert folder not in (home, *home.parents)
    assert cli.found_at_start == [(0o700, [])]


def test_only_the_declared_login_file_reaches_the_folder_with_its_declared_mode(
    login_home: Path, terminal: FakeTerminal, disk: FakeSync
) -> None:
    """#749: hal moves auth.json alone, 0600, into the folder; the CLI's config, logs and temporary folders never get there, and
    what the folder held before stays."""
    folder = private_directory(login_home, CODEX_FOLDER)
    (folder / "notes.txt").write_text("mine")
    cli = FakeCli(mode=0o644, siblings=SIBLINGS_OF_CODEX_LOGIN)

    assert run_login(login_home, terminal, disk, cli) is WalkEnd.DONE

    assert sorted(path.name for path in folder.rglob("*")) == ["auth.json", "notes.txt"]
    assert (
        (folder / "auth.json").read_text(),
        stat.S_IMODE((folder / "auth.json").lstat().st_mode),
        (folder / "notes.txt").read_text(),
    ) == (cli.content, 0o600, "mine")


def test_a_link_planted_at_the_login_files_place_is_replaced_and_its_target_stays_unchanged(
    login_home: Path, tmp_path: Path, terminal: FakeTerminal, disk: FakeSync
) -> None:
    """#749: a link the service put where auth.json goes is replaced by the new login, never written or chmodded through."""
    folder = private_directory(login_home, CODEX_FOLDER)
    victim = tmp_path / "victim"
    victim.write_text("untouched")
    victim.chmod(0o644)
    cli = HomeWatchingCli(then=lambda _home: (folder / "auth.json").symlink_to(victim))

    assert run_login(login_home, terminal, disk, cli) is WalkEnd.DONE

    assert (victim.read_text(), stat.S_IMODE(victim.stat().st_mode)) == ("untouched", 0o644)
    assert stat.S_ISREG((folder / "auth.json").lstat().st_mode)
    assert (folder / "auth.json").read_text() == cli.content


@pytest.mark.parametrize(
    ("cli", "end"),
    [
        (HomeWatchingCli(siblings=SIBLINGS_OF_CODEX_LOGIN), WalkEnd.DONE),
        (HomeWatchingCli(exit_code=1, siblings=SIBLINGS_OF_CODEX_LOGIN), WalkEnd.STILL_OPEN),
        (HomeWatchingCli(raises=KeyboardInterrupt), WalkEnd.ABORTED),
        (HomeWatchingCli(raises=RuntimeError), WalkEnd.ENTRY_FAILED),
    ],
    ids=["signed in", "exit 1", "Ctrl-C", "crash"],
)
def test_the_fresh_home_is_gone_however_the_login_ends(
    login_home: Path, terminal: FakeTerminal, disk: FakeSync, cli: HomeWatchingCli, end: WalkEnd
) -> None:
    """#749: nothing of the CLI's home stays beside the folder, whether it signed in, failed or was stopped."""
    assert run_login(login_home, terminal, disk, cli) is end

    (home,) = cli.homes
    assert not os.path.lexists(home)
    assert [path.name for path in (login_home / CODEX_FOLDER).parent.iterdir()] == ["codex"]


@pytest.mark.parametrize(
    ("planted", "unknown"),
    [
        (("config.toml", "log/codex-login.log"), {"config.toml", "log", "log/codex-login.log"}),
        ((".auth.json.new",), set()),
    ],
    ids=["files planted beside the login", "the service's renewal sibling"],
)
def test_beside_the_login_file_only_the_services_renewal_sibling_is_no_unknown_file(
    login_home: Path, terminal: FakeTerminal, disk: FakeSync, planted: tuple[str, ...], unknown: set[str], capsys
) -> None:
    """#749: the service may write the folder and the CLI never does, so only `.auth.json.new` is expected beside auth.json; a file
    the service planted there shows in `hal secrets`."""
    assert run_login(login_home, terminal, disk, FakeCli()) is WalkEnd.DONE
    folder = login_home / CODEX_FOLDER
    for relative in planted:
        (folder / relative).parent.mkdir(mode=0o700, exist_ok=True)
        (folder / relative).write_text("planted")
        (folder / relative).chmod(0o600)

    run_hal_secrets(login_home, FakeProbe())

    found = findings_of(report_of(login_home), "unknown-file")
    assert set(found) == {f"~/{CODEX_FOLDER}/{relative}" for relative in unknown}


def test_a_failed_login_removes_what_that_run_left_and_keeps_what_was_there_before(
    login_home: Path, terminal: FakeTerminal, disk: FakeSync
) -> None:
    """#666 D3: after a refused run only its own leftovers go; a sibling that existed before the run survives."""
    folder = private_directory(login_home, CODEX_FOLDER)
    (folder / "notes.txt").write_text("mine")
    failing = FakeCli(exit_code=1, siblings=SIBLINGS_OF_CODEX_LOGIN)

    end = run_wizard(
        login_home, Boundaries(terminal.boundary(), refusing_verifier, disk.sync, failing)
    )

    assert end is WalkEnd.STILL_OPEN
    assert sorted(path.name for path in folder.rglob("*")) == ["notes.txt"]


def test_the_renewal_of_a_create_entry_is_hal_setup_once_its_login_file_is_gone(login_home: Path) -> None:
    """#666 D4, #749: the renewal `hal secrets` shows is derived, never a raw CLI run in the folder the service can write."""
    (entry,) = load_manifest(secrets_view.MANIFEST_PATH)

    assert command(Verb.SETUP) in entry.renewal
    assert f"{secrets_view.HOME_PREFIX}{entry.place}" in entry.renewal
    assert "CODEX_HOME" not in entry.renewal


@pytest.mark.parametrize(
    "create_line",
    [
        'create = { run = ["codex"], label = "Codex" }\nrecreate = "by hand"',
        'create = { run = ["codex"], label = "Codex", mode = "x" }',
        'create = { run = [], label = "Codex" }',
    ],
    ids=["recreate beside create", "unknown create key", "empty run"],
)
def test_a_create_entry_is_refused_when_it_is_malformed(use_manifest, create_line: str) -> None:
    """#666 D1/D4: create replaces recreate, takes only run, home and label, and names a CLI."""
    path = use_manifest(CODEX_LOGIN_MANIFEST.replace(CODEX_CREATE_LINE, create_line))

    with pytest.raises(secrets_view.ManifestError):
        load_manifest(path)


def test_the_real_login_runner_keeps_the_operators_environment_and_adds_its_home_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """#666 E1/E2: the CLI sees CODEX_HOME at the folder it is given and still the operator's PATH, HOME, DISPLAY and BROWSER."""
    monkeypatch.setenv("OPERATOR_ENVIRONMENT_MARKER", "present")
    check = (
        "import os, sys; "
        "sys.exit(0 if os.environ.get('CODEX_HOME') == sys.argv[1] "
        "and os.environ.get('OPERATOR_ENVIRONMENT_MARKER') == 'present' else 7)"
    )

    assert run_command([sys.executable, "-c", check, str(tmp_path)], {"CODEX_HOME": str(tmp_path)}) == 0


def test_the_real_login_runner_reports_a_missing_cli_as_none(tmp_path: Path) -> None:
    """#666 D1: an absent executable is answered with None, which the wizard words as 'not installed'."""
    assert run_command([str(tmp_path / "no-such-cli")], {}) is None


GROK_ENTRY_NAME = "agent-service/grok"


@pytest.fixture
def shipped_grok_home(tmp_path: Path, use_manifest) -> Path:
    """A home whose manifest is the shipped entry of the Grok login alone, as shipped, so a walk touches no other entry."""
    shipped = secrets_view.MANIFEST_PATH.read_text()
    (block,) = [part for part in shipped.split("[[secret]]") if f'name = "{GROK_ENTRY_NAME}"' in part]
    use_manifest(f"[[secret]]{block}")
    home = tmp_path / "home"
    home.mkdir()
    return home


def test_the_shipped_grok_entry_is_a_login_made_with_both_home_variables(shipped_grok_home: Path) -> None:
    """the CLI keeps its state below HOME as well as GROK_HOME, so a private home must cover both."""
    (entry,) = load_manifest(secrets_view.MANIFEST_PATH)

    assert entry.create is not None
    assert {"GROK_HOME", "HOME"} <= set(entry.create.home)


def test_the_shipped_grok_entry_signs_in_through_a_private_home_that_is_gone_afterwards(
    shipped_grok_home: Path, boundaries: Boundaries, cli: FakeCli, capsys
) -> None:
    """the walk runs the entry's own command with every home variable at one fresh folder, keeps only the login file at the ruled rights, and prints no content."""
    (entry,) = load_manifest(secrets_view.MANIFEST_PATH)
    assert entry.create is not None
    folder = shipped_grok_home / entry.folder
    cli.siblings = (".cache/state", "logs/grok.log")

    end = run_wizard(shipped_grok_home, boundaries)

    captured = capsys.readouterr()
    ((argv, variables),) = cli.calls
    (private_home,) = set(variables.values())
    assert end is WalkEnd.DONE
    assert argv == entry.create.run
    assert set(variables) == set(entry.create.home)
    assert not Path(private_home).exists()
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    assert stat.S_IMODE((shipped_grok_home / entry.place).stat().st_mode) == 0o600
    assert sorted(path.name for path in folder.iterdir()) == [entry.place.name]
    assert f"{entry.name} new login your {entry.create.label} account" in squeezed(captured.out)[0]
    assert f"✓ {entry.name} signed in" in squeezed(captured.out)[-1]
    assert cli.content not in captured.out + captured.err


def test_a_grok_login_already_present_is_left_untouched_and_the_cli_does_not_run(
    shipped_grok_home: Path, boundaries: Boundaries, cli: FakeCli
) -> None:
    (entry,) = load_manifest(secrets_view.MANIFEST_PATH)
    login = private_directory(shipped_grok_home, str(entry.folder)) / entry.place.name
    login.write_text("kept")

    end = run_wizard(shipped_grok_home, boundaries)

    assert end is WalkEnd.DONE
    assert cli.calls == []
    assert login.read_text() == "kept"


@pytest.mark.parametrize("options", [("-v",), ("--by-service",)], ids=["verbose", "by service"])
def test_hal_secrets_lists_the_shipped_grok_entry_without_its_content(
    shipped_grok_home: Path, probe: FakeProbe, capsys, options: tuple[str, ...]
) -> None:
    """the entry is listed by name, and under agent-service for the inverted view; the login's content is never printed."""
    (entry,) = load_manifest(secrets_view.MANIFEST_PATH)
    login = private_directory(shipped_grok_home, str(entry.folder)) / entry.place.name
    login.write_text("FAKE-LOGIN-CONTENT-0000")
    login.chmod(0o600)

    run_hal_secrets(shipped_grok_home, probe, *options)

    output = capsys.readouterr().out
    assert GROK_ENTRY_NAME in output
    assert "FAKE-LOGIN-CONTENT-0000" not in output
    if "--by-service" in options:
        (reader,) = entry.read_by
        assert any(line.startswith(f"| {reader} |") and GROK_ENTRY_NAME in line for line in output.splitlines())
