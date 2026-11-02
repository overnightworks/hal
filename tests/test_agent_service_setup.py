"""agent-service/setup against a scripted Docker and a throwaway home: no containers, no real token.

The token rules are the service's reader's (agent_runtime.secret_file); the
refused cases below are the ones its docstring names.
"""

import errno
import fcntl
import os
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path

import pytest
import support.agent_service_setup as setup_support
from support.agent_service_setup import (
    DUMMY_TOKEN,
    IMAGE,
    SECOND_TOKEN,
    api_directory,
    credential_path,
    login_directory,
    make_login_directory,
    mode_of,
    signing_directory,
    token_path,
    write_token,
)

from hal.output import hidden_paste

# The scripted Docker host, terminal, throwaway home and openssl are the support module's fixtures.
setup_module, docker, terminal, home, make_setup, openssl = (
    setup_support.setup_module, setup_support.docker, setup_support.terminal, setup_support.home,
    setup_support.make_setup, setup_support.openssl,
)  # fmt: skip


def test_a_set_up_host_passes_the_check_and_prints_nothing_secret(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN + "\n")

    assert make_setup().check() == 0
    assert all(DUMMY_TOKEN not in line for line in terminal.said)


def test_the_check_says_the_image_is_not_built(make_setup, home, docker, terminal):
    write_token(home, DUMMY_TOKEN)
    docker.images.clear()

    assert make_setup().check() == 1
    assert terminal.said[-1] == f"the image {IMAGE} is not built"


def test_the_check_cannot_tell_when_docker_does_not_answer(make_setup, docker, terminal):
    docker.answers = False

    assert make_setup().check() == 2
    assert terminal.said[-1] == (
        "`docker compose config` exited 1: Cannot connect to the Docker daemon"
    )


def test_a_missing_login_directory_is_not_set_up_and_the_check_changes_nothing(
    make_setup, home, terminal
):
    assert make_setup().check() == 1
    assert "does not exist" in terminal.said[-1]
    assert not (home / ".secrets").exists()


@pytest.mark.parametrize(
    ("path_of", "open_mode", "mended_mode"),
    [
        pytest.param(login_directory, 0o755, 0o700, id="login directory"),
        pytest.param(lambda h: signing_directory(h) / "public.pem", 0o600, 0o644, id="public half"),
    ],
)
def test_a_folder_or_public_half_with_another_mode_is_set_to_its_mode(
    make_setup, home, path_of, open_mode, mended_mode
):
    write_token(home, DUMMY_TOKEN)
    path_of(home).chmod(open_mode)
    assert make_setup().check() == 1

    assert make_setup().run(renew=False) == 0
    assert mode_of(path_of(home)) == mended_mode


def test_a_directory_owned_by_another_user_is_reported_not_taken(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN)

    assert make_setup(service_uid=os.getuid() + 1).run(renew=False) == 1
    assert "owned by uid" in terminal.said[-1]
    assert mode_of(token_path(home)) == 0o600


@pytest.mark.parametrize("mode", [0o664, 0o640, 0o604])
def test_a_token_file_open_to_group_or_others_is_narrowed_without_asking_for_a_token(
    make_setup, home, terminal, mode
):
    write_token(home, DUMMY_TOKEN, mode=mode)
    assert make_setup().check() == 1
    assert f"mode {mode:04o}" in terminal.said[-1]

    assert make_setup().run(renew=False) == 0
    assert mode_of(token_path(home)) == 0o600
    assert token_path(home).read_text() == DUMMY_TOKEN
    assert terminal.prompts == []


@pytest.mark.parametrize(
    ("contents", "reason"),
    [
        (b'{"claudeAiOauth": {"accessToken": "x"}}', "JSON"),
        (b'"quoted"', "JSON"),
        (b"sk-ant-api03-dummy\n", "API key"),
        (b"first-line\nsecond-line\n", "more than one line"),
        (b"has a space\n", "whitespace"),
        (b"\n", "empty"),
        (b"tok\x07en\n", "non-printing"),
        (b"\xff\xfe", "UTF-8"),
        pytest.param(b"x" * (16 * 1024 + 1), "larger", id="too-big"),
    ],
)
def test_a_refused_token_file_is_not_set_up_and_never_shown(
    make_setup, home, terminal, contents, reason
):
    write_token(home, contents)

    assert make_setup().check() == 1
    assert reason in terminal.said[-1]
    shown = contents.decode(errors="ignore").strip()
    assert not shown or shown not in " ".join(terminal.said)


def test_a_token_file_that_is_not_a_regular_file_is_refused(make_setup, home, terminal):
    make_login_directory(home)
    token_path(home).mkdir()

    assert make_setup().check() == 1
    assert "not a regular file" in terminal.said[-1]


def test_a_refused_token_is_replaced_by_the_pasted_one(make_setup, home, terminal):
    write_token(home, b'{"accessToken": "x"}')

    assert make_setup().run(renew=False) == 0
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"
    assert mode_of(token_path(home)) == 0o600
    assert not (login_directory(home) / "token.new").exists()
    assert make_setup().check() == 0


def test_a_fresh_home_builds_makes_the_folders_takes_the_token_and_then_passes(
    make_setup, home, docker, terminal
):
    docker.images.clear()

    assert make_setup().run(renew=False) == 0
    assert make_setup().check() == 0
    assert [command[:2] for command in docker.builds()] == [["docker", "build"]]
    assert IMAGE in docker.builds()[0]
    assert mode_of(home / ".secrets" / "agent-service") == 0o700
    assert mode_of(login_directory(home)) == 0o700
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"


@pytest.fixture
def refuse_opening(monkeypatch) -> Callable[[Path], None]:
    """Make the host refuse to open this secret file with a permission error, as it refuses another
    user's 0600 file."""

    def refuse(path: Path) -> None:
        original = os.open

        def open_unless_named(name, flags, *arguments, **keywords):
            if name == path.name:
                raise PermissionError(errno.EACCES, os.strerror(errno.EACCES), name)
            return original(name, flags, *arguments, **keywords)

        monkeypatch.setattr(os, "open", open_unless_named)

    return refuse


SECRET_FILES = {
    "credential": (credential_path, "api_credential"),
    "private key": (lambda home: signing_directory(home) / "private.pem", "signing"),
}
READABILITY = {"readable": (0o600, False), "mode 0000": (0o000, False), "refused": (0o600, True)}


@pytest.mark.parametrize("readability", READABILITY)
@pytest.mark.parametrize("secret_file", SECRET_FILES)
def test_a_secret_file_of_another_owner_names_its_owner_whether_or_not_it_can_be_read(
    make_setup, home, terminal, refuse_opening, secret_file, readability
):
    path_of, step = SECRET_FILES[secret_file]
    mode, refused = READABILITY[readability]
    write_token(home, DUMMY_TOKEN)
    path_of(home).chmod(mode)
    if refused:
        refuse_opening(path_of(home))
    setup = make_setup(service_uid=os.getuid() + 1)
    setup.judge_directory = lambda *_: None  # the folders are mine; only the file's owner differs

    assert setup.attempt(getattr(setup, step).check, read_only=True) == 1
    assert "owned by uid" in terminal.said[-1]
    assert str(path_of(home)) in terminal.said[-1]


@pytest.mark.parametrize("secret_file", SECRET_FILES)
def test_a_secret_file_of_the_right_owner_that_cannot_be_opened_makes_the_check_cannot_tell(
    make_setup, home, terminal, refuse_opening, secret_file
):
    path_of, _ = SECRET_FILES[secret_file]
    write_token(home, DUMMY_TOKEN)
    refuse_opening(path_of(home))

    assert make_setup().check() == 2
    assert str(path_of(home)) in terminal.said[-1]


def test_a_host_with_every_gap_at_once_is_set_up_in_one_run(make_setup, home, docker, terminal):
    docker.images.clear()
    write_token(home, "a refused token with spaces", mode=0o644)
    credential_path(home).unlink()
    api_directory(home).rmdir()
    for directory in (
        home / ".secrets",
        home / ".secrets" / "agent-service",
        login_directory(home),
        signing_directory(home),
    ):
        directory.chmod(0o755)

    assert make_setup().run(renew=False) == 0
    assert terminal.said[-1] == "agent-service/setup: set up"
    assert make_setup().check() == 0


def test_a_fix_that_leaves_its_gap_stops_the_run_after_one_try(make_setup, home, docker, terminal):
    write_token(home, DUMMY_TOKEN)
    docker.images.clear()
    docker.tags_builds = False

    assert make_setup().run(renew=False) == 1
    assert len(docker.builds()) == 1
    assert IMAGE in terminal.said[-1]


def test_two_fixes_that_recreate_each_others_gap_stop_the_run_at_the_first_repeat(
    make_setup, home, docker, terminal
):
    write_token(home, DUMMY_TOKEN)
    docker.images.clear()
    setup = make_setup()
    build, narrow = setup.build_image, setup.narrow

    def build_and_open_the_secrets_folder() -> None:
        # Bounds the test: a loop that misses the repeat would build again, and forever.
        assert not docker.builds(), "setup rebuilt the image: the fix loop missed a repeated gap"
        build()
        (home / ".secrets").chmod(0o755)

    def narrow_and_lose_the_image(path: Path, mode: int) -> None:
        narrow(path, mode)
        docker.images.clear()

    setup.build_image, setup.narrow = build_and_open_the_secrets_folder, narrow_and_lose_the_image

    assert setup.run(renew=False) == 1
    assert len(docker.builds()) == 1
    assert IMAGE in terminal.said[-1]


def test_a_second_run_changes_nothing_and_asks_nothing(make_setup, home, docker, terminal):
    docker.images.clear()
    make_setup().run(renew=False)
    before = token_path(home).stat()
    builds_before = len(docker.builds())
    prompts_before = len(terminal.prompts)

    assert make_setup().run(renew=False) == 0
    assert len(docker.builds()) == builds_before
    assert len(terminal.prompts) == prompts_before
    assert token_path(home).stat().st_ino == before.st_ino


def test_the_token_never_appears_in_anything_the_script_says(make_setup, home, docker, terminal):
    docker.images.clear()
    make_setup().run(renew=False)

    assert not any(DUMMY_TOKEN in line for line in terminal.said + terminal.prompts)
    assert not any(DUMMY_TOKEN in word for command in docker.commands for word in command)


@pytest.mark.parametrize(
    "pasted",
    ['{"accessToken": "x"}', "sk-ant-api03-dummy", "two words", "", "   ", "tok\x07en"],
)
def test_a_refused_paste_writes_nothing(make_setup, home, terminal, pasted):
    make_login_directory(home)
    terminal.pastes = [pasted]

    assert make_setup().run(renew=False) == 1
    assert not token_path(home).exists()
    assert not (login_directory(home) / "token.new").exists()
    assert "nothing was written" in terminal.said[-1]
    assert not pasted.strip() or pasted.strip() not in terminal.said[-1]


@pytest.mark.parametrize(
    ("failure", "line"),
    [
        pytest.param(
            hidden_paste.TerminalCannotHide("no terminal"),
            "the terminal cannot hide the paste; nothing was read",
            id="cannot hide",
        ),
        pytest.param(
            hidden_paste.TerminalNotRestored(),
            f"{hidden_paste.TerminalNotRestored()}; nothing was written",
            id="not restored",
        ),
        pytest.param(
            EOFError(),
            "no token was pasted (the input ended); nothing was written",
            id="input ended",
        ),
        pytest.param(
            hidden_paste.PasteRefused("the 2 pasted lines are not one token"),
            "the 2 pasted lines are not one token; nothing was written",
            id="refused",
        ),
    ],
)
def test_a_paste_the_reader_cannot_take_is_one_line_and_keeps_the_old_token(
    setup_module, make_setup, home, terminal, monkeypatch, failure, line
):
    """A2: the reader's errors reach the operator through setup's own adapter as one line each."""
    write_token(home, DUMMY_TOKEN + "\n")

    def reader_fails(prompt: str) -> str:
        raise failure

    monkeypatch.setattr(setup_module, "read_hidden_paste", reader_fails)

    assert make_setup(read_secret=setup_module.read_pasted_line).run(renew=True) == 1
    assert terminal.said[-1] == f"agent-service/setup FAILED: {line}"
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"
    assert not (login_directory(home) / "token.new").exists()


def test_the_script_imports_its_reader_under_the_system_interpreter(tmp_path):
    """A3: the shebang picks the first `python3` on a bare PATH, as the operator's shell does."""
    result = subprocess.run(
        [str(setup_support.SETUP), "--help"],
        env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path), "PYTHONDONTWRITEBYTECODE": "1"},
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("usage: ")


def test_renew_swaps_in_a_new_token_beside_the_old_one(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN)
    terminal.pastes = [SECOND_TOKEN]

    assert make_setup().run(renew=True) == 0
    assert token_path(home).read_text() == SECOND_TOKEN + "\n"
    assert mode_of(token_path(home)) == 0o600
    assert not (login_directory(home) / "token.new").exists()


def test_renew_with_a_missing_token_asks_once(make_setup, home, terminal):
    make_login_directory(home)

    assert make_setup().run(renew=True) == 0
    assert len(terminal.prompts) == 1


def test_a_stale_pending_file_never_blocks_the_swap(make_setup, home, terminal):
    write_token(home, b"{}")
    (login_directory(home) / "token.new").write_text("stale", encoding="utf-8")

    assert make_setup().run(renew=False) == 0
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"


def pending_path(home: Path) -> Path:
    return login_directory(home) / "token.new"


def test_a_token_file_owned_by_another_user_is_reported_not_taken(
    setup_module, make_setup, home, terminal, monkeypatch
):
    write_token(home, DUMMY_TOKEN)
    monkeypatch.setattr(setup_module.AgentServiceSetup, "judge_directory", lambda *_: None)

    assert make_setup(service_uid=os.getuid() + 1).check() == 1
    assert f"{token_path(home)} is owned by uid" in terminal.said[-1]


def test_a_directory_narrowed_to_0700_says_so(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN)
    login_directory(home).chmod(0o755)

    make_setup().run(renew=False)
    assert f"narrowing {login_directory(home)} to 0700" in terminal.said


def test_the_check_reads_a_token_in_short_reads_as_the_reader_does(
    make_setup, home, terminal, monkeypatch
):
    write_token(home, "first\nsecond\n")
    read = os.read
    monkeypatch.setattr(os, "read", lambda descriptor, count: read(descriptor, min(count, 2)))

    assert make_setup().check() == 1
    assert "more than one line" in terminal.said[-1]


def test_an_oversized_paste_leaves_the_old_token_byte_for_byte(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN + "\n")
    terminal.pastes = ["x" * (16 * 1024)]  # printable, and with its newline one byte too big

    assert make_setup().run(renew=True) == 1
    assert "larger than 16384 bytes" in terminal.said[-1]
    assert token_path(home).read_bytes() == (DUMMY_TOKEN + "\n").encode()
    assert not pending_path(home).exists()


@pytest.mark.parametrize("linked", ["agent-service", "claude"])
@pytest.mark.parametrize("renew", [False, True])
def test_a_symlinked_folder_is_refused_before_the_paste_and_nothing_is_written(
    make_setup, home, terminal, tmp_path, linked, renew
):
    make_login_directory(home)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    if linked == "agent-service":
        (outside / "claude").mkdir(mode=0o700)
        os.replace(home / ".secrets" / "agent-service", tmp_path / "moved")
        (home / ".secrets" / "agent-service").symlink_to(outside)
    else:
        login_directory(home).rmdir()
        login_directory(home).symlink_to(outside)

    assert make_setup().run(renew=renew) == 1
    assert ("symbolic link" if linked == "claude" else "not a plain folder") in terminal.said[-1]
    assert terminal.prompts == []
    assert list(outside.rglob("*")) == ([outside / "claude"] if linked == "agent-service" else [])


def test_a_folder_swapped_for_a_link_after_the_check_still_receives_nothing(
    setup_module, make_setup, home, terminal, tmp_path
):
    make_login_directory(home)
    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    setup = make_setup()

    def swap_then_paste(prompt: str) -> str:
        login_directory(home).rmdir()
        login_directory(home).symlink_to(outside)
        return DUMMY_TOKEN

    setup.tools = setup_module.Tools(
        run=setup.tools.run, say=terminal.say, read_secret=swap_then_paste,
        service_uid=os.getuid(),
    )  # fmt: skip

    assert setup.run(renew=False) == 1
    assert "not a plain folder" in terminal.said[-1]
    assert list(outside.iterdir()) == []


def test_a_stale_pending_folder_is_one_line_and_keeps_the_old_token(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN + "\n")
    pending_path(home).mkdir()
    terminal.pastes = [SECOND_TOKEN]

    assert make_setup().run(renew=True) == 1
    assert "token.new" in terminal.said[-1]
    assert "the old token is kept" in terminal.said[-1]
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"


def test_a_failing_write_removes_the_pending_file_and_keeps_the_old_token(
    make_setup, home, terminal, monkeypatch
):
    write_token(home, DUMMY_TOKEN + "\n")
    terminal.pastes = [SECOND_TOKEN]

    def disk_fails(descriptor: int) -> None:
        raise OSError(errno.EIO, os.strerror(errno.EIO))

    monkeypatch.setattr(os, "fsync", disk_fails)

    assert make_setup().run(renew=True) == 1
    assert "Input/output error" in terminal.said[-1]
    assert not pending_path(home).exists()
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"


@pytest.mark.parametrize("failing", ["lstat", "read"])
def test_a_host_that_cannot_be_read_makes_the_check_cannot_tell_not_not_set_up(
    make_setup, home, terminal, monkeypatch, failing
):
    write_token(home, DUMMY_TOKEN + "\n")
    original = getattr(os, failing)
    refused = OSError(errno.EIO, os.strerror(errno.EIO))

    def fail_on_the_login_folder(*arguments):
        if failing == "read" or str(login_directory(home)) == str(arguments[0]):
            raise refused
        return original(*arguments)

    monkeypatch.setattr(os, failing, fail_on_the_login_folder)

    assert make_setup().check() == 2
    assert terminal.said[-1] == "Input/output error"


def test_a_renewal_holds_a_lock_on_the_login_folder_from_cleanup_to_rename(
    make_setup, home, terminal, monkeypatch
):
    write_token(home, DUMMY_TOKEN + "\n")
    terminal.pastes = [SECOND_TOKEN]
    fsync = os.fsync
    competitors_refused: list[bool] = []

    def fsync_while_a_second_run_tries_the_lock(descriptor: int) -> None:
        competitor = os.open(login_directory(home), os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(competitor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            competitors_refused.append(False)
        except BlockingIOError:
            competitors_refused.append(True)
        finally:
            os.close(competitor)
        fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fsync_while_a_second_run_tries_the_lock)

    assert make_setup().run(renew=True) == 0
    assert competitors_refused
    assert all(competitors_refused)


def test_a_folder_that_cannot_be_synced_after_the_rename_says_the_new_token_is_in_place(
    make_setup, home, terminal, monkeypatch
):
    write_token(home, DUMMY_TOKEN + "\n")
    terminal.pastes = [SECOND_TOKEN]
    fsync = os.fsync

    def only_the_folder_fails(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise OSError(errno.EIO, os.strerror(errno.EIO))
        fsync(descriptor)

    monkeypatch.setattr(os, "fsync", only_the_folder_fails)

    assert make_setup().run(renew=True) == 1
    assert "the new token is in place" in terminal.said[-1]
    assert "Input/output error" in terminal.said[-1]
    assert "old token is kept" not in terminal.said[-1]
    assert token_path(home).read_text() == SECOND_TOKEN + "\n"


@pytest.mark.parametrize("target_exists", [False, True], ids=["dangling", "valid"])
def test_a_symlinked_token_is_not_set_up_and_setup_replaces_the_link_not_its_target(
    make_setup, home, terminal, tmp_path, target_exists
):
    make_login_directory(home)
    target = tmp_path / "elsewhere-token"
    if target_exists:
        target.write_text(DUMMY_TOKEN + "\n")
        target.chmod(0o640)
    token_path(home).symlink_to(target)

    assert make_setup().check() == 1
    assert "is a symbolic link; it must be a regular file" in terminal.said[-1]

    terminal.pastes = [SECOND_TOKEN]
    assert make_setup().run(renew=False) == 0
    assert not token_path(home).is_symlink()
    assert token_path(home).read_text() == SECOND_TOKEN + "\n"
    assert mode_of(token_path(home)) == 0o600
    assert target.exists() == target_exists
    if target_exists:
        assert target.read_text() == DUMMY_TOKEN + "\n"
        assert mode_of(target) == 0o640
    assert make_setup().check() == 0


def test_an_ancestor_swapped_for_a_link_after_the_check_is_never_narrowed_through(
    setup_module, make_setup, home, terminal, tmp_path
):
    write_token(home, DUMMY_TOKEN + "\n")
    login_directory(home).chmod(0o755)
    outside = tmp_path / "outside"
    (outside / "claude").mkdir(parents=True, mode=0o755)
    (outside / "claude").chmod(0o755)

    def swap_when_narrowing(line: str) -> None:
        terminal.say(line)
        if line.startswith("narrowing"):
            os.replace(home / ".secrets" / "agent-service", tmp_path / "moved")
            (home / ".secrets" / "agent-service").symlink_to(outside)

    setup = make_setup()
    setup.tools = setup_module.Tools(
        run=setup.tools.run, say=swap_when_narrowing, read_secret=terminal.read_secret,
        service_uid=os.getuid(),
    )  # fmt: skip

    assert setup.run(renew=False) == 1
    assert "not a plain folder" in terminal.said[-1]
    assert mode_of(outside / "claude") == 0o755


def test_a_token_that_cannot_be_read_is_refused_and_replaced_by_the_paste(
    make_setup, home, terminal
):
    write_token(home, DUMMY_TOKEN + "\n", mode=0o000)

    assert make_setup().check() == 1
    assert terminal.said[-1].endswith("cannot be read: Permission denied")

    assert make_setup().run(renew=False) == 0
    assert token_path(home).read_text() == DUMMY_TOKEN + "\n"
    assert make_setup().check() == 0


def test_a_run_that_finds_the_lock_held_says_it_waits(make_setup, home, terminal, monkeypatch):
    write_token(home, DUMMY_TOKEN + "\n")
    terminal.pastes = [SECOND_TOKEN]
    flock = fcntl.flock

    def held_until_the_blocking_attempt(descriptor: int, operation: int) -> None:
        if operation & fcntl.LOCK_NB:
            raise BlockingIOError
        flock(descriptor, operation)

    monkeypatch.setattr(fcntl, "flock", held_until_the_blocking_attempt)

    assert make_setup().run(renew=True) == 0
    assert "waiting for another run of agent-service/setup" in terminal.said
    assert token_path(home).read_text() == SECOND_TOKEN + "\n"


def test_a_long_docker_diagnostic_is_cut_to_a_bounded_line(setup_module):
    result = subprocess.CompletedProcess(["docker"], 1, "", "first\n" + "x" * 5000 + "\n")

    line = setup_module.failure_line("docker build", result)

    assert line.startswith("`docker build` exited 1: xxx")
    assert len(line) < 300
