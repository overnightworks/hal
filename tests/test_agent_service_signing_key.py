"""The signing key of agent-service/setup (matrix P01-P08 and P32-P34): throwaway keys made by
host openssl in a throwaway home, never the real ~/.secrets."""

import base64
import fcntl
import os
import threading
from pathlib import Path

import pytest
import support.agent_service_setup as base
from support.agent_service_setup import (
    DUMMY_TOKEN,
    SECOND_TOKEN,
    generate_key,
    make_login_directory,
    mode_of,
    sample_pair,
    signing_directory,
    token_path,
    write_token,
)

# The scripted Docker host, terminal, throwaway home and openssl are the support module's fixtures.
setup_module, docker, terminal, home, make_setup, openssl = (
    base.setup_module, base.docker, base.terminal, base.home, base.make_setup, base.openssl,
)  # fmt: skip

REPLACE = "--replace-signing-key"


def private_path(home: Path) -> Path:
    return signing_directory(home) / "private.pem"


def public_path(home: Path) -> Path:
    return signing_directory(home) / "public.pem"


def snapshot(home: Path) -> dict[str, tuple]:
    """Every entry of the signing folder, the folder included: inode, mtime, mode and bytes."""
    directory = signing_directory(home)
    entries = {".": (directory.stat().st_ino, directory.stat().st_mtime_ns)}
    for path in sorted(directory.iterdir()):
        status = path.lstat()
        entries[path.name] = (status.st_ino, status.st_mtime_ns, mode_of(path), path.read_bytes())
    return entries


def run_setup(setup, option: str | None):
    return {
        "check": setup.check,
        REPLACE: setup.replace_signing_key,
        None: lambda: setup.run(renew=False),
    }[option]()


def test_p01_an_empty_state_gets_the_pair_in_the_contract_layout_and_shows_no_key_byte(
    make_setup, home, terminal, openssl, docker
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    public_path(home).unlink()

    assert make_setup().run(renew=False) == 0

    private, public = private_path(home), public_path(home)
    assert (mode_of(signing_directory(home)), mode_of(private), mode_of(public)) == (
        0o700,
        0o600,
        0o644,
    )
    assert {path.stat().st_uid for path in (private, public)} == {os.getuid()}
    assert private.read_bytes() == sample_pair(1)[0]
    assert private.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----\n")
    assert public.read_bytes() == sample_pair(1)[1]
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]
    secret_lines = [line for line in private.read_text().splitlines() if len(line) > 40]
    assert not [line for line in terminal.said if any(part in line for part in secret_lines)]
    assert not [
        word for call in openssl.calls for word in call if "KEY" in word or word in secret_lines
    ]
    assert all(word not in secret_lines for command in docker.commands for word in command)
    assert make_setup().check() == 0


def test_p02_a_second_run_keeps_the_private_inode_and_both_files_byte_for_byte(make_setup, home):
    write_token(home, DUMMY_TOKEN)
    before = snapshot(home)

    assert make_setup().run(renew=False) == 0
    assert snapshot(home) == before


def test_p08_renew_keeps_the_signing_pair(make_setup, home, terminal):
    write_token(home, DUMMY_TOKEN)
    terminal.pastes = [SECOND_TOKEN]
    before = snapshot(home)

    assert make_setup().run(renew=True) == 0
    assert snapshot(home) == before


STATES_THE_CHECK_REJECTS = {
    "empty": {},
    "private only": {"private": sample_pair(0)[0]},
    "public only": {"public": sample_pair(0)[1]},
    "a mismatched public half": {"private": sample_pair(0)[0], "public": sample_pair(1)[1]},
    "a leftover": {"private": sample_pair(0)[0], "public": sample_pair(0)[1], "leftover": b"x"},
}


@pytest.mark.parametrize("state", list(STATES_THE_CHECK_REJECTS))
def test_p03_the_check_rejects_an_incomplete_or_unsound_state_and_changes_nothing(
    make_setup, home, terminal, state
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    public_path(home).unlink()
    for name, contents in STATES_THE_CHECK_REJECTS[state].items():
        path = {"private": private_path, "public": public_path}.get(
            name, lambda h: signing_directory(h) / "private.next.pem"
        )(home)
        path.write_bytes(contents)
        path.chmod(0o600 if name != "public" else 0o644)
    before = snapshot(home)

    assert make_setup().check() == 1
    assert "agent-service/setup FAILED" not in terminal.said[-1]
    assert "--check" not in terminal.said[-1]
    assert snapshot(home) == before


def test_p03_the_check_passes_a_sound_pair_and_changes_nothing(make_setup, home):
    write_token(home, DUMMY_TOKEN)
    before = snapshot(home)

    assert make_setup().check() == 0
    assert snapshot(home) == before


@pytest.mark.parametrize("exit_code", [1, 2])
def test_p03_an_openssl_that_fails_makes_the_check_cannot_tell_not_a_broken_key(
    make_setup, home, openssl, terminal, exit_code
):
    write_token(home, DUMMY_TOKEN)
    openssl.failing = {"pkey": exit_code}
    before = snapshot(home)

    assert make_setup().check() == 2
    assert "openssl" in terminal.said[-1]
    assert "--replace-signing-key" not in terminal.said[-1]
    assert snapshot(home) == before


@pytest.mark.parametrize("variant", ["new only", "same inode", "another inode"])
def test_p04_an_interrupted_creation_is_cleared_or_left_to_the_operator(
    make_setup, home, terminal, variant
):
    write_token(home, DUMMY_TOKEN)
    candidate = signing_directory(home) / "private.pem.new"
    if variant == "new only":
        private_path(home).unlink()
        public_path(home).unlink()
        candidate.write_bytes(b"half")
        (signing_directory(home) / "public.pem.new").write_bytes(b"half")
    elif variant == "same inode":
        os.link(private_path(home), candidate)
    else:
        candidate.write_bytes(sample_pair(0)[0])
        candidate.chmod(0o600)

    code = make_setup().run(renew=False)

    if variant == "another inode":
        assert code == 1
        assert str(candidate) in terminal.said[-1]
        assert "--replace-signing-key" in terminal.said[-1]
        assert candidate.exists()
        return
    assert code == 0
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]
    assert any("removed leftovers" in line or "made" in line for line in terminal.said)
    if variant == "same inode":
        assert private_path(home).read_bytes() == sample_pair(0)[0]


def test_p05_a_missing_public_half_is_derived_and_the_private_key_is_untouched(make_setup, home):
    write_token(home, DUMMY_TOKEN)
    public_path(home).unlink()
    before = snapshot(home)["private.pem"]

    assert make_setup().run(renew=False) == 0
    assert snapshot(home)["private.pem"] == before
    assert public_path(home).read_bytes() == sample_pair(0)[1]
    assert mode_of(public_path(home)) == 0o644


def test_p07_a_symlinked_signing_folder_is_refused_and_nothing_is_written_outside(
    make_setup, home, terminal, tmp_path
):
    write_token(home, DUMMY_TOKEN)
    outside = tmp_path / "outside"
    signing_directory(home).rename(outside)
    signing_directory(home).symlink_to(outside)
    before = sorted(path.name for path in outside.iterdir())

    assert make_setup().run(renew=False) == 1
    assert "not a plain folder" in terminal.said[-1]
    assert sorted(path.name for path in outside.iterdir()) == before
    assert make_setup().check() == 1


@pytest.mark.parametrize("renew", [False, True], ids=["plain", "renew"])
@pytest.mark.parametrize("fault", ["symlink", "not a folder"])
def test_p07_a_refused_signing_folder_stops_setup_before_the_token_or_the_image_is_touched(
    make_setup, home, terminal, docker, tmp_path, fault, renew
):
    write_token(home, DUMMY_TOKEN, mode=0o644)
    docker.images.clear()
    if fault == "symlink":
        outside = tmp_path / "outside"
        signing_directory(home).rename(outside)
        signing_directory(home).symlink_to(outside)
    else:
        for path in signing_directory(home).iterdir():
            path.unlink()
        signing_directory(home).rmdir()
        signing_directory(home).write_bytes(b"in the way")
    status = token_path(home).stat()

    assert make_setup().run(renew=renew) == 1
    after = token_path(home).stat()
    assert (after.st_ino, after.st_mode, token_path(home).read_bytes()) == (
        status.st_ino, status.st_mode, DUMMY_TOKEN.encode(),
    )  # fmt: skip
    assert docker.builds() == []
    assert terminal.prompts == []


def test_p06_a_public_parse_that_fails_for_the_host_is_cannot_tell_not_a_malformed_key(
    make_setup, home, openssl, terminal
):
    write_token(home, DUMMY_TOKEN)
    public_path(home).unlink()
    openssl.failing = {"pkey -pubin": 1}
    before = private_path(home).read_bytes()

    assert make_setup().run(renew=False) == 2
    assert "cannot tell" in terminal.said[-1]
    assert "--replace-signing-key" not in terminal.said[-1]
    assert private_path(home).read_bytes() == before


@pytest.mark.parametrize("linked", ["private", "public"])
@pytest.mark.parametrize("target_exists", [False, True], ids=["dangling", "valid"])
def test_p07_a_symlinked_key_file_is_refused_and_never_followed_or_replaced(
    make_setup, home, terminal, tmp_path, linked, target_exists
):
    write_token(home, DUMMY_TOKEN)
    link = private_path(home) if linked == "private" else public_path(home)
    link.unlink()
    target = tmp_path / "target.pem"
    if target_exists:
        target.write_bytes(b"outside")
    link.symlink_to(target)

    for option in (None, "check", REPLACE):
        assert run_setup(make_setup(), option) == 1
        assert "symbolic link" in terminal.said[-1]
        assert link.is_symlink()
    assert (target.read_bytes() if target_exists else None) == (
        b"outside" if target_exists else None
    )
    assert target.exists() == target_exists


def test_p07_a_dangling_destination_is_not_overwritten_by_the_creation(make_setup, home, tmp_path):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    public_path(home).unlink()
    private_path(home).symlink_to(tmp_path / "nowhere")

    assert make_setup().run(renew=False) == 1
    assert private_path(home).is_symlink()
    assert not (tmp_path / "nowhere").exists()


def test_p07_two_runs_at_once_make_one_pair(
    make_setup, setup_module, home, docker, terminal, openssl
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    public_path(home).unlink()
    waiting = threading.Event()
    second = make_setup()
    second.tools = setup_module.Tools(
        run=docker, say=lambda line: waiting.set() if "waiting" in line else None,
        service_uid=os.getuid(), openssl=openssl,
    )  # fmt: skip
    descriptor = os.open(signing_directory(home), os.O_RDONLY | os.O_DIRECTORY)
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    outcome: list[int] = []
    thread = threading.Thread(target=lambda: outcome.append(second.run(renew=False)))
    thread.start()
    assert waiting.wait(timeout=30)
    assert not private_path(home).exists()
    os.close(descriptor)
    thread.join(timeout=60)

    assert outcome == [0]
    assert private_path(home).read_bytes() == sample_pair(1)[0]


def with_a_wrong_private_exponent(key: bytes) -> bytes:
    """The same PEM structure and public fields, a private exponent that fits no other number."""
    der = bytearray(base64.b64decode("".join(key.decode().splitlines()[1:-1])))
    exponent_at = der.index(b"\x02\x03\x01\x00\x01") + 5 + 4  # past e and the header of d
    der[exponent_at + 200] ^= 1
    body = base64.encodebytes(bytes(der)).decode()
    return f"-----BEGIN PRIVATE KEY-----\n{body}-----END PRIVATE KEY-----\n".encode()


def broken_private_contents() -> dict[str, bytes]:
    key = sample_pair(0)[0]
    return {
        "invalid key": with_a_wrong_private_exponent(key),
        "malformed": b"not a key\n",
        "truncated": key[:-60],
        "encrypted": generate_key(
            "-pkeyopt", "rsa_keygen_bits:2048", "-aes256", "-pass", "pass:throwaway"
        ),
        "wrong size": generate_key("-pkeyopt", "rsa_keygen_bits:2048"),
        "wrong exponent": generate_key(
            "-pkeyopt", "rsa_keygen_bits:3072", "-pkeyopt", "rsa_keygen_pubexp:3"
        ),
        "two blocks": key + key,
        "oversized": b"-----BEGIN PRIVATE KEY-----\n"
        + b"A" * 17000
        + b"\n-----END PRIVATE KEY-----\n",
    }


@pytest.fixture(scope="module")
def broken_privates() -> dict[str, bytes]:
    return broken_private_contents()


BROKEN_KINDS = [
    "invalid key",
    "malformed",
    "truncated",
    "encrypted",
    "wrong size",
    "wrong exponent",
    "two blocks",
    "oversized",
]


@pytest.mark.parametrize("kind", BROKEN_KINDS)
def test_p06_a_broken_private_key_is_refused_naming_the_replacement_and_nothing_changes(
    make_setup, home, terminal, openssl, broken_privates, kind
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).write_bytes(broken_privates[kind])
    before = snapshot(home)

    for option in (None, "check"):
        assert run_setup(make_setup(), option) == 1
        assert "agent-service/setup --replace-signing-key" in terminal.said[-1]
        assert str(private_path(home)) in terminal.said[-1]
    assert snapshot(home) == before


@pytest.mark.parametrize(
    "public", [b"not a key\n", sample_pair(1)[1], sample_pair(0)[1] + sample_pair(0)[1]]
)
def test_p06_a_public_half_that_is_malformed_or_not_the_private_keys_is_refused(
    make_setup, home, terminal, public
):
    write_token(home, DUMMY_TOKEN)
    public_path(home).write_bytes(public)
    before = snapshot(home)

    assert make_setup().run(renew=False) == 1
    assert "agent-service/setup --replace-signing-key" in terminal.said[-1]
    assert str(public_path(home)) in terminal.said[-1]
    assert snapshot(home) == before


@pytest.mark.parametrize("fault", ["mode", "no access", "owner", "not regular"])
def test_p06_a_private_key_with_foreign_rights_asks_for_the_operators_own_fix(
    make_setup, home, terminal, fault
):
    write_token(home, DUMMY_TOKEN)
    setup = make_setup(service_uid=os.getuid() + 1 if fault == "owner" else None)
    if fault == "mode":
        private_path(home).chmod(0o644)
    if fault == "no access":
        private_path(home).chmod(0o000)
    if fault == "not regular":
        private_path(home).unlink()
        private_path(home).mkdir()
    before = {path.name: mode_of(path) for path in signing_directory(home).iterdir()}

    assert setup.run(renew=False) == 1
    assert "--replace-signing-key" not in terminal.said[-1]
    assert ("owned by uid" if fault == "owner" else "fix it yourself") in terminal.said[-1]
    assert setup.check() == 1
    assert "cannot tell" not in terminal.said[-1]
    assert {path.name: mode_of(path) for path in signing_directory(home).iterdir()} == before


PRIVATE_MISSING_LINE = (
    "signing/private.pem is missing but public.pem is still there: "
    "`agent-service/setup --replace-signing-key` makes a new pair; "
    "then recreate agent-service and songmaker-web"
)


def test_p32_a_missing_private_key_beside_a_public_one_is_refused_with_one_line(
    make_setup, home, terminal
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    before = snapshot(home)

    assert make_setup().run(renew=False) == 1
    assert terminal.said[-1] == f"agent-service/setup FAILED: {PRIVATE_MISSING_LINE}"
    assert snapshot(home) == before
    assert make_setup().check() == 1
    assert terminal.said[-1] == PRIVATE_MISSING_LINE
    assert snapshot(home) == before


def break_the_pair(home: Path, state: str, broken: dict[str, bytes]) -> None:
    if state == "no access":
        private_path(home).chmod(0o000)
    elif state == "missing private":
        private_path(home).unlink()
    elif state == "malformed private":
        private_path(home).write_bytes(broken["malformed"])
    elif state == "mismatch":
        public_path(home).write_bytes(sample_pair(2)[1])


@pytest.mark.parametrize(
    "state", ["sound", "no access", "missing private", "malformed private", "mismatch"]
)
def test_p33_the_replacement_makes_a_sound_new_pair_and_leaves_no_old_byte_or_printed_key(
    make_setup, home, terminal, broken_privates, state
):
    write_token(home, DUMMY_TOKEN)
    break_the_pair(home, state, broken_privates)
    old_private = sample_pair(0)[0]

    assert make_setup().replace_signing_key() == 0

    assert private_path(home).read_bytes() == sample_pair(1)[0]
    assert public_path(home).read_bytes() == sample_pair(1)[1]
    assert (mode_of(private_path(home)), mode_of(public_path(home))) == (0o600, 0o644)
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]
    assert all(old_private not in path.read_bytes() for path in signing_directory(home).iterdir())
    secret_lines = [line for line in sample_pair(1)[0].decode().splitlines() if len(line) > 40]
    assert not [line for line in terminal.said if any(part in line for part in secret_lines)]
    warning = terminal.said[0]
    assert "replacement alone revokes nothing" in warning
    assert "both recreated" in warning
    assert "agent-service/live_signer.py" in terminal.said[-1]
    assert make_setup().check() == 0


@pytest.mark.parametrize("refusal", ["no terminal", "no yes", "end of input"])
def test_p33_without_a_terminal_or_a_typed_yes_nothing_changes(make_setup, home, terminal, refusal):
    write_token(home, DUMMY_TOKEN)
    terminal.interactive = refusal != "no terminal"
    terminal.answers = {"no terminal": ["yes"], "no yes": ["y"], "end of input": []}[refusal]
    before = snapshot(home)
    setup = make_setup()
    if refusal == "end of input":
        setup.tools = setup.tools.__class__(
            run=setup.tools.run, say=terminal.say, openssl=setup.tools.openssl,
            has_terminal=lambda: True, confirm=lambda prompt: (_ for _ in ()).throw(EOFError()),
            service_uid=os.getuid(),
        )  # fmt: skip

    assert setup.replace_signing_key() == 1
    assert snapshot(home) == before


def test_p33_a_replacement_before_setup_has_made_the_signing_folder_says_to_run_setup_first(
    make_setup, home, terminal
):
    make_login_directory(home)

    assert make_setup().replace_signing_key() == 1
    assert "run agent-service/setup first" in terminal.said[-1]


@pytest.mark.parametrize("fault", ["is rejected", "fails check"])
def test_p34_r0_a_failing_generation_leaves_the_active_pair_byte_identical(
    make_setup, home, openssl, fault
):
    write_token(home, DUMMY_TOKEN)
    if fault == "is rejected":
        openssl.failing = {"genpkey": 1}
    else:
        openssl.generated = [b"not a key\n"]
    before = snapshot(home)

    assert make_setup().replace_signing_key() == (2 if fault == "is rejected" else 1)
    after = snapshot(home)
    assert {name: after[name] for name in before if name in ("private.pem", "public.pem")} == {
        name: before[name] for name in ("private.pem", "public.pem")
    }
    assert set(after) - set(before) <= {"private.next.pem", "public.next.pem"}
    assert make_setup().check() == (0 if fault == "is rejected" else 1)
    assert make_setup().run(renew=False) == 0
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]


def test_p34_r0_a_failing_public_derivation_leaves_the_pair_and_only_clearable_leftovers(
    make_setup, home, openssl
):
    write_token(home, DUMMY_TOKEN)
    openssl.failing = {"pkey -pubout": 1}
    before = snapshot(home)

    assert make_setup().replace_signing_key() == 2
    assert snapshot(home)["private.pem"] == before["private.pem"]
    assert snapshot(home)["public.pem"] == before["public.pem"]
    openssl.failing = {}
    assert make_setup().run(renew=False) == 0
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]


@pytest.mark.parametrize(
    "forged",
    [b"garbage\n", sample_pair(2)[1]],
    ids=["malformed", "another key's"],
)
def test_p34_r0_a_public_candidate_that_is_no_public_half_of_the_candidate_stops_in_r0(
    make_setup, home, openssl, forged
):
    write_token(home, DUMMY_TOKEN)
    openssl.forged = {"pkey -pubout": forged}
    before = snapshot(home)

    assert make_setup().replace_signing_key() == 1
    after = snapshot(home)
    assert {name: after[name] for name in ("private.pem", "public.pem")} == {
        name: before[name] for name in ("private.pem", "public.pem")
    }
    assert set(after) - set(before) <= {"private.next.pem", "public.next.pem"}


def test_p34_r1_a_new_private_key_beside_the_old_public_one_is_refused_until_replaced_again(
    make_setup, home, terminal
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).write_bytes(sample_pair(2)[0])
    (signing_directory(home) / "public.next.pem").write_bytes(sample_pair(2)[1])
    before = snapshot(home)

    assert make_setup().check() == 1
    assert "agent-service/setup --replace-signing-key" in terminal.said[-1]
    assert make_setup().run(renew=False) == 1
    assert "agent-service/setup --replace-signing-key" in terminal.said[-1]
    assert snapshot(home) == before

    assert make_setup().replace_signing_key() == 0
    assert private_path(home).read_bytes() == sample_pair(1)[0]
    assert private_path(home).read_bytes() != sample_pair(2)[0]
    assert public_path(home).read_bytes() == sample_pair(1)[1]
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.pem",
        "public.pem",
    ]
    assert make_setup().check() == 0


def test_p34_leftovers_beside_a_sound_pair_are_cleared_by_plain_setup_and_fail_the_check(
    make_setup, home, terminal
):
    write_token(home, DUMMY_TOKEN)
    (signing_directory(home) / "private.next.pem").write_bytes(b"candidate")

    assert make_setup().check() == 1
    assert "private.next.pem" in terminal.said[-1]
    assert make_setup().run(renew=False) == 0
    assert any("removed leftovers" in line for line in terminal.said)
    assert make_setup().check() == 0


LEFTOVER_NAMES = ["private.pem.new", "public.pem.new", "private.next.pem", "public.next.pem"]


@pytest.mark.parametrize("name", LEFTOVER_NAMES)
@pytest.mark.parametrize("kind", ["symlink", "folder"])
def test_p07_a_temporary_entry_that_is_a_link_or_no_file_is_refused_and_never_unlinked(
    make_setup, home, terminal, tmp_path, name, kind
):
    write_token(home, DUMMY_TOKEN)
    entry = signing_directory(home) / name
    outside = tmp_path / "outside.pem"
    outside.write_bytes(b"outside")
    if kind == "symlink":
        entry.symlink_to(outside)
    else:
        entry.mkdir()

    for option in (None, "check", REPLACE):
        assert run_setup(make_setup(), option) == 1
        assert str(entry) in terminal.said[-1]
        assert entry.is_symlink() == (kind == "symlink")
        assert entry.exists()
    assert outside.read_bytes() == b"outside"
    assert sorted(path.name for path in signing_directory(home).iterdir()) == sorted(
        ["private.pem", "public.pem", name]
    )


PREFLIGHT_STATES = ["renew", "token missing", "signing folder open", "image not built"]


@pytest.mark.parametrize("state", PREFLIGHT_STATES)
def test_p06_a_refused_signing_key_means_setup_changed_nothing_else_either(
    make_setup, home, terminal, docker, broken_privates, state
):
    write_token(home, DUMMY_TOKEN)
    private_path(home).write_bytes(broken_privates["malformed"])
    token_before = token_path(home).read_bytes()
    terminal.pastes = [SECOND_TOKEN]
    if state == "token missing":
        token_path(home).unlink()
    if state == "signing folder open":
        signing_directory(home).chmod(0o755)
    if state == "image not built":
        docker.images.clear()
    before = snapshot(home)
    folder_mode = mode_of(signing_directory(home))

    assert make_setup().run(renew=state == "renew") == 1
    assert str(private_path(home)) in terminal.said[-1]
    assert terminal.prompts == []
    assert docker.builds() == []
    assert snapshot(home) == before
    assert mode_of(signing_directory(home)) == folder_mode
    assert token_path(home).exists() == (state != "token missing")
    if state != "token missing":
        assert token_path(home).read_bytes() == token_before


def test_p34_plain_setup_clears_replacement_leftovers_only_beside_a_sound_pair(make_setup, home):
    write_token(home, DUMMY_TOKEN)
    private_path(home).unlink()
    public_path(home).unlink()
    for name in ("private.next.pem", "public.next.pem"):
        (signing_directory(home) / name).write_bytes(b"candidate")

    assert make_setup().run(renew=False) == 0
    assert sorted(path.name for path in signing_directory(home).iterdir()) == [
        "private.next.pem",
        "private.pem",
        "public.next.pem",
        "public.pem",
    ]
    assert make_setup().check() == 1

    assert make_setup().run(renew=False) == 0
    assert make_setup().check() == 0
