"""The in-container census (#339 lane C3, agent-runtime#440's secret-safety contract).

Pure tests on temporary trees: nothing here needs a container. The contract lines they prove:
1 nothing leaves before `Names`, 2 the mount table and the descriptor-relative walk, 3 one
content read.
"""

from __future__ import annotations

import json
import os
import re
import socket
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from support.script_module import loaded_script

PROGRAM = Path(__file__).resolve().parent.parent / "agent-service" / "tree_census.py"
KEY = bytes(range(32))
SOCKS_UID = 1000
OPAQUE = re.compile(r"n-[0-9a-f]{8}")
TOKEN = b"sk-ant-oat01-Zq_9-aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"
GRAMMAR = re.compile(
    r"(?:(?:system-prompt|relay-mcp\.json|\.claude|/tmp|home|work|cc-socks-1000"
    r"|agent-run-<8>|n-[0-9a-f]{8}))(?:/(?:system-prompt|relay-mcp\.json|\.claude|home|work"
    r"|cc-socks-1000|agent-run-<8>|n-[0-9a-f]{8}))*"
)


@pytest.fixture(scope="module")
def census() -> Iterator[ModuleType]:
    yield from loaded_script("agent_probe_tree_census", PROGRAM)


@pytest.fixture
def names(census: ModuleType):
    return census.Names(KEY, SOCKS_UID)


HOSTILE = [
    TOKEN.decode(),
    TOKEN.decode()[:20],
    TOKEN.decode()[-20:],
    "aB3_x-Q9" * 5 + "abc",
    "a--b__c---d___e",
    "line\nbreak",
    "\x1b[31mred",
    "tab\there",
    "system-prompt.bak",
    "home2",
    "cc-socks-1000x",
    "cc-socks-",
    "cc-socks-1001",
    "cc-socks-01000",
    "cc-socks-0" + str(int.from_bytes(TOKEN, "big")),
    "agent-run-a\nb",
    "agent-run-",
    "agent-run-Q",
    "agent-run-Ab3xYz9",
    "agent-run-Ab3xYz901",
    "work/",
    "tmp",
    "\udcff\udcfe",
]


@pytest.mark.parametrize(
    "name", ["system-prompt", "relay-mcp.json", ".claude", "home", "work", "cc-socks-1000"]
)
def test_structural_names_are_shown_as_they_are(names, name: str) -> None:
    assert names.show(name) == name


def test_only_the_tmp_mount_is_shown_as_its_path(names) -> None:
    assert names.show_mount("/tmp") == "/tmp" != names.show_mount("/tmp/inner")  # noqa: S108 - a mount point of the scenario and never a path this test creates


def test_the_run_tree_is_shown_without_its_suffix(names) -> None:
    assert names.show("agent-run-Ab3_-xYz") == "agent-run-<8>"


@pytest.mark.parametrize("name", HOSTILE)
def test_every_other_name_becomes_an_opaque_id(names, name: str) -> None:
    shown = names.show(name)
    assert OPAQUE.fullmatch(shown)
    assert name not in shown


def test_opaque_ids_are_stable_per_key_and_differ_across_keys(census: ModuleType, names) -> None:
    other = census.Names(bytes(32), SOCKS_UID)
    assert names.show("alpha") == names.show("alpha") == names.show(b"alpha")
    assert names.show("alpha") != other.show("alpha")
    assert names.show("alpha") != names.show("beta")


def hostile_tree(root: Path) -> None:
    (root / "home").mkdir()
    for name in [*HOSTILE, os.fsdecode(b"\xff\xfe")]:
        if "/" not in name:
            (root / "home" / name).write_bytes(b"x")
    (root / "agent-run-Ab3xYz90").mkdir()
    (root / "agent-run-Ab3xYz90" / "work").mkdir()


def test_a_hostile_tree_is_shown_in_the_closed_grammar_only(
    census: ModuleType, names, tmp_path: Path
) -> None:
    hostile_tree(tmp_path)
    result = walk(census, names, tmp_path)
    shown = [item.path for item in result.listings]
    assert len(shown) > 10
    assert all(GRAMMAR.fullmatch(path) for path in shown)
    assert "agent-run-<8>/work" in shown


def test_the_grammar_check_fails_when_names_is_bypassed(
    census: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hostile_tree(tmp_path)
    monkeypatch.setattr(census.Names, "show", lambda self, component: os.fsdecode(component))
    result = walk(census, census.Names(KEY, SOCKS_UID), tmp_path)
    assert not all(GRAMMAR.fullmatch(item.path) for item in result.listings)


MOUNTINFO = b"\n".join(
    [
        b"20 1 0:18 / / rw,relatime - overlay overlay rw,lowerdir=/a",
        b"21 20 0:19 / /proc rw,nosuid - proc proc rw",
        b"22 20 0:20 / /tmp rw,nosuid - tmpfs tmpfs rw",
        b"23 22 0:21 /x /tmp/ro\\040dir ro,relatime - tmpfs tmpfs rw",
        b"24 22 0:22 / /tmp/inner rw - tmpfs tmpfs ro",
        b"25 20 0:23 / /sys/fs/cgroup rw - cgroup2 cgroup rw",
        b"26 20 0:24 / /run/escaped\\040space rw - ext4 /dev/sda rw",
        b"27 20 0:25 / /dev/shm rw - tmpfs shm ro",
        b"garbage line",
        b"1 2 3 4 5 - ",
        b"",
    ]
)


def test_only_mounts_with_rw_in_their_own_options_are_writable(census: ModuleType) -> None:
    points = {mount.point for mount in census.writable_mounts(MOUNTINFO)}
    assert points == {"/", "/tmp", "/tmp/inner", "/run/escaped space", "/dev/shm"}  # noqa: S108 - a mount point of the scenario and never a path this test creates


def test_a_read_only_bind_over_rw_and_pseudo_filesystems_are_left_out(census: ModuleType) -> None:
    points = {mount.point for mount in census.writable_mounts(MOUNTINFO)}
    assert not points & {"/tmp/ro dir", "/proc", "/sys/fs/cgroup"}  # noqa: S108 - a mount point of the scenario and never a path this test creates


def test_nested_mount_points_are_reported_relative_to_the_walked_mount(census: ModuleType) -> None:
    by_point = {mount.point: mount for mount in census.writable_mounts(MOUNTINFO)}
    assert by_point["/tmp"].nested == {("ro dir",), ("inner",)}  # noqa: S108 - a mount point of the scenario and never a path this test creates
    assert ("tmp", "inner") in by_point["/"].nested
    assert by_point["/dev/shm"].nested == frozenset()  # noqa: S108 - a mount point of the scenario and never a path this test creates


def walk(census: ModuleType, names, root: Path, **rules):
    device = root.stat().st_dev if root.exists() else 0
    return census.census_mount(
        census.WritableMount(
            str(root), rules.pop("nested", frozenset()), (os.major(device), os.minor(device))
        ),
        names,
        census.WalkRules(**rules),
    )


def kinds(result) -> dict[str, str]:
    return {item.path: item.kind for item in result.listings}


def test_a_symlink_is_listed_as_a_link_and_never_followed(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "secret").mkdir()
    (tmp_path / "secret" / "inner").write_bytes(b"x")
    (tmp_path / "to-dir").symlink_to(tmp_path / "secret")
    (tmp_path / "to-root").symlink_to("/")
    result = walk(census, names, tmp_path)
    assert sorted(kinds(result).values()) == ["d", "f", "l", "l"]


def test_a_fifo_that_would_block_an_open_does_not_stop_the_walk(
    census: ModuleType, names, tmp_path: Path
) -> None:
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "later").write_bytes(b"x")
    result = walk(census, names, tmp_path, token=TOKEN)
    assert sorted(kinds(result).values()) == ["f", "p"]
    assert result.skips == {}


def test_a_socket_is_listed_by_type_letter(census: ModuleType, names, tmp_path: Path) -> None:
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(tmp_path / "s"))
        assert list(kinds(walk(census, names, tmp_path)).values()) == ["s"]


@pytest.mark.parametrize(("mode", "letter"), [(0o20600, "c"), (0o60600, "b")])
def test_device_nodes_get_their_type_letters(census: ModuleType, mode: int, letter: str) -> None:
    assert census.kind_letter(mode) == letter
    assert census.kind_letter(0) == "?"


def test_a_nested_mount_point_is_skipped_and_counted(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "inner").mkdir()
    (tmp_path / "inner" / "hidden").write_bytes(b"x")
    result = walk(census, names, tmp_path, nested=frozenset({("inner",)}))
    assert result.skips == {"nested mount skipped": 1}
    assert len(result.listings) == 1


@pytest.mark.parametrize("swap", ["symlink", "directory"])
def test_a_directory_swapped_before_it_is_opened_fails_closed(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, swap: str
) -> None:
    (tmp_path / "victim").mkdir()
    (tmp_path / "victim" / "old").write_bytes(b"x")
    real = census._open_child

    def swap_then_open(name: str, parent_fd: int) -> int:
        if name == "victim":
            os.rename(tmp_path / name, tmp_path / "moved")
            if swap == "symlink":
                os.symlink(tmp_path / "moved", tmp_path / name)
            else:
                os.mkdir(tmp_path / name)
        return real(name, parent_fd)

    monkeypatch.setattr(census, "_open_child", swap_then_open)
    result = walk(census, names, tmp_path)
    assert (result.skips, len(result.listings)) == ({"replaced": 1}, 1)


def test_an_entry_that_vanishes_after_the_listing_is_counted(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "gone").write_bytes(b"x")
    real = os.stat

    def stat_after_removal(path, *args, **kwargs):
        if path == "gone":
            os.unlink(tmp_path / "gone")
        return real(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", stat_after_removal)
    assert walk(census, names, tmp_path).skips == {"vanished": 1}


def test_a_file_that_vanishes_before_its_content_read_is_counted_as_skipped(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "f").write_bytes(TOKEN)
    real = census.count_token

    def count_after_removal(directory_fd: int, name: str, listed, token: bytes):
        os.unlink(tmp_path / name)
        return real(directory_fd, name, listed, token)

    monkeypatch.setattr(census, "count_token", count_after_removal)
    result = walk(census, names, tmp_path, token=TOKEN)
    assert (result.token_files, result.skips) == (0, {"vanished": 1})


def test_a_directory_that_cannot_be_listed_is_refused(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "sub").mkdir()

    def refuse(descriptor):
        raise PermissionError

    monkeypatch.setattr(os, "scandir", refuse)
    assert walk(census, names, tmp_path).skips == {"refused": 1}


def test_a_mount_point_that_cannot_be_opened_is_refused(
    census: ModuleType, names, tmp_path: Path
) -> None:
    assert walk(census, names, tmp_path / "missing").skips == {"refused": 1}


def test_a_tree_deeper_than_the_limit_stops_and_says_so(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(census, "MAXIMUM_DEPTH", 3)
    path = tmp_path
    for _ in range(5):
        path = path / "d"
        path.mkdir()
    result = walk(census, names, tmp_path)
    assert result.skips == {"too deep": 1}
    assert len(result.listings) == 3


def test_a_file_replaced_between_listing_and_read_is_refused_before_reading(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "f").write_bytes(b"x")
    real = census.count_token

    def count_after_replacement(directory_fd: int, name: str, listed, token: bytes):
        (tmp_path / "successor").write_bytes(TOKEN)
        os.replace(tmp_path / "successor", tmp_path / name)
        return real(directory_fd, name, listed, token)

    monkeypatch.setattr(census, "count_token", count_after_replacement)
    result = walk(census, names, tmp_path, token=TOKEN)
    assert (result.token_files, result.skips) == (0, {"replaced": 1})


def test_a_nested_file_mount_is_skipped_before_any_content_read(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "bind-file").write_bytes(TOKEN)
    (tmp_path / "plain").write_bytes(TOKEN)

    def reads_only_the_plain_file(directory_fd: int, name: str, listed, token: bytes):
        assert name == "plain"
        return census.TokenRead.FOUND

    monkeypatch.setattr(census, "count_token", reads_only_the_plain_file)
    result = walk(census, names, tmp_path, nested=frozenset({("bind-file",)}), token=TOKEN)
    assert (result.token_files, result.skips) == (1, {"nested mount skipped": 1})


def test_a_directory_on_another_device_is_a_nested_mount_even_without_its_name(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "foreign").mkdir()
    (tmp_path / "foreign" / "hidden").write_bytes(b"x")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        outcome = census.Census()
        rules = census.WalkRules(root_device=tmp_path.stat().st_dev + 1)
        census._walk(descriptor, (), names, rules, outcome)
    finally:
        os.close(descriptor)
    assert outcome.skips == {"nested mount skipped": 1}
    assert len(outcome.listings) == 1


def test_the_mount_root_is_not_acquired_through_a_symlinked_ancestor(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "real" / "mount").mkdir(parents=True)
    (tmp_path / "real" / "mount" / "inside").write_bytes(b"x")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    result = walk(census, names, tmp_path / "link" / "mount")
    assert result.skips == {"replaced": 1}
    assert result.listings == []


def test_a_root_component_replaced_by_a_directory_on_the_same_device_fails_closed(
    census: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "up" / "mount").mkdir(parents=True)
    (tmp_path / "up" / "mount" / "old").write_bytes(b"x")
    real = census._open_child

    def replace_then_open(name: str, parent_fd: int) -> int:
        if name == "mount":
            os.rename(tmp_path / "up" / name, tmp_path / "moved")
            os.mkdir(tmp_path / "up" / name)
        return real(name, parent_fd)

    monkeypatch.setattr(census, "_open_child", replace_then_open)
    result = walk(census, names, tmp_path / "up" / "mount")
    assert (result.skips, result.listings) == ({"replaced": 1}, [])


def test_a_file_mount_is_left_out_and_never_read(census: ModuleType, names, tmp_path: Path) -> None:
    (tmp_path / "hosts").write_bytes(TOKEN)
    result = walk(census, names, tmp_path / "hosts", token=TOKEN)
    assert (result.skips, result.listings, result.token_files) == ({"file mount": 1}, [], 0)


def test_a_mount_root_whose_device_is_not_the_mounts_fails_closed(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "inside").write_bytes(b"x")
    device = tmp_path.stat().st_dev
    wrong = (os.major(device), os.minor(device) + 1)
    result = census.census_mount(
        census.WritableMount(str(tmp_path), frozenset(), wrong), names, census.WalkRules()
    )
    assert (result.skips, result.listings) == ({"replaced": 1}, [])


def count(census: ModuleType, descriptor: int, name: str, token: bytes, chunk: int = 7):
    """The token read of `name` as the walk makes it: with the identity the listing saw."""
    try:
        listed = census._identity(os.stat(name, dir_fd=descriptor, follow_symlinks=False))
    except FileNotFoundError:
        listed = (0, 0)
    return census.count_token(descriptor, name, listed, token, chunk)


def write_and_count(census: ModuleType, tmp_path: Path, content: bytes, chunk: int = 7) -> str:
    (tmp_path / "f").write_bytes(content)
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        return count(census, descriptor, "f", TOKEN, chunk).value
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("split", [1, 10, len(TOKEN) - 1])
def test_a_token_split_across_a_chunk_boundary_is_found(
    census: ModuleType, tmp_path: Path, split: int
) -> None:
    padding = b"." * (7 - split % 7)
    assert write_and_count(census, tmp_path, padding + TOKEN + b"tail") == "found"
    assert write_and_count(census, tmp_path, b"." * split + TOKEN) == "found"


def test_a_token_in_a_file_larger_than_the_chunk_is_found_even_twice(
    census: ModuleType, tmp_path: Path
) -> None:
    assert write_and_count(census, tmp_path, b"z" * 100 + TOKEN + b"z" * 100 + TOKEN) == "found"


def test_a_file_without_the_token_is_absent_even_with_a_near_miss(
    census: ModuleType, tmp_path: Path
) -> None:
    assert write_and_count(census, tmp_path, TOKEN[:-1] + b"!" + b"x" * 40) == "absent"


def test_a_one_byte_token_needs_no_overlap(census: ModuleType, tmp_path: Path) -> None:
    (tmp_path / "f").write_bytes(b"abc")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert count(census, descriptor, "f", b"c", 2).value == "found"
    finally:
        os.close(descriptor)


def test_an_empty_token_is_refused_up_front(census: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        census.count_token(0, "f", (0, 0), b"")


def test_non_regular_missing_and_linked_files_are_never_read(
    census: ModuleType, tmp_path: Path
) -> None:
    os.mkfifo(tmp_path / "pipe")
    (tmp_path / "target").write_bytes(TOKEN)
    (tmp_path / "link").symlink_to(tmp_path / "target")
    descriptor = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        outcomes = {
            name: count(census, descriptor, name, TOKEN).value
            for name in ("pipe", "link", "missing")
        }
    finally:
        os.close(descriptor)
    assert outcomes == {"pipe": "not regular", "link": "refused", "missing": "vanished"}


def test_a_read_error_after_the_open_is_refused(
    census: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail(descriptor, size):
        raise OSError

    monkeypatch.setattr(os, "read", fail)
    assert write_and_count(census, tmp_path, b"abc") == "refused"


def test_the_walk_counts_files_holding_the_token_and_skips_by_reason(
    census: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "a").write_bytes(b"x" + TOKEN)
    (tmp_path / "b").write_bytes(b"nothing")
    (tmp_path / "c").symlink_to(tmp_path / "a")
    result = walk(census, names, tmp_path, token=TOKEN)
    assert (result.token_files, result.skips) == (1, {})


@pytest.mark.parametrize(
    "settings_text", [TOKEN.decode(), json.dumps({"mode": "census", "key": KEY.hex()})]
)
def test_emit_reports_a_failure_without_its_text(
    census: ModuleType, capsys: pytest.CaptureFixture[str], settings_text: str
) -> None:
    census.emit(settings_text)
    assert json.loads(capsys.readouterr().out) == {"error": "failed"}


def test_the_walk_uses_none_of_the_path_following_calls() -> None:
    source = PROGRAM.read_text()
    forbidden = [
        r"os\.walk",
        r"rglob",
        r"realpath",
        r"readlink",
        r"(?<![\w.])open\(",
        r"print\(",
        r"repr\(",
        r"\bstr\(",
        r"logging",
    ]
    assert [pattern for pattern in forbidden if re.search(pattern, source)] == []
