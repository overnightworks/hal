"""The retention census (#814, S1c of #299): the in-container retention mode of `tree_census.py`
and the host side in `retention_census.py`. Pure tests on temporary trees and a fake command
runner: nothing here needs a container."""

from __future__ import annotations

import ast
import io
import json
import os
import tarfile
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
import yaml
from support.probe_support import probe_imports

KEY = bytes(range(32))
REQUEST, ANSWER = "req-7f3a9c41d2e85b06", "ans-0b6d1e94a7c35f28"
LITELLM_CONFIG = Path(__file__).resolve().parents[1] / "agent-service/litellm/config.yaml"


@pytest.fixture(scope="module")
def tree() -> Iterator[ModuleType]:
    with probe_imports():
        import tree_census

        yield tree_census


@pytest.fixture
def names(tree: ModuleType):
    return tree.Names(KEY, 1000)


def table_with(mount: Path, *extra: str) -> bytes:
    """A mount table whose one tmpfs sits at `mount`, with the device the directory really has."""
    device = mount.stat().st_dev
    ours = f"30 20 {os.major(device)}:{os.minor(device)} / {mount} rw - tmpfs tmpfs rw"
    return "\n".join(["20 1 0:18 / / ro - overlay overlay ro", ours, *extra]).encode()


def settings(*known: str) -> dict:
    return {"known": list(known), "tokens": {"request": REQUEST, "answer": ANSWER}}


def test_the_retention_report_counts_each_token_by_label_in_the_regular_files_of_a_mount(
    tree: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "deep").mkdir()
    (tmp_path / "deep" / "log").write_text(f"before {REQUEST} after")
    (tmp_path / "other").write_text("nothing here")

    report = tree.retention_report(settings(str(tmp_path)), names, table_with(tmp_path))

    (mount,) = report["mounts"]
    assert (mount["mount"], mount["found"], mount["skips"]) == (
        str(tmp_path),
        {"request": 1, "answer": 0},
        {},
    )


@pytest.mark.parametrize("refused_token", [REQUEST, ANSWER])
def test_a_skip_that_only_one_tokens_walk_met_stays_in_the_report(
    tree: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refused_token: str
) -> None:
    (tmp_path / "log").write_text("nothing here")
    walk = tree.census_mount

    def refused_for_one_token(mount, shown_names, rules):
        census = walk(mount, shown_names, rules)
        if rules.token == refused_token.encode():
            census.skip(tree.Skip.REFUSED)
        return census

    monkeypatch.setattr(tree, "census_mount", refused_for_one_token)

    report = tree.retention_report(settings(str(tmp_path)), names, table_with(tmp_path))

    assert report["mounts"][0]["skips"] == {tree.Skip.REFUSED.value: 1}


def test_a_skip_every_walk_met_counts_once_for_the_entry_it_names(
    tree: ModuleType, names, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    walk = tree.census_mount

    def always_refused(mount, shown_names, rules):
        census = walk(mount, shown_names, rules)
        census.skip(tree.Skip.REFUSED)
        return census

    monkeypatch.setattr(tree, "census_mount", always_refused)

    report = tree.retention_report(settings(str(tmp_path)), names, table_with(tmp_path))

    assert report["mounts"][0]["skips"] == {tree.Skip.REFUSED.value: 1}


def test_the_retention_report_applies_no_login_exclusion(
    tree: ModuleType, names, tmp_path: Path
) -> None:
    (tmp_path / "login").mkdir()
    (tmp_path / "login" / "token").write_text(ANSWER)

    report = tree.retention_report(settings(str(tmp_path)), names, table_with(tmp_path))

    assert (report["mounts"][0]["found"]["answer"], report["mounts"][0]["skips"]) == (1, {})


def test_the_retention_report_lists_the_whole_mount_table_before_any_filter(
    tree: ModuleType, names, tmp_path: Path
) -> None:
    extra = (
        "21 20 0:19 / /proc rw - proc proc rw",
        "22 20 0:50 / /srv/customer-name rw - ext4 /dev/sda rw",
    )

    report = tree.retention_report(settings(str(tmp_path)), names, table_with(tmp_path, *extra))

    table = {point: (filesystem, writable) for point, filesystem, writable in report["table"]}
    assert table["/proc"] == ("proc", True)
    assert table[str(tmp_path)] == ("tmpfs", True)
    opaque = [point for point in table if point.startswith("n-")]
    assert sorted(table[point] for point in opaque) == [("ext4", True), ("overlay", False)]
    assert "/srv/customer-name" not in json.dumps(report)


def test_a_mount_entry_keeps_pseudo_and_read_only_mounts_that_the_writable_list_drops(
    tree: ModuleType,
) -> None:
    text = b"21 20 0:19 / /proc rw - proc proc rw\n22 20 0:20 / /ro ro - tmpfs tmpfs rw"

    entries = [(e.point, e.filesystem, e.writable) for e in tree.mount_entries(text)]

    assert entries == [("/proc", "proc", True), ("/ro", "tmpfs", False)]
    assert tree.writable_mounts(text) == ()


def test_the_retention_mode_answers_through_run_with_the_table_and_the_mounts(
    tree: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "file").write_text(REQUEST)
    mountinfo = table_with(tmp_path)
    monkeypatch.setattr(tree, "_read_small", lambda path, directory_fd=None: mountinfo)
    asked = {"key": KEY.hex(), "mode": "retention", **settings(str(tmp_path))}

    report = tree.run(json.dumps(asked))

    assert report["mounts"][0]["found"] == {"request": 1, "answer": 0}


def test_the_program_sent_to_a_container_calls_emit_with_exactly_the_settings(
    tree: ModuleType,
) -> None:
    asked = {"key": KEY.hex(), "mode": "retention", "tokens": {"request": 'it\'s "q"'}}

    text = tree.program(asked)

    call = ast.parse(text.splitlines()[-1]).body[0].value
    assert (call.func.id, json.loads(ast.literal_eval(call.args[0]))) == ("emit", asked)


# --- the host side: retention_census.py ---------------------------------------------------------

LOG_CLEAN = b"INFO started\n"


@pytest.fixture(scope="module")
def retention() -> Iterator[ModuleType]:
    with probe_imports():
        import retention_census

        yield retention_census


def tar_of(files: dict[str, bytes], devices: tuple[str, ...] = ()) -> bytes:
    """A tar stream of regular `files` and character devices, as `tar -c` prints it."""
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as bundle:
        for name, content in files.items():
            member = tarfile.TarInfo(name)
            member.size = len(content)
            bundle.addfile(member, io.BytesIO(content))
        for name in devices:
            device = tarfile.TarInfo(name)
            device.type = tarfile.CHRTYPE
            bundle.addfile(device)
    return out.getvalue()


class FakeDocker:
    """The commands of the census answered from a table keyed by the command."""

    def __init__(self, retention: ModuleType, answers: dict[tuple[str, ...], tuple[int, bytes]]):
        self.completed = retention.Completed
        self.answers = answers
        self.calls: list[tuple[tuple[str, ...], bytes | None]] = []

    def __call__(self, command, stdin=None):
        self.calls.append((tuple(command), stdin))
        return self.completed(*self.answers.get(tuple(command), (1, b"")))


FRONT_TABLE = b"\n".join(
    [
        b"20 1 0:18 / / ro - overlay overlay ro",
        b"21 20 0:19 / /proc rw - proc proc rw",
        b"22 20 0:20 / /dev rw - tmpfs tmpfs rw",
        b"23 22 0:21 / /dev/shm rw - tmpfs shm rw",
        b"24 22 0:22 / /dev/pts rw - devpts devpts rw",
        b"25 21 0:23 / /proc/kcore rw - tmpfs tmpfs rw",
        b"26 20 0:24 / /etc/hosts rw - ext4 /dev/sda rw",
    ]
)


def inspect_answer(mounts=(), tmpfs=None, masked=("/proc/kcore",), driver="json-file") -> bytes:
    document = {
        "Mounts": [{"Destination": point, "RW": writable} for point, writable in mounts],
        "HostConfig": {
            "Tmpfs": tmpfs,
            "MaskedPaths": list(masked),
            "LogConfig": {"Type": driver},
        },
    }
    return json.dumps([document]).encode()


def front_answers(shared: bytes = b"-", **replaced: tuple[int, bytes]) -> dict:
    return {
        ("docker", "inspect", "front"): (0, inspect_answer([("/etc/traefik/traefik.yml", False)])),
        ("docker", "exec", "front", "cat", "/proc/1/mountinfo"): (0, FRONT_TABLE),
        ("docker", "exec", "front", "tar", "-c", "/dev"): (0, tar_of({"dev/null": b""})),
        ("docker", "exec", "front", "tar", "-c", "/dev/shm"): (0, tar_of({"dev/shm/x": shared})),
        ("docker", "exec", "front", "tar", "-c", "/etc/hosts"): (0, tar_of({"hosts": b"-"})),
        ("docker", "logs", "front"): (0, LOG_CLEAN),
    } | {tuple(key.split()): value for key, value in replaced.items()}


def sweep_of(retention: ModuleType, answers: dict, *targets):
    docker = FakeDocker(retention, answers)
    census = retention.Census(docker, KEY)
    return census.sweep(targets or (retention.Target("front", has_python=False),), TOKENS), docker


TOKENS = {"request": REQUEST, "answer": ANSWER}


def test_a_canary_in_a_regular_file_of_a_containers_dev_shm_is_found_by_label(retention) -> None:
    sweep, _ = sweep_of(retention, front_answers(shared=REQUEST.encode()))

    assert (sweep.found, sweep.problems) == ({"request": ("front /dev/shm",)}, ())


def test_a_clean_container_without_python_is_searched_and_inventoried_in_every_sink(retention):
    sweep, _ = sweep_of(retention, front_answers())

    assert sweep.problems == ()
    assert sweep.found == {}
    assert sweep.inventory["front"] == (
        "/dev tmpfs",
        "/dev/shm tmpfs",
        "/etc/hosts ext4",
        "log json-file",
    )


def test_a_canary_in_the_log_of_a_container_is_found_as_the_log(retention) -> None:
    answers = front_answers(**{"docker logs front": (0, b"GET /" + ANSWER.encode() + b" 404\n")})

    sweep, _ = sweep_of(retention, answers)

    assert sweep.found == {"answer": ("front log",)}


def test_a_canary_on_the_standard_error_of_a_container_is_found_in_its_log(retention) -> None:
    docker = FakeDocker(retention, front_answers())
    docker.answers[("docker", "logs", "front")] = (0, LOG_CLEAN, ANSWER.encode())

    sweep = retention.Census(docker, KEY).sweep((retention.Target("front", False),), TOKENS)

    assert sweep.found == {"answer": ("front log",)}


def test_a_log_that_cannot_be_read_is_an_unexamined_sink(retention) -> None:
    sweep, _ = sweep_of(retention, front_answers(**{"docker logs front": (1, b"")}))

    assert sweep.problems == ("front: the log could not be read",)


def test_a_device_node_in_a_mount_is_listed_by_the_archive_and_never_read(retention) -> None:
    archived = tar_of({"dev/null": b""}, devices=("dev/zero",))

    found, problems = retention.search_archive(archived, TOKENS)

    assert (found, problems) == (set(), [])


def test_a_file_over_the_size_bound_is_an_unexamined_sink(retention, monkeypatch) -> None:
    monkeypatch.setattr(retention, "MAXIMUM_ARCHIVED_FILE", 3)

    found, problems = retention.search_archive(tar_of({"big": b"abcd"}), TOKENS)

    assert (found, problems) == (set(), ["a file over the size bound"])


def test_a_truncated_archive_is_an_unexamined_sink(retention) -> None:
    whole = tar_of({"a": REQUEST.encode() * 100})

    _, problems = retention.search_archive(whole[:700], TOKENS)

    assert problems == ["an archive that could not be read completely"]


def test_a_failing_archive_command_is_an_unexamined_sink(retention) -> None:
    answers = front_answers(**{"docker exec front tar -c /dev/shm": (2, b"")})

    sweep, _ = sweep_of(retention, answers)

    assert sweep.problems == ("front /dev/shm: the archive command failed",)


def test_a_container_without_tar_is_read_with_docker_cp(retention) -> None:
    answers = front_answers(
        **{
            "docker exec front tar -c /etc/hosts": (127, b""),
            "docker cp front:/etc/hosts -": (0, tar_of({"hosts": ANSWER.encode()})),
        }
    )

    sweep, _ = sweep_of(retention, answers)

    assert sweep.found == {"answer": ("front /etc/hosts",)}


def test_a_writable_mount_that_nothing_accounts_for_fails(retention) -> None:
    table = FRONT_TABLE + b"\n27 20 0:25 / /srv/data rw - ext4 /dev/sdb rw"
    answers = front_answers(
        **{
            "docker exec front cat /proc/1/mountinfo": (0, table),
            "docker exec front tar -c /srv/data": (0, tar_of({"data": b"-"})),
        }
    )

    sweep, _ = sweep_of(retention, answers)

    assert sweep.problems == ("front: a writable ext4 mount at /srv/data is not accounted for",)


def test_an_inspected_writable_mount_missing_from_the_table_fails(retention) -> None:
    answers = front_answers(
        **{"docker inspect front": (0, inspect_answer([("/data", True)]))},
    )

    sweep, _ = sweep_of(retention, answers)

    assert sweep.problems == (
        "front: the inspected writable mount /data is not in the mount table",
    )


def test_an_inspected_tmpfs_is_accounted_for_and_searched(retention) -> None:
    table = FRONT_TABLE + b"\n27 20 0:25 / /tmp rw - tmpfs tmpfs rw"
    answers = front_answers(
        **{
            "docker inspect front": (0, inspect_answer(tmpfs={"/tmp": "size=1m"})),
            "docker exec front cat /proc/1/mountinfo": (0, table),
            "docker exec front tar -c /tmp": (0, tar_of({"tmp/c": ANSWER.encode()})),
        }
    )

    sweep, _ = sweep_of(retention, answers)

    assert (sweep.found, sweep.problems) == ({"answer": ("front /tmp",)}, ())


def python_answers(report: dict, **replaced: tuple[int, bytes]) -> dict:
    return {
        ("docker", "inspect", "service"): (0, inspect_answer([("/work", True)])),
        ("docker", "exec", "-i", "service", "python", "-I", "-"): (
            0,
            json.dumps(report).encode() + b"\n",
        ),
        ("docker", "logs", "service"): (0, LOG_CLEAN),
    } | {tuple(key.split()): value for key, value in replaced.items()}


def census_report(mounts: list[dict], table=None) -> dict:
    table = table or [["/work", "tmpfs", True], ["/proc", "proc", True]]
    return {"table": table, "mounts": mounts}


HOSTS_TABLE = [["/work", "tmpfs", True], ["/etc/hosts", "ext4", True]]


def mount_report(point: str, found=None, **skips: int) -> dict:
    return {
        "mount": point,
        "listings": 3,
        "skips": {name.replace("_", " "): count for name, count in skips.items()},
        "found": {"request": 0, "answer": 0} | (found or {}),
    }


def test_a_container_with_python_is_searched_by_the_census_and_its_hits_come_back_by_label(
    retention,
) -> None:
    report = census_report([mount_report("/work", {"request": 2})])
    answers = python_answers(report)

    sweep, docker = sweep_of(retention, answers, retention.Target("service", has_python=True))

    assert (sweep.found, sweep.problems) == ({"request": ("service /work",)}, ())
    (program,) = [stdin for command, stdin in docker.calls if "python" in command]
    call = ast.parse(program.decode().splitlines()[-1]).body[0].value
    asked = json.loads(ast.literal_eval(call.args[0]))
    assert (asked["mode"], asked["tokens"], "/work" in asked["known"]) == (
        "retention",
        TOKENS,
        True,
    )


def test_a_file_mount_of_a_container_with_python_is_copied_out_and_searched(retention) -> None:
    report = census_report(
        [mount_report("/work"), mount_report("/etc/hosts", file_mount=1)], HOSTS_TABLE
    )
    answers = python_answers(
        report, **{"docker cp service:/etc/hosts -": (0, tar_of({"hosts": ANSWER.encode()}))}
    )

    sweep, _ = sweep_of(retention, answers, retention.Target("service", has_python=True))

    assert sweep.found == {"answer": ("service /etc/hosts",)}


@pytest.mark.parametrize("reason", ["refused", "replaced", "too_deep", "vanished", "not_regular"])
def test_an_unresolved_skip_of_the_census_fails_the_container(retention, reason) -> None:
    report = census_report([mount_report("/work", **{reason: 1})])

    sweep, _ = sweep_of(retention, python_answers(report), retention.Target("service", True))

    assert sweep.problems == (f"service /work: {reason.replace('_', ' ')} x1 was not resolved",)


def test_a_nested_mount_skip_is_resolved_by_the_walk_of_the_nested_mount(retention) -> None:
    report = census_report([mount_report("/work", nested_mount_skipped=1)])

    sweep, _ = sweep_of(retention, python_answers(report), retention.Target("service", True))

    assert sweep.problems == ()


@pytest.mark.parametrize(
    "answers",
    [
        {("docker", "exec", "-i", "service", "python", "-I", "-"): (1, b"")},
        {("docker", "exec", "-i", "service", "python", "-I", "-"): (0, b'{"error": "failed"}\n')},
    ],
    ids=["exit status", "census error"],
)
def test_a_census_that_fails_leaves_the_container_unexamined(retention, answers) -> None:
    base = python_answers(census_report([]))

    sweep, _ = sweep_of(retention, base | answers, retention.Target("service", True))

    assert sweep.problems == ("service: the census could not search the mounts",)


def test_the_writable_destinations_of_an_inspection_are_its_rw_mounts_and_tmpfs(retention) -> None:
    document = json.loads(inspect_answer([("/a", True), ("/b", False)], {"/t": "size=1m"}))[0]

    assert retention.writable_destinations(document) == {"/a", "/t"}


def test_a_searched_mount_that_the_census_did_not_walk_is_an_unexamined_sink(retention) -> None:
    report = census_report([mount_report("/work")], HOSTS_TABLE)

    sweep, _ = sweep_of(retention, python_answers(report), retention.Target("service", True))

    assert sweep.problems == ("service /etc/hosts: the census did not walk the mount",)


def test_a_mount_table_that_cannot_be_read_leaves_the_container_unexamined(retention) -> None:
    answers = front_answers(**{"docker exec front cat /proc/1/mountinfo": (1, b"")})

    sweep, _ = sweep_of(retention, answers)

    assert sweep.problems == ("front: the mount table could not be read",)


def test_a_census_that_prints_no_json_leaves_the_container_unexamined(retention) -> None:
    answers = python_answers(census_report([])) | {
        ("docker", "exec", "-i", "service", "python", "-I", "-"): (0, b"")
    }

    sweep, _ = sweep_of(retention, answers, retention.Target("service", True))

    assert sweep.problems == ("service: the census could not search the mounts",)


def test_a_sweep_names_every_sink_that_holds_a_canary_in_order(retention) -> None:
    answers = front_answers(
        shared=REQUEST.encode(), **{"docker logs front": (0, REQUEST.encode() * 2)}
    )

    sweep, _ = sweep_of(retention, answers)

    assert sweep.found == {"request": ("front /dev/shm", "front log")}


def test_an_archive_of_a_sink_that_cannot_be_read_completely_fails_the_sweep(retention) -> None:
    whole = tar_of({"dev/shm/a": REQUEST.encode() * 100})
    answers = front_answers(**{"docker exec front tar -c /dev/shm": (0, whole[:700])})

    sweep, _ = sweep_of(retention, answers)

    assert sweep.problems == ("front /dev/shm: an archive that could not be read completely",)


# --- B11's reading of LiteLLM's configuration in litellm_retention.py -----------------------------


@pytest.fixture(scope="module")
def retention_probe() -> Iterator[ModuleType]:
    with probe_imports():
        import litellm_retention

        yield litellm_retention


@pytest.fixture
def shipped_config() -> dict:
    return yaml.safe_load(LITELLM_CONFIG.read_text(encoding="utf-8"))


def test_the_shipped_configuration_holds_exactly_the_settings_b11_allows(
    retention_probe: ModuleType,
) -> None:
    text = LITELLM_CONFIG.read_text(encoding="utf-8")

    found = {section: retention_probe.settings_of(text, section)
             for section in retention_probe.SETTINGS_SECTIONS}  # fmt: skip

    assert found == retention_probe.SETTINGS_SECTIONS


@pytest.mark.parametrize(
    ("section", "key", "value"),
    [
        ("litellm_settings", "success_callback", ["s3"]),
        ("litellm_settings", "s3_callback_params", {"s3_bucket_name": "probe"}),
        ("litellm_settings", "cache", True),
        ("router_settings", "fallbacks", [{"a": ["b"]}]),
    ],
)
def test_an_unexpected_setting_of_any_shape_fails_b11s_comparison(
    retention_probe: ModuleType, shipped_config: dict, section: str, key: str, value: object
) -> None:
    shipped_config[section][key] = value
    text = yaml.safe_dump(shipped_config, default_flow_style=False)

    assert retention_probe.settings_of(text, section) != retention_probe.SETTINGS_SECTIONS[section]


def test_the_environment_name_of_litellms_payload_print_is_a_forbidden_store(
    retention_probe: ModuleType,
) -> None:
    assert retention_probe.STORE_NAMES.search("LITELLM_PRINT_STANDARD_LOGGING_PAYLOAD")
