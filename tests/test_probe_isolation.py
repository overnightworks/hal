"""The probes' network isolation (#346 P26): what probe/edge_copy.py moves and refuses, and what a
probe's shipped script and teardown resolve."""

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from textwrap import dedent
from types import SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "probe"))
sys.path.insert(0, str(ROOT / "src"))

import edge_copy  # noqa: E402
from support.git_support import committed_main, plain_git  # noqa: E402
from support.script_module import loaded_script  # noqa: E402

from hal.backup.docker import PROJECT_LABEL  # noqa: E402
from hal.stack import catalog, checkout  # noqa: E402

PROJECT = "edge-some-probe"


def fixed_names(text: str, section: str = "networks") -> dict[str, str]:
    entries = yaml.safe_load(text)[section]
    return {key: entry["name"] for key, entry in entries.items() if entry and "name" in entry}


@pytest.mark.parametrize("section", ["networks", "volumes"])
def test_every_fixed_name_of_compose_moves_into_the_project(section):
    compose = (ROOT / "compose.yaml").read_text()

    moved = fixed_names(edge_copy.namespaced_compose(compose, PROJECT), section)

    assert moved
    assert all(name.startswith(f"{PROJECT}_") for name in moved.values())
    assert moved.keys() == fixed_names(compose, section).keys()


@pytest.mark.parametrize("section", ["networks", "volumes"])
def test_the_keycloak_overlay_moves_every_fixed_name_of_compose_into_its_project(section):
    moved = fixed_names((ROOT / "probe/keycloak/compose.probe.yaml").read_text(), section)

    fixed = fixed_names((ROOT / "compose.yaml").read_text(), section)
    assert fixed.keys() <= moved.keys()
    assert all(moved[key].startswith("${COMPOSE_PROJECT_NAME}_") for key in fixed)


def test_a_compose_text_with_no_fixed_name_is_refused():
    with pytest.raises(edge_copy.ProbeFailed, match="no fixed network or volume name"):
        edge_copy.namespaced_compose("networks:\n  mcp:\n    internal: true\n", PROJECT)


def test_a_fixed_name_the_rewrite_cannot_match_is_refused():
    text = "networks:\n  a:\n    name: hal_a\n  b:\n    name: hal_b # live\n"

    with pytest.raises(edge_copy.ProbeFailed, match="remains after the rewrite"):
        edge_copy.namespaced_compose(text, PROJECT)


@pytest.mark.parametrize("section", ["networks", "volumes"])
def test_a_fixed_name_with_no_owner_prefix_is_refused(section):
    text = f"{section}:\n  a:\n    name: unowned\n"

    with pytest.raises(edge_copy.ProbeFailed, match="no <owner>_ prefix"):
        edge_copy.namespaced_compose(text, PROJECT)


@pytest.mark.parametrize(
    ("section", "foreign"),
    [("networks", "hal_agent_songmaker"), ("volumes", "edge_keycloak-db")],
)
def test_a_resolved_name_outside_the_project_fails_the_guard(section, foreign):
    resolved = {section: {"a": {"name": f"{PROJECT}_a"}, "b": {"name": foreign}}}

    with pytest.raises(edge_copy.ProbeFailed, match=foreign):
        edge_copy.expect_project_names(resolved, PROJECT)


def test_a_resolved_configuration_inside_the_project_passes_the_guard():
    resolved = {section: {"a": {"name": f"{PROJECT}_a"}} for section in ("networks", "volumes")}

    edge_copy.expect_project_names(resolved, PROJECT)


class FakeDocker:
    """The daemon's volume listings: `existing` volumes, `labelled` the ones of the live project."""

    def __init__(self, existing: list[str], labelled: list[str]) -> None:
        self.existing, self.labelled = existing, labelled

    def __call__(self, command, **_):
        listing = (
            self.labelled
            if any(word.startswith("label=") for word in command)
            else (self.existing if command[:3] == ["docker", "volume", "ls"] else [])
        )
        return SimpleNamespace(stdout="\n".join(listing))


def test_the_live_snapshot_holds_every_volume_compose_resolves_whatever_its_label(monkeypatch):
    kept = fixed_names((ROOT / "compose.yaml").read_text(), "volumes")["keycloak-db"]
    monkeypatch.setattr(
        edge_copy.subprocess, "run", FakeDocker(existing=[kept, "unrelated"], labelled=[])
    )

    snapshot = edge_copy.live_project(ROOT)

    assert snapshot.volumes == {kept}


def entrypoint_addresses(text: str) -> dict[str, str]:
    entrypoints = yaml.safe_load(text)["entryPoints"]
    return {name: entry["address"] for name, entry in entrypoints.items()}


def test_every_entrypoint_of_traefik_moves_to_the_probe_host_with_its_own_port():
    live = (ROOT / "traefik.yml").read_text()

    beside = edge_copy.beside_the_live_edge(live, PROJECT)

    live_addresses, moved = entrypoint_addresses(live), entrypoint_addresses(beside)
    assert moved.keys() == live_addresses.keys()
    for name, address in moved.items():
        host, _, port = address.rpartition(":")
        assert host == edge_copy.PROBE_HOST
        assert port == live_addresses[name].rpartition(":")[2]
        assert address not in live_addresses.values()


def test_the_probe_traefik_keeps_the_live_constraint_and_adds_its_project():
    live = (ROOT / "traefik.yml").read_text()

    beside = yaml.safe_load(edge_copy.beside_the_live_edge(live, PROJECT))

    live_constraint = yaml.safe_load(live)["providers"]["docker"]["constraints"]
    constraint = beside["providers"]["docker"]["constraints"]
    assert constraint == f"{live_constraint} && Label(`{PROJECT_LABEL}`, `{PROJECT}`)"


def test_the_probe_traefik_differs_from_the_live_one_in_addresses_and_constraint_only():
    live = (ROOT / "traefik.yml").read_text()

    beside = yaml.safe_load(edge_copy.beside_the_live_edge(live, PROJECT))

    expected = yaml.safe_load(live)
    for document in (beside, expected):
        for entry in document["entryPoints"].values():
            del entry["address"]
        del document["providers"]["docker"]["constraints"]
    assert beside == expected


TRAEFIK_WITH_ONE_ENTRYPOINT = dedent(
    """\
    entryPoints:
      edge:
        address: "127.0.0.1:8081"
    providers:
      docker:
        constraints: "LabelRegex(`edge.name`, `^[a-z]+$`)"
    """
)


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("entryPoints: {}\nproviders:\n  docker:\n    constraints: x\n", "no entrypoint"),
        ("global: {}\n", "names no entrypoint address"),
        (
            TRAEFIK_WITH_ONE_ENTRYPOINT.replace("127.0.0.1", edge_copy.PROBE_HOST),
            "already on",
        ),
        (
            TRAEFIK_WITH_ONE_ENTRYPOINT.replace(
                'constraints: "LabelRegex(`edge.name`, `^[a-z]+$`)"', "exposedByDefault: false"
            ),
            "names no entrypoint address or Docker constraint",
        ),
        (TRAEFIK_WITH_ONE_ENTRYPOINT + "# was 127.0.0.1:8081\n", "2 times"),
        (TRAEFIK_WITH_ONE_ENTRYPOINT.replace("127.0.0.1", ""), "every address"),
        (TRAEFIK_WITH_ONE_ENTRYPOINT.replace("127.0.0.1", "0.0.0.0"), "every address"),
        (TRAEFIK_WITH_ONE_ENTRYPOINT.replace("127.0.0.1", "[::]"), "every address"),
    ],
    ids=[
        "no entrypoint",
        "no sections",
        "address already moved",
        "no constraint",
        "found twice",
        "no host",
        "every IPv4 address",
        "every IPv6 address",
    ],
)
def test_a_traefik_text_the_move_cannot_follow_is_refused_with_its_reason(text, reason):
    with pytest.raises(edge_copy.ProbeFailed, match=reason):
        edge_copy.beside_the_live_edge(text, PROJECT)


@pytest.mark.parametrize(
    ("resolved", "reason"),
    [('{"name": "edge", "networks": {}}', "not edge-some-probe"), ("{}", "names no project")],
    ids=["another project", "no project"],
)
def test_a_guarded_call_that_resolves_no_or_another_project_is_refused(
    monkeypatch, resolved, reason
):
    monkeypatch.setattr(edge_copy, "live_networks", set)
    guard = edge_copy.NetworkGuard(PROJECT, lambda command: resolved)

    with pytest.raises(edge_copy.ProbeFailed, match=reason):
        guard.expect(["docker", "compose"])


@pytest.mark.parametrize(
    ("arguments", "resolved"),
    [
        (["--profile", "probe", "up", "--detach", "hello"], [["--profile", "probe"]]),
        (["down", "--volumes"], [[]]),
        (["--profile", "*", "ps", "--all"], []),
    ],
    ids=["up with its profile", "down with none", "ps"],
)
def test_the_guard_resolves_the_files_and_profiles_a_compose_call_runs_with(
    monkeypatch, arguments, resolved
):
    monkeypatch.setattr(edge_copy, "live_networks", set)
    prefix = edge_copy.copy_compose_prefix(Path("copy"))
    seen = []
    guard = edge_copy.NetworkGuard(
        PROJECT, lambda command: seen.append(command) or json.dumps({"name": PROJECT})
    )

    runs = edge_copy.guarded_compose(Path("copy"), guard, arguments)

    assert seen == [[*prefix, *options, "config", "--format", "json"] for options in resolved]
    command = ["docker", *runs]
    assert command == [*prefix, *arguments]


OCCUPIED = ["172.31.250.0/24", "172.31.251.0/24", "10.0.0.0/8"]
CANDIDATES = ["172.31.250.0/24", "172.31.251.0/24", "172.31.249.0/24"]


def test_the_first_candidate_that_overlaps_no_occupied_subnet_is_free():
    assert str(edge_copy.free_subnet(CANDIDATES, OCCUPIED)) == "172.31.249.0/24"


def test_a_candidate_inside_a_wider_occupied_subnet_is_taken():
    with pytest.raises(edge_copy.ProbeFailed, match="no free /24"):
        edge_copy.free_subnet(CANDIDATES, ["172.31.0.0/16"])


MIXED_CATALOG = dedent(
    """\
    # comment before
    cloudflare:
      zone: example.invalid

    services:
      blockapp:
        repo: {default_branch: main}
        run:
          enabled: true
        hosts:
          - {name: blockapp, exposure: public, reason: r, ready: /health}

      # a comment between entries
      flowapp: {repo: {default_branch: master}, run: {enabled: false}}
      hostsonly:
        hosts:
          - {name: only, exposure: public, reason: r}
      library:
        repo: {default_branch: main}
      step-ca:
        run:
          enabled: true
      keycloak:
        run:
          enabled: true
          setup: keycloak/go-live
    """
)
WITHOUT_APPS = dedent(
    """\
    # comment before
    cloudflare:
      zone: example.invalid

    services:

      # a comment between entries
      hostsonly:
        hosts:
          - {name: only, exposure: public, reason: r}
      library:
        repo: {default_branch: main}
      step-ca:
        run:
          enabled: true
      keycloak:
        run:
          enabled: true
          setup: keycloak/go-live
    """
)


def unit_keys(text: str) -> list[str]:
    return list(yaml.safe_load(text)["services"])


def non_app_keys(text: str) -> list[str]:
    services = yaml.safe_load(text)["services"]
    return [key for key, entry in services.items() if not catalog.is_app(entry)]


def test_without_inherited_apps_leaves_the_repositorys_catalog_without_an_app():
    text = (ROOT / "fleet.yaml").read_text()
    original = yaml.safe_load(text)["services"]

    filtered = edge_copy.without_inherited_apps(text)

    kept = yaml.safe_load(filtered)["services"]
    assert kept == {key: entry for key, entry in original.items() if not catalog.is_app(entry)}
    assert not any(catalog.is_app(entry) for entry in kept.values())
    original_lines = iter(text.splitlines())
    assert all(line in original_lines for line in filtered.splitlines())  # in order
    lines = text.splitlines()
    app_lines = 0
    for key in (key for key, entry in original.items() if catalog.is_app(entry)):
        start = lines.index(f"  {key}:")
        end = next(
            (
                i
                for i in range(start + 1, len(lines))
                if lines[i].startswith("  ") and not lines[i].startswith("   ")
            ),
            len(lines),
        )
        app_lines += end - start
    assert len(lines) - len(filtered.splitlines()) == app_lines  # every app's entry, nothing else


def test_both_styles_of_app_go_and_hosts_only_and_library_entries_stay():
    assert edge_copy.without_inherited_apps(MIXED_CATALOG) == WITHOUT_APPS


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("services: [unclosed\n", "does not parse"),
        ("cloudflare:\n  zone: example.invalid\n", "no services mapping"),
        ("services: [a, b]\n", "no services mapping"),
        (
            "services:\n  run: {repo: {default_branch: main}, run: {enabled: false}}\n"
            "  step-ca: {\n  run: {enabled: true}\n  }\n",
            "differs",
        ),
        (
            "services: {\n  enabled: {repo: {default_branch: main}, run: {enabled: false}},\n"
            "  step-ca: {run: {\n  <<: {enabled: true},\n  enabled: false,\n  setup: null\n"
            "  }}\n}\n",
            "differs",
        ),
    ],
)
def test_a_catalog_text_that_cannot_be_filtered_is_refused_with_its_reason(text, reason):
    with pytest.raises(edge_copy.ProbeFailed, match=reason):
        edge_copy.without_inherited_apps(text)


def test_filtering_the_filtered_text_changes_nothing():
    assert edge_copy.without_inherited_apps(WITHOUT_APPS) == WITHOUT_APPS


MOVABLE_COMPOSE = "networks:\n  mcp:\n    name: hal_mcp\n"


def a_repository(tmp_path: Path, fleet: str, compose: str = MOVABLE_COMPOSE) -> Path:
    """A committed repository with `fleet`, `compose` as its compose.yaml and no dependencies."""
    tree = tmp_path / "repository"
    tree.mkdir()
    (tree / "fleet.yaml").write_text(fleet)
    (tree / "compose.yaml").write_text(compose)
    (tree / "pyproject.toml").write_text(
        '[project]\nname = "fixture"\nversion = "0"\nrequires-python = ">=3.12"\n'
        "dependencies = []\n"
    )
    return committed_main(tree)


def a_copy(tmp_path: Path, repository: Path) -> tuple[Path, Path]:
    home, scratch = tmp_path / "home", tmp_path / "scratch"
    home.mkdir(exist_ok=True)
    scratch.mkdir(exist_ok=True)
    copy = edge_copy.repository_copy(repository, home, scratch, PROJECT)
    return copy, scratch / edge_copy.REMOTE


def origin_fleet(origin: Path) -> str:
    return plain_git(origin, "show", "main:fleet.yaml").stdout


def test_the_copy_and_its_origin_name_no_inherited_app(tmp_path):
    copy, origin = a_copy(tmp_path, a_repository(tmp_path, MIXED_CATALOG))

    for text in ((copy / "fleet.yaml").read_text(), origin_fleet(origin)):
        assert non_app_keys(text) == unit_keys(text)


def test_the_copy_keeps_every_non_app_line_so_both_switches_stand_once(tmp_path):
    copy, _ = a_copy(tmp_path, a_repository(tmp_path, MIXED_CATALOG))

    text = (copy / "fleet.yaml").read_text()

    assert text == WITHOUT_APPS
    assert text.count("  step-ca:\n    run:\n      enabled: true\n") == 1
    assert text.count("      enabled: true\n      setup: keycloak/go-live\n") == 1


def test_copying_twice_over_one_home_still_has_no_app_and_a_clean_pushed_main(tmp_path):
    repository = a_repository(tmp_path, MIXED_CATALOG)
    _, origin = a_copy(tmp_path, repository)

    second, _ = a_copy(tmp_path, repository)

    assert (second / "fleet.yaml").read_text() == WITHOUT_APPS
    assert origin_fleet(origin) == WITHOUT_APPS
    assert plain_git(second, "status", "--porcelain").stdout == ""
    assert (
        plain_git(second, "rev-parse", "main").stdout
        == plain_git(origin, "rev-parse", "main").stdout
    )


def test_an_unparsable_catalog_fails_the_copy_and_pushes_nothing(tmp_path):
    repository = a_repository(tmp_path, "services: [unclosed\n")

    with pytest.raises(edge_copy.ProbeFailed, match="does not parse"):
        a_copy(tmp_path, repository)

    origin = tmp_path / "scratch" / edge_copy.REMOTE
    assert not origin.exists() or plain_git(origin, "branch", "--list").stdout == ""


def test_the_copy_and_its_origin_hold_compose_with_the_names_moved(tmp_path):
    copy, origin = a_copy(tmp_path, a_repository(tmp_path, MIXED_CATALOG))

    published = plain_git(origin, "show", "main:compose.yaml").stdout
    for text in ((copy / "compose.yaml").read_text(), published):
        assert fixed_names(text) == {"mcp": f"{PROJECT}_mcp"}


@pytest.mark.parametrize(
    ("fleet", "compose"),
    [
        ("services: [unclosed\n", MOVABLE_COMPOSE),
        (MIXED_CATALOG, "networks:\n  a:\n    name: unowned\n"),
        (MIXED_CATALOG, "networks:\n  a:\n    name: hal_a\n  b:\n    name: hal_b # live\n"),
    ],
    ids=["cut before the rename", "a name without an owner", "a name the rewrite misses"],
)
def test_a_copy_cut_by_a_failure_holds_no_unmoved_compose(tmp_path, fleet, compose):
    repository = a_repository(tmp_path, fleet, compose)

    with pytest.raises(edge_copy.ProbeFailed):
        a_copy(tmp_path, repository)

    left = checkout.live_checkout(tmp_path / "home") / "compose.yaml"
    names = edge_copy.fixed_names(left.read_text()) if left.exists() else set()
    assert all(name.startswith(f"{PROJECT}_") for name in names)


def test_an_app_written_after_the_copy_and_published_stays(tmp_path):
    copy, origin = a_copy(tmp_path, a_repository(tmp_path, MIXED_CATALOG))
    fixture_app = "  fixtureapp:\n    repo: {default_branch: main}\n    run: {enabled: true}\n"
    with (copy / "fleet.yaml").open("a") as fleet:
        fleet.write(fixture_app)

    edge_copy.publish(copy, "a fixture app")

    declared = {"repo": {"default_branch": "main"}, "run": {"enabled": True}}
    for text in ((copy / "fleet.yaml").read_text(), origin_fleet(origin)):
        assert yaml.safe_load(text)["services"]["fixtureapp"] == declared
        assert catalog.is_app(yaml.safe_load(text)["services"]["fixtureapp"])


class DockerLog:
    """A docker executable on PATH that logs each call and answers `config` with `resolved`."""

    def __init__(self, directory: Path, monkeypatch: pytest.MonkeyPatch, resolved: dict) -> None:
        self.log = directory / "docker.log"
        answer = directory / "resolved.json"
        answer.write_text(json.dumps(resolved))
        executables = directory / "bin"
        executables.mkdir()
        docker = executables / "docker"
        docker.write_text(
            "#!/bin/sh\n"
            f"""printf '%s\\n' "$*" >> "{self.log}"\n"""
            f"""case "$*" in *" config "*) cat "{answer}" ;; *) exit 1 ;; esac\n"""
        )
        docker.chmod(0o755)
        monkeypatch.setenv("PATH", f"{executables}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setattr(edge_copy, "live_networks", set)

    def compose_calls(self) -> list[list[str]]:
        calls = [line.split() for line in self.log.read_text().splitlines()]
        return [words for words in calls if words[0] == "compose"]


def compose_file_of(call: list[str]) -> Path:
    directory = call[call.index("--project-directory") + 1]
    return Path(directory) / call[call.index("--file") + 1]


def resolved_stack(project: str, step_ca_volume: str | None = None) -> dict:
    """A resolved configuration of `project`, with `step_ca_volume` in place of its own volume."""
    volumes = {key: f"{project}_{key}" for key in ("step-ca", "traefik-mcp-acme")}
    return {
        "name": project,
        "services": {"step-ca": {"image": "step-ca-image"}},
        "volumes": {
            key: {"name": step_ca_volume if key == "step-ca" and step_ca_volume else name}
            for key, name in volumes.items()
        },
    }


@pytest.fixture(scope="module")
def step_ca_probe() -> Iterator:
    yield from loaded_script("step_ca_probe", ROOT / "probe" / "step-ca" / "probe.py")


@pytest.fixture(scope="module")
def apps_probe() -> Iterator:
    with pytest.MonkeyPatch.context() as patch:
        patch.syspath_prepend(str(ROOT / "probe" / "apps"))
        yield from loaded_script("apps_probe", ROOT / "probe" / "apps" / "probe.py")


@pytest.mark.parametrize("flags", [(), ("--check",)], ids=["init", "init --check"])
def test_step_ca_init_as_the_probe_runs_it_reads_only_a_moved_compose_file(
    step_ca_probe, tmp_path, monkeypatch, flags
):
    docker = DockerLog(tmp_path, monkeypatch, resolved_stack(step_ca_probe.PROJECT))
    probe = step_ca_probe.Probe(tmp_path / "scratch")

    probe.init(*flags, check=False)

    files = {compose_file_of(call) for call in docker.compose_calls()}
    assert files
    for file in files:
        names = edge_copy.fixed_names(file.read_text())
        assert all(name.startswith(f"{step_ca_probe.PROJECT}_") for name in names)


def test_a_live_name_in_the_resolved_file_stops_step_ca_init_before_it_runs(
    step_ca_probe, tmp_path, monkeypatch
):
    foreign = "a-live-volume"
    resolved = resolved_stack(step_ca_probe.PROJECT, step_ca_volume=foreign)
    docker = DockerLog(tmp_path, monkeypatch, resolved)
    probe = step_ca_probe.Probe(tmp_path / "scratch")

    with pytest.raises(edge_copy.ProbeFailed, match=foreign):
        probe.init()

    assert len(docker.compose_calls()) == 1


def a_cut_apps_stand(apps_probe, tmp_path, monkeypatch, resolved) -> tuple:
    """The apps probe with a copy begun by a setup that was cut, and its docker log."""
    docker = DockerLog(tmp_path, monkeypatch, resolved)
    monkeypatch.setattr(apps_probe.grp, "getgrnam", lambda _: SimpleNamespace(gr_gid=0))
    probe = apps_probe.Probe(tmp_path / "scratch")
    probe.copy.mkdir(parents=True)
    return probe, docker


def test_the_apps_teardown_checks_what_the_copys_file_resolves_before_it_removes_volumes(
    apps_probe, tmp_path, monkeypatch
):
    resolved = resolved_stack(apps_probe.CORE_PROJECT)
    probe, docker = a_cut_apps_stand(apps_probe, tmp_path, monkeypatch, resolved)
    (probe.copy / "compose.yaml").write_text(MOVABLE_COMPOSE)

    probe.teardown()

    calls = docker.compose_calls()
    assert [("config" in call, "down" in call) for call in calls] == [(True, False), (False, True)]
    assert "--volumes" in calls[1]
    assert {compose_file_of(call) for call in calls} == {probe.copy / "compose.yaml"}


def test_a_live_name_the_copys_file_resolves_stops_the_apps_teardown_before_down(
    apps_probe, tmp_path, monkeypatch
):
    foreign = "a-live-volume"
    resolved = resolved_stack(apps_probe.CORE_PROJECT, step_ca_volume=foreign)
    probe, docker = a_cut_apps_stand(apps_probe, tmp_path, monkeypatch, resolved)
    (probe.copy / "compose.yaml").write_text(MOVABLE_COMPOSE)

    with pytest.raises(edge_copy.ProbeFailed, match=foreign):
        probe.teardown()

    assert not any("down" in call for call in docker.compose_calls())


def test_the_apps_teardown_of_a_copy_cut_before_its_compose_file_calls_no_compose(
    apps_probe, tmp_path, monkeypatch
):
    resolved = resolved_stack(apps_probe.CORE_PROJECT)
    probe, docker = a_cut_apps_stand(apps_probe, tmp_path, monkeypatch, resolved)

    probe.teardown()

    assert docker.compose_calls() == []
