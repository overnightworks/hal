"""The agent service unit as files, no containers (#201 cell U13): the `agent-service` service of
compose.yaml, `agent-service/service.toml`, and what they must agree on with the image recipe.

The running paths (U1-U12) are proven by probe/agent-service/unit.py and egress.py --target
service; these tests hold the static facts the probe does not see in CI: the hardening, the binds
and tmpfs mounts, `pull_policy: never`, the image tag, and that every path in `service.toml` is a
mount target of the service.
"""

import re
import tomllib
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

SERVICE = "agent-service"
OWNER_ONLY_TMPFS = ("uid=1000", "gid=1000", "mode=0700", "nosuid", "nodev", "noexec")
SIZE_BOUND = re.compile(r"size=\d+[kmg]")
# The keys under which each provider's relationship is read from its owners, not values.
VERSION_ARGUMENTS = {"anthropic": "CLAUDE_VERSION", "openai": "CODEX_VERSION"}
LOGIN_ENTRIES = {"anthropic": "agent-service-claude", "openai": "agent-service/codex"}
# The service renews this login itself and needs its directory writable to rename over the file.
RENEWED_LOGIN = "openai"
# agent-runtime's stop waits up to 45 s for a renewal in flight and asks for 60 s beyond that.
MINIMUM_STOP_GRACE_SECONDS = 45 + 60


@pytest.fixture(scope="module")
def service() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"][SERVICE]


@pytest.fixture(scope="module")
def dockerfile() -> str:
    return (ROOT / "agent-service/image/Dockerfile").read_text()


@pytest.fixture(scope="module")
def configuration() -> dict:
    return tomllib.loads((ROOT / "agent-service/service.toml").read_text())


@pytest.fixture(scope="module")
def tmpfs_options(service) -> dict[str, list[str]]:
    mounts = (entry.partition(":") for entry in service["tmpfs"])
    return {path: options.split(",") for path, _, options in mounts}


@pytest.fixture(scope="module")
def binds(service) -> dict[str, dict]:
    return {volume["target"]: volume for volume in service["volumes"]}


def test_the_service_is_hardened_and_never_pulled(service):
    """U13: a fixed user, an init, a read-only root, no capability, no privilege gain, no core."""
    assert service["user"] == "1000:1000"
    assert service["init"] is True
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "cap_add" not in service
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["ulimits"] == {"core": 0}
    assert service["pull_policy"] == "never"


def test_the_service_is_one_replica_with_no_published_port(service):
    """U2: no replicas, no scale; the network is the anchor's alone."""
    assert not {"deploy", "scale", "ports", "network_mode", "expose"} & service.keys()


def test_every_writable_directory_is_a_size_bounded_private_tmpfs_for_the_user(tmpfs_options):
    """U6, U7: on the read-only root, each mounted tmpfs is owned by 1000 with exactly mode 0700,
    nosuid, nodev, noexec and bounded, so no unbounded or shared writable directory exists."""
    assert tmpfs_options
    for options in tmpfs_options.values():
        assert set(options) >= set(OWNER_ONLY_TMPFS)
        assert any(SIZE_BOUND.fullmatch(option) for option in options)


def test_every_volume_of_the_service_is_a_read_only_bind_but_the_renewed_login_directory(
    service, configuration
):
    renewed = str(PurePosixPath(configuration["cli"][RENEWED_LOGIN]["token_file"]).parent)
    assert all(volume["type"] == "bind" for volume in service["volumes"])
    writable = [v["target"] for v in service["volumes"] if not v.get("read_only", False)]
    assert writable == [renewed]


def test_the_stop_grace_covers_a_login_renewal_in_flight(service):
    """A kill during a renewal leaves `.<file>.new` behind and the login then needs a manual fix."""
    grace = re.fullmatch(r"(?:(\d+)m)?(?:(\d+)s)?", str(service["stop_grace_period"]))
    minutes, seconds = (int(part or 0) for part in grace.groups())
    assert minutes * 60 + seconds >= MINIMUM_STOP_GRACE_SECONDS


@pytest.mark.parametrize("provider", LOGIN_ENTRIES)
def test_each_login_is_a_directory_bind_that_is_never_created_and_read_only_unless_renewed(
    provider, configuration, binds
):
    """U8, U10: a directory so that `mv -T` reaches the running container; a missing source fails
    the start instead of becoming root's directory; the source is the folder the secrets manifest
    names for the login."""
    manifest = tomllib.loads((ROOT / "src/hal/workstation/secrets_manifest.toml").read_text())
    entry = next(e for e in manifest["secret"] if e["name"] == LOGIN_ENTRIES[provider])
    folder = PurePosixPath(entry["paths"][0]).parent
    token_file = PurePosixPath(configuration["cli"][provider]["token_file"])
    login = binds[str(token_file.parent)]

    assert login.get("read_only", False) is (provider != RENEWED_LOGIN)
    assert login["bind"] == {"create_host_path": False}
    assert login["source"].replace("${HOME}", "~") == str(folder)


def test_the_configuration_is_a_read_only_file_bind_from_the_checkout(binds):
    configuration = binds["/etc/agent-service/service.toml"]

    assert configuration["read_only"] is True
    assert configuration["bind"] == {"create_host_path": False}


def test_the_image_tag_names_the_locks_release_and_both_cli_versions(service, dockerfile):
    """The tag names the agent-runtime release of the lock and the two CLI pins of the recipe."""
    lock = (ROOT / "agent-service/image/requirements.txt").read_text()
    release = re.match(r"# agent-runtime v(\S+), commit ", lock).group(1)
    claude, codex = (
        re.search(rf"^ARG {VERSION_ARGUMENTS[provider]}=(\S+)$", dockerfile, re.MULTILINE).group(1)
        for provider in ("anthropic", "openai")
    )

    assert service["image"] == f"edge-agent-service:{release}-claude-{claude}-codex-{codex}"


def test_the_service_toml_paths_are_the_services_mount_targets(configuration, tmpfs_options, binds):
    """U13: the working root is a tmpfs and the configuration bind is a mount target."""
    assert configuration["cli"]["working_root"] in tmpfs_options
    assert "/etc/agent-service/service.toml" in binds


@pytest.mark.parametrize("provider", LOGIN_ENTRIES)
def test_each_cli_binary_is_the_images_and_its_token_file_lies_in_a_login_bind(
    provider, configuration, binds, dockerfile
):
    table = configuration["cli"][provider]

    assert re.search(
        rf"^COPY --from=\S+ --chown=0:0 --chmod=0555 \S+ {re.escape(table['binary'])}$",
        dockerfile,
        re.MULTILINE,
    )
    assert str(PurePosixPath(table["token_file"]).parent) in binds


@pytest.mark.parametrize("provider", VERSION_ARGUMENTS)
def test_each_version_pin_equals_the_cli_the_recipe_installs(provider, configuration, dockerfile):
    argument = VERSION_ARGUMENTS[provider]
    pinned = re.search(rf"^ARG {argument}=(\S+)$", dockerfile, re.MULTILINE).group(1)

    assert configuration["cli"][provider]["version"] == pinned


def test_the_service_declares_no_paid_api_route(configuration):
    """Edge holds no API provider key, so a route table would spend money the subscription does
    not."""
    assert not {"purposes", "route", "api", "profiles"} & configuration.keys()


@pytest.mark.parametrize("app", ["presentator", "hopin"])
def test_an_app_that_serves_no_mcp_has_no_tools_and_no_mcp_origin(configuration, app):
    assert not {"tools", "mcp_origin"} & configuration["apps"][app].keys()


def test_the_default_model_is_one_the_anthropic_login_serves(configuration):
    anthropic = configuration["cli"]["anthropic"]

    assert configuration["defaults"]["model"].removeprefix("anthropic/") in anthropic["models"]


def test_songmakers_mcp_origin_is_the_host_traefik_mcp_answers_to_on_mcp(configuration):
    """E1, T1: the origin's host is traefik-mcp's alias on `mcp` and the route's router host."""
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    origin = urlsplit(configuration["apps"]["songmaker"]["mcp_origin"])
    router = yaml.safe_load((ROOT / "mcp/dynamic/songmaker.yml").read_text())["http"]["routers"][
        "songmaker"
    ]

    assert origin.scheme == "https"
    assert origin.hostname in compose["services"]["traefik-mcp"]["networks"]["mcp"]["aliases"]
    assert f"Host(`{origin.hostname}`)" in router["rule"]
    assert "mcp" in compose["services"][SERVICE]["networks"]
    assert "mcp-songmaker" not in compose["services"][SERVICE]["networks"]


def test_the_signing_key_and_the_ca_root_are_compose_secrets_from_the_manifests_paths(
    service, configuration
):
    """E3, B1, T1: `key_file` and `ca_file` are the service's secret targets, and each secret's
    source is the path the secrets manifest names for it, so the folder is never mounted."""
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text())
    manifest = tomllib.loads((ROOT / "src/hal/workstation/secrets_manifest.toml").read_text())
    paths = {entry["name"]: entry["paths"] for entry in manifest["secret"]}
    key_secret, ca_secret = "agent_service_signing_key", "step_ca_root_certificate"

    assert set(service["secrets"]) == {key_secret, ca_secret}
    assert PurePosixPath(configuration["signing"]["key_file"]).name in service["secrets"]
    assert PurePosixPath(configuration["mcp"]["ca_file"]).name in service["secrets"]
    secret_files = [
        compose["secrets"][name]["file"].replace("${HOME}", "~") for name in (key_secret, ca_secret)
    ]
    signing_key_files = [path.removesuffix("*") for path in paths["agent-service/signing-key"]]
    assert secret_files == signing_key_files + paths["step-ca/root_ca.crt"]
    assert "agent-service" in {
        reader
        for entry in manifest["secret"]
        if entry["name"] == "step-ca/root_ca.crt"
        for reader in entry["read_by"]
    }
    assert not any("signing" in str(volume["source"]) for volume in service["volumes"])
