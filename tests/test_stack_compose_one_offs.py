"""A one-off container of the edge stack logs to driver `none`; a long-running service does not.

The one-offs are the services of the `apply` profile: `compose run` starts them for their output,
which belongs to the caller alone and must not reach the journal a second time. A failed one-off
keeps the last line of its standard error apart from its standard output (#965).
"""

import json
import subprocess
from pathlib import Path

import pytest

from hal.backup.restic import container_argv
from hal.backup.settings import Settings
from hal.stack import compose

ROOT = Path(__file__).resolve().parents[1]
APPLY_PROFILE = "apply"
NO_LOGGING = {"driver": "none"}
OVERLAYS = sorted(ROOT.glob("probe/*/compose*.yaml"))
PLACEHOLDER_DIRECTORY = "/tmp"  # noqa: S108 - a bind source that docker compose config interpolates and never opens
PLACEHOLDERS = {
    "DOCKER_GID": "999",
    "EDGE_DOMAIN": "edge.test",
    "PROBE_ADMIN_URL": "https://admin.test",
    "PROBE_CA_JSON": f"{PLACEHOLDER_DIRECTORY}/ca.json",
    "PROBE_CONFIG_DIR": PLACEHOLDER_DIRECTORY,
    "PROBE_EGRESS_STATIC": f"{PLACEHOLDER_DIRECTORY}/static.yml",
    "PROBE_KEYCLOAK_SUBNET": "172.31.240.0/24",
    "PROBE_SECRETS_DIR": PLACEHOLDER_DIRECTORY,
    "PROBE_TRAEFIK_CONFIG": f"{PLACEHOLDER_DIRECTORY}/traefik.yml",
}


def resolved(monkeypatch, *overlays: Path) -> dict:
    """`docker compose config` of compose.yaml and the overlays, every profile switched on."""
    for name, value in PLACEHOLDERS.items():
        monkeypatch.setenv(name, value)
    files = [argument for path in (ROOT / "compose.yaml", *overlays) for argument in ("-f", path)]
    result = compose.run_docker(
        ["docker", "compose", "--project-directory", str(ROOT), *map(str, files),
         "--profile", "*", "config", "--format", "json"],
        compose.READ_SECONDS,
    )  # fmt: skip
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def one_off_names(config: dict) -> set[str]:
    return {
        name
        for name, service in config["services"].items()
        if service.get("profiles") == [APPLY_PROFILE]
    }


def test_every_apply_profile_service_logs_to_none_and_no_other_service_does(monkeypatch):
    """#384 U4"""
    services = resolved(monkeypatch)["services"]

    one_offs = one_off_names({"services": services})
    assert one_offs
    assert {name for name, service in services.items() if service.get("logging") == NO_LOGGING} == (
        one_offs
    )


@pytest.mark.parametrize("overlay", OVERLAYS, ids=lambda path: path.relative_to(ROOT).as_posix())
def test_an_overlay_keeps_the_one_offs_logging_to_none(monkeypatch, overlay):
    """#384 U5"""
    services = resolved(monkeypatch, overlay)["services"]

    assert all(
        services[name].get("logging") == NO_LOGGING
        for name in one_off_names({"services": services})
    )


def test_the_restic_container_starts_with_log_driver_none(tmp_path):
    """#384 U1"""
    argv = container_argv(Settings.for_home(tmp_path, uid=1000, gid=1000))

    assert argv[argv.index("--log-driver") + 1] == "none"


def test_a_failed_one_off_names_its_exit_and_last_error_line_and_never_its_standard_output() -> (
    None
):
    """#965: a one-off whose standard output may carry values names its cause from stderr alone."""
    value = "fp-a-value-the-one-off-printed"

    def runner(command: list[str], _timeout: int, _stdin: str | None = None):
        return subprocess.CompletedProcess(command, 3, f"{value}\n", "first\nthe last error\n\n")

    one_offs = compose.Compose(run=runner)

    with pytest.raises(compose.ComposeError) as raised:
        one_offs.run_once("litellm-keys", ["--read", "x"])

    assert raised.value.one_off_cause("litellm-keys") == "litellm-keys exited 3: the last error"


def test_a_one_off_that_never_exited_is_named_by_the_failure_itself() -> None:
    def runner(command: list[str], timeout: int, _stdin: str | None = None):
        raise compose.ComposeError(f"`{' '.join(command[:3])}` took longer than {timeout}s")

    one_offs = compose.Compose(run=runner)

    with pytest.raises(compose.ComposeError) as raised:
        one_offs.run_once("litellm-keys", ["--write"])

    assert raised.value.one_off_cause("litellm-keys") == str(raised.value)
