"""The one-offs on the Python pin: `compose.yaml` runs `src/hal/stack/litellm_admin.py` as the key
one-off where the program looks for its files, and `agent-canary` beside it on the same pin."""

import re
from pathlib import Path, PurePosixPath

import pytest
import yaml

from hal.stack import litellm_admin as admin
from hal.stack import litellm_keys

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def services() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]


@pytest.fixture(scope="module")
def secrets_declared() -> dict:
    return yaml.safe_load((ROOT / "compose.yaml").read_text())["secrets"]


@pytest.mark.parametrize("name", [litellm_keys.KEYS_SERVICE, "agent-canary"])
def test_the_one_off_shares_the_realm_observers_profile_image_logging_and_hardening(
    services: dict, name: str
) -> None:
    one_off, observer = services[name], services["realm-observer"]

    for key in ("profiles", "image", "logging", "read_only", "cap_drop", "security_opt"):
        assert one_off[key] == observer[key]


def test_the_key_one_off_runs_as_litellms_user(services: dict) -> None:
    one_off = services[litellm_keys.KEYS_SERVICE]

    assert one_off["user"] == services[litellm_keys.LITELLM_SERVICE]["user"]


def test_the_one_off_is_on_litellm_backend_alone_with_no_port_dependency_or_other_environment(
    services: dict,
) -> None:
    one_off = services[litellm_keys.KEYS_SERVICE]

    assert one_off["networks"] == ["litellm-backend"]
    assert (
        not {"ports", "expose", "depends_on", "extra_hosts", "network_mode", "cap_add", "restart"}
        & one_off.keys()
    )
    assert one_off["environment"] == {"PYTHONDONTWRITEBYTECODE": "1"}


def test_the_one_off_runs_the_mounted_program_against_litellms_own_port(services: dict) -> None:
    one_off = services[litellm_keys.KEYS_SERVICE]
    (mount,) = one_off["volumes"]
    source, target, mode = mount.split(":")
    port = re.search(r"--port (\d+)", (ROOT / "agent-service/litellm/start.sh").read_text()).group(
        1
    )

    assert (ROOT / source).resolve() == Path(admin.__file__).resolve()
    assert mode == "ro"
    assert one_off["entrypoint"] == [
        "python",
        "-I",
        "-B",
        target,
        "--base-url",
        f"http://{litellm_keys.LITELLM_SERVICE}:{port}",
    ]


def test_the_one_off_reads_the_master_key_and_one_secret_per_app_key_file_where_the_program_looks(
    services: dict, secrets_declared: dict
) -> None:
    mounted = services[litellm_keys.KEYS_SERVICE]["secrets"]
    master = [entry for entry in mounted if isinstance(entry, str)]
    apps = {
        PurePosixPath("/run/secrets", entry["target"]): secrets_declared[entry["source"]]["file"]
        for entry in mounted
        if isinstance(entry, dict)
    }

    assert [PurePosixPath("/run/secrets", name) for name in master] == [
        PurePosixPath(admin.MASTER_KEY_FILE)
    ]
    assert {path.parent for path in apps} == {PurePosixPath(admin.APP_KEYS_DIRECTORY)}
    assert all(path.name == PurePosixPath(file).name for path, file in apps.items())
    assert len(apps) == len(mounted) - 1
