"""The agent service image recipe's static facts (#192). CI never starts containers, so these pins
hold what the recipe says; the build and the start of the image are the probe's
(`probe/agent-service/image.py`)."""

import argparse
import hashlib
import re
import subprocess
from pathlib import Path
from types import ModuleType

import agent_service_lock
import pytest
import yaml
from support.script_module import script_module

REPOSITORY = Path(__file__).resolve().parents[1]
PROBE = REPOSITORY / "probe" / "agent-service" / "image.py"
IMAGE_DIRECTORY = REPOSITORY / "agent-service" / "image"
DOCKERFILE = (IMAGE_DIRECTORY / "Dockerfile").read_text(encoding="utf-8")
LOCK = (IMAGE_DIRECTORY / "requirements.txt").read_text(encoding="utf-8")
AGENT_SERVICE_DOCUMENT = (REPOSITORY / "docs" / "agent-service.md").read_text(encoding="utf-8")

RELEASE_WHEELS = ("agent-runtime", "agent-runtime-client", "agent-runtime-service")
DIGEST_PINNED_IMAGE = re.compile(r"^FROM \S+@sha256:[0-9a-f]{64}\b", re.MULTILINE)
STAGES = [
    stage
    for stage in re.split(r"^(?=FROM )", DOCKERFILE, flags=re.MULTILINE)
    if stage.startswith("FROM ")
]
# An instruction with its continuation lines.
ADD_STEP = re.compile(r"^ADD [^\n]*(?:\n(?!\S)[^\n]*)*", re.MULTILINE)
RUN_STEP = re.compile(r"^RUN [^\n]*(?:\n(?!\S)[^\n]*)*", re.MULTILINE)


def load_probe() -> ModuleType:
    with script_module("agent_service_image_probe", PROBE) as module:
        return module


PROBE_MODULE = load_probe()


def dockerfile_argument(name: str) -> str:
    return re.search(rf"^ARG {name}=(\S+)$", DOCKERFILE, re.MULTILINE).group(1)


def download_stage(prefix: str) -> str:
    """The build stage that declares the CLI pins whose ARG names start with `prefix`."""
    return next(stage for stage in STAGES if f"\nARG {prefix}_VERSION=" in stage)


def lock_requirements() -> list[str]:
    """Each requirement of the lock with its continuation lines, comments left out."""
    body = "\n".join(line for line in LOCK.splitlines() if not line.lstrip().startswith("#"))
    blocks = re.split(r"\n(?=\S)", body.strip())
    return [" ".join(block.replace("\\\n", " ").split()) for block in blocks]


def release_tag() -> str:
    return re.match(r"# agent-runtime (v\S+), commit [0-9a-f]{40}\n", LOCK).group(1)


def test_every_stage_starts_from_a_digest_pinned_image_or_an_earlier_stage():
    earlier_stages = set()
    for stage in STAGES:
        base, _, name = stage.partition("\n")[0].removeprefix("FROM ").partition(" AS ")
        assert DIGEST_PINNED_IMAGE.match(stage) or base in earlier_stages
        earlier_stages.add(name)


@pytest.mark.parametrize("prefix", PROBE_MODULE.DOCKERFILE_PREFIXES.values())
def test_each_cli_is_fetched_by_its_pinned_version_and_checked_by_sha256_while_it_is_fetched(
    prefix,
):
    assert re.fullmatch(r"\d+\.\d+\.\d+", dockerfile_argument(f"{prefix}_VERSION"))
    assert re.fullmatch(r"[0-9a-f]{64}", dockerfile_argument(f"{prefix}_SHA256"))
    (download,) = ADD_STEP.findall(download_stage(prefix))
    assert download.startswith(f"ADD --checksum=sha256:${{{prefix}_SHA256}} ")
    assert re.search(rf'"https://\S+\${{{prefix}_VERSION}}\S*"', download)


@pytest.mark.parametrize(("provider", "prefix"), PROBE_MODULE.DOCKERFILE_PREFIXES.items())
def test_each_download_stage_holds_a_version_check_that_exits_1_on_a_mismatch(provider, prefix):
    (check,) = RUN_STEP.findall(download_stage(prefix))
    expected = PROBE_MODULE.VERSION_REPORTS[provider].format(version=f"${{{prefix}_VERSION}}")
    assert f'expected="{expected}"' in check
    assert '--version)"' in check
    assert 'if [ "${reported}" != "${expected}" ]; then' in check
    assert "exit 1" in check


@pytest.mark.parametrize("moving_name", ["latest", "stable", "install.sh", "claude.ai/install"])
def test_the_recipe_never_names_a_moving_cli_release(moving_name):
    assert moving_name not in DOCKERFILE


def test_every_cli_is_installed_root_owned_and_not_writable():
    installs = re.findall(r"^COPY --from=\S+ --chown=0:0 --chmod=0555 ", DOCKERFILE, re.MULTILINE)
    assert len(installs) == len(PROBE_MODULE.DOCKERFILE_PREFIXES)


def test_packages_install_only_from_the_hashed_lock_and_are_checked_afterwards():
    assert "pip install --no-cache-dir --no-deps --require-hashes --only-binary :all:" in DOCKERFILE
    assert "-r /tmp/requirements.txt" in DOCKERFILE
    assert "&& pip check" in DOCKERFILE


def test_the_recipe_holds_only_bare_base_stages_download_stages_and_a_final_running_pip_install():
    downloads = {download_stage(prefix) for prefix in PROBE_MODULE.DOCKERFILE_PREFIXES.values()}
    bare_bases = {stage for stage in STAGES if "\n" not in stage.strip()}
    (*_, final) = STAGES
    assert set(STAGES) == bare_bases | downloads | {final}
    assert [step.split()[1:3] for step in RUN_STEP.findall(final)] == [["pip", "install"]]


@pytest.mark.parametrize("package_manager", ["apt", "apt-get", "apk"])
def test_the_recipe_installs_no_system_package(package_manager):
    assert not re.search(rf"\b{package_manager}\b", DOCKERFILE)


@pytest.mark.parametrize("tag", ["v0.7.0", "v10.0.1", "v10.20.30"])
def test_the_lock_script_accepts_a_release_tag(tag):
    assert agent_service_lock.release_tag(tag) == tag


@pytest.mark.parametrize(
    "tag",
    [
        "--upload-pack=x", "v0.4", "0.4.0", "v0.4.0 ", "v0.4.0\n", "v0.4.0/../x", "main", "",
        "v00.4.0", "v0.04.0", "v0.4.00",
    ],
)  # fmt: skip
def test_the_lock_script_refuses_anything_but_a_release_tag(tag):
    with pytest.raises(argparse.ArgumentTypeError):
        agent_service_lock.release_tag(tag)


def composed_lock() -> str:
    names = agent_service_lock.release_wheel_urls("v1.2.3")
    digests = {name: f"{index:064x}" for index, name in enumerate(names)}
    return agent_service_lock.lock_text(
        "v1.2.3", "c0ffee", "pkg==1.0 \\\n    --hash=sha256:ab\n", digests
    )


def test_the_composed_lock_names_the_tag_and_the_commit_in_its_header():
    assert composed_lock().startswith("# agent-runtime v1.2.3, commit c0ffee\n")


def test_the_composed_lock_holds_the_closure_then_each_wheel_by_url_and_hash():
    lines = composed_lock().splitlines()
    assert "pkg==1.0 \\" in lines
    wheels = [line for line in lines if " @ " in line]
    assert [line.split(" @ ")[0] for line in wheels] == list(
        agent_service_lock.release_wheel_urls("v1.2.3")
    )
    assert all("/releases/download/v1.2.3/" in line for line in wheels)
    assert [line.strip() for line in lines if "--hash=sha256:0" in line] == [
        f"--hash=sha256:{index:064x}" for index in range(3)
    ]


def test_the_composed_lock_is_the_same_text_each_time():
    first, second = composed_lock(), composed_lock()
    assert second == first


def test_nothing_is_cloned_for_a_tag_that_is_not_a_release_tag():
    with pytest.raises(argparse.ArgumentTypeError):
        agent_service_lock.released_commit_and_closure("--upload-pack=x")


def test_the_wheel_digest_is_the_sha256_of_the_served_bytes(tmp_path):
    wheel = tmp_path / "wheel.whl"
    wheel.write_bytes(b"served bytes")
    assert (
        agent_service_lock.wheel_digest(wheel.as_uri())
        == hashlib.sha256(b"served bytes").hexdigest()
    )


def test_the_release_is_the_commit_the_tag_points_at_with_its_exported_closure(
    tmp_path, monkeypatch
):
    origin = tmp_path / "origin"
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-C", str(origin)]
    subprocess.run(["git", "init", "--quiet", str(origin)], check=True)
    subprocess.run([*git, "commit", "--quiet", "--allow-empty", "-m", "release"], check=True)
    subprocess.run([*git, "tag", "v1.2.3"], check=True)
    tagged = subprocess.run(
        [*git, "rev-parse", "v1.2.3^{commit}"], check=True, capture_output=True, text=True
    ).stdout.strip()
    monkeypatch.setattr(agent_service_lock, "REPOSITORY_URL", origin.as_uri())
    monkeypatch.setattr(agent_service_lock, "UV_EXPORT", ("printf", "closure"))
    assert agent_service_lock.released_commit_and_closure("v1.2.3") == (tagged, "closure")


def test_the_lock_script_writes_the_built_lock(tmp_path, monkeypatch):
    lock = tmp_path / "image" / "requirements.txt"
    monkeypatch.setattr(agent_service_lock, "LOCK_PATH", lock)
    monkeypatch.setattr(agent_service_lock, "built_lock", lambda tag: f"lock for {tag}\n")
    assert agent_service_lock.main(["v1.2.3"]) == 0
    assert lock.read_text(encoding="utf-8") == "lock for v1.2.3\n"


@pytest.mark.parametrize("login", ["/.claude", "/.codex", "auth.json", "managed-settings"])
def test_the_image_runs_the_service_as_uid_1000_without_a_login(login):
    assert "USER 1000:1000" in DOCKERFILE
    assert login not in DOCKERFILE


def test_every_requirement_of_the_lock_carries_a_hash_and_is_pinned():
    for requirement in lock_requirements():
        assert "--hash=sha256:" in requirement, requirement
        assert re.match(r"[A-Za-z0-9._-]+(\[\w+\])?(==\S+| @ https://)", requirement), requirement


@pytest.mark.parametrize("package", RELEASE_WHEELS)
def test_the_lock_holds_the_release_wheel_by_url_and_sha256(package):
    tag = release_tag()
    wheel = f"overnightworks_{package.replace('-', '_')}-{tag.removeprefix('v')}-py3-none-any.whl"
    url = f"https://github.com/overnightworks/agent-runtime/releases/download/{tag}/{wheel}"
    assert any(
        requirement.startswith(f"overnightworks-{package} @ {url} --hash=sha256:")
        for requirement in lock_requirements()
    )


def test_the_agent_service_document_builds_the_name_compose_runs():
    name = yaml.safe_load((REPOSITORY / "compose.yaml").read_text())["services"]["agent-service"][
        "image"
    ]
    command = f"docker build -f agent-service/image/Dockerfile -t {name} agent-service/image"
    assert command in AGENT_SERVICE_DOCUMENT


@pytest.fixture(scope="module")
def probe() -> ModuleType:
    return PROBE_MODULE


PLANTED = "/usr/local/planted.bin"


@pytest.mark.parametrize(
    ("returncode", "stdout"),
    [
        (2, f"{PLANTED}\n"),
        (1, ""),
        (0, ""),
        (0, f"{PLANTED}\n/usr/other\n"),
    ],
)
def test_the_token_search_bite_check_fails_without_exit_zero_and_exactly_the_planted_path(
    probe, returncode, stdout
):
    bitten = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr="")
    assert probe.bite_check_failure(bitten, PLANTED) is not None


def test_the_token_search_bite_check_passes_on_exit_zero_with_exactly_the_planted_path(probe):
    bitten = subprocess.CompletedProcess([], 0, stdout=f"{PLANTED}\n", stderr="")
    assert probe.bite_check_failure(bitten, PLANTED) is None


def test_the_login_variable_check_names_the_variables_and_never_their_values(probe):
    secret_value = "synthetic-value-that-must-not-print"
    environment = ["PATH=/usr/bin", f"OPENAI_API_KEY={secret_value}", f"CODEX_HOME={secret_value}"]

    names = probe.login_environment_names(environment)

    assert names == ["OPENAI_API_KEY", "CODEX_HOME"]
    assert secret_value not in str(names)
