"""The agent service image probe (#192, cells I1 to I8).

Builds the image with `--no-cache` (the CLI files are served by digest), then drives it as the PC
would: a changed hash fails the build, both CLIs run as uid 1000 on a read-only root, the real
entrypoint starts with both CLI tables
and answers an unauthenticated `POST /runs` with 401, the image holds no login, and the installed
packages are exactly the lock's, and a dropped configuration field stops the start. Run it from
the repository root, in the probe-stack lock:

    flock -o -w 1200 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 50 1780 \\
        python3 probe/agent-service/image.py

Measured teardown: 1 s (K 50 s, CAP 1780 s).

Every image and container it makes carries the probe-only name below and is removed at the end.
Docker's transcripts go to `--output`, an existing directory (default: a new temporary one,
printed).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Sequence
from functools import partial
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))  # egress.py, importable by path too

from egress import scratch_directory  # noqa: E402
from scratch_secrets import write_dummy_codex_login, write_dummy_token  # noqa: E402

from hal.output import Stream, write_line  # noqa: E402

NO_NETWORK = "--network=none"
IMAGE_DIRECTORY = REPOSITORY / "agent-service" / "image"
PROBE_NAME = f"edge-probe-agent-image-{os.getpid()}"
IMAGE = f"{PROBE_NAME}:probe"
SHIPPED_CONFIGURATION = REPOSITORY / "agent-service" / "service.toml"
# The ARG-name prefix of each provider's CLI pins in the Dockerfile, and what its `--version` says.
DOCKERFILE_PREFIXES = {"anthropic": "CLAUDE", "openai": "CODEX"}
VERSION_REPORTS = {"anthropic": "{version} (Claude Code)", "openai": "codex-cli {version}"}
ABSENT_VERSION = "0.0.1"
# BuildKit's refusal of a fetched file whose sha256 is not the pinned one; an absent release
# is fetched as some other body and refused the same way.
DIGEST_REFUSAL = "digest mismatch"
SERVICE_PORT = 8080
LISTEN_SECONDS = 60
BUILD_SECONDS = 1500
RUN_SECONDS = 120
TOKEN_PATTERN = "sk-ant-[a-z]{3}[0-9]{2}-[A-Za-z0-9_-]{20,}"  # noqa: S105 - a pattern that finds tokens in output and holds none
# grep exits 0 on a match and 1 on none; anything above is an error that must not pass.
TOKEN_SEARCH = (
    "for path in /* /.[!.]* /..?*; do "
    '[ -e "$path" ] || [ -L "$path" ] || continue; '
    'case "$path" in /proc|/sys) continue;; esac; '
    f'grep -rlaE "{TOKEN_PATTERN}" "$path"; status=$?; '
    '[ "$status" -le 1 ] || exit "$status"; '
    "done"
)
BASE_IMAGE = re.compile(
    r"^FROM (docker\.io/library/python:\S+@sha256:[0-9a-f]{64})(?: AS \S+)?$", re.MULTILINE
)
LOGIN_PATHS = (
    "managed-settings.json",
    "managed-mcp.json",
    ".claude",
    ".claude.json",
    ".credentials.json",
    "claude-code",
    ".codex",
    "auth.json",
)
LOGIN_ENVIRONMENT = re.compile(r"(CLAUDE|ANTHROPIC|CODEX|OPENAI)")


class ProbeFailed(Exception):
    """A cell did not hold; the message names what was expected and what came back."""


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise ProbeFailed(message)


def docker(
    arguments: Sequence[str], *, timeout: int = RUN_SECONDS, check: bool = False
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(  # noqa: S603 - argv is built by the program itself and no shell runs
        ["docker", *arguments],  # noqa: S607 - docker is found on PATH by design
        capture_output=True,
        text=True,
        timeout=timeout,
        stdin=subprocess.DEVNULL,
    )
    if check and result.returncode != 0:
        raise ProbeFailed(f"docker {' '.join(arguments[:2])} failed: {result.stderr[-400:]}")
    return result


def build(context: Path, transcript: Path, *extra: str, tag: str = IMAGE, cache: bool = False):
    result = docker(
        [
            "build",
            "--progress=plain",
            *([] if cache else ["--no-cache"]),
            *extra,
            "-f",
            str(context / "Dockerfile"),
            "-t",
            tag,
            str(context),
        ],
        timeout=BUILD_SECONDS,
    )
    # The path is the operator's own --output, made absolute and checked once at the argparse
    # boundary by egress.scratch_directory; Sonar does not follow that check across calls.
    transcript.write_text(result.stdout + result.stderr, encoding="utf-8")  # NOSONAR(S8707)
    return result


def shipped_cli(provider: str) -> dict:
    """The `[cli.<provider>]` table of the service.toml the service ships."""
    shipped = tomllib.loads(SHIPPED_CONFIGURATION.read_text(encoding="utf-8"))
    return shipped["cli"][provider]


def normalized_name(name: str) -> str:
    """A distribution name as pip and the lock may spell it (`ruamel.yaml`, `ruamel-yaml`)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def lock_versions() -> dict[str, str]:
    """The name and version of every package the lock pins, wheels by their file names."""
    versions: dict[str, str] = {}
    for line in (IMAGE_DIRECTORY / "requirements.txt").read_text(encoding="utf-8").splitlines():
        pinned = re.match(r"([A-Za-z0-9._-]+)==([^\s;]+)", line)
        wheel = re.match(r"([A-Za-z0-9._-]+) @ \S+/[^/\s]+?-(\d[^-/\s]*)-py3-none-any\.whl", line)
        if match := pinned or wheel:
            versions[normalized_name(match.group(1))] = match.group(2)
    return versions


def cell_i1(output: Path) -> None:
    result = build(IMAGE_DIRECTORY, output / "i1-build.txt")
    expect(result.returncode == 0, f"I1: the build failed (see {output / 'i1-build.txt'})")
    text = result.stdout + result.stderr
    expect("No broken requirements found." in text, "I1: pip check did not pass in the build")


def cell_i2(output: Path, scratch: Path) -> None:
    for provider, prefix in DOCKERFILE_PREFIXES.items():
        altered = build(
            IMAGE_DIRECTORY,
            output / f"i2-{provider}-hash.txt",
            "--build-arg",
            f"{prefix}_SHA256={'0' * 64}",
            tag=f"{PROBE_NAME}:i2-{provider}",
            cache=True,
        )
        expect(altered.returncode != 0, f"I2: a build with an altered {provider} hash succeeded")
        expect(
            DIGEST_REFUSAL in altered.stdout + altered.stderr,
            f"I2: BuildKit did not refuse the {provider} download's altered sha256",
        )
    context = scratch / "altered-wheel"
    shutil.copytree(IMAGE_DIRECTORY, context)
    lock = context / "requirements.txt"
    text = lock.read_text(encoding="utf-8")
    anchor = text.index("overnightworks_agent_runtime_client-")
    digest_at = text.index("sha256:", anchor) + len("sha256:")
    flipped = "0" if text[digest_at] != "0" else "1"
    lock.write_text(text[:digest_at] + flipped + text[digest_at + 1 :], encoding="utf-8")
    altered_wheel = build(
        context, output / "i2-wheel-hash.txt", tag=f"{PROBE_NAME}:i2-wheel", cache=True
    )
    both = altered_wheel.stdout + altered_wheel.stderr
    expect(altered_wheel.returncode != 0, "I2: a build with an altered wheel hash succeeded")
    expect("DO NOT MATCH THE HASHES" in both, "I2: pip did not refuse the altered wheel hash")


def cell_i3(output: Path) -> dict[str, str]:
    """Which check refused the build of each CLI at an absent version, built on I1's warm cache."""
    refusals = {}
    for provider, prefix in DOCKERFILE_PREFIXES.items():
        result = build(
            IMAGE_DIRECTORY,
            output / f"i3-absent-{provider}.txt",
            "--build-arg",
            f"{prefix}_VERSION={ABSENT_VERSION}",
            tag=f"{PROBE_NAME}:i3-{provider}",
            cache=True,
        )
        expect(result.returncode != 0, f"I3: a build for an absent {provider} version succeeded")
        text = result.stdout + result.stderr
        # BuildKit echoes the RUN step with the absent version filled in, so only the check's own
        # message, which ends with the report it expected, shows that the check refused it.
        if f", not '{VERSION_REPORTS[provider].format(version=ABSENT_VERSION)}'" in text:
            refusals[provider] = "the version check"
        elif DIGEST_REFUSAL in text:
            refusals[provider] = "BuildKit's digest check at the fetch"
        else:
            raise ProbeFailed(
                f"I3: neither the fetch nor the version check stopped the {provider} build"
            )
    return refusals


def run_in_image(
    arguments: Sequence[str],
    *,
    entrypoint: str,
    user: str = "1000:1000",
    read_only: bool = True,
    image: str = IMAGE,
    options: Sequence[str] = (),
) -> subprocess.CompletedProcess[str]:
    return docker(
        [
            "run",
            "--rm",
            NO_NETWORK,
            f"--user={user}",
            *(["--read-only"] if read_only else []),
            f"--entrypoint={entrypoint}",
            *options,
            image,
            *arguments,
        ],
        check=False,
    )


def version_reports() -> list[str]:
    """What each shipped CLI's `--version` must say, from the pin in service.toml."""
    return [
        VERSION_REPORTS[provider].format(version=shipped_cli(provider)["version"])
        for provider in DOCKERFILE_PREFIXES
    ]


def cell_i4() -> None:
    for provider, report in zip(DOCKERFILE_PREFIXES, version_reports(), strict=True):
        version = run_in_image(["--version"], entrypoint=shipped_cli(provider)["binary"])
        expect(
            version.stdout.strip() == report,
            f"I4: {provider} --version printed {version.stdout!r} {version.stderr[-200:]!r}",
        )
    platform = run_in_image(
        ["-c", "import platform;print(platform.libc_ver()[0], platform.machine())"],
        entrypoint="python",
    )
    expect(platform.stdout.strip() == "glibc x86_64", f"I4: python is {platform.stdout!r}")


def service_configuration() -> str:
    claude, codex = (shipped_cli(provider) for provider in DOCKERFILE_PREFIXES)
    return f"""[identity]
issuer = "https://issuer.invalid/realms/probe"
jwks_url = "https://issuer.invalid/realms/probe/protocol/openid-connect/certs"
audience = "agent-service"
subscription_groups = ["/services/agent-service/subscription"]
group_claim = "groups"

[server]
host = "0.0.0.0"
port = {SERVICE_PORT}

[cli]
working_root = "/run/work"

[cli.anthropic]
binary = "{claude["binary"]}"
version = "{claude["version"]}"
models = ["sonnet"]
token_file = "/run/secrets/claude-token"

[cli.openai]
binary = "{codex["binary"]}"
version = "{codex["version"]}"
models = ["probe-model"]
token_file = "/run/secrets/codex-login.json"

[defaults]
model = "anthropic/sonnet"

[apps.probe]
workload_client = "probe-client"
"""


PROBE_APP_TABLE = "[apps.probe]"
LEFTOVER_CONFIGURATION = {
    "identity.subscription_group": (
        "[server]",
        'subscription_group = "/services/agent-service/subscription"\n\n[server]',
    ),
    "purposes": (
        PROBE_APP_TABLE,
        f'[purposes.chat]\ncli_provider = "claude"\n\n{PROBE_APP_TABLE}',
    ),
    "apps.probe.tools": (PROBE_APP_TABLE, f"[apps.probe.tools]\n\n{PROBE_APP_TABLE}"),
    "apps.probe.models": (PROBE_APP_TABLE, f"[apps.probe.models]\n\n{PROBE_APP_TABLE}"),
    "profiles": (
        PROBE_APP_TABLE,
        f'[profiles.subscription]\nprovider = "claude"\n\n{PROBE_APP_TABLE}',
    ),
    "cli.claude": (
        "[cli.anthropic]",
        '[cli.claude]\nbinary = "/opt/claude/claude"\n\n[cli.anthropic]',
    ),
}


def cell_i8(scratch: Path) -> None:
    """A dropped field, or a missing required one, stops the start and the log names it."""
    for field, (anchor, leftover) in LEFTOVER_CONFIGURATION.items():
        configuration = scratch / "leftover.toml"
        configuration.write_text(
            service_configuration().replace(anchor, leftover), encoding="utf-8"
        )
        started = docker(
            [
                "run", "--rm", NO_NETWORK, "--read-only", "--cap-drop=ALL",
                f"--mount=type=bind,source={configuration},target=/etc/agent-service/service.toml,readonly",
                IMAGE,
            ],
            check=False,
        )  # fmt: skip
        said = started.stdout + started.stderr
        expect(started.returncode != 0, f"I8: a leftover {field} did not stop the start")
        expect(f"{field}:" in said, f"I8: the refusal of {field} says {said[-300:]!r}")


def free_loopback_port() -> int:
    with socket.socket() as probe_socket:
        probe_socket.bind(("127.0.0.1", 0))
        return probe_socket.getsockname()[1]


def wait_until_listening() -> None:
    """The published port accepts connections before the service does, so uvicorn's own line
    in the service's log is the evidence that it listens."""
    deadline = time.monotonic() + LISTEN_SECONDS
    while time.monotonic() < deadline:
        state = docker(["inspect", "--format", "{{.State.Running}}", PROBE_NAME])
        expect(state.stdout.strip() == "true", "I5: the container stopped before it listened")
        logs = docker(["logs", PROBE_NAME])
        if f"Uvicorn running on http://0.0.0.0:{SERVICE_PORT}" in logs.stdout + logs.stderr:
            return
        time.sleep(0.5)
    raise ProbeFailed("I5: the service did not listen in time")


def unauthenticated_run_status(port: int) -> int:
    request = urllib.request.Request(
        f"http://127.0.0.1:{port}/runs", data=b"{}", method="POST",
        headers={"Content-Type": "application/json"},
    )  # fmt: skip
    try:
        with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - an http URL on the loopback address
            return response.status
    except urllib.error.HTTPError as refusal:
        return refusal.code


def cell_i5(output: Path, scratch: Path) -> None:
    configuration = scratch / "service.toml"
    token, codex_login = scratch / "claude-token", scratch / "codex-login.json"
    configuration.write_text(service_configuration(), encoding="utf-8")
    write_dummy_token(token)
    write_dummy_codex_login(codex_login)
    port = free_loopback_port()
    docker(
        [
            "run",
            "--detach",
            "--name",
            PROBE_NAME,
            "--read-only",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--tmpfs",
            "/run/work:mode=0700,uid=1000,gid=1000",
            "--mount",
            f"type=bind,source={configuration},target=/etc/agent-service/service.toml,readonly",
            "--mount",
            f"type=bind,source={token},target=/run/secrets/claude-token,readonly",
            "--mount",
            f"type=bind,source={codex_login},target=/run/secrets/codex-login.json,readonly",
            "--publish",
            f"127.0.0.1:{port}:{SERVICE_PORT}",
            IMAGE,
        ],
        check=True,
    )
    try:
        wait_until_listening()
        status = unauthenticated_run_status(port)
    finally:
        logs = docker(["logs", PROBE_NAME])
        # The path is the operator's own --output, made absolute and checked once at the argparse
        # boundary by egress.scratch_directory; Sonar does not follow that check across calls.
        (output / "i5-service.txt").write_text(  # NOSONAR(S8707)
            logs.stdout + logs.stderr, encoding="utf-8"
        )
    expect(status == 401, f"I5: POST /runs without tokens answered {status}, not 401")


def bite_check_failure(bitten: subprocess.CompletedProcess[str], planted: str) -> str | None:
    """Why the planted-file run does not prove the token search bites, or None when it does.
    Planting and searching are chained, so exit status 0 means both succeeded."""
    if bitten.returncode != 0:
        return (
            f"planting or searching exited with status {bitten.returncode}: "
            f"{bitten.stderr[-300:]!r}, found {bitten.stdout!r}"
        )
    if bitten.stdout.split() != [planted]:
        return f"the token search missed a token inside a binary file: {bitten.stdout!r}"
    return None


def cell_i6(image: str = IMAGE, options: Sequence[str] = ()) -> None:
    """Both searches run as root over the whole file system, so no directory hides from them,
    and any error of a search fails the cell. `image` and `options` name another image and the
    docker options of its containers."""
    run = partial(run_in_image, image=image, options=options)
    names = " -o ".join(f"-name '{name}'" for name in LOGIN_PATHS)
    found = run(["-c", f"find / -xdev \\( {names} \\)"], entrypoint="sh", user="0:0")
    expect(found.returncode == 0, f"I6: the login search failed: {found.stderr[-300:]!r}")
    expect(found.stdout.strip() == "", f"I6: the image holds login files: {found.stdout!r}")
    tokens = run(["-c", TOKEN_SEARCH], entrypoint="sh", user="0:0")
    expect(tokens.returncode == 0, f"I6: the token search failed: {tokens.stderr[-300:]!r}")
    expect(tokens.stdout.strip() == "", f"I6: a token-shaped text is in {tokens.stdout!r}")
    planted = "/usr/local/planted.bin"
    fake_token = "sk-ant-" + "api03-" + "a" * 30
    bitten = run(
        ["-c", f"printf '\\000{fake_token}\\000' > {planted} && {TOKEN_SEARCH}"],
        entrypoint="sh",
        user="0:0",
        read_only=False,
    )
    failure = bite_check_failure(bitten, planted)
    expect(failure is None, f"I6: {failure}")
    environment = json.loads(
        docker(["image", "inspect", image, "--format", "{{json .Config.Env}}"]).stdout
    )
    offending = login_environment_names(environment)
    expect(
        not offending,
        f"I6: the image sets a Claude, Anthropic, Codex or OpenAI variable: {offending}",
    )


def login_environment_names(environment: list[str]) -> list[str]:
    """The names, never the values, of the entries that set a login variable."""
    return [entry.split("=", 1)[0] for entry in environment if LOGIN_ENVIRONMENT.match(entry)]


def package_versions(frozen: str) -> dict[str, str]:
    pairs = (line.split("==") for line in frozen.split())
    return {normalized_name(name): version for name, version in pairs}


def base_package_versions() -> dict[str, str]:
    """What the pinned base image itself ships, read from the same digest the Dockerfile names."""
    dockerfile = (IMAGE_DIRECTORY / "Dockerfile").read_text(encoding="utf-8")
    base = BASE_IMAGE.search(dockerfile)
    expect(base is not None, "I7: the Dockerfile names no digest-pinned python base image")
    frozen = docker(
        [
            "run", "--rm", NO_NETWORK, "--pull=missing", "--entrypoint=python",
            base.group(1), "-m", "pip", "list", "--format=freeze",
        ],
        check=True,
    )  # fmt: skip
    return package_versions(frozen.stdout)


def cell_i7() -> None:
    frozen = run_in_image(["-m", "pip", "list", "--format=freeze"], entrypoint="python")
    expected = {**base_package_versions(), **lock_versions()}
    installed = package_versions(frozen.stdout)
    expect(installed == expected, f"I7: pip freeze differs from the lock and the base: {installed}")


def remove_probe_artifacts() -> None:
    docker(["rm", "--force", PROBE_NAME])
    images = docker(["images", "--format", "{{.Repository}}:{{.Tag}}", PROBE_NAME]).stdout.split()
    if images:
        docker(["rmi", "--force", *images])


def interrupt(*_: object) -> None:
    """`timeout`'s SIGTERM unwinds the probe, so its teardown removes the container."""
    raise KeyboardInterrupt


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=scratch_directory,
        help="an existing, writable directory for the docker transcripts",
    )
    arguments = parser.parse_args(argv)
    signal.signal(signal.SIGTERM, interrupt)
    output = arguments.output or Path(tempfile.mkdtemp(prefix="agent-image-probe-"))
    write_line(f"transcripts: {output}")
    with tempfile.TemporaryDirectory(prefix="agent-image-probe-") as scratch_name:
        scratch = Path(scratch_name)
        try:
            cell_i1(output)
            write_line(
                "I1 held: built with --no-cache, the CLI files served by digest, "
                "both versions checked, pip check passed"
            )
            cell_i2(output, scratch)
            write_line("I2 held: an altered hash of either CLI or of a wheel fails the build")
            refusals = cell_i3(output)
            write_line(
                "I3 held: an absent version of either CLI fails the build ("
                + ", ".join(f"{provider}: {check}" for provider, check in refusals.items())
                + ")"
            )
            cell_i4()
            write_line(
                f"I4 held: uid 1000, read-only root, {', '.join(version_reports())}, "
                "glibc on x86_64"
            )
            cell_i5(output, scratch)
            write_line(
                "I5 held: the entrypoint listened after its version probe; POST /runs was 401"
            )
            cell_i6()
            write_line("I6 held: no managed settings, no Claude or Codex login, no token")
            cell_i7()
            write_line("I7 held: pip freeze is exactly the lock's names and versions")
            cell_i8(scratch)
            write_line("I8 held: a leftover of the old configuration shape stops the start")
        except (ProbeFailed, subprocess.TimeoutExpired, KeyboardInterrupt) as failure:
            write_line(f"FAILED {type(failure).__name__}: {failure}", stream=Stream.STDERR)
            return 1
        finally:
            remove_probe_artifacts()
    return 0


if __name__ == "__main__":
    sys.exit(main())
