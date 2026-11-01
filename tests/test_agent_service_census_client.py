"""The host side of the census (#457): what a mount shows of a skipped root, and that a failing
census relays nothing of its output."""

from __future__ import annotations

import ast
import json
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType

import pytest
from support.probe_support import probe_imports

KEY_MARKER = "KEY-MARKER-IN-STDERR"
PROBES = Path(__file__).resolve().parents[1] / "probe" / "agent-service"


@pytest.fixture(scope="module")
def census_client() -> Iterator[ModuleType]:
    with probe_imports():
        import census_client as module

        yield module


@pytest.mark.parametrize(
    ("listings", "skips", "listed"),
    [
        ((), (("refused", 1),), False),
        ((), (), True),
        ((("a", "file"),), (("refused", 1),), True),
        ((("a", "file"),), (), True),
    ],
    ids=["no listing and a skip", "no listing and no skip", "listings and a skip", "listings"],
)
def test_a_mount_is_listed_unless_it_shows_nothing_and_skipped_something(
    census_client, listings, skips, listed
):
    """#457 row 8: a mount with no listing and a skip is not listed."""
    assert census_client.Mount(listings, skips).listed is listed


@pytest.mark.parametrize("returncode", [1, 0], ids=["exit status", "census error"])
def test_a_failing_census_relays_neither_stderr_nor_its_key(census_client, returncode):
    """#457 row 7: a failing census relays neither stderr nor its key."""

    class Probe:
        def run(self, command, *, stdin, check, timeout):
            assert check is False
            stdout = '{"error": "failed"}\n' if returncode == 0 else ""
            return subprocess.CompletedProcess(command, returncode, stdout, KEY_MARKER)

    client = object.__new__(census_client.CensusClient)
    client.probe = Probe()
    client.container = "container"
    client.key = b"\x01" * 16
    with pytest.raises(census_client.ProbeFailed) as raised:
        client.ask({"mode": "census"})
    assert KEY_MARKER not in str(raised.value)
    assert client.key.hex() not in str(raised.value)


def test_a_watch_sends_its_settings_and_parses_the_report(census_client):
    """B9 (b), (c): the watch asks in watch mode for the working root and gives back its report."""
    asked = []
    report = {
        "group_seen": True, "group_gone_at": 12.5, "tree_seen": True, "tree_gone_at": None,
        "samples": 9,
    }  # fmt: skip

    class Probe:
        def run(self, command, *, stdin, check, timeout):
            asked.append(stdin)
            return subprocess.CompletedProcess(command, 0, json.dumps(report) + "\n", "")

    client = object.__new__(census_client.CensusClient)
    client.probe, client.container, client.key = Probe(), "container", b"\x01" * 16
    client.working_root = "/work"
    assert client.watch(120)._asdict() == report
    literal = asked[0].rsplit("emit(", 1)[1].strip().removesuffix(")")
    settings = json.loads(ast.literal_eval(literal))
    expected = ("watch", "/work", 120)
    assert (settings["mode"], settings["working_root"], settings["deadline"]) == expected


@pytest.mark.parametrize("module", ["census_client", "containment", "login_checks"])
def test_a_module_of_the_probes_imports_as_the_first_one(module: str) -> None:
    program = f"import sys; sys.path.insert(0, {str(PROBES)!r}); import {module}"

    result = subprocess.run(  # noqa: S603 - argv is built by the test itself and no shell runs
        [sys.executable, "-I", "-c", program], capture_output=True, text=True, check=False
    )

    assert result.returncode == 0, result.stderr
