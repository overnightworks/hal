"""The step-ca probe's verdict (#346 P13): a cell that could not run is not held."""

import json
import os
import signal
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
from support.script_module import loaded_script, script_module

ROOT = Path(__file__).resolve().parents[1]
STEP_CA = ROOT / "probe" / "step-ca"
PROBE = STEP_CA / "probe.py"


def load_mcp_networks() -> ModuleType:
    """At collection: the parameters of the tests read its exit code."""
    with script_module("mcp_networks", STEP_CA / "mcp_networks.py", STEP_CA) as module:
        return module


mcp_networks = load_mcp_networks()


@pytest.fixture(scope="module")
def probe() -> Iterator[ModuleType]:
    yield from loaded_script("step_ca_probe", PROBE)


def test_a_probe_with_a_cell_not_driven_is_incomplete_and_not_passed(
    capsys: pytest.CaptureFixture[str],
):
    exit_code = mcp_networks.print_verdict(["P13 (the image edge-agent-service is absent)"])

    output = capsys.readouterr().out
    assert exit_code == mcp_networks.INCOMPLETE_EXIT_CODE != 0
    assert "PROBE INCOMPLETE" in output
    assert "P13" in output
    assert "PROBE PASSED" not in output


def test_a_probe_with_every_cell_driven_passes(capsys: pytest.CaptureFixture[str]):
    assert mcp_networks.print_verdict([]) == 0
    assert "PROBE PASSED" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("not_driven", "left_behind", "exit_code", "verdict"),
    [
        (["P13 (no image)"], False, mcp_networks.INCOMPLETE_EXIT_CODE, "PROBE INCOMPLETE"),
        (["P13 (no image)"], True, 1, None),
        ([], True, 1, None),
        ([], False, 0, "PROBE PASSED"),
    ],
    ids=["not-driven", "not-driven-teardown-fails", "driven-teardown-fails", "driven"],
)
def test_main_ends_with_the_verdict_of_the_driven_cells(
    probe: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    not_driven: list[str],
    left_behind: bool,
    exit_code: int,
    verdict: str | None,
) -> None:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$*" in\n'
        f"  *\" config \"*) echo '{json.dumps({'name': probe.PROJECT})}' ;;\n"
        f"  ps*) {'echo leftover-container' if left_behind else ':'} ;;\n"
        '  volume*|network*|*" down "*) ;;\n'
        "  *) exit 1 ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}:{os.environ['PATH']}")

    def prove_filling(drive: Any) -> int:
        drive.not_driven.extend(not_driven)
        return 0

    monkeypatch.setattr(probe, "prove", prove_filling)
    handlers_before = {
        number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGINT)
    }
    (tmp_path / "scratch").mkdir()
    try:
        actual = probe.main(["--scratch", str(tmp_path / "scratch")])
    finally:
        for number, handler in handlers_before.items():
            signal.signal(number, handler)

    lines = capsys.readouterr().out.splitlines()
    assert actual == exit_code
    assert not any(tmp_path.joinpath("scratch").iterdir())
    if verdict is None:
        assert not any(line.startswith(("PROBE PASSED", "PROBE INCOMPLETE")) for line in lines)
    else:
        assert lines[-1].startswith(verdict)
    assert ("PROBE PASSED" in "".join(lines)) == (verdict == "PROBE PASSED")
