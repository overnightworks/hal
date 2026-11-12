from __future__ import annotations

from datetime import datetime
from pathlib import Path

import pytest
from support.workstation_secrets_report import findings_of, report_of
from support.workstation_support import FakeProbe, plant_secrets, run_hal_secrets

NOW = datetime(2026, 10, 15, 9, 0)


@pytest.mark.parametrize("name", ["cloudflare/fleet-read", "cloudflare/fleet-write", "opentofu/state-passphrase"])
def test_a_file_the_operator_keeps_to_delete_by_hand_is_no_finding(tmp_path: Path, probe: FakeProbe, capsys, name: str) -> None:
    home = tmp_path / "home"
    plant_secrets(home)
    kept = home / ".secrets" / name
    kept.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    kept.write_text("dummy")
    kept.chmod(0o600)
    run_hal_secrets(home, probe, now=NOW)
    assert findings_of(report_of(home), "unknown-file") == {}
    assert kept.read_text() == "dummy"
