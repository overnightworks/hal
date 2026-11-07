"""Importing the modules of `probe/agent-service`: they import each other by bare name from their
own directory, so a test puts that directory on the path for its module and forgets the modules it
brought in afterwards."""

from __future__ import annotations

from contextlib import AbstractContextManager
from pathlib import Path

from support.script_module import importing_from

ROOT = Path(__file__).resolve().parents[2]


def probe_imports() -> AbstractContextManager[None]:
    return importing_from(ROOT / "probe" / "agent-service", ROOT / "agent-service")
