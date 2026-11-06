"""Importing the modules of `probe/agent-service`: they import each other by bare name from their
own directory, so a test puts that directory on the path for its module and forgets the modules it
brought in afterwards."""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from pathlib import Path
from types import SimpleNamespace

from support.script_module import importing_from

ROOT = Path(__file__).resolve().parents[2]


def probe_imports() -> AbstractContextManager[None]:
    return importing_from(ROOT / "probe" / "agent-service", ROOT / "agent-service")


TOKEN = "sk-ant-oat01-dummy-token"
LOGIN = "/run/agent-service/login/claude"
CONFIGURATION = "/etc/agent-service/service.toml"


@contextmanager
def login_probe_modules() -> Iterator[SimpleNamespace]:
    """The modules of the login command (#457), imported for the length of the `with`."""
    with probe_imports():
        import cells_12b
        import census_client
        import egress
        import fake_app
        import image
        import login_checks

        yield SimpleNamespace(
            cells=cells_12b, checks=login_checks, census=census_client, egress=egress,
            fake_app=fake_app, image=image,
        )  # fmt: skip


def make_login(directory: Path, content: bytes = TOKEN.encode() + b"\n") -> Path:
    directory.mkdir()
    (directory / "token").write_bytes(content)
    return directory


def resolved(*, login_source="/login", configuration_source="/scratch/service.toml") -> dict:
    return {
        "services": {
            "agent-service": {
                "read_only": True,
                "logging": {"driver": "local"},
                "volumes": [
                    {"type": "bind", "source": login_source, "target": LOGIN, "read_only": True},
                    {
                        "type": "bind",
                        "source": configuration_source,
                        "target": CONFIGURATION,
                        "read_only": True,
                    },
                ],
            },
            "agent-egress": {"logging": {"driver": "local"}},
            "agent-issuer": {"logging": {"driver": "local"}},
            "agent-app": {"logging": {"driver": "local"}},
        }
    }
