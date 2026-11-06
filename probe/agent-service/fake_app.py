"""The fake app of the agent service's probes: a service on `agent-songmaker` that lists tools
(app_tools.py), certified by the scratch CA and named in place of songmaker's origin in the
scratch `service.toml`. It logs only the closed vocabulary below, never a token."""

from __future__ import annotations

import json
import re
from enum import StrEnum
from pathlib import Path

from egress import expect
from litellm_ca import issue_certificate

APP_SERVICE = "agent-app"
APP_PORT = 8444
APP_ORIGIN = f"https://{APP_SERVICE}:{APP_PORT}"
HELD_LINE = "method=tools/call tool=step held"
RELEASED_PREFIX = "method=tools/call tool=step released at="
APP_LINE = re.compile(
    r"(?:method=(?:initialize|notifications/initialized|tools/list|other) "
    r"offered=(?:-|step,bare,extra) canary=[01] bearer=[01])"
    rf"|{re.escape(HELD_LINE)}"
    rf"|{re.escape(RELEASED_PREFIX)}\d+\.\d{{3}}"
    r"|method=tools/call tool=other"
)
APP_HANDSHAKE = (
    "method=initialize offered=- canary=0 bearer=1",
    "method=notifications/initialized offered=- canary=0 bearer=1",
)
APP_LISTING = "method=tools/list offered=step,bare,extra canary={canary} bearer=1"


class Mode(StrEnum):
    RELAY = "relay"
    CANARY = "canary"
    HOLD = "hold"


def with_setting(text: str, table: str, key: str, value: str) -> str:
    """The service's configuration with the one `key = "..."` line of `[table]` set to `value`."""
    section = re.compile(rf"^\[{re.escape(table)}\]\n(?:(?!\[).*\n?)*", re.MULTILINE)
    sections = list(section.finditer(text))
    expect(len(sections) == 1, f"service.toml: no single [{table}]")
    line = re.compile(rf'^{re.escape(key)} = ".*"$', re.MULTILINE)
    body = sections[0].group()
    expect(len(line.findall(body)) == 1, f"service.toml: no single {key} in [{table}]")
    set_body = line.sub(lambda _: f'{key} = "{value}"', body)
    return text[: sections[0].start()] + set_body + text[sections[0].end() :]


class FakeApp:
    """A mixin over `IssuerProbe`: the fake app's certificate, mode file and overlay service, and
    the service's configuration pointing at it."""

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        directory = scratch / "fake-app"
        directory.mkdir()
        app = directory / "app"
        app.mkdir()
        self.mode_directory = directory / "mode"
        self.mode_directory.mkdir()
        self.write_mode(Mode.RELAY)
        certificate, key = issue_certificate(self.scratch_secrets, APP_SERVICE, app)
        for readable in (app, self.mode_directory):
            readable.chmod(0o755)
        for name in (certificate, key):
            name.chmod(0o644)
        self.configuration.write_text(
            with_setting(
                self.configuration.read_text(encoding="utf-8"),
                "apps.songmaker",
                "mcp_origin",
                APP_ORIGIN,
            ),
            encoding="utf-8",
        )
        program = Path(__file__).resolve().with_name("app_tools.py")
        overlay = scratch / "compose.app.yaml"
        overlay.write_text(
            json.dumps({"services": {
                APP_SERVICE: {
                    "image": self.image,
                    "profiles": ["agent-service"],
                    "user": "65534:65534", "read_only": True, "cap_drop": ["ALL"],
                    "security_opt": ["no-new-privileges:true"], "networks": ["agent-songmaker"],
                    "entrypoint": ["python", "-I", "-B", "/app_tools.py"],
                    "volumes": [
                        {"type": "bind", "source": str(program), "target": "/app_tools.py",
                         "read_only": True},
                        {"type": "bind", "source": str(app), "target": "/app",
                         "read_only": True},
                        {"type": "bind", "source": str(self.mode_directory), "target": "/mode",
                         "read_only": True},
                    ],
                },
            }}),
            encoding="utf-8",
        )  # fmt: skip
        self.overlays.append(overlay)

    def write_mode(self, mode: Mode) -> None:
        (self.mode_directory / "mode").write_text(mode.value, encoding="utf-8")
        (self.mode_directory / "mode").chmod(0o644)

    def app_lines(self, seconds: int = 300, container: str | None = None) -> list[str]:
        return self.container_log(APP_SERVICE, timeout=seconds, container=container).splitlines()
