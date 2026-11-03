"""The boundary to systemd for the tunnel: `systemctl` verbs and `pkcheck`, nothing else.

edge never handles credentials (rule 8): a password goes to the system's own prompt, and the
tunnel's own files are never read. The unit and the manager are parameters, so the probe can drive
a throwaway user unit in place of `cloudflared.service`.
"""

import subprocess
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Self

CLOUDFLARED_UNIT = "cloudflared.service"
BOOT_DROP_IN = "30-hal-global-stop.conf"
MANAGE_UNITS_ACTION = "org.freedesktop.systemd1.manage-units"
UNIT_VARIABLE = "EDGE_TUNNEL_UNIT"
MANAGER_VARIABLE = "EDGE_TUNNEL_MANAGER"
STOPPED_STATES = frozenset({"inactive", "failed"})
_SECONDS = 120

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]


class TunnelError(Exception):
    """systemd cannot be asked; the message is one line."""


class Manager(StrEnum):
    SYSTEM = "system"
    USER = "user"

    @property
    def flag(self) -> str:
        return f"--{self.value}"


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    """Only stdout is captured: stdin and stderr stay the terminal's, for the system's prompt."""
    try:
        return subprocess.run(  # noqa: S603 - argv is a systemctl or pkcheck command hal builds and no shell runs
            command, stdout=subprocess.PIPE, text=True, check=False, timeout=_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TunnelError(f"cannot run {command[0]} ({error})") from error


@dataclass(frozen=True)
class Tunnel:
    unit: str = CLOUDFLARED_UNIT
    manager: Manager = Manager.SYSTEM
    run: Runner = run_command

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> Self:
        """`cloudflared.service` of the system manager unless the probe names a throwaway unit."""
        manager = environment.get(MANAGER_VARIABLE, Manager.SYSTEM)
        try:
            return cls(environment.get(UNIT_VARIABLE, CLOUDFLARED_UNIT), Manager(manager))
        except ValueError:
            known = " or ".join(Manager)
            raise TunnelError(f"{MANAGER_VARIABLE} must be {known}, not {manager!r}") from None

    def stop(self, *, may_ask_password: bool) -> None:
        """Ask for the stop; whether it happened is for `is_inactive` to say. Without a terminal
        nobody could answer a prompt."""
        flags = [] if may_ask_password else ["--no-ask-password"]
        self._systemctl(*flags, "stop")

    def start(self) -> bool:
        """True when systemd accepted the start; a password goes to the system's own prompt."""
        return self._systemctl("start").returncode == 0

    def is_active(self) -> bool:
        return self._state() == "active"

    def is_inactive(self) -> bool:
        return self._state() in STOPPED_STATES

    def has_boot_drop_in(self) -> bool:
        shown = self._systemctl("show", "-p", "DropInPaths").stdout.strip()
        paths = shown.removeprefix("DropInPaths=").split()
        return any(PurePosixPath(path).name == BOOT_DROP_IN for path in paths)

    def authorized_to_start(self, process_id: int) -> bool:
        """The system's authorization for `start`, asked before anything is cleared. The user
        manager answers to its own user, so there is nothing to ask.

        The internal agent prompts on the terminal where no desktop agent is registered (an SSH
        session); only stdout is captured, so the prompt stays visible."""
        if self.manager is Manager.USER:
            return True
        asked = self.run(
            ["pkcheck", "--action-id", MANAGE_UNITS_ACTION, "--process", str(process_id),
             "--allow-user-interaction", "--enable-internal-agent"]
        )  # fmt: skip
        return asked.returncode == 0

    def _state(self) -> str:
        return self._systemctl("is-active").stdout.strip()

    def _systemctl(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return self.run(["systemctl", self.manager.flag, *arguments, self.unit])
