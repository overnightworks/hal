"""The one owner of the operator-facing command name: the program, the verbs it registers and the
text of a command as a person types it. It imports nothing else of this repository."""

from enum import StrEnum

PROGRAM = "hal"


class Verb(StrEnum):
    APPLY = "apply"
    UPDATE = "update"
    STOP = "stop"
    START = "start"
    OFFLINE = "offline"
    ONLINE = "online"
    SETUP = "setup"
    CHECK = "check"
    ALARM = "alarm"
    BACKUP = "backup"
    RESTORE = "restore"
    VERSION = "version"
    LEGAL = "legal"
    RENAME = "rename"
    MIGRATE = "migrate"
    SECRETS = "secrets"


def command(verb: Verb, *arguments: str) -> str:
    return " ".join((PROGRAM, verb, *arguments))
