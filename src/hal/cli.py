"""`hal`: the door. It lists its commands, parses the command line, and gives every command the
same exit codes and the same error form (`error: …`, then `next: …`), with no traceback."""

import argparse
import sys
from collections.abc import Sequence

from hal import (
    alarm_commands,
    backup_commands,
    check_commands,
    legal_commands,
    migrate_commands,
    rename_commands,
    secrets_commands,
    setup_commands,
    stack_commands,
    version,
)
from hal.grammar import Command, ExitCode
from hal.output import log_format_refusal, logger_run, verbose_run, write_error
from hal.output.command import PROGRAM
from hal.workstation import secrets_view

DESCRIPTION = "hal, the daily door of the workstation."
COMMANDS = (
    *stack_commands.COMMANDS,
    *backup_commands.COMMANDS,
    *check_commands.COMMANDS,
    *alarm_commands.COMMANDS,
    *secrets_commands.COMMANDS,
    *setup_commands.COMMANDS,
    *rename_commands.COMMANDS,
    *migrate_commands.COMMANDS,
    *legal_commands.COMMANDS,
    version.COMMAND,
)


class _Parser(argparse.ArgumentParser):
    """A usage error is one `error:`/`next:` pair that names the parser's own help, exit 2."""

    def error(self, message: str):
        write_error(message, f"{self.prog} --help")
        raise SystemExit(ExitCode.USAGE)

    def parse_known_args(self, args=None, namespace=None):
        # A subcommand's parser judges its own leftovers, so the pair names its help, not hal's.
        parsed, unrecognized = super().parse_known_args(args, namespace)
        if unrecognized:
            self.error(f"unrecognized arguments: {' '.join(unrecognized)}")
        return parsed, unrecognized


def build_parser(commands: Sequence[Command]) -> argparse.ArgumentParser:
    parser = _Parser(prog=PROGRAM, description=DESCRIPTION)
    registry = parser.add_subparsers(dest="command", metavar="command", required=True)
    for command in commands:
        subparser = registry.add_parser(command.name.value, help=command.summary)
        command.configure(subparser)
        subparser.add_argument(
            "-v", "--verbose", action="store_true", help="more detail, where the command has it"
        )
        if command.json:
            subparser.add_argument("--json", action="store_true", help="print the result as JSON")
        subparser.set_defaults(run=command.run)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if refusal := log_format_refusal():
        write_error(refusal)
        return ExitCode.USAGE
    arguments = sys.argv[1:] if argv is None else argv
    parser = build_parser(COMMANDS)
    if not arguments:
        parser.print_help()
        return ExitCode.OK
    try:
        parsed = parser.parse_args(arguments)
        with verbose_run(parsed.verbose), logger_run(f"{PROGRAM}.{parsed.command}"):
            return parsed.run(parsed)
    except KeyboardInterrupt:
        return ExitCode.INTERRUPTED
    except secrets_view.ManifestError as error:
        write_error(str(error))
        return ExitCode.USAGE
    except Exception as error:
        # Only the type: a message may hold a path, a token or a line of someone else's text.
        write_error(f"unexpected error ({type(error).__name__})")
        return ExitCode.FAILURE
