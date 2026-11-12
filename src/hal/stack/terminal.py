"""The operator guard of the commands that ask a person at the terminal.

It stops accidental and non-interactive runs; it does not identify the operator (D14).
"""

import sys

from hal.output import Stream, write_line

NEEDS_TERMINAL = "refused, stdin and stdout must be a terminal"


def at_terminal() -> bool:
    """Whether somebody can answer a prompt: stdin and stdout are both a terminal."""
    return sys.stdin.isatty() and sys.stdout.isatty()


def refused_without_terminal(command: str) -> bool:
    """True, after saying so, when stdin and stdout are not both a terminal."""
    if at_terminal():
        return False
    write_line(f"{command}: {NEEDS_TERMINAL}", stream=Stream.STDERR)
    return True
