"""`hal setup`: the command table entry. The steps run against a sandboxed HOME
in tests/support/workstation_support.py, where the sandbox lives."""

from hal import setup_commands
from hal.grammar import Asks


def test_setup_is_a_command_that_waits_for_the_person_and_prints_no_json():
    (command,) = setup_commands.COMMANDS

    assert (command.name, command.json, command.asks) == ("setup", False, Asks.YES)
