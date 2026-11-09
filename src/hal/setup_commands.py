"""`hal setup`: the typed function of `hal.workstation.setup`, with the layout and boundaries
`hal.workstation.ports` builds, so the steps, the prompts and the lines are
`hal.workstation`' own."""

import argparse
import dataclasses

from hal import config as hal_config
from hal.grammar import Asks, Command, ExitCode, add_dry_run
from hal.output import write_error
from hal.output.command import Verb
from hal.workstation import jobs, setup
from hal.workstation.ports import build_layout_and_ports
from hal.workstation.setup import SetupEnd

EXIT_OF_SETUP: dict[SetupEnd, ExitCode] = {
    SetupEnd.DONE: ExitCode.OK,
    SetupEnd.FAILED: ExitCode.FAILURE,
    SetupEnd.DECLINED: ExitCode.FINDINGS,
    SetupEnd.NO_TERMINAL: ExitCode.REFUSED,
}

SETUP_DESCRIPTION = (
    "Shows what is missing and asks you to type yes; with --dry-run it only shows"
    " (at a terminal sudo still checks the system)."
    " After the yes it sets up quality, its scanners and the hook,"
    " then links ~/.local/bin/hal to the checkout hal runs from"
    " and re-points it after the checkout moved."
    " Then it writes, reloads and enables hal's user units"
    " (the backup, hal-check and hal-alarm timers), installs Ansible and runs the system step,"
    " edge's cloudflared files and the stop-only polkit rule,"
    " which asks once for sudo after the yes; the activation comes before the system step."
    " Without a terminal it shows what is missing and stops, unless nothing is."
    " The system step makes the journal Docker's default log driver and restarts Docker while its"
    " default driver is not journald: every container stops meanwhile, and one without a restart"
    " policy stays down."
    " Last it walks you through every missing secret at the terminal, never showing a value."
)


def _configure(parser: argparse.ArgumentParser) -> None:
    parser.description = SETUP_DESCRIPTION
    add_dry_run(parser)


def _setup(arguments: argparse.Namespace) -> ExitCode:
    layout, ports = build_layout_and_ports()
    try:
        settings = hal_config.load(layout.home)
    except hal_config.ConfigInvalid as error:
        write_error(f"{error.path}: {error.reason}")
        return ExitCode.USAGE
    ports = dataclasses.replace(
        ports, timer_jobs=jobs.with_alarm_interval(ports.timer_jobs, settings.alarm.interval)
    )
    return EXIT_OF_SETUP[setup.setup(layout, ports, arguments.dry_run, settings.docker)]


COMMANDS = (
    Command(
        Verb.SETUP,
        "set up quality, the commit hook, the system step (sudo, terminal) and the missing secrets",
        _setup,
        _configure,
        json=False,
        asks=Asks.YES,
    ),
)
