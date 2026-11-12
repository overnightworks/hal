"""`hal check`: what is wrong with this PC. Bare, it is the daily check, run in process:
rows, verdict, report and the news it delivers. With the area `exposure` (what reaches
beyond loopback, local), the area does the checking; this module adds the grammar, the JSON wrapper
keyed by the area, and the exit code."""

import argparse
import json
from pathlib import Path

from hal import config as hal_config
from hal import exposure_rows
from hal.exposure import exposure, inspection
from hal.grammar import Asks, Command, ExitCode
from hal.output import write_error, write_line
from hal.output.command import Verb, command
from hal.workstation import check as daily_check
from hal.workstation.exposure_check import ExposureRule
from hal.workstation.ports import build_layout_and_ports
from hal.workstation.report import Finding

EXPOSURE = "exposure"


CHECK = command(Verb.CHECK)
HELP = f"""\
{CHECK}             the daily check: services, backup, commit hook, secrets, server logs,
                      exposure; it writes the report and mails and pops up what is new, as the
                      timer's run does
                      settings: ~/.config/hal/config.toml, table [check] (docs/home.md)
{command(Verb.CHECK, EXPOSURE)}    what reaches beyond loopback on this PC
"""


def _configure(parser: argparse.ArgumentParser) -> None:
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.description = HELP
    parser.add_argument("area", nargs="?", choices=(EXPOSURE,), help="the area to check")
    parser.add_argument(
        "--allow-list",
        type=Path,
        help=f"{EXPOSURE} only: known listeners beyond loopback "
        f"(default: {inspection.DEFAULT_ALLOW_LIST})",
    )


EXPOSURE_RULES = {
    exposure.Problem.PUBLICATION_BEYOND_LOOPBACK: ExposureRule.REACHABLE_BEYOND_LOOPBACK,
    exposure.Problem.PUBLICATION_WITHOUT_HOST_IP: ExposureRule.REACHABLE_BEYOND_LOOPBACK,
    exposure.Problem.LISTENER_BEYOND_LOOPBACK: ExposureRule.REACHABLE_BEYOND_LOOPBACK,
    exposure.Problem.ROUTED_WITHOUT_EDGE_NAME: ExposureRule.ROUTING_NAME_UNUSABLE,
    exposure.Problem.INVALID_EDGE_NAME: ExposureRule.ROUTING_NAME_UNUSABLE,
    exposure.Problem.DUPLICATE_EDGE_NAME: ExposureRule.ROUTING_NAME_UNUSABLE,
}


def _read_exposure() -> list[Finding]:
    """The scan as the daily check's findings; a scan that cannot run raises."""
    return [
        Finding(EXPOSURE_RULES[group.problem].value, group.subject, group.fact)
        for group in exposure_rows.groups_of(inspection.inspect(inspection.DEFAULT_ALLOW_LIST))
    ]


def _run_daily() -> ExitCode:
    layout, ports = build_layout_and_ports()
    try:
        settings = hal_config.load(layout.home)
    except hal_config.ConfigInvalid as error:
        write_error(f"{error.path}: {error.reason}")
        return ExitCode.USAGE  # exit 2 is "configuration or manifest invalid" for the daily check
    context = daily_check.CheckContext(
        layout, settings.check, ports.run, ports.probe, ports.now, ports.disk_space, _read_exposure
    )
    return ExitCode(daily_check.check(context))


def _run(arguments: argparse.Namespace) -> ExitCode:
    if arguments.allow_list is not None and arguments.area != EXPOSURE:
        write_error(
            "--allow-list belongs to one area",
            command(Verb.CHECK, EXPOSURE, "--allow-list", "FILE"),
        )
        return ExitCode.USAGE
    if arguments.area is None:
        if arguments.json:
            write_error("--json belongs to one area", command(Verb.CHECK, EXPOSURE, "--json"))
            return ExitCode.USAGE
        return _run_daily()
    try:
        findings = inspection.inspect(arguments.allow_list or inspection.DEFAULT_ALLOW_LIST)
    except inspection.ExposureCheckError as error:
        write_error(f"{CHECK}: {EXPOSURE}: cannot check, {error}")
        return ExitCode.FAILURE
    if arguments.json:
        write_line(json.dumps({EXPOSURE: inspection.as_json_objects(findings)}, indent=2))
    else:
        exposure_rows.write(findings)
    return ExitCode.FINDINGS if findings else ExitCode.OK


COMMANDS = (
    Command(
        Verb.CHECK,
        "run the daily check, or one area: what reaches beyond loopback",
        _run,
        _configure,
        json=True,
        asks=Asks.NEVER,
    ),
)
