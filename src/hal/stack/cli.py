"""The stack's switches as typed functions: apply, stop and start of a unit, stop and start of the
tunnel. `hal` is their one door."""

import os
from datetime import datetime

from hal.output import Stream, write_line
from hal.stack import api_limits, apply, emergency, switches, tunnel, update


def tunnel_of_environment(command: str) -> tunnel.Tunnel | None:
    """The tunnel the environment names; None, after saying why, when it names an invalid one."""
    try:
        return tunnel.Tunnel.from_environment(os.environ)
    except tunnel.TunnelError as error:
        write_line(f"{command}: cannot plan, {error}", stream=Stream.STDERR)
        return None


def stop_all() -> int:
    door = tunnel_of_environment(emergency.STOP_ALL)
    if door is None:
        return apply.ApplyExit.CANNOT_PLAN
    return emergency.stop_all(
        switches.Switches(switches.default_state_directory()),
        datetime.now().astimezone(),
        door,
    )


def start_all() -> int:
    door = tunnel_of_environment(emergency.START_ALL)
    if door is None:
        return apply.ApplyExit.CANNOT_PLAN
    return emergency.start_all(
        switches.Switches(switches.default_state_directory()),
        datetime.now().astimezone(),
        door,
    )


def stop_unit(unit: str) -> int:
    return emergency.stop_unit(
        switches.Switches(switches.default_state_directory()),
        unit,
        datetime.now().astimezone(),
    )


def start_unit(unit: str) -> int:
    return emergency.start_unit(switches.Switches(switches.default_state_directory()), unit)


def update_checkout() -> update.UpdateEnd:
    return update.update_checkout(switches.default_state_directory())


def apply_units(api: api_limits.ApiSettings) -> int:
    return apply.apply_local(switches.default_state_directory(), api=api)
