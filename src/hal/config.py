"""hal's one settings file, `~/.config/hal/config.toml`: a table per timer job that has settings,
and `[api]` with its `[api.<app>]` tables, the numbers LiteLLM enforces on the apps
(`hal.stack.api_limits` decides which of them holds).

A missing file means defaults. hal only reads it; nothing here writes, moves or deletes it."""

from __future__ import annotations

import sys
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType

from hal.stack.api_limits import ApiSettings, AppNumbers
from hal.workstation.alarm import AlarmSettings
from hal.workstation.check import CheckSettings


class Kind(Enum):
    """What a key admits; the value is the text a refusal names."""

    SWITCH = "true or false"
    AT_LEAST_ONE = "a whole number of at least 1"
    COUNT = "a whole number of at least 0"
    DOLLARS = "a finite number of at least 0"


CONFIG_PATH_IN_HOME = Path(".config") / "hal" / "config.toml"
CHECK_TABLE = "check"
CHECK_KEY_KINDS: Mapping[str, Kind] = {"notify": Kind.SWITCH}
ALARM_TABLE = "alarm"
ALARM_KEY_KINDS: Mapping[str, Kind] = {"interval": Kind.AT_LEAST_ONE, "runs": Kind.AT_LEAST_ONE}
API_TABLE = "api"
PERSON_BUDGET_KEY = "person_budget_dollars"
APP_KEY_KINDS: Mapping[str, Kind] = {
    "budget_dollars": Kind.DOLLARS,
    "max_parallel_requests": Kind.COUNT,
}
API_KEY_KINDS: Mapping[str, Kind] = {**APP_KEY_KINDS, PERSON_BUDGET_KEY: Kind.DOLLARS}


class ConfigInvalid(Exception):
    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"{path}: {reason}")
        self.path = path
        self.reason = reason


@dataclass(frozen=True)
class Settings:
    check: CheckSettings = field(default_factory=CheckSettings)
    alarm: AlarmSettings = field(default_factory=AlarmSettings)
    api: ApiSettings = field(default_factory=ApiSettings)


def config_path(home: Path) -> Path:
    return home / CONFIG_PATH_IN_HOME


def _read(path: Path) -> dict[str, object]:
    try:
        with path.open("rb") as handle:
            return tomllib.load(handle)
    except FileNotFoundError:
        return {}
    except tomllib.TOMLDecodeError as error:
        raise ConfigInvalid(path, str(error)) from error
    except UnicodeDecodeError as error:
        raise ConfigInvalid(path, "not UTF-8") from error
    except ValueError as error:  # tomllib converts a decimal integer past the digit limit
        raise ConfigInvalid(path, _past_digit_limit()) from error
    except OSError as error:
        raise ConfigInvalid(path, error.strerror or type(error).__name__) from error


def _past_digit_limit() -> str:
    return f"an integer of more than {sys.get_int_max_str_digits()} digits"


def _shown(value: object) -> str | None:
    """The value as a refusal names it; None when it holds an integer past the digit limit, which
    has no digits to show (a hex integer parses at any length)."""
    try:
        return repr(value)
    except ValueError:
        return None


def _refuse_unknown(path: Path, names: set[str], known: frozenset[str]) -> None:
    unknown = sorted(names - known)
    if unknown:
        raise ConfigInvalid(path, f"unknown key(s) or table(s): {', '.join(unknown)}")


def _admits(kind: Kind, value: object) -> bool:
    if type(value) is int and _shown(value) is None:
        return False
    if kind is Kind.SWITCH:
        return isinstance(value, bool)
    if kind is Kind.AT_LEAST_ONE:
        return type(value) is int and value >= 1
    if kind is Kind.COUNT:
        return type(value) is int and value >= 0
    # Compared as written: an int past float range converts to no float, so none is converted here.
    return type(value) in (int, float) and 0 <= value <= sys.float_info.max


def _table_values(
    path: Path, name: str, table: object, key_kinds: Mapping[str, Kind]
) -> dict[str, object]:
    """The table's values, dollars as floats; a key it does not know or a value its kind does not
    admit raises."""
    if not isinstance(table, dict):
        raise ConfigInvalid(path, f"[{name}] must be a table")
    _refuse_unknown(path, set(table), frozenset(key_kinds))
    for key, value in table.items():
        if not _admits(key_kinds[key], value):
            shown = _shown(value) or _past_digit_limit()
            raise ConfigInvalid(path, f"{key} must be {key_kinds[key].value}, got {shown}")
    return {
        key: float(value) if key_kinds[key] is Kind.DOLLARS else value
        for key, value in table.items()
    }


def _api_settings(path: Path, table: object) -> ApiSettings:
    """`[api]` as written; a key that is no number of `[api]` and holds a table is an app's."""
    if not isinstance(table, dict):
        raise ConfigInvalid(path, f"[{API_TABLE}] must be a table")
    app_tables = {
        app: numbers
        for app, numbers in table.items()
        if app not in API_KEY_KINDS and isinstance(numbers, dict)
    }
    own = {key: value for key, value in table.items() if key not in app_tables}
    numbers = _table_values(path, API_TABLE, own, API_KEY_KINDS)
    person_budget = numbers.pop(PERSON_BUDGET_KEY, None)
    apps = {
        app: AppNumbers(**_table_values(path, f"{API_TABLE}.{app}", app_table, APP_KEY_KINDS))
        for app, app_table in app_tables.items()
    }
    return ApiSettings(AppNumbers(**numbers), MappingProxyType(apps), person_budget)


def load(home: Path) -> Settings:
    path = config_path(home)
    raw = _read(path)
    _refuse_unknown(path, set(raw), frozenset({CHECK_TABLE, ALARM_TABLE, API_TABLE}))
    return Settings(
        check=CheckSettings(
            **_table_values(path, CHECK_TABLE, raw.get(CHECK_TABLE, {}), CHECK_KEY_KINDS)
        ),
        alarm=AlarmSettings(
            **_table_values(path, ALARM_TABLE, raw.get(ALARM_TABLE, {}), ALARM_KEY_KINDS)
        ),
        api=_api_settings(path, raw.get(API_TABLE, {})),
    )
