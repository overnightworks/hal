"""The settings file's loader, called directly: defaults, known names and the records it builds."""

from __future__ import annotations

import dataclasses
import sys
from pathlib import Path

import pytest
from support.workstation_support import write_hal_config

from hal import config as hal_config
from hal.stack.api_limits import ApiSettings, AppNumbers, LogDepth
from hal.workstation.alarm import AlarmSettings
from hal.workstation.check import CheckSettings
from hal.workstation.system_step import DockerSettings


def test_an_empty_file_gives_the_defaults(tmp_path: Path) -> None:
    write_hal_config(tmp_path, "")

    assert hal_config.load(tmp_path) == hal_config.Settings()


def test_every_setting_of_the_check_is_a_known_key() -> None:
    assert {field.name for field in dataclasses.fields(CheckSettings)} == set(
        hal_config.CHECK_KEY_KINDS
    )


def test_an_alarm_table_sets_the_interval_and_the_runs_in_a_row(tmp_path: Path) -> None:
    write_hal_config(tmp_path, "[alarm]\ninterval = 15\nruns = 3\n")

    assert hal_config.load(tmp_path).alarm == AlarmSettings(interval=15, runs=3)


def test_a_missing_alarm_table_gives_five_minutes_and_two_runs(tmp_path: Path) -> None:
    write_hal_config(tmp_path, "[check]\nnotify = false\n")

    assert hal_config.load(tmp_path).alarm == AlarmSettings(interval=5, runs=2)


def test_every_setting_of_the_alarm_is_a_known_key() -> None:
    assert {field.name for field in dataclasses.fields(AlarmSettings)} == set(
        hal_config.ALARM_KEY_KINDS
    )


def test_a_docker_table_sets_the_build_cache_limit(tmp_path: Path) -> None:
    write_hal_config(tmp_path, '[docker]\nbuild_cache_max = "15GiB"\n')

    assert hal_config.load(tmp_path).docker == DockerSettings("15GiB")


def test_every_setting_of_docker_is_a_known_key() -> None:
    assert {field.name for field in dataclasses.fields(DockerSettings)} == set(
        hal_config.DOCKER_KEY_KINDS
    )


def test_the_api_tables_load_as_written_with_dollars_as_floats(tmp_path: Path) -> None:
    write_hal_config(
        tmp_path,
        "[api]\nbudget_dollars = 4\nmax_parallel_requests = 3\nperson_budget_dollars = 1.5\n"
        'log_depth = "everything"\n'
        "[api.hopin]\nbudget_dollars = 6\n[api.songmaker]\nmax_parallel_requests = 1\n",
    )

    api = hal_config.load(tmp_path).api

    assert api == ApiSettings(
        AppNumbers(4.0, 3),
        {"hopin": AppNumbers(6.0, None), "songmaker": AppNumbers(None, 1)},
        1.5,
        LogDepth.EVERYTHING,
    )
    assert {type(api.every_app.budget_dollars), type(api.apps["hopin"].budget_dollars)} == {float}


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            "[api]\nbudget_dollars = 0\nmax_parallel_requests = 0\nperson_budget_dollars = 0\n"
            "[api.hopin]\nbudget_dollars = 0\nmax_parallel_requests = 0\n",
            ApiSettings(AppNumbers(0.0, 0), {"hopin": AppNumbers(0.0, 0)}, 0.0),
            id="zero for each number",
        ),
        pytest.param(
            "[api]\nbudget_dollars = 1e12\nmax_parallel_requests = 10000000000\n",
            ApiSettings(AppNumbers(1e12, 10_000_000_000)),
            id="a large number, with no ceiling",
        ),
    ],
)
def test_zero_and_a_large_number_are_accepted(
    tmp_path: Path, text: str, expected: ApiSettings
) -> None:
    write_hal_config(tmp_path, text)

    assert hal_config.load(tmp_path).api == expected


@pytest.mark.parametrize(
    ("known", "record_fields"),
    [
        pytest.param(
            set(hal_config.APP_KEY_KINDS),
            {field.name for field in dataclasses.fields(AppNumbers)},
            id="an app table",
        ),
        pytest.param(
            set(hal_config.API_KEY_KINDS),
            {field.name for field in dataclasses.fields(AppNumbers)}
            | ({field.name for field in dataclasses.fields(ApiSettings)} - {"every_app", "apps"}),
            id="the api table",
        ),
    ],
)
def test_every_setting_of_the_api_records_is_a_known_key(
    known: set[str], record_fields: set[str]
) -> None:
    assert known == record_fields


DOLLARS = "a finite number of at least 0"
COUNT = "a whole number of at least 0"
LOG_DEPTH = '"metadata" or "everything"'
HUGE_WHOLE_NUMBER = 10**400
DIGIT_LIMIT = sys.get_int_max_str_digits()
PAST_THE_DIGIT_LIMIT = DIGIT_LIMIT + 1
TOO_LONG = f"an integer of more than {DIGIT_LIMIT} digits"
DOCKER_SIZE = 'a size Docker reads, like "20GB"'


@pytest.mark.parametrize(
    ("text", "reason"),
    [
        ("[alarm]\nspeed = 3\n", "unknown key(s) or table(s): speed"),
        ("[alarm]\ninterval = 2.5\n", "interval must be a whole number of at least 1, got 2.5"),
        ("[alarm]\nruns = false\n", "runs must be a whole number of at least 1, got False"),
        ("[alarm]\ninterval = 0\n", "interval must be a whole number of at least 1, got 0"),
        ("alarm = 5\n", "[alarm] must be a table"),
        ("[docker]\nspeed = 3\n", "unknown key(s) or table(s): speed"),
        ("docker = 5\n", "[docker] must be a table"),
        ("[docker]\nbuild_cache_max = 20\n", f"build_cache_max must be {DOCKER_SIZE}, got 20"),
        (
            '[docker]\nbuild_cache_max = "lots"\n',
            f"build_cache_max must be {DOCKER_SIZE}, got 'lots'",
        ),
        (
            '[docker]\nbuild_cache_max = "0GB"\n',
            f"build_cache_max must be {DOCKER_SIZE}, got '0GB'",
        ),
        ("[check]\nnotify = 1\n", "notify must be true or false, got 1"),
        ('[api]\nbudget_dollars = "6"\n', f"budget_dollars must be {DOLLARS}, got '6'"),
        ("[api]\nbudget_dollars = true\n", f"budget_dollars must be {DOLLARS}, got True"),
        ("[api]\nperson_budget_dollars = -1\n", f"person_budget_dollars must be {DOLLARS}, got -1"),
        ("[api.hopin]\nbudget_dollars = inf\n", f"budget_dollars must be {DOLLARS}, got inf"),
        ("[api]\nbudget_dollars = nan\n", f"budget_dollars must be {DOLLARS}, got nan"),
        pytest.param(
            f"[api]\nbudget_dollars = {HUGE_WHOLE_NUMBER}\n",
            f"budget_dollars must be {DOLLARS}, got {HUGE_WHOLE_NUMBER}",
            id="a whole number beyond float range",
        ),
        pytest.param(
            f"[api]\nbudget_dollars = {'9' * PAST_THE_DIGIT_LIMIT}\n",
            TOO_LONG,
            id="a decimal integer past the digit limit",
        ),
        pytest.param(
            f"[api]\nbudget_dollars = 0x{'f' * PAST_THE_DIGIT_LIMIT}\n",
            f"budget_dollars must be {DOLLARS}, got {TOO_LONG}",
            id="a hex integer past the digit limit as dollars",
        ),
        pytest.param(
            f"[api.hopin]\nmax_parallel_requests = 0x{'f' * PAST_THE_DIGIT_LIMIT}\n",
            f"max_parallel_requests must be {COUNT}, got {TOO_LONG}",
            id="a hex integer past the digit limit as a count",
        ),
        pytest.param(
            f"[api.budget_dollars]\nhopin = 0x{'f' * PAST_THE_DIGIT_LIMIT}\n",
            f"budget_dollars must be {DOLLARS}, got {TOO_LONG}",
            id="a hex integer past the digit limit inside a table",
        ),
        ("[api]\nmax_parallel_requests = 2.5\n", f"max_parallel_requests must be {COUNT}, got 2.5"),
        (
            "[api.hopin]\nmax_parallel_requests = -1\n",
            f"max_parallel_requests must be {COUNT}, got -1",
        ),
        (
            "[api]\nmax_parallel_requests = false\n",
            f"max_parallel_requests must be {COUNT}, got False",
        ),
        ('[api]\nmax_parallel_requests = "3"\n', f"max_parallel_requests must be {COUNT}, got '3'"),
        ("[api]\nspeed = 3\n", "unknown key(s) or table(s): speed"),
        (
            "[api.hopin]\nperson_budget_dollars = 1\n",
            "unknown key(s) or table(s): person_budget_dollars",
        ),
        ('[api.hopin]\nmodels = ["text/opus"]\n', "unknown key(s) or table(s): models"),
        ("[api.hopin.extra]\nbudget_dollars = 1\n", "unknown key(s) or table(s): extra"),
        (
            "[api.budget_dollars]\nhopin = 1\n",
            f"budget_dollars must be {DOLLARS}, got {{'hopin': 1}}",
        ),
        ("api = 5\n", "[api] must be a table"),
        ('[api]\nlog_depth = "verbose"\n', f"log_depth must be {LOG_DEPTH}, got 'verbose'"),
        ('[api]\nlog_depth = "Everything"\n', f"log_depth must be {LOG_DEPTH}, got 'Everything'"),
        ("[api]\nlog_depth = true\n", f"log_depth must be {LOG_DEPTH}, got True"),
        ('[api]\nlog_depth = ["metadata"]\n', f"log_depth must be {LOG_DEPTH}, got ['metadata']"),
        (
            '[api.log_depth]\nhopin = "everything"\n',
            f"log_depth must be {LOG_DEPTH}, got {{'hopin': 'everything'}}",
        ),
        ('[api.hopin]\nlog_depth = "everything"\n', "unknown key(s) or table(s): log_depth"),
    ],
)
def test_a_wrong_setting_fails_loud(tmp_path: Path, text: str, reason: str) -> None:
    config_file = write_hal_config(tmp_path, text)

    with pytest.raises(hal_config.ConfigInvalid) as raised:
        hal_config.load(tmp_path)

    assert (raised.value.path, raised.value.reason) == (config_file, reason)
