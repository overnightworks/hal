"""`LOG_FORMAT=json`: every row, verdict and error of the timer path is one flushed line of a
journal priority and a JSON object, and the password, a host path or a row never reaches one."""

import json
import os
import signal
import subprocess
import sys
from datetime import UTC, datetime
from enum import StrEnum
from functools import partial
from pathlib import Path

import pytest
from support.backup_support import (
    CANARY_PASSWORD,
    SONGMAKER_CONTAINER,
    SONGMAKER_TOML,
    SQLITE_TOML,
    declare_apps,
    declare_shipped_apps,
    declare_two_apps,
)

from hal import cli
from hal.grammar import ExitCode
from hal.output import (
    Glyph,
    Noun,
    Row,
    Verdict,
    printable,
    write_error,
    write_row,
    write_verdict,
)
from hal.stack.realm import reconcile

HOSTILE = f'ESC \x1b[31m, newline \n, quote ", prefix <3>, separator {chr(0x2028)} end'
COMMON_FIELDS = ["timestamp", "level", "logger", "service", "event"]


class Event(StrEnum):
    BACKED_UP = "backed up"


class AppCount(Noun):
    APP = "app"
    OTHER = "other"


@pytest.fixture
def json_log(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LOG_FORMAT", "json")


def events(text: str) -> list[tuple[int, dict]]:
    """Each line as its journal priority and its object; a line without both fails the test."""
    parsed = []
    for line in text.splitlines():
        assert line.startswith("<") and line[2] == ">", line
        parsed.append((int(line[1]), json.loads(line[3:])))
    return parsed


def the_one_event(text: str) -> tuple[int, dict]:
    assert text.count("\n") == 1, text
    [event] = events(text)
    return event


def row(glyph: Glyph = Glyph.DONE, **fields: object) -> Row:
    return Row(glyph, **{"subject": "songmaker", "event": Event.BACKED_UP, **fields})


@pytest.mark.usefixtures("json_log")
def test_a_row_is_one_info_line_with_the_common_fields_first(capsys):
    write_row(row(fact="4.2 MiB"))

    priority, event = the_one_event(capsys.readouterr().out)
    assert priority == 6
    assert list(event) == [*COMMON_FIELDS, "subject", "fact"]
    assert (event["level"], event["logger"], event["service"]) == ("info", "hal", "hal")
    assert (event["event"], event["subject"], event["fact"]) == (
        "backed up",
        "songmaker",
        "4.2 MiB",
    )
    moment = datetime.fromisoformat(event["timestamp"])
    assert event["timestamp"].endswith("Z") and moment.utcoffset() == UTC.utcoffset(None)


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize(
    ("glyph", "priority"), [(Glyph.FAILED, 3), (Glyph.NEEDS_YOU, 4), (Glyph.UNCHANGED, 6)]
)
def test_a_row_takes_its_priority_from_its_glyph(capsys, glyph, priority):
    write_row(row(glyph))

    assert the_one_event(capsys.readouterr().out)[0] == priority


@pytest.mark.usefixtures("json_log")
def test_a_rows_count_and_details_are_in_the_object_and_print_no_detail_line(capsys):
    write_row(row(count=3, details=("first", "second")))

    _, event = the_one_event(capsys.readouterr().out)
    assert (event["count"], event["details"]) == (3, ["first", "second"])


@pytest.mark.usefixtures("json_log")
def test_a_verdict_names_its_counts_by_plural_label_and_leaves_out_zeros(capsys):
    verdict = Verdict(
        Glyph.DONE,
        "backup done",
        ((1, AppCount.APP), (0, AppCount.OTHER)),
        elapsed_seconds=3.0,
        next_step="hal restore --test",
    )

    write_verdict(verdict)

    priority, event = the_one_event(capsys.readouterr().out)
    assert priority == 6
    assert list(event) == [*COMMON_FIELDS, "apps", "seconds", "next"]
    assert (event["event"], event["apps"], event["seconds"]) == ("backup done", 1, 3.0)
    assert event["next"] == "hal restore --test"


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize(
    ("next_step", "fields"),
    [(None, ["message"]), ("hal backup", ["message", "next"])],
    ids=["without next", "with next"],
)
def test_an_error_is_the_generic_event_on_stderr(capsys, next_step, fields):
    write_error("it broke", next_step)

    captured = capsys.readouterr()
    priority, event = the_one_event(captured.err)
    assert (captured.out, priority, event["event"]) == ("", 3, "error")
    assert list(event) == [*COMMON_FIELDS, *fields]


@pytest.mark.usefixtures("json_log")
def test_an_error_prints_no_empty_line_for_a_fresh_line(capsys):
    write_error("it broke", fresh_line=True)

    the_one_event(capsys.readouterr().err)


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize("field", ["subject", "fact", "message"])
def test_hostile_text_stays_one_parsing_line_of_escaped_text(capsys, field):
    if field == "message":
        write_error(HOSTILE)
        text = capsys.readouterr().err
    else:
        write_row(row(**{field: HOSTILE}))
        text = capsys.readouterr().out

    _, event = the_one_event(text)
    assert event[field] == printable(HOSTILE).rstrip()


def test_every_event_is_flushed_before_the_process_ends_abruptly():
    script = (
        "import os\n"
        "from enum import StrEnum\n"
        "from hal.output import Glyph, Row, write_error, write_row\n"
        "class Event(StrEnum):\n"
        "    DONE = 'done'\n"
        "write_row(Row(Glyph.DONE, 'songmaker', Event.DONE))\n"
        "write_error('it broke')\n"
        "os._exit(0)\n"
    )

    ended = subprocess.run(  # noqa: S603 - the interpreter of this test run and a fixed script
        [sys.executable, "-c", script],
        env={**os.environ, "LOG_FORMAT": "json"},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )

    assert [event["event"] for _, event in events(ended.stdout)] == ["done", "error"]


def test_unset_and_text_print_the_same_bytes_without_json(monkeypatch, capsys):
    def printed() -> tuple[str, str]:
        write_row(row(fact="4.2 MiB", details=("first",)))
        write_verdict(Verdict(Glyph.DONE, "backup done", ((1, AppCount.APP),)))
        write_error("it broke", "hal backup")
        captured = capsys.readouterr()
        return captured.out, captured.err

    monkeypatch.delenv("LOG_FORMAT", raising=False)
    unset = printed()
    monkeypatch.setenv("LOG_FORMAT", "text")
    text = printed()

    assert unset == text
    assert "{" not in "".join(text)


@pytest.mark.parametrize("value", ["yaml", ""])
@pytest.mark.parametrize("arguments", [["version"], [], ["--help"], ["version", "--bogus"]])
def test_the_door_refuses_a_malformed_log_format_before_anything_runs(
    monkeypatch, capsys, value, arguments
):
    monkeypatch.setenv("LOG_FORMAT", value)

    exit_code = cli.main(arguments)

    captured = capsys.readouterr()
    assert exit_code == ExitCode.USAGE
    assert captured.out == ""
    assert captured.err == f"error: LOG_FORMAT must be json or text, not {value}\n"


@pytest.mark.usefixtures("json_log")
def test_a_good_backup_is_events_of_hal_backup_ending_in_the_verdict(edge_backup):
    outcome = edge_backup("backup")

    assert outcome.exit_code == 0, outcome.err
    parsed = events(outcome.out)
    assert {event["logger"] for _, event in parsed} == {"hal.backup"}
    assert parsed[-1][1]["event"] == "backup done"
    assert len(parsed) > 1


@pytest.mark.usefixtures("json_log")
def test_a_good_restore_test_is_events_of_hal_restore(edge_backup):
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == 0, outcome.err
    assert {event["logger"] for _, event in events(outcome.out)} == {"hal.restore"}


@pytest.mark.usefixtures("json_log")
def test_a_failed_app_is_an_error_row_beside_an_info_row_and_the_error_event(edge_backup, machine):
    machine.other_db_containers["edge"] = []

    outcome = edge_backup(*declare_shipped_apps(), "backup")

    assert outcome.exit_code == ExitCode.FAILURE
    assert [(priority, event["subject"]) for priority, event in events(outcome.out)] == [
        (6, "songmaker"),
        (3, "keycloak"),
        (6, "repository"),
    ]
    [(priority, event)] = events(outcome.err)
    assert (priority, event["event"]) == (3, "error")


@pytest.mark.usefixtures("json_log")
def test_pre_apply_json_answers_one_object_without_a_prefix(edge_backup, machine, home):
    outcome = edge_backup(*declare_two_apps(home), "backup", "radio", "--pre-apply", "--json")

    assert outcome.exit_code == 0, outcome.err
    assert json.loads(outcome.out) == {"snapshot": machine.snapshots[-1]["id"]}
    assert outcome.out.count("\n") == 1


@pytest.mark.usefixtures("json_log")
def test_a_failed_pre_apply_json_keeps_stdout_empty_and_writes_the_error_event(
    edge_backup, machine, home
):
    machine.failing["restic backup"] = 1

    outcome = edge_backup(*declare_two_apps(home), "backup", "radio", "--pre-apply", "--json")

    assert (outcome.exit_code, outcome.out) == (ExitCode.FAILURE, "")
    [(priority, event)] = events(outcome.err)
    assert (priority, event["event"]) == (3, "error")


def forbidden_in(home: Path) -> list[str]:
    return [
        CANARY_PASSWORD,
        str(home),
        "/run/secrets",
        "--password-file",
        "--repo",
        SONGMAKER_CONTAINER,
    ]


def run_every_failing_label(edge_backup, machine):
    """Runs a backup and a restore test, then each again with one of its labels failing; yields
    what each printed."""
    edge_backup("backup")
    edge_backup("restore", "--test")
    labels = sorted(set(machine.labels()))
    for label in labels:
        machine.failing[label] = 1
        for command in (("backup",), ("restore", "--test")):
            outcome = edge_backup(*command)
            yield label, outcome
        del machine.failing[label]


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_no_failing_step_prints_the_password_a_host_path_or_an_argv_marker(
    edge_backup, machine, home, monkeypatch, log_format
):
    monkeypatch.setenv("LOG_FORMAT", log_format)
    machine.restore_diagnostic = 'COPY credential, line 1: "ROW-MARKER-4711"'

    for label, outcome in run_every_failing_label(edge_backup, machine):
        shown = outcome.out + outcome.err
        for marker in [*forbidden_in(home), "ROW-MARKER-4711"]:
            assert marker not in shown, (label, marker)


HOST_PATH_MARKER = "/run/secrets/HOSTPATH-MARKER"
REFUSED_APPS = {
    "database_file": SQLITE_TOML.replace('"presentator.sqlite3"', f'"{HOST_PATH_MARKER}"'),
    "dump": SONGMAKER_TOML.replace('"pg_dump_custom"', f'"{HOST_PATH_MARKER}"'),
    "postgres_major": SONGMAKER_TOML.replace("= 16", f'= "{HOST_PATH_MARKER}"'),
    "require_rows": SONGMAKER_TOML + f'require_rows = "{HOST_PATH_MARKER}"\n',
    "an unknown key": SONGMAKER_TOML.replace(
        "[app.songmaker.restore_test]", f'"{HOST_PATH_MARKER}" = 1\n[app.songmaker.restore_test]'
    ),
    "an unknown top-level key": f'"{HOST_PATH_MARKER}" = 1\n{SONGMAKER_TOML}',
    "an app name": SONGMAKER_TOML.replace("[app.songmaker]", f'[app."{HOST_PATH_MARKER}"]', 1),
    "a syntax error": f'{SONGMAKER_TOML}\n"{HOST_PATH_MARKER}" = = 1\n',
}


@pytest.mark.parametrize("log_format", ["text", "json"])
@pytest.mark.parametrize("refused", REFUSED_APPS)
def test_a_refused_apps_toml_repeats_nothing_it_refused(
    edge_backup, home, monkeypatch, log_format, refused
):
    monkeypatch.setenv("LOG_FORMAT", log_format)

    outcome = edge_backup(*declare_apps(home, REFUSED_APPS[refused]), "backup")

    shown = outcome.out + outcome.err
    assert outcome.exit_code == ExitCode.FAILURE
    assert "HOSTPATH-MARKER" not in shown
    assert all(marker not in shown for marker in forbidden_in(home))
    assert shown


@pytest.mark.usefixtures("json_log")
def test_sigterm_in_pg_dump_is_the_error_event_with_exit_130(edge_backup, machine, home):
    def terminated_by_systemd():
        os.kill(os.getpid(), signal.SIGTERM)

    machine.failing["pg_dump"] = terminated_by_systemd

    outcome = edge_backup("backup")

    assert outcome.exit_code == ExitCode.INTERRUPTED
    [(priority, event)] = events(outcome.err)
    assert (priority, event["event"]) == (3, "error")
    assert list((home / ".cache/edge-backup").iterdir()) == []


@pytest.mark.usefixtures("json_log")
def test_an_unexpected_exception_is_the_error_event_naming_only_its_type(edge_backup, machine):
    machine.failing["restic backup"] = RuntimeError

    outcome = edge_backup("backup")

    assert outcome.exit_code == ExitCode.FAILURE
    [(priority, event)] = events(outcome.err)
    assert (priority, event["logger"], event["message"]) == (
        3,
        "hal",
        "unexpected error (RuntimeError)",
    )


@pytest.mark.usefixtures("json_log")
def test_a_usage_error_is_the_error_event_of_the_door(capsys):
    with pytest.raises(SystemExit) as ended:
        cli.main(["backup", "--bogus"])

    [(priority, event)] = events(capsys.readouterr().err)
    assert (ended.value.code, priority, event["logger"]) == (ExitCode.USAGE, 3, "hal")
    assert "--bogus" in event["message"]


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize("ending", ["success", "failure", "interruption"])
def test_the_logger_is_hal_again_after_a_run(edge_backup, machine, capsys, ending):
    if ending == "failure":
        machine.failing["pg_dump"] = 1
    if ending == "interruption":
        machine.failing["pg_dump"] = KeyboardInterrupt
    edge_backup("backup")

    write_error("afterwards")

    [(_, event)] = events(capsys.readouterr().err)
    assert event["logger"] == "hal"


@pytest.mark.usefixtures("json_log")
def test_a_realm_step_asks_the_backup_child_for_text_under_an_exported_json():
    child = (
        "from enum import StrEnum\n"
        "from hal.output import Glyph, Row, write_error, write_row\n"
        "class Event(StrEnum):\n"
        "    DONE = 'done'\n"
        "write_row(Row(Glyph.DONE, 'keycloak', Event.DONE))\n"
        "write_error('the dump does not restore')\n"
        "raise SystemExit(3)\n"
    )
    backup = reconcile.Backup(
        (sys.executable, "-c", child),
        partial(reconcile.run_edge_backup, waiting=lambda _seconds: None),
    )

    with pytest.raises(reconcile.RealmError) as raised:
        backup.restore_test("ab12cd34")

    assert str(raised.value) == "the restore test failed (the dump does not restore)"
