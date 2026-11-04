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
    declare_songmaker_and_keycloak,
    declare_two_apps,
)

from hal import cli
from hal.grammar import ExitCode
from hal.output import (
    Field,
    Glyph,
    Noun,
    Row,
    Verdict,
    log_format_refusal,
    printable,
    write_error,
    write_row,
    write_verdict,
)
from hal.stack.realm import reconcile
from hal.workstation.jobs import TIMER_JOBS
from hal.workstation.user_units import service_text

SOURCE = Path(__file__).resolve().parents[1] / "src"
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
        assert line.startswith("<"), line
        assert line[2] == ">", line
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

    shown = capsys.readouterr().out
    priority, event = the_one_event(shown)
    assert '"subject":"songmaker","fact":"4.2 MiB"' in shown
    assert priority == 6
    assert list(event) == [*COMMON_FIELDS, "subject", "fact"]
    assert (event["level"], event["logger"], event["service"]) == ("info", "hal", "hal")
    assert (event["event"], event["subject"], event["fact"]) == (
        "backed up",
        "songmaker",
        "4.2 MiB",
    )
    moment = datetime.fromisoformat(event["timestamp"])
    assert event["timestamp"].endswith("Z")
    assert moment.utcoffset() == UTC.utcoffset(None)


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
@pytest.mark.parametrize(
    ("glyph", "priority"), [(Glyph.DONE, 6), (Glyph.FAILED, 3)], ids=["done", "failed"]
)
def test_a_verdict_names_its_counts_by_plural_label_and_leaves_out_zeros(capsys, glyph, priority):
    verdict = Verdict(
        glyph,
        "backup done",
        ((1, AppCount.APP), (0, AppCount.OTHER)),
        hint="hal status",
        elapsed_seconds=3.0,
        details=("checked",),
        next_step="hal restore --test",
    )

    write_verdict(verdict)

    shown_priority, event = the_one_event(capsys.readouterr().out)
    assert shown_priority == priority
    assert list(event) == [*COMMON_FIELDS, "apps", "seconds", "details", "hint", "next"]
    assert (event["event"], event["apps"], event["seconds"]) == ("backup done", 1, 3.0)
    assert (event["details"], event["hint"]) == (["checked"], "hal status")
    assert event["next"] == "hal restore --test"


@pytest.mark.usefixtures("json_log")
def test_a_verdicts_span_is_a_tenth_of_a_second_in_json(capsys):
    write_verdict(Verdict(Glyph.DONE, "done", (), elapsed_seconds=192.44))

    _, event = the_one_event(capsys.readouterr().out)
    assert event["seconds"] == 192.4


@pytest.mark.usefixtures("json_log")
def test_a_verdicts_hostile_text_is_escaped_in_every_field(capsys):
    write_verdict(Verdict(Glyph.DONE, "done", (), HOSTILE, details=(HOSTILE,), next_step=HOSTILE))

    _, event = the_one_event(capsys.readouterr().out)
    expected = printable(HOSTILE)
    assert (event["details"], event["hint"], event["next"]) == ([expected], expected, expected)


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
@pytest.mark.parametrize("field", ["subject", "fact", "details", "message", "next"])
def test_hostile_text_stays_one_parsing_line_of_escaped_text(capsys, field):
    if field in ("message", "next"):
        write_error(HOSTILE, HOSTILE)
        text = capsys.readouterr().err
    else:
        write_row(row(**{field: (HOSTILE,) if field == "details" else HOSTILE}))
        text = capsys.readouterr().out

    _, event = the_one_event(text)
    expected = printable(HOSTILE).rstrip()
    assert event[field] == ([expected] if field == "details" else expected)


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
        env={**os.environ, "LOG_FORMAT": "json", "PYTHONPATH": str(SOURCE)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        check=True,
    )

    assert [event["event"] for _, event in events(ended.stdout)] == ["done", "error"]


def test_unset_and_text_print_the_same_bytes_without_json(monkeypatch, capsys):
    def printed() -> tuple[str, str]:
        write_row(row(fact="4.2 MiB", details=("first",)))
        write_row(row(fact="checked", fields=((Field.BYTES, 4_404_019), (Field.SECONDS, 60))))
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


@pytest.mark.parametrize(
    ("job", "arguments", "logger"),
    [
        ("hal-backup", ("backup",), "hal.backup"),
        ("hal-backup-restore-test", ("restore", "--test"), "hal.restore"),
    ],
)
def test_a_good_run_under_the_environment_a_backup_unit_declares_is_json_events(
    edge_backup, monkeypatch, job, arguments, logger
):
    unit = service_text(next(each for each in TIMER_JOBS if each.name == job), "%h/hal")
    [declared] = [line for line in unit.splitlines() if line.startswith("Environment=")]
    variable, value = declared.removeprefix("Environment=").split("=", 1)
    monkeypatch.setenv(variable, value)
    assert log_format_refusal() is None
    edge_backup("backup")

    outcome = edge_backup(*arguments)

    assert outcome.exit_code == 0, outcome.err
    parsed = events(outcome.out)
    assert {event["logger"] for _, event in parsed} == {logger}
    assert parsed[-1][1]["event"] in {"backup done", "restore test done"}


@pytest.mark.usefixtures("json_log")
def test_a_failed_app_is_an_error_row_beside_an_info_row_and_the_error_event(
    edge_backup, machine, home
):
    machine.lose_keycloak_database()

    outcome = edge_backup(*declare_songmaker_and_keycloak(home), "backup")

    assert outcome.exit_code == ExitCode.FAILURE
    assert [(priority, event["subject"]) for priority, event in events(outcome.out)] == [
        (6, "songmaker"),
        (3, "keycloak"),
        (6, "keycloak"),
        (6, "repository"),
    ]
    [(priority, event)] = events(outcome.err)
    assert (priority, event["event"]) == (3, "error")


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize("failing", [False, True], ids=["good", "failed"])
def test_pre_apply_json_keeps_stdout_a_bare_object_or_empty(edge_backup, machine, home, failing):
    if failing:
        machine.failing["restic backup"] = 1

    outcome = edge_backup(*declare_two_apps(home), "backup", "radio", "--pre-apply", "--json")

    if failing:
        assert (outcome.exit_code, outcome.out) == (ExitCode.FAILURE, "")
        [(priority, event)] = events(outcome.err)
        assert (priority, event["event"]) == (3, "error")
    else:
        assert set(json.loads(outcome.out)) == {"snapshot"}
        assert outcome.out.startswith("{")


def forbidden_in(home: Path) -> list[str]:
    return [
        CANARY_PASSWORD,
        str(home),
        "/run/secrets",
        "--password-file",
        "--repo",
        SONGMAKER_CONTAINER,
    ]


def labels_of_a_good_backup_and_restore_test(edge_backup, machine):
    for command in (("backup",), ("restore", "--test")):
        outcome = edge_backup(*command)
        assert outcome.exit_code == 0, (command, outcome.err)
    return sorted(set(machine.labels()))


def assert_nothing_forbidden_is_shown(outcome, home, label):
    shown = outcome.out + outcome.err
    for marker in [*forbidden_in(home), "ROW-MARKER-4711"]:
        assert marker not in shown, (label, marker)


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_no_failing_step_prints_the_password_a_host_path_or_an_argv_marker(
    edge_backup, machine, home, monkeypatch, log_format
):
    monkeypatch.setenv("LOG_FORMAT", log_format)
    labels = labels_of_a_good_backup_and_restore_test(edge_backup, machine)
    assert {"pg_restore", "psql"} <= set(labels)

    for label in labels:
        machine.failing[label] = 1
        for command in (("backup",), ("restore", "--test")):
            assert_nothing_forbidden_is_shown(edge_backup(*command), home, label)
        del machine.failing[label]


@pytest.mark.parametrize("log_format", ["text", "json"])
def test_a_restore_diagnostic_naming_a_row_is_not_printed(
    edge_backup, machine, home, monkeypatch, log_format
):
    monkeypatch.setenv("LOG_FORMAT", log_format)
    edge_backup("backup")
    machine.restore_diagnostic = 'COPY credential, line 1: "ROW-MARKER-4711"'

    outcome = edge_backup("restore", "--test")

    assert outcome.exit_code == ExitCode.FAILURE
    assert_nothing_forbidden_is_shown(outcome, home, "pg_restore")


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
    "a duplicate table": SONGMAKER_TOML + 2 * f'\n[app."{HOST_PATH_MARKER}"]\n',
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
    assert list((home / ".cache").glob("*/*")) == []


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
def test_a_realm_step_asks_the_backup_child_for_text_under_an_exported_json(monkeypatch):
    monkeypatch.setenv("PYTHONPATH", str(SOURCE))
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


def the_event(outcome_out: str, name: str, subject: str | None = None) -> tuple[int, dict]:
    [found] = [
        (priority, event)
        for priority, event in events(outcome_out)
        if event["event"] == name and subject in (None, event["subject"])
    ]
    return found


@pytest.mark.usefixtures("json_log")
def test_a_backed_up_event_carries_the_snapshot_the_bytes_and_the_seconds_as_raw_values(
    edge_backup, machine
):
    machine.source_bytes = 2_254_857_830
    machine.backup_seconds = 100

    outcome = edge_backup("backup")

    _, event = the_event(outcome.out, "backed up")
    assert list(event) == [*COMMON_FIELDS, "subject", "snapshot", "bytes", "seconds"]
    assert (event["snapshot"], event["bytes"], event["seconds"]) == (
        machine.snapshots[-1]["id"][:8],
        2_254_857_830,
        100.0,
    )


@pytest.mark.usefixtures("json_log")
def test_the_pruned_event_keeps_its_word_and_carries_the_seconds(edge_backup, machine, home):
    machine.maintenance_seconds = 20

    outcome = edge_backup(*declare_two_apps(home), "backup")

    _, event = the_event(outcome.out, "pruned")
    assert (event["fact"], event["seconds"]) == ("checked", 60.0)
    assert list(event)[-2:] == ["fact", "seconds"]


def text_reason_of(output: str, event: str) -> str:
    [line] = [line for line in output.splitlines() if f" {event} " in line]
    return line.split(f"{event} ", 1)[1].strip()


def test_a_failed_app_carries_its_reason_and_its_skipped_prune_carries_its_own(
    edge_backup, machine, monkeypatch
):
    machine.lose_keycloak_database()
    monkeypatch.setenv("LOG_FORMAT", "text")
    in_text = edge_backup(*declare_shipped_apps(), "backup")
    monkeypatch.setenv("LOG_FORMAT", "json")

    in_json = edge_backup(*declare_shipped_apps(), "backup")

    priority, failed = the_event(in_json.out, "not backed up")
    assert priority == 3
    assert failed["reason"] == text_reason_of(in_text.out, "not backed up")
    assert "fact" not in failed
    priority, skipped = the_event(in_json.out, "not pruned")
    assert (priority, skipped["subject"], skipped["reason"]) == (6, "keycloak", "its backup failed")
    assert "fact" not in skipped


@pytest.mark.usefixtures("json_log")
def test_a_proven_restore_carries_the_snapshot_and_the_checked_row_carries_no_field(edge_backup):
    edge_backup("backup")

    outcome = edge_backup("restore", "--test")

    _, proven = the_event(outcome.out, "restore proven")
    assert len(proven["snapshot"]) == 8
    assert "fact" not in proven
    _, checked = the_event(outcome.out, "checked")
    assert not {"fact", "snapshot", "reason"} & set(checked)


@pytest.mark.usefixtures("json_log")
def test_a_restore_that_proves_nothing_and_a_failing_check_each_carry_a_reason(
    edge_backup, machine
):
    machine.failing["restic check"] = 1

    outcome = edge_backup(*declare_shipped_apps(), "restore", "--test")

    for name in ("not proven", "not checked"):
        priority, event = the_event(outcome.out, name, "keycloak" if name == "not proven" else None)
        assert (priority, bool(event["reason"]), "fact" in event) == (3, True, False), name


@pytest.mark.usefixtures("json_log")
@pytest.mark.parametrize(
    ("fields", "raw_bytes", "raw_seconds", "text_ending"),
    [
        (
            ((Field.BYTES, 2_254_857_830), (Field.SECONDS, 192.44)),
            2_254_857_830,
            192.4,
            "2.1 GiB · 3m12s\n",
        ),
        (((Field.BYTES, 0), (Field.SECONDS, 0)), 0, 0, "0 B · <1s\n"),
    ],
    ids=["size and span", "zero"],
)
def test_a_size_and_a_span_stay_raw_in_json_and_read_as_units_in_text_even_at_zero(
    capsys, monkeypatch, fields, raw_bytes, raw_seconds, text_ending
):
    write_row(row(fields=fields))
    in_json = capsys.readouterr().out
    monkeypatch.setenv("LOG_FORMAT", "text")
    write_row(row(fields=fields))
    in_text = capsys.readouterr().out

    _, event = the_one_event(in_json)
    assert (event["bytes"], event["seconds"]) == (raw_bytes, raw_seconds)
    assert in_text.endswith(text_ending)


@pytest.mark.usefixtures("json_log")
def test_a_fact_and_a_field_stand_together_fact_first(capsys, monkeypatch):
    write_row(row(fact="checked", fields=((Field.SECONDS, 60),)))
    in_json = capsys.readouterr().out
    monkeypatch.setenv("LOG_FORMAT", "text")
    write_row(row(fact="checked", fields=((Field.SECONDS, 60),)))
    in_text = capsys.readouterr().out

    _, event = the_one_event(in_json)
    assert list(event)[-2:] == ["fact", "seconds"]
    assert in_text.endswith("checked · 1m00s\n")


@pytest.mark.parametrize("field", [Field.REASON, Field.SNAPSHOT])
@pytest.mark.parametrize("log_format", ["json", "text"])
def test_hostile_text_in_a_field_stays_one_escaped_line(capsys, monkeypatch, field, log_format):
    monkeypatch.setenv("LOG_FORMAT", log_format)

    write_row(row(fields=((field, f"{HOSTILE} "),)))

    shown = capsys.readouterr().out
    expected = printable(f"{HOSTILE} ").rstrip()
    if log_format == "json":
        assert the_one_event(shown)[1][field.value] == expected
    else:
        assert shown.count("\n") == 1
        assert shown.rstrip("\n").endswith(expected)
