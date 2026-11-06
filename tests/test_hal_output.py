"""The terminal form every hal command prints: one row, one verdict, one error pair."""

import io
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from functools import partial

import pytest
from support.terminal_support import put_on_terminals

from hal.output import (
    HEADING_THRESHOLD,
    Glyph,
    Group,
    GroupWriter,
    Noun,
    Row,
    Stream,
    Tone,
    TrailingNoun,
    Verdict,
    confirmed,
    counted,
    format_bytes,
    format_duration,
    format_moment,
    write_detail,
    write_error,
    write_groups,
    write_line,
    write_row,
    write_table,
    write_verdict,
)


class Event(StrEnum):
    CHANGED = "changed"
    UNCHANGED = "unchanged"
    SKIPPED = "skipped"
    RESTORE_PROVEN = "restore proven"
    NOT_PROVEN = "not proven"


class Heading(StrEnum):
    APPS = "apps"
    UNITS = "units"


def test_a_row_is_two_spaces_a_glyph_the_subject_and_the_event_in_fixed_columns(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#296 invariant 3: a row is glyph, subject, event and fact in fixed columns."""

    write_row(Row(Glyph.DONE, "timers", Event.CHANGED))
    write_row(Row(Glyph.UNCHANGED, "commit hook", Event.UNCHANGED, "nothing to do"))

    assert capsys.readouterr().out.splitlines() == [
        "  ✓ timers          changed",
        "  · commit hook     unchanged      nothing to do",
    ]


def test_a_fourteen_character_event_and_a_short_one_put_their_facts_at_the_same_column(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_row(Row(Glyph.DONE, "app", Event.RESTORE_PROVEN, "one"))
    write_row(Row(Glyph.NEEDS_YOU, "app", Event.NOT_PROVEN, "two"))

    first, second = capsys.readouterr().out.splitlines()
    assert first.index("one") == second.index("two")


def test_a_row_shows_text_from_outside_as_one_line_of_plain_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#296 invariant 4: the owner escapes a fact from outside before any renderer sees it."""

    write_row(Row(Glyph.NEEDS_YOU, "secrets", Event.CHANGED, "a\nb\x1b[31m"))

    assert capsys.readouterr().out == "  ! secrets         changed        a\\nb\\x1b[31m\n"


@pytest.mark.parametrize(
    ("seconds", "shown"),
    [
        (0.4, "<1s"),
        (1.0, "1s"),
        (47.9, "47s"),
        (59.9, "59s"),
        (60, "1m00s"),
        (65, "1m05s"),
        (278, "4m38s"),
        (3599.9, "59m59s"),
        (3720, "1h02m"),
    ],
)
def test_a_duration_is_whole_seconds_rounded_down_then_minutes_then_hours(
    seconds: float, shown: str
) -> None:
    """#500: under a second `<1s`, from 60 s `XmYYs`, from one hour `XhYYm`."""

    assert format_duration(seconds) == shown


@pytest.mark.parametrize(
    ("moment", "shown"),
    [
        (datetime(2026, 10, 18, 3, 0, tzinfo=UTC), "18.10. 05:00"),
        (datetime(2026, 10, 25, 0, 30, tzinfo=UTC), "25.10. 02:30"),
        (datetime(2026, 10, 25, 1, 30, tzinfo=UTC), "25.10. 02:30"),
        (datetime(2026, 10, 17, 22, 30, tzinfo=UTC), "18.10. 00:30"),
        (datetime(2025, 12, 31, 12, 0, tzinfo=UTC), "31.12.2025 13:00"),
    ],
    ids=[
        "same year",
        "before the clock change",
        "after the clock change",
        "other local day than UTC",
        "other year",
    ],
)
def test_a_moment_shows_on_the_local_wall_clock_with_the_year_only_when_it_is_not_this_one(
    berlin_time, moment, shown
):
    assert format_moment(moment, datetime(2026, 10, 28, 8, 0, tzinfo=UTC)) == shown


@pytest.mark.parametrize(
    ("size", "shown"),
    [
        (0, "0 B"),
        (999, "999 B"),
        (1024, "1.0 KiB"),
        (1536, "1.5 KiB"),
        (1048575, "1.0 MiB"),
        (1048064, "1.0 MiB"),
        (4404019, "4.2 MiB"),
        (int(9.96 * 1024**2), "10 MiB"),
        (60 * 1024**2, "60 MiB"),
        (2254857830, "2.1 GiB"),
        (3 * 1024**4, "3.0 TiB"),
    ],
)
def test_a_size_is_binary_units_rounded_with_one_decimal_below_ten(size: int, shown: str) -> None:
    assert format_bytes(size) == shown


def test_an_error_pair_goes_to_stderr_with_both_lines_escaped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#296 invariant 3 and 4: the run may end in one `error:`/`next:` pair, escaped, on stderr."""

    write_error("stopped\nat system", "run\x1b[0m it")

    captured = capsys.readouterr()
    assert (captured.out, captured.err.splitlines()) == (
        "",
        ["error: stopped\\nat system", "next: run\\x1b[0m it"],
    )


def test_on_a_terminal_a_row_colours_only_its_glyph_and_dims_its_fact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#495 and #498: the glyph repeats the word in colour; subject and event keep the default."""

    out, _err = put_on_terminals(monkeypatch)
    write_row(Row(Glyph.DONE, "timers", Event.CHANGED, "three units"))
    write_row(Row(Glyph.FAILED, "system", Event.CHANGED))
    write_row(Row(Glyph.NEEDS_YOU, "secrets", Event.CHANGED))
    write_row(Row(Glyph.CHANGE, "commit hook", Event.CHANGED))
    write_row(Row(Glyph.ANNOUNCE, "sudo", Event.CHANGED))

    assert out.getvalue().splitlines() == [
        "  \x1b[32m✓\x1b[0m timers          changed        \x1b[2mthree units\x1b[0m",
        "  \x1b[31m✗\x1b[0m system          changed",
        "  \x1b[33m!\x1b[0m secrets         changed",
        "  \x1b[34m~\x1b[0m commit hook     changed",
        "  \x1b[36m\u203a\x1b[0m sudo            changed",
    ]


def test_on_a_terminal_an_unchanged_row_is_dim_as_a_whole(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#495: a `·` row steps back entirely."""

    out, _err = put_on_terminals(monkeypatch)
    write_row(Row(Glyph.UNCHANGED, "commit hook", Event.UNCHANGED, "nothing to do"))

    assert out.getvalue() == ("\x1b[2m  · commit hook     unchanged      nothing to do\x1b[0m\n")


@pytest.mark.parametrize(
    ("glyph", "style"),
    [
        (Glyph.DONE, "1"),
        (Glyph.CHANGE, "1;34"),
        (Glyph.NEEDS_YOU, "1;33"),
        (Glyph.FAILED, "1;31"),
    ],
)
def test_on_a_terminal_a_verdict_headline_is_bold_in_its_glyphs_colour_and_the_tail_is_dim(
    monkeypatch: pytest.MonkeyPatch, glyph: Glyph, style: str
) -> None:
    out, _err = put_on_terminals(monkeypatch)
    write_verdict(Verdict(glyph, "setup", ((2, Event.CHANGED),), "run hal"))

    assert out.getvalue() == (
        f"\x1b[{style}m{glyph.value} setup\x1b[0m\x1b[2m · 2 changed · run hal\x1b[0m\n"
    )


@pytest.mark.parametrize(
    ("verdict", "plain", "dimmed"),
    [
        pytest.param(
            Verdict(Glyph.DONE, "setup done", ((1, Event.CHANGED),), elapsed_seconds=47.9),
            "✓ setup done · 1 changed · 47s",
            "\x1b[1m✓ setup done\x1b[0m\x1b[2m · 1 changed · 47s\x1b[0m",
            id="counts with the run time",
        ),
        pytest.param(
            Verdict(Glyph.NEEDS_YOU, "88 findings", ((0, Event.CHANGED),), "hal secrets -v"),
            "! 88 findings · hal secrets -v",
            "\x1b[1;33m! 88 findings\x1b[0m\x1b[2m · hal secrets -v\x1b[0m",
            id="a hint alone",
        ),
        pytest.param(
            Verdict(Glyph.NEEDS_YOU, "2 findings", (), "--json lists each", None, ("272 ports",)),
            "! 2 findings · 272 ports · --json lists each",
            "\x1b[1;33m! 2 findings\x1b[0m\x1b[2m · 272 ports · --json lists each\x1b[0m",
            id="details with a hint",
        ),
        pytest.param(
            Verdict(
                Glyph.CHANGE,
                "setup",
                ((2, Event.CHANGED), (0, Event.UNCHANGED), (1, Event.SKIPPED)),
                "run hal",
                47.9,
            ),
            "~ setup · 2 changed, 1 skipped · 47s · run hal",
            "\x1b[1;34m~ setup\x1b[0m\x1b[2m · 2 changed, 1 skipped · 47s · run hal\x1b[0m",
            id="counts around a zero, the run time and the hint in order",
        ),
        pytest.param(
            Verdict(Glyph.DONE, "done", ()),
            "✓ done",
            "\x1b[1m✓ done\x1b[0m",
            id="no tail gets no dim span",
        ),
    ],
)
def test_a_verdicts_whole_tail_is_one_dim_span_on_a_terminal_and_plain_without_colour(
    monkeypatch: pytest.MonkeyPatch, verdict: Verdict, plain: str, dimmed: str
) -> None:
    out, _err = put_on_terminals(monkeypatch)
    write_verdict(verdict)
    terminal = out.getvalue()
    out.truncate(0)
    out.seek(0)
    monkeypatch.setenv("NO_COLOR", "1")
    write_verdict(verdict)

    assert (terminal, out.getvalue()) == (dimmed + "\n", plain + "\n")


@pytest.mark.parametrize("failure", [AttributeError, ValueError])
def test_a_stream_without_a_working_isatty_prints_plain(
    monkeypatch: pytest.MonkeyPatch, failure: type[Exception]
) -> None:
    """#495: a stream without a working isatty prints plain."""

    class Broken(io.StringIO):
        def isatty(self) -> bool:
            raise failure

    out = Broken()
    monkeypatch.setattr(sys, "stdout", out)
    write_row(Row(Glyph.DONE, "timers", Event.CHANGED, "three units"))

    assert out.getvalue() == "  ✓ timers          changed        three units\n"


def test_on_a_terminal_an_error_pair_is_bold_red_error_and_cyan_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#495: only the labels carry colour, the rest of each line stays default."""

    out, err = put_on_terminals(monkeypatch)
    write_error("stopped", "run it")

    assert (out.getvalue(), err.getvalue()) == (
        "",
        "\x1b[1;31merror:\x1b[0m stopped\n\x1b[36mnext:\x1b[0m run it\n",
    )


def test_colour_is_decided_per_stream(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#495: stdout in a pipe stays plain while stderr on a terminal is coloured, and back."""

    _out, err = put_on_terminals(monkeypatch)
    monkeypatch.setattr(sys, "stdout", io.StringIO())
    write_row(Row(Glyph.DONE, "timers", Event.CHANGED))
    write_error("stopped")

    assert sys.stdout.getvalue() == "  ✓ timers          changed\n"
    assert err.getvalue() == "\x1b[1;31merror:\x1b[0m stopped\n"


def test_a_fresh_line_error_starts_with_one_bare_newline_on_stderr(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A hidden prompt leaves the cursor mid-line, so the pair starts on a fresh one."""

    write_error("interrupted", "run it", fresh_line=True)

    assert capsys.readouterr().err == "\nerror: interrupted\nnext: run it\n"


@pytest.mark.parametrize(("fresh_line", "prefix"), [(True, "\n"), (False, "")])
def test_a_fresh_line_row_starts_with_one_empty_line_and_the_default_does_not(
    capsys: pytest.CaptureFixture[str], fresh_line: bool, prefix: str
) -> None:
    """A ^C leaves the cursor mid-line, so the row starts on a fresh one."""

    write_row(Row(Glyph.FAILED, "system", Event.CHANGED), fresh_line=fresh_line)

    assert capsys.readouterr().out == f"{prefix}  ✗ system          changed\n"


def test_a_fresh_line_row_under_json_log_format_adds_no_empty_line_to_the_stream(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("LOG_FORMAT", "json")

    write_row(Row(Glyph.FAILED, "system", Event.CHANGED), fresh_line=True)

    shown = capsys.readouterr().out
    assert shown.startswith("<")
    assert shown.count("\n") == 1


@pytest.mark.parametrize(
    ("variable", "value"), [("NO_COLOR", "1"), ("NO_COLOR", "anything"), ("TERM", "dumb")]
)
def test_a_terminal_that_asks_for_no_colour_gets_the_plain_bytes(
    monkeypatch: pytest.MonkeyPatch,
    variable: str,
    value: str,
) -> None:
    """#296 invariant 2: NO_COLOR or TERM=dumb turns colour off on a terminal."""

    out, err = put_on_terminals(monkeypatch)
    monkeypatch.setenv(variable, value)

    write_row(Row(Glyph.UNCHANGED, "commit hook", Event.UNCHANGED, "nothing to do"))
    write_verdict(Verdict(Glyph.DONE, "setup", ((1, Event.CHANGED),)))
    write_error("stopped", "run it")

    assert out.getvalue().splitlines() == [
        "  · commit hook     unchanged      nothing to do",
        "✓ setup · 1 changed",
    ]
    assert err.getvalue().splitlines() == ["error: stopped", "next: run it"]


def test_an_empty_no_colour_does_not_turn_colour_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#495: only a non-empty NO_COLOR turns colour off."""

    _out, err = put_on_terminals(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "")

    write_error("stopped")

    assert err.getvalue().startswith("\x1b[")


class Finding(Noun):
    ACTION = "action"
    AREA_CHECKED = "area checked"
    ENTRY = "entry"
    DAY = "day"


class Page(TrailingNoun):
    NEW_PAGE = "new page"


@pytest.mark.parametrize(
    ("count", "shown"),
    [(1, "1 action"), (2, "2 actions")],
)
def test_a_rows_count_carries_the_plural_of_a_noun_event(
    capsys: pytest.CaptureFixture[str], count: int, shown: str
) -> None:
    """#493: the event enum holds the singular word; the renderer shows the count and the plural."""

    write_row(Row(Glyph.NEEDS_YOU, "backup", Finding.ACTION, "a fact", count))

    assert capsys.readouterr().out == f"  ! backup          {shown:<13}  a fact\n"


@pytest.mark.parametrize(
    ("count", "shown"),
    [(1, "1 area checked"), (3, "3 areas checked")],
)
def test_counted_puts_the_count_before_the_noun_and_pluralises_its_first_word(
    count: int, shown: str
) -> None:
    assert counted(count, Finding.AREA_CHECKED) == shown


@pytest.mark.parametrize(
    ("noun", "count", "shown"),
    [
        (Page.NEW_PAGE, 1, "1 new page"),
        (Page.NEW_PAGE, 2, "2 new pages"),
        (Page.NEW_PAGE, 0, "0 new pages"),
        (Finding.AREA_CHECKED, 2, "2 areas checked"),
        (Finding.ENTRY, 1, "1 entry"),
        (Finding.ENTRY, 2, "2 entries"),
        (Finding.DAY, 2, "2 days"),
    ],
)
def test_a_trailing_noun_takes_its_plural_after_the_last_word_and_a_noun_after_the_first(
    noun: StrEnum, count: int, shown: str
) -> None:
    assert counted(count, noun) == shown


def test_a_rows_details_print_indented_under_it_and_escaped(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_row(Row(Glyph.CHANGE, "legal", Event.CHANGED, "a fact", details=("one", "t\x1b[31mwo")))

    assert capsys.readouterr().out.splitlines() == [
        "  ~ legal           changed        a fact",
        "    one",
        "    t\\x1b[31mwo",
    ]


def test_on_a_terminal_a_rows_details_are_dim(monkeypatch: pytest.MonkeyPatch) -> None:
    out, _err = put_on_terminals(monkeypatch)

    write_row(Row(Glyph.CHANGE, "legal", Event.CHANGED, details=("one",)))

    assert out.getvalue().splitlines()[1] == "\x1b[2m    one\x1b[0m"


def test_a_verdict_without_a_summary_is_its_counts_then_its_details_and_its_next_step(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """#493: counts of nouns take the plural; the next step follows on its own stdout line."""

    write_verdict(
        Verdict(
            Glyph.NEEDS_YOU,
            "",
            ((2, Finding.ACTION), (0, Finding.AREA_CHECKED), (1, Event.CHANGED)),
            details=("mail sent", "report ~/x"),
            next_step="hal backup",
        )
    )
    write_verdict(Verdict(Glyph.DONE, "all well", ((5, Finding.AREA_CHECKED),)))
    write_verdict(Verdict(Glyph.DONE, "all well", ((1, Finding.AREA_CHECKED),)))

    assert capsys.readouterr().out.splitlines() == [
        "! 2 actions, 1 changed · mail sent · report ~/x",
        "next: hal backup",
        "✓ all well · 5 areas checked",
        "✓ all well · 1 area checked",
    ]


def rows_of(count: int) -> tuple[Row, ...]:
    return tuple(Row(Glyph.CHANGE, f"app{number}", Event.CHANGED) for number in range(count))


def test_below_the_threshold_the_groups_print_their_rows_without_headings(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The blessed picture: headings appear only from about six rows."""

    write_groups(
        (Group(Heading.UNITS, rows_of(2)), Group(Heading.APPS, rows_of(HEADING_THRESHOLD - 3)))
    )

    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == HEADING_THRESHOLD - 1
    assert not any(line.startswith(("units", "apps")) for line in lines)


def test_from_the_threshold_every_named_group_prints_under_an_unindented_heading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_groups(
        (Group(Heading.UNITS, rows_of(2)), Group(Heading.APPS, rows_of(HEADING_THRESHOLD - 2)))
    )

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "units"
    assert lines[3] == "apps"
    assert len(lines) == HEADING_THRESHOLD + 2


def test_an_empty_group_prints_nothing_and_does_not_count_towards_the_threshold(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_groups((Group(Heading.UNITS, ()), Group(Heading.APPS, rows_of(HEADING_THRESHOLD - 1))))

    assert "apps" not in capsys.readouterr().out.splitlines()


def test_rows_without_a_heading_print_first_and_stay_without_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_groups(
        (
            Group(Heading.APPS, rows_of(HEADING_THRESHOLD)),
            Group(None, (Row(Glyph.DONE, "checkout", Event.CHANGED),)),
        )
    )

    lines = capsys.readouterr().out.splitlines()
    assert lines[0] == "  ✓ checkout        changed"
    assert lines[1] == "apps"


def writer_of(rows: int) -> GroupWriter:
    return GroupWriter.for_groups((Group(Heading.APPS, rows_of(rows)),))


def test_a_writer_prints_a_heading_once_with_the_first_row_of_its_group_and_none_for_an_empty_one(
    capsys: pytest.CaptureFixture[str],
) -> None:
    writer = writer_of(HEADING_THRESHOLD)

    writer.enter(Heading.UNITS)
    writer.enter(Heading.APPS)
    writer.write(*rows_of(1))
    writer.write(*rows_of(1))
    writer.enter(Heading.UNITS)
    writer.write(*rows_of(1))

    lines = capsys.readouterr().out.splitlines()
    assert [line for line in lines if not line.startswith(" ")] == ["apps", "units"]
    assert lines[0] == "apps"
    assert lines[3] == "units"


def test_a_writer_of_a_plan_below_the_threshold_prints_its_rows_flat(
    capsys: pytest.CaptureFixture[str],
) -> None:
    writer = writer_of(HEADING_THRESHOLD - 1)

    writer.enter(Heading.APPS)
    writer.write(*rows_of(2))

    assert all(line.startswith(" ") for line in capsys.readouterr().out.splitlines())


def test_a_writer_ends_a_line_a_ctrl_c_left_open_before_the_heading(
    capsys: pytest.CaptureFixture[str],
) -> None:
    writer = writer_of(HEADING_THRESHOLD)
    sys.stdout.write("open")

    writer.enter(Heading.APPS)
    writer.write(*rows_of(1), fresh_line=True)

    assert capsys.readouterr().out.splitlines()[:2] == ["open", "apps"]


def test_on_a_terminal_a_heading_is_bold_and_add_and_remove_rows_are_green_and_red(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, _err = put_on_terminals(monkeypatch)
    write_groups(
        (
            Group(
                Heading.APPS,
                (Row(Glyph.ADD, "hopin", Event.CHANGED), *rows_of(HEADING_THRESHOLD - 2)),
            ),
            Group(Heading.UNITS, (Row(Glyph.REMOVE, "legal", Event.CHANGED),)),
        )
    )

    lines = out.getvalue().splitlines()
    assert lines[0] == "\x1b[1mapps\x1b[0m"
    assert lines[1] == "  \x1b[32m+\x1b[0m hopin           changed"
    assert "  \x1b[31m-\x1b[0m legal           changed" in lines


def test_with_no_colour_a_heading_and_the_add_and_remove_glyphs_are_plain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    out, _err = put_on_terminals(monkeypatch)
    monkeypatch.setenv("NO_COLOR", "1")

    write_groups(
        (
            Group(
                Heading.APPS,
                (
                    Row(Glyph.ADD, "hopin", Event.CHANGED),
                    Row(Glyph.REMOVE, "legal", Event.CHANGED),
                    *rows_of(HEADING_THRESHOLD - 2),
                ),
            ),
        )
    )

    assert out.getvalue().splitlines()[:3] == [
        "apps",
        "  + hopin           changed",
        "  - legal           changed",
    ]


def test_a_plain_detail_line_is_indented_and_escaped(capsys: pytest.CaptureFixture[str]) -> None:
    """Text from outside stays one line under a row."""

    write_detail("why: a reason", "[ ] step\x1b[31m")

    assert capsys.readouterr().out.splitlines() == ["    why: a reason", "    [ ] step\\x1b[31m"]


@pytest.mark.parametrize(
    ("flush", "reaches_the_pipe"),
    [(True, "    a line\n"), (False, "")],
    ids=["flushed", "left to the buffer"],
)
def test_a_detail_line_is_flushed_only_when_asked(
    monkeypatch: pytest.MonkeyPatch, flush: bool, reaches_the_pipe: str
) -> None:
    """A reader that follows the output as it comes asks for `flush`."""

    class BufferedPipe(io.StringIO):
        reached = ""

        def flush(self) -> None:
            self.reached = self.getvalue()

    pipe = BufferedPipe()
    monkeypatch.setattr(sys, "stdout", pipe)

    write_detail("a line", flush=flush)

    assert pipe.reached == reaches_the_pipe


@pytest.mark.parametrize(
    ("tone", "style"), [(Tone.DIM, "2"), (Tone.WARNING, "33")], ids=["dim", "warning is yellow"]
)
def test_on_a_terminal_a_toned_detail_line_is_styled_as_a_whole_and_a_plain_one_is_not(
    monkeypatch: pytest.MonkeyPatch, tone: Tone, style: str
) -> None:
    """The tone styles the indented line; plain carries no style."""

    out, _err = put_on_terminals(monkeypatch)
    write_detail("a line", tone=tone)
    write_detail("a line")

    assert out.getvalue() == f"\x1b[{style}m    a line\x1b[0m\n    a line\n"


@pytest.mark.parametrize(
    ("typed", "expected"),
    [
        ("yes\n", True),
        ("Yes\n", False),
        ("y\n", False),
        (" yes\n", False),
        ("\n", False),
        ("", False),
    ],
    ids=["yes", "capitalised", "short", "padded", "empty line", "closed stdin"],
)
def test_only_the_exact_yes_confirms_and_a_closed_stdin_is_a_no(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], typed: str, expected: bool
) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(typed))

    assert confirmed("start hopin") is expected
    assert capsys.readouterr().out == "Type yes to start hopin: "


def test_on_a_terminal_the_yes_of_the_prompt_is_bold(monkeypatch: pytest.MonkeyPatch) -> None:
    out, _err = put_on_terminals(monkeypatch)
    monkeypatch.setattr(sys, "stdin", io.StringIO("yes\n"))

    confirmed("apply 2 changes")

    assert out.getvalue() == "Type \x1b[1myes\x1b[0m to apply 2 changes: "


def test_a_ctrl_c_at_the_prompt_is_not_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    class Interrupted(io.StringIO):
        def readline(self, *_arguments: object) -> str:
            raise KeyboardInterrupt

    monkeypatch.setattr(sys, "stdin", Interrupted())

    with pytest.raises(KeyboardInterrupt):
        confirmed("start hopin")


@pytest.mark.parametrize(
    ("write", "expected_out", "expected_err"),
    [
        pytest.param(
            partial(write_line, "a line"), "a line\n", "", id="stdout-is-the-default-stream"
        ),
        pytest.param(
            partial(write_line, "a line", stream=Stream.STDERR),
            "",
            "a line\n",
            id="stderr-on-request",
        ),
        pytest.param(
            partial(write_line, "a line", end=""), "a line", "", id="end-replaces-the-line-end"
        ),
    ],
)
def test_a_raw_line_goes_to_the_chosen_stream_exactly_as_given(
    capsys: pytest.CaptureFixture[str],
    write: Callable[[], None],
    expected_out: str,
    expected_err: str,
) -> None:
    write()

    captured = capsys.readouterr()
    assert (captured.out, captured.err) == (expected_out, expected_err)


@pytest.mark.parametrize("stream", [Stream.STDOUT, Stream.STDERR])
@pytest.mark.parametrize("flush", [True, False])
def test_a_line_reaches_its_stream_at_once_only_when_flushed(
    monkeypatch: pytest.MonkeyPatch, stream: Stream, flush: bool
) -> None:
    sink = io.BytesIO()
    monkeypatch.setattr(
        sys, stream.value, io.TextIOWrapper(sink, encoding="utf-8", write_through=False)
    )

    write_line("a line", stream=stream, flush=flush)

    assert sink.getvalue() == (b"a line\n" if flush else b"")


def test_a_table_aligns_each_column_to_its_widest_cell_and_leaves_the_last_unpadded(
    capsys: pytest.CaptureFixture[str],
) -> None:
    write_table(
        ("name", "kind", "renew"), [("a", "derived copy", "x"), ("long-name", "token", "y")]
    )

    assert capsys.readouterr().out.splitlines() == [
        "name       kind          renew",
        "a          derived copy  x",
        "long-name  token         y",
    ]


def test_a_table_escapes_each_cell_before_it_pads(capsys: pytest.CaptureFixture[str]) -> None:
    write_table(("name", "kind"), [("we\nird\x1b[31m", "token"), ("plain", "token")])

    lines = capsys.readouterr().out.splitlines()
    assert lines == ["name             kind", "we\\nird\\x1b[31m  token", "plain            token"]


def test_a_table_header_is_bold_on_a_terminal_and_plain_off_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    write_table(("name", "kind"), [("a", "b")])
    plain = capsys.readouterr().out
    out, _err = put_on_terminals(monkeypatch)

    write_table(("name", "kind"), [("a", "b")])

    assert out.getvalue() == plain.replace("name  kind", "\x1b[1mname  kind\x1b[0m", 1)
