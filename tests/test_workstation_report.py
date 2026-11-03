from __future__ import annotations

import os
from pathlib import Path

import pytest

from hal.workstation.report import findings_count, markdown_table, write_state_file


@pytest.mark.parametrize(("count", "expected"), [(0, "0 findings"), (1, "1 finding"), (2, "2 findings")])
def test_a_count_of_findings_reads_as_english_singular_or_plural(count: int, expected: str) -> None:
    assert findings_count(count) == expected


@pytest.mark.parametrize(
    ("cell", "shown"),
    [
        ("x|y", "x\\|y"),
        ("", "-"),
        ("weird\nna|me\r\tx", "weird\\nna\\|me\\r\\tx"),
        ("bell\x07esc\x1b", "bell\\x07esc\\x1b"),
        ("bad\udcffname", "bad\\udcffname"),
    ],
    ids=[
        "a pipe",
        "an empty cell",
        "a newline, a carriage return and a tab",
        "any other control character",
        "a byte of a file name that is not UTF-8",
    ],
)
def test_a_table_cell_stays_on_its_row_and_marks_empty_cells(cell: str, shown: str) -> None:
    assert markdown_table(["A"], [[cell]]) == ["| A |", "|---|", f"| {shown} |"]


def test_a_state_file_that_cannot_be_replaced_raises_and_leaves_no_fresh_copy_behind(tmp_path: Path) -> None:
    state_directory = tmp_path / ".local" / "state" / "hal"
    report_file = state_directory / "report.md"
    report_file.mkdir(parents=True)

    with pytest.raises(IsADirectoryError):
        write_state_file(tmp_path, report_file, "neuer Bericht")

    assert os.listdir(state_directory) == ["report.md"]
