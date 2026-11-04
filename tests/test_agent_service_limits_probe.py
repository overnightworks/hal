"""The deadline of L7 in the API numbers probe: a person's refusal counts only when it
came within the window the item sets."""

from __future__ import annotations

from collections.abc import Iterator
from types import ModuleType

import pytest
from support.probe_support import probe_imports


@pytest.fixture(scope="module")
def limits() -> Iterator[ModuleType]:
    with probe_imports():
        import litellm_limits as module

        yield module


@pytest.mark.parametrize(
    ("refused", "offset", "verdict"),
    [
        (True, -1, "held"),
        (True, 0, "held"),
        (True, 9, "failed"),
        (False, -1, "wait"),
        (False, 9, "failed"),
    ],
    ids=[
        "refusal inside the window",
        "refusal at the deadline",
        "refusal after the deadline",
        "answer inside the window",
        "answer after the deadline",
    ],
)
def test_a_refusal_after_the_window_fails_l7(limits, refused, offset, verdict):
    elapsed = limits.PERSON_BUDGET_WINDOW + offset
    assert limits.person_budget_verdict(refused, elapsed).value == verdict
