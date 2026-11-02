"""The cell of an unproven barrier after a core recreate (#884 D19) over the switches probe's
`Probe`: with the probe unit's barrier active, a harmless `traefik.yml` edit recreates Traefik
while `dynamic/` is read-only, so the barrier cannot be put up again.

`hal apply --local` ends with 3 and says, in this order, the red row, the cause of the barrier,
the way on, the ruled error words and `next: hal offline`, and no success line for Traefik. With
the directory writable again, the next apply plans the recreate as unfinished and proves the
barrier.
"""

from __future__ import annotations

import re
import stat
from typing import TYPE_CHECKING

from edge_copy import HAL_FAILURE, ProbeFailed, expect

from hal.output import write_line
from hal.output.command import Verb, command
from hal.stack.plan_rows import PlanEvent
from hal.stack.result_rows import ResultEvent

if TYPE_CHECKING:
    from probe import Probe

UNFINISHED_PLAN = f"traefik {PlanEvent.RECREATE} the last recreate did not finish"
IN_ORDER = (
    rf"✗ barriers {ResultEvent.NOT_PROVEN} {re.escape('probe · may be reachable through Traefik')}",
    re.escape("probe: cannot write switch-probe.yml"),
    re.escape(f"then: {command(Verb.APPLY)} repeats the proof"),
    re.escape("error: partial, barriers not proven · no unit switched"),
    re.escape(f"next: {command(Verb.OFFLINE)}"),
)


def cell(probe: Probe) -> None:
    """With the barrier of the probe unit active, as P4 leaves it."""
    probe.edit_traefik_yml()
    dynamic = probe.barrier.parent
    original = stat.S_IMODE(dynamic.stat().st_mode)
    # Traefik reads `dynamic/` as another user than the owner: only the write bits go, or it
    # could not read the directory at all, in this apply or after the mode is restored.
    dynamic.chmod(original & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH))
    try:
        out = probe.hal("apply", "--local", terminal=True, exit_code=HAL_FAILURE)
    finally:
        dynamic.chmod(original)
    position = 0
    for pattern in IN_ORDER:
        found = re.compile(pattern).search(out, position)
        if found is None:
            raise ProbeFailed(f"{pattern!r} is missing or out of order in: {out[-500:]}")
        position = found.end()
    expect("✓ traefik recreated" not in out, f"a success line for traefik: {out[-300:]}")
    again = probe.hal("apply", "--local", terminal=True)
    expect(UNFINISHED_PLAN in again, f"the next apply did not plan the recreate: {again[-300:]}")
    expect("barriers proven" in again, f"the next apply proved nothing: {again[-300:]}")
    write_line(
        "#884 D19 held: a read-only dynamic/ leaves the barrier unproven, exit 3, the red row and "
        "next: hal offline; the next apply recreates and proves it"
    )
