"""`hal version`: which code runs. The commit and branch of the checkout this code lives in, whether
its tree is clean (as `hal apply` means it), and how it stands to the `origin/main` the last fetch
left. It never fetches, so it answers offline and changes nothing in the checkout."""

import argparse
from collections.abc import Sequence
from pathlib import Path

from hal.grammar import Asks, Command, ExitCode
from hal.output import is_verbose, printable, write_error, write_line
from hal.output.command import PROGRAM, Verb, command
from hal.stack import checkout

# The tree this code lives in, looked up when the command runs: an installed wheel has none.
CODE_TREE = Path(__file__).resolve().parents[2]
ORIGIN = f"origin/{checkout.MAIN}"
NO_CHECKOUT = "no checkout (installed from a wheel)"


def configure(parser: argparse.ArgumentParser) -> None:
    parser.description = "Name the code that runs. -v prints each git call on stderr."


def run(arguments: argparse.Namespace) -> ExitCode:
    tree = CODE_TREE
    if not (tree / ".git").exists():
        write_line(NO_CHECKOUT)
        return ExitCode.OK
    runner = checkout.echoing(checkout.run_git) if is_verbose() else checkout.run_git
    try:
        line = describe(checkout.Git(tree, runner))
    except checkout.GitError as error:
        write_error(
            f"cannot read the checkout {printable(str(tree))}, {error}", command(Verb.VERSION, "-v")
        )
        return ExitCode.FAILURE
    write_line(printable(line))
    return ExitCode.OK


def describe(git: checkout.Git) -> str:
    """The line `hal version` prints for a checkout; raises GitError."""
    commit = git.short()
    branch = git.branch()
    where = branch if branch else f"detached at {commit}"
    return " · ".join([f"{PROGRAM} {commit}", where, _tree(git.changed_paths()), _standing(git)])


def _tree(changed: Sequence[str]) -> str:
    return f"{len(changed)} changed" if changed else "clean"


def _standing(git: checkout.Git) -> str:
    if not git.has_fetched_main():
        return f"{ORIGIN} never fetched"
    ahead, behind = git.divergence(checkout.ORIGIN_MAIN)
    standing = checkout.standing_of(ahead, behind)
    if standing is checkout.Standing.CURRENT:
        return f"up to date with {ORIGIN}"
    if standing is checkout.Standing.BEHIND:
        return f"{behind} behind {ORIGIN}"
    if standing is checkout.Standing.AHEAD:
        return f"{ahead} ahead of {ORIGIN}"
    return f"diverged from {ORIGIN} ({ahead} ahead, {behind} behind)"


COMMAND = Command(
    Verb.VERSION, "name the code that runs", run, configure, json=False, asks=Asks.NEVER
)
