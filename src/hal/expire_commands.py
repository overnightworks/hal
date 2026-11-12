"""`hal expire`: the daily deletion of what LiteLLM keeps per person, per tool or per label,
behind hal's door.
`hal.litellm_expiry` deletes; this module adds the grammar, one row per kind, the verdict, the
error pair and the exit code. It prints counts only, never a row value."""

import argparse
from enum import StrEnum

from hal import litellm_expiry
from hal.backup import host
from hal.grammar import Asks, Command, ExitCode
from hal.litellm_expiry import Expired, ExpiryFailed, Kind, Outcome
from hal.output import Glyph, Noun, Row, Verdict, counted, write_error, write_row, write_verdict
from hal.output.command import Verb, command
from hal.stop_signals import terminate_like_interrupt

HAL_EXPIRE = command(Verb.EXPIRE)
DAYS = litellm_expiry.RETENTION_DAYS
SUBJECTS = {
    Kind.PERSON_DAYS: ("person days", f"older than {DAYS} days"),
    Kind.TOOL_DAYS: ("tool days", f"older than {DAYS} days"),
    Kind.TAG_DAYS: ("label days", f"older than {DAYS} days"),
    Kind.TOOLS: ("tools", f"unused for {DAYS} days"),
    Kind.PEOPLE: ("people", f"idle for {DAYS} days"),
}
NOTHING_DELETED = "nothing deleted"
OUTCOME_UNKNOWN = "outcome unknown"


class ExpireEvent(StrEnum):
    DELETED = "deleted"
    NOT_RUNNING = "not running"
    NOT_EXPIRED = "not expired"


class ExpireNoun(Noun):
    ROW = "row"


def _configure(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--project",
        default=litellm_expiry.DEFAULT_PROJECT,
        help="the compose project whose litellm-db the run looks up "
        f"(default: {litellm_expiry.DEFAULT_PROJECT})",
    )


def _expire(arguments: argparse.Namespace) -> ExitCode:
    started = host.monotonic()
    with terminate_like_interrupt():
        try:
            result = litellm_expiry.expire(arguments.project, host.now())
        except ExpiryFailed as failure:
            _tell_failed(str(failure), failure.outcome)
            return ExitCode.FAILURE
        except KeyboardInterrupt:
            _tell_failed("interrupted", Outcome.UNKNOWN)
            return ExitCode.INTERRUPTED
    if isinstance(result, Expired):
        _tell_expired(result, host.monotonic() - started)
    else:
        write_row(
            Row(Glyph.UNCHANGED, litellm_expiry.NAME, ExpireEvent.NOT_RUNNING, NOTHING_DELETED)
        )
        write_verdict(Verdict(Glyph.DONE, "expire done", ()))
    return ExitCode.OK


def _tell_expired(result: Expired, seconds: float) -> None:
    for kind, (subject, period) in SUBJECTS.items():
        count = result.deleted[kind]
        glyph = Glyph.DONE if count else Glyph.UNCHANGED
        fact = f"{counted(count, ExpireNoun.ROW)} · {period}"
        write_row(Row(glyph, subject, ExpireEvent.DELETED, fact))
    total = sum(result.deleted.values())
    write_verdict(
        Verdict(Glyph.DONE, "expire done", ((total, ExpireNoun.ROW),), elapsed_seconds=seconds)
    )


def _tell_failed(reason: str, outcome: Outcome) -> None:
    match outcome:
        case Outcome.NOT_STARTED:
            fact, error = reason, reason
        case Outcome.NOTHING_DELETED:
            fact, error = f"{reason} · {NOTHING_DELETED}", NOTHING_DELETED
        case _:
            fact, error = (
                f"{reason} · {OUTCOME_UNKNOWN}",
                f"{OUTCOME_UNKNOWN} · the next run repeats it",
            )
    write_row(Row(Glyph.FAILED, litellm_expiry.NAME, ExpireEvent.NOT_EXPIRED, fact))
    write_error(f"{litellm_expiry.NAME} {ExpireEvent.NOT_EXPIRED} · {error}", HAL_EXPIRE)


COMMANDS = (
    Command(
        Verb.EXPIRE,
        f"delete what LiteLLM keeps per person, per tool or per label after {DAYS} days unused",
        _expire,
        _configure,
        json=False,
        asks=Asks.NEVER,
    ),
)
