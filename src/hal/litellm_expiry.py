"""What LiteLLM keeps per person or per tool, deleted once it has gone `RETENTION_DAYS` without
use: the daily person and tool rows, the tool rows and the customer rows of idle fingerprints. One
statement in the one `litellm-db` container of a compose project deletes all of it or nothing, and
writes no other table. Days are UTC days, as LiteLLM writes them."""

from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from enum import Enum

from hal.backup import docker, host
from hal.backup.settings import PROBE_TIMEOUT

RETENTION_DAYS = 90
"""Not a setting: the privacy text states this period, and a setting could make it lie."""
DEFAULT_PROJECT = "hal"
"""The compose project `compose.yaml` names."""
NAME = "litellm"
SERVICE = "litellm-db"
SETTINGS_LABEL = "database settings read"
PSQL_LABEL = "psql"


@dataclass(frozen=True)
class Cutoff:
    day: date
    """Daily rows dated before this UTC day go."""
    moment: datetime
    """Tool rows last used before this UTC moment go."""


def cutoff(now: datetime) -> Cutoff:
    utc = now.astimezone(UTC)
    period = timedelta(days=RETENTION_DAYS)
    return Cutoff(day=utc.date() - period, moment=utc - period)


class Kind(Enum):
    """What the run deletes, in the order the statement counts it."""

    PERSON_DAYS = "LiteLLM_DailyEndUserSpend"
    TOOL_DAYS = "LiteLLM_DailyToolSpend"
    TOOLS = "LiteLLM_ToolTable"
    PEOPLE = "LiteLLM_EndUserTable"


@dataclass(frozen=True)
class Off:
    """No ready `litellm-db`: nothing ran."""


@dataclass(frozen=True)
class Expired:
    deleted: dict[Kind, int]


class Outcome(Enum):
    NOT_STARTED = "the statement did not run"
    NOTHING_DELETED = "psql reported the failure: the transaction rolled back"
    UNKNOWN = "the statement may have committed inside the container"


class ExpiryFailed(RuntimeError):
    """One line without a row value; `outcome` says what became of the statement."""

    def __init__(self, reason: str, outcome: Outcome) -> None:
        self.outcome = outcome
        super().__init__(reason)


def statement(limit: Cutoff) -> str:
    """Four data-modifying CTEs share one snapshot: the customer condition reads the daily rows at
    or after the cutoff, which the same statement does not delete. A customer row linked to its
    own budget, or with spend not yet reset, stays."""
    day = f"'{limit.day.isoformat()}'"
    moment = f"TIMESTAMP '{limit.moment.replace(tzinfo=None).isoformat(sep=' ')}'"
    return f"""
WITH person_days AS (
  DELETE FROM "{Kind.PERSON_DAYS.value}" WHERE date < {day} RETURNING 1
), tool_days AS (
  DELETE FROM "{Kind.TOOL_DAYS.value}" WHERE date < {day} RETURNING 1
), tools AS (
  DELETE FROM "{Kind.TOOLS.value}" WHERE coalesce(last_used_at, created_at) < {moment} RETURNING 1
), people AS (
  DELETE FROM "{Kind.PEOPLE.value}" AS person
  WHERE person.budget_id IS NULL AND person.spend = 0 AND NOT EXISTS (
    SELECT 1 FROM "{Kind.PERSON_DAYS.value}" AS kept
    WHERE kept.end_user_id = person.user_id AND kept.date >= {day}
  ) RETURNING 1
)
SELECT (SELECT count(*) FROM person_days), (SELECT count(*) FROM tool_days),
  (SELECT count(*) FROM tools), (SELECT count(*) FROM people)
"""  # noqa: S608 - the only values are the cutoff's day and moment, formatted from date types


def expire(project: str, now: datetime) -> Off | Expired:
    try:
        container = docker.service_container(project, SERVICE, NAME)
        user, database = _database_settings(container)
    except docker.DockerSilentError as error:
        raise ExpiryFailed(str(error), Outcome.NOT_STARTED) from error
    except docker.NotReadyError:
        return Off()
    except (docker.TargetError, host.HostError) as error:
        raise ExpiryFailed(str(error), Outcome.NOT_STARTED) from error
    try:
        answer = host.run(
            ["docker", "exec", container, "psql", "--username", user, "--dbname", database,
             "--no-psqlrc", "--tuples-only", "--no-align", "--set", "ON_ERROR_STOP=1",
             "--command", statement(cutoff(now))],
            label=PSQL_LABEL,
            discard_stderr=True,  # psql quotes row values in its errors
        )  # fmt: skip
    except host.HostCommandError as error:
        raise _failure_of(error, project, container) from error
    return Expired(_counts(answer))


def _database_settings(container: str) -> tuple[str, str]:
    """The user and database the container's own environment names: compose.yaml owns them."""
    answer = host.run(
        ["docker", "exec", container, "printenv", "POSTGRES_USER", "POSTGRES_DB"],
        label=SETTINGS_LABEL,
        timeout=PROBE_TIMEOUT,
    )
    match answer.decode(errors="replace").split():
        case [user, database]:
            return user, database
        case _:
            raise host.UnreadableOutputError("the database settings of litellm are unreadable")


def _failure_of(error: host.HostCommandError, project: str, container: str) -> ExpiryFailed:
    """`docker exec` ends with psql's exit, and with 1 when Docker itself fails: only an exit
    after which Docker still shows the same ready container is psql's own report."""
    if error.exit_code is None:
        return ExpiryFailed(str(error), Outcome.UNKNOWN)
    if _still_ready(project, container):
        return ExpiryFailed(str(error), Outcome.NOTHING_DELETED)
    return ExpiryFailed(f"{error}, unconfirmed by docker", Outcome.UNKNOWN)


def _still_ready(project: str, container: str) -> bool:
    try:
        return docker.service_container(project, SERVICE, NAME) == container
    except docker.NotReadyError, docker.TargetError, host.HostError:
        return False


def _counts(answer: bytes) -> dict[Kind, int]:
    fields = answer.decode(errors="replace").strip().split("|")
    if len(fields) != len(Kind) or not all(field.isdigit() for field in fields):
        raise ExpiryFailed(f"{PSQL_LABEL}'s answer is unreadable", Outcome.UNKNOWN)
    return {kind: int(field) for kind, field in zip(Kind, fields, strict=True)}
