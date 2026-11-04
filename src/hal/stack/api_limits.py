"""The numbers LiteLLM enforces on each app's key and on the person budget: their code defaults,
what `[api]` and `[api.<app>]` of `~/.config/hal/config.toml` say, and which of them holds.

Per number, an app's own table holds, else `[api]`, else the code default; the person budget is
`[api]`'s, else the code default. Only the standard library: `hal.config` builds the record, and
`hal alarm`, `hal check` and `hal setup` must not load the stack with it."""

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

APP_BUDGET_DOLLARS = 10.0
MAX_PARALLEL_REQUESTS = 5
PERSON_BUDGET_DOLLARS = 2.0


@dataclass(frozen=True)
class AppNumbers:
    """What one table says; None where it sets nothing."""

    budget_dollars: float | None = None
    max_parallel_requests: int | None = None


@dataclass(frozen=True)
class AppLimits:
    budget_dollars: float
    max_parallel_requests: int


@dataclass(frozen=True)
class ApiSettings:
    """`[api]` as `every_app` and the person budget, each `[api.<app>]` in `apps`."""

    every_app: AppNumbers = field(default_factory=AppNumbers)
    apps: Mapping[str, AppNumbers] = field(default_factory=lambda: MappingProxyType({}))
    person_budget_dollars: float | None = None

    def limits_of(self, app: str) -> AppLimits:
        own = self.apps.get(app, AppNumbers())
        return AppLimits(
            _first_set(APP_BUDGET_DOLLARS, own.budget_dollars, self.every_app.budget_dollars),
            _first_set(
                MAX_PARALLEL_REQUESTS,
                own.max_parallel_requests,
                self.every_app.max_parallel_requests,
            ),
        )

    def person_budget(self) -> float:
        return _first_set(PERSON_BUDGET_DOLLARS, self.person_budget_dollars)


NONE_SET = ApiSettings()


def _first_set[T](default: T, *candidates: T | None) -> T:
    """The first candidate that is set, else `default`; 0 is set."""
    return next((value for value in candidates if value is not None), default)
