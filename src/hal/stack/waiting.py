"""origin's `main` fetched and pinned for `hal apply` and `hal update`, and the refusals when the
live checkout cannot go on from it (#98)."""

from collections.abc import Callable

from hal.stack import checkout


def fetched(git: checkout.Git, say: Callable[[str], None]) -> checkout.Origin | None:
    """origin's `main` fetched and pinned; None after saying why the apply or the update stops
    there: the fetch failed (S4), or HEAD is ahead of or beside it (S3) (#98 rules 2, 3)."""
    try:
        origin = checkout.fetch_origin(git)
    except checkout.GitError as error:
        reason = str(error).removesuffix(".")
        say(f"cannot fetch {checkout.MAIN} from origin, {reason}; nothing changed")
        return None
    if origin.standing in (checkout.Standing.AHEAD, checkout.Standing.DIVERGED):
        stands = (
            "is ahead of" if origin.standing is checkout.Standing.AHEAD else "has diverged from"
        )
        say(
            f"the live checkout {stands} origin {checkout.MAIN} (HEAD {origin.head}, origin "
            f"{checkout.MAIN} {origin.short}); nothing reset, a change reaches it through a pull "
            "request"
        )
        return None
    return origin
