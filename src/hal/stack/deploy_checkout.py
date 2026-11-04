"""The checkout of an app: `~/srv/<key>`, which `hal apply` deploys from (#255).

It is edge's tree. An existing one must be a main worktree whose origin is exactly the app's
repository, with HEAD detached or unborn and no tracked or untracked change; anything else cannot
be planned and nothing is reset. Ignored files stay the operator's: the checkout is made with
`--no-overwrite-ignore`, so a tag that tracks a path an ignored file occupies is refused.

The fetch writes only `.git`. It mirrors origin's `v*` tags into a private namespace with
`--prune`, apart from `refs/tags` and `refs/remotes/origin`, so a tag that exists only locally is
never read and a tag deleted or moved on origin is seen as it is. A tag counts as a release only
when its commit is reachable from origin's default branch (`releases.py` judges the names).
Git runs through `checkout.Git`, isolated as there; the fetch is the one call in the transfer
profile (the operator's credential helper, ruling of 18.10.2026).
"""

from dataclasses import dataclass
from pathlib import Path

from hal.output import printable
from hal.stack import checkout

ORIGIN = "origin"
TAG_NAMESPACE = "refs/edge/releases/"
COMPOSE_FILE = "compose.yaml"
_REGULAR_FILE_MODES = {"100644", "100755"}
_SYMLINK_MODE = "120000"
_NAMED_CHANGES = 5


class CheckoutRefused(Exception):
    """The checkout cannot be deployed from as it stands; the message is one line."""


@dataclass(frozen=True)
class Tags:
    """The names of the release candidates as the last fetch left them."""

    mirrored: tuple[str, ...]
    on_branch: frozenset[str]


@dataclass(frozen=True)
class AppCheckout:
    git: checkout.Git
    url: str
    branch: str

    @property
    def _branch_reference(self) -> str:
        return f"refs/remotes/{ORIGIN}/{self.branch}"

    def prepare(self) -> None:
        """Make the checkout when `~/srv/<key>` is new or empty; else refuse unless it is a clean
        main worktree of this app's origin with HEAD detached or unborn."""
        tree = self.git.tree
        try:
            tree.mkdir(parents=True, exist_ok=True)
            marker = tree / ".git"
            if not marker.exists() and not marker.is_symlink():
                self._make(tree)
                return
        except OSError as error:
            raise CheckoutRefused(f"cannot be made ({error.strerror})") from error
        if not marker.is_dir() or marker.is_symlink():
            raise CheckoutRefused("is not a main worktree (its .git is not a directory)")
        self._refuse_foreign_origin()
        self._refuse_unusual_head()
        self._refuse_changes()

    def fetch(self) -> None:
        branch, mirror = self.branch, f"{TAG_NAMESPACE}v*"
        refspecs = [f"+refs/heads/{branch}:{self._branch_reference}", f"+refs/tags/v*:{mirror}"]
        fetch = ["fetch", "--quiet", "--no-tags", "--prune", "--no-recurse-submodules", ORIGIN]
        self.git.call([*fetch, *refspecs], profile=checkout.Profile.TRANSFER)

    def tags(self) -> Tags:
        listing = ["for-each-ref", "--format=%(refname) %(*objectname) %(objectname)"]
        every = self._tag_names([*listing, TAG_NAMESPACE])
        merged = self._tag_names([*listing, f"--merged={self._branch_reference}", TAG_NAMESPACE])
        return Tags(every, frozenset(merged))

    def commit_of(self, tag: str) -> str:
        """The full sha of the commit the mirrored `tag` names."""
        revision = f"{TAG_NAMESPACE}{tag}^{{commit}}"
        return _text(self.git.call(["rev-parse", "--verify", revision]).stdout).strip()

    def head(self) -> str | None:
        """The full sha HEAD names; None while the checkout is unborn."""
        if not self.git.has_commit():
            return None
        return _text(self.git.call(["rev-parse", "--verify", "HEAD^{commit}"]).stdout).strip()

    def file_at(self, sha: str, path: str) -> bytes | None:
        """The bytes of the regular file at `path` in the commit; None when the commit has no
        entry there. A symlink or any other entry is refused, never read as absent."""
        listed = _text(self.git.call(["ls-tree", sha, "--", path]).stdout).split()
        if not listed:
            return None
        if listed[0] not in _REGULAR_FILE_MODES or listed[1:2] != ["blob"]:
            kind = "a symlink" if listed[0] == _SYMLINK_MODE else "no regular file"
            raise CheckoutRefused(f"{path} at {sha} is {kind}")
        return self.git.call(["cat-file", "blob", f"{sha}:{path}"]).stdout

    def check_out(self, sha: str) -> None:
        """HEAD detached at the commit; an ignored file a path of it would overwrite refuses."""
        self.git.call(["checkout", "--quiet", "--detach", "--no-overwrite-ignore", sha])

    def _make(self, tree: Path) -> None:
        if any(tree.iterdir()):
            raise CheckoutRefused("is not empty and no git checkout")
        self.git.call(["init", "--quiet"])
        self.git.call(["remote", "add", ORIGIN, self.url])

    def _refuse_foreign_origin(self) -> None:
        answer = self.git.call(["config", "--get", f"remote.{ORIGIN}.url"], accepted=(0, 1))
        configured = _text(answer.stdout).strip()
        if configured != self.url:
            shown = checkout.without_credentials(printable(configured)) or "nothing"
            raise CheckoutRefused(f"has origin {shown}, not {self.url}")

    def _refuse_unusual_head(self) -> None:
        if (branch := self.git.branch()) is not None and self.git.has_commit():
            raise CheckoutRefused(f"is on branch {printable(branch)}, not detached")

    def _refuse_changes(self) -> None:
        if not (changed := self.git.changed_paths()):
            return
        named = ", ".join(changed[:_NAMED_CHANGES])
        more = f" and {len(changed) - _NAMED_CHANGES} more" if len(changed) > _NAMED_CHANGES else ""
        raise CheckoutRefused(f"has local changes, nothing reset: {named}{more}")

    def _tag_names(self, arguments: list[str]) -> tuple[str, ...]:
        names = []
        for line in _text(self.git.call(arguments).stdout).splitlines():
            fields = line.split(" ")
            if len(fields) != 3 or not fields[0].startswith(TAG_NAMESPACE):
                raise checkout.GitError(f"`git for-each-ref` answered '{printable(line)}'")
            names.append(fields[0].removeprefix(TAG_NAMESPACE))
        return tuple(names)


def _text(output: bytes) -> str:
    return output.decode("utf-8", "backslashreplace")
