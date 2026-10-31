"""The live checkout: `~/srv/hal` on `main` is the tree the live stack runs from (P6).

`hal apply` binds the compose project `edge` to the tree its code runs from, so it runs only
from the live checkout (#79 rule 1). Whether a tree is that checkout is read from paths alone,
without git: it is `$HOME/srv/hal` once both are resolved, and it is a main worktree, whose `.git`
is a directory where a linked worktree has a `.git` file.

Whether that checkout is a clean `main` is asked of git, through the one runner here (#95 rule 7).
It runs no hook, no fsmonitor and no maintenance, ignores every inherited `GIT_*` variable and
never prompts; its local profile reads no global or system configuration either, so no filter,
driver or helper of the operator's runs. The repository's own `.git/config` is same-user and still
read (D14). The local profile also reads no global excludes or attributes file, so "ignored" means
only the repository's own `.gitignore` (#98 rule 6).

The one step that reaches beyond the machine is the fetch of origin's `main` (#98): it runs in the
transfer profile, which keeps the global configuration for the operator's credential helper,
refuses a URL that carries a password and never prompts. From the fetch on, the fetched sha is
pinned: the comparison with HEAD is read against it. The fetch writes only objects, FETCH_HEAD and
`origin/main`; HEAD, the index and the tree stay as they are. Only `hal update` moves HEAD, with the
merge profile: the isolation of the local profile, no kill timeout, since a killed merge could leave
a half-updated tree. A credential is never printed: whatever stands before `@` in a URL is redacted.
"""

import contextlib
import os
import re
import signal
import subprocess
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum, StrEnum
from pathlib import Path

from hal.output import Stream, printable, write_line
from hal.output.command import Verb, command
from hal.stack import compose

LIVE_CHECKOUT = "~/srv/hal"
MAIN = "main"
DIRTY_TREE = "the live checkout has local changes, nothing changed"
PULL_REQUEST_ROUTE = f"a change reaches it through a pull request and `{command(Verb.UPDATE)}`"
_BRANCH_PREFIX = "refs/heads/"
_ISOLATION = (
    "-c", "core.hooksPath=/dev/null",
    "-c", "core.fsmonitor=false",
    "-c", "gc.auto=0",
    "-c", "maintenance.auto=false",
    "-c", "submodule.recurse=false",
)  # fmt: skip
_NEVER_PROMPT = {"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "", "SSH_ASKPASS": ""}
_ERROR_PREFIXES = ("fatal:", "error:")
_URL_CREDENTIALS = re.compile(r"(\b[a-z][a-z0-9+.-]*://)[^/\s]+@", re.IGNORECASE)
_REDACTED = r"\1<redacted>@"
_ORIGIN = "origin"
ORIGIN_MAIN = f"refs/remotes/{_ORIGIN}/{MAIN}"  # origin's `main` as the last fetch left it


class Profile(Enum):
    """LOCAL for every step but a fetch: no global or system configuration. TRANSFER for a fetch
    (S2.4b): the global configuration stays, for the operator's credential helper. MERGE for the
    fast-forward of `hal update`: LOCAL's isolation and no timeout."""

    LOCAL = "local"
    TRANSFER = "transfer"
    MERGE = "merge"


_PROFILE_ENVIRONMENT = {
    Profile.LOCAL: {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    Profile.TRANSFER: {},
    Profile.MERGE: {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
}
_PROFILE_ARGUMENTS = {
    Profile.LOCAL: (
        "-c", f"core.excludesFile={os.devnull}",
        "-c", f"core.attributesFile={os.devnull}",
    ),
    Profile.TRANSFER: ("-c", "transfer.credentialsInUrl=die"),
    Profile.MERGE: (
        "-c", f"core.excludesFile={os.devnull}",
        "-c", f"core.attributesFile={os.devnull}",
    ),
}  # fmt: skip
TIMEOUT_SECONDS: dict[Profile, float | None] = {
    Profile.LOCAL: 30,
    Profile.TRANSFER: 120,
    Profile.MERGE: None,
}


class Standing(Enum):
    """How HEAD stands to the fetched `main` (#98 rule 3)."""

    CURRENT = "current"
    BEHIND = "behind"
    AHEAD = "ahead"
    DIVERGED = "diverged"


class EntryKind(StrEnum):
    """What a tree entry at HEAD is: a blob (mode 100644 or 100755), a tree, a symlink or a
    submodule."""

    FILE = "file"
    DIRECTORY = "directory"
    SYMLINK = "symlink"
    SUBMODULE = "submodule"


_ENTRY_KINDS = {
    "100644": EntryKind.FILE,
    "100755": EntryKind.FILE,
    "040000": EntryKind.DIRECTORY,
    "120000": EntryKind.SYMLINK,
    "160000": EntryKind.SUBMODULE,
}


class GitError(Exception):
    """A git call did not run, failed or answered nonsense; the message is one line."""


Runner = Callable[[Path, Sequence[str], Profile], subprocess.CompletedProcess[bytes]]


def run_git(
    tree: Path, arguments: Sequence[str], profile: Profile
) -> subprocess.CompletedProcess[bytes]:
    """One git call on `tree`, isolated as rule 7 says; raises OSError or TimeoutExpired. A call
    that does not finish ends with git's whole process group killed: a fetch's transport helpers
    would otherwise outlive the cut and go on writing objects after edge has said nothing changed
    (#98 rule 2)."""
    command = ["git", "--no-pager", "-C", str(tree), *_ISOLATION, *_PROFILE_ARGUMENTS[profile],
               *arguments]  # fmt: skip
    return run_in_own_group(command, git_environment(os.environ, profile), TIMEOUT_SECONDS[profile])


def run_in_own_group(
    command: Sequence[str], environment: Mapping[str, str], timeout: float | None
) -> subprocess.CompletedProcess[bytes]:
    """`command` in its own process group with no stdin and its output captured; a call that does
    not finish within `timeout` (None: never), or an exception while it waits, ends with the whole
    group killed and every pipe read to its end before the exception goes on. Raises OSError when
    it cannot start."""
    with subprocess.Popen(
        command,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        close_fds=True,
        process_group=0,
    ) as child:
        try:
            stdout, stderr = child.communicate(timeout=timeout)
        except BaseException:
            _kill_group(child)
            raise
    return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)


def _kill_group(child: subprocess.Popen[bytes]) -> None:
    """Kill every process of `child`'s group and wait until the last has closed its pipes."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(child.pid, signal.SIGKILL)
    child.communicate()


def echoing(runner: Runner) -> Runner:
    """`runner` that first prints the git call it makes on stderr, never its environment."""

    def echo(
        tree: Path, arguments: Sequence[str], profile: Profile
    ) -> subprocess.CompletedProcess[bytes]:
        write_line(f"git {printable(' '.join(arguments))}", stream=Stream.STDERR)
        return runner(tree, arguments, profile)

    return echo


def git_environment(inherited: Mapping[str, str], profile: Profile) -> dict[str, str]:
    """`inherited` without any `GIT_*` variable, so none can point git elsewhere, and never
    prompting; the profile's own variables on top."""
    kept = {name: value for name, value in inherited.items() if not name.startswith("GIT_")}
    return {**kept, **_NEVER_PROMPT, **_PROFILE_ENVIRONMENT[profile]}


@dataclass(frozen=True)
class Origin:
    """origin's `main` as fetched, pinned by its full sha, against HEAD (#98 rules 1, 3)."""

    sha: str
    short: str
    head: str  # HEAD's short sha
    head_sha: str  # HEAD's full sha
    ahead: int  # commits HEAD has that the fetched main lacks
    behind: int  # commits the fetched main has that HEAD lacks

    @property
    def standing(self) -> Standing:
        return standing_of(self.ahead, self.behind)


def standing_of(ahead: int, behind: int) -> Standing:
    """How HEAD stands to a `main` it has `ahead` commits on and `behind` commits short of."""
    if ahead and behind:
        return Standing.DIVERGED
    if ahead:
        return Standing.AHEAD
    return Standing.BEHIND if behind else Standing.CURRENT


@dataclass(frozen=True)
class Commit:
    short: str
    subject: str


@dataclass(frozen=True)
class Git:
    """The questions `hal apply` and `hal update` ask of a checkout; only the fetch writes, and only
    to `.git`, and the one write to the tree is `hal update`'s merge."""

    tree: Path
    run: Runner = run_git

    def branch(self) -> str | None:
        """The branch HEAD names, or None when HEAD is detached."""
        result = self.call(["symbolic-ref", "--quiet", "HEAD"], accepted=(0, 1))
        if result.returncode == 1:
            return None
        reference = _text(result.stdout).strip()
        if not reference.startswith(_BRANCH_PREFIX):
            raise GitError(f"`git symbolic-ref` answered '{printable(reference)}'")
        return reference.removeprefix(_BRANCH_PREFIX)

    def short(self, revision: str = "HEAD") -> str:
        return _sha(
            _text(self.call(["rev-parse", "--short", revision]).stdout).strip(), "rev-parse"
        )

    def full(self, revision: str = "HEAD") -> str:
        return _sha(
            _text(self.call(["rev-parse", "--verify", f"{revision}^{{commit}}"]).stdout).strip(),
            "rev-parse",
        )

    def is_commit(self, sha: str) -> bool:
        """Whether `sha` names a commit this repository holds."""
        verified = ["rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"]
        return self.call(verified, accepted=(0, 1)).returncode == 0

    def is_ancestor(self, ancestor: str, descendant: str) -> bool:
        return self.call(["merge-base", "--is-ancestor", ancestor, descendant],
                         accepted=(0, 1)).returncode == 0  # fmt: skip

    def commits_to(self, sha: str) -> list[Commit]:
        """The commits `sha` has that HEAD lacks, newest first."""
        listing = ["log", "-z", "--no-show-signature", "--format=%h%x09%s", f"HEAD..{sha}"]
        records = _text(self.call(listing).stdout).split("\0")
        return [Commit(*record.partition("\t")[::2]) for record in records if record]

    def files_changed_to(self, sha: str) -> list[str]:
        """The paths that differ between HEAD and `sha`, in git's order."""
        diff = ["diff", "--name-only", "-z", "--no-renames", "--no-ext-diff", "HEAD", sha]
        return [os.fsdecode(path) for path in self.call(diff).stdout.split(b"\0") if path]

    def merge_fast_forward(self, sha: str) -> None:
        """Move HEAD, the index and the tree to the commit `sha`, which must be a fast-forward. It
        overwrites no ignored file, stashes nothing and runs no hook."""
        merge = ["merge", "--ff-only", "--no-overwrite-ignore", "--no-autostash",
                 "--no-verify-signatures", sha]  # fmt: skip
        self.call(merge, profile=Profile.MERGE)

    def has_commit(self) -> bool:
        """Whether HEAD names a commit; a branch without one is unborn."""
        verified = ["rev-parse", "--verify", "--quiet", "HEAD^{commit}"]
        return self.call(verified, accepted=(0, 1)).returncode == 0

    def has_fetched_main(self) -> bool:
        """Whether origin's `main` was ever fetched, so `ORIGIN_MAIN` names a commit."""
        verified = ["rev-parse", "--verify", "--quiet", f"{ORIGIN_MAIN}^{{commit}}"]
        return self.call(verified, accepted=(0, 1)).returncode == 0

    def changed_paths(self) -> list[str]:
        """Every path that differs from HEAD: modified, staged or untracked, not ignored. The
        index is never refreshed, so the call writes nothing (`--no-optional-locks`)."""
        status = ["--no-optional-locks", "status", "--porcelain=v1", "-z", "--untracked-files=all"]
        return _porcelain_paths(self.call(status).stdout)

    def entry_kinds(self, paths: Collection[str]) -> dict[str, EntryKind]:
        """The tree entry at HEAD of each requested path; one HEAD does not track is absent. `-t`
        keeps the entry of a tree the listing recurses into, so a path that is the parent of
        another keeps its own."""
        if not paths:
            return {}
        listing = ["ls-tree", "-r", "-t", "-z", "HEAD", "--", *paths]
        return _entry_kinds(self.call(listing).stdout, set(paths))

    def fetch_main(self) -> str:
        """Fetch origin's `main` through the operator's credential helper and pin it: the full sha
        FETCH_HEAD now names (#98 rule 1). Writes only objects, FETCH_HEAD and `origin/main`."""
        fetch = ["fetch", "--no-tags", "--no-recurse-submodules", "--write-fetch-head"]
        self.call([*fetch, _ORIGIN, MAIN], profile=Profile.TRANSFER)
        pinned = self.call(["rev-parse", "--verify", "FETCH_HEAD^{commit}"])
        return _sha(_text(pinned.stdout).strip(), "rev-parse")

    def divergence(self, sha: str) -> tuple[int, int]:
        """The commits HEAD has that `sha` lacks, and those `sha` has that HEAD lacks."""
        answer = _text(self.call(["rev-list", "--left-right", "--count", f"HEAD...{sha}"]).stdout)
        counts = answer.split()
        if len(counts) != 2 or not all(count.isdigit() for count in counts):
            raise GitError(f"`git rev-list` answered '{printable(answer.strip())}'")
        return int(counts[0]), int(counts[1])

    def call(
        self,
        arguments: Sequence[str],
        accepted: tuple[int, ...] = (0,),
        profile: Profile = Profile.LOCAL,
    ) -> subprocess.CompletedProcess[bytes]:
        """One git call on the tree; any exit but `accepted` and every failure to run it is a
        GitError with git's last error line, credentials redacted."""
        verb = next(argument for argument in arguments if not argument.startswith("-"))
        try:
            result = self.run(self.tree, arguments, profile)
        except subprocess.TimeoutExpired as error:
            raise GitError(f"`git {verb}` took longer than {error.timeout}s") from error
        except OSError as error:
            raise GitError(f"cannot run git ({error.strerror})") from error
        if result.returncode not in accepted:
            last = _error_line(_text(result.stderr) + _text(result.stdout))
            raise GitError(f"`git {verb}` exited {result.returncode}: {last}")
        return result


def fetch_origin(git: Git) -> Origin:
    """origin's `main`, fetched and pinned, and how HEAD stands to it; raises GitError."""
    sha = git.fetch_main()
    ahead, behind = git.divergence(sha)
    return Origin(sha, git.short(sha), git.short(), git.full(), ahead, behind)


def without_credentials(text: str) -> str:
    """`text` with the whole userinfo of a `scheme://` URL redacted, every character up to the last
    `@` before the path, punctuation included: a user name may be a token as much as a password
    is (R3)."""
    return _URL_CREDENTIALS.sub(_REDACTED, text)


def _error_line(output: str) -> str:
    """git's last error line, else its last line; one line, credentials redacted (#98 rule 2)."""
    errors = [line for line in output.splitlines() if line.startswith(_ERROR_PREFIXES)]
    return without_credentials(compose.last_line("\n".join(errors) or output))


def _sha(answer: str, verb: str) -> str:
    if not answer or not all(digit in "0123456789abcdef" for digit in answer):
        raise GitError(f"`git {verb}` answered '{printable(answer)}'")
    return answer


def _text(output: bytes) -> str:
    return output.decode("utf-8", "backslashreplace")


def _entry_kinds(output: bytes, wanted: set[str]) -> dict[str, EntryKind]:
    """The kinds of the wanted paths in `ls-tree -z` output, `<mode> <type> <object>TAB<path>`."""
    if not output:
        return {}
    if not output.endswith(b"\0"):
        raise GitError("`git ls-tree` answered no listing")
    kinds = {}
    for entry in output[:-1].split(b"\0"):
        meta, tab, name = entry.partition(b"\t")
        fields = meta.split(b" ")
        if not tab or len(fields) != 3:
            raise GitError(f"`git ls-tree` answered '{printable(_text(entry))}'")
        mode = _text(fields[0])
        if (path := os.fsdecode(name)) in wanted:
            if mode not in _ENTRY_KINDS:
                raise GitError(f"`git ls-tree` answered mode '{printable(mode)}'")
            kinds[path] = _ENTRY_KINDS[mode]
    return kinds


def _porcelain_paths(output: bytes) -> list[str]:
    """The paths of `status --porcelain=v1 -z`, decoded and escaped for one line each; a rename or
    copy names its source too."""
    if not output:
        return []
    if not output.endswith(b"\0"):
        raise GitError("`git status` answered no porcelain")
    entries = iter(output[:-1].split(b"\0"))
    paths = []
    for entry in entries:
        if len(entry) < 4 or entry[2:3] != b" ":
            raise GitError(f"`git status` answered '{printable(_text(entry))}'")
        paths.append(entry[3:])
        if {entry[0], entry[1]} & set(b"RC"):
            if (source := next(entries, None)) is None:
                raise GitError("`git status` named a rename without its source")
            paths.append(source)
    return [printable(_text(path)) for path in paths]


def live_checkout(home: Path) -> Path:
    return home / LIVE_CHECKOUT.removeprefix("~/")


def not_live_checkout(tree: Path, home: Path) -> str | None:
    """None when `tree` is the live checkout, else why not (#95 rule 2)."""
    if tree.resolve() != live_checkout(home).resolve():
        return f"this is {printable(str(tree))}"
    if (tree / ".git").is_file():
        return "a linked worktree, not the main checkout"
    if not (tree / ".git").is_dir():
        return "no git checkout"
    return None


def not_live_checkout_line(tree: Path, home: Path) -> str | None:
    """The refusal line for a `tree` that is not the live checkout; None when it is."""
    if reason := not_live_checkout(tree, home):
        return f"runs only from the live checkout {LIVE_CHECKOUT} ({reason})"
    return None


def not_on_main(git: Git) -> str | None:
    """None when HEAD is a `main` with a commit, else what it is (#95 rule 5); raises GitError."""
    branch = git.branch()
    if branch is None:
        return f"HEAD is detached at {git.short()}"
    if branch != MAIN:
        return f"this is branch {printable(branch)}"
    if not git.has_commit():
        return f"{MAIN} has no commit yet"
    return None


@dataclass(frozen=True)
class Refusal:
    """Why a checkout is not a born `main` with nothing changed; `paths` are the changed paths of
    a dirty tree, in git's order."""

    message: str
    paths: tuple[str, ...] = ()


def not_clean_main(git: Git) -> Refusal | None:
    """Why `git` is not a born `main` with nothing changed; None when it is (#95 rules 5, 6). A
    git that fails is a refusal too, so the caller refuses rather than guesses."""
    try:
        if reason := not_on_main(git):
            return Refusal(f"runs only on {MAIN} ({reason})")
        changed = git.changed_paths()
    except GitError as error:
        return Refusal(f"cannot read the live checkout, {error}")
    if not changed:
        return None
    return Refusal(DIRTY_TREE, tuple(changed))
