"""The checkout of an app, `~/srv/<key>`, against real git under `tmp_path` (#255 A4, A6, A13-A17).

origin is a bare repository reached through `url.<bare>.insteadOf` in the test's own global git
config, as the probe reaches it; nothing leaves `tmp_path`."""

import subprocess
from pathlib import Path

import pytest
import support.throwaway_home as throwaway_home
from support.app_support import (
    COMPOSE,
    FLEET,
    KEY,
    URL,
    Origin,
    ScriptedDocker,
    origin_at,
    runtime_of,
)
from support.git_support import plain_git
from support.stack_apps import EDGE_FLEET

from hal.stack import apps, checkout, deploy_checkout, switches

home = throwaway_home.home


@pytest.fixture
def origin(tmp_path: Path, home: Path) -> Origin:
    return origin_at(tmp_path, home)


@pytest.fixture
def app(home: Path) -> deploy_checkout.AppCheckout:
    return deploy_checkout.AppCheckout(checkout.Git(home / "srv" / "hopin"), URL, "master")


@pytest.fixture
def fetched(origin: Origin, app: deploy_checkout.AppCheckout) -> deploy_checkout.AppCheckout:
    app.prepare()
    app.fetch()
    return app


def test_a_new_checkout_is_made_with_the_apps_origin_and_nothing_else(app, origin):
    app.prepare()

    tree = app.git.tree
    assert plain_git(tree, "config", "--get", "remote.origin.url").stdout.strip() == URL
    assert sorted(path.name for path in tree.iterdir()) == [".git"]
    assert app.head() is None


def test_the_fetch_mirrors_the_release_tags_and_writes_only_dot_git(origin, app):
    sha = origin.commit({"a": "1"})
    origin.push("master")
    origin.tag("v2026.10.22.1", annotated=True)
    origin.tag("v2026.10.22.2")
    app.prepare()

    app.fetch()

    assert app.tags().mirrored == ("v2026.10.22.1", "v2026.10.22.2")
    assert app.tags().on_branch == {"v2026.10.22.1", "v2026.10.22.2"}
    assert app.commit_of("v2026.10.22.1") == sha == app.commit_of("v2026.10.22.2")
    assert sorted(path.name for path in app.git.tree.iterdir()) == [".git"]


def test_a_tag_on_a_side_branch_is_mirrored_but_not_on_the_default_branch(origin, app):
    origin.commit({"a": "1"})
    origin.push("master")
    origin.tag("v2026.10.22.2")
    plain_git(origin.work, "switch", "--quiet", "-c", "side")
    origin.commit({"side": "1"})
    origin.tag("v2026.10.22.9")
    app.prepare()

    app.fetch()

    tags = app.tags()
    assert tags.mirrored == ("v2026.10.22.2", "v2026.10.22.9")
    assert tags.on_branch == {"v2026.10.22.2"}


def test_a_local_tag_is_never_read_and_a_tag_moved_on_origin_is_seen_as_it_is(origin, fetched):
    first = origin.commit({"a": "1"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    plain_git(fetched.git.tree, "tag", "v2026.10.22.7", first)
    plain_git(fetched.git.tree, "tag", "v2026.10.22.1", first)
    moved = origin.commit({"a": "2"})
    origin.push("master")
    origin.tag("v2026.10.22.1")

    fetched.fetch()

    assert fetched.tags().mirrored == ("v2026.10.22.1",)
    assert fetched.commit_of("v2026.10.22.1") == moved


def test_a_tag_deleted_on_origin_leaves_the_mirror(origin, fetched):
    origin.commit({"a": "1"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    plain_git(origin.bare, "tag", "--delete", "v2026.10.22.1")

    fetched.fetch()

    assert fetched.tags().mirrored == ()


def test_an_origin_that_cannot_be_reached_is_a_git_error_with_gits_last_line(fetched, origin):
    (Path.home() / ".gitconfig").write_text(f'[url "file:///nowhere.git"]\n\tinsteadOf = {URL}\n')

    with pytest.raises(checkout.GitError, match=r"`git fetch` exited 128: fatal:"):
        fetched.fetch()


def test_the_checkout_detaches_at_the_tag_and_head_names_it(origin, fetched):
    sha = origin.commit({"a": "1"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()

    fetched.check_out(fetched.commit_of("v2026.10.22.1"))

    assert fetched.head() == sha
    assert fetched.git.branch() is None
    assert (fetched.git.tree / "a").read_text() == "1"


@pytest.mark.parametrize("tracked", ["config.local", "local/config"])
def test_an_ignored_file_the_new_tag_tracks_refuses_the_checkout_and_stays(
    origin, fetched, tracked
):
    first = origin.commit({".gitignore": "config.local\nlocal/\n"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    second = origin.commit({tracked: "from the tag"})
    origin.push("master")
    origin.tag("v2026.10.22.2")
    fetched.fetch()
    fetched.check_out(fetched.commit_of("v2026.10.22.1"))
    kept = fetched.git.tree / tracked
    kept.parent.mkdir(exist_ok=True)
    kept.write_text("the operator's own")

    with pytest.raises(checkout.GitError, match="would be overwritten"):
        fetched.check_out(second)

    assert kept.read_text() == "the operator's own"
    assert fetched.head() == first


def test_an_ignored_file_that_no_tag_tracks_is_allowed_and_kept(origin, fetched):
    origin.commit({".gitignore": ".env\n"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    fetched.check_out(fetched.commit_of("v2026.10.22.1"))
    (fetched.git.tree / ".env").write_text("SECRET=kept")

    fetched.prepare()

    assert (fetched.git.tree / ".env").read_text() == "SECRET=kept"


@pytest.mark.parametrize(
    ("arrange", "named"),
    [
        (lambda tree: (tree / "compose.yaml").write_text("edited"), "compose.yaml"),
        (lambda tree: (tree / "stray").write_text("new"), "stray"),
    ],
)
def test_a_tracked_edit_or_an_untracked_file_cannot_be_planned_and_nothing_is_reset(
    origin, fetched, arrange, named
):
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    fetched.check_out(fetched.commit_of("v2026.10.22.1"))
    arrange(fetched.git.tree)

    with pytest.raises(deploy_checkout.CheckoutRefused, match=f"local changes.*{named}"):
        fetched.prepare()

    assert (fetched.git.tree / named).read_text() in {"edited", "new"}


def test_an_origin_url_other_than_the_apps_repository_cannot_be_planned(fetched):
    plain_git(fetched.git.tree, "remote", "set-url", "origin", "https://token@example.org/x.git")

    with pytest.raises(deploy_checkout.CheckoutRefused) as refused:
        fetched.prepare()

    assert "has origin https://<redacted>@example.org/x.git, not" in str(refused.value)


def test_a_head_on_a_born_branch_cannot_be_planned(origin, fetched):
    plain_git(fetched.git.tree, "fetch", "--quiet", "origin", "master")
    plain_git(fetched.git.tree, "checkout", "--quiet", "-B", "master", "FETCH_HEAD")

    with pytest.raises(deploy_checkout.CheckoutRefused, match="is on branch master, not detached"):
        fetched.prepare()


def test_a_directory_that_is_no_checkout_cannot_be_planned(app):
    app.git.tree.mkdir(parents=True)
    (app.git.tree / "notes").write_text("mine")

    with pytest.raises(deploy_checkout.CheckoutRefused, match="no git checkout"):
        app.prepare()


def test_a_regular_file_where_the_checkout_belongs_is_refused_not_raised(app):
    app.git.tree.parent.mkdir(parents=True, exist_ok=True)
    app.git.tree.write_text("mine")

    with pytest.raises(deploy_checkout.CheckoutRefused, match="cannot be made"):
        app.prepare()


def test_a_linked_worktree_is_no_main_worktree(app):
    app.git.tree.mkdir(parents=True)
    (app.git.tree / ".git").write_text("gitdir: /elsewhere\n")

    with pytest.raises(deploy_checkout.CheckoutRefused, match="not a main worktree"):
        app.prepare()


def test_a_file_is_read_at_the_commit_not_from_the_tree(origin, fetched):
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    sha = fetched.commit_of("v2026.10.22.1")
    fetched.check_out(sha)
    (fetched.git.tree / "compose.yaml").write_text("edited after the checkout")

    assert fetched.file_at(sha, "compose.yaml") == COMPOSE.encode()


def test_a_path_the_commit_does_not_have_is_absent(origin, fetched):
    origin.commit({"legal/nutzungsbedingungen.html": "x"})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()

    assert fetched.file_at(fetched.commit_of("v2026.10.22.1"), "legal/datenschutz.html") is None


def a_symlink(work: Path) -> None:
    (work / "legal").mkdir()
    (work / "legal/datenschutz.html").symlink_to("../compose.yaml")


def a_directory(work: Path) -> None:
    (work / "legal/datenschutz.html").mkdir(parents=True)
    (work / "legal/datenschutz.html/inside").write_text("x")


@pytest.mark.parametrize(("make", "kind"), [(a_symlink, "a symlink"), (a_directory, "no regular")])
def test_an_entry_that_is_no_regular_file_is_refused_not_read_as_absent(
    origin, fetched, make, kind
):
    make(origin.work)
    origin.commit({})
    origin.push("master")
    origin.tag("v2026.10.22.1")
    fetched.fetch()
    sha = fetched.commit_of("v2026.10.22.1")

    with pytest.raises(
        deploy_checkout.CheckoutRefused, match=f"legal/datenschutz.html at {sha} is {kind}"
    ):
        fetched.file_at(sha, "legal/datenschutz.html")


def test_a_compose_file_that_is_no_utf8_refuses_the_plan_of_its_app(origin, home, tmp_path):
    (origin.work / "compose.yaml").write_bytes(b"services: \xff\xfe\n")
    origin.release("v2026.10.22.1")
    repository, state = tmp_path / "edge", tmp_path / "state"
    repository.mkdir()
    (repository / "fleet.yaml").write_text(FLEET)
    runtime = runtime_of(home, state, ScriptedDocker(state, home / "srv" / KEY))

    with pytest.raises(apps.AppError, match=r"compose\.yaml is not UTF-8"):
        apps.plan_apps(repository, EDGE_FLEET, runtime, switches.Switches(state))


def test_a_tag_listing_that_git_does_not_give_in_three_fields_is_an_error(app):
    def odd_listing(_tree, _arguments, _profile):
        return subprocess.CompletedProcess([], 0, b"refs/edge/releases/v1 only-two\n", b"")

    odd = deploy_checkout.AppCheckout(checkout.Git(app.git.tree, odd_listing), URL, "master")

    with pytest.raises(checkout.GitError, match="`git for-each-ref` answered"):
        odd.tags()
