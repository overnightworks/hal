"""speech-runtime's release as hal clones it in H's copy: a bare origin in the scratch.

The origin is cloned from speech-runtime's public repository, with every branch and tag. Its newest
dated tag (hal's grammar) is re-pointed at one commit on top of it that rewrites only the
compose.yaml lines `name: hal_speech_*` to the copy's `<project>_speech_*`, and that commit is the
origin's default branch, so hal plans that tag and skips the others. The scratch HOME's
`.gitconfig` sends hal's clone URL of the probe's app key to this origin; nothing of the public
repository changes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import edge_copy
from edge_copy import expect

from hal.stack import catalog, checkout, deploy_checkout, releases

SPEECH_APP = "speech-runtime"  # fleet.yaml's key of the speech service: its repository's name
ORIGIN = "speech-origin.git"
WORK = "speech-work"
SPEECH_NAME_LINE = re.compile(
    rf"^(?P<head>\s+name: ){re.escape(edge_copy.LIVE_NETWORK_PREFIX)}(?P<rest>speech_\w+)\s*$",
    re.M,
)


@dataclass(frozen=True)
class Release:
    tag: str  # the newest dated tag, re-pointed in the scratch origin
    compose: str  # its compose.yaml as hal checks it out
    skipped: tuple[str, ...]  # every other tag of the origin


def app_entry(fleet_text: str, key: str, *, enabled: bool) -> str:
    """fleet.yaml's lines of the speech app under `key`, with `enabled` as its switch: the
    shipped entry, re-keyed, so its shape is read from its owner."""
    lines = fleet_text.splitlines(keepends=True)
    head = f"  {SPEECH_APP}:\n"
    expect(lines.count(head) == 1, f"fleet.yaml holds {head.strip()!r} {lines.count(head)} times")
    start = lines.index(head)
    end = start + 1
    while end < len(lines) and lines[end].startswith("   "):  # the entry's deeper lines
        end += 1
    entry = "".join([f"  {key}:\n", *lines[start + 1 : end]])
    expect(entry.count("enabled: true") == 1, f"the shipped {SPEECH_APP} entry is not on once")
    return entry.replace("enabled: true", f"enabled: {str(enabled).lower()}")


def clone_url(fleet_text: str, key: str) -> str:
    """The URL hal clones the app `key` from (apps.py), in fleet.yaml's GitHub organisation."""
    organisation = catalog.github_org(catalog.parse(fleet_text.encode()))
    return f"https://github.com/{organisation}/{key}.git"


def tags_of(tree: Path) -> list[str]:
    listed = checkout.run_git(tree, ("tag", "--list"), checkout.Profile.LOCAL)
    expect(listed.returncode == 0, "git tag --list failed in the speech origin")
    return listed.stdout.decode().split()


def build_origin(scratch: Path, home: Path, fleet_text: str, key: str, project: str) -> Release:
    """The scratch origin of the app `key`, its newest dated tag moved onto the copy's networks,
    reached through the scratch HOME's `.gitconfig`; the release hal will plan."""
    origin, work = scratch / ORIGIN, scratch / WORK
    public = clone_url(fleet_text, SPEECH_APP)
    edge_copy.git(scratch, "clone", "--quiet", "--bare", public, str(origin))
    edge_copy.git(scratch, "clone", "--quiet", str(origin), str(work))
    for name, value in edge_copy.PROBE_IDENTITY.items():
        edge_copy.git(work, "config", name, value)
    tags = tags_of(work)
    newest = max(filter(None, map(releases.parse, tags)), default=None)
    expect(newest is not None, f"{public} has no dated tag: {tags}")
    tag = newest.tag
    edge_copy.git(work, "switch", "--quiet", "--detach", tag)
    file = work / deploy_checkout.COMPOSE_FILE
    moved, count = SPEECH_NAME_LINE.subn(rf"\g<head>{project}_\g<rest>", file.read_text())
    expect(count > 0, f"{SPEECH_APP}'s compose.yaml at {tag} names no hal_speech_* network")
    file.write_text(moved)
    edge_copy.git(work, "commit", "--quiet", "--all", "--message", f"probe: {tag} on {project}")
    edge_copy.git(work, "tag", "--force", tag)
    shipped = catalog.parse(fleet_text.encode())["services"][SPEECH_APP]
    branch = f"refs/heads/{shipped['repo']['default_branch']}"
    edge_copy.git(
        work, "push", "--quiet", "--force", "origin", f"HEAD:{branch}", f"refs/tags/{tag}"
    )
    with (home / ".gitconfig").open("a") as config:
        config.write(f'[url "{origin.as_uri()}"]\n\tinsteadOf = {clone_url(fleet_text, key)}\n')
    return Release(tag, moved, tuple(sorted(set(tags) - {tag})))
