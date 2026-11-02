from __future__ import annotations

import os
import select
import shutil
import signal
import stat
import subprocess
import sys
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path, PurePosixPath

import pytest
from support.workstation_secrets_support import never_run, run_wizard
from support.workstation_support import FAKE_SECRET_VALUE, TEST_MANIFEST, UNEXPECTED_ERROR_PREFIX, FakeProbe, plant_secrets, run_hal_secrets, run_report_command, symlinked_folder_fix
from support.workstation_secrets_report import cells_of, findings_of, report_of


from hal.workstation import secrets_view
from hal.workstation.secrets_setup import Boundaries, Terminal, WalkEnd
from hal.workstation.secrets_view import ManifestError, load_manifest
from hal.workstation.layout import Layout

NOW = datetime(2026, 10, 15, 9, 0)
DECLARED_MODE_ENTRY = (
    '[[secret]]\nname = "step-ca/password"\nkind = "token"\npaths = ["~/.secrets/step-ca/password"]\nread_by = []\nrecreate = "r"\n'
    'loosest_mode = 0o644\nloosest_mode_reason = "uid 1000 reads it"\n'
)
WILDCARD_ENTRY = (
    '\n[[secret]]\nname = "step-ca/any"\nkind = "token"\npaths = ["~/.secrets/step-ca/*"]\nread_by = []\nrecreate = "r"\n'
    'loosest_mode = 0o644\nloosest_mode_reason = "a container reads the folder"\n'
)
RESTIC_RECREATE = (
    "Restore it from your password manager. "
    "Never recreate it while backups exist under ~/backups/restic: a new password makes them unreadable."
)
RETIRED_ENTRY = """
[[secret]]
name = "github/token"
kind = "token"
paths = ["~/.secrets/github/token"]
read_by = []
recreate = "nicht neu anlegen"
retired_on = 2026-10-14
revoke_url = "https://github.com/settings/tokens"
"""


def rows_of(output: str) -> dict[str, list[str]]:
    """The status table, keyed by entry name."""
    return {cells[0]: cells for cells in cells_of(output.split("\n\n")[1])}


def finding_subjects(output: str) -> set[str]:
    """The subject of every finding, whatever its rule."""
    table = output.split("## Findings\n\n", 1)[1].split("\n\n")[0] if "## Findings" in output else ""
    return {cells[1] for cells in cells_of(table)}


def test_a_complete_home_lists_every_entry_and_writes_only_its_report(clean_home: Path, probe: FakeProbe, capsys) -> None:
    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    rows = rows_of(output)
    assert code == 0
    assert set(rows) == {"gitlab", "cloudflared", "gh"}
    assert ({name: row[2] for name, row in rows.items()}, rows["gitlab"][1]) == (dict.fromkeys(rows, "present"), "token")
    assert {name: row[3] for name, row in rows.items()} == {"gitlab": "not checked", "cloudflared": "not checked"} | {
        "gh": "checked: valid"
    }
    assert all(row[4] == "expiry unknown" for row in rows.values())
    assert "No findings." in output
    assert probe.calls == [("gh", "auth", "status")]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_no_secret_value_reaches_the_output_or_the_report_and_no_secret_file_is_opened(clean_home: Path, probe: FakeProbe, capsys) -> None:
    unreadable = [path for path in Layout(clean_home).secrets_dir.rglob("*") if path.is_file()]
    for path in unreadable:
        path.chmod(0)  # opening one would now fail; stat still works

    code = run_hal_secrets(clean_home, probe, now=NOW)

    captured = capsys.readouterr()
    output = captured.out + captured.err + report_of(clean_home)
    assert code == 0
    assert not any(part in output for part in FAKE_SECRET_VALUE.split())
    assert all(stat.S_IMODE(path.stat().st_mode) == 0 for path in unreadable)


def symlink_the_report_file(layout: Layout, report_file: Path) -> None:
    report_file.parent.mkdir(parents=True)
    report_file.symlink_to(layout.secrets_dir / "gitlab")


def hard_link_the_report_file(layout: Layout, report_file: Path) -> None:
    report_file.parent.mkdir(parents=True)
    os.link(layout.secrets_dir / "gitlab", report_file)


def symlink_the_state_directory(layout: Layout, report_file: Path) -> None:
    report_file.parent.parent.mkdir(parents=True)
    report_file.parent.symlink_to(layout.secrets_dir)


def symlink_an_ancestor_of_the_state_directory(layout: Layout, report_file: Path) -> None:
    local = report_file.parent.parent.parent
    local.mkdir()
    (local / "state").symlink_to(layout.secrets_dir)


def secret_contents(layout: Layout) -> dict[Path, str]:
    return {path: path.read_text() for path in layout.secrets_dir.rglob("*") if path.is_file()}


def state_file_of(layout: Layout, command: str) -> Path:
    return {"secrets": layout.secrets_report_file, "check": layout.check_report_file}[command]


@pytest.mark.parametrize("plant_link", [symlink_the_report_file, hard_link_the_report_file])
@pytest.mark.parametrize("command", ["secrets", "check"])
def test_a_linked_report_file_is_replaced_and_never_written_through_into_the_secrets(
    clean_home: Path, probe: FakeProbe, runner, command: str, plant_link: Callable[[Layout, Path], None]
) -> None:
    layout = Layout(clean_home)
    report_file = state_file_of(layout, command)
    secrets_before = secret_contents(layout)
    plant_link(layout, report_file)

    run_report_command(command, clean_home, runner, probe)

    assert not report_file.is_symlink()
    assert report_file.stat().st_nlink == 1
    assert secret_contents(layout) == secrets_before


@pytest.mark.parametrize("plant_link", [symlink_the_state_directory, symlink_an_ancestor_of_the_state_directory])
@pytest.mark.parametrize("command", ["secrets", "check"])
def test_a_symlink_on_the_way_to_the_state_directory_is_refused_and_never_carries_the_report_into_the_secrets(
    clean_home: Path, probe: FakeProbe, runner, capsys, command: str, plant_link: Callable[[Layout, Path], None]
) -> None:
    layout = Layout(clean_home)
    secrets_before = secret_contents(layout)
    plant_link(layout, state_file_of(layout, command))

    code = run_report_command(command, clean_home, runner, probe)

    assert code == 3
    assert capsys.readouterr().err.startswith(UNEXPECTED_ERROR_PREFIX)
    assert secret_contents(layout) == secrets_before


def remove_gitlab(home: Path) -> None:
    (home / ".secrets" / "gitlab").unlink()


def remove_the_wildcard_match(home: Path) -> None:
    (home / ".secrets" / "cloudflared" / "fake.json").unlink()


def remove_every_secret(home: Path) -> None:
    shutil.rmtree(home / ".secrets")


def put_a_file_where_a_directory_belongs(home: Path) -> None:
    shutil.rmtree(home / ".secrets" / "cloudflared")
    (home / ".secrets" / "cloudflared").write_text("not a directory")
    (home / ".secrets" / "cloudflared").chmod(0o600)


@pytest.mark.parametrize(
    ("damage", "expected"),
    [
        (remove_gitlab, {"gitlab": "missing", "cloudflared": "present"}),
        (remove_the_wildcard_match, {"gitlab": "present", "cloudflared": "missing"}),
        (remove_every_secret, {"gitlab": "missing", "cloudflared": "missing"}),
        (put_a_file_where_a_directory_belongs, {"gitlab": "present", "cloudflared": "unknown"}),
    ],
    ids=["one file missing", "no file matches the wildcard", "no ~/.secrets at all", "the filesystem cannot say"],
)
def test_each_entry_shows_present_missing_or_unknown_and_every_gap_is_a_finding(
    clean_home: Path, probe: FakeProbe, capsys, damage: Callable[[Path], None], expected: dict[str, str]
) -> None:
    damage(clean_home)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    rows = rows_of(output)
    assert code == 1
    assert {name: rows[name][2] for name in expected} == expected
    gaps = {name for name, presence in expected.items() if presence != "present"}
    assert set(findings_of(output, "missing")) | set(findings_of(output, "presence-unknown")) == gaps


@pytest.mark.parametrize(
    ("exit_code", "shown", "finding"),
    [
        (0, "checked: valid", None),
        (1, "checked: invalid", "verification-failed"),
        (None, "check not possible", "verification-unreachable"),
    ],
    ids=["the probe passes", "the probe fails", "the probe hangs or is missing"],
)
def test_only_github_is_verified_and_its_outcome_is_shown(
    clean_home: Path, probe: FakeProbe, capsys, exit_code: int | None, shown: str, finding: str | None
) -> None:
    probe.code = exit_code

    run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    assert rows_of(output)["gh"][3] == shown
    verification_findings = {rule: findings_of(output, rule) for rule in ("verification-failed", "verification-unreachable")}
    assert {rule for rule, found in verification_findings.items() if "gh" in found} == ({finding} if finding else set())


def test_a_file_no_entry_names_is_reported_as_unknown_and_left_alone(clean_home: Path, probe: FakeProbe, capsys) -> None:
    stray = clean_home / ".secrets" / "old-backup.env"
    stray.write_text(FAKE_SECRET_VALUE)
    stray.chmod(0o600)
    (clean_home / ".secrets" / "latest").symlink_to(stray)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    assert code == 1
    unknown = findings_of(output, "unknown-file")
    assert list(unknown) == ["~/.secrets/latest", "~/.secrets/old-backup.env"]
    assert unknown["~/.secrets/latest"] == ["-", "add ~/.secrets/latest to the manifest or delete it"]
    assert not findings_of(output, "loose-mode")
    assert stray.read_text() == FAKE_SECRET_VALUE


def test_a_newline_or_pipe_in_a_file_name_keeps_the_table_intact(clean_home: Path, probe: FakeProbe, capsys) -> None:
    stray = clean_home / ".secrets" / "weird\nna|me.txt"
    stray.write_text(FAKE_SECRET_VALUE)
    stray.chmod(0o600)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    assert code == 1
    assert list(findings_of(output, "unknown-file")) == ["~/.secrets/weird\\nna\\|me.txt"]


def test_loose_modes_are_reported_and_never_changed(clean_home: Path, probe: FakeProbe, capsys) -> None:
    token, directory = clean_home / ".secrets" / "gitlab", clean_home / ".secrets" / "cloudflared"
    token.chmod(0o644)
    directory.chmod(0o755)
    (clean_home / ".secrets" / "cloudflared" / "cert.pem").chmod(0o400)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    loose = findings_of(report_of(clean_home), "loose-mode")
    assert code == 1
    assert loose == {
        "~/.secrets/gitlab": ["has mode 644; at most 600 allowed", "`chmod 600 ~/.secrets/gitlab`"],
        "~/.secrets/cloudflared": ["has mode 755; at most 700 allowed", "`chmod 700 ~/.secrets/cloudflared`"],
    }
    assert (stat.S_IMODE(token.stat().st_mode), stat.S_IMODE(directory.stat().st_mode)) == (0o644, 0o755)


@pytest.mark.parametrize(
    ("manifest", "file_mode", "loose_findings"),
    [
        (DECLARED_MODE_ENTRY, 0o644, {}),
        (
            DECLARED_MODE_ENTRY,
            0o666,
            {"~/.secrets/step-ca/password": ["has mode 666; at most 644 allowed (uid 1000 reads it)", "`chmod 644 ~/.secrets/step-ca/password`"]},
        ),
        (
            DECLARED_MODE_ENTRY.split("loosest_mode")[0],
            0o644,
            {"~/.secrets/step-ca/password": ["has mode 644; at most 600 allowed", "`chmod 600 ~/.secrets/step-ca/password`"]},
        ),
        (DECLARED_MODE_ENTRY + WILDCARD_ENTRY, 0o644, {}),
        (
            DECLARED_MODE_ENTRY.split("loosest_mode")[0] + WILDCARD_ENTRY,
            0o644,
            {"~/.secrets/step-ca/password": ["has mode 644; at most 600 allowed", "`chmod 600 ~/.secrets/step-ca/password`"]},
        ),
        (
            DECLARED_MODE_ENTRY.replace("0o644", "0o640") + WILDCARD_ENTRY.replace("0o644", "0o604"),
            0o644,
            {"~/.secrets/step-ca/password": ["has mode 644; at most 600 allowed", "`chmod 600 ~/.secrets/step-ca/password`"]},
        ),
    ],
    ids=[
        "M1 declared mode is no finding",
        "M2 looser than declared is fixed to the declared mode",
        "M3 no declaration means 0600",
        "two declarations of the same mode agree",
        "the strictest declaration wins over a looser wildcard",
        "two declarations allow only the bits both allow",
    ],
)
def test_a_file_is_judged_against_the_mode_its_entry_declares(
    tmp_path: Path, use_manifest, probe: FakeProbe, capsys, manifest: str, file_mode: int, loose_findings: dict[str, list[str]]
) -> None:
    """#195 M1-M3: the declared mode replaces 0600 for that entry's files only, and the fix names it."""
    home = tmp_path / "home"
    use_manifest(manifest)
    plant_secrets(home)
    (home / ".secrets" / "step-ca" / "password").chmod(file_mode)

    run_hal_secrets(home, probe, now=NOW)

    assert findings_of(report_of(home), "loose-mode") == loose_findings


@pytest.mark.parametrize(
    ("file_name", "loose_findings"),
    [
        ("root_ca_key", {"~/.secrets/step-ca/.pending-root/root_ca_key": ["has mode 644; at most 600 allowed", "`chmod 600 ~/.secrets/step-ca/.pending-root/root_ca_key`"]}),
        ("root_ca.crt", {}),
    ],
    ids=["a pending root key at 0644 is loose", "a pending root certificate at 0644 is fine"],
)
def test_only_the_pending_root_certificate_may_be_0644(
    tmp_path: Path, probe: FakeProbe, capsys, file_name: str, loose_findings: dict[str, list[str]]
) -> None:
    home = tmp_path / "home"
    pending = home / ".secrets" / "step-ca" / ".pending-root"
    pending.mkdir(parents=True, mode=0o700)
    (pending / file_name).write_text("x")
    (pending / file_name).chmod(0o644)
    for folder in (pending, pending.parent, home / ".secrets"):
        folder.chmod(0o700)

    run_hal_secrets(home, probe, now=NOW)

    assert findings_of(report_of(home), "loose-mode") == loose_findings


def test_the_files_go_live_and_init_write_are_known_and_need_no_change(tmp_path: Path, probe: FakeProbe, capsys) -> None:
    """#195 M5: laid out as keycloak/go-live and step-ca/init write them, `hal check` reports nothing for them; #201 the agent service's token with its renewal file beside it; #356 its signing pair, whose public half at 0644 is no finding."""
    home = tmp_path / "home"
    files = {
        "step-ca": {"password": 0o644, "root_ca_key": 0o600, "root_ca.crt": 0o644},
        "step-ca/.pending-root": {"root_ca_key": 0o600, "root_ca.crt": 0o644},
        "keycloak": {"db-password": 0o644, "config-cli-secret": 0o644, "bootstrap-admin-password": 0o644},
        "keycloak/clients": {"edge": 0o644, "presentator": 0o644},
        "agent-service/claude": {"token": 0o600, "token.new": 0o600}, "agent-service/signing": {"private.pem": 0o600, "public.pem": 0o644},
    }
    for folder, modes in files.items():
        (home / ".secrets" / folder).mkdir(parents=True, mode=0o700)
        for name, mode in modes.items():
            (home / ".secrets" / folder / name).write_text("x")
            (home / ".secrets" / folder / name).chmod(mode)
    folders = ("keycloak/clients", "keycloak", "step-ca/.pending-root", "step-ca", "")
    for folder in ("agent-service/signing", "agent-service/claude", "agent-service", *folders):
        (home / ".secrets" / folder).chmod(0o700)

    run_hal_secrets(home, probe, now=NOW)

    output = report_of(home)
    for rule in ("loose-mode", "unknown-file", "closed-folder", "not-a-folder", "symlinked-folder", "symlinked-file"):
        assert findings_of(output, rule) == {}
    assert not [name for name in findings_of(output, "missing") if name.startswith(("step-ca/", "keycloak/"))]


def test_a_home_where_neither_unit_is_set_up_has_no_finding_about_their_files(tmp_path: Path, probe: FakeProbe, capsys) -> None:
    """#195 H1: each unit's own --check owns presence; the daily check never calls its files missing."""
    home = tmp_path / "home"
    (home / ".secrets").mkdir(parents=True, mode=0o700)

    run_hal_secrets(home, probe, now=NOW)
    subjects = finding_subjects(report_of(home))
    assert not {subject for subject in subjects if subject.startswith(("step-ca/", "keycloak/", "~/.secrets/step-ca", "~/.secrets/keycloak"))}


@pytest.mark.parametrize(
    ("recorded", "shown", "findings"),
    [("", "revocation unconfirmed", ["github/token"]), ("revocation_confirmed = 2026-10-15\n", "revocation confirmed 15.10.2026", [])],
    ids=["revocation unconfirmed", "revocation confirmed"],
)
def test_a_retired_entry_shows_its_revoke_link_and_whether_its_revocation_is_confirmed(
    use_manifest, clean_home: Path, probe: FakeProbe, capsys, recorded: str, shown: str, findings: list[str]
) -> None:
    """#21 point 1: a confirmed revocation is shown with its date and raises no revocation-unconfirmed finding."""
    use_manifest(TEST_MANIFEST + RETIRED_ENTRY + recorded)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    retired = rows_of(output)["github/token"]
    assert code == (1 if findings else 0)
    assert retired[2:5] == ["retired", shown, "expiry unknown"]
    assert retired[-1] == "revoke: https://github.com/settings/tokens"
    assert list(findings_of(output, "revocation-unconfirmed")) == findings
    assert "github/token" not in findings_of(output, "missing")


KNOWN_FILES = """
[[secret]]
name = "secrets/README"
kind = "documentation"
paths = ["~/.secrets/README"]
read_by = []
recreate = "von Hand"

[[secret]]
name = "runtime.env"
kind = "configuration"
paths = ["~/.secrets/runtime.env"]
read_by = ["bot.service"]
recreate = "von Hand"

[[secret]]
name = "ppk"
kind = "derived-mirror"
paths = ["~/.secrets/ppk"]
read_by = []
recreate = "puttygen"
mirror_of = "gitlab"
optional = true
elsewhere = "/etc/example (root)"
"""


def test_known_non_secret_files_show_their_kind_and_a_missing_optional_entry_is_no_finding(
    use_manifest, clean_home: Path, probe: FakeProbe, capsys
) -> None:
    """#21 points 2-4: documentation and configuration are known files; an optional entry may be absent; copies elsewhere are named."""
    use_manifest(TEST_MANIFEST + KNOWN_FILES)
    for name in ("README", "runtime.env"):
        (clean_home / ".secrets" / name).write_text("no secret")
        (clean_home / ".secrets" / name).chmod(0o600)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    rows = rows_of(output)
    assert code == 0
    assert {name: rows[name][1:3] for name in ("secrets/README", "runtime.env", "ppk")} == {
        "secrets/README": ["documentation", "present"],
        "runtime.env": ["configuration", "present"],
        "ppk": ["derived copy", "missing (optional)"],
    }
    assert rows["ppk"][5] == "~/.secrets/ppk; /etc/example (root)"
    assert "No findings." in output


def close_to(mode: int, folder: str) -> Callable[[Path], None]:
    def close(secrets: Path) -> None:
        (secrets / folder).chmod(mode)

    return close


@pytest.fixture
def reopened_secrets(clean_home: Path) -> Iterator[Path]:
    """Gives ~/.secrets and the folders directly under it back to their owner afterwards, so the temporary home can be removed."""
    secrets = clean_home / ".secrets"
    yield secrets
    if secrets.is_dir() and not secrets.is_symlink():
        secrets.chmod(0o700)
        for place in secrets.iterdir():
            if place.is_dir() and not place.is_symlink():
                place.chmod(0o700)


def put_a_file_in_place_of(secrets: Path) -> None:
    shutil.rmtree(secrets)
    secrets.write_text("not a folder")


def point_a_dangling_link_from(secrets: Path) -> None:
    shutil.rmtree(secrets)
    secrets.symlink_to(secrets.with_name("gone"))


NOT_AS_ROOT = pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")


@pytest.mark.parametrize(
    ("block", "rule", "place", "finding", "held"),
    [
        pytest.param(
            close_to(0, "cloudflared"),
            "closed-folder",
            "~/.secrets/cloudflared",
            ["has mode 0; its owner needs 700", "`chmod 700 ~/.secrets/cloudflared`"],
            "unknown",
            id="closed-subfolder",
            marks=NOT_AS_ROOT,
        ),
        pytest.param(
            close_to(0o600, "."),
            "closed-folder",
            "~/.secrets",
            ["has mode 600; its owner needs 700", "`chmod 700 ~/.secrets`"],
            "unknown",
            id="closed-secrets-folder",
            marks=NOT_AS_ROOT,
        ),
        pytest.param(
            put_a_file_in_place_of,
            "not-a-folder",
            "~/.secrets",
            ["is not a folder", "`mv -n ~/.secrets ~/.secrets.alt`"],
            "unknown",
            id="file-in-place-of-secrets",
        ),
        pytest.param(
            point_a_dangling_link_from,
            "symlinked-folder",
            "~/.secrets",
            ["is a symlink", f"`{symlinked_folder_fix('~/.secrets')}`"],
            "missing",
            id="dangling-link-in-place-of-secrets",
        ),
    ],
)
def test_a_folder_on_the_way_that_cannot_hold_a_secret_is_a_finding_with_its_fix_and_nothing_below_it_shows_present(
    clean_home: Path,
    reopened_secrets: Path,
    probe: FakeProbe,
    capsys,
    block: Callable[[Path], None],
    rule: str,
    place: str,
    finding: list[str],
    held: str,
) -> None:
    """#37 line 7: a closed folder, or a file or link where ~/.secrets belongs, is named with its fix, never a dead end."""
    block(reopened_secrets)

    code = run_hal_secrets(clean_home, probe, now=NOW)

    output = report_of(clean_home)
    assert code == 1
    assert findings_of(output, rule) == {place: finding}
    assert rows_of(output)["cloudflared"][2] == held


def test_by_service_inverts_read_by_under_a_declared_dependencies_heading(clean_home: Path, probe: FakeProbe, capsys) -> None:
    code = run_hal_secrets(clean_home, probe, "--by-service", now=NOW)
    output = capsys.readouterr().out
    assert code == 0
    assert output.splitlines()[0] == "# hal secrets --by-service | declared dependencies"
    assert "| .bashrc | gitlab, cloudflared |" in output
    assert "Derived copies" not in output
    assert probe.calls == []
    assert not Layout(clean_home).state_dir.exists()


def test_no_service_reads_a_github_token_that_can_write_or_administer() -> None:
    powerful = [e for e in load_manifest(secrets_view.MANIFEST_PATH) if e.source and any(r.endswith((":admin", ":write")) for r in e.source.scope)]
    assert powerful
    assert all(entry.read_by == () for entry in powerful)


@pytest.mark.parametrize(
    ("state_mode", "loose_findings"),
    [
        (0o600, {}),
        (0o664, {"~/.secrets/opentofu/fleet.tfstate": ["has mode 664; at most 600 allowed", "`chmod 600 ~/.secrets/opentofu/fleet.tfstate`"]}),
    ],
    ids=["owner-only state", "loose state is still reported"],
)
def test_the_files_edge_external_leaves_under_opentofu_are_known_and_only_a_loose_mode_is_a_finding(
    tmp_path: Path, probe: FakeProbe, capsys, state_mode: int, loose_findings: dict[str, list[str]]
) -> None:
    """#159 T2/T3: state, its backup, plans and tmp are declared; the loose-mode check still fires."""
    home = tmp_path / "home"
    plant_secrets(home)
    opentofu = home / ".secrets" / "opentofu"
    for directory in ("plans", "tmp"):
        (opentofu / directory).unlink()
        (opentofu / directory).mkdir(mode=0o700)
    for name, mode in (("fleet.tfstate", state_mode), ("fleet.tfstate.backup", 0o600)):
        (opentofu / name).write_text("encrypted state")
        (opentofu / name).chmod(mode)
    (opentofu / "plans" / "fleet.tfplan").write_text("encrypted plan")
    (opentofu / "plans" / "fleet.tfplan").chmod(0o600)

    code = run_hal_secrets(home, probe, now=NOW)

    output = report_of(home)
    assert findings_of(output, "unknown-file") == {}
    assert findings_of(output, "loose-mode") == loose_findings
    assert code == (1 if loose_findings else 0)


def test_a_stray_copy_of_the_state_beside_it_is_still_an_unknown_file(tmp_path: Path, probe: FakeProbe, capsys) -> None:
    """#159 T4: the state's files are named exactly, so a plaintext `tofu state pull` copy does not hide."""
    home = tmp_path / "home"
    plant_secrets(home)
    stray = home / ".secrets" / "opentofu" / "fleet.tfstate.json"
    stray.write_text("plaintext state")
    stray.chmod(0o600)
    run_hal_secrets(home, probe, now=NOW)
    assert set(findings_of(report_of(home), "unknown-file")) == {"~/.secrets/opentofu/fleet.tfstate.json"}


def test_every_file_the_packaged_manifest_plants_is_known(tmp_path: Path, probe: FakeProbe, capsys) -> None:
    """#42 M1: no planted file is an unknown file."""
    home = tmp_path / "home"
    plant_secrets(home)
    run_hal_secrets(home, probe, now=NOW)
    assert findings_of(report_of(home), "unknown-file") == {}


def never_asked(*_: object) -> object:
    raise AssertionError("--setup asked the operator although nothing is set up by it")


def test_a_missing_restic_password_is_named_with_its_recreate_line_and_setup_never_generates_it(
    tmp_path: Path, probe: FakeProbe, capsys
) -> None:
    """#42 rule 1: losing the restic password makes every backup unreadable, so `--setup` leaves it by hand."""
    home = tmp_path / "home"
    plant_secrets(home)
    password = home / ".secrets" / "restic" / "password"
    password.unlink()
    operator_absent = Boundaries(Terminal(lambda: True, never_asked, never_asked, never_asked), never_asked, os.fsync, never_run)

    view_code = run_hal_secrets(home, probe, now=NOW)
    view = report_of(home)
    capsys.readouterr()
    setup_end = run_wizard(home, operator_absent)
    setup = capsys.readouterr().out.splitlines()

    assert view_code == 1
    assert findings_of(view, "missing") == {"restic/password": ["-", "fetch it back, see the table"]}
    assert rows_of(view)["restic/password"][-1] == RESTIC_RECREATE
    assert setup_end is WalkEnd.STILL_OPEN
    assert f"! restic/password by hand no wizard yet: {RESTIC_RECREATE}" in [" ".join(line.split()) for line in setup]
    assert not password.exists()


@pytest.mark.parametrize(
    ("kind", "generated"),
    [
        ("human-password", False),
        ("service-password", True),
        ("tool-login", False),
        ("token", False),
    ],
)
def test_setup_generates_only_a_service_password_and_never_a_human_one(tmp_path: Path, kind: str, *, generated: bool) -> None:
    """#42 rule 1: a human-password entry is never written by `--setup`, so a lost one is never silently replaced."""
    manifest = tmp_path / "secrets_manifest.toml"
    manifest.write_text(ENTRY.replace('kind = "token"', f'kind = "{kind}"'))

    (entry,) = load_manifest(manifest)

    assert entry.written_by_setup is generated


def test_an_invalid_manifest_exits_2_naming_the_file(use_manifest, clean_home: Path, probe: FakeProbe, capsys) -> None:
    manifest = use_manifest(TEST_MANIFEST + 'value = "x"\n')

    code = run_hal_secrets(clean_home, probe, now=NOW)

    assert code == 2
    assert capsys.readouterr().err.startswith(f"error: {manifest}: ")


ENTRY = '[[secret]]\nname = "e"\nkind = "token"\npaths = ["~/.secrets/e"]\nread_by = []\nrecreate = "r"\n'
SOURCE = 'provider = "github"\nresource = "o"\nscope = ["metadata:read"]\nexpires_in_days = 366\n'


@pytest.mark.parametrize(
    ("text", "named"),
    [
        ("[[secret]\n", "secrets_manifest.toml"),
        ("other = 1\n", "other"),
        ("secret = 1\n", "secret"),
        ("secret = [1]\n", "[[secret]] #1"),
        ('[[secret]]\nname = "e"\n', "kind"),
        (ENTRY + 'value = "hunter2"\n', "value"),
        (ENTRY.replace('"token"', '"password"'), "kind"),
        (ENTRY.replace('recreate = "r"', 'recreate = ["hunter2"]'), "recreate"),
        (ENTRY.replace('name = "e"', "name = 1"), "[[secret]] #1"),
        (ENTRY.replace('recreate = "r"', 'recreate = " "'), "recreate"),
        (ENTRY.replace("read_by = []", "read_by = [1]"), "read_by"),
        (ENTRY.replace('["~/.secrets/e"]', "[]"), "paths"),
        (ENTRY.replace("~/.secrets/e", "/etc/e"), "paths"),
        (ENTRY.replace("~/.secrets/e", "~/../e"), "paths"),
        (ENTRY.replace("~/.secrets/e", "~//etc/e"), "paths"),
        (ENTRY.replace("~/.secrets/e", "~/.secrets/*/e"), "paths"),
        (ENTRY + 'verify = "curl"\n', "verify"),
        (ENTRY.replace('"token"', '"derived-mirror"'), "mirror_of"),
        (ENTRY + 'mirror_of = "e"\n', "mirror_of"),
        (ENTRY + "retired_on = 2026-10-14\n", "revoke_url"),
        (ENTRY + 'retired_on = "yesterday"\nrevoke_url = "https://x"\n', "retired_on"),
        (ENTRY + 'retired_on = 2026-10-14T10:00:00\nrevoke_url = "https://x"\n', "retired_on"),
        (ENTRY + 'retired_on = 2026-10-14\nrevoke_url = "http://x"\n', "revoke_url"),
        # #21 points 1 and 4: a confirmed revocation is a date on a retired entry; optional is true or false.
        (ENTRY + "revocation_confirmed = 2026-10-15\n", "retired entry only"),
        (ENTRY + 'retired_on = 2026-10-14\nrevoke_url = "https://x"\nrevocation_confirmed = "today"\n', "revocation_confirmed"),
        (ENTRY + 'optional = "yes"\n', "optional"),
        (ENTRY + 'elsewhere = " "\n', "elsewhere"),
        # #195 M4: a declared mode comes with its reason and is never looser than 0644.
        (ENTRY + 'loosest_mode = 0o666\nloosest_mode_reason = "r"\n', "loosest_mode"),
        (ENTRY + 'loosest_mode = 0o755\nloosest_mode_reason = "r"\n', "loosest_mode"),
        (ENTRY + 'loosest_mode = "0644"\nloosest_mode_reason = "r"\n', "loosest_mode"),
        (ENTRY + 'loosest_mode = true\nloosest_mode_reason = "r"\n', "loosest_mode"),
        (ENTRY + 'loosest_mode = 0\nloosest_mode_reason = "r"\n', "loosest_mode"),
        (ENTRY + "loosest_mode = 0o644\n", "belong together"),
        (ENTRY + 'loosest_mode_reason = "r"\n', "belong together"),
        (ENTRY + ENTRY, "e"),
        (ENTRY.replace('"token"', '"derived-mirror"') + 'mirror_of = "gone"\n', "gone"),
        # #36 rule 1 / rule 2.2: a token the wizard guides names its provider, resource, rights and expiry, and one place.
        (ENTRY + 'provider = "github"\n', "provider"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace("github", "gitlab"), "provider"),
        (ENTRY.replace('"token"', '"service-password"') + 'purpose = "p"\n' + SOURCE, "token entry only"),
        (ENTRY + SOURCE, "purpose"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace('"metadata:read"', '"metadata"'), "scope"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace('"metadata:read"', '"metadata:own"'), "scope"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace('["metadata:read"]', "[]"), "scope"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace("366", "367"), "expires_in_days"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace("366", "0"), "expires_in_days"),
        (ENTRY + 'purpose = "p"\n' + SOURCE.replace("366", "true"), "expires_in_days"),
        (ENTRY.replace('["~/.secrets/e"]', '["~/.secrets/e", "~/.secrets/f"]') + 'purpose = "p"\n' + SOURCE, "exactly one place"),
        (ENTRY.replace('"token"', '"service-password"').replace("~/.secrets/e", "~/.secrets/*.key"), "exactly one place"),
    ],
)
def test_an_invalid_manifest_is_refused_naming_the_file_and_the_key(tmp_path: Path, text: str, named: str) -> None:
    path = tmp_path / "secrets_manifest.toml"
    path.write_text(text)

    with pytest.raises(ManifestError) as refused:
        load_manifest(path)

    assert str(refused.value).startswith(f"{path}: ")
    assert named in str(refused.value)
    assert "hunter2" not in str(refused.value)


@pytest.mark.parametrize(
    ("pattern", "matched"),
    [
        ("one/file", ["one/file"]),
        ("one/*.key", ["one/a.key", "one/b.key"]),
        ("one/*.nothing", []),
        ("absent/file", []),
        ("absent/*", []),
        ("one/file/x", None),
        ("one/file/*", None),
    ],
)
def test_stat_matches_returns_every_named_path_as_one_tuple_python_S8495(tmp_path: Path, pattern: str, matched: list[str] | None) -> None:
    (tmp_path / "one").mkdir()
    for name in ("file", "a.key", "b.key", "c.txt"):
        (tmp_path / "one" / name).write_text("x")
    layout = Layout(tmp_path)

    facts = secrets_view.stat_matches(layout, PurePosixPath(pattern))

    assert (None if facts is None else [str(fact.relative) for fact in facts]) == matched


def test_a_missing_manifest_is_refused_naming_the_file(tmp_path: Path) -> None:
    with pytest.raises(ManifestError, match="secrets_manifest.toml"):
        load_manifest(tmp_path / "secrets_manifest.toml")


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        ([sys.executable, "-c", "print('ghp_0000notarealtoken')"], 0),
        ([sys.executable, "-c", "import sys; sys.stderr.write('glpat-0000'); raise SystemExit(4)"], 4),
        (["home-no-such-tool"], None),
    ],
    ids=["a probe that passes", "a probe that fails", "a probe that is not installed"],
)
def test_a_probe_hands_back_only_its_exit_code(capfd, argv: list[str], expected: int | None) -> None:
    assert secrets_view.probe_exit_code(argv) == expected
    assert capfd.readouterr() == ("", "")


@pytest.fixture
def probe_family(tmp_path: Path) -> Iterator[tuple[Path, int]]:
    """A FIFO every process of a probe's family holds open for writing: its reader sees EOF only once all of them are gone."""
    held_open_while_alive = tmp_path / "probe-family"
    os.mkfifo(held_open_while_alive)
    reader = os.open(held_open_while_alive, os.O_RDONLY | os.O_NONBLOCK)
    yield held_open_while_alive, reader
    os.close(reader)


def wait_until_the_family_started(reader: int) -> None:
    family_started, _, _ = select.select([reader], [], [], 10)
    assert family_started, "the run never started its probe"
    first_byte = os.read(reader, 1)
    assert first_byte == b"s", "the probe's first byte was not its start marker"


def assert_every_family_member_gone(reader: int) -> None:
    every_writer_gone, _, _ = select.select([reader], [], [], 10)
    assert every_writer_gone, "a process the probe started outlived it"
    assert os.read(reader, 1) == b""


@pytest.mark.parametrize(
    "family",
    ['exec 3>"$1"; sleep 60 & exec sleep 30', 'trap "" TERM; exec 3>"$1"; sleep 60 & exec sleep 30'],
    ids=["a family that dies on SIGTERM", "a family that ignores SIGTERM"],
)
def test_a_probe_that_hangs_is_killed_with_everything_it_started_and_reports_nothing(probe_family: tuple[Path, int], family: str) -> None:
    held_open_while_alive, reader = probe_family
    probe_with_background_child = ["sh", "-c", family, "sh", str(held_open_while_alive)]

    assert secrets_view.probe_exit_code(probe_with_background_child, timeout=1) is None

    assert_every_family_member_gone(reader)


def a_stop_as_the_probe_is_started(monkeypatch: pytest.MonkeyPatch, reader: int) -> None:
    """The stop lands once the probe's family runs but before probe_exit_code holds the probe, where it would orphan it."""
    start = subprocess.Popen

    def start_then_stop(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        probe = start(*args, **kwargs)
        wait_until_the_family_started(reader)
        os.kill(os.getpid(), signal.SIGTERM)
        return probe

    monkeypatch.setattr(subprocess, "Popen", start_then_stop)


def no_stop_from_outside(_monkeypatch: pytest.MonkeyPatch, _reader: int) -> None:
    pass


@pytest.mark.parametrize(
    ("stop_from_outside", "family", "stopped"),
    [
        (a_stop_as_the_probe_is_started, "sleep 60 & printf s >&3; exec sleep 30", SystemExit(128 + signal.SIGTERM)),
        (no_stop_from_outside, "sleep 60 & kill -INT $PPID; exec sleep 30", KeyboardInterrupt()),
        (
            no_stop_from_outside,
            'sleep 60 & trap "kill -TERM $PPID" TERM; while kill -0 $! 2>/dev/null; do wait $!; done',
            SystemExit(128 + signal.SIGTERM),
        ),
    ],
    ids=["a stop while the probe is started", "Ctrl-C while the probe runs", "a stop while the hung probe is killed"],
)
def test_a_stop_ends_the_run_with_its_exit_status_once_the_probe_and_everything_it_started_are_dead(
    monkeypatch: pytest.MonkeyPatch,
    probe_family: tuple[Path, int],
    stop_from_outside: Callable[[pytest.MonkeyPatch, int], None],
    family: str,
    stopped: BaseException,
) -> None:
    held_open_while_alive, reader = probe_family
    stop_from_outside(monkeypatch, reader)

    with pytest.raises(type(stopped)) as run_end:
        secrets_view.probe_exit_code(["sh", "-c", f'exec 3>"$1"; {family}', "sh", str(held_open_while_alive)], timeout=1)

    assert run_end.value.args == stopped.args
    assert_every_family_member_gone(reader)


def test_a_stop_the_caller_ignores_neither_ends_the_run_nor_is_unignored() -> None:
    caller_handler = signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        assert secrets_view.probe_exit_code(["sh", "-c", "kill -HUP $PPID"]) == 0
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    finally:
        signal.signal(signal.SIGHUP, caller_handler)


HAL_SECRETS_FROM_A_TERMINAL = (
    "import signal, sys; signal.signal(signal.SIGINT, signal.default_int_handler); from hal.cli import main; sys.exit(main())"
)


@pytest.mark.parametrize(
    "family",
    [
        "sleep 60 & printf s >&3; exec sleep 30",
        'trap "" TERM; sleep 60 & trap "kill -{stop} $PPID" TERM; printf s >&3; while kill -0 $! 2>/dev/null; do wait $!; done',
    ],
    ids=["a family that dies on SIGTERM", "a family that ignores SIGTERM and stops the run again while it is killed"],
)
@pytest.mark.parametrize(
    ("stop", "exit_status"),
    [(signal.SIGINT, 130), (signal.SIGTERM, 128 + signal.SIGTERM), (signal.SIGHUP, 128 + signal.SIGHUP)],
    ids=["Ctrl-C", "a timeout wrapper", "a closed terminal"],
)
def test_a_stopped_run_takes_its_probe_and_everything_it_started_along(
    tmp_path: Path, probe_family: tuple[Path, int], stop: signal.Signals, exit_status: int, family: str
) -> None:
    held_open_while_alive, reader = probe_family
    tools = tmp_path / "bin"
    tools.mkdir()
    hanging_gh = tools / "gh"
    hanging_gh.write_text(f'#!/bin/sh\nexec 3>"{held_open_while_alive}"; {family.format(stop=stop.value)}\n')
    hanging_gh.chmod(0o755)
    home = tmp_path / "home"
    home.mkdir()
    environment = {**os.environ, "HOME": str(home), "PATH": f"{tools}{os.pathsep}{os.environ['PATH']}"}
    environment["PYTHONPATH"] = str(Path(secrets_view.__file__).parents[2])
    run = subprocess.Popen(
        [sys.executable, "-c", HAL_SECRETS_FROM_A_TERMINAL, "secrets"],
        env=environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        wait_until_the_family_started(reader)

        os.killpg(run.pid, stop)  # a terminal or `timeout` signals the run's process group, never the probe's own session

        assert run.wait(timeout=10) == exit_status
        assert_every_family_member_gone(reader)
    finally:
        if run.poll() is None:
            os.killpg(run.pid, signal.SIGKILL)
            run.wait()
