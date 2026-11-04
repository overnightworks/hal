"""What the pre-apply snapshot says when `hal backup` fails or answers something it cannot read."""

import subprocess

import pytest

from hal.stack import pre_apply
from hal.stack.litellm_keys import LITELLM
from hal.stack.realm.reconcile import KEYCLOAK
from hal.stack.unit_plans import DatabaseUnit


def _answering(stdout: str, stderr: str, code: int, asked: list[list[str]] | None = None):
    def run(command: list[str], _timeout: int, _stdin: str | None = None):
        if asked is not None:
            asked.append(command)
        return subprocess.CompletedProcess(command, code, stdout, stderr)

    return run


@pytest.mark.parametrize("unit", [KEYCLOAK, LITELLM], ids=lambda unit: unit.key)
def test_the_backup_asks_for_its_unit_alone_and_reads_the_snapshot_id(unit: DatabaseUnit) -> None:
    asked: list[list[str]] = []
    backup = pre_apply.Backup(("hal",), _answering('{"snapshot": "ab12cd34"}\n', "", 0, asked))

    snapshot = backup.pre_apply(unit)
    backup.restore_test(unit, snapshot)

    assert snapshot == "ab12cd34"
    assert asked == [
        ["hal", "backup", unit.key, "--pre-apply", "--json"],
        ["hal", "restore", "--test", unit.key, "--snapshot", "ab12cd34"],
    ]


@pytest.mark.parametrize(
    ("stderr", "cause"),
    [
        (
            "error: hal backup: failed: no password\nnext: hal backup --help\n",
            "hal backup: failed: no password",
        ),
        (
            "error: --pre-apply needs the name of an app\nnext: hal backup --help\n",
            "--pre-apply needs the name of an app",
        ),
        ("Traceback ... boom\n", "Traceback ... boom"),
    ],
    ids=["a runtime failure", "a usage failure", "a failure that is not hal's own"],
)
def test_a_failing_backup_names_the_cause_never_the_next_line(stderr: str, cause: str) -> None:
    backup = pre_apply.Backup(("hal",), _answering("", stderr, 3))

    with pytest.raises(pre_apply.PreApplyError) as raised:
        backup.pre_apply(KEYCLOAK)

    assert str(raised.value) == f"the {KEYCLOAK.name} backup failed ({cause})"


@pytest.mark.parametrize("stdout", ["{}\n", "[]\n", '{"snapshot": null}', "not json"])
def test_an_answer_without_a_snapshot_id_is_a_failure(stdout: str) -> None:
    backup = pre_apply.Backup(("hal",), _answering(stdout, "", 0))

    with pytest.raises(pre_apply.PreApplyError, match="named no pre-apply snapshot"):
        backup.pre_apply(KEYCLOAK)


def test_a_failing_restore_test_names_the_cause_never_the_next_line() -> None:
    stderr = "error: keycloak: the dump does not restore\nnext: hal restore --test keycloak\n"
    backup = pre_apply.Backup(("hal",), _answering("", stderr, 3))

    with pytest.raises(pre_apply.PreApplyError) as raised:
        backup.restore_test(KEYCLOAK, "ab12cd34")

    assert str(raised.value) == "the restore test failed (keycloak: the dump does not restore)"
