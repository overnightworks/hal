"""The files of `tunnel/` (#76): the cloudflared unit, its drop-ins and the stop-only polkit rule
that home-tools#9 installs. edge only ships them; the pins below keep them equal to the facts
`hal.stack.tunnel` and `hal.stack.switches` own. polkit's real verdict and `systemd-analyze verify`
are home-tools#9 B1's, where cloudflared and systemd as PID 1 exist."""

import re
from pathlib import Path

import pytest
import yaml

from hal.stack import switches, tunnel
from hal.workstation.layout import Layout

TUNNEL_FILES = Path(__file__).resolve().parents[1] / "tunnel"
BASE_UNIT = TUNNEL_FILES / tunnel.CLOUDFLARED_UNIT
DROP_INS = TUNNEL_FILES / f"{tunnel.CLOUDFLARED_UNIT}.d"
NONROOT_DROP_IN = DROP_INS / "20-nonroot.conf"
BOOT_DROP_IN = DROP_INS / tunnel.BOOT_DROP_IN
HAL_DROP_IN = DROP_INS / "30-hal-global-stop.conf"
POLKIT_RULES = tuple(sorted((TUNNEL_FILES / "polkit").glob("*.rules")))
ALL_FILES = tuple(sorted(path for path in TUNNEL_FILES.rglob("*") if path.is_file()))

PLAYBOOK = Path(__file__).resolve().parents[1] / "src/hal/workstation/system/playbook.yml"

PLACEHOLDER = re.compile(r"@[A-Z_]+@")


def render(text: str, values: dict[str, str]) -> str:
    """What the installer does: every `@NAME@` replaced by its value."""
    for name, value in values.items():
        text = text.replace(f"@{name}@", value)
    return text


def key_value_lines(text: str) -> list[str]:
    return [line for line in text.splitlines() if "=" in line and not line.startswith("#")]


def test_every_shipped_tunnel_file_is_installed_and_every_installed_file_is_shipped():
    """The directory against the playbook's `system_files`, both read: a file nobody installs and an
    entry without a file are both red."""
    installed = {
        entry["src"] for entry in yaml.safe_load(PLAYBOOK.read_text())[0]["vars"]["system_files"]
    }
    shipped = {path.relative_to(TUNNEL_FILES).as_posix() for path in ALL_FILES}
    assert shipped == installed


def test_the_boot_drop_in_carries_the_name_edge_checks_for():
    """#76 rule 3, cell 1."""
    assert BOOT_DROP_IN.is_file()


def test_the_boot_drop_in_skips_the_tunnel_while_the_global_stop_exists(tmp_path, monkeypatch):
    """#76 rule 3, cell 2: rendered with a temporary HOME, the condition names switches' marker."""
    monkeypatch.setenv("HOME", str(tmp_path))
    marker = switches.default_state_directory() / switches.GLOBAL_STOP_FILE
    rendered = render(BOOT_DROP_IN.read_text(), {"HOME": str(tmp_path)})
    assert key_value_lines(rendered) == [
        f"ConditionPathExists=!{marker}",
        f"RequiresMountsFor={marker.parent}",
    ]
    assert "[Unit]" in rendered.splitlines()


def test_the_hal_drop_in_names_the_marker_below_hal_state_dir(tmp_path):
    """#858 A1: rendered with a temporary home, the condition names `hal_state_dir`."""
    state_dir = Layout(tmp_path).hal_state_dir
    rendered = render(HAL_DROP_IN.read_text(), {"HOME": str(tmp_path)})
    assert key_value_lines(rendered) == [
        f"ConditionPathExists=!{state_dir / switches.GLOBAL_STOP_FILE}",
        f"RequiresMountsFor={state_dir}",
    ]
    assert "[Unit]" in rendered.splitlines()


def test_the_polkit_rules_exist():
    assert POLKIT_RULES


@pytest.mark.parametrize("path", POLKIT_RULES, ids=lambda path: path.name)
def test_the_polkit_rule_grants_only_the_operators_stop_of_the_tunnel(path):
    """#76 rule 1, rule 3, cell 3."""
    rule = path.read_text()
    assert "||" not in rule
    for condition in (
        f'action.id == "{tunnel.MANAGE_UNITS_ACTION}"',
        f'action.lookup("unit") == "{tunnel.CLOUDFLARED_UNIT}"',
        'action.lookup("verb") == "stop"',
        'subject.user == "@OPERATOR_USER@"',
    ):
        assert condition in rule
    assert re.findall(r"polkit\.Result\.\w+", rule) == ["polkit.Result.YES"]
    assert rule.count("return") == 1
    assert "subject.local" not in rule
    assert "subject.active" not in rule


@pytest.mark.parametrize("path", POLKIT_RULES, ids=lambda path: path.name)
def test_the_polkit_rule_is_es5(path):
    """#76 rule 1, cell 4: polkit 124 runs its rules on Duktape."""
    code = "\n".join(
        line for line in path.read_text().splitlines() if not line.lstrip().startswith("//")
    )
    assert "=>" not in code
    assert not re.search(r"\b(let|const)\b", code)


def test_the_files_carry_exactly_the_three_placeholders_the_installer_fills():
    """#76 rule 2, cell 5."""
    texts = [path.read_text() for path in ALL_FILES]
    assert {name for text in texts for name in PLACEHOLDER.findall(text)} == {
        "@HOME@",
        "@OPERATOR_USER@",
        "@TUNNEL_ID@",
    }
    values = {"HOME": "/home/someone", "OPERATOR_USER": "someone", "TUNNEL_ID": "0000"}
    assert not [text for text in texts if PLACEHOLDER.search(render(text, values))]


def test_the_unit_keeps_its_hardening_and_has_one_exec_start():
    """The base unit and its non-root drop-in together carry the protective limits and a single
    `ExecStart` (a second one breaks the unit)."""
    lines = key_value_lines(BASE_UNIT.read_text()) + key_value_lines(NONROOT_DROP_IN.read_text())
    protection = {
        "DynamicUser=yes",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
    }

    assert sum(line.partition("=")[0].strip() == "ExecStart" for line in lines) == 1
    assert protection <= set(lines)
    assert any(line.startswith("LoadCredential=") for line in lines)
    assert not [line for line in lines if line.partition("=")[0].strip() == "User"]
    for kept in protection:
        assert sum(line.partition("=")[0].strip() == kept.partition("=")[0] for line in lines) == 1


@pytest.mark.parametrize("path", ALL_FILES, ids=lambda path: path.name)
def test_no_tunnel_file_asks_for_sudo(path):
    """#76 rule 4, cell 9: the files are content; installing them is home-tools#9's one sudo."""
    assert "sudo" not in path.read_text()
