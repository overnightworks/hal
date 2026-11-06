"""#390 cells C1, C6, C11 of the mail account and the msmtp command line: T1 (TLS always on), R1 (the password only by --passwordeval), V1 (an invalid account names the key, never a value), P1 (the manifest inventories both files)."""

from __future__ import annotations

from email.message import EmailMessage
from pathlib import Path

import pytest

from hal.workstation.mail import AccountInvalid, MailAccount, load_account, sendmail_command
from hal.workstation.layout import Layout

ACCOUNT = MailAccount(host="smtp.example.test", port=587, user="home@example.test", to="me@example.test")
VALID_ACCOUNT_TEXT = 'host = "smtp.example.test"\nport = 587\nuser = "home@example.test"\nto = "me@example.test"\n'
CANARY = "CANARY-ACCOUNT-VALUE"


def write_account(home: Path, text: str) -> None:
    account_file = Layout(home).secrets_dir / "smtp" / "account.toml"
    account_file.parent.mkdir(parents=True, exist_ok=True)
    account_file.write_text(text)


def message() -> EmailMessage:
    news = EmailMessage()
    news["Subject"] = "hal check | 2 findings"
    news.set_content("2 new, 0 gone.\n")
    return news


def option_values(command: list[str]) -> list[str]:
    """The msmtp argv: everything after the `msmtp` word of the shell wrapper."""
    return command[command.index("msmtp") + 1 :]


def test_an_absent_account_file_is_no_account(tmp_path: Path) -> None:
    assert load_account(Layout(tmp_path)) is None


def test_a_valid_account_file_is_loaded(tmp_path: Path) -> None:
    write_account(tmp_path, VALID_ACCOUNT_TEXT)

    assert load_account(Layout(tmp_path)) == ACCOUNT


INVALID_ACCOUNTS = {
    "missing key": (VALID_ACCOUNT_TEXT.replace('user = "home@example.test"\n', ""), "missing key: user"),
    "string port": (VALID_ACCOUNT_TEXT.replace("587", '"587"'), "port"),
    "port zero": (VALID_ACCOUNT_TEXT.replace("587", "0"), "port"),
    "port too large": (VALID_ACCOUNT_TEXT.replace("587", "65536"), "port"),
    "host with a space": (VALID_ACCOUNT_TEXT.replace("smtp.example.test", "smtp example"), "host"),
    "host with a leading dash": (VALID_ACCOUNT_TEXT.replace("smtp.example.test", "-oProxy"), "host"),
    "host too long": (VALID_ACCOUNT_TEXT.replace("smtp.example.test", "a" * 254), "host"),
    "user with a comma": (VALID_ACCOUNT_TEXT.replace("home@example.test", "a@example.test,b@example.test"), "user"),
    "to with a newline": (VALID_ACCOUNT_TEXT.replace("me@example.test", "me@example.test\\nBcc: x@example.test"), "to"),
    "to with an angle bracket": (VALID_ACCOUNT_TEXT.replace("me@example.test", "<me@example.test>"), "to"),
    "to without an address": (VALID_ACCOUNT_TEXT.replace("me@example.test", "me"), "to"),
}


@pytest.mark.parametrize(("text", "key"), INVALID_ACCOUNTS.values(), ids=INVALID_ACCOUNTS)
def test_an_invalid_account_names_the_key_and_never_echoes_a_value(tmp_path: Path, text: str, key: str) -> None:
    write_account(tmp_path, text + f"# {CANARY}\n")

    layout = Layout(tmp_path)
    with pytest.raises(AccountInvalid) as refused:
        load_account(layout)

    assert key in str(refused.value)
    assert CANARY not in str(refused.value)


def test_an_extra_password_key_is_refused_without_echoing_it(tmp_path: Path) -> None:
    write_account(tmp_path, VALID_ACCOUNT_TEXT + f'password = "{CANARY}"\n')

    layout = Layout(tmp_path)
    with pytest.raises(AccountInvalid) as refused:
        load_account(layout)

    assert "unknown key" in str(refused.value)
    assert "password" not in str(refused.value)
    assert CANARY not in str(refused.value)


def test_a_file_that_is_no_toml_is_refused_without_echoing_it(tmp_path: Path) -> None:
    write_account(tmp_path, f"host = {CANARY}\n")

    layout = Layout(tmp_path)
    with pytest.raises(AccountInvalid) as refused:
        load_account(layout)

    assert CANARY not in str(refused.value)


@pytest.mark.parametrize(("port", "starttls"), [(587, "on"), (2525, "on"), (465, "off")])
def test_tls_is_always_on_and_only_port_465_is_implicit(port: int, starttls: str) -> None:
    command = sendmail_command(MailAccount("smtp.example.test", port, "home@example.test", "me@example.test"), Path("/h/.secrets"), message())

    assert option_values(command) == [
        "--host=smtp.example.test",
        f"--port={port}",
        "--auth=on",
        "--user=home@example.test",
        "--from=home@example.test",
        "--tls=on",
        f"--tls-starttls={starttls}",
        "--timeout=30",
        "--passwordeval=cat -- /h/.secrets/smtp/password",
        "--",
        "me@example.test",
    ]


def test_the_command_carries_no_way_to_weaken_tls_or_to_read_a_config_file() -> None:
    options = option_values(sendmail_command(ACCOUNT, Path("/h/.secrets"), message()))

    assert not [option for option in options if option.startswith(("--tls-certcheck", "--tls-trust-file", "--tls-fingerprint", "--file", "-C", "-t", "-d", "--read-recipients", "--debug"))]


def test_the_password_path_is_quoted_for_the_shell_and_the_message_is_a_positional_parameter() -> None:
    command = sendmail_command(ACCOUNT, Path("/h o'me/.secrets"), message())

    assert "--passwordeval=cat -- '/h o'\"'\"'me/.secrets/smtp/password'" in command
    assert command[:3] == ["sh", "-c", 'printf %s "$1" | { shift; exec "$@"; }']
    assert command[3:5] == ["sh", message().as_string()]
