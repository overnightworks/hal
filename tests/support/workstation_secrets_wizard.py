"""What the secrets wizard tests share: the manifest it walks, the value a person pastes, the temporary
home and terminal, and the files a run leaves."""

from pathlib import Path

import pytest
from support.workstation_secrets_support import FakeTerminal
from support.workstation_support import FAKE_SECRET_VALUE

# Two guided tokens, one generated passphrase, in the order the walk must keep.
SETUP_MANIFEST = """\
[[secret]]
name = "cloudflare/read"
kind = "token"
paths = ["~/.secrets/cloudflare/read"]
read_by = ["hal apply"]
recreate = "https://dash.cloudflare.com/profile/api-tokens"
purpose = "liest Cloudflare"
provider = "cloudflare"
resource = "example.invalid"
scope = ["Zone › DNS › Read"]
expires_in_days = 30

[[secret]]
name = "github/read"
kind = "token"
paths = ["~/.secrets/github/read"]
read_by = ["hal apply"]
recreate = "https://github.com/settings/personal-access-tokens/new"
purpose = "liest GitHub"
provider = "github"
resource = "example-org"
scope = ["metadata:read", "organization_secrets:read"]
expires_in_days = 366

[[secret]]
name = "keystore/passphrase"
kind = "service-password"
paths = ["~/.secrets/keystore/passphrase"]
read_by = ["hal apply"]
recreate = "hal setup"
purpose = "verschlüsselt den State"
"""
PASSPHRASE_FILE = ".secrets/keystore/passphrase"

# A pasted token carries no whitespace, so the canary's parts are joined; each part alone must stay unseen too.
PASTED_VALUE_PARTS = tuple(FAKE_SECRET_VALUE.split())
PASTED_VALUE = ".".join(PASTED_VALUE_PARTS)


@pytest.fixture
def home(tmp_path: Path, use_manifest) -> Path:
    use_manifest(SETUP_MANIFEST)
    home = tmp_path / "home"
    home.mkdir()
    return home


@pytest.fixture
def terminal() -> FakeTerminal:
    return FakeTerminal()


def files_under(home: Path) -> set[str]:
    return {str(path.relative_to(home)) for path in home.rglob("*") if path.is_file()}
