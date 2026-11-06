"""Probe of what the API route logs (#1084 cells L1-L6): the stack of litellm.py without the agent
service and the issuer (the front, LiteLLM, its database and the gateway's second entrypoint,
against a fake Anthropic and a fake OpenAI) at the log level compose.yaml ships, with the caller of
litellm.py. Nothing live and nothing paid: the probe refuses to start unless `internet` is internal
and holds only the fakes.

    flock -o -w 3600 /tmp/probe-stack.lock setpriv --pdeathsig TERM timeout -k 30 1800 \\
        python3 probe/agent-service/litellm_logs.py --scratch DIR

Measured: a run takes about three minutes and its teardown a few seconds (K 30 s, CAP 1800 s).

Evidence: A is the caller's status, FL the front's access log, LL LiteLLM's log, R a row of
`LiteLLM_SpendLogs` read by SQL. L1 to L5 run at the depth `metadata`, which compose.yaml's
defaults give; L6 recreates LiteLLM with the variables `hal apply` passes at `everything`
(`hal.stack.api_limits`). Every request holds a fresh prompt canary; the sweep of L5 searches every
line of FL and LL and every row of R for a prompt canary, the answer marker, a bearer and each
whole key. The probe prints statuses, error classes, counts and the row's columns, never a key.
Exit 0: every cell held.
"""

from __future__ import annotations

import json
import secrets
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import (  # noqa: E402
    DATABASE,
    FAKE_PICTURES,
    FAKE_PROVIDER,
    FRONT,
    GATEWAY,
    LITELLM,
    PICTURE_HOST,
    expect,
    hashed,
    person_budget,
    run_scratch_probe,
)
from litellm_failures import FailureProbe  # noqa: E402
from litellm_pictures import PictureCalls  # noqa: E402

from hal.output import write_line  # noqa: E402
from hal.stack import api_limits  # noqa: E402
from hal.stack.api_limits import LogDepth  # noqa: E402

UNKNOWN_TOKEN = "Invalid proxy server token passed"
PROVIDER_REFUSED = "litellm.AuthenticationError"
SPEND_TABLE = "LiteLLM_SpendLogs"
APP_ALIAS = "hopin"
EXCERPT = 240
RESOLVED_SETTING = (
    "from litellm.proxy.proxy_server import ProxyConfig; "
    "print(repr(ProxyConfig()._check_for_os_environ_vars({'s': 'os.environ/%s'})['s']))"
)


def front_lines(log: str) -> list[dict]:
    """The access lines of the front's log: its JSON lines that name a router."""
    lines = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
    return [line for line in lines if "DownstreamStatus" in line]


class LogsProbe(FailureProbe, PictureCalls):
    """litellm.py's stack at the shipped log level, read back from its logs and its spend rows."""

    LITELLM_LOG_LEVEL = None

    def __init__(self, scratch: Path) -> None:
        super().__init__(scratch)
        self.canaries: list[str] = []
        self.unknown_key = f"sk-{secrets.token_urlsafe(32)}"

    def services_to_start(self) -> tuple[str, ...]:
        return (GATEWAY, FAKE_PROVIDER, FAKE_PICTURES, FRONT, DATABASE, LITELLM)

    # --- evidence -----------------------------------------------------------------------------

    def prompt(self) -> str:
        canary = f"canary-{secrets.token_hex(8)}"
        self.canaries.append(canary)
        return canary

    def asked(self, key: str, user: str) -> dict:
        """A: one completion whose one message is a fresh prompt canary."""
        messages = [{"role": "user", "content": self.prompt()}]
        return self.complete(key, user=user, messages=messages)

    def new_lines(self, service: str, before: int, holds) -> list[str]:
        """The lines `service` logged after its first `before`, once one of them `holds`."""
        found: list[str] = []

        def logged() -> bool:
            found[:] = self.log_of(service).splitlines()[before:]
            return any(holds(line) for line in found)

        self.wait_for(service, "the line", logged, seconds=30)
        shown = next(line for line in found if holds(line))
        for label, value in self.forbidden().items():
            shown = shown.replace(value, f"<{label}>")
        write_line(f"{service}: {shown[:EXCERPT]}", flush=True)
        return found

    def marks(self) -> tuple[int, int]:
        return tuple(len(self.log_of(service).splitlines()) for service in (FRONT, LITELLM))

    def spend_rows(self, where: str = "true") -> list[dict]:
        query = f'SELECT row_to_json(s) FROM "{SPEND_TABLE}" s WHERE {where}'  # noqa: S608 - the probe writes the condition
        output = self.sql(query, "--tuples-only", "--no-align").stdout
        return [json.loads(line) for line in output.splitlines() if line.strip()]

    def row_of(self, cell: str, user: str, status: str) -> dict:
        """R: the spend row of the person's call with `status`, once LiteLLM wrote it."""
        rows: list[dict] = []

        def written() -> bool:
            rows[:] = [row for row in self.spend_rows(f"end_user = '{user}'")
                       if row["status"] == status]  # fmt: skip
            return bool(rows)

        self.wait_for(cell, f"a {status} row of the person", written)
        return rows[0]

    def message_logging_off(self) -> str:
        """turn_off_message_logging as the pinned image's loader resolves it from the running
        container's environment."""
        variable = api_limits.MESSAGE_LOGGING_OFF_VARIABLE
        argv = ["docker", "exec", self.container(LITELLM), "python", "-B", "-c",
                RESOLVED_SETTING % variable]  # fmt: skip
        return self.run(argv).stdout.strip().splitlines()[-1]

    def forbidden(self) -> dict[str, str]:
        """What no line and no row at the depth `metadata` may hold, by label."""
        keys = [*self.every_value, *self.app_keys, self.unknown_key]
        return {
            **{f"key {index}": key for index, key in enumerate(keys)},
            **{f"prompt {index}": canary for index, canary in enumerate(self.canaries)},
            "answer": self.marker,
            "bearer": "Bearer ",
        }

    # --- the cells ----------------------------------------------------------------------------

    def drive(self) -> None:
        self.wait_until_listening()
        self.wait_for_front()
        self.admin("POST", "/budget/new", person_budget())
        self.key = self.make_key(key_alias=APP_ALIAS)
        self.steer()
        self.cell_l1()
        self.cell_l2()
        self.cell_l3()
        self.cell_l4()
        self.cell_l5()
        self.cell_l6()

    def cell_l1(self) -> None:
        front_before, litellm_before = self.marks()
        status = self.asked(self.unknown_key, self.fingerprint())["status"]
        expect(status == 401, f"L1: the unknown key got {status}")
        lines = self.new_lines(LITELLM, litellm_before, lambda line: UNKNOWN_TOKEN in line)
        logged = "\n".join(self.log_of(FRONT).splitlines()[front_before:])
        refused = [line for line in front_lines(logged) if line["DownstreamStatus"] == 401]
        expect(refused, "L1: no front line with 401")
        expect(not any(PROVIDER_REFUSED in line for line in lines), "L1: a provider's class")
        write_line(f"L1 FL: {json.dumps(refused[-1], sort_keys=True)}", flush=True)
        self.hold("L1", f"an unknown key: A 401, FL {sorted(refused[-1])} with status 401, LL "
                  f"`{UNKNOWN_TOKEN}` and no `{PROVIDER_REFUSED}`")  # fmt: skip

    def cell_l2(self) -> None:
        user = self.fingerprint()
        self.steer(mode="status", status=401)
        _, litellm_before = self.marks()
        answer = self.asked(self.key, user)
        self.steer()
        expect(answer["status"] == 401, f"L2: the provider's 401 reached the caller as {answer}")
        lines = self.new_lines(LITELLM, litellm_before, lambda line: PROVIDER_REFUSED in line)
        expect(not any(UNKNOWN_TOKEN in line for line in lines), "L2: the unknown key's line")
        row = self.row_of("L2", user, "failure")
        error = row["metadata"].get("error_information") or {}
        expect("AuthenticationError" in json.dumps(error), f"L2: R's error {sorted(error)}")
        self.hold("L2", f"Anthropic's 401: A 401, LL `{PROVIDER_REFUSED}` and no "
                  f"`{UNKNOWN_TOKEN}`, R status {row['status']} for the person, its error class "
                  f"{error.get('error_class')}")  # fmt: skip

    def cell_l3(self) -> None:
        user = self.fingerprint()
        self.steer_fake(host=PICTURE_HOST, mode="status", status=401)
        _, litellm_before = self.marks()
        status = self.picture(self.key, user, prompt=self.prompt())["status"]
        self.steer_fake(host=PICTURE_HOST)
        expect(status == 401, f"L3: OpenAI's 401 reached the caller as {status}")
        lines = self.new_lines(LITELLM, litellm_before, lambda line: PROVIDER_REFUSED in line)
        masked = [line for line in lines if "Incorrect API key provided" in line]
        expect(masked, "L3: LL does not quote OpenAI's reason")
        row = self.row_of("L3", user, "failure")
        self.hold("L3", f"OpenAI's 401 on a picture: A 401, LL `{PROVIDER_REFUSED}` with OpenAI's "
                  f"reason, R status {row['status']}")  # fmt: skip

    def cell_l4(self) -> None:
        user = self.fingerprint()
        answer = self.asked(self.key, user)
        expect(answer["status"] == 200, f"L4: the call got {answer['status']}")
        row = self.row_of("L4", user, "success")
        expect(row["api_key"] == hashed(self.key), "L4: the row names another key")
        expect(row["model"] and row["spend"] > 0, f"L4: model {row['model']}, spend {row['spend']}")
        alias = row["metadata"].get("user_api_key_alias")
        expect(alias == APP_ALIAS, f"L4: the row names the alias {alias!r}")
        shown = {name: row[name] for name in ("model", "spend", "status", "call_type")}
        write_line(f"L4 R: {json.dumps(shown, sort_keys=True)}", flush=True)
        self.hold("L4", f"a served call: R with the person, the key's hash, alias {alias!r}, "
                  f"model {row['model']}, spend {row['spend']}")  # fmt: skip

    def cell_l5(self) -> None:
        forbidden = self.forbidden()
        texts = {
            "FL": self.log_of(FRONT), "LL": self.log_of(LITELLM),
            "R": "\n".join(json.dumps(row) for row in self.spend_rows()),
        }  # fmt: skip
        found = sorted(f"{label} in {sink}" for sink, text in texts.items()
                       for label, value in forbidden.items() if value in text)  # fmt: skip
        expect(not found, f"L5: {found}")
        resolved = self.message_logging_off()
        expect(resolved == "True", f"L5: turn_off_message_logging resolves to {resolved}")
        counts = {sink: len(text.splitlines()) for sink, text in texts.items()}
        self.hold("L5", f"none of {len(forbidden)} values (keys, prompt canaries, the answer, a "
                  f"bearer) in {counts}; turn_off_message_logging resolves to True")  # fmt: skip

    def cell_l6(self) -> None:
        everything = api_limits.log_environment(LogDepth.EVERYTHING)
        self.environment.update(everything)
        self.recreate_litellm()
        self.wait_for_front()
        resolved = self.message_logging_off()
        expect(resolved == "False", f"L6: turn_off_message_logging resolves to {resolved}")
        _, litellm_before = self.marks()
        self.asked(self.key, self.fingerprint())
        canary = self.canaries[-1]
        self.new_lines(LITELLM, litellm_before, lambda line: canary in line)
        self.hold("L6", "at `everything` after a recreate: turn_off_message_logging resolves to "
                  "the bool False, the request's prompt canary is in LL")  # fmt: skip


def main() -> int:
    return run_scratch_probe(__doc__.splitlines()[0], LogsProbe)


if __name__ == "__main__":
    sys.exit(main())
