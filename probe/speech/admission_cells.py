"""The speech probe's admission cells A1-A10 and A12: requests on an app's speech network with
tokens from H's scratch Keycloak, refused or admitted as speech-runtime's wire contract
(docs/wire.md, Refusals) says, and the service's log afterwards.

Every token comes from the copy's Keycloak through its edge entrypoint (H's ScratchOnlyHttp) and
goes to curl on stdin; it is never printed, logged or passed as an argument.
"""

from __future__ import annotations

import io
import json
import secrets
import wave
from array import array
from dataclasses import dataclass
from typing import Any

from edge_copy import expect
from speech_docker import Answer, container_log

# speech-runtime's wire (docs/wire.md, Headers and Request): its contract, not hal's
WORKLOAD_HEADER = "Speech-Workload-Token"
SPEAK_PATH, HEAR_PATH = "/v1/audio/speech", "/v1/audio/transcriptions"
MODEL, VOICE = "speech-runtime", "piper"
SPEECH_SCOPE = "speech-service-audience"  # realm.yaml's optional scope of each speech app
SPEECH_GROUP = "/services/speech-service"  # realm.yaml's group: the service's right
SILENCE = 64  # the largest absolute 16-bit sample a WAV of silence holds
CLIENT_RECORDING = "/run/probe/recording.wav"


@dataclass(frozen=True)
class Tokens:
    workload: str | None
    person: str | None

    def headers(self) -> str:
        lines = [f"{WORKLOAD_HEADER}: {self.workload}"] if self.workload else []
        lines += [f"Authorization: Bearer {self.person}"] if self.person else []
        return "".join(f"{line}\n" for line in lines)


def loudest_sample(body: bytes) -> int:
    with wave.open(io.BytesIO(body)) as audio:
        expect(audio.getsampwidth() == 2, "the WAV is not 16-bit")
        samples = array("h", audio.readframes(audio.getnframes()))
    return max((abs(sample) for sample in samples), default=0)


def error_code(answer: Answer) -> str | None:
    try:
        return answer.json()["error"]["code"]
    except ValueError, KeyError, TypeError:
        return None


class AdmissionCells:
    """Mixed into the speech probe, which provides these."""

    hold: Any
    kc: Any
    secret: Any
    curl: Any
    keycloak: Any  # probe/keycloak/probe.py
    topology: Any
    speech_service: str
    port: int
    speech_id: str
    scratch: Any

    def workload(self, client: Any, *, scoped: bool = True) -> str:
        form = {
            "grant_type": "client_credentials",
            "client_id": client.client_id,
            "client_secret": self.secret(client.secret_file),
        }
        if scoped:
            form["scope"] = SPEECH_SCOPE
        response = self.kc.through_tunnel("POST", self.keycloak.PUBLIC_TOKEN_PATH, form=form)
        return self.kc.tokens_from(f"{client.client_id} workload", response)["access_token"]

    def person(self, client: Any, groups: tuple[str, ...], name: str) -> str:
        admin = self.kc.admin_with_client(self.secret("config-cli-secret"))
        username = f"probe-speech-{name}"
        password = self.kc.keep_secret(f"{username} password", secrets.token_urlsafe(16))
        user = admin.create_user(self.keycloak.REALM, username, password)
        for group in groups:
            admin.join_group(user, group)
        tokens = self.kc.app_client_sign_in(
            client,
            self.kc.browser(f"{username} speech"),
            username,
            password,
            self.secret(client.secret_file),
            scope=f"openid {SPEECH_SCOPE}",
        )
        return tokens["access_token"]

    def speech_url(self, path: str) -> str:
        return f"http://{self.speech_service}:{self.port}{path}"

    def speak(self, app: str, tokens: Tokens, words: str) -> Answer:
        body = json.dumps(
            {"model": MODEL, "input": words, "voice": VOICE, "response_format": "wav"}
        )
        return self.curl.at(
            self.topology.callers[app],
            [
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                body,
                "--max-time",
                "60",
                self.speech_url(SPEAK_PATH),
            ],
            headers=tokens.headers(),
            trusted=False,
        )

    def drive_admission(self) -> None:
        kc_hopin, kc_presentator = self.keycloak.HOPIN, self.keycloak.PRESENTATOR
        words = f"Hallo Probe {secrets.token_hex(3)}"
        hopin_work, presentator_work = self.workload(kc_hopin), self.workload(kc_presentator)
        member = self.person(kc_hopin, (kc_hopin.group, SPEECH_GROUP), "hopin-member")
        cases = {
            "A1": ("hopin", Tokens(None, None), 401, "unauthorized"),
            "A2": ("hopin", Tokens(None, member), 401, "unauthorized"),
            "A3": ("hopin", Tokens(hopin_work, None), 401, "unauthorized"),
            "A4": (
                "hopin",
                Tokens(self.workload(kc_hopin, scoped=False), member),
                401,
                "unauthorized",
            ),
            "A5": (
                "hopin",
                Tokens(hopin_work, self.person(kc_hopin, (kc_hopin.group,), "outside-service")),
                403,
                "forbidden",
            ),
            "A6": (
                "hopin",
                Tokens(hopin_work, self.person(kc_hopin, (SPEECH_GROUP,), "outside-app")),
                403,
                "forbidden",
            ),
            "A10": (
                "hopin",
                Tokens(
                    hopin_work,
                    self.person(
                        kc_presentator, (kc_presentator.group, SPEECH_GROUP), "presentator-member"
                    ),
                ),
                403,
                "forbidden",
            ),
        }
        for cell, (app, tokens, status, code) in cases.items():
            answer = self.speak(app, tokens, words)
            expect(
                answer.status == status and error_code(answer) == code,
                f"{cell}: {answer.status} {error_code(answer)}, not {status} {code}",
            )
            self.hold(cell, f"{answer.status} {code}")
        self.admitted_tokens = Tokens(hopin_work, member)
        self.cell_a7(words)
        presenter = self.person(kc_presentator, (kc_presentator.group, SPEECH_GROUP), "presenter")
        self.presentator_tokens = Tokens(presentator_work, presenter)
        a8 = self.speak("presentator", self.presentator_tokens, words)
        expect(a8.status == 200, f"A8: presentator got {a8.status} {error_code(a8)}")
        self.hold("A8", f"presentator's workload and member: 200, {len(a8.body)} bytes")
        self.cell_a9()
        self.cell_a12(words)

    def cell_a7(self, words: str) -> None:
        answer = self.speak("hopin", self.admitted_tokens, words)
        expect(answer.status == 200, f"A7: {answer.status} {error_code(answer)}")
        loudest = loudest_sample(answer.body)
        expect(loudest > SILENCE, f"A7: the WAV is silent (loudest sample {loudest})")
        self.recording = self.scratch / "a7.wav"
        self.recording.write_bytes(answer.body)
        self.hold(
            "A7",
            f"hopin's workload and member: 200, a WAV of {len(answer.body)} bytes, "
            f"loudest sample {loudest}",
        )

    def cell_a9(self) -> None:
        self.recording.chmod(0o644)
        answer = self.curl.at(
            self.topology.callers["hopin"],
            [
                "--form",
                f"file=@{CLIENT_RECORDING}",
                "--form",
                f"model={MODEL}",
                self.speech_url(HEAR_PATH),
            ],
            headers=self.admitted_tokens.headers(),
            trusted=False,
            mounts=((self.recording, CLIENT_RECORDING),),
        )
        expect(
            answer.status == 403 and error_code(answer) == "not_enabled",
            f"A9: {answer.status} {error_code(answer)}",
        )
        self.hold("A9", "hopin on the hearing route: 403 not_enabled")

    def cell_a12(self, words: str) -> None:
        logs = container_log(self.speech_id)
        found = [mark for mark in ("eyJ", "Bearer", words, words.split()[-1]) if mark in logs]
        expect(not found, f"A12: the speech log holds {found}")
        self.hold("A12", f"{len(logs.splitlines())} log lines: no eyJ, no Bearer, no input words")
