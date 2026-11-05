"""The picture route on the stack of litellm.py, for the probes that drive it (litellm_admission.py,
litellm_retention.py): the shipped picture name, agent-runtime's picture body, the call and the
fake OpenAI's request log. The text names stay the completion route's.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from litellm import FAKE_PICTURES, PICTURE_ROUTE, LitellmProbe, shipped_models

TEXT_PREFIX, PICTURE_PREFIX = "text/", "image/"
PICTURE_MODEL = next(name for name in shipped_models() if name.startswith(PICTURE_PREFIX))
PICTURE_SIZE = "1024x1024"


def text_models() -> dict[str, dict]:
    """The shipped names an app sends a completion to, with their `litellm_params`."""
    return {
        name: params for name, params in shipped_models().items() if name.startswith(TEXT_PREFIX)
    }


def picture_body(user: str | None, prompt: str = "probe", model: str = PICTURE_MODEL) -> dict:
    """agent-runtime's picture body: `model`, `prompt`, `size` and `user` (none when None)."""
    asked = {"model": model, "prompt": prompt, "size": PICTURE_SIZE}
    return {**asked, **({"user": user} if user else {})}


def picture_of(answer: dict) -> str | None:
    """The `b64_json` of the answer's one picture."""
    try:
        return answer["document"]["data"][0]["b64_json"]
    except KeyError, IndexError, TypeError:
        return None


class PictureCalls(LitellmProbe):
    """litellm.py's stack with the picture call and the fake OpenAI's log."""

    def picture(self, key: str | None, user: str | None, *, prompt: str = "probe",
                model: str = PICTURE_MODEL, front: bool = True) -> dict:  # fmt: skip
        """A: one picture request through the front, or straight at LiteLLM."""
        body = picture_body(user, prompt, model)
        return self.call(key, "POST", PICTURE_ROUTE, body, front=front)

    def picture_requests(self) -> list[dict]:
        """F of the fake OpenAI: one record per request it received."""
        lines = self.log_of(FAKE_PICTURES).splitlines()
        return [json.loads(line) for line in lines if line.startswith("{")]
