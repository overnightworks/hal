"""LiteLLM's custom auth (config.yaml `custom_auth`): a thin adapter that hands the request to
gate.py and returns a minimal key allowed on the one route, so LiteLLM's own route check is a
second line. The decision lives in gate.py."""

import os
from pathlib import Path

from fastapi import Request
from gate import PATH, decide
from litellm.proxy._types import ProxyException, UserAPIKeyAuth

CREDENTIAL_FILE = Path("/run/secrets/agent_service_api_credential")
HTTP_UNAUTHORIZED = 401
# compose.yaml owns the number. A missing or malformed value stops the hook from loading, so the
# route refuses everything instead of running without a bound.
MAX_PARALLEL_REQUESTS = int(os.environ["API_ROUTE_MAX_PARALLEL_REQUESTS"])


# LiteLLM calls the hook as `user_custom_auth(request=request, api_key=api_key)`; the bearer is read
# from the request itself.
async def user_api_key_auth(
    request: Request,
    api_key: str,  # NOSONAR(S1172) LiteLLM passes it by keyword, so the name is its interface
) -> UserAPIKeyAuth:
    verdict = decide(
        method=request.method,
        path=request.url.path,
        query=request.url.query,
        authorization=request.headers.get("authorization"),
        content_types=request.headers.getlist("content-type"),
        header_names=request.headers.keys(),
        body=await request.body(),
        credential_file=CREDENTIAL_FILE,
    )
    if not verdict.allowed:
        raise ProxyException(
            message=verdict.reason, type="auth_error", param="authorization", code=HTTP_UNAUTHORIZED
        )
    return UserAPIKeyAuth(
        api_key="service", allowed_routes=[PATH], max_parallel_requests=MAX_PARALLEL_REQUESTS
    )
