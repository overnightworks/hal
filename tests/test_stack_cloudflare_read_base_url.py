"""The Cloudflare read client (#138 R4): the token goes only to Cloudflare's API or to loopback."""

import socket
from pathlib import Path

import pytest

from hal.stack.external import cloudflare_read
from hal.stack.external.cloudflare_read import CloudflareClient, OwnTunnel

TOKEN = "sentinel-token-4b1d-never-print-me"
OWN_TUNNEL = OwnTunnel(
    "11111111-2222-3333-4444-555555555555", Path("/scenario/cloudflared/config.yml")
)

pytestmark = pytest.mark.usefixtures("loopback_only")


@pytest.mark.parametrize(
    "base_url",
    [
        "http://example.com",
        "ftp://127.0.0.1",
        "http://127.0.0.1.example.com",
        "https://example.com/client/v4",
        "https://api.cloudflare.com.evil.test/client/v4",
        "https://api.cloudflare.com/client/v4/",
        "https://127.0.0.1",
    ],
)
def test_the_token_goes_only_to_cloudflares_api_or_to_http_on_loopback(base_url):
    """R4."""
    with pytest.raises(ValueError):
        CloudflareClient(TOKEN, OWN_TUNNEL, base_url=base_url)


@pytest.mark.parametrize(
    "base_url", [cloudflare_read.BASE_URL, "http://127.0.0.1:8080", "http://localhost"]
)
def test_cloudflares_api_and_loopback_are_accepted(base_url):
    """R4."""
    CloudflareClient(TOKEN, OWN_TUNNEL, base_url=base_url)


def test_the_default_base_url_is_cloudflares_https_api():
    """R4."""
    assert cloudflare_read.BASE_URL == "https://api.cloudflare.com/client/v4"


def test_the_backstop_refuses_a_connection_beyond_loopback():
    """R4."""
    with pytest.raises(AssertionError, match="leaves loopback"):
        socket.create_connection(("192.0.2.1", 9), timeout=0.1)
