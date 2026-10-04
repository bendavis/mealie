"""Client metadata validation for public MCP OAuth clients."""

import socket

import httpx
import pytest

from mealie.mcp import oauth

CLIENT_ID = "https://chatgpt.com/oauth/client.json"
REDIRECT = "https://chatgpt.com/connector_platform_oauth_redirect"


@pytest.mark.asyncio
async def test_cimd_selects_public_method_from_supported_methods(monkeypatch):
    seen = []
    payload = {
        "client_id": CLIENT_ID,
        "client_name": "ChatGPT",
        "redirect_uris": [REDIRECT],
        "token_endpoint_auth_method": "private_key_jwt",
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
    }

    def respond(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=payload)

    real_client = httpx.AsyncClient

    def client_factory(**kwargs):
        return real_client(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(
        oauth.socket, "getaddrinfo", lambda *_args, **_kwargs: [(socket.AF_INET, 0, 0, "", ("93.184.215.14", 443))]
    )
    monkeypatch.setattr(oauth.httpx, "AsyncClient", client_factory)
    client = await oauth._fetch_client_metadata(CLIENT_ID)
    assert client is not None
    assert client.token_endpoint_auth_method == "none"
    assert str(client.redirect_uris[0]) == REDIRECT
    assert seen[0].url.host == "93.184.215.14"
    assert seen[0].headers["host"] == "chatgpt.com"
    assert seen[0].extensions["sni_hostname"] == "chatgpt.com"

    payload["token_endpoint_auth_methods_supported"] = ["private_key_jwt"]
    assert await oauth._fetch_client_metadata(CLIENT_ID) is None


@pytest.mark.asyncio
async def test_cimd_rejects_private_dns_addresses(monkeypatch):
    monkeypatch.setattr(
        oauth.socket, "getaddrinfo", lambda *_args, **_kwargs: [(socket.AF_INET, 0, 0, "", ("127.0.0.1", 443))]
    )
    assert await oauth._fetch_client_metadata(CLIENT_ID) is None
