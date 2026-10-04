"""End-to-end checks for the MCP feature in the normal Mealie ASGI app."""

import base64
import hashlib
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlsplit
from uuid import uuid4

from bs4 import BeautifulSoup
from fastapi.testclient import TestClient

from mealie.app import app

RESOURCE = "http://localhost:8080/mcp"


def _tool(client: TestClient, token: str, name: str, arguments: dict | None = None):
    return client.post(
        "/mcp",
        headers={
            "Authorization": f"Bearer {token}",
            "MCP-Protocol-Version": "2026-07-28",
            "Mcp-Method": "tools/call",
            "Mcp-Name": name,
        },
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {},
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                    "io.modelcontextprotocol/clientCapabilities": {},
                    "io.modelcontextprotocol/clientInfo": {"name": "Mealie test", "version": "1"},
                },
            },
        },
    )


def _tool_result(response) -> dict:
    assert response.status_code == 200, response.text
    result = response.json()["result"]
    assert not result["isError"], response.text
    return json.loads(result["content"][0]["text"])


def test_native_mcp_oauth_flow_and_switch():
    with TestClient(app, base_url="http://localhost:8080") as client:
        login = client.post("/api/auth/token", data={"username": "changeme@example.com", "password": "MyPassword"})
        assert login.status_code == 200
        mealie_auth = {"Authorization": f"Bearer {login.json()['access_token']}"}
        assert client.put("/api/admin/mcp", json={"enabled": False}).status_code == 200
        assert client.get("/mcp").status_code == 404
        assert client.get("/.well-known/oauth-protected-resource/mcp").status_code == 404
        assert client.put("/api/admin/mcp", json={"enabled": True}).status_code == 200

        metadata = client.get("/.well-known/oauth-protected-resource/mcp").json()
        assert metadata["resource"] == RESOURCE
        assert "recipes:read" in metadata["scopes_supported"]
        assert client.get("/mcp").status_code == 401
        assert _tool(client, login.json()["access_token"], "get_profile").status_code == 401
        registration = client.post(
            "/oauth/register",
            json={
                "client_name": "Mealie test client",
                "redirect_uris": ["http://127.0.0.1:5599/callback"],
                "token_endpoint_auth_method": "none",
                "application_type": "native",
            },
        )
        assert registration.status_code in (200, 201), registration.text
        client_id = registration.json()["client_id"]

        verifier = "test-verifier-for-mcp-oauth-pkce-12345678901234567890"
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        auth_params = {
            "client_id": client_id,
            "redirect_uri": "http://127.0.0.1:5599/callback",
            "response_type": "code",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": RESOURCE,
            "scope": "profile:read recipes:read",
            "state": "test-state",
        }
        authorization = client.get("/oauth/authorize", params=auth_params, follow_redirects=False)
        assert authorization.status_code == 302, authorization.text
        consent = client.get(authorization.headers["location"])
        assert consent.status_code == 200
        assert "Read recipes" in consent.text
        soup = BeautifulSoup(consent.text, "html.parser")
        form = {item["name"]: item["value"] for item in soup.select("input[type=hidden]")}
        assert client.post("/oauth/consent", data={**form, "csrf": "wrong", "decision": "approve"}).status_code == 403
        approval = client.post("/oauth/consent", data={**form, "decision": "approve"}, follow_redirects=False)
        assert approval.status_code == 302, approval.text
        code = parse_qs(urlsplit(approval.headers["location"]).query)["code"][0]
        token_fields = {
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": verifier,
            "client_id": client_id,
            "redirect_uri": auth_params["redirect_uri"],
            "resource": RESOURCE,
        }
        assert (
            client.post("/oauth/token", data={**token_fields, "resource": "https://wrong.example/mcp"}).status_code
            == 400
        )
        assert client.post("/oauth/token", data={**token_fields, "code_verifier": "wrong"}).status_code == 400
        tokens = client.post("/oauth/token", data=token_fields)
        assert tokens.status_code == 200, tokens.text
        access = tokens.json()["access_token"]
        assert client.post("/oauth/token", data=token_fields).status_code == 400  # one-time code
        _tool_result(_tool(client, access, "get_profile"))
        _tool_result(_tool(client, access, "search_recipes"))
        denied = _tool(
            client, access, "add_shopping_item", {"list_id": "00000000-0000-0000-0000-000000000000", "note": "Milk"}
        )
        assert denied.status_code == 403
        assert 'scope="shopping:write"' in denied.headers["www-authenticate"]
        assert client.get("/api/users/self", headers={"Authorization": f"Bearer {access}"}).status_code == 401
        read_grant_id = client.get("/api/users/mcp/connections").json()[0]["id"]

        # A separate approval can add a write scope without changing the first grant.
        write_auth = client.get(
            "/oauth/authorize",
            params={
                **auth_params,
                "scope": " ".join(
                    [
                        "profile:read",
                        "recipes:read",
                        "recipes:write",
                        "mealplans:read",
                        "mealplans:write",
                        "shopping:read",
                        "shopping:write",
                    ]
                ),
            },
            follow_redirects=False,
        )
        write_consent = client.get(write_auth.headers["location"])
        write_form = {
            item["name"]: item["value"]
            for item in BeautifulSoup(write_consent.text, "html.parser").select("input[type=hidden]")
        }
        write_approval = client.post(
            "/oauth/consent", data={**write_form, "decision": "approve"}, follow_redirects=False
        )
        write_code = parse_qs(urlsplit(write_approval.headers["location"]).query)["code"][0]
        write_token = client.post("/oauth/token", data={**token_fields, "code": write_code})
        assert write_token.status_code == 200
        write_access = write_token.json()["access_token"]
        shopping_list = client.post(
            "/api/households/shopping/lists", json={"name": "MCP test list"}, headers=mealie_auth
        )
        assert shopping_list.status_code == 201, shopping_list.text
        list_id = shopping_list.json()["id"]
        item = _tool_result(_tool(client, write_access, "add_shopping_item", {"list_id": list_id, "note": "Milk"}))
        item_id = item["createdItems"][0]["id"]
        _tool_result(_tool(client, write_access, "update_shopping_item", {"item_id": item_id, "quantity": 2}))
        _tool_result(_tool(client, write_access, "set_shopping_item_checked", {"item_id": item_id, "checked": True}))
        _tool_result(_tool(client, write_access, "get_shopping_list", {"list_id": list_id}))
        _tool_result(_tool(client, write_access, "list_shopping_lists"))

        recipe = _tool_result(_tool(client, write_access, "create_recipe", {"name": "MCP test recipe"}))
        _tool_result(_tool(client, write_access, "get_recipe", {"slug_or_id": recipe["slug"]}))
        _tool_result(
            _tool(client, write_access, "update_recipe", {"slug_or_id": recipe["slug"], "name": "MCP recipe updated"})
        )
        meal = _tool_result(
            _tool(
                client,
                write_access,
                "add_meal_plan_entry",
                {"date": datetime.now(UTC).date().isoformat(), "title": "MCP dinner"},
            )
        )
        _tool_result(
            _tool(client, write_access, "update_meal_plan_entry", {"entry_id": meal["id"], "title": "MCP supper"})
        )
        _tool_result(_tool(client, write_access, "list_meal_plan"))

        # Even an administrator's MCP grant stays bound to the approved household.
        group = client.get("/api/groups/self", headers=mealie_auth).json()
        other_name = f"MCP other {uuid4().hex[:8]}"
        other_household = client.post(
            "/api/admin/households", json={"name": other_name, "groupId": group["id"]}, headers=mealie_auth
        )
        assert other_household.status_code == 201, other_household.text
        other_email = f"mcp-{uuid4().hex[:12]}@example.com"
        other_user = client.post(
            "/api/admin/users",
            json={
                "fullName": "Other MCP user",
                "username": f"mcp{uuid4().hex[:12]}",
                "email": other_email,
                "password": "other-user-password",
                "group": group["name"],
                "household": other_name,
                "admin": False,
                "tokens": [],
            },
            headers=mealie_auth,
        )
        assert other_user.status_code == 201, other_user.text
        other_login = client.post("/api/auth/token", data={"username": other_email, "password": "other-user-password"})
        assert other_login.status_code == 200
        other_auth = {"Authorization": f"Bearer {other_login.json()['access_token']}"}
        other_recipe = client.post("/api/recipes", json={"name": "Other household secret"}, headers=other_auth)
        assert other_recipe.status_code == 201, other_recipe.text
        other_slug = other_recipe.json()
        assert _tool(client, write_access, "get_recipe", {"slug_or_id": other_slug}).json()["result"]["isError"]
        assert _tool(client, write_access, "update_recipe", {"slug_or_id": other_slug, "name": "Wrong"}).json()[
            "result"
        ]["isError"]
        other_list = client.post("/api/households/shopping/lists", json={"name": "Other list"}, headers=other_auth)
        assert other_list.status_code == 201
        other_list_id = other_list.json()["id"]
        assert _tool(client, write_access, "get_shopping_list", {"list_id": other_list_id}).json()["result"]["isError"]
        assert _tool(client, write_access, "add_shopping_item", {"list_id": other_list_id, "note": "Wrong"}).json()[
            "result"
        ]["isError"]

        connections = client.get("/api/users/mcp/connections", headers=mealie_auth)
        assert connections.status_code == 200
        assert client.delete(f"/api/users/mcp/connections/{read_grant_id}", headers=mealie_auth).status_code == 200
        assert _tool(client, access, "get_profile").status_code == 401
        refresh_fields = {
            "grant_type": "refresh_token",
            "refresh_token": write_token.json()["refresh_token"],
            "client_id": client_id,
            "resource": RESOURCE,
        }
        rotated = client.post("/oauth/token", data=refresh_fields)
        assert rotated.status_code == 200, rotated.text
        reused = client.post("/oauth/token", data=refresh_fields)
        assert reused.status_code == 400
        assert _tool(client, write_access, "get_profile").status_code == 401
        assert _tool(client, rotated.json()["access_token"], "get_profile").status_code == 401

        revoke_authorization = client.get("/oauth/authorize", params=auth_params, follow_redirects=False)
        revoke_consent = client.get(revoke_authorization.headers["location"])
        revoke_form = {
            item["name"]: item["value"]
            for item in BeautifulSoup(revoke_consent.text, "html.parser").select("input[type=hidden]")
        }
        revoke_approval = client.post(
            "/oauth/consent", data={**revoke_form, "decision": "approve"}, follow_redirects=False
        )
        revoke_code = parse_qs(urlsplit(revoke_approval.headers["location"]).query)["code"][0]
        revoke_tokens = client.post("/oauth/token", data={**token_fields, "code": revoke_code})
        assert revoke_tokens.status_code == 200, revoke_tokens.text
        revoke_access = revoke_tokens.json()["access_token"]
        assert _tool(client, revoke_access, "get_profile").status_code == 200
        revocation = client.post(
            "/oauth/revoke",
            data={"token": revoke_access, "token_type_hint": "access_token", "client_id": client_id},
        )
        assert revocation.status_code == 200, revocation.text
        assert _tool(client, revoke_access, "get_profile").status_code == 401
        assert (
            client.post(
                "/oauth/token",
                data={**refresh_fields, "refresh_token": revoke_tokens.json()["refresh_token"]},
            ).status_code
            == 400
        )
        assert client.put("/api/admin/mcp", json={"enabled": False}, headers=mealie_auth).status_code == 200
        assert _tool(client, write_access, "get_profile").status_code == 404
        assert client.get("/.well-known/oauth-authorization-server").status_code == 404


def test_http_base_url_does_not_prevent_mealie_startup(tmp_path):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """from mealie.app import app
from mealie.mcp.oauth import validate_enablement_url
assert app is not None
try:
    validate_enablement_url()
except ValueError:
    pass
else:
    raise AssertionError('Remote HTTP must not enable MCP')
""",
        ],
        env={
            **os.environ,
            "BASE_URL": "http://mealie.example.com",
            "DATA_DIR": str(tmp_path),
            "PRODUCTION": "True",
            "TESTING": "True",
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert result.returncode == 0, result.stderr
