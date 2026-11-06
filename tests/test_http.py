"""Signed Access assertion -> real registered MCP tool -> fixture file readback."""
import hashlib
import json
import os
import tempfile
import time
import unittest
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from vault_mcp.auth import AccessVerifier, principal
from vault_mcp.config import Config
from vault_mcp.server import create_app


class HTTPFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.root = base / "vault"
        (self.root / "Agents").mkdir(parents=True)
        (self.root / "Reference").mkdir()
        (self.root / "Agents/sample.md").write_text("fixture text")
        (self.root / "Reference/sample.md").write_text("reference fixture")
        (self.root / "AGENTS.md").write_text("fixture rules")
        self.verifier = AccessVerifier("fixture", "fixture-audience",
            {"owner@example.invalid": frozenset({"read", "agent_write"})},
            {"fixture-reader.access": frozenset({"read"})})
        self.verifier.keys.get_signing_key_from_jwt = lambda _: type("Key", (), {"key": self.key.public_key()})()
        self.config = Config(self.root, base / "state")
        self.app = create_app(self.config, self.verifier)

    def assertion(self, service=False, signing_key=None, **overrides):
        identity = {"common_name": "fixture-reader.access"} if service else {"email": "owner@example.invalid"}
        claims = {"iss": "https://fixture.cloudflareaccess.com", "aud": "fixture-audience",
                  "iat": int(time.time()), "exp": int(time.time()) + 60, **identity, **overrides}
        return jwt.encode(claims, signing_key or self.key, algorithm="RS256")

    def post(self, client, method, params=None, assertion=None):
        headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json",
                   "MCP-Protocol-Version": "2025-06-18"}
        if assertion is not None:
            headers["Cf-Access-Jwt-Assertion"] = assertion
        return client.post("/mcp", headers=headers,
                           json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}})

    def call(self, client, name, arguments=None, service=False):
        response = self.post(client, "tools/call", {"name": name, "arguments": arguments or {}}, self.assertion(service))
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertNotIn("error", body)
        return body["result"]

    def data(self, result):
        self.assertFalse(result.get("isError", False), result)
        # Parse the serialized registered-tool content, not incidental response strings.
        structured = result["structuredContent"]
        return structured["result"] if result.get("_meta", {}).get("fastmcp", {}).get("wrap_result") else structured

    def test_local_initialize_tools_create_nested_read_update_replay(self):
        with TestClient(self.app) as client:
            initialized = self.post(client, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                "clientInfo": {"name": "fixture", "version": "1"}}, self.assertion())
            self.assertEqual(initialized.status_code, 200)
            self.assertEqual(initialized.json()["result"]["serverInfo"]["name"], "Self-hosted Vault MCP")
            self.assertNotIn("mcp-session-id", initialized.headers)
            listed = self.post(client, "tools/list", assertion=self.assertion()).json()["result"]["tools"]
            self.assertEqual({t["name"] for t in listed}, {"bootstrap", "list_files", "list_files_page", "read_file", "search_notes", "search_notes_page",
                                                               "create_note", "update_note", "storage_status"})
            self.assertEqual(self.data(self.call(client, "bootstrap"))["instructions"]["text"], "fixture rules")
            self.assertEqual(self.data(self.call(client, "storage_status"))["mode"], "local")
            arguments = {"path": "Agents/New Project/Notes/new.md", "content": "created", "request_id": str(uuid.uuid4())}
            first = self.data(self.call(client, "create_note", arguments))
            self.assertEqual((self.root / arguments["path"]).read_text(), "created")
            self.assertEqual(first, self.data(self.call(client, "create_note", arguments)))
            self.assertTrue(self.call(client, "create_note", {**arguments, "content": "different"})["isError"])
            read = self.data(self.call(client, "read_file", {"path": arguments["path"]}))
            self.assertEqual(read["sha256"], hashlib.sha256(b"created").hexdigest())
            update = {**arguments, "content": "updated", "expected_sha256": "0"*64, "request_id": str(uuid.uuid4())}
            self.assertTrue(self.call(client, "update_note", update)["isError"])
            update["expected_sha256"] = read["sha256"]
            changed = self.data(self.call(client, "update_note", update))
            self.assertEqual(changed, self.data(self.call(client, "update_note", update)))
            self.assertEqual((self.root / arguments["path"]).read_text(), "updated")
            self.assertEqual(self.data(self.call(client, "read_file", {"path": arguments["path"]}))["text"], "updated")
            paths = self.data(self.call(client, "list_files"))
            self.assertIn(arguments["path"], paths)
            self.assertEqual(self.data(self.call(client, "search_notes", {"query": "reference fixture"})), [])
            self.assertEqual(self.data(self.call(client, "search_notes", {"query": "reference fixture", "prefix": "Reference"}))[0]["path"], "Reference/sample.md")

    def test_assertion_denials_and_per_request_service_isolation(self):
        with TestClient(self.app) as client:
            invalid = [None, "invalid", self.assertion(signing_key=self.other_key),
                       self.assertion(exp=int(time.time())-1), self.assertion(aud="wrong"),
                       self.assertion(iss="https://wrong.invalid"), self.assertion(exp=None), self.assertion(iat=None), self.assertion(email="unknown@example.invalid"),
                       self.assertion(service=True, common_name="unknown.access")]
            for assertion in invalid:
                with self.subTest(case=invalid.index(assertion)):
                    self.assertEqual(self.post(client, "tools/list", assertion=assertion).status_code, 401)
            self.data(self.call(client, "read_file", {"path": "Agents/sample.md"}, service=True))
            args = {"path": "Agents/permission.md", "content": "body", "request_id": str(uuid.uuid4())}
            self.data(self.call(client, "create_note", args))
            args.update(path="Agents/denied.md", request_id=str(uuid.uuid4()))
            self.assertTrue(self.call(client, "create_note", args, service=True)["isError"])
            self.assertFalse((self.root / "Agents/denied.md").exists())
            self.assertEqual(self.post(client, "tools/list").status_code, 401)
            self.data(self.call(client, "create_note", args))
        with self.assertRaises(LookupError):
            principal()

    def test_mcp_paths_and_guarded_retries(self):
        (self.root / "Agents/link").symlink_to(self.root / "Reference", target_is_directory=True)
        with TestClient(self.app) as client:
            for path in ("Reference/no.md", "../no.md", "Agents/../no.md", "Agents/.hidden.md",
                         "Agents/link/no.md", "Agents/CON.md", "Agents/a:b.md"):
                result = self.call(client, "create_note", {"path": path, "content": "body", "request_id": str(uuid.uuid4())})
                self.assertTrue(result["isError"])
            self.assertFalse((self.root / "Reference/no.md").exists())
        ready = Path(self.tmp.name) / "ready.json"
        guarded = create_app(Config(self.root, Path(self.tmp.name) / "guard-state", ready=ready), self.verifier)
        args = {"path": "Agents/guarded/new.md", "content": "guarded", "request_id": str(uuid.uuid4())}
        with TestClient(guarded) as client:
            for marker in (None, {"phase": "error", "error_code": "failed"},
                           {"phase": "ready", "ok": True, "heartbeat_at": time.time()-6, "completed_at": time.time()}):
                if marker is not None:
                    ready.write_text(json.dumps(marker))
                self.assertTrue(self.call(client, "create_note", args)["isError"])
                self.assertFalse((self.root / args["path"]).exists())
            ready.write_text(json.dumps({"phase": "ready", "ok": True, "heartbeat_at": time.time(), "completed_at": time.time()}))
            self.data(self.call(client, "create_note", args))
            self.assertEqual((self.root / args["path"]).read_text(), "guarded")

    def test_explicit_root_discovery_and_safe_missing_errors(self):
        for number in range(225):
            (self.root / f"Agents/note-{number}.md").write_text("synthetic")
        (self.root / ".hidden").mkdir()
        (self.root / "alias").symlink_to(self.root / "Reference", target_is_directory=True)
        with TestClient(self.app) as client:
            defaults = self.data(self.call(client, "list_files_page"))
            self.assertEqual(len(defaults["items"]), 100)
            self.assertTrue(defaults["truncated"])
            self.assertTrue(all(path.startswith("Agents/") for path in defaults["items"]))
            self.assertTrue(self.call(client, "list_files")["isError"])
            entries = self.data(self.call(client, "list_files", {"prefix": ""}))
            self.assertEqual(entries, ["AGENTS.md", "Agents/", "Reference/"])
            self.assertEqual(self.data(self.call(client, "search_notes", {"query": "reference fixture", "prefix": ""}))[0]["path"], "Reference/sample.md")
            for prefix in (".", "..", ".hidden", "alias", "Agents/../Reference"):
                self.assertTrue(self.call(client, "list_files", {"prefix": prefix})["isError"])
            for tool, arguments in (("read_file", {"path": "Reference/missing.md"}),
                                    ("list_files", {"prefix": "missing"}),
                                    ("search_notes", {"prefix": "Agents/sample.md/child", "query": "fixture"})):
                result = self.call(client, tool, arguments)
                self.assertTrue(result["isError"])
                self.assertEqual(result["content"], [{"type": "text", "text": "not found"}])

    def test_transport_policy_and_page_coverage(self):
        (self.root / "Agents" / "Private").mkdir()
        (self.root / "Agents" / "Private" / "secret.md").write_text("private marker")
        app = create_app(Config(self.root, Path(self.tmp.name) / "policy-state",
                                denied_paths=("Agents/Private", "AGENTS.md")), self.verifier)
        with TestClient(app) as client:
            for name, args in (("read_file", {"path": "Agents/Private/secret.md"}),
                               ("bootstrap", {}), ("list_files_page", {"prefix": "Agents/private"}),
                               ("search_notes_page", {"query": "private", "prefix": "Agents/Private"}),
                               ("create_note", {"path": "Agents/Private/new.md", "content": "x", "request_id": str(uuid.uuid4())})):
                self.assertTrue(self.call(client, name, args)["isError"], name)
            page = self.data(self.call(client, "list_files_page", {"prefix": "Agents"}))
            self.assertNotIn("Agents/Private/secret.md", page["items"])
            self.assertEqual(self.data(self.call(client, "search_notes_page", {"query": "private marker"}))["items"], [])
            self.assertFalse((self.root / "Agents/Private/new.md").exists())

    def test_time_filter_schema_and_actual_calls(self):
        os.utime(self.root / "Agents/sample.md", (1767225600, 1767225600))
        bounds = {"modified_after": "2026-01-01T00:00:00Z", "modified_before": "2026-01-01T00:00:01Z"}
        with TestClient(self.app) as client:
            listed = self.post(client, "tools/list", assertion=self.assertion()).json()["result"]["tools"]
            for tool in listed:
                if tool["name"] in {"list_files", "list_files_page", "search_notes", "search_notes_page"}:
                    self.assertTrue({"modified_after", "modified_before"} <= tool["inputSchema"]["properties"].keys())
                    self.assertFalse({"modified_after", "modified_before"} & set(tool["inputSchema"].get("required", [])))
            for name in ("list_files", "list_files_page", "search_notes", "search_notes_page"):
                args = {**bounds, **({"query": "fixture"} if name.startswith("search") else {})}
                result = self.data(self.call(client, name, args))
                items = result["items"] if name.endswith("_page") else result
                self.assertEqual(items[0]["path"] if name.startswith("search") else items[0], "Agents/sample.md")
                self.assertTrue(self.call(client, name, {**args, "modified_before": bounds["modified_after"]})["isError"])
                invalid = self.call(client, name, {**args, "modified_after": "fixture private input"})
                self.assertTrue(invalid["isError"])
                self.assertEqual(invalid["content"], [{"type": "text", "text": "invalid modification timestamp; use timezone-aware RFC3339"}])
                empty = self.data(self.call(client, name, {**args, "modified_after": "2026-01-01T00:00:00.000000001Z"}))
                self.assertEqual(empty["items"] if name.endswith("_page") else empty, [])
            self.assertEqual(self.data(self.call(client, "read_file", {"path": "Agents/sample.md"}))["modified_at"],
                             "2026-01-01T00:00:00.000000000Z")
