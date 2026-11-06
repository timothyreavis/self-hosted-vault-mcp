import hashlib
import fcntl
import json
import os
import stat
import shutil
import sqlite3
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

from vault_mcp.auth import Principal
from vault_mcp.vault import PrePublishError, Vault


class VaultFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.mirror = root / "vault"
        self.mirror.mkdir()
        for path in ("Agents", "Reference", "Projects"):
            (self.mirror / path).mkdir(parents=True)
        (self.mirror / "Reference" / "sample.md").write_text("reference marker")
        (self.mirror / "Agents" / "hello.md").write_text("hello")
        (self.mirror / "AGENTS.md").write_text("fixture governing rules")
        context = self.mirror / "Context.md"
        context.parent.mkdir(parents=True, exist_ok=True)
        context.write_text("fixture current context")
        coord = root / "coord"
        coord.mkdir()
        self.ready = coord / "ready.json"
        self.ready.write_text(json.dumps({"phase": "ready", "ok": True, "completed_at": time.time(),
                                          "heartbeat_at": time.time(), "completed_at_utc": "fixture", "error_code": None}))
        self.vault = Vault(self.mirror, root / "state", self.ready, context="Context.md")
        self.reader = Principal("reader", frozenset({"read"}))
        self.writer = Principal("writer", frozenset({"read", "agent_write"}))

    def test_path_and_write_scope(self):
        for path in ("../outside", "/etc/passwd", "Agents/../Reference/x.md", "Agents/.hidden.md", "Agents\\x.md"):
            with self.assertRaises((ValueError, PermissionError, FileNotFoundError)):
                self.vault.read(self.reader, path)
        (self.mirror / "Agents" / "escape.md").symlink_to(self.mirror / "Reference" / "sample.md")
        with self.assertRaises((ValueError, OSError)):
            self.vault.read(self.reader, "Agents/escape.md")
        with self.assertRaises(PermissionError):
            self.vault.create_note(self.writer, "Reference/new.md", "x", str(uuid.uuid4()))
        with self.assertRaises(PermissionError):
            self.vault.create_note(self.reader, "Agents/new.md", "x", str(uuid.uuid4()))

    def test_exclusive_create_update_and_retry(self):
        request = str(uuid.uuid4())
        first = self.vault.create_note(self.writer, "Agents/new.md", "new", request)
        self.assertEqual(first, self.vault.create_note(self.writer, "Agents/new.md", "new", request))
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/new.md", "other", str(uuid.uuid4()))
        conflict_request = str(uuid.uuid4())
        with self.assertRaisesRegex(PrePublishError, "content conflict"):
            self.vault.update_note(self.writer, "Agents/new.md", "edit", "0" * 64, conflict_request)
        with self.assertRaises(PrePublishError):
            self.vault.update_note(self.writer, "Agents/new.md", "edit", "0" * 64, conflict_request)
        updated = self.vault.update_note(self.writer, "Agents/new.md", "edit", first["sha256"], str(uuid.uuid4()))
        self.assertEqual(updated["sha256"], hashlib.sha256(b"edit").hexdigest())
        nested = self.vault.create_note(self.writer, "Agents/New Project/Notes/first.md", "nested", str(uuid.uuid4()))
        self.assertEqual(nested["path"], "Agents/New Project/Notes/first.md")
        (self.mirror / "Agents" / "evil").symlink_to(self.mirror / "Reference", target_is_directory=True)
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/evil/new.md", "escape", str(uuid.uuid4()))

    def test_atomic_create_failure_and_retry(self):
        request = str(uuid.uuid4())
        with patch("vault_mcp.vault.os.fsync", side_effect=OSError("injected stage failure")):
            with self.assertRaises(PrePublishError):
                self.vault.create_note(self.writer, "Agents/atomic.md", "complete body", request)
        self.assertFalse((self.mirror / "Agents/atomic.md").exists())
        self.assertEqual(list((self.mirror / "Agents").glob(".vault-*.tmp")), [])
        self.vault.create_note(self.writer, "Agents/atomic.md", "complete body", request)
        self.assertEqual((self.mirror / "Agents/atomic.md").read_text(), "complete body")

    def test_equivalent_name_collisions(self):
        (self.mirror / "Agents/Caf\u00e9.md").write_text("old")
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/Cafe\u0301.md", "new", str(uuid.uuid4()))
        (self.mirror / "Agents/Project").mkdir()
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/project/first.md", "new", str(uuid.uuid4()))
        self.assertFalse((self.mirror / "Agents/project").exists())
        (self.mirror / "Agents/Caf\u00e9").mkdir()
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/Cafe\u0301/first.md", "new", str(uuid.uuid4()))

    def test_write_only_cli_filename_rules(self):
        invalid = ("Agents/foo:bar.md", "Agents/a#b.md", 'Agents/a"b.md',
                   "Agents/a>b.md", "Agents/CON.md", "Agents/Project./note.md",
                   "Agents/Project /note.md", "Agents/AUX/note.md")
        for path in invalid:
            request = str(uuid.uuid4())
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "invalid portable filename"):
                self.vault.create_note(self.writer, path, "body", request)
            with sqlite3.connect(self.vault.state / "operations.sqlite3") as db:
                self.assertIsNone(db.execute("SELECT status FROM operations WHERE id=?", (request,)).fetchone())
            self.assertFalse((self.mirror / path).exists())
        legacy = self.mirror / "Agents/legacy#note.md"
        legacy.write_text("existing raw path")
        self.assertEqual(self.vault.read(self.reader, "Agents/legacy#note.md")["text"], "existing raw path")
        result = self.vault.create_note(self.writer, "Agents/Caf\u00e9/na\u00efve.md", "valid Unicode", str(uuid.uuid4()))
        self.assertEqual(result["path"], "Agents/Caf\u00e9/na\u00efve.md")

    def test_detached_write_directory_rejected(self):
        directory = self.mirror / "Agents/Detached"
        def detach(_fd):
            shutil.rmtree(directory)
        with patch("vault_mcp.vault.os.fsync", side_effect=detach):
            with self.assertRaises(PrePublishError):
                self.vault.create_note(self.writer, "Agents/Detached/note.md", "body", str(uuid.uuid4()))
        self.assertFalse((directory / "note.md").exists())

    def test_bootstrap_reads_live_sources(self):
        result = self.vault.bootstrap(self.reader)
        self.assertEqual(result["instructions"]["path"], "AGENTS.md")
        self.assertEqual(result["context"]["text"], "fixture current context")

    def test_search_privacy_and_targeted_read(self):
        self.assertEqual(self.vault.search(self.reader, "reference marker"), [])
        self.assertEqual(self.vault.read(self.reader, "Reference/sample.md")["text"], "reference marker")
        (self.mirror / "Projects" / "target.md").write_text("outside target marker")
        self.assertEqual(self.vault.search(self.reader, "outside target marker"), [])
        self.assertEqual(self.vault.search(self.reader, "outside target marker", "Projects")[0]["path"], "Projects/target.md")
        self.assertEqual(self.vault.search(self.reader, "reference marker", "Reference")[0]["path"], "Reference/sample.md")

    def test_ready_gate(self):
        self.ready.write_text(json.dumps({"phase": "ready", "ok": True, "completed_at": time.time() - 1000,
                                          "heartbeat_at": time.time(), "error_code": None}))
        with self.assertRaises(RuntimeError):
            self.vault.create_note(self.writer, "Agents/blocked.md", "x", str(uuid.uuid4()))

    def test_syncing_and_error_status_block_writes(self):
        for phase in ("syncing", "error"):
            self.ready.write_text(json.dumps({"phase": phase, "ok": False,
                                              "completed_at": time.time(), "completed_at_utc": "fixture",
                                              "heartbeat_at": time.time(), "error_code": "replication_failed" if phase == "error" else None}))
            status = self.vault.storage_status(self.reader)
            self.assertTrue(status["last_success_fresh"])
            self.assertEqual(status["healthy"], phase == "syncing")
            self.assertFalse(status["ready"])
            if phase == "error":
                with self.assertRaises(RuntimeError):
                    self.vault.create_note(self.writer, "Agents/error.md", "body", str(uuid.uuid4()))
        self.ready.write_text(json.dumps({"phase": "syncing", "ok": False,
                                          "completed_at": time.time() - 1000, "completed_at_utc": "old",
                                          "heartbeat_at": time.time(), "error_code": None}))
        self.assertFalse(self.vault.storage_status(self.reader)["healthy"])

    def test_stale_heartbeat_blocks_writes(self):
        self.ready.write_text(json.dumps({"phase": "ready", "ok": True, "completed_at": time.time(),
                                          "heartbeat_at": time.time() - 10, "error_code": None}))
        self.assertFalse(self.vault.storage_status(self.reader)["ready"])
        with self.assertRaises(RuntimeError):
            self.vault.create_note(self.writer, "Agents/stale-heartbeat.md", "x", str(uuid.uuid4()))

    def test_healthy_syncing_waits_before_ledger(self):
        request = str(uuid.uuid4())
        syncing = {"phase": "syncing", "ready": False, "healthy": True}
        ready = {"phase": "ready", "ready": True, "healthy": True}
        with patch.object(self.vault, "storage_status", side_effect=[syncing, ready]), patch("vault_mcp.vault.time.sleep"):
            self.vault.create_note(self.writer, "Agents/after-sync.md", "body", request)
        self.assertEqual((self.mirror / "Agents/after-sync.md").read_text(), "body")

    def test_busy_lock_retry_does_not_consume_request_id(self):
        request = str(uuid.uuid4())
        with self.vault.lock.open("a+") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with patch("vault_mcp.vault.time.monotonic", side_effect=[0, 46]):
                with self.assertRaisesRegex(RuntimeError, "storage busy"):
                    self.vault.create_note(self.writer, "Agents/after-lock.md", "body", request)
        self.vault.create_note(self.writer, "Agents/after-lock.md", "body", request)

    def test_standalone_missing_metadata_and_custom_write_folder(self):
        (self.mirror / "Output").mkdir()
        local = Vault(self.mirror, Path(self.tmp.name) / "local-state", write_folder="Output", context="missing.md")
        self.assertEqual(local.storage_status(self.reader)["mode"], "local")
        self.assertEqual(local.bootstrap(self.reader)["context"]["status"], "missing")
        (self.mirror / "AGENTS.md").unlink()
        self.assertEqual(local.bootstrap(self.reader)["instructions"]["status"], "missing")
        result = local.create_note(self.writer, "Output/Nested/new.md", "local", str(uuid.uuid4()))
        self.assertTrue(result["local_save"])
        self.assertEqual((self.mirror / "Output/Nested/new.md").read_text(), "local")
        self.assertEqual(local.search(self.reader, "local")[0]["path"], "Output/Nested/new.md")
        with self.assertRaises(PermissionError):
            local.create_note(self.writer, "Agents/no.md", "body", str(uuid.uuid4()))

    def test_uuid_payload_and_ambiguous_publication(self):
        request = str(uuid.uuid4())
        self.vault.create_note(self.writer, "Agents/replay.md", "first", request)
        with self.assertRaisesRegex(ValueError, "different content"):
            self.vault.create_note(self.writer, "Agents/replay.md", "different", request)
        request = str(uuid.uuid4())
        real_fsync = __import__("os").fsync
        calls = 0
        def fail_after_publish(fd):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("injected post-publication failure")
            return real_fsync(fd)
        with patch("vault_mcp.vault.os.fsync", side_effect=fail_after_publish):
            with self.assertRaises(OSError):
                self.vault.create_note(self.writer, "Agents/ambiguous.md", "once", request)
        self.assertEqual((self.mirror / "Agents/ambiguous.md").read_text(), "once")
        with self.assertRaisesRegex(RuntimeError, "ambiguous"):
            self.vault.create_note(self.writer, "Agents/ambiguous.md", "once", request)

    def test_guard_failures_allow_same_uuid_after_recovery(self):
        good = self.ready.read_text()
        failures = [None, "not json", "[]", "null"]
        marker = json.loads(good)
        for overrides in ({"phase": "stopped"}, {"phase": "error", "error_code": "failed"},
                          {"ok": False}, {"heartbeat_at": time.time()-6},
                          {"completed_at": time.time()-91}, {"heartbeat_at": time.time()+10},
                          {"completed_at": None}, {"phase": []}):
            failures.append(json.dumps({**marker, **overrides}))
        for index, body in enumerate(failures):
            with self.subTest(index=index):
                request = str(uuid.uuid4())
                if body is None:
                    self.ready.unlink()
                else:
                    self.ready.write_text(body)
                self.assertFalse(self.vault.storage_status(self.reader)["ready"])
                path = f"Agents/recover-{index}.md"
                with self.assertRaises(RuntimeError):
                    self.vault.create_note(self.writer, path, "body", request)
                self.assertFalse((self.mirror / path).exists())
                self.ready.write_text(good)
                self.vault.create_note(self.writer, path, "body", request)
                self.assertEqual((self.mirror / path).read_text(), "body")

    def test_guard_freshness_boundaries_and_busy_timeout(self):
        now = 2000
        for heartbeat, completed, expected in ((5, 90, True), (5.01, 90, False),
                                                (5, 90.01, False), (-1, 0, False)):
            self.ready.write_text(json.dumps({"phase": "ready", "ok": True,
                                              "heartbeat_at": now-heartbeat, "completed_at": now-completed}))
            with patch("vault_mcp.vault.time.time", return_value=now):
                self.assertEqual(self.vault.storage_status(self.reader)["ready"], expected)
        request = str(uuid.uuid4())
        self.ready.write_text(json.dumps({"phase": "syncing", "ok": False,
                                          "heartbeat_at": time.time(), "completed_at": time.time()}))
        with patch("vault_mcp.vault.time.monotonic", side_effect=[0, 46]):
            with self.assertRaisesRegex(RuntimeError, "storage busy"):
                self.vault.create_note(self.writer, "Agents/after-busy.md", "body", request)
        with sqlite3.connect(self.vault.state / "operations.sqlite3") as db:
            self.assertIsNone(db.execute("SELECT id FROM operations WHERE id=?", (request,)).fetchone())
        self.ready.write_text(json.dumps({"phase": "ready", "ok": True,
                                          "heartbeat_at": time.time(), "completed_at": time.time()}))
        self.vault.create_note(self.writer, "Agents/after-busy.md", "body", request)
        self.assertEqual((self.mirror / "Agents/after-busy.md").read_text(), "body")

    def test_shared_group_modes_survive_nested_create_and_atomic_update(self):
        (self.mirror / "Agents").chmod(0o2770)
        previous_umask = os.umask(0o077)
        try:
            first = self.vault.create_note(self.writer, "Agents/Shared/Nested/note.md", "created", str(uuid.uuid4()))
            note = self.mirror / first["path"]
            self.assertEqual(stat.S_IMODE(note.stat().st_mode), 0o660)
            self.assertEqual(note.stat().st_gid, (self.mirror / "Agents").stat().st_gid)
            for path in ("Agents/Shared", "Agents/Shared/Nested"):
                directory = self.mirror / path
                self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o2770)
                self.assertEqual(directory.stat().st_gid, note.stat().st_gid)
            note.chmod(0o600)
            self.vault.update_note(self.writer, first["path"], "updated", first["sha256"], str(uuid.uuid4()))
            self.assertEqual(note.read_text(), "updated")
            self.assertEqual(stat.S_IMODE(note.stat().st_mode), 0o660)
            self.assertEqual(note.stat().st_gid, (self.mirror / "Agents").stat().st_gid)
            self.assertEqual(stat.S_IMODE(self.vault.state.stat().st_mode), 0o700)
        finally:
            os.umask(previous_umask)

    def test_live_bootstrap_and_bounds(self):
        (self.mirror / "AGENTS.md").write_text("updated fixture rules")
        self.assertEqual(self.vault.bootstrap(self.reader)["instructions"]["text"], "updated fixture rules")
        (self.mirror / "Agents/large.md").write_bytes(b"x" * (256*1024+1))
        with self.assertRaises(ValueError):
            self.vault.read(self.reader, "Agents/large.md")
        with self.assertRaises(PrePublishError):
            self.vault.create_note(self.writer, "Agents/oversize.md", "x" * (64*1024+1), str(uuid.uuid4()))
        for request in ("invalid", str(uuid.uuid4()).upper()):
            with self.assertRaises(ValueError):
                self.vault.create_note(self.writer, "Agents/no.md", "body", request)
        self.assertFalse((self.mirror / "Agents/no.md").exists())


if __name__ == "__main__":
    unittest.main()
