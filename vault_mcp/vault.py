"""Single vault path and permission kernel. All caller adapters use this class."""
import fcntl
import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import time
import unicodedata
import uuid
from contextlib import contextmanager
from pathlib import Path

from .auth import Principal


WINDOWS_FORBIDDEN = re.compile(r'["\\:?#<>|*]')
WINDOWS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.IGNORECASE)
READ_LIMIT = 256 * 1024
NOTE_LIMIT = 64 * 1024
SEARCH_LIMIT = 1000
CURSOR_LIMIT = 4096


class PrePublishError(RuntimeError):
    """The target was not published; its request UUID may safely be retried."""


def _equivalent_name(left: str, right: str) -> bool:
    return unicodedata.normalize("NFC", left).casefold() == unicodedata.normalize("NFC", right).casefold()


def _reject_sibling_collision(dir_fd: int, name: str) -> None:
    if any(_equivalent_name(existing, name) for existing in os.listdir(dir_fd)):
        raise FileExistsError("equivalent sibling already exists")


def safe_parts(path: str) -> tuple[str, ...]:
    if not isinstance(path, str) or not path or path.startswith("/") or "\\" in path:
        raise ValueError("invalid path")
    parts = tuple(path.split("/"))
    if any(p in ("", ".", "..") or p.startswith(".") or any(ord(c) < 32 or ord(c) == 127 for c in p) for p in parts):
        raise ValueError("invalid path")
    return parts


def write_parts(path: str) -> tuple[str, ...]:
    """Portable CLI write identity; reads retain existing raw vault path spellings."""
    parts = safe_parts(path)
    if any(WINDOWS_FORBIDDEN.search(part) or part.endswith((" ", ".")) or WINDOWS_RESERVED.match(part) for part in parts):
        raise ValueError("invalid portable filename")
    return parts


def _identity(parts: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)


def policy_parts(paths) -> tuple[tuple[str, ...], ...]:
    if not isinstance(paths, (tuple, list)):
        raise ValueError("invalid VAULT_DENIED_PATHS")
    result = []
    for path in paths:
        parts = _identity(safe_parts(path))
        if parts in result:
            raise ValueError("duplicate VAULT_DENIED_PATHS")
        result.append(parts)
    return tuple(result)


class Vault:
    denied_paths: tuple[tuple[str, ...], ...] = ()  # Legacy object.__new__ read views default to empty policy.
    def __init__(self, root: Path, state: Path, ready: Path | None = None,
                 write_folder: str = "Agents", instructions: str = "AGENTS.md", context: str | None = None,
                 denied_paths: tuple[str, ...] = ()):
        from .config import validate_paths
        validate_paths(root, state, ready, write_folder, instructions, context, denied_paths)
        self.root, self.state, self.ready = root, state, ready
        self.write_folder, self.instructions, self.context = write_folder, instructions, context
        self.write_root = write_parts(write_folder)
        self.denied_paths = policy_parts(denied_paths)
        self.lock = state / "operations.lock"
        state.mkdir(mode=0o700, parents=True, exist_ok=True)
        with sqlite3.connect(state / "operations.sqlite3") as db:
            db.execute("CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, fingerprint TEXT NOT NULL, status TEXT NOT NULL, result TEXT)")

    def _directory(self, parts: tuple[str, ...], create: bool = False) -> int:
        """Walk pinned directory descriptors; never follow a symlink ancestor."""
        fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            for index, part in enumerate(parts):
                created = False
                if create and index >= len(self.write_root):
                    names = os.listdir(fd)
                    if part not in names:
                        if any(_equivalent_name(name, part) for name in names):
                            raise FileExistsError("equivalent ancestor already exists")
                        os.mkdir(part, 0o770, dir_fd=fd)
                        created = True
                        os.fsync(fd)
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                if created:
                    os.fchmod(fd, 0o770 | (os.fstat(fd).st_mode & stat.S_ISGID))
                if os.fstat(fd).st_nlink == 0:
                    raise OSError("write directory was detached")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _read_bytes(self, path: str, limit: int = READ_LIMIT) -> bytes:
        parts = safe_parts(path)
        self._allowed(parts)
        fd = self._directory(parts[:-1])
        try:
            file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            with os.fdopen(file_fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("not a regular file")
                data = stream.read(limit + 1)
            if len(data) > limit:
                raise ValueError("file exceeds read limit")
            return data
        finally:
            os.close(fd)

    def _writable(self, path: str) -> None:
        parts = write_parts(path)
        self._allowed(parts)
        if parts[:len(self.write_root)] != self.write_root or len(parts) <= len(self.write_root):
            raise PermissionError("write outside configured folder")
        if not path.endswith(".md"):
            raise ValueError("notes must use .md extension")

    def _allowed(self, parts: tuple[str, ...]) -> None:
        identity = _identity(parts)
        if any(identity[:len(denied)] == denied for denied in self.denied_paths):
            raise PermissionError("path excluded by vault policy")

    def read(self, actor: Principal, path: str) -> dict:
        actor.require("read")
        data = self._read_bytes(path)
        result = {"path": path, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        try:
            result["text"] = data.decode("utf-8")
        except UnicodeDecodeError:
            result["kind"] = "attachment"
        return result

    def bootstrap(self, actor: Principal) -> dict:
        """Read live optional owner metadata; never invent missing instructions."""
        actor.require("read")
        def optional(path):
            if path is None:
                return {"path": None, "status": "not_configured"}
            try:
                return {"status": "present", **self.read(actor, path)}
            except FileNotFoundError:
                return {"path": path, "status": "missing"}
        return {"instructions": optional(self.instructions), "context": optional(self.context),
                "write_folder": self.write_folder}

    def _files(self, prefix: str, recursive: bool = True):
        parts = () if prefix == "" else safe_parts(prefix)
        self._allowed(parts)
        def walk(fd, parents):
            try:
                names = sorted(os.listdir(fd))
            except OSError:
                yield (None, parents)
                return
            for name in names:
                if name.startswith("."):
                    continue
                child_parts = (*parents, name)
                if any(_identity(child_parts)[:len(denied)] == denied for denied in self.denied_paths):
                    continue
                try:
                    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                except OSError:
                    yield (None, child_parts)
                    continue
                if stat.S_ISREG(info.st_mode):
                    yield "/".join(child_parts)
                elif stat.S_ISDIR(info.st_mode):
                    if not recursive:
                        yield "/".join(child_parts) + "/"
                        continue
                    try:
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    except OSError:
                        yield (None, child_parts)
                        continue
                    try:
                        yield from walk(child, child_parts)
                    finally:
                        os.close(child)
        fd = self._directory(parts)
        try:
            yield from walk(fd, parts)
        finally:
            os.close(fd)

    def _cursor(self, operation: str, prefix: str, query: str | None, cursor: str | None):
        binding = hashlib.sha256(json.dumps([operation, prefix, query, self.denied_paths],
                                            ensure_ascii=False).encode()).hexdigest()
        if cursor is None:
            return binding, None
        if (not isinstance(cursor, str) or not cursor or len(cursor) > CURSOR_LIMIT
                or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor)):
            raise ValueError("invalid cursor")
        try:
            raw = base64.b64decode(cursor + "=" * (-len(cursor) % 4), altchars=b"-_", validate=True)
            value = json.loads(raw)
            after = value["after"]
            if (value["v"] != 1 or value["binding"] != binding or not isinstance(after, list)
                    or not after or any(not isinstance(part, str) or not part for part in after)
                    or set(value) != {"v", "binding", "after"}):
                raise ValueError
            # Cursors are positions only; path policy remains enforced by the current traversal.
            safe_parts("/".join(after))
            return binding, tuple(after)
        except (ValueError, KeyError, TypeError, UnicodeError, base64.binascii.Error):
            raise ValueError("invalid cursor") from None

    def _page(self, actor: Principal, operation: str, prefix: str | None, limit: int,
              cursor: str | None, query: str | None = None) -> dict:
        actor.require("read")
        max_items = 200 if operation == "list" else 50
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= max_items:
            raise ValueError("invalid limit")
        if operation == "search" and (not isinstance(query, str) or not query or len(query) > 200):
            raise ValueError("invalid search")
        selected = self.write_folder if prefix is None else prefix
        if selected != "":
            safe_parts(selected)
        binding, after = self._cursor(operation, selected, query, cursor)
        items, scanned, skipped = [], 0, 0
        last = after
        paths = self._files(selected, recursive=operation == "search" or selected != "")
        try:
            for relative in paths:
                key = relative[1] if isinstance(relative, tuple) else tuple(relative.rstrip("/").split("/"))
                if after is not None and key <= after:
                    continue
                if scanned >= SEARCH_LIMIT or len(items) >= limit:
                    break
                scanned += 1
                last = key
                if isinstance(relative, tuple):
                    skipped += 1
                    continue
                if operation == "list":
                    items.append(relative)
                elif relative.lower().endswith(".md"):
                    if query.casefold() in relative.casefold():
                        items.append({"path": relative, "match": "filename"})
                    else:
                        try:
                            lines = self._read_bytes(relative).decode("utf-8", errors="replace").splitlines()
                        except (OSError, ValueError):
                            skipped += 1
                            continue
                        for number, line in enumerate(lines, 1):
                            if query.casefold() in line.casefold():
                                items.append({"path": relative, "line": number, "excerpt": line.strip()[:240]})
                                break
            else:
                return {"items": items, "scanned": scanned, "skipped": skipped,
                        "truncated": False, "next_cursor": None}
        finally:
            paths.close()
        encoded = base64.urlsafe_b64encode(json.dumps({"v": 1, "binding": binding, "after": last},
                                                     separators=(",", ":")).encode()).decode().rstrip("=")
        return {"items": items, "scanned": scanned, "skipped": skipped,
                "truncated": True, "next_cursor": encoded}

    def list_files_page(self, actor: Principal, prefix: str | None = None, limit: int = 100,
                        cursor: str | None = None) -> dict:
        return self._page(actor, "list", prefix, limit, cursor)

    def search_notes_page(self, actor: Principal, query: str, prefix: str | None = None,
                          limit: int = 20, cursor: str | None = None) -> dict:
        return self._page(actor, "search", prefix, limit, cursor, query)

    def list_files(self, actor: Principal, prefix: str | None = None, limit: int = 100) -> list[str]:
        page = self.list_files_page(actor, prefix, limit)
        if page["truncated"] or page["skipped"]:
            raise ValueError("list incomplete; use list_files_page and inspect skipped")
        return page["items"]

    def search(self, actor: Principal, query: str, prefix: str | None = None, limit: int = 20) -> list[dict]:
        page = self.search_notes_page(actor, query, prefix, limit)
        if page["truncated"] or page["skipped"]:
            raise ValueError("search incomplete; use search_notes_page and inspect skipped")
        return page["items"]

    def storage_status(self, actor: Principal) -> dict:
        actor.require("read")
        if self.ready is None:
            return {"mode": "local", "ready": True, "local_persistence_only": True,
                    "external_sync_verified": False}
        try:
            marker = json.loads(self.ready.read_text())
            if not isinstance(marker, dict):
                raise ValueError("invalid readiness document")
            phase = marker["phase"]
            completed_at = marker.get("completed_at")
            age = time.time() - float(completed_at) if completed_at is not None else None
            heartbeat_age = time.time() - float(marker["heartbeat_at"])
            completion_fresh = age is not None and 0 <= age <= 90
            heartbeat_fresh = 0 <= heartbeat_age <= 5
            healthy = phase in {"ready", "syncing"} and heartbeat_fresh and completion_fresh and marker.get("error_code") is None
            ready = phase == "ready" and marker.get("ok") is True and healthy
            return {"mode": "external_guard", "local_persistence_only": True, "external_sync_verified": False, "phase": phase, "ready": ready, "healthy": healthy,
                    "last_success_fresh": completion_fresh, "last_success_utc": marker.get("completed_at_utc"),
                    "age_seconds": round(age, 1) if age is not None else None,
                    "heartbeat_age_seconds": round(heartbeat_age, 1), "error_code": marker.get("error_code")}
        except (OSError, ValueError, KeyError, TypeError):
            return {"mode": "external_guard", "local_persistence_only": True, "external_sync_verified": False, "phase": "unavailable", "ready": False, "healthy": False,
                    "last_success_fresh": False, "last_success_utc": None, "age_seconds": None,
                    "heartbeat_age_seconds": None, "error_code": None}

    @contextmanager
    def _write_guard(self):
        with self.lock.open("a+") as lock:
            deadline = time.monotonic() + 45
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise RuntimeError("storage busy; retry with the same request UUID")
                    time.sleep(0.1)
            while self.ready is not None:
                status = self.storage_status(Principal("internal", frozenset({"read"})))
                if status["ready"]:
                    break
                if status["phase"] != "syncing" or not status["healthy"]:
                    raise RuntimeError("external readiness guard denied write")
                if time.monotonic() >= deadline:
                    raise RuntimeError("storage busy; retry with the same request UUID")
                time.sleep(0.1)
            yield

    def _operation(self, request_id: str, fingerprint: str, action):
        if str(uuid.UUID(request_id)) != request_id:
            raise ValueError("canonical request UUID required")
        with self._write_guard(), sqlite3.connect(self.state / "operations.sqlite3", timeout=10) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT fingerprint,status,result FROM operations WHERE id=?", (request_id,)).fetchone()
            if row:
                if row[0] != fingerprint:
                    raise ValueError("request ID reused with different content")
                if row[1] == "complete":
                    return json.loads(row[2])
                raise RuntimeError("ambiguous prior write; inspect source before retry")
            db.execute("INSERT INTO operations VALUES (?,?,?,NULL)", (request_id, fingerprint, "pending"))
            db.commit()  # Crash after this point remains ambiguous, so retries cannot duplicate writes.
            try:
                result = action()
            except PrePublishError:
                db.execute("DELETE FROM operations WHERE id=? AND status='pending'", (request_id,))
                db.commit()
                raise
            db.execute("UPDATE operations SET status='complete', result=? WHERE id=?", (json.dumps(result), request_id))
            db.commit()
            return result

    def _write(self, path: str, content: str, exclusive: bool, expected_sha: str | None = None) -> dict:
        published = False
        temporary = None
        fd = None
        try:
            write_parts(path)
            data = content.encode("utf-8")
            if len(data) > NOTE_LIMIT:
                raise ValueError("note exceeds write limit")
            parts = write_parts(path)
            fd = self._directory(parts[:-1], create=exclusive)
            name = parts[-1]
            if exclusive:
                _reject_sibling_collision(fd, name)
            else:
                if not re.fullmatch(r"[0-9a-f]{64}", expected_sha or ""):
                    raise ValueError("expected SHA-256 required")
                original = self._read_bytes(path, NOTE_LIMIT)
                if hashlib.sha256(original).hexdigest() != expected_sha:
                    raise PrePublishError("content conflict")
            temporary = f".vault-{uuid.uuid4().hex}.tmp"
            out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o660, dir_fd=fd)
            with os.fdopen(out, "wb") as stream:
                os.fchmod(stream.fileno(), 0o660)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            if os.fstat(fd).st_nlink == 0:
                raise OSError("write directory was detached")
            if exclusive:
                # Same-directory hardlink publishes all bytes atomically and never replaces a file.
                os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            else:
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            published = True
            if exclusive:
                os.unlink(temporary, dir_fd=fd)
                temporary = None
            else:
                temporary = None
            os.fsync(fd)
        except Exception as error:
            if not published:
                if isinstance(error, PrePublishError):
                    raise
                if isinstance(error, ValueError) and str(error) in {"invalid portable filename", "note exceeds write limit", "expected SHA-256 required"}:
                    raise PrePublishError(str(error)) from None
                raise PrePublishError(type(error).__name__) from None
            raise
        finally:
            if temporary is not None and fd is not None:
                try:
                    os.unlink(temporary, dir_fd=fd)
                except OSError:
                    pass
            if fd is not None:
                os.close(fd)
        return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "local_save": True,
                "external_sync_verified": False}

    def create_note(self, actor: Principal, path: str, content: str, request_id: str) -> dict:
        actor.require("agent_write")
        self._writable(path)
        write_parts(path)
        fingerprint = hashlib.sha256(f"create\0{path}\0{content}".encode()).hexdigest()
        return self._operation(request_id, fingerprint, lambda: self._write(path, content, True))

    def update_note(self, actor: Principal, path: str, content: str, expected_sha: str, request_id: str) -> dict:
        actor.require("agent_write")
        self._writable(path)
        write_parts(path)
        fingerprint = hashlib.sha256(f"update\0{path}\0{expected_sha}\0{content}".encode()).hexdigest()
        return self._operation(request_id, fingerprint, lambda: self._write(path, content, False, expected_sha))
