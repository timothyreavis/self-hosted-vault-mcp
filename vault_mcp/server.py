"""Thin stateless Streamable HTTP adapter; every request authenticates first."""
from fastmcp import FastMCP
from fastmcp.exceptions import ToolError

from .auth import AccessASGI, principal
from .config import Config, configured_verifier
from .vault import PrePublishError, Vault


def _call(method, *args):
    try:
        return method(principal(), *args)
    except (FileNotFoundError, NotADirectoryError):
        raise ToolError("not found") from None
    except (ValueError, PermissionError, PrePublishError, RuntimeError) as error:
        # Expected failures stay actionable; unexpected filesystem errors are masked.
        raise ToolError(str(error)) from None


def create_app(config: Config | None = None, verifier=None):
    # Authenticate configuration before opening any vault/state storage.
    verifier = verifier if verifier is not None else configured_verifier()
    config = config if config is not None else Config.from_env()
    vault = Vault(config.root, config.state, config.ready, config.write_folder, config.instructions,
                  config.context, config.denied_paths)
    mcp = FastMCP("Self-hosted Vault MCP", mask_error_details=True, instructions=(
        "Call bootstrap for live owner instructions and optional context. Missing files do not grant "
        "additional authority. Read only relevant paths; routine writes stay in the configured write folder."))

    @mcp.tool
    def bootstrap() -> dict:
        """Read live optional owner instructions/context, with missing-file metadata."""
        return _call(vault.bootstrap)

    @mcp.tool
    def list_files(prefix: str | None = None, limit: int = 100,
                   modified_after: str | None = None, modified_before: str | None = None) -> list[str]:
        """List recursively in the write folder by default; empty prefix lists root entries. Optional aware RFC3339 mtime window is [after, before)."""
        return _call(vault.list_files, prefix, limit, modified_after, modified_before)

    @mcp.tool
    def list_files_page(prefix: str | None = None, limit: int = 100, cursor: str | None = None,
                        modified_after: str | None = None, modified_before: str | None = None) -> dict:
        """List with bounded continuation and explicit scan coverage; optional aware RFC3339 mtime window [after, before)."""
        return _call(vault.list_files_page, prefix, limit, cursor, modified_after, modified_before)

    @mcp.tool
    def read_file(path: str) -> dict:
        """Read one visible file with SHA-256 and UTC modified_at, bounded to 256 KiB."""
        return _call(vault.read, path)

    @mcp.tool
    def search_notes(query: str, prefix: str | None = None, limit: int = 20,
                     modified_after: str | None = None, modified_before: str | None = None) -> list[dict]:
        """Search bounded Markdown content; default write folder, empty prefix searches the vault. Optional aware RFC3339 mtime window is [after, before)."""
        return _call(vault.search, query, prefix, limit, modified_after, modified_before)

    @mcp.tool
    def search_notes_page(query: str, prefix: str | None = None, limit: int = 20,
                          cursor: str | None = None, modified_after: str | None = None,
                          modified_before: str | None = None) -> dict:
        """Search with bounded continuation and explicit scan coverage; optional aware RFC3339 mtime window [after, before)."""
        return _call(vault.search_notes_page, query, prefix, limit, cursor, modified_after, modified_before)

    @mcp.tool
    def create_note(path: str, content: str, request_id: str) -> dict:
        """Exclusively create a Markdown note; reuse the UUID for identical retries."""
        return _call(vault.create_note, path, content, request_id)

    @mcp.tool
    def update_note(path: str, content: str, expected_sha256: str, request_id: str) -> dict:
        """Replace a Markdown note only when its current SHA-256 matches."""
        return _call(vault.update_note, path, content, expected_sha256, request_id)

    @mcp.tool
    def storage_status() -> dict:
        """Report local mode or optional external readiness; never claim sync convergence."""
        return _call(vault.storage_status)

    return AccessASGI(mcp.http_app(stateless_http=True, json_response=True), verifier)
