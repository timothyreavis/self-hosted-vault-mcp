# Self-hosted Vault MCP

Give an MCP client access to a Markdown or Obsidian folder on your server. Read relevant files, search a selected subtree, and create or update notes in one configured folder (default `Agents`). No running Obsidian app or synchronization plugin is needed.

Cloudflare Access authenticates every request. The server verifies signed Access assertions and uses stateless Streamable HTTP at `/mcp`.

## Quick start

You need a Linux server with Docker Engine and Docker Compose v2, an existing vault folder, and a Cloudflare account with a domain, Tunnel, and Access. The image uses Python 3.12. A direct Python installation needs Python 3.12+ with venv/pip and the dependencies in `requirements.txt`.

1. Download this source and copy `.env.example` to `.env`. Set the vault, state, and write-folder paths. Follow the concrete [storage permission instructions](AGENTS.md#storage-permissions) to match the vault owner's numeric UID/GID, or use a dedicated service identity and shared group. The defaults are nonroot `10001:10001`; do not recursively change your vault's ownership.
2. Follow the ordered [Cloudflare setup](AGENTS.md#cloudflare-and-client-setup): create the tunnel route, protect the entire hostname with Access, configure Managed OAuth (or a bot's Service Auth policy), and save the tunnel token through your password manager into its private file. Fill the corresponding `.env` settings and choose a published cloudflared image version, pinned to its digest for production.
3. Run `docker compose up -d --build`. Compose publishes no origin host port.
4. Connect your Streamable HTTP MCP client to `https://vault.example.com/mcp`, complete Access login, and call `bootstrap`.

Ask your agent to follow [AGENTS.md](AGENTS.md) for detailed configuration and a synthetic-note verification. Missing `AGENTS.md` or optional context in the served vault is reported honestly; the server invents no owner rules.

## Tools

| Tool | Purpose |
| --- | --- |
| `bootstrap` | Live owner instructions and optional context, including hashes or missing metadata |
| `list_files` | Recursive files in the write folder by default; explicit `prefix: ""` lists immediate root entries, with `/` after directory names |
| `list_files_page` | Preferred discovery; same prefix defaults, up to 200 items per page, with continuation and coverage |
| `read_file` | One explicit visible file, with SHA-256 (up to 256 KiB) |
| `search_notes` | Legacy bounded Markdown search; fails with a page-tool hint when the answer is incomplete |
| `search_notes_page` | Preferred Markdown search; same prefix defaults, up to 50 matches and 1,000 scanned entries per page |
| `create_note` | Exclusive atomic creation, including new nested folders |
| `update_note` | Atomic replacement with an expected SHA-256 precondition |
| `storage_status` | Local persistence mode or optional external readiness guard |

Writes require `agent_write`, a portable `.md` path inside the write folder, content no larger than 64 KiB, and a canonical UUID `request_id`. Use the same UUID and payload on retry. Hash conflicts do not overwrite the file. A crash after possible publication leaves an ambiguous ledger entry: inspect the actual file before deciding what to do. Do not bypass ambiguity with a fresh UUID blindly.

## Storage and limits

A successful save confirms local filesystem persistence. It does **not** confirm synchronization to another device. Use a separately managed synchronization solution if needed; this project bundles none. Standalone writes work as soon as valid storage and authentication are configured. An optional external-readiness guard is documented in AGENTS.md and fails closed whenever configured.

The mutex coordinates MCP writers sharing the state directory. It is not a distributed lock; external editors and synchronizers can race a hash check. Use one MCP instance and avoid concurrent external edits to agent-owned notes. Keep backups of the vault and private state together; the state ledger preserves retry history and contains stored operation receipts.

Hidden paths, traversal, and symlinks are blocked. Visible files elsewhere in the vault can be read explicitly. This is one vault trust boundary, not a per-folder multi-user permission system. Notes are untrusted data; the owner's instructions govern permitted use.

Set `VAULT_DENIED_PATHS` to semicolon-separated visible relative paths, for example `Private;Agents/Archive`, to exclude those paths and descendants from generic reads, bootstrap, discovery, and writes. Matching uses Unicode NFC and casefolded path components, so `Privateer` is unaffected. The empty default keeps prior access. The configured write folder itself cannot be excluded. Restart after changing this setting.

Prefer the page tools for discovery. Their envelope contains `items`, `scanned`, `skipped`, `truncated`, and `next_cursor`. `scanned` counts examined visible entries in this call; `skipped` counts entries that could not be examined or read. A page may have no items and still have a cursor. Follow cursors until `next_cursor` is null and inspect skipped counts before claiming complete content coverage. Cursors bind to the operation, query, prefix and exclusion policy; malformed or mismatched cursors fail. They hold traversal position, not access rights or a snapshot of concurrent vault edits. Legacy `list_files` and `search_notes` retain their inputs and list output shapes when complete, and return an actionable error when bounded results are incomplete.

For existing clients, keep their legacy calls while upgrading them to follow page cursors. Reconnect after the server restarts so the client discovers the new tools. Start a new search after changing the query, prefix, or exclusion setting; an old cursor will be rejected. A completed page traversal proves only what this server could read during that traversal. It does not prove remote synchronization or a stable snapshot while another editor changes files.

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install --index-url https://pypi.org/simple --require-hashes -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip wheel --no-deps --wheel-dir dist .
```

The tests use synthetic temporary files and locally signed assertions through the real ASGI/MCP transport, with a fixture signing key resolver. They do not establish real Cloudflare configuration or native-client compatibility. CI also builds the container. Follow the deployment verification in AGENTS.md for your actual environment.

Source-available under [PolyForm Perimeter 1.0.1](LICENSE). Personal and internal business use are allowed; providing competing products or services is restricted, including free competing offerings. Exceptions for competing commercial or free offerings require separate permission from the copyright owner. See [NOTICE](NOTICE). Runtime dependencies FastMCP, PyJWT with cryptography, and Uvicorn retain their respective upstream licenses; cloudflared is a separate container maintained by Cloudflare.
