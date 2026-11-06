# Agent setup and repository guide

This file guides agents configuring or maintaining this server. It does not supply instructions for the served vault. The vault's own live `AGENTS.md` is separate. Do not copy this file into a user's vault as their policy.

## Scope and development

Keep one filesystem kernel in `vault_mcp/vault.py`, one authentication boundary in `auth.py`, one environment configuration owner in `config.py`, and thin registered MCP tools in `server.py`. Preserve per-request authentication, path guards, narrow writes, SHA preconditions, and durable UUID replay/ambiguity handling. Do not add hidden-file access, shell execution, or delete/rename tools.

Use synthetic temporary files for development and tests. Never read a real vault or credentials to debug a fixture. Run the commands in README. Test transport responses and actual file outcomes, not response substring matches. Authentication, filesystem, configuration, and deployment changes need independent security review before release.

## Configure an owner deployment

Ask the owner which existing server folder to serve, which single visible folder agents may write, who may connect, and whether they already run outside synchronization. Keep credentials in the owner's password manager and settings in one private deployment configuration. Do not invent extra feature toggles. Once storage and required authentication are valid, standalone filesystem operations are enabled.

Use absolute host paths in `.env`; it is ignored by Git. The server requires existing vault and write directories, rejects symlink configuration paths, and creates only its separate state directory. Back up state with the vault and restrict state access to the server operator. The SQLite ledger stores fingerprints, pending/completed states, and receipts, not full note bodies. Retain it for retry safety.

| Server variable | Default / meaning |
| --- | --- |
| `VAULT_ROOT` | `/vault`; existing vault directory |
| `VAULT_STATE` | `/state`; separate private writable directory |
| `VAULT_WRITE_FOLDER` | `Agents`; existing visible relative folder, possibly nested |
| `VAULT_INSTRUCTIONS_PATH` | `AGENTS.md`; optional live file relative to the vault |
| `VAULT_DENIED_PATHS` | Empty by default; semicolon-separated visible relative path prefixes denied from generic reads, discovery, and writes |
| `VAULT_CONTEXT_PATH` | Unset; optional live context file relative to the vault |
| `VAULT_EXTERNAL_READY_FILE` | Unset; optional absolute readiness JSON path outside the vault |
| `CF_ACCESS_TEAM` | Required team label, such as `example-team`, not a URL |
| `CF_ACCESS_AUD` | Required exact Access application AUD |
| `VAULT_ALLOWED_USERS` | Exact emails: `owner@example.invalid=read,agent_write` |
| `VAULT_ALLOWED_SERVICES` | Exact service Client IDs: `fixture-reader.access=read` |

Multiple allowlist entries use semicolons; scopes use commas. The only scopes are `read` and `agent_write`. Scope sets are explicit per principal; no wildcard, domain-wide, or permissive mode exists. Empty combined allowlists prevent startup. A service assertion must match the service list; it cannot fall back to a user entry. Restart the process after changing settings. For a direct Python installation, set these variables in the process environment through your private service configuration, then run `.venv/bin/python -m vault_mcp`; the server does not automatically load a `.env` file outside Compose.

Compose maps the host paths `VAULT_HOST_PATH`, `VAULT_STATE_PATH`, and `TUNNEL_TOKEN_FILE`. The same `VAULT_WRITE_FOLDER` value controls both code enforcement and the nested read/write bind mount. The full vault mount stays read-only. Compose deliberately does not pass arbitrary environment variables through to the server. To configure optional context, add `VAULT_CONTEXT_PATH: Context.md` under the MCP service's `environment` using a local Compose override. Do not change the full-vault mount to read/write.

Compose passes `VAULT_DENIED_PATHS` explicitly. Configure it in `.env` using semicolons and visible relative path prefixes, such as `Private;Agents/Archive`; no globs or regular expressions. It excludes matching path components and descendants from generic reads, bootstrap, list/search and writes. Empty is the compatibility default. It cannot exclude the write folder itself. Use `list_files_page` and `search_notes_page` for discovery; follow `next_cursor` until null and inspect `skipped`. Legacy list/search return their original list shapes only when complete and otherwise direct clients to the page tools.

## Storage permissions

Keep runtime IDs in **one place**, `.env`: `VAULT_UID` and `VAULT_GID` are used by both containers. Defaults are `10001:10001`; set positive numeric IDs for your deployment. Never set UID 0. The Python entry point rejects root. `HOME=/tmp` supports numeric IDs that do not have an account entry in the image. Restart after changing IDs.

**Normal vault owner (recommended):** set `VAULT_UID` to that owner's `id -u` and `VAULT_GID` to their `id -g`. Existing notes then remain readable to the same owner after atomic replacement. The defaults also work when the vault is already managed by UID/GID 10001. Create the chosen write folder if missing and allow that owner to write it. Only the selected folder is mounted writable.

**Separate service identity with a shared group:** leave `VAULT_UID=10001` or select another dedicated nonroot UID. Set `VAULT_GID` to an existing group shared with the vault owner and synchronizer. The host users must be members of this group (a new login may be needed). Set the write folder's group to that GID and enable setgid and group write. For synthetic defaults:

```sh
sudo mkdir -p /srv/example-vault/Agents /srv/example-vault-mcp-state /srv/example-vault-mcp-secrets
sudo chgrp 10001 /srv/example-vault/Agents
sudo chmod 2770 /srv/example-vault/Agents
sudo chown 10001:10001 /srv/example-vault-mcp-state
sudo chmod 700 /srv/example-vault-mcp-state /srv/example-vault-mcp-secrets
```

Replace the numeric IDs with your `.env` choices. These commands do not change ownership of existing vault notes. Give the runtime identity traversal/read access on the remaining vault for its read-only mount; do not make it world-readable. For existing notes or subfolders inside the write folder, the owner must grant the shared group the necessary read/write/traversal access on those selected paths. Do not run blanket recursive `chown` on the vault.

New and atomically replaced notes have mode **0660**. New subfolders have **0770**, preserving inherited **setgid** from their parent so the selected shared group continues into nested folders. These mode bits are enforced even if the calling process had a restrictive umask; the service starts with umask **0007**. Updates replace the file's inode and set these documented modes rather than retaining an old inode's owner or ACL. Arrange the UID/group as above; do not rely on custom ACL inheritance for additional identities. Nothing grants access to users outside the owner/group.

Keep private state **separate from the vault**, owned by `VAULT_UID`, mode **0700**; the server creates a missing state directory with that mode. It contains the retry ledger and is not a shared-group data folder. Save the tunnel token through the owner's secret workflow, set its file owner to the chosen UID/GID and mode **0400**; only cloudflared mounts that file. Never paste tokens into a shell command, repository, chat transcript, or log.

The image needs outbound HTTPS for Access signing keys. cloudflared needs its normal outbound Tunnel connectivity. No origin host port is published. Keep untrusted containers off these networks. Use one MCP instance with its private state; the advisory mutex does not coordinate external editors.

## Dependency maintenance

`requirements.in` owns the three direct PEP 508 requirements used in wheel metadata. `requirements.txt` locks the full runtime dependency graph with hashes. Docker, CI, and Python setup install that lock with `--require-hashes` from public PyPI. Do not put hash options into wheel metadata. The Python base image is pinned to a multiarchitecture index digest; review and update it intentionally.

To regenerate the lock from the repository root, use a separately installed lock tool (generated with uv 0.13.7), not a new runtime dependency:

```sh
uv --no-config pip compile --universal --python-version 3.12 --generate-hashes --index-url https://pypi.org/simple requirements.in -o requirements.txt
```

Use public PyPI only, with no extra-index environment settings. Inspect the generated lock/header for credentials or host-specific paths before committing. Reinstall with hashes, run the relevant tests, and rebuild the wheel after changes. The build backend remains separately pinned in `pyproject.toml`.


## Cloudflare and client setup

Perform provider changes only with the owner's explicit authority. Record non-secret settings privately; never commit account identifiers or real hostnames.

1. Create a remotely managed Tunnel and save its token into the secret file. Configure a published hostname, for example `vault.example.com`, with service `http://mcp:8000`. Choose an existing published cloudflared image version and pin its digest for production. Container networking resolves `mcp` inside Compose.
2. Create a self-hosted Access application covering the **entire hostname**, including `/mcp` and discovery paths. Add an **Allow** policy for the exact owner email, authenticated by the owner's identity provider. Require MFA if appropriate. Do not use Bypass, Everyone, or an entire email domain. Copy the application AUD and team label into the private configuration; match the owner email in `VAULT_ALLOWED_USERS`.
3. Enable **Managed OAuth** in the application's Advanced settings for interactive MCP clients. Enable dynamic client registration (DCR) as needed. Obtain each client's actual callback URI from its official documentation or connection flow and verify its exact host/scheme/path before allowing it. `https://client.example.com/oauth/callback` is only a synthetic example, not a usable client callback. Add exact redirects; avoid wildcard paths. Enable localhost/loopback callbacks only for a verified client that requires them. Native custom-scheme callbacks must match exactly. Do not guess redirects or add arbitrary requester-supplied URLs. Cloudflare's [Claude Desktop portal instructions](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#connect-claude-desktop) are a current callback reference for **MCP portals**; verify the callback and direct Access application flow separately before configuring this server.
4. Configure a short OAuth access-token lifetime (for example `15m`). Cloudflare recommends a grant session duration of **one to two weeks**; choose and read back the owner's duration in `oauth_configuration.grant.session_duration`. A longer owner-selected example is `2160h` (90 days), if specifically needed and accepted by the provider. This is a configurable refresh-grant lifetime, not an indefinite login or a server setting. Clients must refresh tokens; owners must reauthenticate on grant expiry and can revoke access sooner. Do not confuse grant duration with the short assertion expiry, which the origin always enforces.
5. Connect an OAuth-capable Streamable HTTP client using the `/mcp` URL. Access supplies discovery/challenges and resolves the client's opaque OAuth bearer into a signed `Cf-Access-Jwt-Assertion` for the origin. This Python server does not implement OAuth or forward client Authorization headers. Check that discovery, login, initialize, tools/list, and actual tool calls work in that client before claiming support.
   For large vaults, make clients call `list_files_page` or `search_notes_page` repeatedly with the returned `next_cursor` until it is null. Keep the same query and prefix throughout a traversal; restart after an exclusion-policy change. Inspect `skipped` before claiming content coverage. Legacy bounded calls fail with a page-tool hint when they cannot return a complete list.
6. For a headless bot, create a dedicated **service token** with a configurable duration, for example `8760h` (one year), and a separate **Service Auth** policy selecting that exact token. Do not select all service tokens. Add its exact Client ID (the signed assertion's `common_name`) to `VAULT_ALLOWED_SERVICES` with the minimum scopes. The bot must send **both** `CF-Access-Client-Id` and `CF-Access-Client-Secret` on each request to the public endpoint. Cloudflare turns those credentials into the signed assertion that this server checks. Raw service headers alone do not authenticate directly to the origin.
7. Put the bot Client ID/Secret and tunnel token in the owner's password manager as separate records, with purpose, expiry, rotation owner, and revocation instructions. Hand off access through the manager's sharing mechanism, never plaintext documentation. Store bot credentials in its own secret store, not in the MCP container. Revoke a bot at Access and remove its server allowlist entry; restart. Keep OAuth access lifetimes short to limit the lifetime of any already issued assertion. Expiry and revocation are distinct.

On **every HTTP request**, the origin validates RS256 signature using the team's Access signing keys, exact issuer `https://example-team.cloudflareaccess.com`, configured audience, required issued-at and expiry claims, and explicit principal allowlist. Missing, duplicate, invalid, or expired assertions get 401. A successful login or old MCP session does not authorize a later request. Never expose the origin directly or weaken this boundary to make a client connect.

Provider references: [OAuth duration schema](https://github.com/cloudflare/cloudflare-python/blob/main/src/cloudflare/types/zero_trust/access/application_update_params.py), [Managed OAuth](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/), [Claude Desktop portal connection](https://developers.cloudflare.com/cloudflare-one/access-controls/ai-controls/mcp-portals/#connect-claude-desktop), [service tokens and revocation](https://developers.cloudflare.com/cloudflare-one/access-controls/service-credentials/service-tokens/), [origin assertion validation](https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/authorization-cookie/validating-json/), [tunnel run parameters](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/configure-tunnels/cloudflared-parameters/run-parameters/). These describe provider mechanics; fixture tests do not prove a deployed Access policy or direct native-client flow.

## Optional external-readiness guard

Leave `VAULT_EXTERNAL_READY_FILE` **unset** for standalone mode. No readiness file or producer is required. If an owner explicitly configures an external synchronizer's readiness file, mount its directory read-only (so atomic marker replacement remains visible) and set the absolute container path through a local Compose override:

```yaml
services:
  mcp:
    environment:
      VAULT_EXTERNAL_READY_FILE: /readiness/ready.json
    volumes:
      - type: bind
        source: /srv/example-readiness
        target: /readiness
        read_only: true
        bind:
          create_host_path: false
```

The producer is external and is **not** included. It must atomically publish JSON such as this schema example, with current Unix epoch seconds replacing the zeros:

```json
{"phase":"ready","ok":true,"heartbeat_at":0,"completed_at":0,"completed_at_utc":"2026-01-01T00:00:00Z","error_code":null}
```

A write requires phase `ready`, `ok` exactly `true`, no error code, heartbeat age between 0 and 5 seconds, and completion age between 0 and 90 seconds. The external producer must set `ok` false while its transfer queues are not drained; on failure it must set phase `error` and an error code. This server observes that producer contract, not remote queues directly. It never claims remote convergence.

A healthy `syncing` phase can wait for `ready` within the shared 45-second mutex/readiness deadline. Missing, malformed, stale, future-dated, stopped, error, or otherwise unhealthy readiness denies writes. `ready` with `ok: false` also denies writes. It never falls back to standalone. Pre-publication guard failures do not consume a request UUID; retry the identical request after recovery. `storage_status` remains readable for diagnosis.

## Verify and operate

First use a synthetic fixture vault and least-privileged test principals. Verify container startup, read-only root filesystem, nonroot user, no published origin port, the full read-only vault mount, and the narrow writable overlay. Confirm missing/invalid assertions fail, the owner can initialize and list tools, and a read-only bot cannot write. Call bootstrap and verify missing metadata if no owner files exist.

With owner permission, create a synthetic note inside the configured write folder using a UUID, read the file and its SHA, update with that SHA and a new UUID, then read back. Retry identical UUIDs and confirm no duplicate action. Try a stale SHA and an outside path and confirm neither writes. Synthetic-note cleanup is an operator filesystem action; there is no delete tool. Never use real personal content as a test payload.

Before relying on synchronization, verify the actual synchronizer ignores `.vault-*.tmp` staging files. Using synthetic content, confirm a completed MCP save appears on another device, then edit that note on the other device and confirm MCP reads the new content and SHA. Independently test the intended native client through OAuth login, initialize, tools/list, read, and a permitted synthetic create/update; a fixture transport test alone does not establish client compatibility. Keep the same-directory atomic staging behavior.

If the external guard is enabled, additionally stop its fixture producer/remove its marker and confirm fail-closed denial, then recover and retry the same UUID. Check `storage_status`, HTTP 401 versus MCP `isError` tool responses, and container process health to distinguish authentication, path/scope, readiness, and persistence failures. Logs should contain no tokens or note bodies; avoid recording raw HTTP requests or dumping environment/configuration during troubleshooting.
