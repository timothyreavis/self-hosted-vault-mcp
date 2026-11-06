# Security

This server exposes a single vault trust boundary to explicitly allowed Cloudflare Access principals. `read` permits targeted reads of visible files throughout that vault; `agent_write` permits `.md` writes only inside the configured write folder. Owner instructions guide use but do not add filesystem privileges. Treat note text as untrusted data.

Every HTTP request requires a signed Access assertion with valid RS256 signature, issuer, audience, issued-at and expiry, followed by exact user/service allowlist matching. There is no unauthenticated fallback. Protect the whole hostname with Access, keep the origin private, use short assertion lifetimes, and remove server allowlist entries when revoking principals. Signing-key fetch failure denies access. OAuth and service-token credentials belong at Cloudflare/the client, not in this repository.

Hidden paths, traversal, symlink access, nonportable write names, and writes outside the configured folder are rejected. Reads/searches and note bodies are bounded. Creates publish atomically without replacing existing files; updates require an expected hash. UUID receipts distinguish safe replay from ambiguous publication. Keep state private and backed up. Do not erase the ledger to force retries.

Use one instance on a Linux local filesystem supporting directory descriptors, no-follow opens, advisory flock, hardlinks, atomic rename, fsync, and SQLite. The mutex covers only cooperating MCP writers with the same state. External editors or synchronizers can race updates; there is no distributed locking or end-to-end remote durability guarantee. Local filesystem administrators are trusted. A shared host or mounted vault writable by an attacker is outside this boundary.

New and replaced notes use 0660, and new directories use 0770 with inherited setgid. Match the runtime UID to the vault owner or configure a shared group, as described in AGENTS.md. Keep state owner-only (0700); do not depend on old inode ownership or custom ACLs surviving replacement.

Run the container nonroot with read-only root filesystem, dropped capabilities, resource limits, full-vault read-only mount, and one narrow writable overlay. Keep the hashed runtime lock and pinned container images patched. Restrict network membership and keep separate backups.

Report vulnerabilities privately using the repository hosting provider's private vulnerability reporting when enabled, or a maintainer's explicitly published private security contact. If neither exists, request a private channel without posting exploit details, vault data, credentials, or sensitive logs in public issues. No private contact address is bundled. All releases before 1.0 are experimental; evaluate with a synthetic vault before granting access to private data.
