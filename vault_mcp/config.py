"""One environment configuration owner; invalid settings fail at startup."""
import os
from dataclasses import dataclass
from pathlib import Path

from .auth import AccessVerifier
from .vault import safe_parts, write_parts, policy_parts, _identity


def _absolute(path: Path) -> None:
    if not path.is_absolute() or path != path.resolve():
        raise ValueError("configured filesystem paths must be absolute without symlinks or traversal")


def validate_paths(root, state, ready, write_folder, instructions, context, denied_paths=()):
    for path in (root, state, ready):
        if path is not None:
            _absolute(path)
    if not root.is_dir():
        raise ValueError("VAULT_ROOT must be an existing directory")
    if state == root or root in state.parents or state in root.parents:
        raise ValueError("VAULT_STATE must be separate from VAULT_ROOT")
    if state.exists() and not state.is_dir():
        raise ValueError("VAULT_STATE must be a directory")
    parts = write_parts(write_folder)
    denied = policy_parts(denied_paths)
    if any(_identity(parts)[:len(path)] == path for path in denied):
        raise ValueError("VAULT_DENIED_PATHS cannot contain the write folder")
    target = root.joinpath(*parts)
    if target.resolve() != target or not target.is_dir():
        raise ValueError("VAULT_WRITE_FOLDER must be an existing visible directory without symlinks")
    for path in (instructions, context):
        if path is not None:
            target = root.joinpath(*safe_parts(path))
            if target.resolve() != target or (target.exists() and not target.is_file()):
                raise ValueError("optional metadata must be a visible file without symlinks")
    for path in denied:
        target = root.joinpath(*path)
        if target.resolve() != target:
            raise ValueError("VAULT_DENIED_PATHS cannot contain symlinks")
    if ready is not None and (ready == root or root in ready.parents or ready == state or ready.is_dir()):
        raise ValueError("external readiness file must be outside the vault and must be a file")


def _allowlist(name):
    entries = {}
    value = os.getenv(name, "")
    if not value:
        return entries
    for item in value.split(";"):
        identity, sep, scopes = item.partition("=")
        identity = identity.lower() if name == "VAULT_ALLOWED_USERS" else identity
        scope_set = frozenset(scopes.split(","))
        if (not sep or not identity or identity.strip() != identity or identity in entries
                or not scope_set or not scope_set <= {"read", "agent_write"}):
            raise ValueError(f"invalid {name}")
        entries[identity] = scope_set
    return entries


@dataclass(frozen=True)
class Config:
    root: Path
    state: Path
    write_folder: str = "Agents"
    instructions: str = "AGENTS.md"
    context: str | None = None
    ready: Path | None = None
    denied_paths: tuple[str, ...] = ()

    @classmethod
    def from_env(cls):
        def optional(name):
            value = os.getenv(name)
            if value == "":
                raise ValueError(f"{name} must be unset or nonempty")
            return value
        root = os.getenv("VAULT_ROOT", "/vault")
        state = os.getenv("VAULT_STATE", "/state")
        if not root or not state:
            raise ValueError("VAULT_ROOT and VAULT_STATE must be nonempty")
        ready = optional("VAULT_EXTERNAL_READY_FILE")
        config = cls(Path(root), Path(state), os.getenv("VAULT_WRITE_FOLDER", "Agents"),
                     os.getenv("VAULT_INSTRUCTIONS_PATH", "AGENTS.md"), optional("VAULT_CONTEXT_PATH"),
                     Path(ready) if ready else None,
                     tuple(os.getenv("VAULT_DENIED_PATHS", "").split(";")) if os.getenv("VAULT_DENIED_PATHS") else ())
        validate_paths(config.root, config.state, config.ready, config.write_folder, config.instructions, config.context, config.denied_paths)
        return config


def configured_verifier():
    return AccessVerifier(os.getenv("CF_ACCESS_TEAM", ""), os.getenv("CF_ACCESS_AUD", ""),
                          _allowlist("VAULT_ALLOWED_USERS"), _allowlist("VAULT_ALLOWED_SERVICES"))
