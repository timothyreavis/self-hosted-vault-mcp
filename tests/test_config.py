import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from vault_mcp.config import Config, configured_verifier
from vault_mcp.server import create_app


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.root = self.base / "vault"
        (self.root / "Agents").mkdir(parents=True)
        self.env = {"VAULT_ROOT": str(self.root), "VAULT_STATE": str(self.base / "state"),
                    "CF_ACCESS_TEAM": "fixture", "CF_ACCESS_AUD": "fixture-audience",
                    "VAULT_ALLOWED_USERS": "owner@example.invalid=read,agent_write"}

    def test_valid_defaults_and_required_auth(self):
        with patch.dict(os.environ, self.env, clear=True):
            config = Config.from_env()
            self.assertEqual(config.write_folder, "Agents")
            self.assertIsNone(config.ready)
            create_app()
        for change in ({"CF_ACCESS_TEAM": ""}, {"CF_ACCESS_AUD": ""}, {"VAULT_ALLOWED_USERS": ""}):
            with patch.dict(os.environ, {**self.env, **change}, clear=True), self.assertRaises(ValueError):
                create_app()

    def test_invalid_configuration_fails_clearly(self):
        (self.root / "link").symlink_to(self.root / "Agents", target_is_directory=True)
        for change in ({"VAULT_ROOT": "relative"}, {"VAULT_ROOT": ""},
                       {"VAULT_STATE": str(self.root / "state")}, {"VAULT_STATE": str(self.base)},
                       {"VAULT_WRITE_FOLDER": "../escape"}, {"VAULT_WRITE_FOLDER": ".hidden"},
                       {"VAULT_WRITE_FOLDER": "missing"}, {"VAULT_WRITE_FOLDER": "link"},
                       {"VAULT_INSTRUCTIONS_PATH": "../AGENTS.md"}, {"VAULT_CONTEXT_PATH": ".config/context.md"},
                       {"VAULT_EXTERNAL_READY_FILE": ""}, {"VAULT_EXTERNAL_READY_FILE": "relative"},
                       {"VAULT_EXTERNAL_READY_FILE": str(self.root / "ready.json")}):
            with self.subTest(change=change), patch.dict(os.environ, {**self.env, **change}, clear=True):
                with self.assertRaises(ValueError):
                    Config.from_env()
        (self.root / "PolicyLink").symlink_to(self.root / "Agents", target_is_directory=True)
        for value in ("Agents", "agents/Private;AGENTS.md;agents/private", "../escape", "/absolute",
                      "Agents/.hidden", "Private; Health", "Private;Health ", "Agents/ Private", "PolicyLink"):
            with self.subTest(denied=value), patch.dict(os.environ, {**self.env, "VAULT_DENIED_PATHS": value}, clear=True):
                with self.assertRaises(ValueError):
                    Config.from_env()
        with patch.dict(os.environ, {**self.env, "VAULT_DENIED_PATHS": "Agents/Private;Reference"}, clear=True):
            self.assertEqual(Config.from_env().denied_paths, ("Agents/Private", "Reference"))
        for change in ({"CF_ACCESS_TEAM": "https://wrong.invalid"}, {"CF_ACCESS_TEAM": "fixture/path"},
                       {"VAULT_ALLOWED_USERS": "anyone"}, {"VAULT_ALLOWED_USERS": "user@example.invalid=admin"},
                       {"VAULT_ALLOWED_SERVICES": "bot=read;bot=agent_write"},
                       {"VAULT_ALLOWED_USERS": "owner@example.invalid=read;"}):
            with self.subTest(change=change), patch.dict(os.environ, {**self.env, **change}, clear=True):
                with self.assertRaises(ValueError):
                    configured_verifier()
