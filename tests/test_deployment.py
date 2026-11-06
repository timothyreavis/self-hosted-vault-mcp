"""Validate parsed deployment values that Docker consumes."""
from pathlib import Path
import unittest

import yaml


class ComposeTests(unittest.TestCase):
    def test_tmpfs_mounts_are_single_paths_with_options(self):
        compose = yaml.safe_load((Path(__file__).parents[1] / "compose.yaml").read_text())
        for name in ("mcp", "cloudflared"):
            with self.subTest(service=name):
                mounts = compose["services"][name]["tmpfs"]
                self.assertEqual(len(mounts), 1)
                path, options = mounts[0].split(":", 1)
                self.assertEqual(path, "/tmp")
                parsed = dict(option.split("=", 1) for option in options.split(","))
                self.assertEqual(parsed["mode"], "1777")
                self.assertTrue(parsed["size"].endswith("m"))
                self.assertGreater(int(parsed["size"][:-1]), 0)
