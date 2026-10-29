"""Check release metadata and upgrade guidance before publishing a version."""

import argparse
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VERSION = "0.3.0"


class ReleaseMetadataTest(unittest.TestCase):
    def test_manifest_and_lock_agree_with_release(self):
        manifest = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        lock = (ROOT / "Cargo.lock").read_text(encoding="utf-8")
        self.assertRegex(manifest, rf'(?m)^version = "{re.escape(VERSION)}"$')
        self.assertIn(f'name = "ping-rust"\nversion = "{VERSION}"', lock)

    def test_readme_installation_examples_use_release(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"releases/tag/v{VERSION}", readme)
        self.assertIn(f"--version v{VERSION}", readme)
        self.assertNotRegex(readme, r"--version v0\.2\.")
        self.assertNotIn("VLESS-ENC（开发分支，未发版）", readme)

    def test_release_notes_cover_compatibility_and_upgrade_order(self):
        notes = (ROOT / "docs" / f"RELEASE_NOTES_v{VERSION}.md").read_text(encoding="utf-8")
        for requirement in (
            "25.5.16", "旧版 v2rayN", "aes-128-gcm", "已有节点",
            "通配符", "自动迁移", "先升级 shoes", "不套 TLS",
            "不支持 sing-box", "v26.6.27", "v1.19.33", "CI 实测",
            "不能降级到 v0.2.x", "v0.3.6",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, notes)
        self.assertLess(notes.index("sudo ping-rust self-update"), notes.index("sudo ping-rust update"))
        self.assertNotIn("bero", notes)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=VERSION)
    args, remaining = parser.parse_known_args()
    VERSION = args.version
    unittest.main(argv=[__file__, *remaining])
