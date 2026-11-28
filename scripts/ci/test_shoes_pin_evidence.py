from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import call, patch

import shoes_pin_evidence as evidence


TAG = "v0.3.9"
COMMIT = "a" * 40
TAG_OBJECT = "b" * 40
ASSET = "shoes-x86_64-unknown-linux-musl.tar.gz"
RUNNER_ENV = {
    "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "test/repository", "GITHUB_SHA": COMMIT,
    "GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "test",
}


class ShoesPinEvidenceTests(unittest.TestCase):
    @patch.dict(evidence.os.environ, RUNNER_ENV, clear=True)
    @patch.object(evidence.platform, "system", return_value="Linux")
    @patch.object(evidence.platform, "machine", return_value="x86_64")
    @patch.object(evidence.subprocess, "run")
    @patch.object(evidence, "collect", side_effect=lambda tag, commit: {"tag": tag, "commit": commit})
    def test_collects_new_baseline_and_only_an_explicit_candidate(self, collect, run, _machine, _system):
        run.return_value.stdout = COMMIT
        baseline = ("v0.3.8", "7680938b96a245a21d9e481ad009205b956e4436")
        self.assertEqual(evidence.BASELINE_MUSL_SHA256,
                         "83a31e39a622b0a28d74b8c73488bb8aa42b1758251b355685f65c80f484e5a6")
        for args, expected in (
            ([], [baseline]),
            (["--candidate-tag", TAG], [baseline, (TAG, None)]),
            (["--candidate-tag", TAG, "--expected-candidate-commit", COMMIT], [baseline, (TAG, COMMIT)]),
        ):
            with self.subTest(args=args), patch("sys.argv", ["shoes_pin_evidence.py", *args]):
                collect.reset_mock()
                with redirect_stdout(io.StringIO()) as stdout:
                    evidence.main()
                self.assertEqual(collect.call_args_list, [call(*release) for release in expected])
                self.assertEqual(json.loads(stdout.getvalue())["releases"],
                                 [{"tag": tag, "commit": commit} for tag, commit in expected])

    @patch.dict(evidence.os.environ, RUNNER_ENV, clear=True)
    @patch.object(evidence.platform, "system", return_value="Linux")
    @patch.object(evidence.platform, "machine", return_value="x86_64")
    @patch.object(evidence, "collect")
    def test_rejects_invalid_candidate_options_before_collecting(self, collect, _machine, _system):
        for args in (
            ["--expected-candidate-commit", COMMIT],
            ["--candidate-tag", "latest"],
            ["--candidate-tag", "v0.3.8"],
            ["--candidate-tag", TAG, "--expected-candidate-commit", "invalid"],
        ):
            with self.subTest(args=args), patch("sys.argv", ["shoes_pin_evidence.py", *args]), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as error:
                    evidence.main()
                self.assertEqual(error.exception.code, 2)
        collect.assert_not_called()

    @patch.object(evidence, "api_json")
    def test_peels_annotated_tag_to_commit(self, api_json):
        api_json.side_effect = [
            {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": TAG_OBJECT}},
            {"sha": TAG_OBJECT, "object": {"type": "commit", "sha": COMMIT}},
        ]
        self.assertEqual(evidence.resolve_commit(TAG, COMMIT), COMMIT)
        self.assertEqual(api_json.call_args.args, (f"git/tags/{TAG_OBJECT}",))

    @patch.object(evidence, "api_json")
    def test_rejects_mismatched_commit(self, api_json):
        api_json.return_value = {
            "ref": f"refs/tags/{TAG}", "object": {"type": "commit", "sha": COMMIT},
        }
        with self.assertRaisesRegex(ValueError, "commit"):
            evidence.resolve_commit(TAG, TAG_OBJECT)

    @patch.object(evidence, "api_json")
    def test_rejects_tag_object_with_wrong_identity(self, api_json):
        api_json.side_effect = [
            {"ref": f"refs/tags/{TAG}", "object": {"type": "tag", "sha": TAG_OBJECT}},
            {"sha": COMMIT, "object": {"type": "commit", "sha": COMMIT}},
        ]
        with self.assertRaisesRegex(ValueError, "tag"):
            evidence.resolve_commit(TAG, None)

    @patch.object(evidence, "release_assets", return_value={})
    @patch.object(evidence, "resolve_commit", return_value=COMMIT)
    @patch.object(evidence.subprocess, "run")
    def test_stops_before_asset_download_if_git_and_api_disagree(self, run, _resolve_commit, assets):
        run.return_value.stdout = f"{TAG_OBJECT}\trefs/tags/{TAG}\n"
        with self.assertRaisesRegex(ValueError, "Git 远端.*commit"):
            evidence.collect(TAG, None)
        assets.assert_not_called()

    @patch.object(evidence.subprocess, "run")
    def test_compares_peeled_git_ref_not_annotated_tag_object(self, run):
        ref = f"refs/tags/{TAG}"
        run.return_value.stdout = f"{TAG_OBJECT}\t{ref}\n{COMMIT}\t{ref}^{{}}\n"
        evidence.check_git_ref(TAG, COMMIT)

    @patch.object(evidence, "api_json")
    def test_rejects_wrong_release_tag_and_missing_musl_asset(self, api_json):
        api_json.return_value = {"tag_name": "v0.3.7", "assets": []}
        with self.assertRaisesRegex(ValueError, "Release tag"):
            evidence.release_assets(TAG)
        api_json.return_value = {"tag_name": TAG, "assets": [{"name": ASSET}]}
        with self.assertRaisesRegex(ValueError, "aarch64-unknown-linux-musl"):
            evidence.release_assets(TAG)

    @patch.object(evidence.subprocess, "run")
    def test_records_version_output_and_rejects_wrong_version(self, run):
        run.return_value.stdout = f"shoes {TAG[1:]}\ntarget: x86_64-unknown-linux-musl\ncompiler: rustc test\n"
        run.return_value.stderr = ""
        self.assertEqual(evidence.version_output(TAG, Path("shoes"))["stdout"], run.return_value.stdout)
        with self.assertRaisesRegex(ValueError, "版本行"):
            evidence.version_output("v0.3.7", Path("shoes"))

    @patch.object(evidence.platform, "system", return_value="Linux")
    @patch.object(evidence.platform, "machine", return_value="x86_64")
    @patch.object(evidence, "version_output", return_value={"stdout": f"shoes {TAG[1:]}\n", "stderr": ""})
    def test_checks_archive_size_digest_and_binary_digest(self, version_output, _machine, _system):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / ASSET
            binary = b"offline synthetic binary"
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("nested/shoes")
                member.size = len(binary)
                bundle.addfile(member, io.BytesIO(binary))
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            asset = {
                "name": ASSET,
                "browser_download_url": f"{evidence.REPOSITORY}/releases/download/{TAG}/{ASSET}",
                "digest": f"sha256:{digest}",
                "size": archive.stat().st_size,
            }
            with patch.object(evidence, "download") as download:
                record = evidence.verify_asset(TAG, asset, Path(directory))
                self.assertEqual(record["archive_sha256"], digest)
                self.assertEqual(record["binary_sha256"], hashlib.sha256(binary).hexdigest())
                self.assertEqual(record["version"], version_output.return_value)
                download.assert_called_once_with(asset["browser_download_url"], archive)
            for changes, error, should_download in [
                ({"digest": None}, "API SHA-256", False),
                ({"digest": "sha256:" + "0" * 64}, "归档 SHA-256", True),
                ({"size": asset["size"] + 1}, "归档大小", True),
                ({"browser_download_url": asset["browser_download_url"].replace(TAG, "v0.3.7")}, "URL", False),
            ]:
                with self.subTest(error=error), patch.object(evidence, "download") as download:
                    with self.assertRaisesRegex(ValueError, error):
                        evidence.verify_asset(TAG, asset | changes, Path(directory))
                    self.assertEqual(download.called, should_download)
            version_output.assert_called_once_with(TAG, Path(directory) / "shoes")

    @patch.object(evidence, "download")
    def test_rejects_new_baseline_digest_mismatch_before_download(self, download):
        asset = {
            "name": ASSET,
            "browser_download_url": f"{evidence.REPOSITORY}/releases/download/v0.3.8/{ASSET}",
            "digest": "sha256:" + "0" * 64,
            "size": 1,
        }
        with self.assertRaisesRegex(ValueError, "API SHA-256 与基线 pin 不符"):
            evidence.verify_asset("v0.3.8", asset, Path("."))
        download.assert_not_called()


if __name__ == "__main__":
    unittest.main()
