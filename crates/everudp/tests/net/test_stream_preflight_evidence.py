import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from stream_preflight_evidence import save


class EvidenceTests(unittest.TestCase):
    def identity(self):
        return {"collector_head": "a" * 40, "collector_tree": "b" * 40,
                "binary_sha256": "c" * 64, "collector_sha256": "d" * 64,
                "evidence_writer_sha256": "e" * 64}

    def profiles(self):
        return {(runtime, side): f"{side} config" for runtime in ("ordinary", "native")
                for side in ("client", "server")}

    def test_seal_contains_only_receipt_and_four_profiles_and_never_overwrites(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "evidence"
            save(output, self.identity(), self.profiles(), os.getuid(), os.getgid())
            files = {p.name for p in output.iterdir()}
            self.assertEqual(len(files), 6)
            receipt = json.loads((output / "receipt.json").read_text())
            self.assertFalse(receipt["performance_qualification"])
            self.assertTrue(receipt["fixture_cleanup"])
            self.assertEqual(len(receipt["cases"]), 6)
            for line in (output / "SHA256SUMS").read_text().splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for path in output.iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                save(output, self.identity(), self.profiles(), os.getuid(), os.getgid())

    def test_partial_or_mismatched_profiles_do_not_create_evidence(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "evidence"
            for profiles in ({}, {**self.profiles(), ("native", "client"): "different"}):
                with self.assertRaises(ValueError):
                    save(output, self.identity(), profiles, os.getuid(), os.getgid())
                self.assertFalse(output.exists())

    def test_missing_identity_never_creates_pass_receipt(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "evidence"
            with self.assertRaises(ValueError):
                save(output, {}, self.profiles(), os.getuid(), os.getgid())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
