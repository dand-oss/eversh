import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from seal_floor_invalid import seal_invalid


class InvalidReceiptTests(unittest.TestCase):
    def test_partial_evidence_is_hashed_and_cannot_authorize(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "partial.log").write_text("partial")
            self.assertTrue(seal_invalid(root, "candidate", "tree", "interrupted 143"))
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertEqual(receipt["status"], "INVALID")
            self.assertFalse(receipt["production_actor_integration_authorized"])
            self.assertEqual(receipt["candidate"]["head_sha"], "candidate")
            for line in (root / "SHA256SUMS").read_text().splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256((root / name).read_bytes()).hexdigest(), expected)

    def test_existing_receipt_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "receipt.json").write_text("immutable")
            self.assertFalse(seal_invalid(root, "candidate", "tree", "interrupted"))
            self.assertEqual((root / "receipt.json").read_text(), "immutable")


if __name__ == "__main__":
    unittest.main()
