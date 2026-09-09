import copy
import json
import pathlib
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import analyze_attribution_overhead as analyzer


def archive_root() -> pathlib.Path:
    # Tests are run from the checkout, so discover the canonical evidence without
    # baking a machine-specific path into the helper.
    here = pathlib.Path(__file__).resolve()
    starts = [pathlib.Path.cwd(), here, *here.parents]
    for start in starts:
        for parent in [start, *start.parents]:
            candidate = parent / "docs/release-evidence/20260907-everudp-attribution-e727820/measurements"
            if candidate.is_dir():
                return candidate
    raise RuntimeError("canonical attribution archive not found")


class AttributionAnalyzerTests(unittest.TestCase):
    def copy_fixture(self) -> pathlib.Path:
        tmp = pathlib.Path(tempfile.mkdtemp(prefix="everudp-attribution-fixture."))
        self.addCleanup(shutil.rmtree, tmp)
        shutil.copytree(archive_root(), tmp / "measurements")
        return tmp / "measurements"

    def reseal_result(self, root: pathlib.Path, block_name: str, candidate: str) -> None:
        block = root / block_name
        result_path = block / candidate / "result.json"
        manifest_path = block / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["results"][candidate]["sha256"] = analyzer._sha256(result_path)
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")))
        entries = {}
        for line in (block / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            entries[name] = digest
        entries[f"{candidate}/result.json"] = analyzer._sha256(result_path)
        entries["manifest.json"] = analyzer._sha256(manifest_path)
        (block / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in entries.items()))

    def test_archived_collection_is_diagnostic(self):
        report = analyzer.analyze(archive_root())
        self.assertEqual(report["status"], "DIAGNOSTIC")
        self.assertEqual(report["attribution"], "UNKNOWN")
        self.assertEqual(report["collection"]["blocks"], 12)
        self.assertEqual(report["collection"]["responses"], 4800)
        self.assertEqual(len(report["blocks"]), 12)
        self.assertEqual(len(report["mode_comparisons"]), 8)

    def test_missing_block_rejected(self):
        root = self.copy_fixture()
        shutil.rmtree(root / "loss0-block1-plain")
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)

    def test_digest_tamper_rejected(self):
        root = self.copy_fixture()
        path = root / "loss0-block1-plain" / "everudp-floor" / "result.json"
        payload = json.loads(path.read_text())
        payload["samples_us"][0] += 1
        path.write_text(json.dumps(payload))
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)

    def test_boundary_tamper_rejected_even_if_manifest_resealed(self):
        root = self.copy_fixture()
        block = root / "loss0-block1-plain"
        path = block / "everudp-floor" / "result.json"
        payload = json.loads(path.read_text())
        payload["public_boundaries"][0]["accepted_ns"] += 1000
        path.write_text(json.dumps(payload, separators=(",", ":")))
        self.reseal_result(root, "loss0-block1-plain", "everudp-floor")
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)

    def test_bool_sample_rejected(self):
        root = self.copy_fixture()
        path = root / "loss0-block1-plain/everudp-floor/result.json"
        payload = json.loads(path.read_text())
        payload["samples_us"][0] = True
        path.write_text(json.dumps(payload, separators=(",", ":")))
        self.reseal_result(root, "loss0-block1-plain", "everudp-floor")
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)

    def test_negative_and_overlapping_boundaries_rejected(self):
        for field, value in (("send_ns", -1), ("accepted_ns", 0)):
            root = self.copy_fixture()
            path = root / "loss0-block1-plain/everudp-floor/result.json"
            payload = json.loads(path.read_text())
            if field == "send_ns":
                payload["public_boundaries"][0][field] = value
            else:
                payload["public_boundaries"][1][field] = payload["public_boundaries"][0]["accepted_ns"] - 1
            path.write_text(json.dumps(payload, separators=(",", ":")))
            self.reseal_result(root, "loss0-block1-plain", "everudp-floor")
            with self.assertRaises(analyzer.InvalidCollection):
                analyzer.analyze(root)

    def test_exact_clock_and_literal_tracing_required(self):
        root = self.copy_fixture()
        path = root / "loss0-block1-plain/everudp-floor/result.json"
        payload = json.loads(path.read_text())
        payload["public_clock"] = "CLOCK_MONOTONIC"
        path.write_text(json.dumps(payload, separators=(",", ":")))
        self.reseal_result(root, "loss0-block1-plain", "everudp-floor")
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)
        root = self.copy_fixture()
        manifest_path = root / "loss0-block1-plain/manifest.json"
        manifest = json.loads(manifest_path.read_text())
        manifest["diagnostic_tracing"] = "false"
        manifest_path.write_text(json.dumps(manifest, separators=(",", ":")))
        block = manifest_path.parent
        entries = {}
        for line in (block / "SHA256SUMS").read_text().splitlines():
            digest, name = line.split(maxsplit=1)
            entries[name] = digest
        entries["manifest.json"] = analyzer._sha256(manifest_path)
        (block / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in entries.items()))
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)

    def test_symlink_escape_rejected(self):
        root = self.copy_fixture()
        path = root / "loss0-block1-plain/everudp-floor/candidate.stderr"
        path.unlink()
        path.symlink_to("/etc/hosts")
        with self.assertRaises(analyzer.InvalidCollection):
            analyzer.analyze(root)


if __name__ == "__main__":
    unittest.main()
