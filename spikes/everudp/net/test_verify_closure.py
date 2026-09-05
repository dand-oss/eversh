#!/usr/bin/env python3
"""Regression tests for the exact-source everudp closure verifier."""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).with_name("verify-closure.py")
SPEC = importlib.util.spec_from_file_location("everudp_verify_closure", SCRIPT)
VERIFY = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(VERIFY)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ClosureVerifierTests(unittest.TestCase):
    def test_build_provenance_binds_exact_source_and_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            repository = root / "repository"
            build = root / "build"
            (repository / "spikes/everudp/net").mkdir(parents=True)
            (build / "artifacts").mkdir(parents=True)

            inputs = {
                "root_cargo_lock": repository / "Cargo.lock",
                "spike_cargo_lock": repository / "spikes/everudp/Cargo.lock",
                "zmosh_bench_source": repository / "spikes/everudp/net/zmosh-bench.c",
            }
            for name, path in inputs.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())

            artifact_paths = {}
            for name in ("everudp", "eversh", "zmosh", "zmosh_bench", "zmosh_header", "zmosh_library"):
                path = build / "artifacts" / name
                path.write_bytes(f"artifact:{name}".encode())
                artifact_paths[name] = path

            head = "1" * 40
            tree = "2" * 40
            provenance = {
                "schema_version": 1,
                "source": {"head_sha": head, "tree_sha": tree, "clean": True},
                "build": {
                    "fresh_output": True,
                    "isolated_cargo_targets": True,
                    "isolated_zig_caches": True,
                },
                "zmosh_source": {
                    "commit": VERIFY.ZMOSH_SOURCE_COMMIT,
                    "tree": VERIFY.ZMOSH_SOURCE_TREE,
                },
                "inputs": {name: {"sha256": digest(path)} for name, path in inputs.items()},
                "artifacts": {
                    name: {
                        "path": str(path.relative_to(build)),
                        "sha256": digest(path),
                    }
                    for name, path in artifact_paths.items()
                },
            }
            provenance_path = build / "provenance.json"
            provenance_path.write_text(json.dumps(provenance), encoding="utf-8")

            observed = VERIFY.verify_build_provenance(
                provenance_path, repository, head, tree
            )
            self.assertEqual(observed["everudp"], digest(artifact_paths["everudp"]))

            artifact_paths["everudp"].write_bytes(b"substituted binary")
            with self.assertRaisesRegex(ValueError, "everudp artifact hash mismatch"):
                VERIFY.verify_build_provenance(provenance_path, repository, head, tree)

    def test_analyzer_output_is_reexecuted_and_must_match_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            producer = root / "producer.py"
            producer.write_text(
                "import json\nprint(json.dumps({'derived': 7}, indent=2, sort_keys=True))\n",
                encoding="utf-8",
            )
            expected = root / "analysis.json"
            expected.write_text('{\n  "derived": 7\n}\n', encoding="utf-8")

            VERIFY.verify_reproduced_json(
                [sys.executable, str(producer)], expected, root, "test analysis"
            )
            expected.write_text('{\n  "derived": 8\n}\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "test analysis reproduction mismatch"):
                VERIFY.verify_reproduced_json(
                    [sys.executable, str(producer)], expected, root, "test analysis"
                )

    def test_receipt_digest_map_is_derived_from_child_manifests(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            mapping = {}
            for name in ("cell-a", "cell-b"):
                child = root / name
                child.mkdir()
                manifest = child / "manifest.json"
                manifest.write_text(json.dumps({"name": name}), encoding="utf-8")
                mapping[name] = digest(manifest)

            VERIFY.verify_digest_map(root, mapping, "manifest.json", "test children")
            mapping["cell-a"] = "0" * 64
            with self.assertRaisesRegex(ValueError, "test children hash mismatch"):
                VERIFY.verify_digest_map(root, mapping, "manifest.json", "test children")


if __name__ == "__main__":
    unittest.main()
