"""Tests for sealed ordinary performance-control reuse."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "reuse_performance_controls", HERE / "reuse_performance_controls.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def seal(root: Path) -> None:
    paths = sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest(root / relative)}  {relative}\n" for relative in paths),
        encoding="utf-8",
    )


class ReusePerformanceControlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="reuse-performance-controls-")
        self.root = Path(self.temp.name)
        self.net = self.root / "net"
        self.net.mkdir()
        for name in MODULE.FIXTURE_INPUTS:
            (self.net / name).write_bytes(f"current:{name}\n".encode())
        self.control = self.root / "control"
        (self.control / "artifacts/bin").mkdir(parents=True)
        for name in MODULE.ARTIFACTS:
            (self.control / "artifacts/bin" / name).write_bytes(f"artifact:{name}\n".encode())
        for name in ("stdout.log", "stderr.log"):
            (self.control / "logs").mkdir(exist_ok=True)
            (self.control / "logs" / name).write_text("ok\n", encoding="utf-8")
        self.provenance = {
            "schema_version": 1,
            "source": {
                "clean": True,
                "head_sha": "a" * 40,
                "tree_sha": "b" * 40,
            },
            "zmosh_sources": {
                "udp": {**MODULE.FROZEN_UDP, "clean": True},
                "quic": {**MODULE.FROZEN_QUIC, "clean": True},
            },
            "everudp_build": {
                "cargo_features": ["cli"],
                "profile": dict(MODULE.PROFILE),
            },
            "inputs": {name: digest(self.net / name) for name in MODULE.FIXTURE_INPUTS},
            "artifacts": {
                name: {
                    "path": f"artifacts/bin/{name}",
                    "sha256": digest(self.control / "artifacts/bin" / name),
                }
                for name in MODULE.ARTIFACTS
            },
        }
        (self.control / "provenance.json").write_text(
            json.dumps(self.provenance, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        seal(self.control)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def output(self, name: str = "output") -> Path:
        output = self.root / name
        (output / "artifacts/bin").mkdir(parents=True)
        return output

    def copy_control(self, name: str = "control") -> Path:
        target = self.root / name
        if target != self.control:
            shutil.copytree(self.control, target)
        return target

    def refresh_provenance_seal(self, root: Path) -> None:
        seal(root)

    def test_valid_bundle_copies_controls_and_original_provenance(self) -> None:
        output = self.output()
        before = {
            path.relative_to(self.control).as_posix(): digest(path)
            for path in self.control.rglob("*")
            if path.is_file()
        }
        self.assertIsNone(MODULE.copy_controls(str(self.control), str(output), str(self.net)))
        for name in MODULE.CONTROL_ARTIFACTS:
            self.assertEqual(
                (output / "artifacts/bin" / name).read_bytes(),
                (self.control / "artifacts/bin" / name).read_bytes(),
            )
        self.assertFalse((output / "artifacts/bin/everudp").exists())
        self.assertEqual(
            (output / "provenance-inputs/control.json").read_bytes(),
            (self.control / "provenance.json").read_bytes(),
        )
        after = {
            path.relative_to(self.control).as_posix(): digest(path)
            for path in self.control.rglob("*")
            if path.is_file()
        }
        self.assertEqual(before, after)

    def test_rejects_tampered_unsealed_or_wrong_artifact(self) -> None:
        for case in ("tampered", "unsealed", "wrong-path"):
            with self.subTest(case=case):
                control = self.copy_control(case)
                if case == "tampered":
                    with (control / "artifacts/bin/zmosh-udp").open("ab") as stream:
                        stream.write(b"tamper")
                elif case == "unsealed":
                    (control / "extra").write_text("unsealed", encoding="utf-8")
                else:
                    provenance = json.loads((control / "provenance.json").read_text())
                    provenance["artifacts"]["zmosh-udp"]["path"] = "artifacts/bin/other"
                    (control / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
                    self.refresh_provenance_seal(control)
                with self.assertRaises(MODULE.ReuseError):
                    MODULE.copy_controls(str(control), str(self.output(f"output-{case}")), str(self.net))

    def test_rejects_symlink_and_recursive_reuse(self) -> None:
        symlink = self.copy_control("symlink")
        (symlink / "logs/stderr.log").unlink()
        (symlink / "logs/stderr.log").symlink_to(symlink / "logs/stdout.log")
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(symlink), str(self.output("output-symlink")), str(self.net))

        recursive = self.copy_control("recursive")
        provenance = json.loads((recursive / "provenance.json").read_text())
        provenance["control_reuse"] = {"schema_version": 1}
        (recursive / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        self.refresh_provenance_seal(recursive)
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(recursive), str(self.output("output-recursive")), str(self.net))

    def test_rejects_wrong_pins_profile_features_and_inputs(self) -> None:
        mutations = (
            lambda p: p["zmosh_sources"]["udp"].__setitem__("commit", "0" * 40),
            lambda p: p["everudp_build"].__setitem__("cargo_features", ["cli", "path-diagnostics"]),
            lambda p: p["everudp_build"].__setitem__("profile", {"lto": "thin"}),
            lambda p: p["inputs"].__setitem__("pty-bench.c", "0" * 64),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                control = self.copy_control(f"invalid-{index}")
                provenance = json.loads((control / "provenance.json").read_text())
                mutate(provenance)
                (control / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
                self.refresh_provenance_seal(control)
                with self.assertRaises(MODULE.ReuseError):
                    MODULE.copy_controls(str(control), str(self.output(f"output-invalid-{index}")), str(self.net))

    def test_rejects_duplicate_json_keys_and_boolean_schema(self) -> None:
        duplicate = self.copy_control("duplicate")
        (duplicate / "provenance.json").write_text(
            '{"schema_version":1,"schema_version":1}\n', encoding="utf-8"
        )
        self.refresh_provenance_seal(duplicate)
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(duplicate), str(self.output("output-duplicate")), str(self.net))

        boolean = self.copy_control("boolean-schema")
        provenance = json.loads((boolean / "provenance.json").read_text())
        provenance["schema_version"] = True
        (boolean / "provenance.json").write_text(json.dumps(provenance), encoding="utf-8")
        self.refresh_provenance_seal(boolean)
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(boolean), str(self.output("output-boolean")), str(self.net))

    def test_rejects_existing_targets_and_preserves_them(self) -> None:
        output = self.output()
        existing = output / "artifacts/bin/zmosh-udp"
        existing.write_bytes(b"keep")
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(self.control), str(output), str(self.net))
        self.assertEqual(existing.read_bytes(), b"keep")

    def test_rejects_symlinked_output_artifacts_parent(self) -> None:
        output = self.root / "output-parent-link"
        (output / "artifacts-target/bin").mkdir(parents=True)
        (output / "artifacts").symlink_to(output / "artifacts-target", target_is_directory=True)
        with self.assertRaises(MODULE.ReuseError):
            MODULE.copy_controls(str(self.control), str(output), str(self.net))


if __name__ == "__main__":
    unittest.main()
