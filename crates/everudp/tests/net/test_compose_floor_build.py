#!/usr/bin/env python3
"""Tests for the sealed floor-build composition helper."""

from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE.parents[3] / "docs/release-evidence/20260907-everudp-initial-offer-f90c878"
RUNTIME_TEMPLATE = EVIDENCE / "build-candidate.json"
CONTROL_TEMPLATE = EVIDENCE / "build-baseline.json"
SPEC = importlib.util.spec_from_file_location("compose_floor_build", HERE / "compose_floor_build.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def tree_hashes(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file()
    }


def make_fixture(template: Path, root: Path, label: str) -> Path:
    build = json.loads(template.read_text(encoding="utf-8"))
    fixture = root / label
    (fixture / "artifacts/bin").mkdir(parents=True)
    for name in MODULE.ARTIFACTS:
        payload_label = "shared" if name in ("pty-bench", "pty-echo") else label
        payload = f"{payload_label}:{name}\n".encode()
        artifact = fixture / f"artifacts/bin/{name}"
        artifact.write_bytes(payload)
        build["artifacts"][name]["sha256"] = hashlib.sha256(payload).hexdigest()
    (fixture / "provenance.json").write_text(
        json.dumps(build, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    files = sorted(
        path.relative_to(fixture).as_posix()
        for path in fixture.rglob("*")
        if path.is_file()
    )
    (fixture / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((fixture / relative).read_bytes()).hexdigest()}  {relative}\n"
            for relative in files
        ),
        encoding="utf-8",
    )
    return fixture


def refresh_provenance_seal(root: Path) -> None:
    digest = hashlib.sha256((root / "provenance.json").read_bytes()).hexdigest()
    lines = (root / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    replaced = []
    for line in lines:
        old_digest, relative = line.split("  ", 1)
        replaced.append(f"{digest if relative == 'provenance.json' else old_digest}  {relative}")
    (root / "SHA256SUMS").write_text("\n".join(replaced) + "\n", encoding="utf-8")


class ComposeFloorBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="compose-floor-build-")
        self.root = Path(self.temp.name)
        self.runtime = make_fixture(RUNTIME_TEMPLATE, self.root, "runtime")
        self.control = make_fixture(CONTROL_TEMPLATE, self.root, "control")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def copy_build(self, source: Path, name: str) -> Path:
        target = self.root / name
        shutil.copytree(source, target)
        return target

    def test_valid_composition_preserves_inputs_and_records_origins(self) -> None:
        runtime_before = tree_hashes(self.runtime)
        control_before = tree_hashes(self.control)
        output = self.root / "composed"
        MODULE.compose(str(self.runtime), str(self.control), str(output))
        self.assertEqual(tree_hashes(self.runtime), runtime_before)
        self.assertEqual(tree_hashes(self.control), control_before)
        runtime = json.loads((self.runtime / "provenance.json").read_text())
        control = json.loads((self.control / "provenance.json").read_text())
        composed = json.loads((output / "provenance.json").read_text())
        self.assertEqual(composed["source"], runtime["source"])
        self.assertEqual(composed["everudp_build"], runtime["everudp_build"])
        self.assertEqual(composed["artifacts"]["everudp-floor"], runtime["artifacts"]["everudp-floor"])
        for name in ("pty-bench", "pty-echo", "zmosh-udp"):
            self.assertEqual(composed["artifacts"][name], control["artifacts"][name])
            self.assertEqual(composed["control_reuse"]["selected_control_artifacts"][name]["source_build"], "control")
        self.assertEqual((output / "provenance-inputs/runtime.json").read_bytes(), (self.runtime / "provenance.json").read_bytes())
        self.assertEqual((output / "provenance-inputs/control.json").read_bytes(), (self.control / "provenance.json").read_bytes())
        self.assertEqual((output / "artifacts/bin/everudp-floor").read_bytes(), (self.runtime / "artifacts/bin/everudp-floor").read_bytes())

    def test_existing_output_is_never_overwritten(self) -> None:
        output = self.root / "composed"
        MODULE.compose(str(self.runtime), str(self.control), str(output))
        before = tree_hashes(output)
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(self.runtime), str(self.control), str(output))
        self.assertEqual(tree_hashes(output), before)

    def test_tampered_artifact_and_missing_seal_fail(self) -> None:
        tampered = self.copy_build(self.runtime, "tampered")
        with (tampered / "artifacts/bin/everudp-floor").open("ab") as stream:
            stream.write(b"tamper")
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(tampered), str(self.control), str(self.root / "out1"))
        missing = self.copy_build(self.runtime, "missing")
        lines = (missing / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
        (missing / "SHA256SUMS").write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(missing), str(self.control), str(self.root / "out2"))

    def test_source_mismatch_and_path_escape_fail_after_seal_refresh(self) -> None:
        mismatched = self.copy_build(self.control, "mismatched")
        provenance_path = mismatched / "provenance.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["zmosh_source"]["commit"] = "0" * 40
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
        refresh_provenance_seal(mismatched)
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(self.runtime), str(mismatched), str(self.root / "out3"))
        escaped = self.copy_build(self.runtime, "escaped")
        provenance_path = escaped / "provenance.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["artifacts"]["everudp-floor"]["path"] = "../outside"
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
        refresh_provenance_seal(escaped)
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(escaped), str(self.control), str(self.root / "out4"))

    def test_incomplete_matching_metadata_is_not_evidence(self) -> None:
        mutations = (
            lambda p: p["source"].pop("head_sha"),
            lambda p: p["everudp_build"].__setitem__("profile", {}),
            lambda p: p["everudp_build"].__setitem__("cargo_features", None),
            lambda p: p["inputs"].pop("pty-bench.c"),
            lambda p: p.__setitem__("schema_version", True),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                paths = []
                for label, source in (("runtime", self.runtime), ("control", self.control)):
                    changed = self.copy_build(source, f"{label}-invalid-{index}")
                    path = changed / "provenance.json"
                    document = json.loads(path.read_text())
                    mutate(document)
                    path.write_text(json.dumps(document))
                    refresh_provenance_seal(changed)
                    paths.append(str(changed))
                output = self.root / f"invalid-out-{index}"
                with self.assertRaises(MODULE.ComposeError):
                    MODULE.compose(*paths, str(output))
                self.assertFalse(output.exists())

    def test_dangling_output_symlink_is_not_followed(self) -> None:
        target = self.root / "absent-target"
        output = self.root / "linked-output"
        output.symlink_to(target)
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(self.runtime), str(self.control), str(output))
        self.assertTrue(output.is_symlink())
        self.assertFalse(target.exists())

    def test_nested_seal_and_symlink_artifact_are_rejected(self) -> None:
        nested = self.copy_build(self.runtime, "nested-seal")
        (nested / "artifacts/SHA256SUMS").write_text("unsealed")
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(nested), str(self.control), str(self.root / "out-nested"))
        linked = self.copy_build(self.runtime, "linked-artifact")
        artifact = linked / "artifacts/bin/everudp-floor"
        artifact.unlink()
        artifact.symlink_to(self.runtime / "artifacts/bin/everudp-floor")
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(linked), str(self.control), str(self.root / "out-linked"))

    def test_unknown_artifact_and_input_output_overlap_fail(self) -> None:
        unknown = self.copy_build(self.runtime, "unknown")
        provenance_path = unknown / "provenance.json"
        provenance = json.loads(provenance_path.read_text())
        provenance["artifacts"]["other"] = provenance["artifacts"].pop("everudp-floor")
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
        refresh_provenance_seal(unknown)
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(unknown), str(self.control), str(self.root / "out5"))
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(self.runtime), str(self.control), str(self.runtime / "nested-output"))
        dangling = self.root / "dangling-output"
        dangling.symlink_to(self.root / "not-created")
        with self.assertRaises(MODULE.ComposeError):
            MODULE.compose(str(self.runtime), str(self.control), str(dangling))
        self.assertTrue(dangling.is_symlink())


if __name__ == "__main__":
    unittest.main()
