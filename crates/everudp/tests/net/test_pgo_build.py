import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from pgo_build import build_plan, run, TARGET


class PgoBuildTests(unittest.TestCase):
    def lifecycle(self, mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "source"
            root.mkdir()
            output = Path(directory) / "build"

            def query(command, **kwargs):
                if command[0] == "rustc" and mode == "tool-failure":
                    raise FileNotFoundError("test compiler unavailable")
                if command[0] != "git":
                    return "test tool version"
                if command[1] == "status":
                    return b""
                return "a" * 40 + "\n"

            def compile_binary(command, **kwargs):
                if mode == "compile-failure":
                    raise subprocess.CalledProcessError(1, command)
                binary = output / "target" / TARGET / "release/everudp"
                binary.parent.mkdir(parents=True)
                binary.write_bytes(b"test build artifact")

            with patch("pgo_build.subprocess.check_output", side_effect=query), \
                    patch("pgo_build.subprocess.run", side_effect=compile_binary):
                if mode == "success":
                    result = run(root, output, "baseline", None)
                    self.assertEqual(result["status"], "BUILT")
                else:
                    with self.assertRaises((FileNotFoundError, subprocess.CalledProcessError)):
                        run(root, output, "baseline", None)
            report = json.loads((output / "pgo-build.json").read_text())
            self.assertEqual(report["status"], "BUILT" if mode == "success" else "FAILED")
            self.assertFalse(report["qualification"])
            self.assertFalse((output / "provenance.json").exists())
            for line in (output / "SHA256SUMS").read_text().splitlines():
                expected, name = line.split(maxsplit=1)
                self.assertEqual(hashlib.sha256((output / name).read_bytes()).hexdigest(), expected)

    def test_successful_build_is_sealed_and_not_a_qualification_bundle(self):
        self.lifecycle("success")

    def test_compilation_failure_is_sealed(self):
        self.lifecycle("compile-failure")

    def test_compiler_metadata_failure_is_sealed(self):
        self.lifecycle("tool-failure")

    def test_baseline_explicit_target_and_scrubbed_environment(self):
        command, env, plan = build_plan(Path("/source"), Path("/output"), "baseline", None,
            {"RUSTFLAGS": "-Ctarget-cpu=native", "CARGO_ENCODED_RUSTFLAGS": "bad",
             "RUSTC_WRAPPER": "bad", "LLVM_PROFILE_FILE": "bad", "PATH": "/usr/bin",
             "CARGO_PROFILE_RELEASE_OPT_LEVEL": "0", "CARGO_PROFILE_RELEASE_DEBUG": "true"})
        self.assertEqual(command[command.index("--target") + 1], TARGET)
        self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"], "")
        self.assertEqual(env["CARGO_PROFILE_RELEASE_OPT_LEVEL"], "3")
        self.assertNotIn("RUSTC_WRAPPER", env)
        self.assertNotIn("LLVM_PROFILE_FILE", env)
        self.assertNotIn("CARGO_PROFILE_RELEASE_DEBUG", env)
        self.assertIsNone(plan["profile_sha256"])

    def test_generation_requires_fresh_directory_and_handles_spaces(self):
        with tempfile.TemporaryDirectory(prefix="pgo test ") as directory:
            profile = Path(directory)
            _, env, _ = build_plan(Path("/source"), Path("/output"), "generate", profile, {})
            self.assertEqual(env["CARGO_ENCODED_RUSTFLAGS"], f"-Cprofile-generate={profile}")
            (profile / "old.profraw").write_bytes(b"old")
            with self.assertRaises(ValueError):
                build_plan(Path("/source"), Path("/output"), "generate", profile, {})

    def test_use_records_profile_identity_and_warns_missing_functions(self):
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "merged.profdata"
            profile.write_bytes(b"test identity only")
            _, env, plan = build_plan(Path("/source"), Path("/output"), "use", profile, {})
            self.assertEqual(plan["profile_sha256"], hashlib.sha256(profile.read_bytes()).hexdigest())
            self.assertIn("\x1f-Cllvm-args=-pgo-warn-missing-function", env["CARGO_ENCODED_RUSTFLAGS"])

    def test_invalid_modes_and_paths_fail(self):
        for phase, profile in (("unknown", None), ("baseline", Path("/profile")),
                               ("generate", None), ("use", Path("relative")),
                               ("use", Path("/nonexistent-everudp-profile"))):
            with self.subTest(phase=phase), self.assertRaises(ValueError):
                build_plan(Path("/source"), Path("/output"), phase, profile, {})
        with self.assertRaises(ValueError):
            build_plan(Path("relative"), Path("/output"), "baseline", None, {})


if __name__ == "__main__":
    unittest.main()
