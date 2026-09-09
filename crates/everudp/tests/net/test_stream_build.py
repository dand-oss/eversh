"""Exercise the actual stream recipe without compiling or opening sockets."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

NET = Path(__file__).resolve().parent
SCRIPT = NET / "build-stream-floor.sh"
ROOT = NET.parents[3]


class StreamBuildTests(unittest.TestCase):
    def test_confounded_options_fail_before_creating_output(self):
        options = ("EVERUDP_FLOOR_DIAGNOSTICS", "EVERUDP_FLOOR_SEND_FAST_PATH",
                   "EVERUDP_FLOOR_ACK_INLINE_STORAGE", "EVERUDP_FLOOR_SINGLE_OWNER",
                   "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "RUSTC_BOOTSTRAP", "CARGO_BUILD_TARGET")
        base = {key: value for key, value in os.environ.items() if key not in options}
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw) / "build"
            for option in options:
                with self.subTest(option=option):
                    result = subprocess.run(["bash", str(SCRIPT), str(output)],
                                            env=dict(base, **{option: "1"}),
                                            capture_output=True, text=True, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn("stream build forbids " + option, result.stderr)
                    self.assertFalse(output.exists())

    def test_actual_cargo_invocation_locks_profile_and_feature_closure(self):
        source = SCRIPT.read_text()
        recipe = source.split("# BEGIN ISOLATED CARGO BUILD\n", 1)[1].split("# END ISOLATED CARGO BUILD", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            (Path(raw) / "logs").mkdir()
            env = dict(os.environ, OUTDIR=raw, ROOT_TARGET="/isolated-target", SOURCE=raw,
                       STREAM_CARGO_HOME=raw + "/empty-cargo-home", CARGO_EXECUTABLE=raw + "/cargo-stub",
                       FLOOR_FEATURES="cli,stream-floor", RUSTFLAGS="confounded", CARGO_ENCODED_RUSTFLAGS="confounded",
                       CARGO_BUILD_RUSTFLAGS="confounded", CARGO_PROFILE_RELEASE_DEBUG="confounded")
            stub = '''#!/bin/bash
set -euo pipefail
[[ ! -v CARGO_BUILD_RUSTFLAGS && ! -v CARGO_PROFILE_RELEASE_DEBUG ]]
[[ $PWD == "$HOME" ]] && exit 90
[[ $CARGO_HOME == "$PWD/empty-cargo-home" ]]
printf '%s\\n' "$CARGO_PROFILE_RELEASE_LTO" "$CARGO_PROFILE_RELEASE_CODEGEN_UNITS" "$CARGO_PROFILE_RELEASE_PANIC" "$CARGO_PROFILE_RELEASE_OPT_LEVEL" "$RUSTFLAGS" "$CARGO_ENCODED_RUSTFLAGS" "$CARGO_TARGET_DIR"
printf '%s\\n' "$@"
'''
            (Path(raw) / "cargo-stub").write_text(stub)
            (Path(raw) / "cargo-stub").chmod(0o700)
            result = subprocess.run(["bash", "-c", "set -euo pipefail\n" + recipe],
                                    env=env, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            lines = (Path(raw) / "logs/everudp-stream-floor-build.stdout").read_text().splitlines()
            self.assertEqual(lines[:7], ["fat", "1", "unwind", "3", "", "", "/isolated-target"])
            self.assertEqual(lines[7:], ["build", "--locked", "--release", "--manifest-path",
                                         raw + "/Cargo.toml", "-p", "everudp",
                                         "--no-default-features", "--features", "cli,stream-floor",
                                         "--example", "everudp-stream-floor"])

    def test_actual_provenance_is_stream_specific(self):
        source = SCRIPT.read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
        with tempfile.TemporaryDirectory() as raw:
            output = Path(raw)
            (output / "artifacts/bin").mkdir(parents=True)
            for name in ("everudp-stream-floor", "zmosh-udp", "pty-bench", "pty-echo"):
                (output / "artifacts/bin" / name).write_bytes(b"fixture")
            arguments = ["-", raw, str(ROOT), str(NET), "a" * 40, "b" * 40,
                         "dfc8395b5edcd237bf82712fbde879c6e8be7dfa", "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514",
                         "started", "finished", "cargo", "rustc", "cc", "git", "0.15.2", "c" * 64, "cli,stream-floor"]
            with patch.object(sys, "argv", arguments):
                exec(compile(source, "build-stream-floor.sh:provenance", "exec"), {})
            receipt = json.loads((output / "provenance.json").read_text())
            self.assertEqual(receipt["purpose"], "matched-noq-reliable-stream-floor")
            self.assertEqual(set(receipt["tool_binaries"]), {"cargo", "rustc", "cc", "git"})
            for tool in receipt["tool_binaries"].values():
                self.assertTrue(Path(tool["path"]).is_absolute())
                self.assertEqual(len(tool["sha256"]), 64)
            self.assertEqual(set(receipt["artifacts"]), {"everudp-stream-floor", "zmosh-udp", "pty-bench", "pty-echo"})
            build = receipt["everudp_build"]
            self.assertEqual(build["cargo_features"], ["cli", "stream-floor"])
            self.assertFalse(build["default_features"])
            self.assertFalse(build["diagnostic_build"])
            self.assertEqual(build["runtime_modes"], ["ordinary", "native"])
            self.assertEqual(build["profile"], {"lto": "fat", "codegen_units": 1, "panic": "unwind",
                                                "opt_level": 3, "rustflags": "", "target_cpu": "portable default"})
            self.assertTrue(receipt["isolation"]["archived_eversh_source"])
            self.assertTrue(receipt["isolation"]["empty_cargo_home"])
            self.assertTrue(receipt["isolation"]["cleared_cargo_environment"])


if __name__ == "__main__":
    unittest.main()
