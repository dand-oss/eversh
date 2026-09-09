"""The measured release settings must reach Cargo and match the workspace."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest

NET = Path(__file__).resolve().parent
ROOT = NET.parents[3]
EXPECTED = {
    "CARGO_PROFILE_RELEASE_LTO": "fat",
    "CARGO_PROFILE_RELEASE_CODEGEN_UNITS": "1",
    "CARGO_PROFILE_RELEASE_PANIC": "unwind",
    "CARGO_PROFILE_RELEASE_OPT_LEVEL": "3",
    "RUSTFLAGS": "",
    "CARGO_ENCODED_RUSTFLAGS": "",
}


class ReleaseProfileTests(unittest.TestCase):
    def test_workspace_profile_matches_measured_variant(self):
        profile = tomllib.loads((ROOT / "Cargo.toml").read_text())["profile"]["release"]
        for key, value in {"lto": "fat", "codegen-units": 1,
                           "panic": "unwind", "opt-level": 3}.items():
            self.assertEqual(profile.get(key), value)

    def test_build_command_overrides_inherited_profile_and_flags(self):
        for engine in ("noq", "quinn-eval"):
            with self.subTest(engine=engine):
                self.check_build_command(engine)

    def check_build_command(self, engine):
        script = (NET / "build-performance.sh").read_text()
        selection = script[script.index("EVERUDP_FEATURES="):script.index("[[ ! -e $OUTDIR ]]")]
        command = script[script.index("CARGO_TARGET_DIR=$ROOT_TARGET"):]
        command = command[:command.index("\ninstall -m")]
        with tempfile.TemporaryDirectory(prefix="everudp-profile-") as directory:
            root = Path(directory)
            (root / "logs").mkdir()
            cargo = root / "cargo"
            cargo.write_text("#!/usr/bin/python3\nimport json, os, sys\nprint(json.dumps({'profile':{k:os.environ.get(k) for k in "
                             + repr(list(EXPECTED)) + "},'args':sys.argv[1:]}))\n")
            cargo.chmod(0o700)
            env = {**os.environ, **{key: "fixture-override" for key in EXPECTED},
                   "PATH": str(root) + os.pathsep + os.environ["PATH"],
                   "ROOT_TARGET": str(root / "target"), "ROOT": str(ROOT),
                   "OUTDIR": str(root), "EVERUDP_CARGO_FEATURES": "cli",
                   "EVERUDP_ENGINE": engine}
            subprocess.run(["bash", "-eu", "-c", selection + command], env=env, check=True,
                           capture_output=True, timeout=5)
            result = json.loads((root / "logs/everudp-build.stdout").read_text())
            self.assertEqual(result["profile"], EXPECTED)
            manifest = "Cargo.toml" if engine == "noq" else "spikes/everudp-quinn-eval/Cargo.toml"
            package = "everudp" if engine == "noq" else "everudp-quinn-eval"
            self.assertEqual(result["args"], ["build", "--locked", "--release",
                             "--manifest-path", str(ROOT / manifest), "-p", package,
                             "--features", "cli"])


if __name__ == "__main__":
    unittest.main()
