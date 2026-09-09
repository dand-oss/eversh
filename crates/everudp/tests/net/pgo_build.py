"""Isolated PGO experiment builds, deliberately not performance-build bundles."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess

TARGET = "x86_64-unknown-linux-gnu"


def build_plan(root, output, phase, profile, inherited):
    root, output = Path(root), Path(output)
    if not root.is_absolute() or not output.is_absolute():
        raise ValueError("absolute source/output paths required")
    if phase not in ("baseline", "generate", "use"):
        raise ValueError("invalid PGO phase")
    flags = []
    profile_hash = None
    if phase == "baseline":
        if profile is not None:
            raise ValueError("baseline must not consume a profile")
    else:
        profile = Path(profile) if profile is not None else None
        if profile is None or not profile.is_absolute() or "\x1f" in str(profile):
            raise ValueError("absolute profile path required")
        if phase == "generate":
            if not profile.is_dir() or any(profile.iterdir()):
                raise ValueError("generation directory must exist and be empty")
            flags = [f"-Cprofile-generate={profile}"]
        else:
            if not profile.is_file() or profile.stat().st_size == 0:
                raise ValueError("nonempty merged profile required")
            profile_hash = hashlib.sha256(profile.read_bytes()).hexdigest()
            flags = [f"-Cprofile-use={profile}", "-Cllvm-args=-pgo-warn-missing-function"]
    env = {k: v for k, v in inherited.items()
           if not k.startswith("CARGO_PROFILE_RELEASE_") and k not in
           ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS", "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER", "RUSTC", "LLVM_PROFILE_FILE")}
    env.update(CARGO_TARGET_DIR=str(output / "target"), CARGO_PROFILE_RELEASE_LTO="fat",
               CARGO_PROFILE_RELEASE_CODEGEN_UNITS="1", CARGO_PROFILE_RELEASE_PANIC="unwind",
               CARGO_PROFILE_RELEASE_OPT_LEVEL="3", RUSTFLAGS="",
               CARGO_ENCODED_RUSTFLAGS="\x1f".join(flags))
    command = ["cargo", "build", "--locked", "--release", "--target", TARGET,
               "--manifest-path", str(root / "Cargo.toml"), "-p", "everudp", "--features", "cli"]
    return command, env, {"phase": phase, "target": TARGET, "flags": flags,
                          "profile": str(profile) if profile is not None else None,
                          "profile_sha256": profile_hash}


def run(root, output, phase, profile):
    command, env, plan = build_plan(root, output, phase, profile, os.environ)
    if output.exists():
        raise ValueError("refusing to overwrite experiment build")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip()
    tree = subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=root, text=True).strip()
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
        raise ValueError("clean source required")
    output.mkdir(mode=0o700, parents=True)
    report = {"schema_version": 1, "status": "FAILED", "qualification": False,
              "source": {"head_sha": head, "tree_sha": tree}, "plan": plan,
              "command": command}
    try:
        report["rustc"] = subprocess.check_output(["rustc", "-vV"], text=True)
        report["cargo"] = subprocess.check_output(["cargo", "--version"], text=True)
        with (output / "stdout.log").open("w") as stdout, (output / "stderr.log").open("w") as stderr:
            subprocess.run(command, cwd=root, env=env, stdout=stdout, stderr=stderr, check=True)
        if plan["profile_sha256"] is not None:
            if hashlib.sha256(Path(profile).read_bytes()).hexdigest() != plan["profile_sha256"]:
                raise ValueError("profile changed during compilation")
        if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root, text=True).strip() != head:
            raise ValueError("source HEAD changed during compilation")
        if subprocess.check_output(["git", "status", "--porcelain"], cwd=root):
            raise ValueError("source changed during compilation")
        binary = output / "target" / TARGET / "release/everudp"
        report["binary_sha256"] = hashlib.sha256(binary.read_bytes()).hexdigest()
        report["binary"] = str(binary)
        report["status"] = "BUILT"
    finally:
        # No provenance.json: ordinary benchmark/qualification entrypoints must
        # not mistake these training or experimental artifacts for release builds.
        (output / "pgo-build.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        names = [name for name in ("pgo-build.json", "stdout.log", "stderr.log")
                 if (output / name).is_file()]
        (output / "SHA256SUMS").write_text("".join(
            f"{hashlib.sha256((output / name).read_bytes()).hexdigest()}  {name}\n" for name in names))
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("baseline", "generate", "use"))
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--profile", type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.source, args.output, args.phase, args.profile), sort_keys=True))
