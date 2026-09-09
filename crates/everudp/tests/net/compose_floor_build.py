#!/usr/bin/env python3
"""Compose a floor benchmark bundle from two independently sealed builds.

The runtime build supplies ``everudp-floor``.  A previously sealed control
build supplies the C fixtures and zmosh binary.  This helper is intentionally
fail-closed: it verifies every file in each input seal before copying, never
modifies an input, and refuses to overwrite an output directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any


FROZEN_ZMOSH_COMMIT = "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
FROZEN_ZMOSH_TREE = "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514"
ARTIFACTS = ("everudp-floor", "pty-bench", "pty-echo", "zmosh-udp")
CONTROL_ARTIFACTS = ("pty-bench", "pty-echo", "zmosh-udp")
BUILD_MATCH_FIELDS = ("cargo_features", "profile", "target", "diagnostic_build")


class ComposeError(RuntimeError):
    """An input or output failed the composition contract."""


def _fail(message: str) -> None:
    raise ComposeError(message)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_relative(root: Path, value: Any, *, label: str) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail(f"{label} is not a safe relative path")
    relative = Path(value)
    if relative.is_absolute() or any(part in ("", ".", "..") for part in relative.parts):
        _fail(f"{label} escapes its build root")
    raw = root / relative
    if raw.is_symlink():
        _fail(f"{label} is a symlink")
    candidate = raw.resolve(strict=True)
    try:
        candidate.relative_to(root)
    except ValueError:
        _fail(f"{label} escapes its build root")
    if not candidate.is_file() or candidate.is_symlink():
        _fail(f"{label} is not a regular file")
    return relative


def _read_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        _fail(f"cannot read {label}: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _load_sealed_build(root_arg: str, label: str) -> tuple[Path, dict[str, Any], dict[str, str]]:
    raw_root = Path(root_arg).expanduser()
    if raw_root.is_symlink():
        _fail(f"{label} root is a symlink")
    root = raw_root.resolve(strict=True)
    if not root.is_dir():
        _fail(f"{label} is not a directory")
    provenance_path = root / "provenance.json"
    seal_path = root / "SHA256SUMS"
    if not provenance_path.is_file() or not seal_path.is_file():
        _fail(f"{label} lacks provenance.json or SHA256SUMS")

    try:
        lines = seal_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        _fail(f"cannot read {label} seal: {error}")
    sealed: dict[str, str] = {}
    for line in lines:
        if not line or "  " not in line:
            _fail(f"{label} has malformed SHA256SUMS entry")
        digest, relative_text = line.split("  ", 1)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            _fail(f"{label} has malformed digest")
        if relative_text in sealed:
            _fail(f"{label} repeats sealed path {relative_text}")
        relative = _safe_relative(root, relative_text, label=f"{label} seal path")
        sealed[str(relative)] = digest

    actual: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail(f"{label} contains symlink {path.relative_to(root)}")
        if path.is_file() and path == seal_path:
            continue
        if path.is_file() and path.name == "SHA256SUMS":
            _fail(f"{label} contains an unexpected nested SHA256SUMS")
        if path.is_file():
            actual[str(path.relative_to(root))] = _sha256(path)
    if set(actual) != set(sealed):
        missing = sorted(set(actual) - set(sealed))
        extra = sorted(set(sealed) - set(actual))
        _fail(f"{label} seal inventory mismatch; missing={missing}, extra={extra}")
    for relative, expected in sealed.items():
        if actual[relative] != expected:
            _fail(f"{label} digest mismatch for {relative}")

    provenance = _read_json(provenance_path, f"{label} provenance")
    if type(provenance.get("schema_version")) is not int or provenance["schema_version"] != 1:
        _fail(f"{label} has an unsupported provenance schema")
    artifacts = provenance.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACTS):
        _fail(f"{label} must contain exactly the known floor artifacts")
    for name in ARTIFACTS:
        entry = artifacts[name]
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            _fail(f"{label} artifact {name} has an unsupported shape")
        relative = _safe_relative(root, entry["path"], label=f"{label} artifact {name}")
        if str(relative) != f"artifacts/bin/{name}":
            _fail(f"{label} artifact {name} is not at the canonical path")
        if entry["sha256"] != sealed[str(relative)]:
            _fail(f"{label} artifact {name} disagrees with its seal")

    source = provenance.get("source")
    zmosh = provenance.get("zmosh_source")
    if not isinstance(source, dict) or source.get("clean") is not True:
        _fail(f"{label} source is not marked clean")
    for field in ("head_sha", "tree_sha"):
        value = source.get(field)
        if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            _fail(f"{label} source {field} is missing or malformed")
    if not isinstance(zmosh, dict) or zmosh.get("clean") is not True:
        _fail(f"{label} zmosh source is not marked clean")
    if zmosh.get("commit") != FROZEN_ZMOSH_COMMIT or zmosh.get("tree") != FROZEN_ZMOSH_TREE:
        _fail(f"{label} zmosh source is not the frozen control")
    build = provenance.get("everudp_build")
    if not isinstance(build, dict):
        _fail(f"{label} lacks everudp_build provenance")
    for field in BUILD_MATCH_FIELDS:
        if field not in build:
            _fail(f"{label} everudp_build lacks {field}")
    features = build["cargo_features"]
    if (
        not isinstance(features, list)
        or not features
        or any(not isinstance(feature, str) or not feature for feature in features)
        or len(set(features)) != len(features)
    ):
        _fail(f"{label} everudp_build cargo_features are malformed")
    if not isinstance(build["profile"], dict) or not isinstance(build["target"], str) or not build["target"]:
        _fail(f"{label} everudp_build profile/target are malformed")
    profile = build["profile"]
    if set(profile) != {"codegen_units", "lto", "panic", "rustflags", "target_cpu"}:
        _fail(f"{label} build profile fields are incomplete or unsupported")
    if type(profile["codegen_units"]) is not int or profile["codegen_units"] <= 0:
        _fail(f"{label} build profile codegen_units is malformed")
    if any(not isinstance(profile[field], str) for field in ("lto", "panic", "rustflags", "target_cpu")):
        _fail(f"{label} build profile strings are malformed")
    if any(not profile[field] for field in ("lto", "panic", "target_cpu")):
        _fail(f"{label} build profile fields are empty")
    if not isinstance(build["diagnostic_build"], bool) or build["diagnostic_build"]:
        _fail(f"{label} is not a non-diagnostic floor build")
    inputs = provenance.get("inputs")
    if not isinstance(inputs, dict):
        _fail(f"{label} lacks build inputs")
    for name in ("pty-bench.c", "pty-echo.c"):
        digest = inputs.get(name)
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            _fail(f"{label} fixture digest for {name} is missing or malformed")
    for name in ARTIFACTS:
        digest = artifacts[name]["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            _fail(f"{label} artifact {name} has a malformed digest")
    return root, provenance, sealed


def _validate_match(runtime: dict[str, Any], control: dict[str, Any]) -> None:
    if runtime["everudp_build"] != control["everudp_build"]:
        _fail("runtime/control everudp_build metadata mismatch")
    runtime_inputs = runtime.get("inputs")
    control_inputs = control.get("inputs")
    if not isinstance(runtime_inputs, dict) or not isinstance(control_inputs, dict):
        _fail("runtime/control inputs are missing")
    for name in ("pty-bench.c", "pty-echo.c"):
        if runtime_inputs.get(name) != control_inputs.get(name):
            _fail(f"runtime/control PTY fixture digest mismatch for {name}")
    for name in ("pty-bench", "pty-echo"):
        if runtime["artifacts"][name]["sha256"] != control["artifacts"][name]["sha256"]:
            _fail(f"runtime/control PTY fixture artifact mismatch for {name}")
    if runtime.get("zmosh_source") != control.get("zmosh_source"):
        _fail("runtime/control frozen zmosh source mismatch")


def _copy_verified(source_root: Path, relative: str, expected: str, destination: Path) -> None:
    source = _safe_relative(source_root, relative, label="selected artifact")
    if _sha256(source_root / source) != expected:
        _fail(f"selected artifact digest changed for {relative}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source_root / source, destination)
    if _sha256(destination) != expected:
        _fail(f"copied artifact digest mismatch for {relative}")


def compose(runtime_arg: str, control_arg: str, output_arg: str) -> Path:
    runtime_root, runtime, runtime_seal = _load_sealed_build(runtime_arg, "runtime build")
    control_root, control, control_seal = _load_sealed_build(control_arg, "control build")
    _validate_match(runtime, control)
    raw_output = Path(output_arg).expanduser()
    if raw_output.is_symlink():
        _fail("output may not be a symlink")
    output = raw_output.resolve(strict=False)
    if output.exists():
        _fail(f"output already exists: {output}")
    if output == runtime_root or output == control_root:
        _fail("output must be separate from both inputs")
    for root in (runtime_root, control_root):
        try:
            output.relative_to(root)
        except ValueError:
            continue
        _fail("output may not be inside an input build")
    output.mkdir(parents=True)
    try:
        for name in ARTIFACTS:
            source_root = runtime_root if name == "everudp-floor" else control_root
            source_provenance = runtime if name == "everudp-floor" else control
            _copy_verified(
                source_root,
                f"artifacts/bin/{name}",
                source_provenance["artifacts"][name]["sha256"],
                output / f"artifacts/bin/{name}",
            )

        runtime_provenance_bytes = (runtime_root / "provenance.json").read_bytes()
        control_provenance_bytes = (control_root / "provenance.json").read_bytes()
        if hashlib.sha256(runtime_provenance_bytes).hexdigest() != runtime_seal["provenance.json"]:
            _fail("runtime provenance changed after validation")
        if hashlib.sha256(control_provenance_bytes).hexdigest() != control_seal["provenance.json"]:
            _fail("control provenance changed after validation")
        (output / "provenance-inputs").mkdir()
        (output / "provenance-inputs/runtime.json").write_bytes(runtime_provenance_bytes)
        (output / "provenance-inputs/control.json").write_bytes(control_provenance_bytes)

        composed = json.loads(json.dumps(runtime))
        composed["artifacts"] = {
            name: {
                "path": f"artifacts/bin/{name}",
                "sha256": (runtime if name == "everudp-floor" else control)["artifacts"][name]["sha256"],
            }
            for name in ARTIFACTS
        }
        composed["control_reuse"] = {
            "schema_version": 1,
            "runtime_provenance_sha256": runtime_seal["provenance.json"],
            "control_provenance_sha256": control_seal["provenance.json"],
            "runtime_input": "provenance-inputs/runtime.json",
            "control_input": "provenance-inputs/control.json",
            "selected_control_artifacts": {
                name: {
                    "source_build": "control",
                    "source_path": control["artifacts"][name]["path"],
                    "sha256": control["artifacts"][name]["sha256"],
                }
                for name in CONTROL_ARTIFACTS
            },
            "selected_runtime_artifact": {
                "source_build": "runtime",
                "source_path": runtime["artifacts"]["everudp-floor"]["path"],
                "sha256": runtime["artifacts"]["everudp-floor"]["sha256"],
            },
        }
        provenance_path = output / "provenance.json"
        provenance_path.write_text(json.dumps(composed, indent=2, sort_keys=True) + "\n", encoding="utf-8")

        files = sorted(
            path.relative_to(output).as_posix()
            for path in output.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        )
        with (output / "SHA256SUMS").open("w", encoding="utf-8") as seal:
            for relative in files:
                seal.write(f"{_sha256(output / relative)}  {relative}\n")
        # Verify the just-created bundle using the same strict inventory checks.
        _load_sealed_build(str(output), "composed output")
        return output
    except Exception:
        shutil.rmtree(output, ignore_errors=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_build")
    parser.add_argument("control_build")
    parser.add_argument("output_dir")
    args = parser.parse_args(argv)
    try:
        output = compose(args.runtime_build, args.control_build, args.output_dir)
    except (ComposeError, OSError, ValueError) as error:
        print(f"compose-floor-build: {error}", file=sys.stderr)
        return 2
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
