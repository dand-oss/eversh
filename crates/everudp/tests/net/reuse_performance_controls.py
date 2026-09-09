#!/usr/bin/env python3
"""Copy controls from one sealed ordinary performance build.

This helper deliberately has no build logic.  A candidate build may reuse an
already sealed ordinary bundle's controls, but only after the complete input
bundle and its provenance have been checked.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import sys
from typing import Any


FROZEN_UDP = {
    "commit": "dfc8395b5edcd237bf82712fbde879c6e8be7dfa",
    "tree": "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514",
}
FROZEN_QUIC = {
    "commit": "21db4a4de6040b254531f2131b6f1c0cd146a7a1",
    "tree": "38ea33069ce480a1b6465d4c49eafc59c3b6edd8",
}
ARTIFACTS = (
    "everudp",
    "pty-bench",
    "pty-echo",
    "zmosh-quic",
    "zmosh-quic-bridge",
    "zmosh-udp",
)
CONTROL_ARTIFACTS = tuple(name for name in ARTIFACTS if name != "everudp")
FIXTURE_INPUTS = (
    "pty-bench.c",
    "pty-echo.c",
    "zmosh-quic-bench-build.zig",
    "zmosh-quic-bridge.zig",
)
PROFILE = {
    "codegen_units": 1,
    "encoded_rustflags": "",
    "lto": "fat",
    "opt_level": 3,
    "panic": "unwind",
    "rustflags": "",
    "target_cpu": "portable default",
}


class ReuseError(RuntimeError):
    """The input or destination does not satisfy the reuse contract."""


def _fail(message: str) -> None:
    raise ReuseError(message)


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
    try:
        candidate = raw.resolve(strict=True)
    except OSError as error:
        _fail(f"{label} does not exist: {error}")
    try:
        candidate.relative_to(root)
    except ValueError:
        _fail(f"{label} escapes its build root")
    if not candidate.is_file() or candidate.is_symlink():
        _fail(f"{label} is not a regular file")
    return relative


def _read_json(path: Path, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"{label} contains duplicate key {key}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, ValueError) as error:
        _fail(f"cannot read {label}: {error}")
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _load_seal(root: Path) -> dict[str, str]:
    seal_path = root / "SHA256SUMS"
    if not seal_path.is_file() or seal_path.is_symlink():
        _fail("control build lacks a regular SHA256SUMS")
    try:
        lines = seal_path.read_text(encoding="utf-8").splitlines()
    except OSError as error:
        _fail(f"cannot read control SHA256SUMS: {error}")
    sealed: dict[str, str] = {}
    for line in lines:
        if not line or "  " not in line:
            _fail("control SHA256SUMS has a malformed entry")
        digest, relative_text = line.split("  ", 1)
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            _fail("control SHA256SUMS has a malformed digest")
        if relative_text in sealed:
            _fail(f"control SHA256SUMS repeats {relative_text}")
        relative = _safe_relative(root, relative_text, label="control seal path")
        sealed[str(relative)] = digest

    actual: dict[str, str] = {}
    for path in root.rglob("*"):
        if path.is_symlink():
            _fail(f"control build contains symlink {path.relative_to(root)}")
        if path.is_file() and path == seal_path:
            continue
        if path.is_file() and path.name == "SHA256SUMS":
            _fail(f"control build contains nested SHA256SUMS: {path.relative_to(root)}")
        if path.is_file():
            actual[str(path.relative_to(root))] = _sha256(path)
    if set(actual) != set(sealed):
        _fail(
            "control seal inventory mismatch; "
            f"missing={sorted(set(actual) - set(sealed))}, "
            f"extra={sorted(set(sealed) - set(actual))}"
        )
    for relative, expected in sealed.items():
        if actual[relative] != expected:
            _fail(f"control digest mismatch for {relative}")
    return sealed


def _load_control(root_arg: str, net: Path) -> tuple[Path, dict[str, Any], dict[str, str]]:
    raw_root = Path(root_arg).expanduser()
    if raw_root.is_symlink():
        _fail("control build root is a symlink")
    try:
        root = raw_root.resolve(strict=True)
    except OSError as error:
        _fail(f"control build root does not exist: {error}")
    if not root.is_dir():
        _fail("control build root is not a directory")
    sealed = _load_seal(root)
    provenance_path = root / "provenance.json"
    if not provenance_path.is_file() or provenance_path.is_symlink():
        _fail("control build lacks a regular provenance.json")
    provenance = _read_json(provenance_path, "control provenance")
    if sealed.get("provenance.json") != _sha256(provenance_path):
        _fail("control provenance is not covered by SHA256SUMS")
    if type(provenance.get("schema_version")) is not int or provenance["schema_version"] != 1:
        _fail("control provenance schema is unsupported")
    if "control_reuse" in provenance or (root / "provenance-inputs").exists():
        _fail("control build recursively reuses another control bundle")

    source = provenance.get("source")
    if not isinstance(source, dict) or source.get("clean") is not True:
        _fail("control source is not marked clean")
    for field in ("head_sha", "tree_sha"):
        value = source.get(field)
        if not isinstance(value, str) or len(value) != 40 or any(c not in "0123456789abcdef" for c in value):
            _fail(f"control source {field} is malformed")

    zmosh = provenance.get("zmosh_sources")
    if not isinstance(zmosh, dict) or set(zmosh) != {"udp", "quic"}:
        _fail("control zmosh_sources are incomplete")
    for name, expected in (("udp", FROZEN_UDP), ("quic", FROZEN_QUIC)):
        entry = zmosh[name]
        if not isinstance(entry, dict) or entry.get("clean") is not True:
            _fail(f"control {name} zmosh source is not clean")
        if entry.get("commit") != expected["commit"] or entry.get("tree") != expected["tree"]:
            _fail(f"control {name} zmosh source is not frozen")

    build = provenance.get("everudp_build")
    if not isinstance(build, dict) or build.get("cargo_features") != ["cli"]:
        _fail("control build must use exactly the ordinary cli feature")
    if build.get("profile") != PROFILE:
        _fail("control build does not use the exact portable release profile")

    artifacts = provenance.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(ARTIFACTS):
        _fail("control provenance must contain exactly six artifacts")
    for name in ARTIFACTS:
        entry = artifacts[name]
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256"}:
            _fail(f"control artifact {name} has an unsupported shape")
        relative = _safe_relative(root, entry["path"], label=f"control artifact {name}")
        if str(relative) != f"artifacts/bin/{name}":
            _fail(f"control artifact {name} is not at its canonical path")
        digest = entry["sha256"]
        if not isinstance(digest, str) or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            _fail(f"control artifact {name} has a malformed digest")
        if sealed[str(relative)] != digest:
            _fail(f"control artifact {name} disagrees with SHA256SUMS")

    inputs = provenance.get("inputs")
    if not isinstance(inputs, dict):
        _fail("control provenance lacks inputs")
    for name in FIXTURE_INPUTS:
        path = net / name
        if not path.is_file() or path.is_symlink():
            _fail(f"current benchmark input {name} is not a regular file")
        recorded = inputs.get(name)
        if not isinstance(recorded, str) or len(recorded) != 64 or any(c not in "0123456789abcdef" for c in recorded):
            _fail(f"control fixture input {name} has a malformed digest")
        if recorded != _sha256(path):
            _fail(f"control fixture input {name} differs from the current benchmark input")
    return root, provenance, sealed


def copy_controls(control_dir: str, output_dir: str, net_dir: str) -> None:
    """Copy the five controls from a validated bundle into an existing build."""
    net = Path(net_dir).expanduser().resolve(strict=True)
    if not net.is_dir():
        _fail("benchmark input directory is not a directory")
    root, provenance, sealed = _load_control(control_dir, net)
    raw_output = Path(output_dir).expanduser()
    if raw_output.is_symlink():
        _fail("output build root is a symlink")
    output = raw_output.resolve(strict=True)
    if not output.is_dir() or output == root:
        _fail("output build root must be an existing directory distinct from control")
    artifacts_root = output / "artifacts"
    artifact_dir = artifacts_root / "bin"
    if artifacts_root.is_symlink() or artifact_dir.is_symlink() or not artifact_dir.is_dir():
        _fail("output artifacts/bin must be an existing directory")
    provenance_dir = output / "provenance-inputs"
    if provenance_dir.exists() and (provenance_dir.is_symlink() or not provenance_dir.is_dir()):
        _fail("output provenance-inputs is not a directory")
    destinations = [artifact_dir / name for name in CONTROL_ARTIFACTS]
    if any(path.exists() or path.is_symlink() for path in destinations):
        _fail("refusing to overwrite an existing control artifact")
    control_provenance = output / "provenance-inputs" / "control.json"
    if control_provenance.exists() or control_provenance.is_symlink():
        _fail("refusing to overwrite control provenance")
    provenance_dir.mkdir(mode=0o700, exist_ok=True)

    for name, destination in zip(CONTROL_ARTIFACTS, destinations):
        source = root / f"artifacts/bin/{name}"
        expected = provenance["artifacts"][name]["sha256"]
        if _sha256(source) != expected:
            _fail(f"control artifact {name} changed after validation")
        shutil.copy2(source, destination)
        if destination.is_symlink() or _sha256(destination) != expected:
            _fail(f"copied control artifact {name} failed digest verification")
    original_provenance = root / "provenance.json"
    provenance_bytes = original_provenance.read_bytes()
    if hashlib.sha256(provenance_bytes).hexdigest() != sealed["provenance.json"]:
        _fail("control provenance changed after validation")
    control_provenance.write_bytes(provenance_bytes)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control_dir")
    parser.add_argument("output_dir")
    parser.add_argument("net_dir")
    args = parser.parse_args(argv)
    try:
        copy_controls(args.control_dir, args.output_dir, args.net_dir)
    except (OSError, ReuseError, ValueError) as error:
        print(f"reuse-performance-controls: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
