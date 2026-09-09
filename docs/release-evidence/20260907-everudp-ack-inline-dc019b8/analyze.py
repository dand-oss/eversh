#!/usr/bin/env python3
"""Fail-closed diagnostic analysis for the ACK inline-storage A/B run."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import pathlib
import statistics
import sys
from typing import Any

EXPECTED_HEAD = "dc019b8ecf41279e1c33c223d9632562962fb223"
EXPECTED_TREE = "cfbe2988a78667ac9ab272070d088c5ac5d3ab1f"
EXPECTED = {
    f"loss{loss}-block{block}-{mode}"
    for loss in (0, 5)
    for block in (1, 2)
    for mode in ("control", "inline")
}
ORDERS = {1: ["everudp-floor", "zmosh-udp"], 2: ["zmosh-udp", "everudp-floor"]}
CANDIDATES = ("everudp-floor", "zmosh-udp")


class InvalidCollection(ValueError):
    pass


def read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InvalidCollection(f"cannot read JSON {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InvalidCollection(f"JSON object required: {path}")
    return value


def digest(path: pathlib.Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError as exc:
        raise InvalidCollection(f"cannot hash {path}: {exc}") from exc


def verify_inventory(block: pathlib.Path) -> None:
    base = block.resolve()
    for path in block.rglob("*"):
        if path.is_symlink() and not path.resolve(strict=True).is_relative_to(base):
            raise InvalidCollection(f"{block.name}: symlink escapes block")
    sums = block / "SHA256SUMS"
    try:
        entries: dict[str, str] = {}
        for line_no, line in enumerate(sums.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            parts = line.split(maxsplit=1)
            if len(parts) != 2 or len(parts[0]) != 64 or any(c not in "0123456789abcdefABCDEF" for c in parts[0]):
                raise InvalidCollection(f"{block.name}: malformed SHA256SUMS line {line_no}")
            name = parts[1][2:] if parts[1].startswith("./") else parts[1]
            rel = pathlib.PurePosixPath(name)
            if not name or rel.is_absolute() or ".." in rel.parts or name in entries:
                raise InvalidCollection(f"{block.name}: unsafe/duplicate checksum path {name}")
            entries[name] = parts[0]
    except OSError as exc:
        raise InvalidCollection(f"cannot read {sums}: {exc}") from exc
    actual = {p.relative_to(block).as_posix() for p in block.rglob("*") if p.is_file() and p.name != "SHA256SUMS"}
    if set(entries) != actual:
        raise InvalidCollection(f"{block.name}: checksum inventory mismatch")
    for name, expected in entries.items():
        if digest(block / name) != expected:
            raise InvalidCollection(f"{block.name}: digest mismatch {name}")


def parse_name(name: str) -> tuple[int, int, str]:
    parts = name.split("-", 2)
    try:
        loss = int(parts[0][4:])
        block = int(parts[1][5:])
        mode = parts[2]
    except (IndexError, ValueError) as exc:
        raise InvalidCollection(f"invalid block name {name}") from exc
    if name not in EXPECTED or loss not in (0, 5) or block not in (1, 2) or mode not in ("control", "inline"):
        raise InvalidCollection(f"unexpected block name {name}")
    return loss, block, mode


def result_samples(block: pathlib.Path, candidate: str, manifest: dict[str, Any]) -> list[int]:
    info = manifest.get("results", {}).get(candidate)
    if not isinstance(info, dict) or info.get("path") != f"{candidate}/result.json":
        raise InvalidCollection(f"{block.name}: result metadata missing for {candidate}")
    result = read_json(block / candidate / "result.json")
    if result.get("schema_version") != 1 or result.get("trials") != 200 or result.get("transcript_failures") != 0:
        raise InvalidCollection(f"{block.name}/{candidate}: result contract failed")
    if result.get("gap_ms") != 100 or result.get("public_clock") != "CLOCK_MONOTONIC; local host and time namespace only":
        raise InvalidCollection(f"{block.name}/{candidate}: timing metadata mismatch")
    samples = result.get("samples_us")
    if not isinstance(samples, list) or len(samples) != 200 or any(isinstance(x, bool) or not isinstance(x, int) or x <= 0 for x in samples):
        raise InvalidCollection(f"{block.name}/{candidate}: malformed samples")
    boundaries = result.get("public_boundaries")
    if not isinstance(boundaries, list) or len(boundaries) != 200:
        raise InvalidCollection(f"{block.name}/{candidate}: malformed public boundaries")
    previous = -1
    for index, boundary in enumerate(boundaries):
        if not isinstance(boundary, dict) or set(boundary) != {"trial", "send_ns", "accepted_ns"}:
            raise InvalidCollection(f"{block.name}/{candidate}: malformed boundary {index}")
        send, accepted = boundary["send_ns"], boundary["accepted_ns"]
        if boundary["trial"] != index or any(isinstance(x, bool) or not isinstance(x, int) for x in (boundary["trial"], send, accepted)) or send < 0 or send < previous or accepted < send:
            raise InvalidCollection(f"{block.name}/{candidate}: boundary order {index}")
        if samples[index] != (accepted - send + 999) // 1000:
            raise InvalidCollection(f"{block.name}/{candidate}: sample boundary mismatch {index}")
        previous = accepted
    if digest(block / candidate / "result.json") != info.get("sha256") or info.get("samples") != 200 or info.get("transcript_failures") != 0:
        raise InvalidCollection(f"{block.name}/{candidate}: result digest metadata mismatch")
    return samples


def import_accounting(net: pathlib.Path):
    spec = importlib.util.spec_from_file_location("packet_accounting", net / "packet_accounting.py")
    if spec is None or spec.loader is None:
        raise InvalidCollection(f"cannot load packet accounting helper from {net}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def account_block(block: pathlib.Path, candidate: str, manifest: dict[str, Any], accounting: Any) -> int:
    evidence = manifest.get("loss_evidence", {}).get(candidate)
    if not isinstance(evidence, dict):
        raise InvalidCollection(f"{block.name}/{candidate}: missing loss evidence")
    paths = [
        block / f"netem-{candidate}-client-before.txt",
        block / f"netem-{candidate}-client-after.txt",
        block / f"netem-{candidate}-server-before.txt",
        block / f"netem-{candidate}-server-after.txt",
    ]
    try:
        result = accounting.account_packet_attempts(*(p.read_text(encoding="utf-8") for p in paths))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise InvalidCollection(f"{block.name}/{candidate}: packet accounting failed: {exc}") from exc
    expected = {
        "client_egress_drop_delta": result.client.dropped_packets,
        "server_egress_drop_delta": result.server.dropped_packets,
        "client_egress_packet_delta": result.client.sent_packets,
        "server_egress_packet_delta": result.server.sent_packets,
        "summed_egress_attempt_delta": result.total_attempts,
    }
    for key, actual in expected.items():
        if evidence.get(key) != actual:
            raise InvalidCollection(f"{block.name}/{candidate}: packet evidence mismatch {key}")
    return result.total_attempts


def analyze(root: pathlib.Path, net: pathlib.Path, provenance_dir: pathlib.Path | None = None) -> dict[str, Any]:
    if not root.is_dir():
        raise InvalidCollection(f"collection root is not a directory: {root}")
    dirs = {p.name for p in root.iterdir() if p.is_dir()}
    if dirs != EXPECTED:
        raise InvalidCollection(f"expected exactly 8 blocks; missing={sorted(EXPECTED-dirs)} extra={sorted(dirs-EXPECTED)}")
    accounting = import_accounting(net)
    rows: list[dict[str, Any]] = []
    common_controls: dict[str, str] | None = None
    variant_artifacts: dict[str, str] = {}
    source: tuple[str, str] | None = None
    grouped: dict[tuple[int, str], dict[str, Any]] = {}
    for name in sorted(EXPECTED):
        block = root / name
        verify_inventory(block)
        loss, number, mode = parse_name(name)
        manifest = read_json(block / "manifest.json")
        if manifest.get("schema_version") != 1 or manifest.get("loss_percent_each_direction") != loss or manifest.get("trials_per_candidate") != 200 or manifest.get("gap_ms") != 100:
            raise InvalidCollection(f"{name}: manifest schedule/schema mismatch")
        if manifest.get("order") != ORDERS[number] or manifest.get("diagnostic_tracing") is not False:
            raise InvalidCollection(f"{name}: preregistered order/tracing mismatch")
        offset = ({"control": 1, "inline": 2} if number == 1 else {"inline": 3, "control": 4})[mode]
        seed = (90600 if loss == 0 else 90700) + offset
        if manifest.get("seeds") != {"client": seed, "server": seed + 1000003}:
            raise InvalidCollection(f"{name}: preregistered seed mismatch")
        src = manifest.get("source")
        if not isinstance(src, dict) or src.get("head_sha") != EXPECTED_HEAD or src.get("dirty") is not False or src.get("tree_sha") != EXPECTED_TREE:
            raise InvalidCollection(f"{name}: source identity mismatch")
        if source is None:
            source = (src["head_sha"], src["tree_sha"])
        elif (src["head_sha"], src["tree_sha"]) != source:
            raise InvalidCollection(f"{name}: source differs from collection")
        build_path = pathlib.Path(manifest.get("build", {}).get("path", ""))
        provenance_path = build_path / "provenance.json"
        if provenance_dir is not None:
            provenance_path = provenance_dir / ("control.json" if mode == "control" else "inline-common-control.json")
        provenance = read_json(provenance_path)
        evbuild = provenance.get("everudp_build")
        if not isinstance(evbuild, dict) or evbuild.get("ack_inline_storage_experiment") is not (mode == "inline") or evbuild.get("diagnostic_build") is not False or evbuild.get("udp_send_fast_path_experiment") is not False:
            raise InvalidCollection(f"{name}: build feature provenance mismatch")
        features = ["cli", "reliable-datagram-spike"]
        if mode == "inline":
            features.append("floor-ack-inline-storage")
        if evbuild.get("cargo_features") != features:
            raise InvalidCollection(f"{name}: cargo features mismatch")
        if (provenance.get("source", {}).get("head_sha") != EXPECTED_HEAD
                or provenance.get("source", {}).get("tree_sha") != src["tree_sha"]
                or provenance.get("source", {}).get("clean") is not True):
            raise InvalidCollection(f"{name}: build provenance source mismatch")
        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, dict):
            raise InvalidCollection(f"{name}: artifact metadata missing")
        controls = {key: artifacts.get(key, {}).get("sha256") for key in ("zmosh-udp", "pty-bench", "pty-echo")}
        if any(not isinstance(value, str) or len(value) != 64 for value in controls.values()):
            raise InvalidCollection(f"{name}: control artifact digest missing")
        if common_controls is None:
            common_controls = controls
        elif controls != common_controls:
            raise InvalidCollection(f"{name}: control artifact identity differs")
        for candidate in CANDIDATES:
            if candidate not in artifacts or not isinstance(artifacts[candidate].get("sha256"), str):
                raise InvalidCollection(f"{name}: candidate artifact missing {candidate}")
        floor_digest = artifacts["everudp-floor"]["sha256"]
        if variant_artifacts.setdefault(mode, floor_digest) != floor_digest:
            raise InvalidCollection(f"{name}: floor artifact changed within variant")
        provenance_artifacts = provenance.get("artifacts")
        if not isinstance(provenance_artifacts, dict):
            raise InvalidCollection(f"{name}: build provenance artifacts missing")
        for artifact_name, artifact_meta in artifacts.items():
            if artifact_name not in provenance_artifacts or provenance_artifacts[artifact_name].get("sha256") != artifact_meta.get("sha256"):
                raise InvalidCollection(f"{name}: build/manifest artifact provenance mismatch {artifact_name}")
        recorded_provenance = manifest.get("build", {}).get("provenance_sha256")
        if recorded_provenance != digest(provenance_path):
            raise InvalidCollection(f"{name}: build provenance digest mismatch")
        samples: dict[str, list[int]] = {}
        attempts: dict[str, int] = {}
        for candidate in CANDIDATES:
            samples[candidate] = result_samples(block, candidate, manifest)
            attempts[candidate] = account_block(block, candidate, manifest, accounting)
        floor, control = samples["everudp-floor"], samples["zmosh-udp"]
        floor_attempts, control_attempts = attempts["everudp-floor"], attempts["zmosh-udp"]
        rows.append({"name": name, "loss_percent": loss, "block": number, "mode": mode,
                     "floor_p50_us": statistics.median(floor), "zmosh_p50_us": statistics.median(control),
                     "p50_ratio": statistics.median(floor) / statistics.median(control),
                     "floor_attempts": floor_attempts, "zmosh_attempts": control_attempts,
                     "packet_attempt_ratio_le_1_60": floor_attempts / control_attempts <= 1.60,
                     "packet_attempt_ratio": floor_attempts / control_attempts})
        key = (loss, mode)
        acc = grouped.setdefault(key, {"floor": [], "zmosh": [], "floor_attempts": 0, "zmosh_attempts": 0})
        acc["floor"].extend(floor); acc["zmosh"].extend(control)
        acc["floor_attempts"] += floor_attempts; acc["zmosh_attempts"] += control_attempts
    pooled = []
    for (loss, mode), acc in sorted(grouped.items()):
        floor_p50, zmosh_p50 = statistics.median(acc["floor"]), statistics.median(acc["zmosh"])
        pooled.append({"loss_percent": loss, "mode": mode, "observations_per_candidate": 400,
                       "floor_p50_us": floor_p50, "zmosh_p50_us": zmosh_p50,
                       "p50_ratio": floor_p50 / zmosh_p50,
                       "floor_attempts": acc["floor_attempts"], "zmosh_attempts": acc["zmosh_attempts"],
                       "packet_attempt_ratio": acc["floor_attempts"] / acc["zmosh_attempts"],
                       "frozen_floor_criterion": {"p50_ratio_le_0_90": floor_p50 / zmosh_p50 <= 0.90,
                                                    "packet_attempt_ratio_le_1_60": acc["floor_attempts"] / acc["zmosh_attempts"] <= 1.60}})
    return {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE", "integration_authorized": False,
            "collection": {"blocks": 8, "responses": 8 * 2 * 200, "source": {"head_sha": source[0], "tree_sha": source[1]}, "common_control_artifacts": common_controls},
            "blocks": rows, "pooled_by_loss_and_variant": pooled,
            "interpretation": ["This is a diagnostic ACK-inline-storage experiment, not production qualification or approval.",
                               "Pooled ratios use two 200-trial blocks per loss and variant; no per-trial pairing or cross-clock subtraction is performed.",
                               "The frozen floor thresholds are reported only as descriptive criteria; they do not authorize integration."]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", type=pathlib.Path)
    parser.add_argument("--net", type=pathlib.Path, default=pathlib.Path("crates/everudp/tests/net"))
    parser.add_argument("--provenance-dir", type=pathlib.Path)
    args = parser.parse_args(argv)
    try:
        report = analyze(args.root.resolve(), args.net.resolve(), args.provenance_dir)
    except (InvalidCollection, OSError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"status": "UNKNOWN", "qualification": "NOT_APPLICABLE", "integration_authorized": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
