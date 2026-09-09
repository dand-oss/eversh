#!/usr/bin/env python3
"""Fail-closed descriptive analyzer for the everudp attribution collection.

This tool is deliberately diagnostic-only.  It never emits PASS and never
writes into the collection tree.  It verifies the sealed block contract before
calculating medians and mode ratios.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import statistics
import sys
from dataclasses import dataclass
from typing import Any

EXPECTED = {
    f"loss{loss}-block{block}-{mode}"
    for loss in (0, 5)
    for block in (1, 2)
    for mode in ("plain", "instrumented", "traced")
}
EXPECTED_ORDER = {
    1: ("everudp-floor", "zmosh-udp"),
    2: ("zmosh-udp", "everudp-floor"),
}
MODES = ("plain", "instrumented", "traced")
CANDIDATES = ("everudp-floor", "zmosh-udp")
PUBLIC_CLOCK = "CLOCK_MONOTONIC; local host and time namespace only"


class InvalidCollection(ValueError):
    pass


def _is_digest(value: Any, lengths: tuple[int, ...] = (40, 64)) -> bool:
    return isinstance(value, str) and len(value) in lengths and all(c in "0123456789abcdefABCDEF" for c in value)


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
    except OSError as e:
        raise InvalidCollection(f"cannot hash {path}: {e}") from e
    return h.hexdigest()


def _read_json(path: pathlib.Path) -> dict[str, Any]:
    try:
        x = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise InvalidCollection(f"cannot read JSON {path}: {e}") from e
    if not isinstance(x, dict):
        raise InvalidCollection(f"JSON object required: {path}")
    return x


def _sum_entries(path: pathlib.Path) -> dict[str, str]:
    try:
        lines = path.read_text().splitlines()
    except OSError as e:
        raise InvalidCollection(f"cannot read checksum file {path}: {e}") from e
    out: dict[str, str] = {}
    for n, line in enumerate(lines, 1):
        if not line.strip():
            continue
        parts = line.split(maxsplit=1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise InvalidCollection(f"malformed checksum line {path}:{n}")
        digest, name = parts
        if any(c not in "0123456789abcdefABCDEF" for c in digest):
            raise InvalidCollection(f"non-hex checksum line {path}:{n}")
        if name.startswith("./"):
            name = name[2:]
        if not name or pathlib.PurePosixPath(name).is_absolute() or ".." in pathlib.PurePosixPath(name).parts:
            raise InvalidCollection(f"unsafe checksum path {path}:{n}")
        if name in out:
            raise InvalidCollection(f"duplicate checksum path {path}:{n}")
        out[name] = digest
    return out


def _verify_block_inventory(block: pathlib.Path) -> None:
    sums_path = block / "SHA256SUMS"
    entries = _sum_entries(sums_path)
    actual = {
        p.relative_to(block).as_posix()
        for p in block.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    block_root = block.resolve()
    for p in block.rglob("*"):
        if p.is_symlink():
            try:
                target = p.resolve(strict=True)
            except OSError as e:
                raise InvalidCollection(f"{block.name}: broken symlink {p}: {e}") from e
            if target != block_root and block_root not in target.parents:
                raise InvalidCollection(f"{block.name}: symlink escapes block {p}")
    listed = set(entries)
    if actual != listed:
        missing = sorted(listed - actual)
        extra = sorted(actual - listed)
        raise InvalidCollection(f"{block.name}: checksum inventory mismatch missing={missing} extra={extra}")
    for name, expected in entries.items():
        got = _sha256(block / name)
        if got != expected:
            raise InvalidCollection(f"{block.name}: digest mismatch {name}")


def _parse_name(name: str) -> tuple[int, int, str]:
    try:
        loss_s, block_s, mode = name.split("-", 2)
        loss = int(loss_s.removeprefix("loss"))
        block = int(block_s.removeprefix("block"))
    except (ValueError, AttributeError) as e:
        raise InvalidCollection(f"invalid block name {name}") from e
    if name not in EXPECTED or loss not in (0, 5) or block not in (1, 2) or mode not in MODES:
        raise InvalidCollection(f"unexpected block name {name}")
    return loss, block, mode


def _assert_result(block: pathlib.Path, candidate: str, manifest: dict[str, Any]) -> list[int]:
    info = manifest.get("results", {}).get(candidate)
    if not isinstance(info, dict) or info.get("path") != f"{candidate}/result.json":
        raise InvalidCollection(f"{block.name}: result metadata missing for {candidate}")
    result = _read_json(block / candidate / "result.json")
    if (result.get("schema_version") != 1 or isinstance(result.get("trials"), bool) or
            result.get("trials") != 200):
        raise InvalidCollection(f"{block.name}/{candidate}: wrong result schema/trial count")
    if result.get("gap_ms") != manifest.get("gap_ms") or result.get("public_clock") != PUBLIC_CLOCK:
        raise InvalidCollection(f"{block.name}/{candidate}: clock/gap metadata mismatch")
    if result.get("transcript_failures") != 0 or not isinstance(result.get("samples_us"), list):
        raise InvalidCollection(f"{block.name}/{candidate}: transcript/result invalid")
    samples = result["samples_us"]
    boundaries = result.get("public_boundaries")
    if len(samples) != 200 or not isinstance(boundaries, list) or len(boundaries) != 200:
        raise InvalidCollection(f"{block.name}/{candidate}: expected 200 samples and boundaries")
    previous_accepted = None
    for i, (sample, boundary) in enumerate(zip(samples, boundaries)):
        if isinstance(sample, bool) or not isinstance(sample, int) or sample <= 0 or not isinstance(boundary, dict):
            raise InvalidCollection(f"{block.name}/{candidate}: malformed trial {i}")
        if isinstance(boundary.get("trial"), bool) or boundary.get("trial") != i:
            raise InvalidCollection(f"{block.name}/{candidate}: trial numbering mismatch {i}")
        send, accepted = boundary.get("send_ns"), boundary.get("accepted_ns")
        if (isinstance(send, bool) or not isinstance(send, int) or
                isinstance(accepted, bool) or not isinstance(accepted, int) or
                send < 0 or accepted < send or
                (previous_accepted is not None and send < previous_accepted)):
            raise InvalidCollection(f"{block.name}/{candidate}: invalid boundary {i}")
        if sample != (accepted - send + 999) // 1000:
            raise InvalidCollection(f"{block.name}/{candidate}: sample/boundary mismatch {i}")
        previous_accepted = accepted
    if _sha256(block / candidate / "result.json") != info.get("sha256"):
        raise InvalidCollection(f"{block.name}/{candidate}: manifest result digest mismatch")
    if info.get("samples") != 200 or info.get("transcript_failures") != 0:
        raise InvalidCollection(f"{block.name}/{candidate}: manifest result count/failure metadata mismatch")
    return samples


def _assert_manifest(block: pathlib.Path) -> tuple[dict[str, Any], int, int, str]:
    loss, number, mode = _parse_name(block.name)
    manifest = _read_json(block / "manifest.json")
    if manifest.get("schema_version") != 1 or manifest.get("loss_percent_each_direction") != loss:
        raise InvalidCollection(f"{block.name}: schema/loss mismatch")
    if (isinstance(manifest.get("trials_per_candidate"), bool) or manifest.get("trials_per_candidate") != 200 or
            isinstance(manifest.get("gap_ms"), bool) or manifest.get("gap_ms") != 100):
        raise InvalidCollection(f"{block.name}: schedule mismatch")
    if manifest.get("order") != list(EXPECTED_ORDER[number]):
        raise InvalidCollection(f"{block.name}: candidate order mismatch")
    if type(manifest.get("diagnostic_tracing")) is not bool or manifest.get("diagnostic_tracing") != (mode == "traced"):
        raise InvalidCollection(f"{block.name}: tracing mode mismatch")
    source = manifest.get("source")
    if (not isinstance(source, dict) or source.get("dirty") is not False or
            not _is_digest(source.get("head_sha")) or not _is_digest(source.get("tree_sha"))):
        raise InvalidCollection(f"{block.name}: source identity missing/dirty")
    for candidate in CANDIDATES:
        samples = _assert_result(block, candidate, manifest)
        if candidate not in manifest.get("artifacts", {}):
            raise InvalidCollection(f"{block.name}: artifact missing {candidate}")
    for artifact in ("everudp-floor", "zmosh-udp", "pty-bench", "pty-echo"):
        if not _is_digest(manifest.get("artifacts", {}).get(artifact, {}).get("sha256"), (64,)):
            raise InvalidCollection(f"{block.name}: artifact digest missing/malformed {artifact}")
    return manifest, loss, number, mode


def _median(xs: list[int]) -> float:
    return float(statistics.median(xs))


@dataclass
class Block:
    name: str
    manifest: dict[str, Any]
    loss: int
    number: int
    mode: str
    medians: dict[str, float]


def analyze(root: pathlib.Path) -> dict[str, Any]:
    if not root.is_dir():
        raise InvalidCollection(f"collection root is not a directory: {root}")
    names = {p.name for p in root.iterdir() if p.is_dir()}
    if names != EXPECTED:
        raise InvalidCollection(f"expected exactly 12 blocks; missing={sorted(EXPECTED-names)} extra={sorted(names-EXPECTED)}")
    blocks: list[Block] = []
    common: dict[str, str] | None = None
    common_source: tuple[str, str] | None = None
    for name in sorted(EXPECTED):
        p = root / name
        _verify_block_inventory(p)
        manifest, loss, number, mode = _assert_manifest(p)
        artifacts = manifest["artifacts"]
        ids = {k: artifacts[k]["sha256"] for k in ("zmosh-udp", "pty-bench", "pty-echo")}
        if common is None:
            common = ids
            common_source = (manifest["source"]["head_sha"], manifest["source"]["tree_sha"])
        elif ids != common:
            raise InvalidCollection(f"{name}: baseline/PTY artifact identity differs from common collection")
        if (manifest["source"]["head_sha"], manifest["source"]["tree_sha"]) != common_source:
            raise InvalidCollection(f"{name}: source identity differs from common collection")
        medians = {}
        for candidate in CANDIDATES:
            result = _read_json(p / candidate / "result.json")
            medians[candidate] = _median(result["samples_us"])
        blocks.append(Block(name, manifest, loss, number, mode, medians))
    by_key = {(b.loss, b.number, b.mode): b for b in blocks}
    mode_rows = []
    for loss in (0, 5):
        for number in (1, 2):
            for mode in MODES:
                b = by_key[(loss, number, mode)]
                f, z = b.medians["everudp-floor"], b.medians["zmosh-udp"]
                mode_rows.append({"loss_percent": loss, "block": number, "mode": mode,
                                  "everudp_median_us": f, "zmosh_median_us": z,
                                  "floor_over_zmosh": f / z})
    ratios_by_loss: dict[int, dict[str, list[float]]] = {0: {"instrumented_over_plain": [], "traced_over_instrumented": []}, 5: {"instrumented_over_plain": [], "traced_over_instrumented": []}}
    comparisons = []
    for loss in (0, 5):
        for number in (1, 2):
            plain, instr, traced = (by_key[(loss, number, m)] for m in MODES)
            for label, a, b in (("instrumented_over_plain", instr, plain), ("traced_over_instrumented", traced, instr)):
                floor_a, floor_b = a.medians["everudp-floor"], b.medians["everudp-floor"]
                zmosh_a, zmosh_b = a.medians["zmosh-udp"], b.medians["zmosh-udp"]
                ratio = floor_a / floor_b
                normalized = (floor_a / zmosh_a) / (floor_b / zmosh_b)
                ratios_by_loss[loss][label].append(ratio)
                comparisons.append({"loss_percent": loss, "block": number, "comparison": label,
                                    "numerator_median_us": floor_a,
                                    "denominator_median_us": floor_b, "ratio": ratio,
                                    "normalized_floor_over_zmosh_ratio": normalized})
    sensitivity = {}
    for loss, grouped in ratios_by_loss.items():
        sensitivity[str(loss)] = {}
        for label, values in grouped.items():
            sensitivity[str(loss)][f"{label}_min"] = min(values)
            sensitivity[str(loss)][f"{label}_max"] = max(values)
    return {"status": "DIAGNOSTIC", "attribution": "UNKNOWN", "qualification": "UNCHANGED",
            "collection": {"blocks": 12, "responses": 12 * 2 * 200, "common_source": {"head_sha": common_source[0], "tree_sha": common_source[1]}, "common_artifacts": common},
            "blocks": mode_rows, "mode_comparisons": comparisons,
            "sensitivity_by_loss": sensitivity,
            "interpretation": ["Ratios are descriptive medians from two reversed blocks per loss/mode, not a qualification result.",
                               "Disjoint seeds and host variation prevent identifying pure causal tracing overhead.",
                               "Block ratios are paired by schedule/order, not paired per-trial latencies.",
                               "No cross-process timestamp subtraction or network-only attribution is made."]}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} COLLECTION_ROOT", file=sys.stderr)
        return 2
    try:
        report = analyze(pathlib.Path(argv[1]).resolve())
    except (InvalidCollection, OSError, TypeError, KeyError, AttributeError) as e:
        print(json.dumps({"status": "UNKNOWN", "attribution": "UNKNOWN", "qualification": "UNCHANGED", "error": str(e)}, sort_keys=True))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
