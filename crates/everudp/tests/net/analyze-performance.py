#!/usr/bin/env python3
"""Validate and analyze the frozen everudp/zmosh performance matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any

CANDIDATES = ("everudp", "zmosh-udp", "zmosh-quic")
BASELINES = ("zmosh-udp", "zmosh-quic")
LOSSES = (0, 5)
EXPECTED_ORDERS = {
    tuple(order)
    for order in (
        ("everudp", "zmosh-udp", "zmosh-quic"),
        ("everudp", "zmosh-quic", "zmosh-udp"),
        ("zmosh-udp", "everudp", "zmosh-quic"),
        ("zmosh-udp", "zmosh-quic", "everudp"),
        ("zmosh-quic", "everudp", "zmosh-udp"),
        ("zmosh-quic", "zmosh-udp", "everudp"),
    )
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def nearest_rank(values: list[int], probability: float) -> int:
    if not values:
        raise ValueError("cannot take a quantile of no samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def percentile(values: list[float], probability: float) -> float:
    if not values:
        raise ValueError("cannot take a percentile of no samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def metrics(everudp: list[int], baseline: list[int]) -> dict[str, float | int]:
    everudp_p50 = nearest_rank(everudp, 0.50)
    everudp_p95 = nearest_rank(everudp, 0.95)
    baseline_p50 = nearest_rank(baseline, 0.50)
    baseline_p95 = nearest_rank(baseline, 0.95)
    return {
        "everudp_p50_us": everudp_p50,
        "everudp_p95_us": everudp_p95,
        "baseline_p50_us": baseline_p50,
        "baseline_p95_us": baseline_p95,
        "p50_ratio": everudp_p50 / baseline_p50,
        "p95_ratio": everudp_p95 / baseline_p95,
    }


def compare(
    blocks: list[dict[str, list[int]]],
    baseline: str,
    iterations: int,
    seed: int,
) -> dict[str, Any]:
    everudp = [sample for block in blocks for sample in block["everudp"]]
    control = [sample for block in blocks for sample in block[baseline]]
    point = metrics(everudp, control)
    generator = random.Random(seed)
    p50_ratios: list[float] = []
    p95_ratios: list[float] = []
    for _ in range(iterations):
        everudp_resample: list[int] = []
        control_resample: list[int] = []
        for block in blocks:
            # Preserve every candidate-order block as a stratum. The packet
            # streams differ by implementation, so observations are sampled
            # independently within the same stratum.
            left = block["everudp"]
            right = block[baseline]
            everudp_resample.extend(generator.choice(left) for _ in left)
            control_resample.extend(generator.choice(right) for _ in right)
        sampled = metrics(everudp_resample, control_resample)
        p50_ratios.append(float(sampled["p50_ratio"]))
        p95_ratios.append(float(sampled["p95_ratio"]))

    p50_upper = percentile(p50_ratios, 0.95)
    p95_upper = percentile(p95_ratios, 0.95)
    gate = {
        "p50_point_at_most_1_00": point["p50_ratio"] <= 1.00,
        "p50_upper95_at_most_1_10": p50_upper <= 1.10,
        "p95_upper95_at_most_1_00": p95_upper <= 1.00,
    }
    return {
        "baseline": baseline,
        "sample_count_per_implementation": len(everudp),
        "point": point,
        "bootstrap": {
            "iterations": iterations,
            "seed": seed,
            "method": "independent resampling within each candidate-order block stratum",
            "p50_ratio_interval_95": [
                percentile(p50_ratios, 0.025),
                percentile(p50_ratios, 0.975),
            ],
            "p50_ratio_upper95": p50_upper,
            "p95_ratio_interval_95": [
                percentile(p95_ratios, 0.025),
                percentile(p95_ratios, 0.975),
            ],
            "p95_ratio_upper95": p95_upper,
        },
        "gate": {**gate, "pass": all(gate.values())},
    }


def verify_checksum_receipt(path: Path) -> None:
    receipt = path / "SHA256SUMS"
    if not receipt.is_file():
        raise ValueError(f"{path}: SHA256SUMS is missing")
    for line in receipt.read_text(encoding="utf-8").splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip(" *")
        target = path / relative
        if digest(target) != expected:
            raise ValueError(f"{path}: checksum mismatch for {relative}")


def load_block(path: Path, expected_trials: int) -> dict[str, Any]:
    verify_checksum_receipt(path)
    manifest_path = path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError(f"{path}: unsupported manifest")
    trace_flags = ("diagnostic_tracing", "production_path_tracing", "production_io_tracing", "production_packet_tracing", "native_stage_tracing",
                   "reactor_work_tracing", "reactor_partition_tracing")
    if any(manifest.get(flag, False) is not False for flag in trace_flags) or any(
        (path / "everudp" / name).exists()
        for name in ("client-path-trace.json", "gateway-path-trace.json",
                     "client-path-trace.json.io.json", "gateway-path-trace.json.io.json",
                     "client-path-trace.json.packets.json", "gateway-path-trace.json.packets.json")
    ):
        raise ValueError(f"{path}: diagnostic tracing cannot qualify production performance")
    if manifest.get("trials_per_candidate") != expected_trials:
        raise ValueError(f"{path}: wrong trial count")
    loss = manifest.get("loss_percent_each_direction")
    if loss not in LOSSES:
        raise ValueError(f"{path}: wrong loss cell")
    order = tuple(manifest.get("order", []))
    if order not in EXPECTED_ORDERS:
        raise ValueError(f"{path}: invalid candidate order")

    samples: dict[str, list[int]] = {}
    for candidate in CANDIDATES:
        result_meta = manifest["results"][candidate]
        result_path = path / result_meta["path"]
        if digest(result_path) != result_meta["sha256"]:
            raise ValueError(f"{path}: {candidate} result hash mismatch")
        result = json.loads(result_path.read_text(encoding="utf-8"))
        values = result.get("samples_us")
        if (
            result.get("trials") != expected_trials
            or result.get("transcript_failures") != 0
            or not isinstance(values, list)
            or len(values) != expected_trials
            or any(type(value) is not int or value <= 0 for value in values)
        ):
            raise ValueError(f"{path}: invalid {candidate} observations")
        evidence = manifest["loss_evidence"][candidate]
        if loss == 5 and (
            evidence["client_egress_drop_delta"] <= 0
            or evidence["server_egress_drop_delta"] <= 0
        ):
            raise ValueError(f"{path}: {candidate} did not observe symmetric loss")
        samples[candidate] = values
    return {
        "path": path,
        "manifest": manifest,
        "manifest_sha256": digest(manifest_path),
        "loss": loss,
        "order": order,
        "samples": samples,
    }


def analyze(
    paths: list[Path],
    expected_trials: int,
    iterations: int,
    allow_smoke: bool = False,
) -> dict[str, Any]:
    blocks = [load_block(path, expected_trials) for path in paths]
    grouped = {loss: [block for block in blocks if block["loss"] == loss] for loss in LOSSES}
    for loss, cell in grouped.items():
        if len(cell) != 6:
            raise ValueError(f"loss {loss}: expected six blocks, got {len(cell)}")
        if {block["order"] for block in cell} != EXPECTED_ORDERS:
            raise ValueError(f"loss {loss}: candidate-order permutations are incomplete")

    identities = {
        (
            block["manifest"]["source"]["head_sha"],
            block["manifest"]["source"]["tree_sha"],
        )
        for block in blocks
    }
    artifact_sets = {
        tuple(
            block["manifest"]["artifacts"][name]["sha256"]
            for name in (
                "everudp",
                "zmosh-udp",
                "zmosh-quic",
                "zmosh-quic-bridge",
                "pty-bench",
                "pty-echo",
            )
        )
        for block in blocks
    }
    build_receipts = {
        block["manifest"]["build"]["provenance_sha256"] for block in blocks
    }
    if len(identities) != 1 or len(artifact_sets) != 1 or len(build_receipts) != 1:
        raise ValueError("all blocks must bind one source, build, and artifact set")

    clean = all(not block["manifest"]["source"]["dirty"] for block in blocks)
    sealed_build = next(iter(build_receipts)) is not None
    final_shape = expected_trials == 200 and clean and sealed_build
    if not allow_smoke and not final_shape:
        raise ValueError("release analysis requires 200 trials, clean source, and a sealed build")

    cells: dict[str, Any] = {}
    every_comparison_pass = True
    for loss in LOSSES:
        sample_blocks = [block["samples"] for block in grouped[loss]]
        comparisons = {}
        for ordinal, baseline in enumerate(BASELINES):
            comparison = compare(
                sample_blocks,
                baseline,
                iterations,
                seed=0x45565000 + loss * 101 + ordinal,
            )
            comparisons[baseline] = comparison
            every_comparison_pass &= comparison["gate"]["pass"]
        cells[str(loss)] = {
            "blocks": [
                {
                    "path": str(block["path"]),
                    "manifest_sha256": block["manifest_sha256"],
                    "order": list(block["order"]),
                    "seed": block["manifest"]["seeds"]["client"],
                }
                for block in grouped[loss]
            ],
            "comparisons": comparisons,
        }

    identity = next(iter(identities))
    artifact_hashes = next(iter(artifact_sets))
    evidence_pass = clean and sealed_build and expected_trials == 200
    return {
        "schema_version": 1,
        "source": {
            "head_sha": identity[0],
            "tree_sha": identity[1],
            "all_blocks_clean": clean,
        },
        "artifacts": dict(
            zip(
                (
                    "everudp",
                    "zmosh_udp",
                    "zmosh_quic",
                    "zmosh_quic_bridge",
                    "pty_bench",
                    "pty_echo",
                ),
                artifact_hashes,
            )
        ),
        "build_provenance_sha256": next(iter(build_receipts)),
        "method": {
            "trials_per_implementation_per_cell": expected_trials * 6,
            "blocks_per_cell": 6,
            "observations_per_block": expected_trials,
            "bootstrap_iterations": iterations,
            "thresholds": {
                "p50_point_ratio_max": 1.00,
                "p50_ratio_upper95_max": 1.10,
                "p95_ratio_upper95_max": 1.00,
            },
        },
        "cells": cells,
        "verdict": {
            "zero_transcript_failures": True,
            "exact_release_evidence": evidence_pass,
            "all_four_comparisons_pass": every_comparison_pass,
            "qualification_outcome": (
                "PASS" if evidence_pass and every_comparison_pass else "FAIL"
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("blocks", nargs="+", type=Path)
    parser.add_argument("--trials", type=int, default=200)
    parser.add_argument("--bootstrap", type=int, default=20_000)
    parser.add_argument("--allow-smoke", action="store_true")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    if arguments.trials < 1 or arguments.bootstrap < 100:
        raise SystemExit("trials must be positive and bootstrap must be at least 100")
    result = analyze(
        arguments.blocks,
        arguments.trials,
        arguments.bootstrap,
        arguments.allow_smoke,
    )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        print(rendered, end="")
    else:
        arguments.output.write_text(rendered, encoding="utf-8")
    if result["verdict"]["qualification_outcome"] != "PASS" and not arguments.allow_smoke:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
