#!/usr/bin/env python3
"""Verify and analyze the hash-bound everudp control/resource matrix."""

import argparse
import hashlib
import json
import math
import random
import re
from pathlib import Path


CELLS = {
    "loss0": (0, 0, 0),
    "loss1": (1, 0, 0),
    "loss5": (5, 0, 0),
    "loss10": (10, 0, 0),
    "loss25": (25, 0, 0),
    "loss5-jitter25": (5, 25, 0),
    "loss5-jitter50": (5, 50, 0),
    "loss5-reorder2": (5, 0, 2),
}
CANDIDATES = (
    "ssh",
    "everssh",
    "mosh",
    "zmosh",
    "everudp-udp-pred",
    "everudp-udp-nopred",
    "everudp-quic-pred",
    "everudp-quic-nopred",
)
MAX_RSS_KIB = 131_072
MAX_CPU_SECONDS = 5.0
MAX_NETWORK_BYTES_PER_TRIAL = 65_536


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def nearest_rank(samples: list[float], probability: float) -> float:
    ordered = sorted(samples)
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def quantiles(samples: list[float]) -> dict:
    return {
        "n": len(samples),
        "p50_us": nearest_rank(samples, 0.50),
        "p95_us": nearest_rank(samples, 0.95),
        "max_us": max(samples),
    }


def percentile(ordered: list[float], probability: float) -> float:
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def bootstrap_ratio(
    numerator: list[float], denominator: list[float], iterations: int, seed: int
) -> dict:
    generator = random.Random(seed)
    p50_ratios = []
    p95_ratios = []
    for _ in range(iterations):
        left = [generator.choice(numerator) for _ in numerator]
        right = [generator.choice(denominator) for _ in denominator]
        p50_ratios.append(nearest_rank(left, 0.50) / nearest_rank(right, 0.50))
        p95_ratios.append(nearest_rank(left, 0.95) / nearest_rank(right, 0.95))
    p50_ratios.sort()
    p95_ratios.sort()
    return {
        "iterations": iterations,
        "seed": seed,
        "p50_ratio_ci95": [
            percentile(p50_ratios, 0.025),
            percentile(p50_ratios, 0.975),
        ],
        "p50_ratio_upper95": percentile(p50_ratios, 0.95),
        "p95_ratio_ci95": [
            percentile(p95_ratios, 0.025),
            percentile(p95_ratios, 0.975),
        ],
        "p95_ratio_upper95": percentile(p95_ratios, 0.95),
    }


def verify_checksums(cell: Path) -> None:
    entries = (cell / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    expected = {}
    for line in entries:
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise ValueError(f"{cell}: malformed SHA256SUMS entry")
        expected[match.group(2)] = match.group(1)
    actual_names = {
        path.name for path in cell.iterdir() if path.is_file() and path.name != "SHA256SUMS"
    }
    if set(expected) != actual_names:
        raise ValueError(f"{cell}: SHA256SUMS inventory mismatch")
    for name, wanted in expected.items():
        if digest(cell / name) != wanted:
            raise ValueError(f"{cell}: checksum mismatch for {name}")


def load_time(path: Path) -> dict:
    fields = {}
    patterns = {
        "user_seconds": r"^\s*User time \(seconds\): ([0-9.]+)$",
        "system_seconds": r"^\s*System time \(seconds\): ([0-9.]+)$",
        "max_rss_kib": r"^\s*Maximum resident set size \(kbytes\): ([0-9]+)$",
        "exit_status": r"^\s*Exit status: ([0-9]+)$",
    }
    text = path.read_text(encoding="utf-8")
    for name, pattern in patterns.items():
        match = re.search(pattern, text, flags=re.MULTILINE)
        if not match:
            raise ValueError(f"{path}: missing GNU time field {name}")
        fields[name] = float(match.group(1)) if name.endswith("seconds") else int(match.group(1))
    fields["cpu_seconds"] = fields["user_seconds"] + fields["system_seconds"]
    return fields


def link_stats(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list) or len(data) != 1:
        raise ValueError(f"{path}: expected one link record")
    stats = data[0]["stats64"]
    return {
        "rx_bytes": stats["rx"]["bytes"],
        "rx_packets": stats["rx"]["packets"],
        "tx_bytes": stats["tx"]["bytes"],
        "tx_packets": stats["tx"]["packets"],
    }


def network_delta(cell: Path, candidate: str, side: str) -> dict:
    before = link_stats(cell / f"network-{candidate}-{side}-before.json")
    after = link_stats(cell / f"network-{candidate}-{side}-after.json")
    delta = {name: after[name] - before[name] for name in before}
    if any(value < 0 for value in delta.values()):
        raise ValueError(f"{cell}: network counters regressed for {candidate}/{side}")
    delta["total_bytes"] = delta["rx_bytes"] + delta["tx_bytes"]
    delta["total_packets"] = delta["rx_packets"] + delta["tx_packets"]
    return delta


def qdisc_drop_delta(cell: Path, candidate: str, side: str) -> int:
    values = []
    for phase in ("before", "after"):
        text = (cell / f"netem-{candidate}-{side}-{phase}.txt").read_text(
            encoding="utf-8"
        )
        match = re.search(r"\bdropped ([0-9]+)", text)
        if not match:
            raise ValueError(f"{cell}: missing qdisc drop counter for {candidate}/{side}")
        values.append(int(match.group(1)))
    if values[1] < values[0]:
        raise ValueError(f"{cell}: qdisc counter regressed for {candidate}/{side}")
    return values[1] - values[0]


def load_cell(path: Path, cell_name: str, expected_trials: int) -> tuple[dict, dict]:
    verify_checksums(path)
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 3 or manifest.get("cell") != cell_name:
        raise ValueError(f"{path}: wrong manifest schema/cell")
    expected_impairment = CELLS[cell_name]
    observed_impairment = manifest["impairment"]
    observed = (
        observed_impairment["symmetric_loss_percent"],
        observed_impairment["delay_ms"],
        observed_impairment["reorder_percent"],
    )
    if observed != expected_impairment:
        raise ValueError(f"{path}: impairment does not match frozen cell")
    if manifest["trials_per_candidate"] != expected_trials:
        raise ValueError(f"{path}: trial count does not match gate")
    actual_receipts = {
        item.name: digest(item)
        for item in path.iterdir()
        if item.is_file() and item.name not in {"manifest.json", "SHA256SUMS"}
    }
    if manifest.get("receipt_files") != actual_receipts:
        raise ValueError(f"{path}: manifest receipt hashes do not match")

    candidates = {}
    for candidate in CANDIDATES:
        result_path = path / f"{candidate}-{cell_name}.json"
        result = json.loads(result_path.read_text(encoding="utf-8"))
        samples = result.get("samples")
        if not isinstance(samples, list) or len(samples) != expected_trials:
            raise ValueError(f"{result_path}: expected {expected_trials} raw samples")
        if any(not isinstance(value, (int, float)) or value <= 0 for value in samples):
            raise ValueError(f"{result_path}: nonpositive latency sample")
        timing = load_time(path / f"resource-{candidate}-client.txt")
        client_network = network_delta(path, candidate, "client")
        server_network = network_delta(path, candidate, "server")
        resource_pass = (
            timing["exit_status"] == 0
            and timing["max_rss_kib"] <= MAX_RSS_KIB
            and timing["cpu_seconds"] <= MAX_CPU_SECONDS
            and client_network["total_bytes"]
            <= MAX_NETWORK_BYTES_PER_TRIAL * expected_trials
        )
        candidates[candidate] = {
            "samples": samples,
            "latency": quantiles(samples),
            "resources": {
                "client_process_tree": timing,
                "client_interface": client_network,
                "server_interface": server_network,
                "qdisc_drop_delta": {
                    "client_egress": qdisc_drop_delta(path, candidate, "client"),
                    "server_egress": qdisc_drop_delta(path, candidate, "server"),
                },
                "ceiling_pass": resource_pass,
            },
        }
    return manifest, candidates


def comparison(left: dict, right: dict, iterations: int, seed: int) -> dict:
    left_metrics = left["latency"]
    right_metrics = right["latency"]
    return {
        "point": {
            "p50_ratio": left_metrics["p50_us"] / right_metrics["p50_us"],
            "p95_ratio": left_metrics["p95_us"] / right_metrics["p95_us"],
        },
        "bootstrap": bootstrap_ratio(left["samples"], right["samples"], iterations, seed),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("matrix_root", type=Path)
    parser.add_argument("--trials", type=int, default=30)
    parser.add_argument("--bootstrap", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=9015)
    args = parser.parse_args()

    loaded = {}
    for cell_name in CELLS:
        loaded[cell_name] = load_cell(
            args.matrix_root / cell_name, cell_name, args.trials
        )
    heads = {manifest["source"]["head_sha"] for manifest, _ in loaded.values()}
    trees = {manifest["source"]["tree_sha"] for manifest, _ in loaded.values()}
    dirty = [manifest["source"]["dirty"] for manifest, _ in loaded.values()]
    artifact_sets = {
        tuple(
            manifest["artifacts"][name]["sha256"]
            for name in ("everudp", "everssh", "zmosh", "zmosh_bench")
        )
        for manifest, _ in loaded.values()
    }
    exact_source_pass = len(heads) == len(trees) == len(artifact_sets) == 1 and not any(dirty)
    loss5 = loaded["loss5"][1]
    everssh = comparison(
        loss5["everudp-udp-pred"], loss5["everssh"], args.bootstrap, args.seed
    )
    zmosh = comparison(
        loss5["everudp-udp-pred"], loss5["zmosh"], args.bootstrap, args.seed + 1
    )
    everssh["thresholds"] = {"p50_ratio_max": 0.50, "p95_ratio_max": 0.67}
    everssh["frozen_point_rule_pass"] = (
        everssh["point"]["p50_ratio"] <= 0.50
        and everssh["point"]["p95_ratio"] <= 0.67
    )
    zmosh["thresholds"] = {"p50_ratio_max": 1.10, "p95_ratio_max": 1.15}
    zmosh["frozen_point_rule_pass"] = (
        zmosh["point"]["p50_ratio"] <= 1.10
        and zmosh["point"]["p95_ratio"] <= 1.15
    )

    prediction = {}
    for index, (cell_name, (_, candidates)) in enumerate(loaded.items()):
        prediction[cell_name] = {
            transport: comparison(
                candidates[f"everudp-{transport}-pred"],
                candidates[f"everudp-{transport}-nopred"],
                args.bootstrap,
                args.seed + 100 + index * 2 + (transport == "quic"),
            )
            for transport in ("udp", "quic")
        }

    resource_pass = all(
        candidate["resources"]["ceiling_pass"]
        for _, candidates in loaded.values()
        for candidate in candidates.values()
    )
    correction_p95_us = loss5["everudp-udp-pred"]["latency"]["p95_us"]
    correction_pass = correction_p95_us < 300_000
    matrix_receipts = {
        cell_name: digest(args.matrix_root / cell_name / "manifest.json")
        for cell_name in CELLS
    }
    result = {
        "schema_version": 1,
        "source": {
            "head_sha": next(iter(heads)) if len(heads) == 1 else sorted(heads),
            "tree_sha": next(iter(trees)) if len(trees) == 1 else sorted(trees),
            "all_cells_clean_and_identical": exact_source_pass,
        },
        "method": {
            "quantile": "empirical nearest-rank ceil(p*n)-1",
            "uncertainty": "independent nonparametric bootstrap of each candidate's raw samples",
            "bootstrap_iterations": args.bootstrap,
            "resource_ceilings": {
                "client_max_rss_kib": MAX_RSS_KIB,
                "client_cpu_seconds_per_candidate": MAX_CPU_SECONDS,
                "client_interface_bytes_per_trial": MAX_NETWORK_BYTES_PER_TRIAL,
            },
        },
        "matrix_manifest_sha256": matrix_receipts,
        "cells": {
            cell_name: {
                candidate: {
                    "latency": data["latency"],
                    "resources": data["resources"],
                }
                for candidate, data in candidates.items()
            }
            for cell_name, (_, candidates) in loaded.items()
        },
        "comparisons": {
            "everudp_udp_predicted_vs_everssh_at_loss5": everssh,
            "everudp_udp_predicted_vs_zmosh_at_loss5": zmosh,
            "prediction_on_vs_off": prediction,
        },
        "correction_convergence": {
            "everudp_udp_predicted_loss5_p95_us": correction_p95_us,
            "threshold_us_exclusive": 300_000,
            "pass": correction_pass,
        },
        "verdict": {
            "exact_source_pass": exact_source_pass,
            "all_resource_ceilings_pass": resource_pass,
            "everssh_frozen_point_rule_pass": everssh["frozen_point_rule_pass"],
            "zmosh_frozen_point_rule_pass": zmosh["frozen_point_rule_pass"],
            "correction_convergence_pass": correction_pass,
            "matrix_pass": exact_source_pass
            and resource_pass
            and everssh["frozen_point_rule_pass"]
            and zmosh["frozen_point_rule_pass"]
            and correction_pass,
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["verdict"]["matrix_pass"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
