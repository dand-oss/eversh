#!/usr/bin/env python3
"""Validate, rank, and freeze the preregistered everudp tuning sweep."""

from __future__ import annotations

import argparse
import json
import math
import random
from pathlib import Path
from typing import Any

RTTS = (25, 100, 333)
ACKS = ("off", "every-1ms", "every-other-5ms")
GSOS = ("off", "on")
LOSSES = (0, 5)
DEFAULT = "rtt100-every-1ms-gso-off"
BOOTSTRAP_SEED = 0x45564552554450
BLOCK_SIZE = 20


def profile_names() -> list[str]:
    return [
        f"rtt{rtt}-{ack}-gso-{gso}"
        for rtt in RTTS
        for ack in ACKS
        for gso in GSOS
    ]


def nearest_rank(values: list[int], quantile: float) -> int:
    if not values:
        raise ValueError("cannot take a quantile of no samples")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(quantile * len(ordered)) - 1)]


def read_time(path: Path) -> dict[str, float | int]:
    fields = path.read_text(encoding="utf-8").strip().split()
    if len(fields) != 4:
        raise ValueError(f"{path}: expected user_s sys_s max_rss_kib elapsed_s")
    user, system, rss, elapsed = fields
    return {
        "user_s": float(user),
        "system_s": float(system),
        "cpu_s": float(user) + float(system),
        "max_rss_kib": int(rss),
        "elapsed_s": float(elapsed),
    }


def read_cell(
    root: Path,
    profile: str,
    loss: int,
    trials: int,
    seed: int,
) -> dict[str, Any]:
    stem = f"{profile}-loss{loss}"
    payload = json.loads((root / f"{stem}.json").read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1 or payload.get("correct") is not True:
        raise ValueError(f"{stem}: correctness marker missing")
    if payload.get("loss_percent") != loss or payload.get("trials") != trials:
        raise ValueError(f"{stem}: cell identity mismatch")
    if payload.get("seed") != seed:
        raise ValueError(f"{stem}: seed mismatch")
    samples = payload.get("total_us")
    if (
        not isinstance(samples, list)
        or len(samples) != trials
        or any(type(sample) is not int or sample <= 0 for sample in samples)
    ):
        raise ValueError(f"{stem}: expected {trials} positive integer samples")
    for component in ("local_send_us", "gateway_accept_us", "gateway_echo_us"):
        values = payload.get(component)
        if (
            not isinstance(values, list)
            or len(values) != trials
            or any(type(value) is not int or value < 0 for value in values)
        ):
            raise ValueError(f"{stem}: invalid {component}")
    proxy = payload.get("proxy")
    if not isinstance(proxy, dict):
        raise ValueError(f"{stem}: proxy counters missing")
    if loss == 5 and (
        proxy.get("client_drops", 0) <= 0 or proxy.get("server_drops", 0) <= 0
    ):
        raise ValueError(f"{stem}: configured loss was not observed in both directions")
    timing = read_time(root / f"{stem}.time")
    return {
        "samples": samples,
        "p50_us": nearest_rank(samples, 0.50),
        "p95_us": nearest_rank(samples, 0.95),
        "max_us": max(samples),
        "timing": timing,
        "proxy": proxy,
    }


def blocks(values: list[int]) -> list[list[int]]:
    return [values[index : index + BLOCK_SIZE] for index in range(0, len(values), BLOCK_SIZE)]


def paired_ratio_interval(
    winner: dict[int, dict[str, Any]],
    default: dict[int, dict[str, Any]],
    resamples: int,
) -> tuple[float, float]:
    rng = random.Random(BOOTSTRAP_SEED)
    ratios: list[float] = []
    paired = {
        loss: (blocks(winner[loss]["samples"]), blocks(default[loss]["samples"]))
        for loss in LOSSES
    }
    for loss, (winner_blocks, default_blocks) in paired.items():
        if len(winner_blocks) != len(default_blocks):
            raise ValueError(f"loss {loss}: profile block counts differ")
    for _ in range(resamples):
        winner_worst = 0
        default_worst = 0
        for loss in LOSSES:
            winner_blocks, default_blocks = paired[loss]
            winner_sample: list[int] = []
            default_sample: list[int] = []
            for _ in range(len(winner_blocks)):
                index = rng.randrange(len(winner_blocks))
                winner_sample.extend(winner_blocks[index])
                default_sample.extend(default_blocks[index])
            winner_worst = max(winner_worst, nearest_rank(winner_sample, 0.95))
            default_worst = max(default_worst, nearest_rank(default_sample, 0.95))
        ratios.append(winner_worst / default_worst)
    ratios.sort()
    lower = ratios[max(0, math.floor(0.025 * resamples))]
    upper = ratios[min(resamples - 1, math.ceil(0.975 * resamples) - 1)]
    return lower, upper


def analyze(root: Path, resamples: int) -> dict[str, Any]:
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported tuning manifest")
    trials = manifest.get("trials")
    seeds_raw = manifest.get("seeds")
    if type(trials) is not int or trials < 1 or not isinstance(seeds_raw, dict):
        raise ValueError("invalid trials or seeds in tuning manifest")
    seeds = {int(loss): int(seeds_raw[str(loss)]) for loss in LOSSES}
    expected_profiles = profile_names()
    if manifest.get("profiles") != expected_profiles:
        raise ValueError("manifest profile order differs from the registered matrix")

    valid: dict[str, dict[int, dict[str, Any]]] = {}
    rejected: dict[str, str] = {}
    for profile in expected_profiles:
        try:
            valid[profile] = {
                loss: read_cell(root, profile, loss, trials, seeds[loss])
                for loss in LOSSES
            }
        except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            rejected[profile] = str(error)

    if DEFAULT not in valid:
        raise ValueError(f"preregistered default did not pass correctness: {rejected.get(DEFAULT)}")
    ranked = []
    for profile, cells in valid.items():
        worst_p95 = max(cell["p95_us"] for cell in cells.values())
        worst_p50 = max(cell["p50_us"] for cell in cells.values())
        cpu_s = sum(float(cell["timing"]["cpu_s"]) for cell in cells.values())
        ranked.append(
            {
                "profile": profile,
                "worst_cell_p95_us": worst_p95,
                "worst_cell_p50_us": worst_p50,
                "cpu_s": cpu_s,
                "cells": {str(loss): cells[loss] for loss in LOSSES},
            }
        )
    ranked.sort(
        key=lambda item: (
            item["worst_cell_p95_us"],
            item["worst_cell_p50_us"],
            item["cpu_s"],
            item["profile"],
        )
    )
    raw_winner = ranked[0]["profile"]
    interval = [1.0, 1.0]
    selection_eligible = trials >= 200
    distinguishable = raw_winner == DEFAULT and selection_eligible
    selected = DEFAULT
    if raw_winner != DEFAULT:
        lower, upper = paired_ratio_interval(
            valid[raw_winner], valid[DEFAULT], resamples
        )
        interval = [lower, upper]
        distinguishable = selection_eligible and upper < 1.0
        if distinguishable:
            selected = raw_winner

    return {
        "schema_version": 1,
        "decision": (
            "validation-only-default-retained"
            if not selection_eligible
            else "selected" if selected != DEFAULT else "default-retained"
        ),
        "selection_eligible": selection_eligible,
        "selected_profile": selected,
        "preregistered_default": DEFAULT,
        "raw_winner": raw_winner,
        "winner_default_p95_ratio_interval_95": interval,
        "winner_distinguishable": distinguishable,
        "ranking_rule": "worst-cell p95, then worst-cell p50, then summed process CPU",
        "selection_rule": "change default only when paired block-stratified p95 ratio upper-95 is below 1.00",
        "bootstrap": {
            "resamples": resamples,
            "seed": BOOTSTRAP_SEED,
            "block_size": BLOCK_SIZE,
            "strata": ["loss0", "loss5"],
        },
        "trials_per_profile_per_cell": trials,
        "tuning_seeds": {str(loss): seeds[loss] for loss in LOSSES},
        "valid_profile_count": len(valid),
        "rejected_profiles": rejected,
        "ranking": ranked,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--resamples", type=int, default=20_000)
    arguments = parser.parse_args()
    if arguments.resamples < 100:
        raise SystemExit("at least 100 bootstrap resamples are required")
    result = analyze(arguments.root, arguments.resamples)
    arguments.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(
        f"{result['decision']}: {result['selected_profile']} "
        f"(raw winner {result['raw_winner']}, "
        f"valid {result['valid_profile_count']}/18)"
    )


if __name__ == "__main__":
    main()
