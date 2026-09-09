"""Pure quantitative analysis for the matched reliable-stream floor.

This module deliberately accepts already validated, in-memory evidence.  Build,
source, trace, and receipt validation belong to the caller.  The returned
report is a floor result only; it cannot certify production everudp.
"""

from __future__ import annotations

import math
import numbers
import random
import statistics
from dataclasses import dataclass
from typing import Any


CANDIDATES = (
    "everudp-stream-native",
    "everudp-stream-ordinary",
    "zmosh-udp",
)
LOSSES = (0, 5)
TRIALS = 200
BLOCKS_PER_CELL = 2
BOOTSTRAP_RESAMPLES = 20_000
BOOTSTRAP_SEED = 76_000
P50_LIMIT = 0.90
PACKET_LIMIT = 1.60


@dataclass(frozen=True)
class Block:
    """One complete trial block from one loss cell.

    ``results`` values are the canonical result objects, and ``order`` is the
    candidate order used by the block's reversed scheduling design.
    """

    loss: int
    order: tuple[str, ...]
    results: dict[str, dict[str, Any]]
    packet_attempts: dict[str, int]


def _invalid(message: str) -> ValueError:
    return ValueError(f"invalid stream-floor evidence: {message}")


def _validate_result(candidate: str, result: Any) -> list[float]:
    if type(result) is not dict:
        raise _invalid(f"{candidate}: result must be an object")
    required = {"schema_version", "trials", "gap_ms", "samples_us", "transcript_failures"}
    if not required.issubset(result):
        raise _invalid(f"{candidate}: result is missing canonical fields")
    # pty-bench emits these provenance/timing fields.  Harmless additional
    # metadata is intentionally retained by the caller and does not make the
    # numerical evaluator reject the record.
    if type(result["schema_version"]) is not int or result["schema_version"] != 1:
        raise _invalid(f"{candidate}: schema_version must be exactly one")
    if type(result["gap_ms"]) is not int or result["gap_ms"] != 100:
        raise _invalid(f"{candidate}: gap_ms must be exactly 100")
    if type(result["trials"]) is not int or result["trials"] != TRIALS:
        raise _invalid(f"{candidate}: trials must be exactly {TRIALS}")
    if type(result["transcript_failures"]) is not int or result["transcript_failures"] != 0:
        raise _invalid(f"{candidate}: transcript failures must be exactly zero")
    samples = result["samples_us"]
    if type(samples) is not list or len(samples) != TRIALS:
        raise _invalid(f"{candidate}: samples_us must contain {TRIALS} values")
    values: list[float] = []
    for index, value in enumerate(samples):
        if isinstance(value, bool) or not isinstance(value, numbers.Real):
            raise _invalid(f"{candidate}: sample {index} is not a real number")
        try:
            converted = float(value)
        except (OverflowError, TypeError, ValueError) as error:
            raise _invalid(f"{candidate}: sample {index} is not finite and positive") from error
        if not math.isfinite(converted) or converted <= 0:
            raise _invalid(f"{candidate}: sample {index} is not finite and positive")
        values.append(converted)
    return values


def _validate_block(block: Any) -> None:
    if not isinstance(block, Block):
        raise _invalid("all entries must be Block values")
    if type(block.loss) is not int or block.loss not in LOSSES:
        raise _invalid("loss must be exactly 0 or 5")
    if type(block.order) is not tuple or len(block.order) != len(CANDIDATES):
        raise _invalid("order must be a three-item tuple")
    if any(type(name) is not str for name in block.order) or set(block.order) != set(CANDIDATES):
        raise _invalid("order must contain each candidate exactly once")
    if type(block.results) is not dict or set(block.results) != set(CANDIDATES):
        raise _invalid("results must contain exactly the three candidates")
    if type(block.packet_attempts) is not dict or set(block.packet_attempts) != set(CANDIDATES):
        raise _invalid("packet_attempts must contain exactly the three candidates")
    for candidate in CANDIDATES:
        _validate_result(candidate, block.results[candidate])
        attempts = block.packet_attempts[candidate]
        if type(attempts) is not int or attempts <= 0:
            raise _invalid(f"{candidate}: packet attempts must be a positive integer")


def _nearest_rank(values: list[float], fraction: float) -> float:
    if not values:
        raise ValueError("cannot calculate a percentile of an empty sample")
    ordered = sorted(values)
    rank = max(1, math.ceil(len(ordered) * fraction))
    return ordered[rank - 1]


def _summary(values: list[float]) -> dict[str, float]:
    p50 = statistics.median(values)
    p95 = _nearest_rank(values, 0.95)
    if not math.isfinite(p50) or not math.isfinite(p95) or p50 <= 0 or p95 <= 0:
        raise _invalid("derived latency percentile is not finite and positive")
    return {"p50_us": p50, "p95_us": p95}


def _bootstrap_upper95(
    native_blocks: list[list[float]],
    udp_blocks: list[list[float]],
    *,
    seed: int,
    resamples: int = BOOTSTRAP_RESAMPLES,
) -> float:
    """Block-stratified bootstrap upper 95th percentile of the p50 ratio."""

    rng = random.Random(seed)
    ratios: list[float] = []
    for _ in range(resamples):
        native = [value for block in native_blocks for value in rng.choices(block, k=len(block))]
        udp = [value for block in udp_blocks for value in rng.choices(block, k=len(block))]
        ratios.append(_ratio(statistics.median(native), statistics.median(udp)))
    return _nearest_rank(ratios, 0.95)


def _ratio(numerator: float, denominator: float) -> float:
    try:
        value = numerator / denominator
    except (OverflowError, ZeroDivisionError) as error:
        raise _invalid("derived ratio is not finite") from error
    if not math.isfinite(value) or value <= 0:
        raise _invalid("derived ratio is not finite and positive")
    return value


def analyze(blocks: list[Block]) -> dict[str, Any]:
    """Validate and analyze exactly the frozen four-block floor experiment."""

    if type(blocks) is not list or len(blocks) != 4:
        raise _invalid("exactly four blocks are required")
    for block in blocks:
        _validate_block(block)
    by_loss = {loss: [block for block in blocks if block.loss == loss] for loss in LOSSES}
    for loss, cell_blocks in by_loss.items():
        if len(cell_blocks) != BLOCKS_PER_CELL:
            raise _invalid(f"loss {loss} requires exactly two blocks")
        orders = [block.order for block in cell_blocks]
        if orders[0] == orders[1] or orders[1] != tuple(reversed(orders[0])):
            raise _invalid(f"loss {loss} blocks must use reversed candidate orders")

    cells: dict[str, Any] = {}
    overall_pass = True
    for loss in LOSSES:
        cell_blocks = by_loss[loss]
        pooled: dict[str, list[float]] = {candidate: [] for candidate in CANDIDATES}
        packet_totals = {candidate: 0 for candidate in CANDIDATES}
        block_reports: list[dict[str, Any]] = []
        packet_block_ratios: list[dict[str, float]] = []
        native_blocks: list[list[float]] = []
        udp_blocks: list[list[float]] = []
        for block in cell_blocks:
            block_values = {
                candidate: _validate_result(candidate, block.results[candidate])
                for candidate in CANDIDATES
            }
            for candidate in CANDIDATES:
                pooled[candidate].extend(block_values[candidate])
                packet_totals[candidate] += block.packet_attempts[candidate]
            native_blocks.append(block_values["everudp-stream-native"])
            udp_blocks.append(block_values["zmosh-udp"])
            block_packet_ratios = {
                candidate: _ratio(
                    block.packet_attempts[candidate], block.packet_attempts["zmosh-udp"]
                )
                for candidate in CANDIDATES
            }
            packet_block_ratios.append(block_packet_ratios)
            block_reports.append(
                {
                    "order": list(block.order),
                    "samples_per_candidate": TRIALS,
                    "latency": {candidate: _summary(block_values[candidate]) for candidate in CANDIDATES},
                    "packet_attempts": dict(block.packet_attempts),
                    "packet_attempt_ratios_vs_zmosh_udp": block_packet_ratios,
                }
            )

        latency = {candidate: _summary(pooled[candidate]) for candidate in CANDIDATES}
        p50_native_udp = _ratio(latency[CANDIDATES[0]]["p50_us"], latency["zmosh-udp"]["p50_us"])
        p95_native_udp = _ratio(latency[CANDIDATES[0]]["p95_us"], latency["zmosh-udp"]["p95_us"])
        p50_native_ordinary = _ratio(
            latency[CANDIDATES[0]]["p50_us"], latency[CANDIDATES[1]]["p50_us"]
        )
        p95_native_ordinary = _ratio(
            latency[CANDIDATES[0]]["p95_us"], latency[CANDIDATES[1]]["p95_us"]
        )
        pooled_packet_ratios = {
            candidate: _ratio(packet_totals[candidate], packet_totals["zmosh-udp"])
            for candidate in CANDIDATES
        }
        bootstrap_seed = BOOTSTRAP_SEED + loss
        bootstrap_upper95 = _bootstrap_upper95(
            native_blocks, udp_blocks, seed=bootstrap_seed
        )
        packet_blocks_pass = all(
            ratios["everudp-stream-native"] <= PACKET_LIMIT for ratios in packet_block_ratios
        )
        cell_pass = p50_native_udp <= P50_LIMIT and packet_blocks_pass and pooled_packet_ratios[
            "everudp-stream-native"
        ] <= PACKET_LIMIT
        overall_pass &= cell_pass
        cells[str(loss)] = {
            "blocks": block_reports,
            "observations_per_candidate": TRIALS * BLOCKS_PER_CELL,
            "latency": latency,
            "ratios": {
                "native_vs_ordinary": {"p50": p50_native_ordinary, "p95": p95_native_ordinary},
                "native_vs_zmosh_udp": {"p50": p50_native_udp, "p95": p95_native_udp},
            },
            "packet_attempts": packet_totals,
            "packet_attempt_ratios_vs_zmosh_udp": pooled_packet_ratios,
            "bootstrap": {
                "seed": bootstrap_seed,
                "resamples": BOOTSTRAP_RESAMPLES,
                "native_vs_zmosh_udp_p50_upper95": bootstrap_upper95,
                "upper95_reported_not_gating": True,
            },
            "gate": {
                "native_vs_zmosh_udp_p50_at_most_0_90": p50_native_udp <= P50_LIMIT,
                "native_packet_ratio_each_block_at_most_1_60": packet_blocks_pass,
                "native_packet_ratio_pooled_at_most_1_60": pooled_packet_ratios[
                    "everudp-stream-native"
                ]
                <= PACKET_LIMIT,
                "pass": cell_pass,
            },
        }

    return {
        "schema_version": 1,
        "purpose": "matched-reliable-stream-floor-quantitative",
        "quantitative_gate_status": "PASS" if overall_pass else "FAIL",
        "bootstrap": {
            "resamples": BOOTSTRAP_RESAMPLES,
            "block_stratified": True,
            "upper95_reported_not_gating": True,
            "seed_base": BOOTSTRAP_SEED,
        },
        "thresholds": {"p50_native_udp_max": P50_LIMIT, "packet_ratio_max": PACKET_LIMIT},
        "cells": cells,
    }


__all__ = ["Block", "analyze"]
