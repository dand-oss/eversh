#!/usr/bin/env python3
"""Analyze hash-bound everudp/zmosh parity blocks with one common estimator."""

import argparse
import hashlib
import json
import math
import random
from pathlib import Path


def nearest_rank(samples, probability):
    ordered = sorted(samples)
    if not ordered:
        raise ValueError("cannot take a quantile of an empty sample")
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def percentile(ordered, probability):
    return ordered[max(0, math.ceil(probability * len(ordered)) - 1)]


def load_block(path):
    manifest_path = path / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    manifest["receipt_sha256"] = hashlib.sha256(manifest_bytes).hexdigest()
    result_paths = {name: path / name for name in ("everudp.json", "zmosh.json")}
    for name, result_path in result_paths.items():
        actual = hashlib.sha256(result_path.read_bytes()).hexdigest()
        if actual != manifest["results"][name]:
            raise ValueError(f"{path}: {name} hash does not match manifest")
    if manifest.get("schema_version", 1) >= 2:
        netem_receipts = manifest.get("netem_receipts", {})
        if len(netem_receipts) != 8:
            raise ValueError(f"{path}: expected eight netem counter receipts")
        for name, expected_hash in netem_receipts.items():
            actual_hash = hashlib.sha256((path / name).read_bytes()).hexdigest()
            if actual_hash != expected_hash:
                raise ValueError(f"{path}: {name} hash does not match manifest")
        observed = manifest["loss"]["observed_drop_delta"]
        if any(
            count <= 0
            for candidate in observed.values()
            for count in candidate.values()
        ):
            raise ValueError(f"{path}: candidate path did not observe configured loss")
    everudp = json.loads(result_paths["everudp.json"].read_text(encoding="utf-8"))
    zmosh = json.loads(result_paths["zmosh.json"].read_text(encoding="utf-8"))
    ev_samples = everudp["samples"]
    zm_samples = zmosh["samples"]
    expected = manifest["trials_per_candidate"]
    if len(ev_samples) != expected or len(zm_samples) != expected:
        raise ValueError(f"{path}: sample count does not match manifest")
    if any(value <= 0 for value in ev_samples + zm_samples):
        raise ValueError(f"{path}: zero/negative sample denotes a timeout or invalid observation")
    return manifest, ev_samples, zm_samples


def metrics(everudp, zmosh):
    ev_p50 = nearest_rank(everudp, 0.50)
    ev_p95 = nearest_rank(everudp, 0.95)
    zm_p50 = nearest_rank(zmosh, 0.50)
    zm_p95 = nearest_rank(zmosh, 0.95)
    return {
        "everudp_p50_us": ev_p50,
        "everudp_p95_us": ev_p95,
        "zmosh_p50_us": zm_p50,
        "zmosh_p95_us": zm_p95,
        "p50_ratio": ev_p50 / zm_p50,
        "p95_ratio": ev_p95 / zm_p95,
    }


def bootstrap(blocks, iterations, seed):
    generator = random.Random(seed)
    p50_ratios = []
    p95_ratios = []
    for _ in range(iterations):
        everudp = []
        zmosh = []
        for _, ev_block, zm_block in blocks:
            everudp.extend(generator.choice(ev_block) for _ in ev_block)
            zmosh.extend(generator.choice(zm_block) for _ in zm_block)
        sample_metrics = metrics(everudp, zmosh)
        p50_ratios.append(sample_metrics["p50_ratio"])
        p95_ratios.append(sample_metrics["p95_ratio"])
    p50_ratios.sort()
    p95_ratios.sort()
    return {
        "iterations": iterations,
        "seed": seed,
        "p50_ratio_ci95": [percentile(p50_ratios, 0.025), percentile(p50_ratios, 0.975)],
        "p50_ratio_upper95": percentile(p50_ratios, 0.95),
        "p95_ratio_ci95": [percentile(p95_ratios, 0.025), percentile(p95_ratios, 0.975)],
        "p95_ratio_upper95": percentile(p95_ratios, 0.95),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("blocks", nargs="+", type=Path)
    parser.add_argument("--bootstrap", type=int, default=20_000)
    parser.add_argument("--seed", type=int, default=9015)
    args = parser.parse_args()

    blocks = [load_block(path) for path in args.blocks]
    heads = {block[0]["source"]["head_sha"] for block in blocks}
    trees = {block[0]["source"]["tree_sha"] for block in blocks}
    artifact_sets = {
        (
            block[0]["artifacts"]["everudp"]["sha256"],
            block[0]["artifacts"]["zmosh"]["sha256"],
            block[0]["artifacts"]["zmosh_bench"]["sha256"],
        )
        for block in blocks
    }
    dirty = [block[0]["source"]["dirty"] for block in blocks]
    if len(heads) != 1 or len(trees) != 1 or len(artifact_sets) != 1:
        raise SystemExit("all blocks must bind the same source commit, tree, and candidate binaries")

    everudp = [value for _, ev_block, _ in blocks for value in ev_block]
    zmosh = [value for _, _, zm_block in blocks for value in zm_block]
    pooled = metrics(everudp, zmosh)
    uncertainty = bootstrap(blocks, args.bootstrap, args.seed)
    point_pass = pooled["p50_ratio"] <= 1.10 and pooled["p95_ratio"] <= 1.15
    artifact_sha256 = next(iter(artifact_sets))
    exact_sha_evidence_pass = not any(dirty)
    observed_loss_evidence_pass = all(
        block[0].get("schema_version", 1) >= 2 for block in blocks
    )
    equivalence_pass = exact_sha_evidence_pass and observed_loss_evidence_pass and (
        uncertainty["p50_ratio_upper95"] <= 1.10
        and uncertainty["p95_ratio_upper95"] <= 1.15
    )
    wins = sum(left < right for left in everudp for right in zmosh)
    ties = sum(left == right for left in everudp for right in zmosh)
    probability_faster = (wins + 0.5 * ties) / (len(everudp) * len(zmosh))

    result = {
        "schema_version": 1,
        "source": {
            "head_sha": next(iter(heads)),
            "tree_sha": next(iter(trees)),
            "all_blocks_clean": exact_sha_evidence_pass,
            "artifact_sha256": {
                "everudp": artifact_sha256[0],
                "zmosh": artifact_sha256[1],
                "zmosh_bench": artifact_sha256[2],
            },
        },
        "method": {
            "quantile": "empirical nearest-rank ceil(p*n)-1, applied identically to both candidates",
            "uncertainty": "stratified independent nonparametric bootstrap within each run block",
            "loss_evidence": "hash-bound before/after qdisc counters with positive drop deltas on both egress paths",
            "thresholds": {"p50_ratio_max": 1.10, "p95_ratio_max": 1.15},
        },
        "blocks": [
            {
                "path": path.name,
                "manifest_sha256": manifest["receipt_sha256"],
                "seed": manifest["loss"]["client_seed"],
                "order": manifest["order"],
                **metrics(ev_block, zm_block),
            }
            for path, (manifest, ev_block, zm_block) in zip(args.blocks, blocks)
        ],
        "pooled": {
            "everudp_n": len(everudp),
            "zmosh_n": len(zmosh),
            **pooled,
            "probability_everudp_faster": probability_faster,
        },
        "uncertainty": uncertainty,
        "verdict": {
            "preregistered_point_rule_pass": point_pass,
            "exact_sha_evidence_pass": exact_sha_evidence_pass,
            "observed_loss_evidence_pass": observed_loss_evidence_pass,
            "conservative_upper95_equivalence_pass": equivalence_pass,
        },
    }
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
