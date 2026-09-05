#!/usr/bin/env python3
"""Verify one-source everudp parity, controls, oracle, and reachability evidence."""

import argparse
import hashlib
import json
import re
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path}: expected JSON object")
    return data


def verify_inventory(root: Path, checksum_name: str) -> str:
    checksum_path = root / checksum_name
    expected = {}
    for line in checksum_path.read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        require(match is not None, f"{checksum_path}: malformed checksum line")
        relative = match.group(2).removeprefix("./")
        target = (root / relative).resolve()
        require(target.is_relative_to(root.resolve()), f"{checksum_path}: unsafe path")
        expected[relative] = match.group(1)
    actual = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file() and path.name != checksum_name
    }
    require(set(expected) == actual, f"{root}: checksum inventory mismatch")
    for relative, wanted in expected.items():
        require(digest(root / relative) == wanted, f"{root}: checksum mismatch for {relative}")
    return digest(checksum_path)


def source_tuple(source: dict, style: str) -> tuple[str, str, bool]:
    if style == "reachability":
        return source["commit"], source["tree"], source["clean"]
    if "clean" in source:
        clean = source["clean"]
    elif "dirty" in source:
        clean = not source["dirty"]
    elif "all_cells_clean_and_identical" in source:
        clean = source["all_cells_clean_and_identical"]
    else:
        clean = source.get("all_blocks_clean", False)
    return source["head_sha"], source["tree_sha"], clean


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--controls", required=True, type=Path)
    parser.add_argument("--parity", required=True, type=Path)
    parser.add_argument("--oracle", required=True, type=Path)
    parser.add_argument("--reachability", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    checksums = {
        "controls": verify_inventory(args.controls, "CONTROL_SHA256SUMS"),
        "parity": verify_inventory(args.parity, "SHA256SUMS"),
        "reachability": verify_inventory(args.reachability, "SHA256SUMS"),
    }
    controls_receipt = load_json(args.controls / "receipt.json")
    controls_analysis = load_json(args.controls / "analysis.json")
    parity_receipt = load_json(args.parity / "receipt.json")
    parity_analysis = load_json(args.parity / "analysis.json")
    oracle = load_json(args.oracle)
    reachability = load_json(args.reachability / "receipt.json")

    sources = {
        "controls_receipt": source_tuple(controls_receipt["source"], "standard"),
        "controls_analysis": source_tuple(controls_analysis["source"], "standard"),
        "parity_receipt": source_tuple(parity_receipt["source"], "standard"),
        "parity_analysis": source_tuple(parity_analysis["source"], "standard"),
        "oracle": source_tuple(oracle["source"], "standard"),
        "reachability": source_tuple(reachability["source"], "reachability"),
    }
    wanted_source = (args.expected_head, args.expected_tree, True)
    for name, observed in sources.items():
        require(observed == wanted_source, f"{name}: source mismatch {observed!r}")

    controls_verdict = controls_receipt["verdict"]
    require(controls_verdict["control_qualification_pass"], "control qualification failed")
    require(controls_verdict["measurement_integrity_pass"], "control integrity failed")
    require(controls_verdict["resource_gate_pass"], "control resource gate failed")
    require(controls_verdict["outage_gate_pass"], "control outage gate failed")
    require(
        controls_analysis["verdict"]["zmosh_frozen_point_rule_pass"],
        "control matrix zmosh point rule failed",
    )

    parity_verdict = parity_analysis["verdict"]
    for field in (
        "preregistered_point_rule_pass",
        "exact_sha_evidence_pass",
        "observed_loss_evidence_pass",
        "conservative_upper95_equivalence_pass",
    ):
        require(parity_verdict[field], f"parity verdict failed: {field}")
    require(
        parity_receipt["analysis_sha256"] == digest(args.parity / "analysis.json"),
        "parity receipt analysis hash mismatch",
    )

    require(oracle["verdict"]["pass"], "terminal-grid oracle failed")
    require(oracle["oracle"]["real_pty_runs"] >= 30, "terminal-grid oracle under-sampled")
    require(
        oracle["oracle"]["password_prediction_displays"] == 0,
        "terminal-grid oracle displayed a password prediction",
    )
    require(
        oracle["oracle"]["correction_p95_us"]
        < oracle["oracle"]["correction_p95_limit_us"],
        "terminal-grid correction threshold failed",
    )

    require(reachability["overall_verdict"] == "PASS", "reachability gate failed")
    rows = {row["environment"]: row for row in reachability["rows"]}
    required_reachable = {
        "direct-ipv4",
        "direct-ipv6",
        "udp-blocked",
        "full-cone",
        "restricted-cone",
        "port-restricted-cone",
        "symmetric",
        "zerotier",
        "everssh-fallback",
    }
    require(required_reachable <= rows.keys(), "reachability rows missing")
    for name in required_reachable:
        row = rows[name]
        require(row["verdict"] == "PASS", f"reachability row failed: {name}")
        require(row["successes"] >= row["minimum"], f"reachability ratio failed: {name}")
    require(rows.get("tailscale", {}).get("verdict") in {"PASS", "UNAVAILABLE"}, "bad Tailscale verdict")
    require(
        reachability["blocked_udp"]
        == {
            "diagnosed_failures": 20,
            "diagnostic": "everudp-spike: UDP association handshake timed out",
        },
        "blocked-UDP diagnostic count mismatch",
    )
    require(
        reachability["fallback"] == {"invocations": 1, "transport": "everssh"},
        "fallback transition mismatch",
    )

    controls_loss5 = load_json(args.controls / "loss5" / "manifest.json")
    spike_hashes = {
        "controls": controls_loss5["artifacts"]["everudp"]["sha256"],
        "parity": parity_analysis["source"]["artifact_sha256"]["everudp"],
        "oracle": oracle["source"]["binary_sha256"],
        "reachability": reachability["source"]["spike_sha256"],
    }
    require(len(set(spike_hashes.values())) == 1, "everudp binary differs across gates")
    eversh_hashes = {
        "controls": controls_loss5["artifacts"]["everssh"]["sha256"],
        "reachability": reachability["source"]["eversh_sha256"],
    }
    require(len(set(eversh_hashes.values())) == 1, "eversh binary differs across gates")
    zmosh_hashes = {
        "controls": controls_loss5["artifacts"]["zmosh"]["sha256"],
        "parity": parity_analysis["source"]["artifact_sha256"]["zmosh"],
    }
    require(len(set(zmosh_hashes.values())) == 1, "zmosh binary differs across gates")
    zmosh_bench_hashes = {
        "controls": controls_loss5["artifacts"]["zmosh_bench"]["sha256"],
        "parity": parity_analysis["source"]["artifact_sha256"]["zmosh_bench"],
    }
    require(
        len(set(zmosh_bench_hashes.values())) == 1,
        "zmosh benchmark binary differs across gates",
    )

    tailscale_available = rows["tailscale"]["verdict"] == "PASS"
    all_performance = controls_verdict["all_preregistered_performance_thresholds_pass"]
    build_allowed = all_performance and tailscale_available
    closure = {
        "schema_version": 1,
        "source": {
            "head_sha": args.expected_head,
            "tree_sha": args.expected_tree,
            "all_components_clean_and_identical": True,
        },
        "component_sha256": {
            "controls_checksums": checksums["controls"],
            "controls_receipt": digest(args.controls / "receipt.json"),
            "controls_analysis": digest(args.controls / "analysis.json"),
            "parity_checksums": checksums["parity"],
            "parity_receipt": digest(args.parity / "receipt.json"),
            "parity_analysis": digest(args.parity / "analysis.json"),
            "oracle": digest(args.oracle),
            "reachability_checksums": checksums["reachability"],
            "reachability_receipt": digest(args.reachability / "receipt.json"),
        },
        "binary_sha256": {
            "everudp": next(iter(spike_hashes.values())),
            "eversh": next(iter(eversh_hashes.values())),
            "zmosh": next(iter(zmosh_hashes.values())),
            "zmosh_bench": next(iter(zmosh_bench_hashes.values())),
        },
        "requested_zmosh_parity": {
            "pooled": parity_analysis["pooled"],
            "uncertainty": parity_analysis["uncertainty"],
            "point_rule_pass": parity_verdict["preregistered_point_rule_pass"],
            "conservative_upper95_rule_pass": parity_verdict[
                "conservative_upper95_equivalence_pass"
            ],
            "proven": True,
        },
        "other_thresholds": {
            "everssh_point_rule_pass": controls_analysis["verdict"][
                "everssh_frozen_point_rule_pass"
            ],
            "correction_convergence_pass": controls_analysis["verdict"][
                "correction_convergence_pass"
            ],
            "tailscale": rows["tailscale"]["verdict"],
        },
        "verdict": {
            "exact_sha_closure_pass": True,
            "requested_zmosh_parity_proven": True,
            "all_preregistered_performance_thresholds_pass": all_performance,
            "tailscale_available_and_passed": tailscale_available,
            "decision": "BUILD" if build_allowed else "NOT-BUILD",
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(closure, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(closure["verdict"], sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (FileNotFoundError, KeyError, ValueError) as error:
        raise SystemExit(f"closure verification failed: {error}") from error
