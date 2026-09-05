#!/usr/bin/env python3
"""Verify one-source everudp parity, controls, oracle, and reachability evidence."""

import argparse
import csv
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path


ZMOSH_SOURCE_COMMIT = "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
ZMOSH_SOURCE_TREE = "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514"
CONTROL_CELLS = (
    "loss0",
    "loss1",
    "loss5",
    "loss10",
    "loss25",
    "loss5-jitter25",
    "loss5-jitter50",
    "loss5-reorder2",
)
ORACLE_WORKLOADS = (
    "echo",
    "mismatch-correction",
    "duplicate-reorder",
    "full-screen",
    "resize",
    "tmux",
    "no-echo",
    "epoch-reset-resync",
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def load_json(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    require(isinstance(data, dict), f"{path}: expected JSON object")
    return data


def verify_build_provenance(
    provenance_path: Path, repository_root: Path, expected_head: str, expected_tree: str
) -> dict[str, str]:
    provenance = load_json(provenance_path)
    require(provenance.get("schema_version") == 1, "build provenance schema mismatch")
    require(
        provenance.get("source")
        == {"head_sha": expected_head, "tree_sha": expected_tree, "clean": True},
        "build provenance source mismatch",
    )
    build = provenance.get("build", {})
    for field in ("fresh_output", "isolated_cargo_targets", "isolated_zig_caches"):
        require(build.get(field) is True, f"build provenance does not guarantee {field}")
    require(
        provenance.get("zmosh_source")
        == {"commit": ZMOSH_SOURCE_COMMIT, "tree": ZMOSH_SOURCE_TREE},
        "build provenance zmosh source mismatch",
    )

    input_paths = {
        "root_cargo_lock": repository_root / "Cargo.lock",
        "spike_cargo_lock": repository_root / "spikes/everudp/Cargo.lock",
        "zmosh_bench_source": repository_root / "spikes/everudp/net/zmosh-bench.c",
    }
    inputs = provenance.get("inputs", {})
    require(set(inputs) == set(input_paths), "build provenance input inventory mismatch")
    for name, path in input_paths.items():
        require(
            inputs[name].get("sha256") == digest(path),
            f"{name} build input hash mismatch",
        )

    artifact_names = {
        "everudp",
        "eversh",
        "zmosh",
        "zmosh_bench",
        "zmosh_header",
        "zmosh_library",
    }
    artifacts = provenance.get("artifacts", {})
    require(set(artifacts) == artifact_names, "build provenance artifact inventory mismatch")
    build_root = provenance_path.parent.resolve()
    observed = {}
    for name in sorted(artifact_names):
        relative = Path(artifacts[name].get("path", ""))
        require(not relative.is_absolute(), f"{name} artifact path must be relative")
        target = (build_root / relative).resolve()
        require(target.is_relative_to(build_root), f"{name} artifact escapes build root")
        actual = digest(target)
        require(
            artifacts[name].get("sha256") == actual,
            f"{name} artifact hash mismatch",
        )
        observed[name] = actual
    return observed


def verify_reproduced_json(
    command: list[str], expected_path: Path, cwd: Path, label: str
) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    require(
        completed.returncode == 0,
        f"{label} reproduction failed ({completed.returncode}): "
        f"{completed.stderr.decode(errors='replace').strip()}",
    )
    try:
        json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ValueError(f"{label} reproduction emitted invalid JSON: {error}") from error
    require(
        completed.stdout == expected_path.read_bytes(),
        f"{label} reproduction mismatch",
    )


def verify_digest_map(root: Path, mapping: dict, child_name: str, label: str) -> None:
    require(isinstance(mapping, dict) and mapping, f"{label} digest map missing")
    for name, wanted in mapping.items():
        require(re.fullmatch(r"[A-Za-z0-9._-]+", name) is not None, f"{label} unsafe name")
        require(
            digest(root / name / child_name) == wanted,
            f"{label} hash mismatch for {name}",
        )


def git_output(repository_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository_root), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    require(
        completed.returncode == 0,
        f"git {' '.join(arguments)} failed: {completed.stderr.strip()}",
    )
    return completed.stdout.strip()


def verify_current_source(
    repository_root: Path, expected_head: str, expected_tree: str
) -> None:
    require(
        git_output(repository_root, "rev-parse", "HEAD") == expected_head,
        "current checkout HEAD differs from closure source",
    )
    require(
        git_output(repository_root, "rev-parse", "HEAD^{tree}") == expected_tree,
        "current checkout tree differs from closure source",
    )
    require(
        not git_output(repository_root, "status", "--porcelain=v1"),
        "current checkout is dirty during closure verification",
    )


def verify_receipt_files(root: Path, manifest: dict, label: str) -> None:
    actual = {
        path.name: digest(path)
        for path in root.iterdir()
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    require(manifest.get("receipt_files") == actual, f"{label} receipt inventory mismatch")


def nearest_rank(samples: list[int], probability: float) -> int:
    ordered = sorted(samples)
    require(bool(ordered), "cannot compute a quantile from no samples")
    index = max(0, math.ceil(probability * len(ordered)) - 1)
    return ordered[index]


def verify_oracle_raw(oracle_path: Path, oracle: dict) -> str:
    raw = oracle.get("raw_runs", {})
    raw_name = raw.get("path", "")
    require(re.fullmatch(r"[A-Za-z0-9._-]+", raw_name) is not None, "unsafe oracle raw path")
    raw_path = oracle_path.parent / raw_name
    raw_digest = digest(raw_path)
    require(raw.get("sha256") == raw_digest, "oracle raw-run hash mismatch")

    expected_workloads = ",".join(ORACLE_WORKLOADS)
    pattern = re.compile(
        r"^oracle: PASS workloads=(\S+) correction_us=(\d+) "
        r"password_prediction_displays=(\d+) "
        r"persistent_predictions_applied=(\d+) persistent_corrections=(\d+)$"
    )
    corrections = []
    for line_number, line in enumerate(raw_path.read_text(encoding="utf-8").splitlines(), 1):
        match = pattern.fullmatch(line)
        require(match is not None, f"malformed oracle raw run on line {line_number}")
        workloads, correction, password, predictions, redraws = match.groups()
        require(workloads == expected_workloads, f"oracle workload mismatch on line {line_number}")
        require(password == "0", f"oracle password prediction on line {line_number}")
        require(predictions == "9", f"oracle prediction count mismatch on line {line_number}")
        require(redraws == "5", f"oracle correction count mismatch on line {line_number}")
        corrections.append(int(correction))

    details = oracle["oracle"]
    require(len(corrections) >= 30, "terminal-grid oracle under-sampled")
    require(details.get("real_pty_runs") == len(corrections), "oracle raw-run count mismatch")
    require(details.get("correction_samples_us") == corrections, "oracle correction samples mismatch")
    require(
        details.get("correction_p95_us") == nearest_rank(corrections, 0.95),
        "oracle correction p95 was not derived from raw runs",
    )
    require(details.get("persistent_replica") is True, "oracle did not use a persistent replica")
    require(
        details.get("persistent_predictions_applied_per_run") == 9,
        "oracle persistent prediction count mismatch",
    )
    require(
        details.get("persistent_corrections_per_run") == 5,
        "oracle persistent correction count mismatch",
    )
    derived_pass = details["correction_p95_us"] < details["correction_p95_limit_us"]
    require(oracle.get("verdict") == {"pass": derived_pass}, "oracle verdict is not derived")
    return raw_digest


def verify_controls_relationships(
    root: Path, receipt: dict, analysis: dict, wanted_source: tuple[str, str, bool]
) -> tuple[dict, dict]:
    require(receipt.get("trials_per_candidate_per_cell") == 30, "controls trial count mismatch")
    require(
        receipt.get("analysis_sha256") == digest(root / "analysis.json"),
        "controls receipt analysis hash mismatch",
    )
    require(set(receipt.get("cells", {})) == set(CONTROL_CELLS), "controls receipt cells mismatch")
    verify_digest_map(root, receipt["cells"], "manifest.json", "control cells")
    require(
        receipt["cells"] == analysis.get("matrix_manifest_sha256"),
        "controls receipt and analysis disagree on cell manifests",
    )

    children = {}
    for name, verdict_name in (("resource", "resource_gate_pass"), ("outage", "outage_gate_pass")):
        child = load_json(root / name / "manifest.json")
        require(source_tuple(child["source"], "standard") == wanted_source, f"{name} source mismatch")
        verify_receipt_files(root / name, child, name)
        recorded = receipt.get("child_gates", {}).get(name, {})
        require(
            recorded.get("manifest_sha256") == digest(root / name / "manifest.json"),
            f"{name} receipt manifest hash mismatch",
        )
        require(recorded.get("verdict") == child.get("verdict"), f"{name} receipt verdict mismatch")
        require(child["verdict"].get(verdict_name) is True, f"{name} gate failed")
        children[name] = child

    analysis_verdict = analysis["verdict"]
    expected_verdict = {
        "measurement_integrity_pass": analysis_verdict["measurement_integrity_pass"],
        "resource_gate_pass": children["resource"]["verdict"]["resource_gate_pass"],
        "outage_gate_pass": children["outage"]["verdict"]["outage_gate_pass"],
        "all_preregistered_performance_thresholds_pass": analysis_verdict[
            "all_preregistered_performance_thresholds_pass"
        ],
        "decision": analysis_verdict["decision"],
        "control_qualification_pass": (
            analysis_verdict["measurement_integrity_pass"]
            and children["resource"]["verdict"]["resource_gate_pass"]
            and children["outage"]["verdict"]["outage_gate_pass"]
        ),
    }
    require(receipt.get("verdict") == expected_verdict, "controls receipt verdict is not derived")
    return children["resource"], children["outage"]


def verify_parity_relationships(root: Path, receipt: dict, analysis: dict) -> None:
    require(
        receipt.get("analysis_sha256") == digest(root / "analysis.json"),
        "parity receipt analysis hash mismatch",
    )
    blocks = sorted(path for path in root.glob("block-*") if path.is_dir())
    expected_names = {f"block-{seed}" for seed in range(13001, 13007)}
    require({path.name for path in blocks} == expected_names, "parity block inventory mismatch")
    require(receipt.get("trials_per_candidate_per_block") == 100, "parity trial count mismatch")
    expected = {path.name: digest(path / "manifest.json") for path in blocks}
    require(receipt.get("blocks") == expected, "parity receipt block map mismatch")
    analysis_blocks = {
        block["path"]: block["manifest_sha256"] for block in analysis.get("blocks", [])
    }
    require(analysis_blocks == expected, "parity analysis block map mismatch")
    require(receipt.get("verdict") == analysis.get("verdict"), "parity receipt verdict mismatch")
    for path in blocks:
        manifest = load_json(path / "manifest.json")
        seed = int(path.name.removeprefix("block-"))
        expected_order = "everudp-first" if seed % 2 else "zmosh-first"
        require(manifest.get("trials_per_candidate") == 100, f"{path.name} trial count mismatch")
        require(manifest.get("loss", {}).get("client_seed") == seed, f"{path.name} seed mismatch")
        require(manifest.get("order") == expected_order, f"{path.name} order mismatch")


def verify_reachability_relationships(root: Path, receipt: dict) -> None:
    artifact_lines = (root / "artifact-sha256.txt").read_text(encoding="utf-8").splitlines()
    recorded = {}
    for line in artifact_lines:
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        require(match is not None, "malformed reachability artifact checksum")
        name = match.group(2).removeprefix("./")
        recorded[name] = match.group(1)
        require(digest(root / name) == match.group(1), f"reachability artifact hash mismatch: {name}")
    actual_names = {
        str(path.relative_to(root))
        for path in root.rglob("*")
        if path.is_file()
        and path.name not in {"artifact-sha256.txt", "receipt.json", "SHA256SUMS"}
    }
    require(set(recorded) == actual_names, "reachability artifact inventory mismatch")
    require(receipt.get("artifacts") == recorded, "reachability receipt artifact map mismatch")

    with (root / "rows.tsv").open(encoding="utf-8", newline="") as stream:
        rows = list(csv.DictReader(stream, delimiter="\t"))
    for row in rows:
        for field in ("successes", "attempts", "minimum"):
            row[field] = int(row[field])
    require(receipt.get("rows") == rows, "reachability receipt rows differ from raw TSV")
    allowed_unavailable = {"zerotier", "tailscale"}
    derived_pass = all(
        row["verdict"] == "PASS"
        or (row["environment"] in allowed_unavailable and row["verdict"] == "UNAVAILABLE")
        for row in rows
    )
    require(
        receipt.get("overall_verdict") == ("PASS" if derived_pass else "FAIL"),
        "reachability overall verdict is not derived from rows",
    )


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
    parser.add_argument("--build-provenance", required=True, type=Path)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--expected-tree", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    repository_root = Path(__file__).resolve().parents[3]
    net_root = Path(__file__).resolve().parent
    verify_current_source(repository_root, args.expected_head, args.expected_tree)
    built_hashes = verify_build_provenance(
        args.build_provenance,
        repository_root,
        args.expected_head,
        args.expected_tree,
    )

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

    controls_trials = controls_receipt.get("trials_per_candidate_per_cell")
    verify_reproduced_json(
        [
            sys.executable,
            str(net_root / "analyze-controls.py"),
            str(args.controls),
            "--trials",
            str(controls_trials),
            "--bootstrap",
            "20000",
            "--seed",
            "9015",
        ],
        args.controls / "analysis.json",
        repository_root,
        "controls analysis",
    )
    parity_blocks = sorted(path for path in args.parity.glob("block-*") if path.is_dir())
    verify_reproduced_json(
        [
            sys.executable,
            str(net_root / "analyze-parity.py"),
            *(str(path) for path in parity_blocks),
            "--bootstrap",
            "20000",
            "--seed",
            "9015",
        ],
        args.parity / "analysis.json",
        repository_root,
        "parity analysis",
    )
    resource_manifest, outage_manifest = verify_controls_relationships(
        args.controls, controls_receipt, controls_analysis, wanted_source
    )
    verify_parity_relationships(args.parity, parity_receipt, parity_analysis)
    oracle_raw_sha256 = verify_oracle_raw(args.oracle, oracle)
    verify_reachability_relationships(args.reachability, reachability)

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
    require(
        set(spike_hashes.values()) == {built_hashes["everudp"]},
        "everudp gate binary differs from the fresh exact-source build",
    )
    eversh_hashes = {
        "controls": controls_loss5["artifacts"]["everssh"]["sha256"],
        "reachability": reachability["source"]["eversh_sha256"],
    }
    require(
        set(eversh_hashes.values()) == {built_hashes["eversh"]},
        "eversh gate binary differs from the fresh exact-source build",
    )
    zmosh_hashes = {
        "controls": controls_loss5["artifacts"]["zmosh"]["sha256"],
        "parity": parity_analysis["source"]["artifact_sha256"]["zmosh"],
    }
    require(
        set(zmosh_hashes.values()) == {built_hashes["zmosh"]},
        "zmosh gate binary differs from the fresh pinned-source build",
    )
    zmosh_bench_hashes = {
        "controls": controls_loss5["artifacts"]["zmosh_bench"]["sha256"],
        "parity": parity_analysis["source"]["artifact_sha256"]["zmosh_bench"],
    }
    require(
        set(zmosh_bench_hashes.values()) == {built_hashes["zmosh_bench"]},
        "zmosh benchmark differs from the fresh exact-source build",
    )
    require(
        resource_manifest["method"]["server_binary_sha256"] == built_hashes["everudp"],
        "resource gate did not use the fresh everudp build",
    )
    require(
        outage_manifest["method"]["server_binary_sha256"] == built_hashes["everudp"],
        "outage gate did not use the fresh everudp build",
    )
    for path in parity_blocks:
        manifest = load_json(path / "manifest.json")
        zmosh_source = manifest["artifacts"]["zmosh"]
        require(
            zmosh_source.get("source_commit") == ZMOSH_SOURCE_COMMIT
            and zmosh_source.get("source_tree") == ZMOSH_SOURCE_TREE,
            f"{path.name}: zmosh source provenance mismatch",
        )

    tailscale_available = rows["tailscale"]["verdict"] == "PASS"
    all_performance = controls_verdict["all_preregistered_performance_thresholds_pass"]
    build_allowed = all_performance and tailscale_available
    closure = {
        "schema_version": 2,
        "source": {
            "head_sha": args.expected_head,
            "tree_sha": args.expected_tree,
            "all_components_clean_and_identical": True,
        },
        "component_sha256": {
            "build_provenance": digest(args.build_provenance),
            "controls_checksums": checksums["controls"],
            "controls_receipt": digest(args.controls / "receipt.json"),
            "controls_analysis": digest(args.controls / "analysis.json"),
            "parity_checksums": checksums["parity"],
            "parity_receipt": digest(args.parity / "receipt.json"),
            "parity_analysis": digest(args.parity / "analysis.json"),
            "oracle": digest(args.oracle),
            "oracle_raw_runs": oracle_raw_sha256,
            "reachability_checksums": checksums["reachability"],
            "reachability_receipt": digest(args.reachability / "receipt.json"),
        },
        "binary_sha256": {
            "everudp": built_hashes["everudp"],
            "eversh": built_hashes["eversh"],
            "zmosh": built_hashes["zmosh"],
            "zmosh_bench": built_hashes["zmosh_bench"],
        },
        "derivation": {
            "fresh_isolated_source_builds_verified": True,
            "controls_analysis_reexecuted_byte_identical": True,
            "parity_analysis_reexecuted_byte_identical": True,
            "receipt_to_child_hash_relations_verified": True,
            "oracle_recomputed_from_raw_runs": True,
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
