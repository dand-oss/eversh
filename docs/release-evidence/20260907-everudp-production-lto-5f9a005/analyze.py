"""Frozen production-stream A/B diagnostic; not a qualification receipt."""
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "support"))
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHA = "5f9a0057213b3dc8b562c5c8959ea661868a3277"
TREE = "084738b2b60747a6dccc2994fddccf07d9f053af"
NAMES = ("everudp", "zmosh-udp", "zmosh-quic")
ROLES = ("baseline", "variant")
ITERATIONS = 20000


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def quantile(values, fraction):
    return sorted(values)[math.ceil(fraction * len(values)) - 1]


def verify_redaction(directory):
    record = load(directory / "redaction.json")
    assert record["path"] == "zmosh-quic/connect.log"
    assert record["original_receipt"] == "SHA256SUMS.original"
    assert digest(directory / record["path"]) == record["redacted_sha256"]
    found = 0
    for line in (directory / "SHA256SUMS.original").read_text().splitlines():
        expected, relative = line.split(maxsplit=1)
        relative = relative.lstrip(" *").removeprefix("./")
        if relative == record["path"]:
            assert expected == record["original_sha256"]
            found += 1
        else:
            assert digest(directory / relative) == expected
    assert found == 1
    records = [line for line in (directory / record["path"]).read_text().splitlines()
               if line.startswith("ZMX_CONNECT ")]
    assert records and all(line.split()[-1] == "[REDACTED]" for line in records)


builds = {role: load(ROOT / f"build-{role}.json") for role in ROLES}
for role, build in builds.items():
    assert build["source"] == {"head_sha": SHA, "tree_sha": TREE, "clean": True}
    assert build["everudp_build"]["cargo_features"] == ["cli"]
    assert build["everudp_build"]["profile"] == {
        "lto": "false" if role == "baseline" else "fat",
        "codegen_units": 16 if role == "baseline" else 1,
        "panic": "unwind", "opt_level": 3, "rustflags": "",
        "encoded_rustflags": "", "target_cpu": "portable default"}
    assert build["zmosh_sources"]["udp"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
    assert build["zmosh_sources"]["quic"]["commit"] == "21db4a4de6040b254531f2131b6f1c0cd146a7a1"
control_origins = []
for role, build in builds.items():
    origins = {}
    for name in ("control", "runtime"):
        reuse = build["control_reuse" if name == "control" else "runtime_build"]
        assert reuse["provenance"] == f"provenance-inputs/{name}.json"
        path = ROOT / "provenance-inputs" / role / f"{name}.json"
        assert digest(path) == reuse["sha256"]
        origins[name] = load(path)
    control_origins.append(origins["control"])
    assert origins["runtime"]["source"] == build["source"]
    assert origins["runtime"]["cargo_features"] == build["everudp_build"]["cargo_features"]
    assert origins["runtime"]["profile"] == build["everudp_build"]["profile"]
    assert origins["runtime"]["inputs"]["Cargo.lock"] == build["inputs"]["Cargo.lock"]
    assert origins["runtime"]["artifact_sha256"] == build["artifacts"]["everudp"]["sha256"]
    for stream in ("stdout", "stderr"):
        assert digest(ROOT / "logs" / role / f"everudp-build.{stream}") == origins["runtime"]["logs"][stream]
    assert origins["control"]["source"] == {
        "head_sha": "a86efafe2daff03e895616a6e8db9fd58ea48ffa",
        "tree_sha": "d145fe5eb17f905ba4292ff5887357350d221ae0", "clean": True}
    for name in ("cargo", "rustc"):
        assert origins["runtime"][name] == build["tools"][name]
        assert origins["control"]["tools"][name] == build["tools"][name]
    assert origins["control"]["inputs"] == build["inputs"]
    assert origins["control"]["zmosh_sources"] == build["zmosh_sources"]
    assert set(build["artifacts"]) == set(origins["control"]["artifacts"])
    for name, artifact in build["artifacts"].items():
        if name != "everudp":
            assert artifact == origins["control"]["artifacts"][name]
assert control_origins[0] == control_origins[1]

failed = ROOT / "loss5-block1-failed"
subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=failed, check=True)
failure = load(failed / "failure.json")
assert failure["status"] == "FAILED_BEFORE_MEASUREMENT"
assert failure["source_sha"] == SHA and failure["seed"] == 1126701
assert failure["failed_candidate"] == "zmosh-quic" and failure["replacement_run"] is False
assert not (failed / "zmosh-quic/connect.log").exists()
assert not (failed / "zmosh-quic/result.json").exists()
for name in NAMES[:2]:
    result = load(failed / name / "result.json")
    trials, boundaries = _validated_boundaries(result)
    _sample_check(result, boundaries)
    assert trials == 200 and result["transcript_failures"] == 0

cells = {}
for loss in (0, 5):
    grouped = {role: [] for role in ROLES}
    for index, role in enumerate(("baseline", "variant", "variant", "baseline"), 1):
        if loss == 5 and index == 1:
            continue  # Preserved failure, never replaced or pooled as complete.
        directory = ROOT / f"loss{loss}-block{index}"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        verify_redaction(directory)
        manifest = load(directory / "manifest.json")
        assert manifest["source"] == {"head_sha": SHA, "tree_sha": TREE, "dirty": False}
        assert manifest["build"]["provenance_sha256"] == digest(ROOT / f"build-{role}.json")
        assert manifest["order"] == (list(NAMES) if index in (1, 3) else list(reversed(NAMES)))
        seed = 1121700 + loss * 1000 + index
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["affinity"] == "40,42,44,46"
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["timer"] == "immediately before PTY public send; after exact byte accepted by /dev/null sink"
        for flag in ("diagnostic_tracing", "production_path_tracing", "production_io_tracing", "native_stage_tracing", "reactor_work_tracing", "reactor_partition_tracing"):
            assert manifest[flag] is False
        for name in ("client-path-trace.json", "gateway-path-trace.json", "client-path-trace.json.io.json", "gateway-path-trace.json.io.json"):
            assert not (directory / "everudp" / name).exists()
        pinned = directory / "governors-pinned.txt"
        assert digest(pinned) == manifest["governors"]["pinned"]["sha256"]
        assert pinned.read_text().splitlines() == [f"cpu{cpu} performance" for cpu in (40, 42, 44, 46)]
        assert set(manifest["artifacts"]) == set(builds[role]["artifacts"])
        for name, artifact in manifest["artifacts"].items():
            assert artifact["sha256"] == builds[role]["artifacts"][name]["sha256"]
        row = {"block": index, "samples": {}, "attempts": {}}
        for name in NAMES:
            path = directory / name / "result.json"
            result = load(path)
            trials, boundaries = _validated_boundaries(result)
            _sample_check(result, boundaries)
            assert trials == 200 and result["transcript_failures"] == 0
            assert digest(path) == manifest["results"][name]["sha256"]
            accounting = account_packet_attempts(*(
                (directory / f"netem-{name}-{direction}-{phase}.txt").read_text()
                for direction in ("client", "server") for phase in ("before", "after")))
            evidence = manifest["loss_evidence"][name]
            assert evidence["measurement_window"] == "post-warmup-start-barrier-to-pre-teardown-finish-barrier"
            assert accounting.total_attempts == evidence["summed_egress_attempt_delta"] > 0
            if loss:
                assert accounting.client.dropped_packets > 0 and accounting.server.dropped_packets > 0
            row["samples"][name] = result["samples_us"]
            row["attempts"][name] = accounting.total_attempts
        grouped[role].append(row)

    def summarize(data):
        return {role: {name: {
            label: quantile([v for block in blocks for v in block["samples"][name]], fraction)
            for label, fraction in (("p50", .5), ("p95", .95))}
            for name in NAMES} for role, blocks in data.items()}

    if loss == 5:
        cells["5"] = {"status": "INCOMPLETE", "comparative_inference": False,
            "complete_blocks": {role: [{"block": block["block"], "latency_us": {
                name: {"p50": quantile(block["samples"][name], .5),
                       "p95": quantile(block["samples"][name], .95)} for name in NAMES}}
                for block in blocks] for role, blocks in grouped.items()},
            "failed_block": 1, "partial_responses_retained_not_pooled": 400}
        continue
    point = summarize(grouped)
    rng = random.Random(1131700 + loss)
    distributions = {name: {label: [] for label in ("p50", "p95")} for name in NAMES}
    for _ in range(ITERATIONS):
        sampled = summarize({role: [{"samples": {name: rng.choices(block["samples"][name], k=200)
                              for name in NAMES}} for block in blocks]
                             for role, blocks in grouped.items()})
        for name in NAMES:
            for label in ("p50", "p95"):
                distributions[name][label].append(sampled["variant"][name][label] / sampled["baseline"][name][label])
    cells[str(loss)] = {
        "samples_per_name_per_role": 400,
        "latency_us": point,
        "variant_baseline": {name: {label: {
            "ratio": point["variant"][name][label] / point["baseline"][name][label],
            "central95": [quantile(distributions[name][label], .025), quantile(distributions[name][label], .975)]}
            for label in ("p50", "p95")} for name in NAMES},
        "versus_controls": {role: {name: {label: point[role]["everudp"][label] / point[role][name][label]
                              for label in ("p50", "p95")} for name in NAMES[1:]} for role in ROLES},
        "packet_attempts": {role: [{"block": block["block"], **block["attempts"]} for block in blocks]
                            for role, blocks in grouped.items()},
    }
print(json.dumps({"status": "INCOMPLETE_DIAGNOSTIC", "qualification": False, "production_adoption": False,
    "incomplete_cells": {"5": "Frozen zmosh QUIC warm-up failed in block1; no replacement."},
    "source_sha": SHA, "tree_sha": TREE, "resamples": ITERATIONS, "cells": cells,
    "method": "Nearest-rank quantiles; independent resampling within each fixed block; central 95% variant/baseline intervals.",
    "caveat": "Within-block resampling is not independent experimental replication. Four blocks/cell do not satisfy the frozen six-block production qualification."}, indent=2, sort_keys=True))
