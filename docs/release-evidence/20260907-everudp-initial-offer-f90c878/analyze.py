"""Strict .33 matched experiment analysis. Not production qualification."""
import hashlib
import json
import math
from pathlib import Path
import random
from statistics import median
import subprocess
import sys

ROOT = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(ROOT / "support"))
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHAS = {"baseline": "1bdd3528bc4d257a1f33adc96b1fb48a97a777d9",
        "candidate": "f90c878dfda16c86b7bd04ee255889450eedb859"}
NAMES = ("everudp-floor", "zmosh-udp")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def load(path):
    return json.loads(path.read_text())

def quantile(values, fraction):
    return sorted(values)[math.ceil(fraction * len(values)) - 1]

builds = {role: load(ROOT / f"build-{role}.json") for role in SHAS}
for role, build in builds.items():
    assert build["source"]["clean"] is True
    assert build["source"]["head_sha"] == SHAS[role]
    assert build["everudp_build"]["cargo_features"] == ["cli", "reliable-datagram-spike", "floor-single-owner"]
    assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
assert builds["baseline"]["everudp_build"] == builds["candidate"]["everudp_build"]
for name in ("zmosh-udp", "pty-bench", "pty-echo"):
    assert builds["baseline"]["artifacts"][name]["sha256"] == builds["candidate"]["artifacts"][name]["sha256"]

cells = {}
for loss, seed_base in ((0, 980700), (5, 985700)):
    grouped = {role: [] for role in SHAS}
    for index, role in enumerate(("baseline", "candidate", "candidate", "baseline"), 1):
        directory = ROOT / f"loss{loss}-block{index}"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        manifest = load(directory / "manifest.json")
        build = builds[role]
        # The frozen execution harness is the candidate checkout even for old binaries.
        assert manifest["source"] == {"head_sha": SHAS["candidate"],
                                      "tree_sha": builds["candidate"]["source"]["tree_sha"], "dirty": False}
        assert manifest["build"]["provenance_sha256"] == digest(ROOT / f"build-{role}.json")
        assert manifest["order"] == (list(NAMES) if index in (1, 3) else list(reversed(NAMES)))
        assert manifest["seeds"] == {"client": seed_base + index, "server": seed_base + index + 1000003}
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["affinity"] == "40,42,44,46"
        assert manifest["timer"] == "immediately before PTY public send; after exact byte accepted by /dev/null sink"
        pinned = directory / "governors-pinned.txt"
        assert digest(pinned) == manifest["governors"]["pinned"]["sha256"]
        assert pinned.read_text().splitlines() == [f"cpu{cpu} performance" for cpu in (40, 42, 44, 46)]
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["diagnostic_tracing"] is False and manifest["native_stage_tracing"] is False
        assert set(manifest["artifacts"]) == set(build["artifacts"])
        for name, artifact in manifest["artifacts"].items():
            assert artifact["sha256"] == build["artifacts"][name]["sha256"]
        row = {"block": index, "samples": {}, "attempts": {}}
        for name in NAMES:
            result_path = directory / name / "result.json"
            result = load(result_path)
            trials, boundaries = _validated_boundaries(result)
            _sample_check(result, boundaries)
            assert trials == 200
            assert manifest["results"][name]["sha256"] == digest(result_path)
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
    rng = random.Random(986000 + loss)
    distributions = {role: [] for role in SHAS}
    matched = {name: [] for name in NAMES}
    for _ in range(20000):
        sampled = {role: {name: median([v for block in blocks
                         for v in rng.choices(block["samples"][name], k=200)])
                         for name in NAMES} for role, blocks in grouped.items()}
        for role in SHAS:
            distributions[role].append(sampled[role][NAMES[0]] / sampled[role][NAMES[1]])
        for name in NAMES:
            matched[name].append(sampled["candidate"][name] / sampled["baseline"][name])
    summaries = {}
    for role, blocks in grouped.items():
        p50 = {name: median([v for block in blocks for v in block["samples"][name]]) for name in NAMES}
        attempts = {name: sum(block["attempts"][name] for block in blocks) for name in NAMES}
        ratios = [block["attempts"][NAMES[0]] / block["attempts"][NAMES[1]] for block in blocks]
        ratio = p50[NAMES[0]] / p50[NAMES[1]]
        packet_ratio = attempts[NAMES[0]] / attempts[NAMES[1]]
        summaries[role] = {"p50_us": p50, "p50_ratio": ratio,
            "p50_ratio_upper95": quantile(distributions[role], .95), "attempts": attempts,
            "packet_ratio": packet_ratio, "packet_block_ratios": ratios,
            "numerical_floor_gate_pass": ratio <= .90 and packet_ratio <= 1.60 and all(v <= 1.60 for v in ratios)}
    cells[str(loss)] = {"runtimes": summaries, "candidate_baseline": {
        name: {"p50_ratio": summaries["candidate"]["p50_us"][name] / summaries["baseline"]["p50_us"][name],
               "central95": [quantile(matched[name], .025), quantile(matched[name], .975)]} for name in NAMES}}
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
    "production_adoption": False, "runtime_shas": SHAS, "cells": cells,
    "resamples": 20000, "caveat": "Within-block resampling is not independent experiment replication or causal certainty. Allocation/component and production gates remain separate."}, indent=2, sort_keys=True))
