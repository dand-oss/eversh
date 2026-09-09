"""Reproduce diagnostic overhead and stage observations; never qualification."""
import hashlib
import json
import math
from pathlib import Path
import random
from statistics import median
import subprocess
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "support"))
from analyze_native_stages import analyze, INTERVALS
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHA = "1bdd3528bc4d257a1f33adc96b1fb48a97a777d9"
build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
assert build["source"]["head_sha"] == SHA and build["source"]["clean"] is True
assert build["everudp_build"]["cargo_features"] == ["cli", "reliable-datagram-spike", "floor-single-owner"]
assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
cells = {}
for loss, seed_base in ((0, 970700), (5, 975700)):
    samples = {mode: {name: [] for name in ("everudp-floor", "zmosh-udp")} for mode in ("off", "on")}
    reports, stage_rows, calibration = {}, [], []
    for block in (1, 2, 3, 4):
        directory = root / f"loss{loss}-block{block}"
        mode = "off" if block in (1, 4) else "on"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["source"] == {"head_sha": SHA, "tree_sha": build["source"]["tree_sha"], "dirty": False}
        assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
        seed = seed_base + block
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["order"] == (["everudp-floor", "zmosh-udp"] if block in (1, 3) else ["zmosh-udp", "everudp-floor"])
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["diagnostic_tracing"] is (mode == "on")
        assert manifest["native_stage_tracing"] is (mode == "on")
        assert set(manifest["artifacts"]) == set(build["artifacts"])
        for name, artifact in manifest["artifacts"].items():
            assert artifact["sha256"] == build["artifacts"][name]["sha256"]
        for name in ("everudp-floor", "zmosh-udp"):
            result_path = directory / name / "result.json"
            result = json.loads(result_path.read_text())
            trials, boundaries = _validated_boundaries(result)
            _sample_check(result, boundaries)
            assert trials == 200
            assert manifest["results"][name]["sha256"] == hashlib.sha256(result_path.read_bytes()).hexdigest()
            accounting = account_packet_attempts(*(
                (directory / f"netem-{name}-{direction}-{phase}.txt").read_text()
                for direction in ("client", "server") for phase in ("before", "after")))
            assert accounting.total_attempts == manifest["loss_evidence"][name]["summed_egress_attempt_delta"]
            if loss:
                assert accounting.client.dropped_packets > 0 and accounting.server.dropped_packets > 0
            samples[mode][name].append(result["samples_us"])
            trace_path = directory / name / "native-stage-trace.json"
            if name == "everudp-floor":
                assert trace_path.exists() is (mode == "on")
                if mode == "on":
                    trace = json.loads(trace_path.read_text())
                    report = analyze(result, trace)
                    assert report["status"] == "DIAGNOSTIC", report
                    stage_rows.extend(row for row in report["rows"] if row["status"] == "included")
                    calibration.extend(trace["cpu_clock_calibration_ns"])
                    reports[directory.name] = {key: value for key, value in report.items() if key != "rows"}
                    reports[directory.name]["excluded_rows"] = [row for row in report["rows"] if row["status"] != "included"]
    rng = random.Random(978000 + loss)
    ratios = {name: [] for name in ("everudp-floor", "zmosh-udp")}
    for _ in range(20000):
        for name in ratios:
            resampled = {mode: [sample for block in samples[mode][name]
                                for sample in rng.choices(block, k=len(block))] for mode in ("off", "on")}
            ratios[name].append(median(resampled["on"]) / median(resampled["off"]))
    overhead = {}
    for name, values in ratios.items():
        values.sort()
        off = median([value for block in samples["off"][name] for value in block])
        on = median([value for block in samples["on"][name] for value in block])
        overhead[name] = {"off_p50_us": off, "on_p50_us": on, "on_off_p50_ratio": on / off,
                          "on_off_ratio_central95": [values[math.ceil(.025 * len(values)) - 1],
                                                     values[math.ceil(.975 * len(values)) - 1]],
                          "observations_per_mode": 400}
    cells[str(loss)] = {
        "overhead_observations": overhead, "stage_reports": reports,
        "included_stage_trials": len(stage_rows),
        "pooled_stage_medians_ns": {clock: {name: median(row["intervals_ns"][clock][name] for row in stage_rows)
                                           for name, _, _ in INTERVALS} for clock in ("wall", "thread_cpu")},
        "cpu_clock_pair_calibration_ns": {"min": min(calibration), "median": median(calibration), "max": max(calibration)},
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                  "production_actor_integration_authorized": False,
                  "bootstrap": {"resamples": 20000, "block_stratified": True,
                                "caveat": "Within-block resampling, not independent experiment replications or causal overhead certainty."},
                  "cells": cells}, indent=2, sort_keys=True))
