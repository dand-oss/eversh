"""Reproduce diagnostic overhead and reactor observations; never qualification."""
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
from analyze_reactor_work import analyze
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHA = "080f36fa20f393774fe8ff8b6bdf22545a9ce3e1"
build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
assert build["source"]["head_sha"] == SHA and build["source"]["clean"] is True
assert build["source"]["tree_sha"] == "b5dd17e0cefef31dfe8af961e5a22b851be53cb7"
for role in ("runtime", "control"):
    original = root / build["control_reuse"][f"{role}_input"]
    assert hashlib.sha256(original.read_bytes()).hexdigest() == build["control_reuse"][f"{role}_provenance_sha256"]
assert build["artifacts"]["zmosh-udp"]["sha256"] == "de1e96e5ef57df173db266747eb18b8bce6911952410d298f236ab9c1e7fa162"
assert build["everudp_build"]["cargo_features"] == ["cli", "reliable-datagram-spike", "floor-single-owner"]
assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
cells = {}
for loss, seed_base in ((0, 1000700), (5, 1005700)):
    samples = {mode: {name: [] for name in ("everudp-floor", "zmosh-udp")} for mode in ("off", "on")}
    reports, stage_rows, calibration = {}, [], []
    for block in (1, 2, 3, 4):
        directory = root / f"loss{loss}-block{block}"
        mode = "off" if block in (1, 4) else "on"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["source"] == {"head_sha": "d1e27dffc632949ad54ba31426e94e5d778bf981", "tree_sha": "652565f0d714f9aad8307e23b740679008db13a2", "dirty": False}
        assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
        seed = seed_base + block
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["order"] == (["everudp-floor", "zmosh-udp"] if block in (1, 3) else ["zmosh-udp", "everudp-floor"])
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["diagnostic_tracing"] is (mode == "on")
        assert manifest["native_stage_tracing"] is False
        assert manifest["reactor_work_tracing"] is (mode == "on")
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
            trace_path = directory / name / "reactor-work-trace.json"
            if name == "everudp-floor":
                assert trace_path.exists() is (mode == "on")
                if mode == "on":
                    trace = json.loads(trace_path.read_text())
                    report = analyze(result, trace)
                    assert report["status"] == "DIAGNOSTIC", report
                    stage_rows.extend(report["initial_post_offer_pairs"])
                    calibration.extend(trace["cpu_clock_calibration_ns"])
                    reports[directory.name] = {key: value for key, value in report.items() if key not in ("rows", "initial_post_offer_pairs")}
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
        "pooled_step_medians_ns": {phase: {clock: median(row[phase]["duration_ns"][clock] for row in stage_rows)
                                           for clock in ("wall", "thread_cpu")} for phase in ("initial_post_offer", "following_loop_top")},
        "following_top_nonidle_observations": sum(
            any(row["following_loop_top"][key] for key in ("send_attempts", "receive_batches", "receive_datagrams", "retained_gro_segments_delivered", "events_drained", "timer_due", "application_ready"))
            or any(row["following_loop_top"]["pump"].values()) for row in stage_rows),
        "cpu_clock_pair_calibration_ns": {"min": min(calibration), "median": median(calibration), "max": max(calibration)},
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                  "production_actor_integration_authorized": False,
                  "bootstrap": {"resamples": 20000, "block_stratified": True,
                                "caveat": "Within-block resampling, not independent experiment replications or causal overhead certainty."},
                  "cells": cells}, indent=2, sort_keys=True))
