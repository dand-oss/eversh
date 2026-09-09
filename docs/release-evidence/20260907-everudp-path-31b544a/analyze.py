"""Frozen trace-overhead and path attribution; never production qualification."""
import hashlib
import json
import math
from pathlib import Path
import random
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "support"))
from analyze_path_trace import analyze
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHA = "31b544a8e33b06ff8563410935a6ecc4c578dbe0"
TREE = "200806e0bb552c64a56732c533c13a731163050f"
NAMES = ("everudp", "zmosh-udp", "zmosh-quic")
MODES = ("off", "on")
ITERATIONS = 20000


def load(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def q(values, fraction):
    return sorted(values)[math.ceil(fraction * len(values)) - 1]


build = load(ROOT / "build.json")
assert build["source"] == {"head_sha": SHA, "tree_sha": TREE, "clean": True}
assert build["everudp_build"]["cargo_features"] == ["cli", "path-diagnostics"]
origins = {}
for name in ("control", "runtime"):
    path = ROOT / "provenance-inputs" / f"{name}.json"
    assert digest(path) == build["control_reuse"][f"{name}_provenance_sha256"]
    origins[name] = load(path)
assert origins["runtime"]["source"] == build["source"]
assert origins["runtime"]["everudp_build"] == build["everudp_build"]
assert origins["runtime"]["artifact"] == build["artifacts"]["everudp"]
assert digest(ROOT / "logs/everudp-build.log") == origins["runtime"]["build_log"]["sha256"]
for name in NAMES[1:] + ("pty-bench", "pty-echo", "zmosh-quic-bridge"):
    assert build["artifacts"][name] == origins["control"]["artifacts"][name]
assert build["zmosh_sources"] == origins["control"]["zmosh_sources"]
assert build["zmosh_sources"]["udp"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
assert build["zmosh_sources"]["quic"]["commit"] == "21db4a4de6040b254531f2131b6f1c0cd146a7a1"

cells = {}
for loss in (0, 5):
    grouped = {mode: [] for mode in MODES}
    intervals = {name: [] for name in (
        "public_to_queue", "queue_to_stream", "stream_to_gateway", "gateway_input_sink",
        "pty_response", "gateway_to_client", "client_output_sink", "public_after_client_marker")}
    for index, mode in enumerate(("off", "on", "on", "off"), 1):
        directory = ROOT / f"loss{loss}-block{index}"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        manifest = load(directory / "manifest.json")
        assert manifest["source"] == {"head_sha": SHA, "tree_sha": TREE, "dirty": False}
        assert manifest["build"]["provenance_sha256"] == digest(ROOT / "build.json")
        assert manifest["order"] == (list(NAMES) if index in (1, 3) else list(reversed(NAMES)))
        seed = 1061700 + loss * 1000 + index
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["affinity"] == "40,42,44,46" and manifest["loss_percent_each_direction"] == loss
        assert manifest["diagnostic_tracing"] is (mode == "on")
        assert manifest["production_path_tracing"] is (mode == "on")
        for flag in ("native_stage_tracing", "reactor_work_tracing", "reactor_partition_tracing"):
            assert manifest[flag] is False
        pinned = directory / "governors-pinned.txt"
        assert digest(pinned) == manifest["governors"]["pinned"]["sha256"]
        assert pinned.read_text().splitlines() == [f"cpu{cpu} performance" for cpu in (40, 42, 44, 46)]
        for name, artifact in manifest["artifacts"].items():
            assert artifact["sha256"] == build["artifacts"][name]["sha256"]
        samples = {}
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
            assert accounting.total_attempts == manifest["loss_evidence"][name]["summed_egress_attempt_delta"] > 0
            if loss:
                assert accounting.client.dropped_packets > 0 and accounting.server.dropped_packets > 0
            samples[name] = result["samples_us"]
        grouped[mode].append(samples)
        if mode == "on":
            base = directory / "everudp"
            result = load(base / "result.json")
            report = analyze(load(base / "client-path-trace.json"), load(base / "gateway-path-trace.json"), result)
            assert report == load(base / "path-analysis.json") and len(report["rows"]) == 200
            for row, boundary in zip(report["rows"], result["public_boundaries"]):
                i, o = row["input"], row["output"]
                stamps = [boundary["send_ns"], i["queued_ns"], i["written_ns"][0], i["prepared_ns"][0],
                          i["accepted_ns"], o["gateway_queued_ns"], o["staged_ns"], o["accepted_ns"], boundary["accepted_ns"]]
                for name, left, right in zip(intervals, stamps, stamps[1:]):
                    intervals[name].append(right - left)

    def summarize(data):
        return {mode: {name: {label: q([v for block in blocks for v in block[name]], fraction)
                for label, fraction in (("p50", .5), ("p95", .95))} for name in NAMES}
                for mode, blocks in data.items()}

    point = summarize(grouped)
    rng = random.Random(1071700 + loss)
    distributions = {name: {label: [] for label in ("p50", "p95")} for name in NAMES}
    for _ in range(ITERATIONS):
        sample = summarize({mode: [{name: rng.choices(block[name], k=200) for name in NAMES}
                            for block in blocks] for mode, blocks in grouped.items()})
        for name in NAMES:
            for label in ("p50", "p95"):
                distributions[name][label].append(sample["on"][name][label] / sample["off"][name][label])
    cells[str(loss)] = {
        "samples_per_name_per_mode": 400, "latency_us": point,
        "on_off": {name: {label: {
            "ratio": point["on"][name][label] / point["off"][name][label],
            "central95": [q(distributions[name][label], .025), q(distributions[name][label], .975)]}
            for label in ("p50", "p95")} for name in NAMES},
        "interval_ns": {name: {"p50": q(v, .5), "p95": q(v, .95), "negative": sum(x < 0 for x in v)}
                        for name, v in intervals.items()},
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False, "source_sha": SHA,
    "tree_sha": TREE, "resamples": ITERATIONS, "cells": cells,
    "method": "Nearest-rank quantiles; independent resampling within each fixed block; central95 on/off intervals.",
    "caveat": "Within-block resampling is not independent replication. Feature-enabled OFF is not the default build. Signed userspace intervals are not exclusive CPU/kernel/network costs; do not sum stage medians."}, indent=2, sort_keys=True))
