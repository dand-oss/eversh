"""Reproduce bounded I/O diagnostic evidence; never production qualification."""
import collections
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
from validate_io_trace import load, validate
from analyze_poll_turns import _sample_check
from clock_alignment import _validated_boundaries
from packet_accounting import account_packet_attempts

SHA = "25439e3596811694686874bfa2a50eb1cb3673a0"
TREE = "9084af9cdb5e277d2f28383b5540da2a6c554f59"
NAMES = ("everudp", "zmosh-udp", "zmosh-quic")
ITERATIONS = 20_000


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def q(values, fraction):
    return sorted(values)[math.ceil(len(values) * fraction) - 1]


def selected(events, stage, start, end):
    return [e for e in events if e["stage"] == stage and start <= e["time_ns"] <= end]


build = load(ROOT / "build.json")
assert build["source"] == {"head_sha": SHA, "tree_sha": TREE, "clean": True}
assert build["everudp_build"]["cargo_features"] == ["cli", "path-io-diagnostics"]
control = load(ROOT / build["control_reuse"]["provenance"])
runtime = load(ROOT / build["runtime_build"]["provenance"])
for key in ("control_reuse", "runtime_build"):
    assert digest(ROOT / build[key]["provenance"]) == build[key]["sha256"]
assert runtime["source"] == build["source"]
assert runtime["cargo_features"] == build["everudp_build"]["cargo_features"]
assert runtime["artifact_sha256"] == build["artifacts"]["everudp"]["sha256"]
for path, sha in runtime["logs"].items():
    assert digest(ROOT / path) == sha
for name in NAMES[1:] + ("pty-bench", "pty-echo", "zmosh-quic-bridge"):
    assert build["artifacts"][name] == control["artifacts"][name]
assert build["inputs"] == control["inputs"]
assert build["zmosh_sources"] == control["zmosh_sources"]
assert build["zmosh_sources"]["udp"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
assert build["zmosh_sources"]["quic"]["commit"] == "21db4a4de6040b254531f2131b6f1c0cd146a7a1"

cells = {}
for loss in (0, 5):
    grouped = {"off": [], "on": []}
    intervals = collections.defaultdict(list)
    readable_counts = collections.Counter()
    gateway_tx_counts = collections.Counter()
    for block, mode in enumerate(("off", "on", "on", "off"), 1):
        directory = ROOT / f"loss{loss}-block{block}"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory, check=True)
        manifest = load(directory / "manifest.json")
        assert manifest["source"] == {"head_sha": SHA, "tree_sha": TREE, "dirty": False}
        assert manifest["build"]["provenance_sha256"] == digest(ROOT / "build.json")
        assert manifest["order"] == (list(NAMES) if block in (1, 3) else list(reversed(NAMES)))
        seed = 1081700 + loss * 1000 + block
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["affinity"] == "40,42,44,46" and manifest["loss_percent_each_direction"] == loss
        assert manifest["diagnostic_tracing"] is True and manifest["production_path_tracing"] is True
        assert manifest["production_io_tracing"] is (mode == "on")
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
        base = directory / "everudp"
        client = load(base / "client-path-trace.json")
        gateway = load(base / "gateway-path-trace.json")
        report = analyze(client, gateway, load(base / "result.json"))
        assert report == load(base / "path-analysis.json") and len(report["rows"]) == 200
        if mode == "off":
            assert not any((base / f"{role}-path-trace.json.io.json").exists() for role in ("client", "gateway"))
            continue
        io = {}
        for role, paired in (("client", client), ("gateway", gateway)):
            sidecar = load(base / f"{role}-path-trace.json.io.json")
            assert validate(sidecar, paired, role) == load(base / f"{role}-io-validation.json")
            io[role] = sidecar["events"]
        for row in report["rows"]:
            i = row["input"]
            start, written, prepared = i["queued_ns"], i["written_ns"][0], i["prepared_ns"][0]
            # Production uses the first client uni stream (QUIC id 2) for input.
            reads = [e for e in selected(io["gateway"], "stream_readable", start, prepared) if e["stream"] == 2]
            readable_counts[len(reads)] += 1
            if len(reads) != 1:
                continue  # Report ambiguity counts; never drop latency observations.
            ready = reads[0]["time_ns"]
            intervals["stream_accept_to_readable"].append(ready - written)
            intervals["readable_to_prepared"].append(prepared - ready)
            rx = selected(io["gateway"], "udp_receive", start, ready)
            tx = selected(io["client"], "transmit_accepted", written, ready)
            if rx:
                intervals["latest_receive_marker_to_readable"].append(ready - rx[-1]["time_ns"])
                gateway_tx_counts[len(selected(io["gateway"], "transmit_accepted", rx[-1]["time_ns"], ready))] += 1
            if tx:
                intervals["stream_accept_to_first_transmit_accept"].append(tx[0]["time_ns"] - written)
            if rx and tx:
                intervals["first_transmit_accept_to_latest_receive_marker"].append(rx[-1]["time_ns"] - tx[0]["time_ns"])

    def summarize(data):
        return {mode: {name: {label: q([v for block in blocks for v in block[name]], fraction)
                for label, fraction in (("p50", .5), ("p95", .95))} for name in NAMES}
                for mode, blocks in data.items()}

    point = summarize(grouped)
    rng = random.Random(1091700 + loss)
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
        "readable_matches_per_row": dict(readable_counts),
        "gateway_transmit_markers_between_latest_receive_and_readable": dict(gateway_tx_counts),
        "interval_ns": {name: {"n": len(v), "p50": q(v, .5), "p95": q(v, .95),
            "negative": sum(x < 0 for x in v)} for name, v in intervals.items()},
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False, "source_sha": SHA,
    "tree_sha": TREE, "resamples": ITERATIONS, "cells": cells,
    "method": "Nearest-rank quantiles; independent resampling within fixed blocks; central95 ON/OFF bounds.",
    "caveat": "Both modes include path tracing and a diagnostic-feature build. Within-block resampling is not independent replication. I/O markers lack packet identities: selected nearest/first markers are descriptive boundaries, not causal packet pairs, exclusive CPU/crypto/kernel costs, or additive median components."}, indent=2, sort_keys=True))
