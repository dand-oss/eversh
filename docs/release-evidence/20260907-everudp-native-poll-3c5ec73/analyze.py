"""Reproduce descriptive polling cost; never grant optimization/ship authority."""
import hashlib
import json
import math
from pathlib import Path
import random
import statistics
import subprocess
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "support"))
from analyze_poll_turns import analyze
from poll_interval_union import combine

build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
assert build["source"]["head_sha"] == "a9321d0060cc726b27fcde89ca7d31e9519c5425"
assert build["everudp_build"]["cargo_features"] == ["cli", "reliable-datagram-spike", "floor-single-owner"]
assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
cells = {}
for loss, seed in ((0, 940701), (5, 945701)):
    directory = root / f"loss{loss}"
    receipt = json.loads((directory / "receipt.json").read_text())
    assert receipt["status"] == "DIAGNOSTIC_COMPLETE"
    assert receipt["source_build"] == build["source"]
    assert receipt["seed"] == seed and receipt["loss"] == loss
    subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=directory / "measurement", check=True)
    manifest = json.loads((directory / "measurement/manifest.json").read_text())
    assert manifest["seeds"]["client"] == seed
    assert manifest["loss_percent_each_direction"] == loss
    assert manifest["source"]["dirty"] is False
    assert manifest["source"]["head_sha"] == receipt["harness_head"]
    assert manifest["order"] == (["everudp-floor", "zmosh-udp"] if loss == 0 else ["zmosh-udp", "everudp-floor"])
    assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
    reports = {}
    results = {}
    for name, role in (("everudp-floor", "client"), ("everudp-floor", "server"), ("zmosh-udp", "client")):
        target = directory / f"{name}-{role}"
        capture = json.loads((target / "capture.json").read_text())
        result = json.loads((directory / "measurement" / name / "result.json").read_text())
        identity = capture["identity"]
        assert capture["source_build"] == build["source"] and capture["harness_head"] == receipt["harness_head"]
        assert identity["boot_id"] == result["clock_identity"]["boot_id"]
        assert identity["time_namespace"] == [result["clock_identity"]["time_namespace_dev"], result["clock_identity"]["time_namespace_ino"]]
        assert identity["tids"] == [identity["pid"]]
        command = capture["command"]
        assert [command[i + 1] for i, value in enumerate(command) if value == "--filter"] == [f"common_pid == {identity['pid']}"] * 4
        attributes = [line for line in (target / "events-attributes.txt").read_text().splitlines() if line.startswith("syscalls:")]
        assert len(attributes) == 4 and all("use_clockid: 1" in line and "clockid: 1" in line for line in attributes)
        text = (target / "events.txt").read_text()
        assert "LOST" not in text.upper() and "buf:" not in text and "ufds:" not in text
        assert result["trials"] == 200 and result["transcript_failures"] == 0
        report = analyze(result, text, identity["pid"])
        assert report["status"] == "DIAGNOSTIC", report
        reports[target.name] = report
        results[name] = result
    union = combine(results["everudp-floor"], reports["everudp-floor-client"], reports["everudp-floor-server"])
    assert union["status"] == "DIAGNOSTIC", union
    values = [row["union_ns"] for row in union["rows"] if row["status"] == "included"]
    assert values
    rng = random.Random(949000 + loss)
    bootstrap = sorted(statistics.median(rng.choices(values, k=len(values))) for _ in range(20000))
    cells[str(loss)] = {
        "reports": reports, "matched_union": union,
        "descriptive_median_union_upper95_ns": bootstrap[math.ceil(.95 * len(bootstrap)) - 1],
        "bootstrap_caveat": "Within-capture trial resampling only; not independent runs or causal savings uncertainty.",
    }
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
    "production_actor_integration_authorized": False, "cells": cells}, indent=2, sort_keys=True))
