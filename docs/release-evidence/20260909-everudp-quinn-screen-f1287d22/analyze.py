"""Verify and reproduce the frozen engine screen; not qualification."""
import hashlib
import json
import math
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples

expected = "f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c"
names = ("everudp", "zmosh-udp", "zmosh-quic")
builds = {mode: json.loads((root / "builds" / mode / "provenance.json").read_text())
          for mode in "AB"}
assert builds["A"]["source"] == builds["B"]["source"]
assert builds["A"]["source"]["head_sha"] == expected
assert builds["A"]["source"]["clean"] is True
for mode, engine, manifest, package in (
    ("A", "noq", "Cargo.toml", "everudp"),
    ("B", "quinn-eval", "spikes/everudp-quinn-eval/Cargo.toml", "everudp-quinn-eval"),
):
    build = builds[mode]["everudp_build"]
    assert build["engine"] == engine and build["manifest"] == manifest
    assert build["package"] == package and build["cargo_features"] == ["cli"]
    assert build["profile"] == builds["A"]["everudp_build"]["profile"]
    assert build["profile"]["lto"] == "fat" and build["profile"]["codegen_units"] == 1
    assert builds[mode]["isolation"]["sealed_control_reuse"] is True
assert builds["B"]["everudp_build"]["pinned_dependencies"]["quinn"]["version"] == "0.11.11"
assert builds["B"]["everudp_build"]["pinned_dependencies"]["quinn-proto"]["version"] == "0.11.15"
for name in ("pty-bench", "pty-echo", "zmosh-udp", "zmosh-quic", "zmosh-quic-bridge"):
    assert builds["A"]["artifacts"][name] == builds["B"]["artifacts"][name]
assert hashlib.sha256((root / "measurement/frozen-schedule.sh").read_bytes()).hexdigest() == (
    "cbc84101ac169be5e26dddb96221e0ea06a10c8f336afc04b6a4201b2b4e2eb1")
orders = (list(names), [names[2], names[0], names[1]],
          [names[1], names[2], names[0]], [names[0], names[2], names[1]])


def quantiles(samples):
    ordered = sorted(samples)
    return [ordered[math.ceil(q * len(ordered)) - 1] for q in (.5, .95)]


blocks, pooled = [], []
for cell, loss in enumerate((0, 5)):
    pools = {mode: {name: [] for name in names} for mode in "AB"}
    for index, mode in enumerate("ABBA"):
        directory = root / "measurement" / f"loss{loss}-block{index}-{mode}"
        sealed(directory)
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["source"]["head_sha"] == expected
        assert manifest["source"]["dirty"] is False
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
        for flag in ("diagnostic_tracing", "production_io_tracing",
                     "production_packet_tracing", "production_path_tracing"):
            assert manifest[flag] is False
        assert manifest["seeds"]["client"] == 213400001 + cell * 100 + index
        assert manifest["order"] == orders[index]
        assert manifest["build"]["provenance_sha256"] == hashlib.sha256(
            (root / "builds" / mode / "provenance.json").read_bytes()).hexdigest()
        values = {}
        for name in names:
            result = json.loads((directory / name / "result.json").read_text())
            public_samples(result)
            assert result["trials"] == 200 and result["transcript_failures"] == 0
            assert len(result["samples_us"]) == 200
            pools[mode][name].extend(result["samples_us"])
            values[name] = quantiles(result["samples_us"])
        blocks.append({"loss_percent": loss, "block": index, "mode": mode, "p50_p95_us": values})
    for mode in "AB":
        values = {name: quantiles(samples) for name, samples in pools[mode].items()}
        pooled.append({"loss_percent": loss, "mode": mode, "observations_each": 400,
                       "p50_p95_us": values,
                       "udp_p50_ratio": values["everudp"][0] / values["zmosh-udp"][0]})
print(json.dumps({"status": "SCREENING_ONLY", "qualification": False,
                  "blocks": blocks, "pooled": pooled}, indent=2, sort_keys=True))
