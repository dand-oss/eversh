"""Reproduce ACK-policy screening; this is not release qualification."""
import hashlib
import json
import math
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples

names = ("everudp", "zmosh-udp", "zmosh-quic")
builds = {mode: json.loads((root / "builds" / mode / "provenance.json").read_text())
          for mode in "AB"}
expected = "9dc0c0e9f38b660a0efbe7f694e8e8c648415e3a"
features = ["cli", "application-task-spike", "stream-delivery-spike"]
assert builds["A"]["source"] == builds["B"]["source"]
assert builds["A"]["source"]["head_sha"] == expected
assert builds["A"]["source"]["clean"] is True
assert builds["A"]["everudp_build"]["cargo_features"] == features
assert builds["B"]["everudp_build"]["cargo_features"] == features + ["quic-ack-coalescing-spike"]
for name in ("pty-bench", "pty-echo", "zmosh-udp", "zmosh-quic", "zmosh-quic-bridge"):
    assert builds["A"]["artifacts"][name] == builds["B"]["artifacts"][name]
assert hashlib.sha256((root / "measurement/frozen-schedule.sh").read_bytes()).hexdigest() == (
    "330f3be76783a7b0c06383f78ef84d76f154f4d44b228328f46e2072543fd5d7")
orders = (list(names), [names[2], names[0], names[1]],
          [names[1], names[2], names[0]], [names[0], names[2], names[1]])


def quantiles(samples):
    ordered = sorted(samples)
    return [ordered[math.ceil(q * len(ordered)) - 1] for q in (.5, .95)]


blocks, pooled = [], []
for cell, loss in enumerate((0, 5)):
    pools = {mode: {name: [] for name in names} for mode in "AB"}
    attempts = {mode: {name: 0 for name in names} for mode in "AB"}
    for index, mode in enumerate("ABBA"):
        directory = root / "measurement" / f"loss{loss}-block{index}-{mode}"
        sealed(directory)
        manifest = json.loads((directory / "manifest.json").read_text())
        assert manifest["source"]["head_sha"] == expected
        assert manifest["source"]["dirty"] is False
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["affinity"] == "40,42,44,46"
        assert manifest["gap_ms"] == 100
        for flag in ("diagnostic_tracing", "production_io_tracing",
                     "production_packet_tracing", "production_path_tracing"):
            assert manifest[flag] is False
        assert manifest["seeds"]["client"] == 212600001 + cell * 100 + index
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
            count = manifest["loss_evidence"][name]["summed_egress_attempt_delta"]
            attempts[mode][name] += count
            values[name] = {"p50_p95_us": quantiles(result["samples_us"]),
                            "egress_attempts": count}
        blocks.append({"loss_percent": loss, "block": index, "mode": mode, "values": values})
    for mode in "AB":
        pooled.append({"loss_percent": loss, "mode": mode, "values": {
            name: {"p50_p95_us": quantiles(samples), "observations": len(samples),
                   "egress_attempts_per_echo": attempts[mode][name] / len(samples)}
            for name, samples in pools[mode].items()}})
print(json.dumps({"status": "NOT_ADOPTED", "qualification": False,
                  "blocks": blocks, "pooled": pooled}, indent=2, sort_keys=True))
