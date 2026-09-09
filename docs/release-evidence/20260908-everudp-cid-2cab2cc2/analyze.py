"""Reproduce bounded CID experiment; never qualification."""
import json
import math
from pathlib import Path
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples

names = ("everudp", "zmosh-udp", "zmosh-quic")
pools = {mode: {name: [] for name in names} for mode in ("A", "B")}
builds = {mode: json.loads((root / "builds" / mode / "provenance.json").read_text())
          for mode in pools}
assert builds["A"]["source"] == builds["B"]["source"]
assert builds["A"]["source"]["head_sha"].startswith("2cab2cc2")
assert builds["A"]["source"]["clean"] is True
for name in ("pty-bench", "pty-echo", "zmosh-udp", "zmosh-quic", "zmosh-quic-bridge"):
    assert builds["A"]["artifacts"][name] == builds["B"]["artifacts"][name]
orders = (list(names), [names[2], names[0], names[1]],
          [names[1], names[2], names[0]], [names[0], names[2], names[1]])

def quantiles(samples):
    ordered = sorted(samples)
    return [ordered[math.ceil(q * len(ordered)) - 1] for q in (.5, .95)]

blocks = []
for index, mode in enumerate(("A", "B", "B", "A")):
    directory = root / "measurement" / f"block{index}-{mode}"
    sealed(directory)
    manifest = json.loads((directory / "manifest.json").read_text())
    assert manifest["source"]["head_sha"] == builds[mode]["source"]["head_sha"]
    assert manifest["seeds"]["client"] == 212500001 + index
    assert manifest["order"] == orders[index]
    values = {}
    for name in names:
        result = json.loads((directory / name / "result.json").read_text())
        public_samples(result)
        assert result["trials"] == 200 and result["transcript_failures"] == 0
        assert len(result["samples_us"]) == 200
        pools[mode][name].extend(result["samples_us"])
        values[name] = quantiles(result["samples_us"])
    blocks.append({"block": index, "mode": mode, "p50_p95_us": values})
print(json.dumps({"status": "NOT_ADOPTED", "qualification": False, "blocks": blocks,
                  "pooled": {mode: {name: quantiles(samples) for name, samples in data.items()}
                             for mode, data in pools.items()}}, indent=2, sort_keys=True))
