#!/usr/bin/env python3
"""Summarize already validated handoff intervals; not a qualification gate."""
import json
from pathlib import Path
from statistics import median

root = Path(__file__).resolve().parent
blocks = []
for loss, block in ((0, 1), (0, 2), (5, 1), (5, 2)):
    name = f"loss{loss}-block{block}-traced"
    report = json.loads((root / "analysis" / f"{name}.json").read_text())
    handoffs = report["local_handoffs"]
    assert report["status"] == handoffs["status"] == "DIAGNOSTIC"
    assert len(handoffs["rows"]) == 200
    row = {"block": name, "uncertainty_ns": handoffs["clock_alignment"]["uncertainty_ns"]}
    for field in ("input_handoff_ns", "output_handoff_ns"):
        row[field.replace("_ns", "_median_us")] = {
            bound: median(item[field][bound] for item in handoffs["rows"]) / 1000
            for bound in ("lower", "upper")
        }
    row["public_median_us"] = {}
    for candidate in ("everudp-floor", "zmosh-udp"):
        result = json.loads((root / "measurements" / name / candidate / "result.json").read_text())
        assert result["trials"] == 200 and result["transcript_failures"] == 0
        row["public_median_us"][candidate] = median(result["samples_us"])
    blocks.append(row)
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                  "integration_authorized": False, "blocks": blocks}, indent=2))
