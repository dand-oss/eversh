"""Verify and summarize instruction-weighted samples; not CPU-time attribution."""
from bisect import bisect_right
from collections import Counter
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "crates/everudp/tests/net"))
from instruction_capture import validate_attributes


def read(path):
    return json.loads(path.read_text())


def main():
    build_path = ROOT / "build-provenance.json"
    build = read(build_path)
    rows = []
    for index in (0, 1):
        root = ROOT / f"block{index}"
        subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"],
                       cwd=root / "measurement", check=True)
        report = read(root / "capture.json")
        manifest = read(root / "measurement/manifest.json")
        assert report["status"] == "CAPTURED" and report["benchmark_exit_code"] == 0
        assert report["diagnostic_only"] and not report["qualification"]
        assert report["mode"] == "instruction-leaves"
        assert report["harness_sha"] == "f6ad8cb4e6be6ea7a53181542279118b7e680067"
        assert report["runtime_sha"] == build["source"]["head_sha"] == "f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c"
        assert report["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
        assert manifest["diagnostic_tracing"] and manifest["hardware_counter_capture"]
        assert manifest["loss_percent_each_direction"] == 0 and manifest["gap_ms"] == 100
        assert manifest["seeds"] == {"client": 215000001 + index, "server": 216000004 + index}
        order = ["everudp", "zmosh-udp", "zmosh-quic"]
        if index:
            order.reverse()
        assert report["order"] == manifest["order"] == order
        for name in order:
            result = read(root / "measurement" / name / "result.json")
            assert result["trials"] == len(result["samples_us"]) == 200
            assert result["transcript_failures"] == 0
            assert manifest["artifacts"][name]["sha256"] == build["artifacts"][name]["sha256"]
            if name == "zmosh-quic":
                continue
            client = report["clients"][name]
            capture = client["capture"]
            assert client["before"] == client["after"]
            pid = client["before"]["pid"]
            assert client["before"]["tids"] == [pid]
            assert client["before"]["affinity"] == [40, 42, 44, 46]
            assert client["binary_sha256"] == build["artifacts"][name]["sha256"]
            validate_attributes((root / f"{name}-counters/event-attributes.txt").read_text())
            assert capture["period"] == 10000
            start, stop = capture["control"]
            assert start["operation"] == "enable" and stop["operation"] == "disable"
            boundaries = result["public_boundaries"]
            starts = [b["send_ns"] for b in boundaries]
            assert len(boundaries) == 200
            for i, boundary in enumerate(boundaries):
                assert boundary["trial"] == i
                assert boundary["send_ns"] < boundary["accepted_ns"]
                if i:
                    assert boundaries[i - 1]["accepted_ns"] < boundary["send_ns"]
            assert start["sent_ns"] <= start["acknowledged_ns"] < starts[0]
            assert boundaries[-1]["accepted_ns"] < stop["sent_ns"] <= stop["acknowledged_ns"]
            histograms = {key: Counter() for key in ("all", "inside", "outside")}
            previous = start["sent_ns"]
            for sample in capture["samples"]:
                assert set(sample) == {"pid", "tid", "time_ns", "event", "symbol"}
                assert sample["pid"] == sample["tid"] == pid and sample["event"] == "instructions:u"
                timestamp = sample["time_ns"]
                assert previous <= timestamp <= stop["acknowledged_ns"]
                previous = timestamp
                trial = bisect_right(starts, timestamp) - 1
                location = "inside" if trial >= 0 and timestamp <= boundaries[trial]["accepted_ns"] else "outside"
                histograms["all"][sample["symbol"]] += 1
                histograms[location][sample["symbol"]] += 1
            assert histograms["all"]
            rows.append({"block": index, "client": name,
                         "sample_counts": {k: sum(v.values()) for k, v in histograms.items()},
                         "leaves": {k: v.most_common() for k, v in histograms.items()}})
    print(json.dumps({"diagnostic_only": True, "qualification": False, "rows": rows}, indent=2))


if __name__ == "__main__":
    main()
