"""Reproduce bounded hardware-counter evidence; never latency qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "crates/everudp/tests/net"))
from perf_counter_values import parse_counter_values


def read(path):
    return json.loads(path.read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    build = read(ROOT / "build-provenance.json")
    output = []
    for block in (0, 1):
        root = ROOT / f"block{block}"
        subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"],
                       cwd=root / "measurement", check=True)
        report = read(root / "capture.json")
        manifest = read(root / "measurement/manifest.json")
        assert report["status"] == "CAPTURED" and report["benchmark_exit_code"] == 0
        assert report["diagnostic_only"] and not report["qualification"]
        assert report["harness_sha"] == "7b40afd1e1b7d78ac8ae326781ba780f635bcd45"
        assert report["runtime_sha"] == build["source"]["head_sha"] == "f1287d22d4e0e7591d83792e1e2fb951ac7f9e8c"
        assert report["provenance_sha256"] == digest(ROOT / "build-provenance.json")
        assert manifest["diagnostic_tracing"] and manifest["hardware_counter_capture"]
        assert manifest["loss_percent_each_direction"] == 0 and manifest["gap_ms"] == 100
        assert manifest["seeds"]["client"] == 214000001 + block
        assert manifest["seeds"]["server"] == 215000004 + block
        expected = ["everudp", "zmosh-udp", "zmosh-quic"]
        if block:
            expected.reverse()
        assert report["order"] == manifest["order"] == expected
        values = {}
        for name in expected:
            result = read(root / "measurement" / name / "result.json")
            assert result["trials"] == len(result["samples_us"]) == 200
            assert result["transcript_failures"] == 0
            assert manifest["artifacts"][name]["sha256"] == build["artifacts"][name]["sha256"]
            if name == "zmosh-quic":
                continue
            client = report["clients"][name]
            assert client["before"] == client["after"]
            assert client["before"]["tids"] == [client["before"]["pid"]]
            assert client["before"]["affinity"] == [40, 42, 44, 46]
            assert client["binary_sha256"] == build["artifacts"][name]["sha256"]
            capture = client["capture"]
            start, stop = capture["control"]
            assert start["operation"] == "enable" and stop["operation"] == "disable"
            boundaries = result["public_boundaries"]
            assert len(boundaries) == 200
            assert start["sent_ns"] <= start["acknowledged_ns"] < boundaries[0]["send_ns"]
            assert boundaries[-1]["accepted_ns"] < stop["sent_ns"] <= stop["acknowledged_ns"]
            raw = parse_counter_values((root / f"{name}-counters/counters.jsonl").read_text(), grouped=True)
            assert raw == capture["values"]
            values[name] = raw
        output.append({"block": block, "values": values,
            "everudp_over_udp": {event: values["everudp"]["counts"][event] /
                values["zmosh-udp"]["counts"][event] for event in values["everudp"]["events"]}})
    print(json.dumps({"diagnostic_only": True, "qualification": False, "blocks": output}, indent=2))


if __name__ == "__main__":
    main()
