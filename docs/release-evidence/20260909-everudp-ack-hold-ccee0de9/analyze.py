"""Frozen packet-count cutoff only; never performance qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ARCHIVE = Path(__file__).resolve().parent
ROOT = ARCHIVE / "measurement"
sys.path.insert(0, str(ARCHIVE.parents[2] / "crates/everudp/tests/net"))
from packet_accounting import account_packet_attempts
from stream_floor_blocks import public_samples

SHA = "ccee0de938a043a90795a21c27ae9f5c4b9d3985"
RUNNER = "5848468d86380337067a21bd0acf8b8dce0549ba1dae824b9287b1e5e3fed0ee"
NAMES = ["everudp", "zmosh-udp", "zmosh-quic"]
ORDERS = [NAMES, ["zmosh-quic", "everudp", "zmosh-udp"],
          ["zmosh-udp", "zmosh-quic", "everudp"], ["everudp", "zmosh-quic", "zmosh-udp"]]


def read(path):
    return json.loads(path.read_text())


def packet_cutoff(a, b):
    if len(a) != 2 or len(b) != 2 or any(type(n) is not int or n <= 0 for n in a + b):
        raise ValueError("two positive integer counts per mode required")
    return all(200 * n <= 85 * sum(a) for n in b)


def main():
    assert (ROOT / "exit-status").read_text().strip() == "0"
    assert hashlib.sha256((ROOT / "frozen-schedule.sh").read_bytes()).hexdigest() == RUNNER
    builds = {mode: read(ROOT / f"{mode}-build.json") for mode in "AB"}
    assert builds["A"]["everudp_build"]["profile"] == builds["B"]["everudp_build"]["profile"]
    for mode, build in builds.items():
        assert build["source"]["head_sha"] == SHA and build["source"]["clean"]
        expected = ["cli"] + (["input-ack-hold-spike"] if mode == "B" else [])
        assert build["everudp_build"]["cargo_features"] == expected
        assert build["everudp_build"]["engine"] == "noq"
        assert build["everudp_build"]["profile"]["lto"] == "fat"
        assert build["everudp_build"]["profile"]["codegen_units"] == 1
        assert build["isolation"]["sealed_control_reuse"]
    for name in (*NAMES[1:], "zmosh-quic-bridge", "pty-bench", "pty-echo"):
        assert builds["A"]["artifacts"][name]["sha256"] == builds["B"]["artifacts"][name]["sha256"]
    rows, counts = [], {"A": [], "B": []}
    for index, mode in enumerate("ABBA"):
        root = ROOT / f"block{index}-{mode}"
        subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=root, check=True)
        manifest = read(root / "manifest.json")
        assert manifest["source"]["head_sha"] == SHA and not manifest["source"]["dirty"]
        assert manifest["trials_per_candidate"] == 200 and manifest["order"] == ORDERS[index]
        assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
        assert manifest["loss_percent_each_direction"] == 0
        assert manifest["seeds"] == {"client": 219000001 + index, "server": 220000004 + index}
        assert not manifest["diagnostic_tracing"] and not manifest["hardware_counter_capture"]
        packets = {}
        for name in NAMES:
            assert manifest["artifacts"][name]["sha256"] == builds[mode]["artifacts"][name]["sha256"]
            result = read(root / name / "result.json")
            public_samples(result)
            receipts = [root / f"netem-{name}-{side}-{phase}.txt"
                        for side in ("client", "server") for phase in ("before", "after")]
            accounting = account_packet_attempts(*(path.read_text() for path in receipts))
            packets[name] = accounting.total_attempts
            assert accounting.client.dropped_packets == accounting.server.dropped_packets == 0
            assert packets[name] == manifest["loss_evidence"][name]["summed_egress_attempt_delta"]
            before = read(root / name / "host-before.json")
            after = read(root / name / "host-after.json")
            assert before["end_monotonic_ns"] < result["public_boundaries"][0]["send_ns"]
            assert after["begin_monotonic_ns"] > result["public_boundaries"][-1]["accepted_ns"]
        counts[mode].append(packets["everudp"])
        rows.append({"block": index, "mode": mode, "packet_attempts": packets})
    passed = packet_cutoff(counts["A"], counts["B"])
    print(json.dumps({"status": "PACKET_CUTOFF_PASS" if passed else "STOP_NOT_ADOPTED",
                      "qualification": False, "blocks": rows,
                      "b_to_mean_a": [2 * n / sum(counts["A"]) for n in counts["B"]]}, indent=2))


if __name__ == "__main__":
    main()
