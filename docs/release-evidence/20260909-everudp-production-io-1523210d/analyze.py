"""Validate bounded, external production-client diagnostics; not qualification."""
import hashlib
import json
from pathlib import Path
import sys
from collections import Counter

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from io_trial_windows import analyze_client
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples

runtime = "4221bc1497a4fa0b1cfcbd688b47bd77785ebb55"
harness = "1523210d5a017fcdd6a1cf88ce2b4b9766e284a3"
build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
assert build["source"]["head_sha"] == runtime and build["source"]["clean"] is True
assert build["everudp_build"]["cargo_features"] == [
    "cli", "application-task-spike", "stream-delivery-spike", "quic-ack-threshold-spike"]
events = [f"syscalls:sys_{edge}_{call}" for call in
          ("poll", "read", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "sendto", "recvfrom")
          for edge in ("enter", "exit")] + ["raw_syscalls:sys_enter", "raw_syscalls:sys_exit"]
reports = []
for direction, seed in (("forward", 213000001), ("reverse", 213000002)):
    directory = root / direction
    receipt = json.loads((directory / "receipt.json").read_text())
    assert receipt["status"] == "DIAGNOSTIC_COMPLETE"
    assert receipt["source_build"] == build["source"] and receipt["harness_head"] == harness
    assert receipt["seed"] == seed and receipt["loss"] == 0
    assert receipt["production_clients"] and receipt["io"] and receipt["raw_perf_private"]
    measurement = directory / "measurement"
    sealed(measurement)
    manifest = json.loads((measurement / "manifest.json").read_text())
    order = ["everudp", "zmosh-udp", "zmosh-quic"]
    if direction == "reverse":
        order.reverse()
    assert manifest["order"] == receipt["order"] == order
    assert manifest["source"]["head_sha"] == harness and manifest["source"]["dirty"] is False
    assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
    assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
    assert manifest["loss_percent_each_direction"] == 0
    assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
    for name in order:
        result = json.loads((measurement / name / "result.json").read_text())
        public_samples(result)
        assert result["trials"] == 200 and result["transcript_failures"] == 0
        if name == "zmosh-quic":
            continue
        target = directory / (name + "-client")
        capture = json.loads((target / "capture.json").read_text())
        assert capture["source_build"] == build["source"] and capture["harness_head"] == harness
        assert capture["events_file"] == "io-events.json" and capture["duration_seconds"] == 10
        assert capture["identity"]["affinity"] == [40, 42, 44, 46]
        pid = capture["identity"]["pid"]
        command = capture["command"]
        assert [command[i + 1] for i, v in enumerate(command) if v == "-e"] == events
        assert [command[i + 1] for i, v in enumerate(command) if v == "--filter"] == (
            [f"common_pid == {pid}"] * 16 + [f"common_pid == {pid} && id == 1"] * 2)
        attrs = (target / "events-attributes.txt").read_text().splitlines()
        assert all(line.startswith(("syscalls:", "raw_syscalls:", "dummy:u", "# Tip:")) for line in attrs)
        attrs = [line for line in attrs if line.startswith(("syscalls:", "raw_syscalls:"))]
        assert [line.split(": type:", 1)[0] for line in attrs] == events
        assert all("use_clockid: 1" in line and "clockid: 1" in line for line in attrs)
        assert all("LOST" not in (target / name).read_text().upper() for name in ("record.log", "decode.log"))
        export = json.loads((target / "io-events.json").read_text())
        report = analyze_client(result, export, capture)
        assert report["status"] == "DIAGNOSTIC" and report["included_trials"] >= 80, report
        assert len(report["rows"]) == 200
        exclusions = Counter(row["exclusion"] for row in report["rows"] if row["status"] != "included")
        assert set(exclusions) <= {"outside_capture_coverage"}, exclusions
        reports.append({"direction": direction, "candidate": name, "exclusions": dict(exclusions),
                        "terminal_fds": capture["terminal_fds"], "analysis": report})
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False, "reports": reports}, indent=2))
