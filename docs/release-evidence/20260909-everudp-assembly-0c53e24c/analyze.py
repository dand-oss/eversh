"""Reproduce exact packet assembly phases; never a qualification receipt."""
import hashlib
import json
from pathlib import Path
from statistics import median
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from analyze_packet_protection import analyze_directory
from stream_floor_blocks import public_samples
from stream_floor_evidence import sealed
from validate_packet_trace import load

sha = "0c53e24cf18e68e910ace90daf7433be7a95aeb6"
build_file = root / "build-provenance.json"
build = load(build_file)
assert build["source"]["head_sha"] == sha and build["source"]["clean"] is True
assert build["everudp_build"]["cargo_features"] == [
    "cli", "path-packet-diagnostics", "application-task-spike",
    "stream-delivery-spike", "quic-ack-threshold-spike"]
capture = root / "capture"
sealed(capture)
manifest = load(capture / "manifest.json")
assert manifest["source"]["head_sha"] == sha and manifest["source"]["dirty"] is False
assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_file.read_bytes()).hexdigest()
assert manifest["order"] == ["everudp", "zmosh-udp", "zmosh-quic"]
assert manifest["seeds"] == {"client": 213200001, "server": 214200004}
assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
assert manifest["loss_percent_each_direction"] == 0
assert all(manifest[key] is True for key in (
    "production_path_tracing", "production_io_tracing", "production_packet_tracing"))
for name in manifest["order"]:
    result = load(capture / name / "result.json")
    public_samples(result)
    assert result["trials"] == 200 and result["transcript_failures"] == 0
report = analyze_directory(capture / "everudp", assembly=True)
assert report["status"] == "DIAGNOSTIC" and len(report["rows"]) == 200
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False,
    "joined_operations": 200, "median_us": {
        direction: {key: median(row[direction][key] for row in report["rows"]) / 1000
                    for key in report["rows"][0][direction]}
        for direction in ("input", "output")}}, indent=2, sort_keys=True))
