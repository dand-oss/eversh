"""Reproduce pre-frame attribution from the already sealed assembly capture."""
import hashlib
import json
from pathlib import Path
from statistics import median
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / "crates/everudp/tests/net"))
from analyze_preframes import analyze_directory
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples
from validate_packet_trace import load

source = root.parent / "20260909-everudp-assembly-0c53e24c"
# Archive inventories use sha256sum's ./ prefix; capture inventories do not.
# Validate the prefix explicitly rather than relaxing the shared capture parser.
inventory = set()
for line in (source / "SHA256SUMS").read_text().splitlines():
    digest, name = line.split("  ", 1)
    assert name.startswith("./")
    name = name[2:]
    assert name and all(part not in ("", ".", "..") for part in name.split("/"))
    assert not Path(name).is_absolute() and name not in inventory
    inventory.add(name)
    assert hashlib.sha256((source / name).read_bytes()).hexdigest() == digest
assert inventory == {str(path.relative_to(source)) for path in source.rglob("*")
                     if path.is_file() and path != source / "SHA256SUMS"}
capture = source / "capture"
sealed(capture)
manifest = load(capture / "manifest.json")
assert manifest["source"]["head_sha"] == "0c53e24cf18e68e910ace90daf7433be7a95aeb6"
assert manifest["source"]["dirty"] is False
assert manifest["seeds"] == {"client": 213200001, "server": 214200004}
assert manifest["order"] == ["everudp", "zmosh-udp", "zmosh-quic"]
assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
assert manifest["loss_percent_each_direction"] == 0
assert all(manifest[key] is True for key in (
    "production_path_tracing", "production_io_tracing", "production_packet_tracing"))
assert manifest["build"]["provenance_sha256"] == hashlib.sha256(
    (source / "build-provenance.json").read_bytes()).hexdigest()
for candidate in manifest["order"]:
    result = load(capture / candidate / "result.json")
    public_samples(result)
    assert result["trials"] == 200 and result["transcript_failures"] == 0
report = analyze_directory(capture / "everudp")
assert report["status"] == "DIAGNOSTIC" and len(report["rows"]) == 200
keys = ("reservation_to_service_ns", "service_to_protocol_ns", "protocol_to_frames_ns")
print(json.dumps({"status": "DIAGNOSTIC", "qualification": False,
    "joined_rows": len(report["rows"]), "median_us": {
        direction: {key: median(row[direction]["preframes"][key]
                               for row in report["rows"]) / 1000 for key in keys}
        for direction in ("input", "output")}}, indent=2, sort_keys=True))
