"""Verify the frozen blocks and rerun the unchanged stage-zero analyzer."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from packet_accounting import account_packet_attempts

root = Path(__file__).resolve().parent
build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
expected_sha = "9b67a67a4834daea193af4e6a4270e6155dac048"
assert build["source"]["head_sha"] == expected_sha
assert build["source"]["clean"] is True
assert build["everudp_build"]["cargo_features"] == [
    "cli", "reliable-datagram-spike", "floor-single-owner"]
assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
paths = []
manifests = []
for loss, seeds in ((0, (950701, 950702)), (5, (955701, 955702))):
    for block, seed in enumerate(seeds, 1):
        path = root / f"loss{loss}-block{block}"
        subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=path, check=True)
        manifest = json.loads((path / "manifest.json").read_text())
        assert manifest["source"] == {
            "head_sha": expected_sha, "tree_sha": build["source"]["tree_sha"], "dirty": False}
        assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
        assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
        assert manifest["loss_percent_each_direction"] == loss
        assert manifest["trials_per_candidate"] == 200 and manifest["gap_ms"] == 100
        assert manifest["order"] == (["everudp-floor", "zmosh-udp"] if block == 1 else ["zmosh-udp", "everudp-floor"])
        for name in manifest["order"]:
            counters = account_packet_attempts(*(
                (path / f"netem-{name}-{direction}-{phase}.txt").read_text()
                for direction in ("client", "server") for phase in ("before", "after")))
            assert counters.total_attempts == manifest["loss_evidence"][name]["summed_egress_attempt_delta"]
            if loss:
                assert counters.client.dropped_packets > 0 and counters.server.dropped_packets > 0
        paths.append(path)
        manifests.append(manifest)

source = (root / "analyzer-source.sh").read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
sys.argv = ["-", str(root), expected_sha, build["source"]["tree_sha"], "200",
            min(m["started_utc"] for m in manifests), max(m["finished_utc"] for m in manifests),
            *map(str, paths)]
exec(compile(source, "analyzer-source.sh:analyzer", "exec"), {})
print((root / "analysis.json").read_text())
