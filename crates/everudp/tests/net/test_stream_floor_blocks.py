"""Use the actual block manifest emitter; mutate and reseal its evidence."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from stream_floor_blocks import validate_block
from stream_floor_statistics import CANDIDATES
from test_stream_floor_evidence import HEAD, TREE, NET, ROOT, digest, make_build, seal


def fixture(root, build_root, loss=0, counter_capture="0"):
    root.mkdir()
    for phase in ("before", "pinned", "after"):
        (root / f"governors-{phase}.txt").write_text("cpu0 performance\n")
    for side, interface in (("client", "c0"), ("server", "s0")):
        (root / f"topology-{side}.json").write_text(json.dumps([{"ifname": interface, "mtu": 1500}]))
    for name in CANDIDATES:
        (root / name).mkdir()
        result = {"schema_version": 1, "trials": 200, "gap_ms": 100, "transcript_failures": 0,
                  "samples_us": [80] * 200,
                  "public_clock": "CLOCK_MONOTONIC; local host and time namespace only",
                  "clock_identity": {"boot_id": "12345678-1234-1234-1234-123456789abc",
                                     "time_namespace_dev": 4, "time_namespace_ino": 5},
                  "benchmark_pid": 42,
                  "public_boundaries": [{"trial": i, "send_ns": 1 + i * 100000000,
                                         "accepted_ns": 80001 + i * 100000000} for i in range(200)]}
        (root / name / "result.json").write_text(json.dumps(result))
        (root / name / "candidate.stderr").write_text("")
        (root / name / "resources.txt").write_text("fixture resource output\n")
        for side in ("client", "server"):
            for phase in ("before", "after"):
                count, drops = (100, 2 if loss else 0) if phase == "after" else (0, 0)
                settings = (" loss 5%" if loss else "") + f" seed {80001 if side == 'client' else 1080004}"
                (root / f"netem-{name}-{side}-{phase}.txt").write_text(
                    f"qdisc netem 1: root refcnt 2 limit 1000{settings}\n"
                    f" Sent {count * 80} bytes {count} pkt (dropped {drops}, overlimits 0 requeues 0)\n")
    # Execute the production manifest emitter instead of reproducing its schema.
    script = (NET / "bench-performance-block.sh").read_text()
    marker = '"$BUILD_PROVENANCE_SHA" "$COUNTER_CAPTURE" <<\'PY\'\n'
    source = script.split(marker, 1)[1].split("\nPY\n", 1)[0]
    args = ["-", str(root), str(ROOT), str(build_root), HEAD, TREE, "false", "200", str(loss),
            "80001", ",".join(CANDIDATES), "0", "start", "finish", "kernel", "cpu", digest(build_root / "provenance.json"), counter_capture]
    with patch.object(sys, "argv", args):
        exec(compile(source, "bench-performance-block.sh:manifest", "exec"), {})
    seal(root)


class BlockEvidenceTests(unittest.TestCase):
    def test_counter_capture_emitter_is_diagnostic_without_trace_files(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            build = make_build(root / "build")
            fixture(root / "block", root / "build", counter_capture="1")
            manifest = json.loads((root / "block/manifest.json").read_text())
            self.assertTrue(manifest["hardware_counter_capture"])
            self.assertTrue(manifest["diagnostic_tracing"])
            with self.assertRaises(ValueError):
                self.validate(root / "block", root / "build", build)

    def validate(self, root, build_root, build, loss=0):
        return validate_block(root, build_root, build, loss=loss, seed=80001, order=CANDIDATES,
                              affinity="0", governors="cpu0 performance\n")

    def test_actual_manifest_emitter_is_accepted_in_both_cells(self):
        for loss in (0, 5):
            with self.subTest(loss=loss), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                build = make_build(root / "build")
                fixture(root / "block", root / "build", loss)
                block = self.validate(root / "block", root / "build", build, loss)
                self.assertEqual(block.packet_attempts[CANDIDATES[0]], 204 if loss else 200)

    def test_resealed_wrong_manifest_claims_are_rejected(self):
        mutations = [lambda p: p["source"].update(dirty=True),
                     lambda p: p["build"].update(provenance_sha256="0" * 64),
                     lambda p: p["seeds"].update(client=80002),
                     lambda p: p.update(diagnostic_tracing=True),
                     lambda p: p.pop("production_io_tracing"),
                     lambda p: p.update(order=list(reversed(CANDIDATES))),
                     lambda p: p.update(gap_ms=1),
                     lambda p: p.update(affinity="1"),
                     lambda p: p["artifacts"].pop("everudp-stream-floor"),
                     lambda p: p["loss_evidence"][CANDIDATES[0]].update(summed_egress_attempt_delta=1),
                     lambda p: p["loss_evidence"][CANDIDATES[0]].update(packet_definition="sent only"),
                     lambda p: p["loss_evidence"][CANDIDATES[0]].update(measurement_window="whole-process")]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                build = make_build(root / "build")
                block_root = root / "block"
                fixture(block_root, root / "build")
                path = block_root / "manifest.json"
                manifest = json.loads(path.read_text())
                mutate(manifest)
                path.write_text(json.dumps(manifest))
                seal(block_root)
                with self.assertRaises(ValueError):
                    self.validate(block_root, root / "build", build)

    def test_resealed_raw_evidence_mismatch_is_rejected(self):
        for case in ("sample", "clock", "qdisc", "governor", "mtu", "trace"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                build = make_build(root / "build")
                block_root = root / "block"
                fixture(block_root, root / "build")
                if case in ("sample", "clock"):
                    path = block_root / CANDIDATES[0] / "result.json"
                    result = json.loads(path.read_text())
                    if case == "sample":
                        result["samples_us"][0] = 1
                    else:
                        result["public_boundaries"][1]["send_ns"] = 1
                    path.write_text(json.dumps(result))
                elif case == "qdisc":
                    path = block_root / f"netem-{CANDIDATES[0]}-client-after.txt"
                    path.write_text(path.read_text().replace("100 pkt", "101 pkt"))
                elif case == "governor":
                    (block_root / "governors-pinned.txt").write_text("cpu0 powersave\n")
                elif case == "mtu":
                    (block_root / "topology-client.json").write_text('[{"ifname":"c0","mtu":1280}]')
                else:
                    (block_root / "hidden-trace.json").write_text("{}")
                seal(block_root)
                with self.assertRaises(ValueError):
                    self.validate(block_root, root / "build", build)

    def test_resealed_and_rehashed_wrong_settings_and_mixed_clock_rejected(self):
        for case in ("seed", "loss", "clock"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                build = make_build(root / "build")
                block_root = root / "block"
                fixture(block_root, root / "build")
                manifest_path = block_root / "manifest.json"
                manifest = json.loads(manifest_path.read_text())
                name = CANDIDATES[1]
                if case == "clock":
                    path = block_root / name / "result.json"
                    result = json.loads(path.read_text())
                    result["clock_identity"]["time_namespace_ino"] += 1
                    path.write_text(json.dumps(result))
                    manifest["results"][name]["sha256"] = digest(path)
                else:
                    for phase in ("before", "after"):
                        path = block_root / f"netem-{name}-client-{phase}.txt"
                        value = path.read_text()
                        value = value.replace("seed 80001", "seed 999") if case == "seed" else value.replace("limit 1000", "limit 1000 loss 5%")
                        path.write_text(value)
                        manifest["loss_evidence"][name]["receipts"][path.name] = digest(path)
                manifest_path.write_text(json.dumps(manifest))
                seal(block_root)
                with self.assertRaises(ValueError):
                    self.validate(block_root, root / "build", build)


if __name__ == "__main__":
    unittest.main()
