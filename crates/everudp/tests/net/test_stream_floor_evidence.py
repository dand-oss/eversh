"""Reject plausible-looking but unsealed or mismatched experiment evidence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from stream_floor_evidence import digest, read_json, sealed, validate_build, validate_preflight
from stream_preflight_evidence import save

NET = Path(__file__).resolve().parent
ROOT = NET.parents[3]
HEAD, TREE = "a" * 40, "b" * 40


def seal(root):
    (root / "SHA256SUMS").write_text("".join(
        f"{digest(path)}  {path.relative_to(root).as_posix()}\n"
        for path in sorted(root.rglob("*")) if path.is_file() and path.name != "SHA256SUMS"))


def make_build(root):
    (root / "artifacts/bin").mkdir(parents=True)
    for name in ("everudp-stream-floor", "zmosh-udp", "pty-bench", "pty-echo"):
        (root / "artifacts/bin" / name).write_bytes(b"fixture")
    source = (NET / "build-stream-floor.sh").read_text().split("<<'PY'\n", 1)[1].split("\nPY\n", 1)[0]
    args = ["-", str(root), str(ROOT), str(NET), HEAD, TREE,
            "dfc8395b5edcd237bf82712fbde879c6e8be7dfa", "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514",
            "started", "finished", "cargo", "rustc", "cc", "git", "0.15.2", "c" * 64, "cli,stream-floor"]
    with patch.object(sys, "argv", args):
        exec(compile(source, "build-stream-floor.sh:provenance", "exec"), {})
    seal(root)
    return read_json(root / "provenance.json")


def profiles():
    # Synthetic local config values from the locked profile contract, not a run receipt.
    fields = ["datagram_receive_buffer_size: None", "datagram_send_buffer_size: 0",
              "stream_receive_window: 4194304", "receive_window: 8388608", "send_window: 4194304",
              "enable_segmentation_offload: true", "max_concurrent_uni_streams: 1",
              "initial_rtt: 100ms", "initial_mtu: 1200", "min_mtu: 1200",
              "ack_frequency_config: Some(AckFrequencyConfig { ack_eliciting_threshold: 0, max_ack_delay: Some(1ms) })"]
    return {(mode, side): ", ".join(fields + [f"max_concurrent_bidi_streams: {0 if side == 'client' else 1}"])
            + "; socket_initial_gso_cap=10" for mode in ("ordinary", "native") for side in ("client", "server")}


def make_preflight(root, build):
    frozen = {"collector_head": HEAD, "collector_tree": TREE,
              "binary_sha256": build["artifacts"]["everudp-stream-floor"]["sha256"],
              "collector_sha256": digest(NET / "test-stream-process.py"),
              "evidence_writer_sha256": digest(NET / "stream_preflight_evidence.py")}
    save(root, frozen, profiles(), os.getuid(), os.getgid())


class EvidenceTests(unittest.TestCase):
    def test_actual_builder_and_preflight_writer_produce_accepted_shapes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            build = make_build(root / "build")
            self.assertEqual(validate_build(root / "build", HEAD, TREE, ROOT), build)
            make_preflight(root / "preflight", build)
            self.assertEqual(validate_preflight(root / "preflight", build, ROOT)["status"], "PASS")

    def test_resealed_wrong_build_claims_rejected(self):
        mutations = [lambda p: p.update(purpose="old-datagram-floor"),
                     lambda p: p.pop("tool_binaries"),
                     lambda p: p["tool_binaries"]["cargo"].update(sha256="not-a-hash"),
                     lambda p: p["source"].update(clean=False),
                     lambda p: p["zmosh_source"].update(commit="f" * 40),
                     lambda p: p["everudp_build"].update(default_features=True),
                     lambda p: p["everudp_build"]["profile"].update(panic="abort"),
                     lambda p: p["everudp_build"]["profile"].update(codegen_units=True),
                     lambda p: p["isolation"].update(empty_cargo_home=False),
                     lambda p: p["inputs"].update(builder="f" * 64)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                receipt = make_build(root)
                mutate(receipt)
                (root / "provenance.json").write_text(json.dumps(receipt))
                seal(root)
                with self.assertRaises(ValueError):
                    validate_build(root, HEAD, TREE, ROOT)

    def test_corruption_unlisted_file_symlink_and_unsafe_seal_rejected(self):
        for case in ("corrupt", "extra", "symlink", "traversal", "duplicate"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                make_build(root)
                if case == "corrupt":
                    (root / "artifacts/bin/zmosh-udp").write_bytes(b"changed")
                elif case == "extra":
                    (root / "unlisted").write_text("extra")
                elif case == "symlink":
                    (root / "linked").symlink_to(root / "provenance.json")
                else:
                    entry = "0" * 64 + "  ../outside\n" if case == "traversal" else (root / "SHA256SUMS").read_text()
                    with (root / "SHA256SUMS").open("a") as stream:
                        stream.write(entry)
                with self.assertRaises(ValueError):
                    sealed(root)

    def test_resealed_incomplete_or_wrong_preflight_rejected(self):
        for case in ("binary", "cleanup", "case", "authority", "cap", "ack"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                build = make_build(root / "build")
                preflight = root / "preflight"
                make_preflight(preflight, build)
                receipt = read_json(preflight / "receipt.json")
                if case == "binary":
                    receipt["identity"]["binary_sha256"] = "f" * 64
                elif case == "cleanup":
                    receipt["fixture_cleanup"] = False
                elif case == "case":
                    receipt["cases"].pop()
                elif case == "authority":
                    receipt["performance_qualification"] = True
                else:
                    for name in receipt["profiles"]:
                        path = preflight / name
                        text = path.read_text().replace("socket_initial_gso_cap=10", "socket_initial_gso_cap=64") if case == "cap" else path.read_text().replace("max_ack_delay: Some(1ms)", "max_ack_delay: Some(5ms)")
                        path.write_text(text)
                        receipt["profiles"][name] = digest(path)
                (preflight / "receipt.json").write_text(json.dumps(receipt))
                seal(preflight)
                with self.assertRaises(ValueError):
                    validate_preflight(preflight, build, ROOT)

    def test_duplicate_json_keys_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "receipt.json"
            path.write_text('{"status":"FAIL","status":"PASS"}')
            with self.assertRaises(ValueError):
                read_json(path)


if __name__ == "__main__":
    unittest.main()
