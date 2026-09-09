"""Validate sealed measured blocks before admitting their numbers to analysis."""
import json
from pathlib import Path
import re

from packet_accounting import account_packet_attempts, parse_root_netem
from stream_floor_evidence import ARTIFACTS, digest, read_json, require, sealed
from stream_floor_statistics import Block, CANDIDATES, _validate_result

WINDOW = "post-warmup-start-barrier-to-pre-teardown-finish-barrier"
TRACES = ("diagnostic_tracing", "native_stage_tracing", "production_path_tracing",
          "production_io_tracing", "reactor_work_tracing", "reactor_partition_tracing")


def public_samples(result):
    """Check the compiled fixture's integer microseconds against its clock bounds."""
    _validate_result("compiled PTY fixture", result)
    require(result.get("public_clock") == "CLOCK_MONOTONIC; local host and time namespace only",
            "wrong public clock")
    clock = result.get("clock_identity", {})
    require(isinstance(clock, dict) and set(clock) == {"boot_id", "time_namespace_dev", "time_namespace_ino"},
            "missing clock identity")
    require(isinstance(clock["boot_id"], str) and re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", clock["boot_id"]),
            "invalid boot identity")
    require(all(type(clock[key]) is int and clock[key] >= 0 for key in ("time_namespace_dev", "time_namespace_ino")),
            "invalid clock namespace")
    require(type(result.get("benchmark_pid")) is int and result["benchmark_pid"] > 0, "invalid benchmark pid")
    bounds = result.get("public_boundaries")
    require(isinstance(bounds, list) and len(bounds) == 200, "missing public boundaries")
    last = 0
    for index, (bound, sample) in enumerate(zip(bounds, result["samples_us"])):
        require(isinstance(bound, dict) and set(bound) == {"trial", "send_ns", "accepted_ns"}
                and all(type(value) is int for value in bound.values()), "invalid public boundary")
        require(bound["trial"] == index and last < bound["send_ns"] < bound["accepted_ns"],
                "nonmonotonic public boundary")
        require(type(sample) is int and sample == (bound["accepted_ns"] - bound["send_ns"] + 999) // 1000,
                "sample differs from public clock interval")
        last = bound["accepted_ns"]


def validate_block(root, build_root, build, *, loss, seed, order, affinity, governors, mtu=1500):
    """Expected settings must come from the frozen plan, never the block itself."""
    root, build_root = Path(root), Path(build_root)
    require(type(loss) is int and loss in (0, 5) and type(seed) is int and 1 <= seed <= 2146483643,
            "invalid frozen cell or seed")
    require(isinstance(order, tuple) and len(order) == 3 and set(order) == set(CANDIDATES), "invalid frozen order")
    require(isinstance(affinity, str) and re.fullmatch(r"[0-9]+(?:,[0-9]+)*", affinity), "invalid frozen affinity")
    require(isinstance(governors, str) and governors and type(mtu) is int and mtu >= 1200,
            "missing frozen environment")
    hashes = sealed(root)
    manifest = read_json(root / "manifest.json")
    require(type(manifest.get("schema_version")) is int and manifest["schema_version"] == 1, "wrong block schema")
    require(manifest.get("source") == {"head_sha": build["source"]["head_sha"],
            "tree_sha": build["source"]["tree_sha"], "dirty": False}
            and manifest["source"].get("dirty") is False, "block source mismatch")
    require(manifest.get("build") == {"path": str(build_root), "provenance_sha256": digest(build_root / "provenance.json")},
            "block build identity mismatch")
    for key, expected in (("trials_per_candidate", 200), ("gap_ms", 100), ("loss_percent_each_direction", loss)):
        require(type(manifest.get(key)) is int and manifest[key] == expected, "wrong block setting: " + key)
    require(manifest.get("seeds") == {"client": seed, "server": seed + 1_000_003}
            and all(type(v) is int for v in manifest["seeds"].values()), "wrong block seeds")
    require(manifest.get("order") == list(order) and manifest.get("affinity") == affinity, "wrong order or affinity")
    require(all(manifest.get(field) is False for field in TRACES), "missing or enabled trace flag")
    require(not any("trace" in name or name.endswith("-built.txt") for name in hashes), "instrumented evidence")
    require(manifest.get("timer") == "immediately before PTY public send; after exact byte accepted by /dev/null sink"
            and manifest.get("topology") == "two isolated Linux network namespaces joined by one veth pair"
            and manifest.get("workload") == "rotating printable byte through authenticated reliable QUIC STREAM echo floor; matched ordinary/native runtime modes; zmosh uses compiled raw remote PTY echo",
            "wrong measurement contract")
    require(manifest.get("artifacts") == {name: {"path": str(build_root / "artifacts/bin" / name),
            "sha256": build["artifacts"][name]["sha256"]} for name in ARTIFACTS}, "wrong measured artifacts")
    require(manifest.get("governors") == {phase: {"path": f"governors-{phase}.txt",
            "sha256": hashes.get(f"governors-{phase}.txt")} for phase in ("before", "pinned", "after")},
            "wrong governor receipt identity")
    require((root / "governors-pinned.txt").read_text() == governors, "governor differs from frozen setting")
    require((root / "governors-before.txt").read_bytes() == (root / "governors-after.txt").read_bytes(),
            "governor restoration mismatch")
    for side, interface in (("client", "c0"), ("server", "s0")):
        path = root / f"topology-{side}.json"
        require(path.stat().st_size <= 65536, "oversized topology")
        topology = json.loads(path.read_text())
        require(isinstance(topology, list), "invalid topology")
        links = [link for link in topology if isinstance(link, dict) and link.get("ifname") == interface]
        require(len(links) == 1 and type(links[0].get("mtu")) is int and links[0]["mtu"] == mtu,
                "wrong measured link MTU")
    require(set(manifest.get("results", {})) == set(CANDIDATES)
            and set(manifest.get("loss_evidence", {})) == set(CANDIDATES), "missing candidate evidence")
    results, packets, clock_identity = {}, {}, None
    for name in CANDIDATES:
        relative = f"{name}/result.json"
        result = read_json(root / relative)
        public_samples(result)
        if clock_identity is None:
            clock_identity = result["clock_identity"]
        require(result["clock_identity"] == clock_identity, "mixed block clock identities")
        expected_result = {"path": relative, "sha256": hashes.get(relative), "samples": 200,
                           "transcript_failures": 0, "stderr_sha256": hashes.get(f"{name}/candidate.stderr"),
                           "resources_sha256": hashes.get(f"{name}/resources.txt")}
        require(all(expected_result[key] is not None for key in ("sha256", "stderr_sha256", "resources_sha256"))
                and manifest["results"][name] == expected_result, "result inventory mismatch")
        paths = [f"netem-{name}-{side}-{phase}.txt" for side in ("client", "server") for phase in ("before", "after")]
        require(all(path in hashes and (root / path).stat().st_size <= 65536 for path in paths), "missing qdisc evidence")
        snapshots = [(root / path).read_text() for path in paths]
        for index, snapshot in enumerate(snapshots):
            counter = parse_root_netem(snapshot)
            direction_seed = seed + (1_000_003 if index >= 2 else 0)
            settings = ("root", "limit", "1000") + (("loss", "5%") if loss else ()) + ("seed", str(direction_seed))
            require(counter.identity == ("netem", counter.handle, *settings), "wrong raw qdisc configuration")
        accounting = account_packet_attempts(*snapshots)
        evidence = manifest["loss_evidence"][name]
        expected_counts = {"client_egress_drop_delta": accounting.client.dropped_packets,
                           "server_egress_drop_delta": accounting.server.dropped_packets,
                           "client_egress_packet_delta": accounting.client.sent_packets,
                           "server_egress_packet_delta": accounting.server.sent_packets,
                           "summed_egress_packet_delta": accounting.total_sent_packets,
                           "summed_egress_attempt_delta": accounting.total_attempts}
        require(all(type(evidence.get(key)) is int and evidence[key] == value for key, value in expected_counts.items()),
                "packet summary disagrees with raw counters")
        require(evidence.get("measurement_window") == WINDOW
                and evidence.get("packet_definition") == "summed root-netem sent-plus-drop attempts in both directions; sent-only legacy field excludes netem drops"
                and evidence.get("receipts") == {path: hashes[path] for path in paths}, "wrong packet window or hashes")
        require((accounting.client.dropped_packets > 0 and accounting.server.dropped_packets > 0) if loss else
                accounting.total_dropped_packets == 0, "observed loss differs from frozen cell")
        results[name], packets[name] = result, accounting.total_attempts
    return Block(loss, order, results, packets)
