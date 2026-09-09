"""Fail-closed identity checks for the matched reliable-stream experiment."""
import hashlib
import json
from pathlib import Path

ARTIFACTS = {"everudp-stream-floor", "zmosh-udp", "pty-bench", "pty-echo"}
UDP_COMMIT = "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
UDP_TREE = "1a3a615fd69d25e2c4c058e1d86b1d7be5e9f514"
PROFILE = {"lto": "fat", "codegen_units": 1, "panic": "unwind", "opt_level": 3,
           "rustflags": "", "target_cpu": "portable default"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def hex_id(value, size):
    return isinstance(value, str) and len(value) == size and all(c in "0123456789abcdef" for c in value)


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    require(path.stat().st_size <= 1048576, "oversized JSON receipt")
    value = json.loads(path.read_text(), object_pairs_hook=unique)
    require(isinstance(value, dict), "receipt must be an object")
    return value


def sealed(root):
    """Verify every regular file, not just the artifacts named by provenance."""
    root = Path(root)
    require(not root.is_symlink() and root.is_dir(), "invalid evidence root")
    seal = root / "SHA256SUMS"
    require(not seal.is_symlink() and seal.is_file() and seal.stat().st_size <= 1048576,
            "missing or oversized seal")
    expected = {}
    for line in seal.read_text().splitlines():
        parts = line.split("  ", 1)
        require(len(parts) == 2 and hex_id(parts[0], 64), "malformed checksum entry")
        checksum, name = parts
        require(name and "\\" not in name and not any(p in ("", ".", "..") for p in name.split("/")),
                "unsafe sealed path")
        require(name not in expected and name != "SHA256SUMS", "duplicate or self-referential seal")
        expected[name] = checksum
    require(0 < len(expected) <= 2048, "invalid seal inventory size")
    actual = {}
    for path in root.rglob("*"):
        require(not path.is_symlink(), "symlink in evidence")
        if path.is_dir():
            continue
        require(path.is_file(), "non-regular evidence file")
        if path == seal:
            continue
        actual[path.relative_to(root).as_posix()] = digest(path)
        require(len(actual) <= 2048, "oversized evidence inventory")
    require(actual == expected, "evidence seal mismatch")
    return expected


def validate_build(root, head, tree, source_root):
    root, source_root = Path(root), Path(source_root)
    hashes = sealed(root)
    receipt = read_json(root / "provenance.json")
    require(hex_id(head, 40) and hex_id(tree, 40), "invalid expected source identity")
    require(receipt.get("schema_version") == 1 and type(receipt.get("schema_version")) is int,
            "unsupported build schema")
    require(receipt.get("purpose") == "matched-noq-reliable-stream-floor", "wrong build purpose")
    tools = receipt.get("tool_binaries", {})
    require(isinstance(tools, dict) and set(tools) == {"cargo", "rustc", "cc", "git"}, "missing tool identities")
    for tool in tools.values():
        require(isinstance(tool, dict) and set(tool) == {"path", "sha256"}
                and isinstance(tool["path"], str) and Path(tool["path"]).is_absolute()
                and hex_id(tool["sha256"], 64), "invalid tool identity")
    zig = receipt.get("tools", {}).get("zig_0_15_2", {})
    require(zig.get("version") == "0.15.2" and hex_id(zig.get("sha256"), 64), "invalid frozen Zig tool")
    source = receipt.get("source", {})
    require(source.get("head_sha") == head and source.get("tree_sha") == tree and source.get("clean") is True,
            "build source mismatch")
    zmosh = receipt.get("zmosh_source", {})
    require(zmosh.get("commit") == UDP_COMMIT and zmosh.get("tree") == UDP_TREE and zmosh.get("clean") is True,
            "unfrozen UDP control")
    build = receipt.get("everudp_build", {})
    require(build.get("cargo_features") == ["cli", "stream-floor"] and build.get("default_features") is False
            and build.get("diagnostic_build") is False and build.get("runtime_modes") == ["ordinary", "native"]
            and build.get("target") == "example everudp-stream-floor", "wrong runtime build")
    profile = build.get("profile", {})
    require(profile == PROFILE and type(profile.get("codegen_units")) is int and type(profile.get("opt_level")) is int,
            "wrong release profile")
    isolation = receipt.get("isolation", {})
    for field in ("fresh_detached_zmosh_clone", "isolated_cargo_target", "archived_eversh_source",
                  "empty_cargo_home", "cleared_cargo_environment", "isolated_zig_local_cache", "isolated_zig_global_cache"):
        require(isolation.get(field) is True, "missing build isolation: " + field)
    artifacts = receipt.get("artifacts", {})
    require(set(artifacts) == ARTIFACTS, "wrong build artifacts")
    for name in ARTIFACTS:
        require(artifacts[name] == {"path": f"artifacts/bin/{name}", "sha256": hashes.get(f"artifacts/bin/{name}")},
                "artifact identity mismatch")
        require(f"artifacts/bin/{name}" in hashes, "missing artifact")
    net = source_root / "crates/everudp/tests/net"
    inputs = {"Cargo.lock": source_root / "Cargo.lock",
              "everudp-stream-floor.rs": source_root / "crates/everudp/examples/everudp-stream-floor.rs",
              "builder": net / "build-stream-floor.sh", "pty-bench.c": net / "pty-bench.c", "pty-echo.c": net / "pty-echo.c"}
    require(receipt.get("inputs") == {name: digest(path) for name, path in inputs.items()}, "build input mismatch")
    return receipt


def validate_preflight(root, build, source_root):
    root, source_root = Path(root), Path(source_root)
    hashes = sealed(root)
    receipt = read_json(root / "receipt.json")
    require(receipt.get("schema_version") == 1 and type(receipt.get("schema_version")) is int
            and receipt.get("purpose") == "matched-stream-untimed-preflight" and receipt.get("status") == "PASS",
            "invalid preflight receipt")
    require(receipt.get("performance_qualification") is False and receipt.get("fixture_cleanup") is True
            and receipt.get("built_profile_parity") is True and receipt.get("scope") == "local-built-not-negotiated",
            "wrong preflight authority or cleanup")
    net = source_root / "crates/everudp/tests/net"
    require(receipt.get("identity") == {
        "collector_head": build["source"]["head_sha"], "collector_tree": build["source"]["tree_sha"],
        "binary_sha256": build["artifacts"]["everudp-stream-floor"]["sha256"],
        "collector_sha256": digest(net / "test-stream-process.py"),
        "evidence_writer_sha256": digest(net / "stream_preflight_evidence.py")}, "preflight identity mismatch")
    require(receipt.get("cases") == [f"{mode}/{case}" for mode in ("ordinary", "native")
            for case in ("exact-pty-cancel-restore", "wrong-pin", "wrong-token")], "missing preflight case")
    names = {f"{mode}-{side}-built.txt" for mode in ("ordinary", "native") for side in ("client", "server")}
    require(set(hashes) == names | {"receipt.json"} and receipt.get("profiles") == {name: hashes[name] for name in names},
            "wrong preflight artifact inventory")
    for side in ("client", "server"):
        ordinary = (root / f"ordinary-{side}-built.txt").read_text()
        native = (root / f"native-{side}-built.txt").read_text()
        require(ordinary == native and len(ordinary) <= 16385 and ordinary.count("\n") == 1,
                "built profile parity mismatch")
        for field in ("datagram_receive_buffer_size: None", "datagram_send_buffer_size: 0",
                      "stream_receive_window: 4194304", "receive_window: 8388608", "send_window: 4194304",
                      "enable_segmentation_offload: true", "max_concurrent_uni_streams: 1",
                      "initial_rtt: 100ms", "initial_mtu: 1200", "min_mtu: 1200",
                      "ack_frequency_config: Some(AckFrequencyConfig { ack_eliciting_threshold: 0, max_ack_delay: Some(1ms)"):
            require(field in ordinary, "missing locked profile setting: " + field)
        require(f"max_concurrent_bidi_streams: {0 if side == 'client' else 1}" in ordinary,
                "wrong bidirectional stream limit")
        parts = ordinary.strip().rsplit("; socket_initial_gso_cap=", 1)
        require(len(parts) == 2 and parts[1] in {str(i) for i in range(1, 11)}, "invalid initial socket cap")
    return receipt
