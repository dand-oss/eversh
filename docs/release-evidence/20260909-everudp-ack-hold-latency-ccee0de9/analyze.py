"""Reproduce the predeclared ACK-hold screen, never production qualification."""
import hashlib
import json
import math
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "crates/everudp/tests/net"))
from stream_floor_evidence import sealed
from stream_floor_blocks import public_samples


def read(path):
    return json.loads(path.read_text())


def quantiles(samples):
    ordered = sorted(samples)
    return [ordered[math.ceil(q * len(ordered)) - 1] for q in (.5, .95)]


def main():
    measurement = ROOT / "measurement"
    exit_status = (measurement / "exit-status").read_text().strip()
    assert exit_status == "1", "this receipt records the failed frozen run"
    assert hashlib.sha256((measurement / "frozen-schedule.sh").read_bytes()).hexdigest() == (
        "cc76693fed7d2cb1fba7bfd2ef9de16ba49d5d0b41ec71cfb758f98f422d752e")
    builds = {mode: read(measurement / f"{mode}-build.json") for mode in "AB"}
    names = ("everudp", "zmosh-udp", "zmosh-quic")
    orders = (list(names), [names[2], names[0], names[1]],
              [names[1], names[2], names[0]], [names[0], names[2], names[1]])
    expected = "ccee0de938a043a90795a21c27ae9f5c4b9d3985"
    for mode, build in builds.items():
        assert build["source"]["head_sha"] == expected and build["source"]["clean"]
        features = ["cli"] + (["input-ack-hold-spike"] if mode == "B" else [])
        assert build["everudp_build"]["cargo_features"] == features
        assert build["everudp_build"]["engine"] == "noq"
        assert build["everudp_build"]["profile"] == builds["A"]["everudp_build"]["profile"]
        assert build["everudp_build"]["profile"]["lto"] == "fat"
        assert build["everudp_build"]["profile"]["codegen_units"] == 1
        assert build["isolation"]["sealed_control_reuse"]
    for name in (*names[1:], "pty-bench", "pty-echo", "zmosh-quic-bridge"):
        assert builds["A"]["artifacts"][name] == builds["B"]["artifacts"][name]
    blocks, pooled, cutoffs = [], [], []
    for loss in (0, 5):
        pools = {mode: {name: [] for name in names} for mode in "AB"}
        for index, mode in enumerate("ABBA"):
            directory = measurement / f"loss{loss}-block{index}-{mode}"
            if loss == 5 and index >= 1:
                if index == 1:
                    assert directory.is_dir()
                    assert not (directory / "manifest.json").exists()
                    assert not (directory / "zmosh-quic/result.json").exists()
                    assert "state=awaiting_ack" in (directory / "zmosh-quic/candidate.stderr").read_text()
                else:
                    assert not directory.exists()
                continue
            sealed(directory)
            manifest = read(directory / "manifest.json")
            assert manifest["source"]["head_sha"] == expected and not manifest["source"]["dirty"]
            assert manifest["loss_percent_each_direction"] == loss
            assert manifest["trials_per_candidate"] == 200
            assert manifest["affinity"] == "40,42,44,46" and manifest["gap_ms"] == 100
            assert manifest["order"] == orders[index]
            seed = 221000001 + loss * 100 + index
            assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
            for flag in ("diagnostic_tracing", "hardware_counter_capture", "production_io_tracing",
                         "production_packet_tracing", "production_path_tracing"):
                assert not manifest[flag]
            assert manifest["build"]["provenance_sha256"] == hashlib.sha256(
                (measurement / f"{mode}-build.json").read_bytes()).hexdigest()
            values = {}
            for name in names:
                result = read(directory / name / "result.json")
                public_samples(result)
                assert result["trials"] == len(result["samples_us"]) == 200
                assert manifest["artifacts"][name]["sha256"] == builds[mode]["artifacts"][name]["sha256"]
                before = read(directory / name / "host-before.json")
                after = read(directory / name / "host-after.json")
                assert before["end_monotonic_ns"] < result["public_boundaries"][0]["send_ns"]
                assert after["begin_monotonic_ns"] > result["public_boundaries"][-1]["accepted_ns"]
                pools[mode][name].extend(result["samples_us"])
                values[name] = quantiles(result["samples_us"])
            blocks.append({"loss": loss, "block": index, "mode": mode, "p50_p95_us": values})
        if loss == 5:
            continue  # Incomplete cell cannot be pooled or satisfy the cutoff.
        values = {mode: {name: quantiles(samples) for name, samples in pool.items()}
                  for mode, pool in pools.items()}
        a, b = (values[mode]["everudp"] for mode in "AB")
        cutoffs.append(b[0] < a[0] and 10 * b[1] <= 11 * a[1])
        for mode in "AB":
            pooled.append({"loss": loss, "mode": mode, "observations_each": 400,
                           "p50_p95_us": values[mode],
                           "udp_p50_ratio": values[mode]["everudp"][0] / values[mode]["zmosh-udp"][0]})
    print(json.dumps({"status": "INCOMPLETE_CONTROL_STARTUP_FAILURE",
                      "qualification": False, "screen_cutoff_evaluable": False,
                      "completed_cell_cutoffs": cutoffs,
                      "blocks": blocks, "pooled_completed_cells_only": pooled}, indent=2))


if __name__ == "__main__":
    main()
