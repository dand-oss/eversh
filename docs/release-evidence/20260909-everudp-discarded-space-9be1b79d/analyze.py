"""Verify the frozen initial screen; not performance qualification."""
import hashlib
import json
import math
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent / "measurement"
SHA = "9be1b79d25c5fb3347b9335c6899c9f3a7e1b932"
NAMES = ["everudp", "zmosh-udp", "zmosh-quic"]
ORDERS = [NAMES, ["zmosh-quic", "everudp", "zmosh-udp"],
          ["zmosh-udp", "zmosh-quic", "everudp"], ["everudp", "zmosh-quic", "zmosh-udp"]]


def read(path):
    return json.loads(path.read_text())


def quantiles(values):
    values = sorted(values)
    return [values[math.ceil(len(values) * q) - 1] for q in (.5, .95)]


def main():
    assert (ROOT / "exit-status").read_text().strip() == "0"
    assert hashlib.sha256((ROOT / "frozen-schedule.sh").read_bytes()).hexdigest() == "345e90e9958f7e40298a3fe231833976e9914ecd62ed4d44b9644bf95d15058e"
    builds = {mode: read(ROOT / f"{mode}-build.json") for mode in "AB"}
    for mode, build in builds.items():
        assert build["source"]["head_sha"] == SHA and build["source"]["clean"]
        expected = ["cli"] + (["discarded-space-spike"] if mode == "B" else [])
        assert build["everudp_build"]["cargo_features"] == expected
        assert build["everudp_build"]["engine"] == "noq"
        assert build["everudp_build"]["profile"]["lto"] == "fat"
        assert build["everudp_build"]["profile"]["codegen_units"] == 1
        assert build["isolation"]["sealed_control_reuse"]
    for name in ("zmosh-udp", "zmosh-quic", "zmosh-quic-bridge", "pty-bench", "pty-echo"):
        assert builds["A"]["artifacts"][name]["sha256"] == builds["B"]["artifacts"][name]["sha256"]
    pools = {mode: {name: [] for name in NAMES} for mode in "AB"}
    rows = []
    for index, mode in enumerate("ABBA"):
        root = ROOT / f"block{index}-{mode}"
        subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=root, check=True)
        manifest = read(root / "manifest.json")
        assert manifest["source"]["head_sha"] == SHA and not manifest["source"]["dirty"]
        assert manifest["trials_per_candidate"] == 200
        assert manifest["order"] == ORDERS[index] and manifest["affinity"] == "40,42,44,46"
        assert manifest["loss_percent_each_direction"] == 0 and manifest["gap_ms"] == 100
        assert manifest["seeds"] == {"client": 216000001 + index, "server": 217000004 + index}
        assert not manifest["diagnostic_tracing"] and not manifest["hardware_counter_capture"]
        data = {}
        for name in NAMES:
            assert manifest["artifacts"][name]["sha256"] == builds[mode]["artifacts"][name]["sha256"]
            result = read(root / name / "result.json")
            assert result["trials"] == len(result["samples_us"]) == 200
            assert result["transcript_failures"] == 0
            pools[mode][name].extend(result["samples_us"])
            data[name] = quantiles(result["samples_us"])
        rows.append({"block": index, "mode": mode, "p50_p95_us": data})
    pooled = {mode: {name: quantiles(values) for name, values in names.items()} for mode, names in pools.items()}
    print(json.dumps({"status": "INCONCLUSIVE_NOT_ADOPTED", "qualification": False,
                      "blocks": rows, "pooled": pooled}, indent=2))


if __name__ == "__main__":
    main()
