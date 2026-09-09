"""Reproduce per-thread scheduling waits; not an exclusive latency decomposition."""
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "crates/everudp/tests/net"))
from analyze_public_scheduler import timelines, correlate, _LINE, _WAKE, _SWITCH
from scheduler_capture import sanitize_scheduler, validate_attributes
from stream_floor_blocks import public_samples


def read(path):
    return json.loads(path.read_text())


def main():
    subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=ROOT, check=True)
    capture = ROOT / "capture"
    measure = capture / "measurement"
    subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=measure, check=True)
    receipt = read(capture / "capture.json")
    assert receipt["status"] == "CAPTURED" and receipt["benchmark_exit_code"] == 0
    assert receipt["mode"] == "scheduler" and not receipt["qualification"]
    assert receipt["harness_sha"] == "b5d0ddc6db2b616cadb92b4b5ffe1a4ca90cf6ee"
    assert receipt["runtime_sha"] == "9be1b79d25c5fb3347b9335c6899c9f3a7e1b932"
    assert receipt["provenance_sha256"] == hashlib.sha256((ROOT / "build-provenance.json").read_bytes()).hexdigest()
    manifest = read(measure / "manifest.json")
    assert manifest["diagnostic_tracing"] and manifest["hardware_counter_capture"]
    assert manifest["source"]["head_sha"] == receipt["harness_sha"]
    assert manifest["seeds"]["client"] == 218000001
    assert manifest["loss_percent_each_direction"] == 0
    report = {"qualification": False, "status": "DIAGNOSTIC_ONLY", "candidates": {}}
    for name in receipt["order"]:
        result = read(measure / name / "result.json")
        public_samples(result)
        before = read(measure / name / "host-before.json")
        after = read(measure / name / "host-after.json")
        assert before["end_monotonic_ns"] < result["public_boundaries"][0]["send_ns"]
        assert after["begin_monotonic_ns"] > result["public_boundaries"][-1]["accepted_ns"]
        output = {"trials": result["trials"], "median_us": statistics.median(result["samples_us"]), "threads": []}
        assert before["cpus"].keys() == after["cpus"].keys()
        total = idle = 0
        for cpu, counters in before["cpus"].items():
            low, high = counters["ticks"], after["cpus"][cpu]["ticks"]
            assert len(low) == len(high) and len(low) >= 8
            delta = [b - a for a, b in zip(low, high)]
            assert all(value >= 0 for value in delta)
            # guest/guest_nice already appear in user/nice; do not add twice.
            total += sum(delta[:8])
            idle += delta[3]
        assert total > 0
        output["selected_and_smt_nonidle_percent"] = (total - idle) * 100 / total
        output["cpu_pressure_before"] = before["cpu_pressure"]
        output["cpu_pressure_after"] = after["cpu_pressure"]
        report["candidates"][name] = output
        if name not in receipt["clients"]:
            output["scheduler"] = "not recorded"
            continue
        item = receipt["clients"][name]
        assert item["before"] == item["after"]
        recording = item["capture"]
        scope = item["scheduler_scope"]
        assert set(recording["targets"]) == {row["tid"] for row in scope}
        controls = recording["control"]
        assert [row["operation"] for row in controls] == ["enable", "disable"]
        assert all(row["sent_ns"] <= row["acknowledged_ns"] for row in controls)
        assert before["end_monotonic_ns"] < controls[0]["sent_ns"]
        assert after["begin_monotonic_ns"] > controls[1]["acknowledged_ns"]
        assert controls[0]["acknowledged_ns"] < result["public_boundaries"][0]["send_ns"]
        assert controls[1]["sent_ns"] > result["public_boundaries"][-1]["accepted_ns"]
        validate_attributes((capture / f"{name}-counters/events-attributes.txt").read_text())
        text = recording["scheduler_text"]
        assert sanitize_scheduler(text, recording["targets"]) == text
        lines = {row["tid"]: [] for row in scope}
        for line in text.splitlines():
            event = _LINE.fullmatch(line)
            switch = event["kind"] == "sched_switch"
            fields = (_SWITCH if switch else _WAKE).fullmatch(event["body"])
            for key in (("prev_pid", "next_pid") if switch else ("pid",)):
                tid = int(fields[key])
                if tid in lines:
                    lines[tid].append(line)
        for target in scope:
            tid = target["tid"]
            row = {key: target[key] for key in ("binary", "side", "pid", "tid")}
            output["threads"].append(row)
            if not lines[tid]:
                row["excluded"] = "no scheduler events; not evidence of zero wait"
                continue
            tracks = timelines("\n".join(lines[tid]), {"task": tid})
            trials = correlate(result["public_boundaries"], tracks)
            waits = [trial["runnable_wait_ns"]["task"] / 1000 for trial in trials if "excluded" not in trial]
            row["covered_trials"] = len(waits)
            row["excluded_trials"] = 200 - len(waits)
            if waits:
                row["wait_us_median_mean_max"] = [statistics.median(waits), statistics.mean(waits), max(waits)]
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
