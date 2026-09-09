"""Read-only bookends, never a sampler or a causal latency decomposition.

Run outside the public measurement window. Export no command lines, process
names, environment, payloads or stacks. Counters are cumulative; match thread
IDs AND start_ticks before taking deltas. Missing/exited tasks are not zeros.
CPU tick arrays retain Linux /proc/stat order (including guest fields, which
must not be added to user/nice again). Snapshots are not atomic.
The block's SHA256SUMS seals these files; the latency result manifest is
unchanged. enumerated_threads is discovery-time count, not an atomic census.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import time


def cpu_list(text):
    result = set()
    for item in text.strip().split(","):
        bounds = item.split("-")
        if len(bounds) not in (1, 2) or not all(x.isdecimal() for x in bounds):
            raise ValueError("invalid CPU list")
        low, high = int(bounds[0]), int(bounds[-1])
        if not 0 <= low <= high < 4096:
            raise ValueError("invalid CPU range")
        result.update(range(low, high + 1))
    return sorted(result)


def task_sample(root):
    try:
        # proc_pid_stat(5): comm can contain spaces and parentheses; fields
        # after its final ')' begin at field 3, starttime is field 22.
        before = (root / "stat").read_text().rsplit(")", 1)[1].split()
        status = dict(line.split(":", 1) for line in
                      (root / "status").read_text().splitlines())
        after = (root / "stat").read_text().rsplit(")", 1)[1].split()
        if before[19] != after[19]:
            return {"status": "identity_changed"}
        return {"status": "available", "start_ticks": int(before[19]),
                "user_ticks": int(before[11]), "system_ticks": int(before[12]),
                "voluntary": int(status["voluntary_ctxt_switches"]),
                "involuntary": int(status["nonvoluntary_ctxt_switches"]),
                "affinity": cpu_list(status["Cpus_allowed_list"])}
    except (OSError, ValueError, IndexError, KeyError) as error:
        return {"status": type(error).__name__}


def scalar_file(path):
    try:
        return {"status": "available", "value": path.read_text().strip()}
    except OSError as error:
        return {"status": type(error).__name__}


def snapshot(selected, sides):
    result = {"schema_version": 1, "qualification": False,
              "begin_monotonic_ns": time.monotonic_ns(),
              "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
              "selected_cpus": selected, "cpus": {}, "tasks": []}
    syscpu = Path("/sys/devices/system/cpu")
    siblings = {}
    for cpu in selected:
        item = scalar_file(syscpu / f"cpu{cpu}/topology/thread_siblings_list")
        siblings[str(cpu)] = item
    tracked = set(selected)
    for item in siblings.values():
        if item["status"] == "available":
            tracked.update(cpu_list(item["value"]))
    result["siblings"] = siblings
    stats = {line.split()[0]: line.split()[1:] for line in Path("/proc/stat").read_text().splitlines()}
    for cpu in sorted(tracked):
        root = syscpu / f"cpu{cpu}/cpufreq"
        result["cpus"][str(cpu)] = {
            "ticks": [int(x) for x in stats.get(f"cpu{cpu}", [])],
            "governor": scalar_file(root / "scaling_governor"),
            "frequency_khz": scalar_file(root / "scaling_cur_freq")}
    result["cpu_pressure"] = scalar_file(Path("/proc/pressure/cpu"))
    for side, pids in sides.items():
        for pid in sorted(set(pids)):
            root = Path(f"/proc/{pid}/task")
            try:
                tids = sorted(int(path.name) for path in root.iterdir())
            except OSError as error:
                result["tasks"].append({"side": side, "pid": pid,
                                        "status": type(error).__name__})
                continue
            for tid in tids:
                result["tasks"].append({"side": side, "pid": pid, "tid": tid,
                                        "enumerated_threads": len(tids),
                                        **task_sample(root / str(tid))})
    result["end_monotonic_ns"] = time.monotonic_ns()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cpus", type=cpu_list)
    parser.add_argument("client_namespace")
    parser.add_argument("server_namespace")
    args = parser.parse_args()
    sides = {}
    for side, namespace in (("client", args.client_namespace), ("server", args.server_namespace)):
        found = subprocess.run(["/usr/bin/ip", "netns", "pids", namespace],
                               check=True, capture_output=True, text=True, timeout=5)
        sides[side] = [int(pid) for pid in found.stdout.split()]
    print(json.dumps(snapshot(args.cpus, sides), sort_keys=True))


if __name__ == "__main__":
    main()
