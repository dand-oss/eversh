"""One bounded hardware or scheduler diagnostic block, not qualification.

Count selected client main-thread user-space work over the entire post-warmup
public window, including idle periods. This is not per-keystroke exclusive CPU
time or evidence that observed work can be removed. Scheduler mode instead
tracks sealed client/server/fixture threads. No payload or argv export.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

from capture_native_poll import identity, targets
from perf_counter_control import CounterSession
from host_snapshot import task_sample


def scheduler_scope(bookend, binaries, samefile=os.path.samefile, sample=task_sample):
    """Select sealed-binary threads only within the owned benchmark namespaces."""
    selected = []
    for row in bookend["tasks"]:
        if row["status"] != "available":
            continue
        for name, binary in binaries.items():
            try:
                matches = samefile(f"/proc/{row['pid']}/exe", binary)
            except (FileNotFoundError, ProcessLookupError, PermissionError):
                continue
            if matches:
                current = sample(Path(f"/proc/{row['pid']}/task/{row['tid']}"))
                if current.get("start_ticks") != row["start_ticks"]:
                    raise ValueError("scheduler target identity changed before capture")
                selected.append({**row, "binary": name})
                break
    if {row["binary"] for row in selected} != set(binaries):
        raise ValueError("scheduler scope is missing a required binary")
    if len({row["tid"] for row in selected}) != len(selected):
        raise ValueError("duplicate scheduler thread identity")
    return selected


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def wait_marker(path, process, budget):
    deadline = time.monotonic() + budget
    while not path.is_file():
        if process.poll() is not None:
            raise ValueError("benchmark ended before counter barrier")
        if time.monotonic() >= deadline:
            raise TimeoutError("benchmark counter barrier timed out")
        time.sleep(.01)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--perf", type=Path, required=True)
    parser.add_argument("--perf-libs", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--loss", type=int, choices=(0, 5), required=True)
    parser.add_argument("--reverse", action="store_true")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--instructions", action="store_true",
                        help="record instruction-weighted leaves instead of aggregate counters")
    mode.add_argument("--scheduler", action="store_true",
                      help="record scoped client/server/fixture scheduling over the public window")
    args = parser.parse_args()
    repo = Path(__file__).resolve().parents[4]
    build = args.build.resolve()
    out = args.out.resolve()
    if subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip() != args.head:
        raise ValueError("harness SHA mismatch")
    if subprocess.check_output(["git", "status", "--porcelain"], cwd=repo):
        raise ValueError("harness source must be clean")
    provenance = json.loads((build / "provenance.json").read_text())
    subprocess.run(["sha256sum", "--quiet", "-c", "SHA256SUMS"], cwd=build, check=True)
    if subprocess.check_output(["git", "diff", provenance["source"]["head_sha"], args.head, "--",
        "Cargo.toml", "Cargo.lock", "vendor", "crates/everudp/Cargo.toml", "crates/everudp/src",
        "crates/everudp/examples", "crates/everssh", "crates/everpty"], cwd=repo):
        raise ValueError("runtime inputs changed since sealed build")
    roles = {"everudp": "production-client", "zmosh-udp": "attach"}
    order = ["everudp", "zmosh-udp", "zmosh-quic"]
    if args.reverse:
        order.reverse()
    for name, role in roles.items():
        if targets(build / "artifacts/bin" / name, role):
            raise ValueError("existing target process")
    out.mkdir(mode=0o700)
    base = ["sudo", "-n", "env", f"LD_LIBRARY_PATH={args.perf_libs.resolve()}",
            "DEBUGINFOD_URLS=", str(args.perf.resolve())]
    command = ["sudo", "-n", "env", f"EVERUDP_PERF_BUILD={build}",
               "EVERUDP_COUNTER_CAPTURE=1", "EVERUDP_BENCH_CPUSET=40,42,44,46",
               "EVERUDP_PATH_TRACE=0", "EVERUDP_PATH_IO_TRACE=0", "EVERUDP_PATH_PACKET_TRACE=0",
               "EVERUDP_FLOOR_TRACE=0", "EVERUDP_FLOOR_NATIVE_TRACE=0",
               "EVERUDP_FLOOR_REACTOR_TRACE=0", "EVERUDP_FLOOR_PARTITION_TRACE=0",
               "bash", str(repo / "crates/everudp/tests/net/bench-performance-block.sh"),
               "200", str(args.loss), str(args.seed), str(out / "measurement"), ",".join(order)]
    report = {"diagnostic_only": True, "qualification": False, "status": "FAILED",
              "mode": "scheduler" if args.scheduler else "instruction-leaves" if args.instructions else "aggregate-counters",
              "harness_sha": args.head, "runtime_sha": provenance["source"]["head_sha"],
              "provenance_sha256": digest(build / "provenance.json"),
              "perf_sha256": digest(args.perf), "order": order, "clients": {}}
    with (out / "benchmark.log").open("w") as log:
        bench = subprocess.Popen(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT)
        try:
            for name in order:
                window = out / "measurement" / name / "window"
                wait_marker(window / "counter-start.ready", bench, 90)
                if name not in roles:
                    (window / "counter-start.go").touch()
                    wait_marker(window / "counter-stop.ready", bench, 60)
                    (window / "counter-stop.go").touch()
                    continue
                binary = build / "artifacts/bin" / name
                selected = targets(binary, roles[name])
                if len(selected) != 1:
                    raise ValueError("target missing or ambiguous")
                tid = selected[0]
                before = identity(tid)
                if before["time_namespace"] != identity(os.getpid())["time_namespace"]:
                    raise ValueError("target clock namespace mismatch")
                scope = None
                capture_target = tid
                if args.scheduler:
                    from scheduler_capture import SchedulerSession
                    bookend = json.loads((window.parent / "host-before.json").read_text())
                    binaries = {label: build / "artifacts/bin" / label
                                for label in (name, "pty-bench", "pty-echo")}
                    scope = scheduler_scope(bookend, binaries)
                    process_scope = {pid: identity(pid) for pid in {row["pid"] for row in scope}}
                    if any(item["time_namespace"] != before["time_namespace"]
                           for item in process_scope.values()):
                        raise ValueError("scheduler target clock namespace mismatch")
                    capture_target = [row["tid"] for row in scope]
                    session_type = SchedulerSession
                elif args.instructions:
                    from instruction_capture import InstructionSession
                    session_type = InstructionSession
                else:
                    session_type = CounterSession
                with session_type(base, capture_target, out / f"{name}-counters") as capture:
                    capture.enable()
                    (window / "counter-start.go").touch()
                    wait_marker(window / "counter-stop.ready", bench, 50)
                    capture.disable()
                    after = identity(tid)
                    if before != after or not os.path.samefile(f"/proc/{tid}/exe", binary):
                        raise ValueError("target identity changed")
                    if scope is not None:
                        if any(identity(pid) != item for pid, item in process_scope.items()):
                            raise ValueError("scheduler process thread set or identity changed")
                        for row in scope:
                            current = task_sample(Path(f"/proc/{row['pid']}/task/{row['tid']}"))
                            if (current.get("start_ticks") != row["start_ticks"] or
                                    not os.path.samefile(f"/proc/{row['pid']}/exe", binaries[row["binary"]])):
                                raise ValueError("scheduler target identity changed during capture")
                    result = capture.result()
                    report["clients"][name] = {"before": before, "after": after,
                        "binary_sha256": digest(binary), "capture": result}
                    if scope is not None:
                        report["clients"][name]["scheduler_scope"] = scope
                        report["clients"][name]["scheduler_processes"] = process_scope
                    (window / "counter-stop.go").touch()
            if bench.wait(timeout=30) != 0:
                raise ValueError("benchmark failed")
            manifest = json.loads((out / "measurement/manifest.json").read_text())
            if not manifest["diagnostic_tracing"] or not manifest["hardware_counter_capture"]:
                raise ValueError("capture was not marked diagnostic")
            report["status"] = "CAPTURED"
        finally:
            if bench.poll() is None:
                bench.terminate()
                bench.wait(timeout=30)
            report["benchmark_exit_code"] = bench.returncode
            (out / "capture.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
