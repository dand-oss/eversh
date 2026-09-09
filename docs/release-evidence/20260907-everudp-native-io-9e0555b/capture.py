"""Bounded external syscall diagnostics; never performance qualification.

Raw perf files remain in the supplied private output directory. Only sanitized
event text and explicitly selected process metadata may be archived.
"""
import argparse
import hashlib
import json
import os
import platform
from pathlib import Path
import re
import subprocess
import time

if __package__:
    from . import syscall_export
    from .syscall_pairs import pair_syscalls
else:
    import syscall_export
    from syscall_pairs import pair_syscalls


def identity(pid):
    proc = Path(f"/proc/{pid}")
    ns = (proc / "ns/time").stat()
    return {
        "pid": pid,
        "start_ticks": (proc / "stat").read_text().rsplit(")", 1)[1].split()[19],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "time_namespace": [ns.st_dev, ns.st_ino],
        "tids": sorted(int(p.name) for p in (proc / "task").iterdir()),
        "affinity": sorted(os.sched_getaffinity(pid)),
    }


def targets(binary, role):
    found = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            if not os.path.samefile(proc / "exe", binary):
                continue
            args = (proc / "cmdline").read_bytes().split(b"\0")
            if len(args) > 1 and args[1] == role.encode():
                found.append(int(proc.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--perf", type=Path, required=True)
    parser.add_argument("--perf-libs", type=Path, required=True)
    parser.add_argument("--head", required=True)
    parser.add_argument("--seed", type=int, required=True)
    parser.add_argument("--loss", choices=(0, 5), type=int, required=True)
    parser.add_argument("--reverse", action="store_true")
    parser.add_argument("--io", action="store_true",
                        help="export strict syscall fields to io-events.json")
    args = parser.parse_args()
    if args.io:
        assert platform.machine() == "x86_64", "raw write syscall number is x86_64-specific"
        for call in ("poll", "read", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "sendto", "recvfrom"):
            for edge in ("enter", "exit"):
                trace_format = subprocess.check_output([
                    "sudo", "-n", "head", "-c", "32768",
                    f"/sys/kernel/tracing/events/syscalls/sys_{edge}_{call}/format"])
                assert b"__data_loc" not in trace_format, "augmented tracepoint would capture payload"
    repo = Path(__file__).resolve().parents[4]
    build = args.build.resolve()
    out = args.out.resolve()
    assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip() == args.head
    assert not subprocess.check_output(["git", "status", "--porcelain"], cwd=repo)
    provenance = json.loads((build / "provenance.json").read_text())
    subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=build, check=True)
    # The harness may be newer, but no runtime or dependency input may drift.
    assert not subprocess.check_output([
        "git", "diff", provenance["source"]["head_sha"], args.head, "--",
        "Cargo.toml", "Cargo.lock", "vendor", "crates/everudp/src",
        "crates/everudp/examples", "crates/everssh", "crates/everpty"], cwd=repo)
    out.mkdir(mode=0o700)
    base = ["sudo", "-n", "env", f"LD_LIBRARY_PATH={args.perf_libs.resolve()}",
            "DEBUGINFOD_URLS=", str(args.perf.resolve())]
    roles = {"everudp-floor": [("client", "client"), ("server", "__floor-server-v1")],
             "zmosh-udp": [("client", "attach")]}
    order = ["everudp-floor", "zmosh-udp"]
    if args.reverse:
        order.reverse()
    for name in order:
        for _, role in roles[name]:
            assert not targets(build / "artifacts/bin" / name, role), "existing target process"
    command = ["sudo", "-n", "env", f"EVERUDP_PERF_BUILD={build}", "bash",
               str(repo / "crates/everudp/tests/net/bench-performance-block.sh"),
               "200", str(args.loss), str(args.seed), str(out / "measurement"), ",".join(order)]
    with (out / "benchmark.log").open("w") as log:
        bench = subprocess.Popen(command, cwd=repo, stdout=log, stderr=subprocess.STDOUT)
        completed = False
        try:
            for name in order:
                deadline = time.monotonic() + 90
                while True:
                    assert bench.poll() is None, "benchmark ended before capture"
                    assert time.monotonic() < deadline, "target discovery timeout"
                    selected = [(label, targets(build / "artifacts/bin" / name, role))
                                for label, role in roles[name]]
                    assert all(len(pids) <= 1 for _, pids in selected), "ambiguous target"
                    if all(pids for _, pids in selected) and (out / "measurement" / name / "window/start.go").exists():
                        break
                    time.sleep(.01)
                captures = []
                for label, pids in selected:
                    pid = pids[0]
                    directory = out / f"{name}-{label}"
                    directory.mkdir(mode=0o700)
                    before = identity(pid)
                    assert before["time_namespace"] == identity(os.getpid())["time_namespace"]
                    record = base + ["record", "-a", "--synth", "no", "--clockid", "mono"]
                    syscalls = ("poll", "read", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "sendto", "recvfrom") if args.io else ("poll", "read")
                    for event in syscalls:
                        for edge in ("enter", "exit"):
                            record += ["-e", f"syscalls:sys_{edge}_{event}", "--filter", f"common_pid == {pid}"]
                    if args.io:
                        for edge in ("enter", "exit"):
                            record += ["-e", f"raw_syscalls:sys_{edge}", "--filter",
                                       f"common_pid == {pid} && id == 1"]
                    record += ["-o", str(directory / "perf.data"), "--", "/usr/bin/sleep", "10"]
                    record_log = (directory / "record.log").open("w")
                    process = subprocess.Popen(record, stdout=record_log, stderr=subprocess.STDOUT)
                    captures.append((process, record_log, directory, before, record))
                for process, record_log, directory, before, record in captures:
                    try:
                        assert process.wait(timeout=20) == 0, "perf capture failed"
                    finally:
                        record_log.close()
                    assert identity(before["pid"]) == before, "PID/clock/thread identity changed"
                    decoded = subprocess.run(base + ["script", "--show-lost-events", "--ns", "-i",
                        str(directory / "perf.data"), "-F", "time,event,trace"], capture_output=True, text=True, check=True)
                    if args.io:
                        exported = syscall_export.parse(decoded.stdout)
                        # Validate single-thread enter/exit structure before
                        # persisting the scalar export; pair output is a
                        # diagnostic derivation, not part of the wire schema.
                        pair_syscalls(exported)
                        (directory / "io-events.json").write_text(
                            json.dumps(exported, separators=(",", ":"), sort_keys=True) + "\n"
                        )
                    else:
                        safe = re.sub(r"(?:buf|ufds): 0x[0-9a-fA-F]+, ", "", decoded.stdout)
                        assert "LOST" not in safe.upper(), "lost events invalidate capture"
                        (directory / "events.txt").write_text(safe)
                    (directory / "decode.log").write_text(decoded.stderr)
                    attrs = subprocess.run(base + ["evlist", "-v", "-i", str(directory / "perf.data")],
                        capture_output=True, text=True, check=True)
                    (directory / "events-attributes.txt").write_text(attrs.stdout)
                    metadata = {"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                        "identity": before, "source_build": provenance["source"], "harness_head": args.head,
                        "clock": "CLOCK_MONOTONIC", "duration_seconds": 10, "command": record,
                        "perf_sha256": hashlib.sha256(args.perf.read_bytes()).hexdigest(),
                        "scope": ("PID-filtered poll/read/write/sendmsg/sendmmsg/recvmsg/recvmmsg boundaries; "
                                  "write via raw syscall NR1; strict scalar export; pointers and payloads omitted" if args.io else
                                  "PID-filtered poll/read boundaries; no payloads; exported pointer fields removed"),
                        "events_file": "io-events.json" if args.io else "events.txt"}
                    (directory / "capture.json").write_text(json.dumps(metadata, indent=2) + "\n")
                    print("captured", directory.name, flush=True)
            assert bench.wait(timeout=90) == 0, "benchmark failed"
            completed = True
        finally:
            try:
                if bench.poll() is None:
                    bench.terminate()
                    bench.wait(timeout=30)
            finally:
                (out / "receipt.json").write_text(json.dumps({
                    "status": "DIAGNOSTIC_COMPLETE" if completed else "INVALID",
                    "production_actor_integration_authorized": False,
                    "source_build": provenance["source"], "harness_head": args.head,
                        "seed": args.seed, "loss": args.loss, "order": order,
                    "io": args.io,
                    "raw_perf_private": True,
                }, indent=2) + "\n")


if __name__ == "__main__":
    main()
