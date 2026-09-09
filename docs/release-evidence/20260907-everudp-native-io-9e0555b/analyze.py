"""Validate and reproduce bounded syscall observations, never qualification."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root / "support"))
from io_trial_windows import analyze, analyze_client

runtime = "9b67a67a4834daea193af4e6a4270e6155dac048"
harness = "9e0555b19123f464894679bef06df7ce5abb20c2"
build_path = root / "build-provenance.json"
build = json.loads(build_path.read_text())
assert build["source"]["head_sha"] == runtime and build["source"]["clean"] is True
assert build["everudp_build"]["cargo_features"] == ["cli", "reliable-datagram-spike", "floor-single-owner"]
assert build["zmosh_source"]["commit"] == "dfc8395b5edcd237bf82712fbde879c6e8be7dfa"
events = [f"syscalls:sys_{edge}_{call}" for call in
          ("poll", "read", "sendmsg", "sendmmsg", "recvmsg", "recvmmsg", "sendto", "recvfrom")
          for edge in ("enter", "exit")] + ["raw_syscalls:sys_enter", "raw_syscalls:sys_exit"]
cells = {}
for loss, seed in ((0, 960701), (5, 965701)):
    directory = root / f"loss{loss}"
    receipt = json.loads((directory / "receipt.json").read_text())
    assert receipt["status"] == "DIAGNOSTIC_COMPLETE"
    assert receipt["source_build"] == build["source"] and receipt["harness_head"] == harness
    assert receipt["seed"] == seed and receipt["loss"] == loss and receipt["raw_perf_private"] is True
    measurement = directory / "measurement"
    subprocess.run(["sha256sum", "-c", "SHA256SUMS", "--quiet"], cwd=measurement, check=True)
    manifest = json.loads((measurement / "manifest.json").read_text())
    assert manifest["source"]["head_sha"] == harness and manifest["source"]["dirty"] is False
    assert manifest["seeds"] == {"client": seed, "server": seed + 1000003}
    assert manifest["loss_percent_each_direction"] == loss and manifest["trials_per_candidate"] == 200
    assert manifest["order"] == receipt["order"] == (["everudp-floor", "zmosh-udp"] if loss == 0 else ["zmosh-udp", "everudp-floor"])
    assert manifest["build"]["provenance_sha256"] == hashlib.sha256(build_path.read_bytes()).hexdigest()
    reports, pids = {}, set()
    for name, role in (("everudp-floor", "client"), ("everudp-floor", "server"), ("zmosh-udp", "client")):
        target = directory / f"{name}-{role}"
        capture = json.loads((target / "capture.json").read_text())
        assert capture["source_build"] == build["source"] and capture["harness_head"] == harness
        assert capture["events_file"] == "io-events.json"
        pid = capture["identity"]["pid"]
        assert pid not in pids
        pids.add(pid)
        command = capture["command"]
        assert [command[i + 1] for i, value in enumerate(command) if value == "-e"] == events
        filters = [command[i + 1] for i, value in enumerate(command) if value == "--filter"]
        assert filters == [f"common_pid == {pid}"] * 16 + [f"common_pid == {pid} && id == 1"] * 2
        attrs = (target / "events-attributes.txt").read_text().splitlines()
        assert all(line.startswith(("syscalls:", "raw_syscalls:", "dummy:u", "# Tip:")) for line in attrs)
        attrs = [line for line in attrs if line.startswith(("syscalls:", "raw_syscalls:"))]
        assert len(attrs) == 18 and [line.split(": type:", 1)[0] for line in attrs] == events
        assert all("use_clockid: 1" in line and "clockid: 1" in line for line in attrs)
        assert all("LOST" not in (target / file).read_text().upper() for file in ("record.log", "decode.log"))
        result = json.loads((measurement / name / "result.json").read_text())
        assert result["trials"] == 200 and result["transcript_failures"] == 0
        export = json.loads((target / "io-events.json").read_text())
        report = (analyze_client if role == "client" else analyze)(result, export, capture)
        assert report["status"] == "DIAGNOSTIC", report
        if role == "server":
            report = {key: value for key, value in report.items() if key != "rows"}
        reports[target.name] = report
    cells[str(loss)] = reports
print(json.dumps({"status": "DIAGNOSTIC", "qualification": "NOT_APPLICABLE",
                  "production_actor_integration_authorized": False, "cells": cells}, indent=2, sort_keys=True))
