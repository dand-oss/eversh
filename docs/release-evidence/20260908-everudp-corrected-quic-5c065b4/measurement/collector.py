"""Bounded adapter-correction measurement, explicitly not release qualification."""
import importlib.util
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import statistics
import sys

ROOT = Path("/home/appsmith/asv/ports/repo/eversh/.claude/worktrees/eversh-5fc-everudp-WORK")
NET = ROOT / "crates/everudp/tests/net"
sys.path.insert(0, str(NET))
from qualify_stream_floor import run_command, seal_output, source_identity, write_json
from stream_floor_evidence import digest, require, sealed
from stream_floor_blocks import public_samples
from packet_accounting import account_packet_attempts

BUILD = Path("/tmp/everudp-bridge-corrected-build-5c065b4")
OUT = Path("/tmp/everudp-corrected-control-5c065b4")
SOURCE = {"head_sha": "5c065b4024b6c14a117ebed516500b5a020b467f",
          "tree_sha": "e5f78f0145748ffa92e360b0dc02f5e8341acd81"}
NAMES = ("everudp", "zmosh-udp", "zmosh-quic")
SEEDS = (15000001, 15000002, 15050001, 15050002)

require(os.geteuid() == 0, "requires private netns privileges")
def interrupted(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")
for signum in (signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, interrupted)
os.umask(0o077)
OUT.mkdir(mode=0o700, exist_ok=False)
account = pwd.getpwnam("appsmith")
os.chown(OUT, account.pw_uid, account.pw_gid)
receipt = {"schema_version": 1, "purpose": "zmosh-quic-adapter-correction",
           "status": "INVALID", "production_qualification": False, "source": SOURCE}
try:
    require(source_identity() == SOURCE, "candidate changed")
    sealed(BUILD)
    provenance = json.loads((BUILD / "provenance.json").read_text())
    require(provenance["source"] == {**SOURCE, "clean": True}, "build source differs")
    write_json(OUT / "build-provenance.json", provenance)
    shutil.copyfile(__file__, OUT / "collector.py")
    plan = {"source": SOURCE, "seeds": list(SEEDS), "trials_per_name_per_block": 200,
            "affinity": "40,42,44,46", "gap_ms": 100, "losses": [0, 5],
            "orders": [list(NAMES), list(reversed(NAMES))],
            "purpose": receipt["purpose"], "production_qualification": False,
            "collector_sha256": digest(__file__), "build_provenance_sha256": digest(BUILD / "provenance.json")}
    write_json(OUT / "frozen-plan.json", plan)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("EVERUDP_")}
    environment.update(EVERUDP_PERF_BUILD=str(BUILD), EVERUDP_BENCH_CPUSET=plan["affinity"],
                       SUDO_USER="appsmith", PYTHONDONTWRITEBYTECODE="1")
    paths = []
    for ordinal, seed in enumerate(SEEDS):
        loss = 0 if ordinal < 2 else 5
        order = NAMES if ordinal % 2 == 0 else tuple(reversed(NAMES))
        label = f"loss{loss}-block{ordinal % 2 + 1}"
        path = OUT / label
        print("Running " + label, flush=True)
        run_command([str(NET / "bench-performance-block.sh"), "200", str(loss), str(seed), str(path), ",".join(order)],
                    OUT, label, environment)
        require(source_identity() == SOURCE, "source changed during measurement")
        paths.append((path, loss, seed, order))
    spec = importlib.util.spec_from_file_location("performance", NET / "analyze-performance.py")
    analyzer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(analyzer)
    cells = {str(loss): {name: [] for name in NAMES} for loss in (0, 5)}
    for path, loss, seed, order in paths:
        sealed(path)
        block = analyzer.load_block(path, 200)
        manifest = block["manifest"]
        require(manifest["source"] == {**SOURCE, "dirty": False}, "block source differs")
        require(manifest["order"] == list(order) and manifest["loss_percent_each_direction"] == loss
                and manifest["seeds"] == {"client": seed, "server": seed + 1000003}, "frozen schedule differs")
        require(manifest["build"]["provenance_sha256"] == plan["build_provenance_sha256"], "build receipt differs")
        require(manifest["affinity"] == plan["affinity"] and manifest["gap_ms"] == 100, "timing settings differ")
        require((path / "governors-pinned.txt").read_text() == "".join(f"cpu{cpu} performance\n" for cpu in (40,42,44,46)), "governor differs")
        for name, artifact in manifest["artifacts"].items():
            require(artifact["sha256"] == provenance["artifacts"][name]["sha256"], "binary differs")
        for name in NAMES:
            result = json.loads((path / name / "result.json").read_text())
            public_samples(result)
            snapshots = [path / f"netem-{name}-{side}-{phase}.txt" for side in ("client", "server") for phase in ("before", "after")]
            counters = account_packet_attempts(*(p.read_text() for p in snapshots))
            require(counters.total_attempts == manifest["loss_evidence"][name]["summed_egress_attempt_delta"], "packet summary differs")
            cells[str(loss)][name].extend(result["samples_us"])
    sealed(BUILD)
    summary = {loss: {name: {"samples": len(values), "p50_us": statistics.median(values),
                            "p95_us": sorted(values)[379]} for name, values in cell.items()}
               for loss, cell in cells.items()}
    write_json(OUT / "summary.json", {"purpose": receipt["purpose"], "production_qualification": False, "cells": summary})
    receipt["status"] = "MEASURED"
except (Exception, KeyboardInterrupt) as error:
    receipt["reason"] = f"{type(error).__name__}: {error}"
write_json(OUT / "receipt.json", receipt)
seal_output(OUT)
for path in OUT.rglob("*"):
    os.chown(path, account.pw_uid, account.pw_gid)
print(receipt["status"], str(OUT), flush=True)
sys.exit(0 if receipt["status"] == "MEASURED" else 1)
