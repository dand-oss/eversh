#!/usr/bin/env python3
"""One frozen reliable-stream comparison; never production acceptance."""
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import signal
import subprocess
import sys

from stream_floor_blocks import validate_block
from stream_floor_evidence import digest, hex_id, read_json, require, sealed, validate_build, validate_preflight
from stream_floor_statistics import CANDIDATES, analyze

NET = Path(__file__).resolve().parent
ROOT = NET.parents[3]
TESTS = ("stream_floor_admission", "stream_floor_io", "stream_floor_native",
         "stream_floor_native_echo", "stream_floor_native_run", "stream_floor_ordinary")


def source_identity():
    def git(*args):
        return subprocess.check_output(["git", "-C", str(ROOT), *args], text=True).strip()
    require(not git("status", "--porcelain=v1", "--untracked-files=all"), "dirty candidate worktree")
    return {"head_sha": git("rev-parse", "HEAD"), "tree_sha": git("rev-parse", "HEAD^{tree}")}


def validate_plan(plan):
    require(set(plan) == {"schema_version", "purpose", "source", "build_provenance_sha256",
                         "preflight_seal_sha256", "affinity", "governors", "mtu", "seeds", "bead"}, "wrong frozen plan fields")
    require(type(plan["schema_version"]) is int and plan["schema_version"] == 1
            and plan["purpose"] == "matched-reliable-stream-floor" and plan["bead"] == "eversh-5fc.52", "wrong frozen plan identity")
    require(isinstance(plan["source"], dict) and set(plan["source"]) == {"head_sha", "tree_sha"}
            and all(hex_id(value, 40) for value in plan["source"].values()), "invalid frozen source")
    require(all(hex_id(plan[key], 64) for key in ("build_provenance_sha256", "preflight_seal_sha256")), "invalid frozen evidence hashes")
    require(isinstance(plan["affinity"], str) and re.fullmatch(r"[0-9]+(?:,[0-9]+)*", plan["affinity"]), "invalid affinity")
    cpus = plan["affinity"].split(",")
    require(len(cpus) == len(set(cpus)) and all(str(int(cpu)) == cpu for cpu in cpus), "duplicate or noncanonical CPUs")
    require(isinstance(plan["governors"], str) and len(plan["governors"].splitlines()) == len(cpus), "missing governors")
    for cpu, line in zip(cpus, plan["governors"].splitlines()):
        require(line in (f"cpu{cpu} performance", f"cpu{cpu} unavailable"), "governor must be performance or explicitly unavailable")
    require(plan["governors"].endswith("\n") and type(plan["mtu"]) is int and plan["mtu"] == 1500, "wrong frozen environment")
    seeds = plan["seeds"]
    require(isinstance(seeds, list) and len(seeds) == 4
            and all(type(seed) is int and 1 <= seed <= 2146483643 for seed in seeds), "invalid frozen seeds")
    require(len(set(seeds + [seed + 1_000_003 for seed in seeds])) == 8, "overlapping directional seeds")
    return plan


def schedule(plan):
    return [{"name": f"loss{loss}-block{index + 1}", "loss": loss, "seed": plan["seeds"][cell * 2 + index],
             "order": CANDIDATES if index == 0 else tuple(reversed(CANDIDATES))}
            for cell, loss in enumerate((0, 5)) for index in range(2)]


def block_command(build, out, item):
    return [str(NET / "bench-performance-block.sh"), "200", str(item["loss"]), str(item["seed"]),
            str(out / item["name"]), ",".join(item["order"])]


def write_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, indent=2, sort_keys=True, allow_nan=False)
        stream.write("\n")


def seal_output(out):
    # Nested seals are evidence too; exclude only this root's own seal.
    files = []
    for path in sorted(out.rglob("*")):
        require(not path.is_symlink(), "cannot seal linked evidence")
        if path.is_dir():
            continue
        require(path.is_file() and path != out / "SHA256SUMS", "cannot overwrite evidence seal")
        files.append(path)
    with (out / "SHA256SUMS").open("x") as stream:
        stream.writelines(f"{digest(path)}  {path.relative_to(out).as_posix()}\n" for path in files)
    sealed(out)


def run_command(command, out, label, env):
    """Keep logs private and terminate only our own process group on interruption."""
    with (out / f"{label}.stdout").open("xb") as stdout, (out / f"{label}.stderr").open("xb") as stderr:
        process = subprocess.Popen(command, cwd=ROOT, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        try:
            code = process.wait()
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            raise
    write_json(out / f"{label}.command.json", {"argv": command, "exit_code": code})
    require(code == 0, f"{label} failed with exit {code}; inspect private logs")


def receipt(plan, status, reason=None, analysis=None):
    result = {"schema_version": 1, "purpose": "matched-reliable-stream-floor", "status": status,
              "candidate": plan.get("source"), "finished_utc": datetime.now(timezone.utc).isoformat(),
              "production_qualification": False, "production_actor_integration_authorized": False,
              "integration_proposal_eligible": status == "PASS"}
    if reason:
        result["reason"] = reason
    if analysis is not None:
        result["quantitative_gate_status"] = analysis["quantitative_gate_status"]
    return result


def qualify(build_root, preflight_root, plan_path, out, run_user):
    # An existing result is never retried or overwritten by this invocation.
    out.mkdir(mode=0o700, parents=False, exist_ok=False)
    account = pwd.getpwnam(run_user)
    os.chown(out, account.pw_uid, account.pw_gid)
    plan, status, analysis = {}, "INVALID", None
    try:
        plan = validate_plan(read_json(plan_path))
        write_json(out / "frozen-plan.json", plan)
        require(source_identity() == plan["source"], "frozen source mismatch")
        require(digest(build_root / "provenance.json") == plan["build_provenance_sha256"]
                and digest(preflight_root / "SHA256SUMS") == plan["preflight_seal_sha256"], "frozen evidence identity mismatch")
        build = validate_build(build_root, plan["source"]["head_sha"], plan["source"]["tree_sha"], ROOT)
        try:
            validate_preflight(preflight_root, build, ROOT)
        except ValueError as error:
            if str(error).startswith(("built profile parity mismatch", "missing locked profile setting:",
                                      "wrong bidirectional stream limit", "invalid initial socket cap")):
                status = "HOLD"
            raise
        shutil.copytree(preflight_root, out / "preflight")
        write_json(out / "build-provenance.json", build)
        write_json(out / "input-identities.json", {"build_root": str(build_root), "preflight_root": str(preflight_root),
                   "plan_sha256": digest(plan_path), "build_seal_sha256": digest(build_root / "SHA256SUMS"),
                   "preflight_seal_sha256": digest(preflight_root / "SHA256SUMS")})
        env = {key: value for key, value in os.environ.items() if not key.startswith("EVERUDP_")}
        env.update(PYTHONDONTWRITEBYTECODE="1", EVERUDP_PERF_BUILD=str(build_root), EVERUDP_BENCH_CPUSET=plan["affinity"], SUDO_USER=run_user)
        require(set(map(int, plan["affinity"].split(","))).issubset(os.sched_getaffinity(0)), "frozen CPUs unavailable")
        cargo = shutil.which("cargo")
        require(cargo is not None, "cargo unavailable for untimed correctness gates")
        test_args = [cargo, "test", "--locked", "-p", "everudp", "--no-default-features", "--features", "cli,stream-floor",
                     "--lib", "--example", "everudp-stream-floor"]
        for test in TESTS:
            test_args += ["--test", test]
        print("Running untimed stream correctness gates", flush=True)
        run_command(["/usr/bin/sudo", "-u", run_user, "--", *test_args], out, "correctness", env)
        summaries = re.findall(r"test result: ok\. (\d+) passed; 0 failed;", (out / "correctness.stdout").read_text())
        require(len(summaries) == len(TESTS) + 2 and all(int(count) > 0 for count in summaries), "missing correctness targets")
        require(source_identity() == plan["source"], "source changed during correctness gates")
        for item in schedule(plan):
            print(f"Running frozen {item['name']} (200 trials per candidate)", flush=True)
            run_command(block_command(build_root, out, item), out, item["name"], env)
            require(source_identity() == plan["source"], "source changed during timing")
        # All heavy analysis waits until the final timed block has finished.
        validate_build(build_root, plan["source"]["head_sha"], plan["source"]["tree_sha"], ROOT)
        blocks = [validate_block(out / item["name"], build_root, build, loss=item["loss"], seed=item["seed"],
                                 order=item["order"], affinity=plan["affinity"], governors=plan["governors"], mtu=plan["mtu"])
                  for item in schedule(plan)]
        analysis = analyze(blocks)
        write_json(out / "analysis.json", analysis)
        status = "PASS" if analysis["quantitative_gate_status"] == "PASS" else "NOT-ADOPTED"
        result = receipt(plan, status, analysis=analysis)
    except (Exception, KeyboardInterrupt) as error:
        result = receipt(plan, status, reason=f"{type(error).__name__}: {error}")
    write_json(out / "receipt.json", result)
    seal_output(out)
    for path in out.rglob("*"):
        os.chown(path, account.pw_uid, account.pw_gid)
    print(f"Reliable-stream experiment {result['status']}: {out}", flush=True)
    return 0 if result["status"] == "PASS" else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("build", "preflight", "plan", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--run-user", required=True)
    args = parser.parse_args()
    require(os.geteuid() == 0, "requires root for private network namespaces")
    require(pwd.getpwnam(args.run_user).pw_uid != 0, "run-user must be unprivileged")
    os.umask(0o077)
    def interrupted(signum, _frame):
        raise KeyboardInterrupt(f"signal {signum}")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, interrupted)
    return qualify(args.build.resolve(strict=True), args.preflight.resolve(strict=True),
                   args.plan.resolve(strict=True), args.output.absolute(), args.run_user)


if __name__ == "__main__":
    sys.exit(main())
