"""Reproduce derived CPU evidence; original collector INVALID is preserved."""
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT.parents[2] / "crates/everudp/tests/net"))
from parse_cpu_samples import parse, correlate
from clock_alignment import _validated_boundaries, _identity
from analyze_poll_turns import _sample_check


def read(name):
    return json.loads((ROOT / name).read_text())


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def analyze():
    for name, expected in read("helper-hashes.json").items():
        assert digest(ROOT.parents[2] / "crates/everudp/tests/net" / name) == expected
    inventory = ROOT / "original-SHA256SUMS"
    assert digest(inventory) == "baf38fb7f5a8e580bc41f7e3ba8950804509261ab60f23f5b94067f31ce94495"
    hashes = {}
    for line in inventory.read_text().splitlines():
        value, name = line.split(maxsplit=1)
        hashes[name.removeprefix("./")] = value
    for path in (ROOT / "capture").rglob("*"):
        if path.is_file():
            assert digest(path) == hashes[path.relative_to(ROOT / "capture").as_posix()]
    receipt = read("capture/receipt.json")
    assert receipt == {"status": "INVALID", "production_qualification": False,
                       "reason": "ValueError: lost samples"}
    scope = read("capture/scope.json")
    assert scope["before"] == read("capture/scope-after.json")["after"]
    provenance = read("capture/build-provenance.json")
    assert provenance["source"]["head_sha"] == "bd53692a23e498408f55ee30b03309017a923a4c"
    assert provenance["everudp_build"]["cargo_features"] == ["cli"]
    result = read("capture/measurement/everudp/result.json")
    trials, bounds = _validated_boundaries(result)
    _sample_check(result, bounds)
    assert trials == 600
    clock = _identity(result["clock_identity"], "public")
    assert clock["boot_id"] == scope["boot_id"]
    for target in scope["before"].values():
        assert target["namespace"] == [clock["time_namespace_dev"], clock["time_namespace_ino"]]
        assert target["affinity"] == [40, 42, 44, 46]
    attrs = (ROOT / "events-attributes.txt").read_text().strip().splitlines()
    assert len(attrs) == 2
    for line, kind, excluded in zip(attrs, ("u", "k"), ("kernel", "user")):
        assert line.startswith("cpu-clock:" + kind + ":")
        for token in ("sample_freq }: 4999", "use_clockid: 1", "clockid: 1",
                      "exclude_" + excluded + ": 1", "type: 1 (PERF_TYPE_SOFTWARE)",
                      "config: 0 (PERF_COUNT_SW_CPU_CLOCK)"):
            assert token in line
        assert "inherit: 1" not in line
    samples = parse((ROOT / "samples.txt").read_text(),
                    {v["pid"]: v["tids"] for v in scope["before"].values()})
    assert len(samples) == 2136
    report = correlate(samples, bounds, {v["pid"]: role for role, v in scope["before"].items()})
    report["original_collector_status"] = "INVALID"
    report["interpretation"] = "leaf sample counts, not exclusive CPU time or causal savings"
    return report


if __name__ == "__main__":
    print(json.dumps(analyze(), indent=2, sort_keys=True))
