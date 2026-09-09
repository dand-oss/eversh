"""Runner policy tests without privileged commands or timed experiments."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import pwd
import tempfile
import unittest
from unittest.mock import patch

import qualify_stream_floor as runner
from stream_floor_evidence import digest, sealed
from test_stream_floor_evidence import HEAD, TREE, make_build, make_preflight


class QualifierTests(unittest.TestCase):
    def fixture(self, root):
        build = make_build(root / "build")
        make_preflight(root / "preflight", build)
        cpu = min(os.sched_getaffinity(0))
        plan = {"schema_version": 1, "purpose": "matched-reliable-stream-floor", "bead": "eversh-5fc.52",
                "source": {"head_sha": HEAD, "tree_sha": TREE},
                "build_provenance_sha256": digest(root / "build/provenance.json"),
                "preflight_seal_sha256": digest(root / "preflight/SHA256SUMS"),
                "affinity": str(cpu), "governors": f"cpu{cpu} performance\n", "mtu": 1500,
                "seeds": [80001, 80002, 85001, 85002]}
        (root / "plan.json").write_text(json.dumps(plan))
        return plan

    def test_plan_rejects_overlap_shortcuts_and_unfrozen_fields(self):
        with tempfile.TemporaryDirectory() as raw:
            plan = self.fixture(Path(raw))
            self.assertEqual(runner.validate_plan(plan), plan)
            mutations = [lambda p: p.update(seeds=[1, 1000004, 3, 4]),
                         lambda p: p.update(seeds=[True, 2, 3, 4]),
                         lambda p: p.update(trials=2), lambda p: p.update(mtu=1280),
                         lambda p: p.update(governors="cpu0 powersave\n"),
                         lambda p: p.update(build_provenance_sha256="missing")]
            for mutation in mutations:
                altered = copy.deepcopy(plan)
                mutation(altered)
                with self.assertRaises(ValueError):
                    runner.validate_plan(altered)

    def run_fixture(self, root, plan, failure=None, numerical="PASS"):
        commands = []
        def execute(command, out, label, env):
            commands.append((command, label, env))
            if label == "correctness":
                (out / "correctness.stdout").write_text("test result: ok. 1 passed; 0 failed;\n" * 8)
            else:
                if failure is not None:
                    raise failure
                (out / label).mkdir()
                (out / label / "marker").write_text(label)
                runner.seal_output(out / label)
        with ExitStack() as stack:
            stack.enter_context(patch.object(runner, "source_identity", return_value=plan["source"]))
            stack.enter_context(patch.object(runner, "run_command", side_effect=execute))
            block = stack.enter_context(patch.object(runner, "validate_block", return_value="validated-block"))
            stack.enter_context(patch.object(runner, "analyze", return_value={"quantitative_gate_status": numerical}))
            code = runner.qualify(root / "build", root / "preflight", root / "plan.json", root / "out",
                                  pwd.getpwuid(os.getuid()).pw_name)
        return code, commands, block

    def test_one_four_block_run_and_floor_only_receipt(self):
        for numerical, expected in (("PASS", "PASS"), ("FAIL", "NOT-ADOPTED")):
            with self.subTest(numerical=numerical), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                plan = self.fixture(root)
                code, commands, block = self.run_fixture(root, plan, numerical=numerical)
                self.assertEqual(len(commands), 5)
                self.assertEqual(block.call_count, 4)
                for item, (command, label, env) in zip(runner.schedule(plan), commands[1:]):
                    self.assertEqual(command[1:4], ["200", str(item["loss"]), str(item["seed"])])
                    self.assertEqual(command[-1], ",".join(item["order"]))
                    self.assertEqual(env["EVERUDP_BENCH_CPUSET"], plan["affinity"])
                receipt = json.loads((root / "out/receipt.json").read_text())
                self.assertEqual(receipt["status"], expected)
                self.assertFalse(receipt["production_actor_integration_authorized"])
                self.assertFalse(receipt["production_qualification"])
                self.assertEqual(code, 0 if expected == "PASS" else 1)
                self.assertIn("loss0-block1/SHA256SUMS", sealed(root / "out"))

    def test_interruption_and_failure_seal_invalid_without_retry(self):
        for failure in (KeyboardInterrupt("test cancel"), ValueError("block failed")):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                plan = self.fixture(root)
                code, commands, block = self.run_fixture(root, plan, failure=failure)
                self.assertEqual(code, 1)
                self.assertEqual(len(commands), 2)
                block.assert_not_called()
                self.assertEqual(json.loads((root / "out/receipt.json").read_text())["status"], "INVALID")
                sealed(root / "out")
                with self.assertRaises(FileExistsError):
                    self.run_fixture(root, plan)

    def test_wrong_source_stops_before_commands(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            plan = self.fixture(root)
            plan["source"]["head_sha"] = "f" * 40
            (root / "plan.json").write_text(json.dumps(plan))
            code, commands, block = self.run_fixture(root, plan)
            self.assertEqual(code, 1)
            self.assertFalse(commands)
            block.assert_not_called()
            sealed(root / "out")


if __name__ == "__main__":
    unittest.main()
