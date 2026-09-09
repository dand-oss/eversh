from pathlib import Path
import unittest

from instruction_capture import instruction_command, validate_attributes

ATTRIBUTES = """instructions:u: type: 4 (cpu), size: 144, config: 0xc0 (inst_retired.any), { sample_period, sample_freq }: 10000, sample_type: IP|TID|TIME|ID, read_format: ID|LOST, disabled: 1, exclude_kernel: 1, exclude_hv: 1, sample_id_all: 1, use_clockid: 1, clockid: 1
dummy:u: type: 1 (PERF_TYPE_SOFTWARE), size: 144, config: 0x9 (PERF_COUNT_SW_DUMMY), { sample_period, sample_freq }: 10000, sample_type: IP|TID|TIME|ID, read_format: ID|LOST, disabled: 1, exclude_kernel: 1, exclude_hv: 1, mmap: 1, comm: 1, enable_on_exec: 1, task: 1, sample_id_all: 1, exclude_guest: 1, mmap2: 1, comm_exec: 1, use_clockid: 1, ksymbol: 1, bpf_event: 1, build_id: 1, clockid: 1
"""


class InstructionCaptureTests(unittest.TestCase):
    def test_actual_attributes_and_sensitive_or_wrong_configuration(self):
        validate_attributes(ATTRIBUTES)
        for text in (ATTRIBUTES.replace("clockid: 1", "clockid: 10"),
                     ATTRIBUTES.replace("sample_type: IP", "sample_type: RAW|IP"),
                     ATTRIBUTES.replace("10000", "100001"),
                     ATTRIBUTES + ATTRIBUTES,
                     ATTRIBUTES.replace("disabled: 1", "disabled: 1, inherit: 1")):
            with self.subTest(text=text), self.assertRaises(ValueError):
                validate_attributes(text)
    def test_instruction_recording_is_scoped_and_has_no_sensitive_samples(self):
        command = instruction_command(["perf"], 123, Path("/capture"), 60000)
        self.assertEqual(command[1], "record")
        self.assertEqual(command[command.index("-e") + 1], "instructions:u")
        self.assertEqual(command[command.index("-c") + 1], "10000")
        self.assertEqual(command[command.index("-t") + 1], "123")
        self.assertIn("--no-inherit", command)
        self.assertIn("--delay=-1", command)
        self.assertEqual(command[-3:], ["--", "/usr/bin/sleep", "60.0"])
        for forbidden in ("-a", "-g", "--call-graph", "--sample-cpu", "--user-regs", "--intr-regs", "-R"):
            self.assertNotIn(forbidden, command)

    def test_invalid_scope_and_lifetime_fail(self):
        for tid, budget in ((0, 60000), (1, 60001)):
            with self.assertRaises(ValueError):
                instruction_command(["perf"], tid, Path("/capture"), budget)


if __name__ == "__main__":
    unittest.main()
