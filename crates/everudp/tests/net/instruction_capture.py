"""Instruction-weighted leaf sampling, without stacks, registers or payloads."""
import re
import signal
import subprocess

from perf_counter_control import CounterSession, counter_command


def instruction_command(base, tid, directory, budget_ms):
    counter_command(base, tid, directory, budget_ms)  # Shared scope/budget validation.
    return [*base, "record", "--no-inherit", "--no-buildid-cache", "--clockid", "mono",
            "-T", "--delay=-1", "-e", "instructions:u", "-c", "10000", "-t", str(tid),
            "--control", f"fifo:{directory / 'control'},{directory / 'ack'}",
            "-o", str(directory / "private-perf.data"), "--", "/usr/bin/sleep", str(budget_ms / 1000)]


def validate_attributes(text):
    lines = text.splitlines()
    if (len(lines) != 2 or not lines[0].startswith("instructions:u:")
            or not lines[1].startswith("dummy:u: type: 1 (PERF_TYPE_SOFTWARE)")
            or "config: 0x9 (PERF_COUNT_SW_DUMMY)" not in lines[1]):
        raise ValueError("unexpected instruction sample event")
    for line in lines:
        validate_event_fields(line)


def validate_event_fields(text):
    for field in ("sample_type: IP|TID|TIME|ID", "exclude_kernel: 1", "exclude_hv: 1",
                  "{ sample_period, sample_freq }: 10000", "use_clockid: 1", "clockid: 1"):
        if not re.search(r"(?:^|, )" + re.escape(field) + r"(?:,|$)", text):
            raise ValueError("instruction event attributes do not match capture contract")
    if re.search(r"(?:^|, )(?:inherit|freq): 1(?:,|$)", text):
        raise ValueError("instruction recording inherited or frequency-scaled")
    sample_type = re.search(r"sample_type: ([^,]+)", text)
    if sample_type is None or sample_type[1] != "IP|TID|TIME|ID":
        raise ValueError("unexpected or sensitive sample fields")


class InstructionSession(CounterSession):
    command_builder = staticmethod(instruction_command)
    # perf record finalizes its bounded sleep workload with TERM after the
    # acknowledged disable and our SIGINT; verified on installed perf 7.1.13.
    final_exit_codes = (*CounterSession.final_exit_codes, -signal.SIGTERM)

    def __init__(self, base, tid, directory, budget_ms=60000):
        self.base, self.tid = base, tid
        super().__init__(base, tid, directory, budget_ms)

    def result(self):
        from parse_instruction_samples import parse
        code = self.finalize()
        attrs = subprocess.run([*self.base, "evlist", "-v", "-i", str(self.directory / "private-perf.data")],
                               capture_output=True, text=True, check=True, timeout=10)
        (self.directory / "event-attributes.txt").write_text(attrs.stdout)
        validate_attributes(attrs.stdout)
        decoded = subprocess.run([*self.base, "script", "--show-lost-events", "--ns", "-i",
                                  str(self.directory / "private-perf.data"),
                                  "-F", "pid,tid,time,event,ip,sym,dso"],
                                 capture_output=True, text=True, check=True, timeout=10)
        (self.directory / "decode.log").write_text(decoded.stderr)
        if decoded.stderr.strip():
            raise ValueError("instruction decoder reported warnings")
        samples = parse(decoded.stdout, {self.tid: [self.tid]})
        return {"diagnostic_only": True, "scope": "selected-main-thread-user-instructions",
                "period": 10000, "control": self.transitions, "exit_code": code, "samples": samples}
