#!/usr/bin/env python3
"""Compile and exercise the allocation-free PTY echo benchmark fixture."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


NET = Path(__file__).resolve().parent


class PtyEchoFixtureTest(unittest.TestCase):
    def test_echoes_input_byte_for_byte(self) -> None:
        with tempfile.TemporaryDirectory(prefix="everudp-pty-echo-") as raw:
            binary = Path(raw) / "pty-echo"
            compiled = subprocess.run(
                [
                    "/usr/bin/cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(NET / "pty-echo.c"),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            payload = bytes(range(256)) * 257
            completed = subprocess.run(
                [str(binary)],
                input=payload,
                check=False,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(completed.stdout, payload)


if __name__ == "__main__":
    unittest.main()
