#!/usr/bin/env python3
"""Compile and exercise the zmosh benchmark's exact transcript oracle."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


NET = Path(__file__).resolve().parent


class TranscriptOracleTest(unittest.TestCase):
    def test_exact_one_byte_transcript_is_the_only_success(self) -> None:
        source = r'''
#include "zmosh-transcript.h"

#include <stdint.h>

static int expect_status(
    const uint8_t expected,
    const uint8_t *first,
    const size_t first_len,
    const uint8_t *second,
    const size_t second_len,
    const everudp_transcript_status wanted
) {
    everudp_transcript transcript;
    everudp_transcript_begin(&transcript, expected);
    if (first_len != 0) {
        (void)everudp_transcript_feed(&transcript, first, first_len);
    }
    if (second_len != 0) {
        (void)everudp_transcript_feed(&transcript, second, second_len);
    }
    return everudp_transcript_finish(&transcript) == wanted ? 0 : 1;
}

int main(void) {
    const uint8_t a[] = {'a'};
    const uint8_t b[] = {'b'};
    const uint8_t wrong_then_expected[] = {'x', 'a'};
    uint8_t oversized[EVERUDP_TRANSCRIPT_CAP + 1] = {0};

    if (expect_status('a', a, 1, NULL, 0, EVERUDP_TRANSCRIPT_MATCH) != 0) return 1;
    if (expect_status('a', NULL, 0, NULL, 0, EVERUDP_TRANSCRIPT_WAITING) != 0) return 2;
    if (expect_status('a', b, 1, NULL, 0, EVERUDP_TRANSCRIPT_INVALID) != 0) return 3;
    if (expect_status('a', wrong_then_expected, 2, NULL, 0, EVERUDP_TRANSCRIPT_INVALID) != 0) return 4;
    if (expect_status('a', a, 1, b, 1, EVERUDP_TRANSCRIPT_INVALID) != 0) return 5;
    if (expect_status('a', a, 1, a, 1, EVERUDP_TRANSCRIPT_INVALID) != 0) return 6;
    if (expect_status('a', oversized, sizeof(oversized), NULL, 0, EVERUDP_TRANSCRIPT_INVALID) != 0) return 7;
    return 0;
}
'''
        with tempfile.TemporaryDirectory(prefix="everudp-transcript-") as raw:
            directory = Path(raw)
            harness = directory / "harness.c"
            binary = directory / "harness"
            harness.write_text(source, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    "/usr/bin/cc",
                    "-std=c11",
                    "-O2",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(NET),
                    str(harness),
                    str(NET / "zmosh-transcript.c"),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            completed = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


if __name__ == "__main__":
    unittest.main()
