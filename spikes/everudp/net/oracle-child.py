#!/usr/bin/env python3
"""Deterministic programs exercised through a real PTY by the grid oracle."""

import fcntl
import os
import struct
import sys
import termios
import time


def read_exact(length: int) -> bytes:
    data = bytearray()
    while len(data) < length:
        chunk = os.read(0, length - len(data))
        if not chunk:
            raise RuntimeError("unexpected PTY EOF")
        data.extend(chunk)
    return bytes(data)


def write(data: bytes) -> None:
    offset = 0
    while offset < len(data):
        offset += os.write(1, data[offset:])


def set_size(rows: int, cols: int) -> None:
    packed = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(0, termios.TIOCSWINSZ, packed)
    size = os.get_terminal_size(0)
    if (size.lines, size.columns) != (rows, cols):
        raise RuntimeError(f"PTY resize failed: {size.lines}x{size.columns}")


def main() -> None:
    mode = sys.argv[1]
    if mode == "echo":
        write(read_exact(int(sys.argv[2])))
    elif mode == "mismatch":
        read_exact(1)
        write(b"y")
    elif mode == "full-screen":
        write(
            b"\x1b[2J\x1b[H"
            b"\x1b[1;31mTITLE\x1b[0m\r\n"
            b"row-a\r\n"
            b"\x1b[4;34mrow-b\x1b[0m"
            b"\x1b[2;3H!"
        )
    elif mode == "no-echo":
        secret = read_exact(int(sys.argv[2]))
        if not secret:
            raise RuntimeError("empty password fixture")
        write(b"\r\n\x1b[32maccepted\x1b[0m\r\n")
    elif mode == "resize":
        set_size(24, 80)
        write(b"\x1b[2J\x1b[Hsmall\x1b[24;79HX")
        if read_exact(1) != b"r":
            raise RuntimeError("missing resize trigger")
        set_size(30, 100)
        write(b"\x1bPeverudp-resize\x1b\\")
        write(b"\x1b[2J\x1b[Hlarge\x1b[1;35m!\x1b[0m\x1b[30;99HY")
    elif mode == "tmux":
        write(
            b"\x1b[2J\x1b[H"
            b"\x1b[1;36mpane-1\x1b[0m\r\n"
            b"pane-2\x1b[10;20Hcursor"
        )
        time.sleep(0.1)
    else:
        raise RuntimeError(f"unknown oracle mode: {mode}")


if __name__ == "__main__":
    main()
