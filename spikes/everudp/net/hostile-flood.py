#!/usr/bin/env python3
"""Send deterministic invalid UDP datagrams and count any amplification."""

import argparse
import json
import socket
import time


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("--count", type=int, default=10_000)
    parser.add_argument("--size", type=int, default=1_200)
    parser.add_argument("--drain-seconds", type=float, default=0.5)
    args = parser.parse_args()
    if args.count < 1 or not 4 <= args.size <= 65_507:
        raise SystemExit("invalid count or UDP payload size")

    payload = b"BAD!" + bytes(args.size - 4)
    target = (args.host, args.port)
    sent = 0
    started = time.monotonic_ns()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.05)
        for _ in range(args.count):
            if sock.sendto(payload, target) != len(payload):
                raise SystemExit("short UDP send")
            sent += 1
        sent_finished = time.monotonic_ns()
        responses = 0
        response_bytes = 0
        deadline = time.monotonic() + args.drain_seconds
        while time.monotonic() < deadline:
            try:
                reply, _ = sock.recvfrom(65_535)
            except socket.timeout:
                continue
            responses += 1
            response_bytes += len(reply)

    print(
        json.dumps(
            {
                "sent_datagrams": sent,
                "payload_bytes_each": len(payload),
                "sent_bytes": sent * len(payload),
                "send_elapsed_us": (sent_finished - started) // 1_000,
                "response_datagrams": responses,
                "response_bytes": response_bytes,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
