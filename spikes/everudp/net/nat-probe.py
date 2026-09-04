#!/usr/bin/env python3
"""Behavioral probes for the four deterministic Linux NAT models."""

import json
import select
import socket
import sys
import time

INTERNAL = ("192.168.50.2", 40000)
EXTERNAL_NAT = ("10.242.1.1", 40000)
SERVER_A = ("10.242.1.2", 41000)
SERVER_A_OTHER_PORT = ("10.242.1.2", 41001)
SERVER_B = ("10.242.1.3", 41000)
DEADLINE_SECONDS = 2.0


def udp(address: tuple[str, int]) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(address)
    sock.setblocking(False)
    return sock


def receive_until(
    sockets: list[socket.socket], expected: int
) -> list[tuple[socket.socket, bytes, tuple[str, int]]]:
    received: list[tuple[socket.socket, bytes, tuple[str, int]]] = []
    deadline = time.monotonic() + DEADLINE_SECONDS
    while len(received) < expected and time.monotonic() < deadline:
        ready, _, _ = select.select(sockets, [], [], max(0.0, deadline - time.monotonic()))
        for sock in ready:
            data, peer = sock.recvfrom(1024)
            received.append((sock, data, peer))
    return received


def cone_server() -> None:
    same = udp(SERVER_A)
    other_port = udp(SERVER_A_OTHER_PORT)
    other_ip = udp(SERVER_B)
    opened = receive_until([same], 1)
    if len(opened) != 1 or opened[0][1] != b"open":
        raise RuntimeError("cone probe did not receive client opening packet")
    mapped_peer = opened[0][2]
    same.sendto(b"open-ack", mapped_peer)
    time.sleep(0.05)
    probes = [
        (same, b"a-same"),
        (other_port, b"a-other-port"),
        (other_ip, b"b-other-ip"),
    ]
    for _ in range(3):
        for sock, payload in probes:
            sock.sendto(payload, EXTERNAL_NAT)
        time.sleep(0.01)
    print(json.dumps({"mapped_peer": mapped_peer}, sort_keys=True))


def cone_client() -> None:
    client = udp(INTERNAL)
    client.sendto(b"open", SERVER_A)
    received = receive_until([client], 10)
    labels = sorted(
        {
            data.decode("ascii")
            for _, data, _ in received
            if data in {b"open-ack", b"a-same", b"a-other-port", b"b-other-ip"}
        }
    )
    print(json.dumps({"received": labels}, sort_keys=True))


def symmetric_server() -> None:
    first = udp(SERVER_A)
    second = udp(SERVER_B)
    received = receive_until([first, second], 2)
    peers: dict[str, tuple[str, int]] = {}
    for sock, data, peer in received:
        if data == b"to-a":
            peers["a"] = peer
            sock.sendto(b"from-a", peer)
        elif data == b"to-b":
            peers["b"] = peer
            sock.sendto(b"from-b", peer)
    if set(peers) != {"a", "b"}:
        raise RuntimeError(f"symmetric probe missed destination: {peers}")
    print(json.dumps({"mapped_peers": peers}, sort_keys=True))


def symmetric_client() -> None:
    client = udp(INTERNAL)
    client.sendto(b"to-a", SERVER_A)
    client.sendto(b"to-b", SERVER_B)
    received = receive_until([client], 2)
    labels = sorted(data.decode("ascii") for _, data, _ in received)
    print(json.dumps({"received": labels}, sort_keys=True))


def main() -> None:
    roles = {
        "cone-server": cone_server,
        "cone-client": cone_client,
        "symmetric-server": symmetric_server,
        "symmetric-client": symmetric_client,
    }
    try:
        role = roles[sys.argv[1]]
    except (IndexError, KeyError) as error:
        raise SystemExit("usage: nat-probe.py cone-server|cone-client|symmetric-server|symmetric-client") from error
    role()


if __name__ == "__main__":
    main()
