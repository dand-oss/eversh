"""Root-only live calibration: 20 UDP attempts at 0% and 100% netem loss."""
import json
import os
import select
import subprocess
import sys
import time
import unittest
import uuid

from packet_accounting import derive_attempt_delta, parse_root_netem


@unittest.skipUnless(os.geteuid() == 0, "requires root network namespaces")
class NetemCalibrationTests(unittest.TestCase):
    def test_sent_plus_dropped_matches_exact_udp_offers(self):
        suffix = uuid.uuid4().hex[:10]
        client, server = f"euc-{suffix}", f"eus-{suffix}"
        created = []
        listener = None

        def run(*args):
            return subprocess.check_output(args, text=True, stderr=subprocess.PIPE)

        def ip(namespace, *args):
            return run("/usr/bin/ip", "-n", namespace, *args)

        def tc(*args):
            return run("/usr/bin/ip", "netns", "exec", client, "/usr/sbin/tc", *args)

        try:
            for namespace in (client, server):
                run("/usr/bin/ip", "netns", "add", namespace)
                created.append(namespace)
                ip(namespace, "link", "set", "lo", "up")
            ip(client, "link", "add", "c0", "type", "veth", "peer", "name", "s0", "netns", server)
            for namespace, interface, address in ((client, "c0", "10.249.19.1"),
                                                   (server, "s0", "10.249.19.2")):
                ip(namespace, "addr", "add", address + "/24", "dev", interface)
                # Suppress unrelated IPv6 discovery traffic in this calibration.
                run("/usr/bin/ip", "netns", "exec", namespace, "/usr/sbin/sysctl", "-q", "-w",
                    f"net.ipv6.conf.{interface}.disable_ipv6=1")
                ip(namespace, "link", "set", interface, "up")
            mac = json.loads(ip(server, "-j", "link", "show", "s0"))[0]["address"]
            ip(client, "neigh", "replace", "10.249.19.2", "lladdr", mac,
               "nud", "permanent", "dev", "c0")
            listener = subprocess.Popen([
                "/usr/bin/ip", "netns", "exec", server, sys.executable, "-c",
                "import socket,sys; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                "s.bind(('10.249.19.2',32199)); print('ready',flush=True); sys.stdin.readline()"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            self.assertTrue(select.select([listener.stdout], [], [], 5)[0], "listener deadline")
            self.assertEqual(listener.stdout.readline().strip(), "ready")
            for loss in (0, 100):
                with self.subTest(loss=loss):
                    tc("qdisc", "replace", "dev", "c0", "root", "netem", "loss", f"{loss}%")
                    before = parse_root_netem(tc("-s", "qdisc", "show", "dev", "c0"))
                    run("/usr/bin/ip", "netns", "exec", client, sys.executable, "-c",
                        "import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                        "[s.sendto(b'x',('10.249.19.2',32199)) for _ in range(20)]")
                    deadline = time.monotonic() + 3
                    while True:
                        delta = derive_attempt_delta(before, parse_root_netem(tc("-s", "qdisc", "show", "dev", "c0")))
                        if delta.attempts >= 20 or time.monotonic() >= deadline:
                            break
                        time.sleep(0.01)
                    self.assertEqual(delta.attempts, 20)
                    self.assertEqual(delta.sent_packets, 20 if loss == 0 else 0)
                    self.assertEqual(delta.dropped_packets, 20 if loss == 100 else 0)
        finally:
            if listener is not None:
                listener.communicate("stop\n", timeout=5)
            for namespace in reversed(created):
                run("/usr/bin/ip", "netns", "delete", namespace)


if __name__ == "__main__":
    unittest.main()
