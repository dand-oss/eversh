#!/usr/bin/env python3
"""Untimed real-OpenSSH/PTY gate for both disposable stream-floor modes.

Requires root solely for private network namespaces and the fixture sshd.
Ephemeral keys/logs stay in a temporary directory and are never emitted.
"""

import argparse
import fcntl
import os
from pathlib import Path
import pwd
import secrets
import select
import shutil
import signal
import struct
import subprocess
import tempfile
import termios
import time
from stream_preflight_evidence import identity as evidence_identity, save as save_evidence


def command(*args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=10, check=False)
    if check and result.returncode:
        # Never forward arbitrary setup output or credential-bearing argv.
        raise RuntimeError(f"fixture command failed: {Path(args[0]).name}")
    return result


def namespace_pids(namespace):
    result = command("/usr/bin/ip", "netns", "pids", namespace, check=False)
    return [int(value) for value in result.stdout.split()] if result.returncode == 0 else []


def binary_pids(namespace, binary):
    found = []
    for pid in namespace_pids(namespace):
        try:
            if Path(f"/proc/{pid}/exe").resolve() == binary:
                found.append(pid)
        except (FileNotFoundError, PermissionError):
            pass
    return found


def await_condition(predicate, seconds, message):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.01)
    raise AssertionError(message)


def exercise(mode, binary, user, client_ns, server_ns, root):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    before_termios = termios.tcgetattr(slave)
    before_flags = fcntl.fcntl(slave, fcntl.F_GETFL)
    os.set_blocking(master, False)
    process = None
    try:
        with (root / f"{mode}.stderr").open("wb") as errors:
            process = subprocess.Popen([
                "/usr/bin/ip", "netns", "exec", client_ns,
                "/usr/bin/sudo", "-n", "-u", user, "--", "/usr/bin/env",
                f"PATH={root / 'bin'}:/usr/bin:/bin",
                f"EVERUDP_BENCH_SSH_CONFIG={root / 'client_config'}",
                f"EVERUDP_STREAM_PROFILE_DIR={root / 'profiles'}",
                str(binary), "client", "target", "--runtime", mode,
                "--session", "stream-process", "--remote-program", str(root / "profile-remote"),
            ], stdin=slave, stdout=slave, stderr=errors, start_new_session=True)

            def activated():
                if process.poll() is not None:
                    raise AssertionError(f"{mode}: client exited before terminal activation")
                return termios.tcgetattr(slave) != before_termios

            await_condition(activated, 10, f"{mode}: terminal activation deadline")
            if select.select([master], [], [], 0)[0]:
                raise AssertionError(f"{mode}: unsolicited terminal output")
            payload = b"opaque\x00\xff\x1b[31m\x03\x04\r\n" * 32
            sent = 0
            received = bytearray()
            deadline = time.monotonic() + 5
            while len(received) < len(payload) or sent < len(payload):
                if time.monotonic() >= deadline:
                    raise AssertionError(f"{mode}: exact delivery deadline")
                readable, writable, _ = select.select(
                    [master], [master] if sent < len(payload) else [], [], 0.05)
                if writable:
                    sent += os.write(master, payload[sent:])
                if readable:
                    received.extend(os.read(master, 65536))
                if not payload.startswith(received):
                    raise AssertionError(f"{mode}: incorrect or duplicated output")
            assert bytes(received) == payload, f"{mode}: transcript mismatch"
            assert not select.select([master], [], [], 0.1)[0], f"{mode}: extra output"

            clients = binary_pids(client_ns, binary)
            assert len(clients) == 1, f"{mode}: expected one terminal client"
            os.kill(clients[0], signal.SIGTERM)
            process.wait(timeout=5)
            assert process.returncode == 3, f"{mode}: cancellation exit status"
            assert termios.tcgetattr(slave) == before_termios, f"{mode}: raw mode leaked"
            assert fcntl.fcntl(slave, fcntl.F_GETFL) == before_flags, f"{mode}: descriptor flags leaked"
            await_condition(lambda: not binary_pids(server_ns, binary), 5,
                            f"{mode}: detached server survived cancellation")
            assert not binary_pids(client_ns, binary), f"{mode}: client process leaked"
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master)
        os.close(slave)


def rejected_admission(mode, fault, binary, user, client_ns, server_ns, root):
    master, slave = os.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    initial = termios.tcgetattr(slave)
    initial[3] &= ~termios.ECHO
    termios.tcsetattr(slave, termios.TCSANOW, initial)
    initial = termios.tcgetattr(slave)
    flags = fcntl.fcntl(slave, fcntl.F_GETFL)
    queued = b"must remain unread before authenticated admission\n"
    assert os.write(master, queued) == len(queued)
    process = None
    try:
        with (root / f"{fault}-{mode}.stderr").open("wb") as errors:
            process = subprocess.Popen([
                "/usr/bin/ip", "netns", "exec", client_ns,
                "/usr/bin/sudo", "-n", "-u", user, "--", "/usr/bin/env",
                f"PATH={root / 'bin'}:/usr/bin:/bin",
                f"EVERUDP_BENCH_SSH_CONFIG={root / 'client_config'}",
                str(binary), "client", "target", "--runtime", mode,
                "--session", "stream-rejection", "--remote-program", str(root / fault),
            ], stdin=slave, stdout=slave, stderr=errors, start_new_session=True)
            deadline = time.monotonic() + 10
            while process.poll() is None:
                assert time.monotonic() < deadline, f"{mode}/{fault}: rejection deadline"
                assert termios.tcgetattr(slave) == initial, f"{mode}/{fault}: premature raw mode"
                assert fcntl.fcntl(slave, fcntl.F_GETFL) == flags, f"{mode}/{fault}: premature descriptor change"
                time.sleep(0.005)
            assert process.returncode == 3, f"{mode}/{fault}: rejection exit"
            assert (root / "mutations" / f"{fault}-{mode}").read_text() == "mutated\n", "fault was not injected"
            assert termios.tcgetattr(slave) == initial, f"{mode}/{fault}: changed terminal"
            assert fcntl.fcntl(slave, fcntl.F_GETFL) == flags, f"{mode}/{fault}: changed descriptor flags"
            assert not select.select([master], [], [], 0)[0], f"{mode}/{fault}: terminal output before admission"
            os.set_blocking(slave, False)
            assert os.read(slave, len(queued) + 1) == queued, f"{mode}/{fault}: consumed unauthenticated input"
            await_condition(lambda: not binary_pids(server_ns, binary), 5,
                            f"{mode}/{fault}: server leaked after rejection")
            assert not binary_pids(client_ns, binary), f"{mode}/{fault}: client leaked"
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)
        os.close(master)
        os.close(slave)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--run-user", required=True)
    parser.add_argument("--evidence-dir", type=Path,
                        help="retain only non-secret exact-source receipts; requires clean source")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("requires root for isolated namespaces")
    binary = args.binary.resolve(strict=True)
    account = pwd.getpwnam(args.run_user)
    if account.pw_uid == 0:
        parser.error("run-user must be unprivileged")
    frozen = None
    if args.evidence_dir is not None:
        if args.evidence_dir.exists() or args.evidence_dir.is_symlink():
            parser.error("refusing to overwrite preflight evidence")
        frozen = evidence_identity(binary)
    for executable in ("/usr/bin/ip", "/usr/bin/ssh", "/usr/bin/ssh-keygen",
                       "/usr/sbin/sshd", "/usr/bin/sudo"):
        if not os.access(executable, os.X_OK):
            parser.error(f"missing {executable}")
    tag = "eus" + secrets.token_hex(3)
    server_ns, client_ns = tag + "s", tag + "c"
    created = []
    daemon = None
    with tempfile.TemporaryDirectory(prefix="everudp-stream-process-") as temporary:
        root = Path(temporary)
        # Public traversal permits the unprivileged client to reach its key;
        # private keys and logs remain individually mode 0600.
        root.chmod(0o755)
        try:
            for name in (server_ns, client_ns):
                command("/usr/bin/ip", "netns", "add", name)
                created.append(name)
            command("/usr/bin/ip", "link", "add", tag + "s0", "type", "veth", "peer", "name", tag + "c0")
            for name, device, address in ((server_ns, tag + "s0", "10.247.0.1/24"),
                                           (client_ns, tag + "c0", "10.247.0.2/24")):
                command("/usr/bin/ip", "link", "set", device, "netns", name)
                command("/usr/bin/ip", "-n", name, "link", "set", "lo", "up")
                command("/usr/bin/ip", "-n", name, "addr", "add", address, "dev", device)
                command("/usr/bin/ip", "-n", name, "link", "set", device, "up")
            for name in ("host", "client"):
                command("/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name))
            os.chown(root / "client", account.pw_uid, account.pw_gid)
            shutil.copyfile(root / "client.pub", root / "authorized_keys")
            (root / "authorized_keys").chmod(0o644)
            (root / "known").write_text("[10.247.0.1]:22462 " + (root / "host.pub").read_text())
            (root / "known").chmod(0o644)
            (root / "bin").mkdir(mode=0o755)
            (root / "bin").chmod(0o755)
            shutil.copyfile(Path(__file__).with_name("ssh-wrapper.sh"), root / "bin/ssh")
            (root / "bin/ssh").chmod(0o755)
            (root / "mutations").mkdir(mode=0o700)
            os.chown(root / "mutations", account.pw_uid, account.pw_gid)
            (root / "profiles").mkdir(mode=0o700)
            os.chown(root / "profiles", account.pw_uid, account.pw_gid)
            (root / "profile-remote").write_text(f"""#!/usr/bin/python3
import os
import sys
os.environ['EVERUDP_STREAM_PROFILE_DIR'] = {str(root / 'profiles')!r}
os.execv({str(binary)!r}, [{str(binary)!r}, *sys.argv[1:]])
""")
            (root / "profile-remote").chmod(0o755)
            for fault, field in (("wrong-pin", 4), ("wrong-token", 5)):
                # Fault injection runs only on the authenticated SSH bootstrap
                # edge. Tokens never enter argv, logs, or retained artifacts.
                (root / fault).write_text(f"""#!/usr/bin/python3
import pathlib
import subprocess
import sys
assert len(sys.argv) == 4 and sys.argv[1] == '__stream-bootstrap-v1'
assert sys.argv[2] in ('ordinary', 'native')
result = subprocess.run([{str(binary)!r}, *sys.argv[1:]], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=5, check=True)
assert result.stdout.endswith(b'\\n') and result.stdout.count(b'\\n') == 1
fields = result.stdout[:-1].split(b' ')
assert len(fields) == 9 and fields[:2] == [b'everudp', b'v1']
assert len(fields[{field}]) == 64
fields[{field}] = (b'0' if fields[{field}][:1] != b'0' else b'1') + fields[{field}][1:]
pathlib.Path({str(root / 'mutations')!r}, {fault!r} + '-' + sys.argv[2]).write_text('mutated\\n')
sys.stdout.buffer.write(b' '.join(fields) + b'\\n')
""")
                (root / fault).chmod(0o755)
            (root / "client_config").write_text(f"""Host target
    HostName 10.247.0.1
    Port 22462
    User {args.run_user}
    IdentityFile {root / 'client'}
    IdentitiesOnly yes
    UserKnownHostsFile {root / 'known'}
    GlobalKnownHostsFile /dev/null
    StrictHostKeyChecking yes
    BatchMode yes
    ConnectTimeout 2
    ControlMaster no
    ControlPath none
    RequestTTY no
""")
            (root / "client_config").chmod(0o644)
            (root / "sshd_config").write_text(f"""Port 22462
ListenAddress 10.247.0.1
HostKey {root / 'host'}
AuthorizedKeysFile {root / 'authorized_keys'}
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
StrictModes no
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
UseDNS no
PermitUserEnvironment no
PermitUserRC no
AllowUsers {args.run_user}
LogLevel ERROR
""")
            with (root / "sshd.stderr").open("wb") as errors:
                daemon = subprocess.Popen(["/usr/bin/ip", "netns", "exec", server_ns,
                    "/usr/sbin/sshd", "-D", "-e", "-f", str(root / "sshd_config")],
                    stdout=subprocess.DEVNULL, stderr=errors)
                def ssh_ready():
                    if daemon.poll() is not None:
                        raise AssertionError("fixture sshd exited")
                    return command("/usr/bin/ip", "netns", "exec", client_ns,
                        "/usr/bin/ssh", "-F", str(root / "client_config"), "target", "true", check=False).returncode == 0
                await_condition(ssh_ready, 10, "fixture sshd readiness")
                for mode in ("ordinary", "native"):
                    exercise(mode, binary, args.run_user, client_ns, server_ns, root)
                    print(f"PASS {mode}: real SSH, exact PTY bytes, cancellation, restoration, cleanup", flush=True)
                    for fault in ("wrong-pin", "wrong-token"):
                        rejected_admission(mode, fault, binary, args.run_user, client_ns, server_ns, root)
                        print(f"PASS {mode}/{fault}: rejected before terminal input or activation; processes cleaned", flush=True)
                profiles = {}
                for path in (root / "profiles").iterdir():
                    metadata = path.stat()
                    assert metadata.st_uid == account.pw_uid and metadata.st_mode & 0o777 == 0o600
                    assert metadata.st_size <= 17000, "unbounded built profile"
                    lines = path.read_text().splitlines()
                    assert len(lines) == 4 and lines[0] == "everudp-stream-built-profile-v1"
                    assert lines[2] == "scope=local-built-not-negotiated"
                    fields = dict(item.split("=", 1) for item in lines[1].split())
                    key = fields["runtime"], fields["side"]
                    assert key not in profiles, "duplicate built profile"
                    assert path.name == f"{key[0]}-{key[1]}-{int(fields['pid'])}-built.txt"
                    profiles[key] = lines[3]
                assert set(profiles) == {(mode, side) for mode in ("ordinary", "native")
                                         for side in ("client", "server")}
                for side in ("client", "server"):
                    assert profiles["ordinary", side] == profiles["native", side], f"{side}: built configuration mismatch"
                    snapshot = profiles["ordinary", side]
                    for field in ("datagram_receive_buffer_size: None", "datagram_send_buffer_size: 0",
                                  "stream_receive_window: 4194304", "receive_window: 8388608",
                                  "send_window: 4194304", "ack_frequency_config: Some",
                                  "enable_segmentation_offload: true", "max_concurrent_uni_streams: 1"):
                        assert field in snapshot, f"{side}: missing locked setting {field}"
                    expected_bidi = 0 if side == "client" else 1
                    assert f"max_concurrent_bidi_streams: {expected_bidi}" in snapshot
                    _, cap = snapshot.rsplit("; socket_initial_gso_cap=", 1)
                    assert 1 <= int(cap) <= 10, f"{side}: effective initial GSO cap outside locked bound"
                print("PASS built profile parity: four private receipts, exact per-side runtime match", flush=True)
        finally:
            for name in reversed(created):
                for pid in namespace_pids(name):
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                command("/usr/bin/ip", "netns", "del", name, check=False)
            command("/usr/bin/ip", "link", "del", tag + "s0", check=False)
            if daemon is not None:
                daemon.wait(timeout=5)
            remaining = command("/usr/bin/ip", "netns", "list").stdout.decode().splitlines()
            assert not {line.split()[0] for line in remaining}.intersection(created), "namespace cleanup failed"
    assert not root.exists(), "temporary credential directory survived cleanup"
    print("PASS fixture cleanup: temporary namespaces, keys and logs removed", flush=True)
    if args.evidence_dir is not None:
        assert evidence_identity(binary) == frozen, "collector source or binary changed during preflight"
        save_evidence(args.evidence_dir, frozen, profiles, account.pw_uid, account.pw_gid)
        print("PASS retained non-secret preflight evidence", flush=True)


if __name__ == "__main__":
    os.umask(0o077)
    main()
