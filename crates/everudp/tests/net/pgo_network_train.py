#!/usr/bin/env python3
"""Isolated two-netns training; never performance qualification."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import secrets
import select
import shlex
import signal
import subprocess

CELLS = ((0, 20100001), (5, 20105001))
NET = Path(__file__).resolve().parent


def execute(command):
    return subprocess.check_output(command, stderr=subprocess.PIPE, text=True, timeout=15)


def netem_commands(server, client, loss, seed):
    return [["ip", "netns", "exec", ns, "tc", "qdisc", "replace", "dev", dev,
             "root", "netem", "loss", "random", f"{loss}%", "seed", str(value)]
            for ns, dev, value in ((client, "c0", seed), (server, "s0", seed + 1000003))]


def shim_text(server, user):
    prefix = shlex.join(["/usr/bin/sudo", "-n", "/usr/bin/ip", "netns", "exec", server,
                         "/usr/bin/sudo", "-n", "-u", user, "/usr/bin/env"])
    return '''#!/bin/sh
set -eu
for arg; do
  if [ "$arg" = "-G" ]; then
    printf 'hostname localhost\\nproxycommand none\\nproxyjump none\\n'
    exit 0
  fi
done
remote=
for arg; do remote=$arg; done
[ -n "$remote" ] || exit 255
exec ''' + prefix + ''' EVERSH_STATE_DIR="$EVERSH_STATE_DIR" SSH_CONNECTION='10.247.0.2 40000 10.247.0.1 22' /bin/sh -c "$remote"
'''


def namespace_pids(namespace):
    return [int(value) for value in execute(["ip", "netns", "pids", namespace]).split()]


def cleanup_namespace(namespace):
    """Pin each process then recheck ownership by the exact netns inode."""
    inode = Path('/run/netns', namespace).stat().st_ino
    for pid in namespace_pids(namespace):
        try:
            fd = os.pidfd_open(pid)
        except ProcessLookupError:
            continue
        try:
            try:
                if Path(f'/proc/{pid}/ns/net').stat().st_ino != inode:
                    continue
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except (ProcessLookupError, FileNotFoundError):
                continue
            if not select.select([fd], [], [], 3)[0]:
                raise RuntimeError('namespace process did not exit')
        finally:
            os.close(fd)
    execute(['ip', 'netns', 'delete', namespace])


def run(args):
    binary, fixture, out = map(Path, (args.binary, args.fixture, args.output_dir))
    if os.geteuid() != 0:
        raise ValueError('requires root for isolated namespace setup')
    if not all(p.is_absolute() for p in (binary, fixture, out)) or not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError('absolute paths and finite positive timeout required')
    account = pwd.getpwnam(args.user)
    if account.pw_uid == 0:
        raise ValueError('training endpoints must run as an unprivileged user')
    for path in (binary, fixture):
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValueError('binary and fixture must be executable')
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    os.chown(out, account.pw_uid, account.pw_gid)
    receipt = {'schema_version': 1, 'qualification': False, 'status': 'FAILED', 'cells': [],
               'hashes': {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in
                          (binary, fixture, Path(__file__).resolve(), NET / 'pgo_terminal_train.py')}}
    created = []
    try:
        for loss, seed in CELLS:
            tag = 'epgo' + secrets.token_hex(3)
            server, client = tag + 's', tag + 'c'
            for namespace in (server, client):
                execute(['ip', 'netns', 'add', namespace])
                created.append(namespace)
            # Both ends are created inside namespaces; no host link is changed.
            execute(['ip', '-n', server, 'link', 'add', 's0', 'type', 'veth',
                     'peer', 'name', 'c0', 'netns', client])
            for ns, dev, address in ((server, 's0', '10.247.0.1'), (client, 'c0', '10.247.0.2')):
                execute(['ip', '-n', ns, 'link', 'set', 'lo', 'up'])
                execute(['ip', '-n', ns, 'addr', 'add', address + '/24', 'dev', dev])
                execute(['ip', '-n', ns, 'link', 'set', dev, 'up'])
                execute(['ip', '-n', ns, 'route', 'add', 'default', 'dev', dev])
            for command in netem_commands(server, client, loss, seed):
                execute(command)
            shim = out / f'ssh-{loss}.sh'
            shim.write_text(shim_text(server, args.user))
            shim.chmod(0o600)
            os.chown(shim, account.pw_uid, account.pw_gid)
            cell = {'loss_percent': loss, 'client_seed': seed, 'server_seed': seed + 1000003}
            receipt['cells'].append(cell)
            for phase in ('before', 'after'):
                if phase == 'after':
                    command = ['ip', 'netns', 'exec', client, 'sudo', '-n', '-u', args.user,
                               '/usr/bin/python3', '-B', str(NET / 'pgo_terminal_train.py'),
                               '--binary', str(binary), '--fixture', str(fixture), '--output-dir',
                               str(out / f'cell-{loss}'), '--timeout', str(args.timeout), '--bootstrap-shim', str(shim)]
                    with (out / f'child-{loss}.log').open('xb') as log:
                        os.fchmod(log.fileno(), 0o600)
                        subprocess.run(command, stdout=log, stderr=log, check=True, timeout=args.timeout + 20)
                    trained = json.loads((out / f'cell-{loss}/pgo-training-receipt.json').read_text())
                    if trained['status'] != 'TRAINED' or trained['qualification'] is not False:
                        raise RuntimeError('child training did not succeed')
                    cell['training'] = trained
                    if namespace_pids(server) or namespace_pids(client):
                        raise RuntimeError('training left namespace processes alive')
                for ns, dev, role in ((server, 's0', 'server'), (client, 'c0', 'client')):
                    stats = execute(['ip', 'netns', 'exec', ns, 'tc', '-j', '-s', 'qdisc', 'show', 'dev', dev])
                    (out / f'qdisc-{loss}-{role}-{phase}.json').write_text(stats)
            for ns in (client, server):
                cleanup_namespace(ns)
                created.remove(ns)
        if len({cell['training']['transcript_sha256'] for cell in receipt['cells']}) != 1:
            raise RuntimeError('loss cells produced different transcripts')
        receipt['status'] = 'TRAINED'
    except Exception as error:
        receipt['error_type'] = type(error).__name__
    finally:
        for namespace in reversed(created):
            try:
                cleanup_namespace(namespace)
            except Exception as error:
                receipt['status'] = 'FAILED'
                receipt.setdefault('cleanup_errors', []).append(type(error).__name__)
        target = out / 'pgo-network-training-receipt.json'
        target.write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        files = [target, *sorted(out.glob('qdisc-*.json'))]
        (out / 'SHA256SUMS').write_text(''.join(f'{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n' for p in files))
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'fixture', 'output-dir'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--user', required=True)
    parser.add_argument('--timeout', type=float, default=60)
    receipt = run(parser.parse_args())
    print(json.dumps({'status': receipt['status'], 'qualification': False}))
    raise SystemExit(0 if receipt['status'] == 'TRAINED' else 1)


if __name__ == '__main__':
    main()
