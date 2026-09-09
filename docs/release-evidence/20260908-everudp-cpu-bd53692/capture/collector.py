"""One bounded production CPU diagnostic; raw perf remains private."""
import json
import os
from pathlib import Path
import pwd
import signal
import subprocess
import sys
import time

REPO = Path('/tmp/eversh-fairness-bd53692')
BUILD = Path('/tmp/everudp-fairness-build-bd53692')
OUT = Path('/tmp/everudp-production-cpu-bd53692')
PERF = '/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/bin/perf'
sys.path.insert(0, str(REPO / 'crates/everudp/tests/net'))
from stream_floor_evidence import sealed, digest, require
from qualify_stream_floor import seal_output, write_json


def identity(pid):
    root = Path(f'/proc/{pid}')
    fields = (root / 'stat').read_text().rsplit(')', 1)[1].split()
    ns = (root / 'ns/time').stat()
    exe = (root / 'exe').stat()
    return {'pid': pid, 'start_ticks': fields[19], 'namespace': [ns.st_dev, ns.st_ino],
            'exe': [exe.st_dev, exe.st_ino], 'affinity': sorted(os.sched_getaffinity(pid)),
            'tids': sorted(int(p.name) for p in (root / 'task').iterdir())}


def targets():
    found = {}
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal():
            continue
        try:
            if not os.path.samefile(item / 'exe', BUILD / 'artifacts/bin/everudp'):
                continue
            args = (item / 'cmdline').read_bytes().split(b'\0')
            role = 'gateway' if b'__gateway-v1' in args else 'client' if b'connect' in args else None
            if role:
                require(role not in found, 'ambiguous role')
                found[role] = int(item.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found


def stop(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()


def interrupt(signum, frame):
    raise KeyboardInterrupt(str(signum))


require(os.geteuid() == 0, 'root required for isolated netns and scoped profiling')
os.umask(0o077)
OUT.mkdir(mode=0o700, exist_ok=False)
user = pwd.getpwnam('appsmith')
os.chown(OUT, user.pw_uid, user.pw_gid)
bench = record = None
receipt = {'status': 'INVALID', 'production_qualification': False}
for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, interrupt)
try:
    sealed(BUILD)
    provenance = json.loads((BUILD / 'provenance.json').read_text())
    require(provenance['everudp_build']['cargo_features'] == ['cli'], 'production cli required')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    require(head == provenance['source']['head_sha'] == 'bd53692a23e498408f55ee30b03309017a923a4c', 'identity mismatch')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO), 'dirty source')
    require(not targets(), 'matching binary already running')
    write_json(OUT / 'build-provenance.json', provenance)
    (OUT / 'collector.py').write_bytes(Path(__file__).read_bytes())
    command = [str(REPO / 'crates/everudp/tests/net/bench-performance-block.sh'),
               '600', '0', '19000001', str(OUT / 'measurement'), 'everudp,zmosh-udp,zmosh-quic']
    write_json(OUT / 'plan.json', {'command': command, 'head': head,
        'collector_sha256': digest(__file__), 'perf_sha256': digest(PERF),
        'capture_seconds': 45, 'frequency_hz': 4999, 'qualification': False,
        'scope': 'client and gateway process CPU leaf samples; no inherit, stacks, registers, payloads or argv export; raw perf private; public-window filtering required after capture'})
    env = {k: v for k, v in os.environ.items() if not k.startswith('EVERUDP_')}
    env.update(EVERUDP_PERF_BUILD=str(BUILD), EVERUDP_BENCH_CPUSET='40,42,44,46',
               SUDO_USER='appsmith', PYTHONDONTWRITEBYTECODE='1')
    perf_env = dict(env, LD_LIBRARY_PATH='/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/lib/x86_64-linux-gnu', DEBUGINFOD_URLS='')
    with (OUT / 'benchmark.stdout').open('w') as stdout, (OUT / 'benchmark.stderr').open('w') as stderr:
        bench = subprocess.Popen(command, cwd=REPO, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + 90
        while True:
            require(bench.poll() is None, 'benchmark ended before discovery')
            require(time.monotonic() < deadline, 'discovery timeout')
            found = targets()
            if set(found) == {'client', 'gateway'} and (OUT / 'measurement/everudp/window/start.go').exists():
                break
            time.sleep(0.02)
        before = {role: identity(pid) for role, pid in found.items()}
        own_ns = Path('/proc/self/ns/time').stat()
        require(all(v['namespace'] == [own_ns.st_dev, own_ns.st_ino] for v in before.values()), 'clock mismatch')
        require(all(v['affinity'] == [40, 42, 44, 46] for v in before.values()), 'affinity mismatch')
        perf_command = [PERF, 'record', '--no-inherit', '--no-buildid-cache', '--clockid', 'mono',
            '-T', '-e', 'cpu-clock:u,cpu-clock:k', '-F', '4999', '--strict-freq',
            '-p', ','.join(str(pid) for pid in found.values()), '-o', str(OUT / 'private-perf.data'),
            '--', '/usr/bin/sleep', '45']
        write_json(OUT / 'scope.json', {'before': before, 'command': perf_command,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'start_ns': time.clock_gettime_ns(time.CLOCK_MONOTONIC)})
        print('Capturing 45 seconds of scoped production CPU samples', flush=True)
        with (OUT / 'perf-record.log').open('w') as log:
            record = subprocess.Popen(perf_command, env=perf_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            require(record.wait(timeout=60) == 0, 'perf failed')
        after = {role: identity(pid) for role, pid in found.items()}
        require(before == after, 'process identity changed')
        write_json(OUT / 'scope-after.json', {'after': after, 'end_ns': time.clock_gettime_ns(time.CLOCK_MONOTONIC)})
        print('Capture finished; waiting for exact-byte benchmark completion', flush=True)
        require(bench.wait(timeout=240) == 0, 'benchmark failed')
    decoded = subprocess.run([PERF, 'script', '--show-lost-events', '--ns', '-i', str(OUT / 'private-perf.data'),
                              '-F', 'pid,tid,time,event,ip,sym,dso'], env=perf_env,
                             capture_output=True, text=True, check=True)
    require('LOST' not in decoded.stdout.upper() and 'LOST' not in decoded.stderr.upper(), 'lost samples')
    (OUT / 'samples.txt').write_text(decoded.stdout)
    (OUT / 'decode.log').write_text(decoded.stderr)
    attrs = subprocess.run([PERF, 'evlist', '-v', '-i', str(OUT / 'private-perf.data')],
                           env=perf_env, capture_output=True, text=True, check=True)
    (OUT / 'events-attributes.txt').write_text(attrs.stdout)
    sealed(OUT / 'measurement')
    receipt['status'] = 'CAPTURED'
except (Exception, KeyboardInterrupt) as error:
    receipt['reason'] = f'{type(error).__name__}: {error}'
finally:
    stop(record)
    stop(bench)
    write_json(OUT / 'receipt.json', receipt)
    seal_output(OUT)
    for path in OUT.rglob('*'):
        os.chown(path, user.pw_uid, user.pw_gid)
print(receipt['status'], str(OUT), flush=True)
sys.exit(0 if receipt['status'] == 'CAPTURED' else 1)
