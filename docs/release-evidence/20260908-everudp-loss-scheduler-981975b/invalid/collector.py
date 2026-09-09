"""One instrumented reproduction; never a performance qualification receipt."""
import json
import os
from pathlib import Path
import pwd
import re
import signal
import subprocess
import sys
import time

REPO = Path('/tmp/eversh-loss-capture-981975b')
BUILD = Path('/tmp/everudp-backpressure-build-981975b')
OUT = Path('/tmp/everudp-loss-scheduler-981975b')
PERF = '/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/bin/perf'
sys.path.insert(0, str(REPO / 'crates/everudp/tests/net'))
from stream_floor_evidence import sealed, digest, require
from qualify_stream_floor import seal_output, write_json

require(os.geteuid() == 0, 'root required for private netns and scoped tracing')
os.umask(0o077)
OUT.mkdir(mode=0o700, exist_ok=False)
user = pwd.getpwnam('appsmith')
os.chown(OUT, user.pw_uid, user.pw_gid)
bench = None
record = None
receipt = {'status': 'INVALID', 'production_qualification': False,
           'purpose': 'same-seed instrumented loss-block reproduction'}

def interrupted(signum, _frame):
    raise KeyboardInterrupt(str(signum))

for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, interrupted)

def stop(process):
    if process is not None and process.poll() is None:
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()

def namespace(pid):
    value = Path(f'/proc/{pid}/ns/time').stat()
    return [value.st_dev, value.st_ino]

def identity(pid):
    fields = Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()
    return {'pid': pid, 'start_ticks': fields[19], 'time_namespace': namespace(pid),
            'tids': sorted(int(p.name) for p in Path(f'/proc/{pid}/task').iterdir()),
            'affinity': sorted(os.sched_getaffinity(pid))}

def targets():
    found = {}
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal():
            continue
        try:
            if not os.path.samefile(item / 'exe', BUILD / 'artifacts/bin/everudp'):
                continue
            # Inspect role only; never export credential-bearing argv.
            args = (item / 'cmdline').read_bytes().split(b'\0')
            role = 'gateway' if b'__gateway-v1' in args else 'client' if b'connect' in args else None
            if role:
                require(role not in found, 'ambiguous target role')
                found[role] = int(item.name)
        except (FileNotFoundError, ProcessLookupError):
            continue
    return found

try:
    sealed(BUILD)
    provenance = json.loads((BUILD / 'provenance.json').read_text())
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=REPO, text=True).strip()
    require(head == provenance['source']['head_sha'] == '981975bceed8a315b3c827406dc8c5be029ec272', 'source mismatch')
    require(not subprocess.check_output(['git', 'status', '--porcelain'], cwd=REPO), 'dirty capture source')
    require(not targets(), 'matching binary already active')
    write_json(OUT / 'build-provenance.json', provenance)
    (OUT / 'collector.py').write_bytes(Path(__file__).read_bytes())
    command = [str(REPO / 'crates/everudp/tests/net/bench-performance-block.sh'),
               '200', '5', '18050002', str(OUT / 'measurement'), 'zmosh-quic,zmosh-udp,everudp']
    write_json(OUT / 'plan.json', {'command': command, 'source': head,
        'collector_sha256': digest(__file__), 'perf_sha256': digest(PERF),
        'instrumented': True, 'production_qualification': False,
        'affinity': '40,42,44,46', 'capture_seconds': 19,
        'scope': 'client and gateway scheduler events only; no terminal payloads, argv exports or stacks'})
    env = {k: v for k, v in os.environ.items() if not k.startswith('EVERUDP_')}
    env.update(EVERUDP_PERF_BUILD=str(BUILD), EVERUDP_BENCH_CPUSET='40,42,44,46',
               SUDO_USER='appsmith', PYTHONDONTWRITEBYTECODE='1')
    with (OUT / 'benchmark.stdout').open('w') as stdout, (OUT / 'benchmark.stderr').open('w') as stderr:
        bench = subprocess.Popen(command, cwd=REPO, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        deadline = time.monotonic() + 180
        while True:
            require(bench.poll() is None, 'benchmark ended before target discovery')
            require(time.monotonic() < deadline, 'target discovery timeout')
            found = targets()
            if set(found) == {'client', 'gateway'} and (OUT / 'measurement/everudp/window/start.go').exists():
                break
            time.sleep(0.02)
        before = {role: identity(pid) for role, pid in found.items()}
        require(all(v['time_namespace'] == namespace('self') for v in before.values()), 'clock namespace differs')
        pids = list(found.values())
        pid_filter = ' || '.join(f'pid == {pid}' for pid in pids)
        switch_filter = ' || '.join(f'prev_pid == {pid} || next_pid == {pid}' for pid in pids)
        perf_command = [PERF, 'record', '-a', '--synth', 'no', '--clockid', 'mono',
            '-e', 'sched:sched_waking', '--filter', pid_filter,
            '-e', 'sched:sched_wakeup', '--filter', pid_filter,
            '-e', 'sched:sched_switch', '--filter', switch_filter,
            '-o', str(OUT / 'private-perf.data'), '--', '/usr/bin/sleep', '19']
        perf_env = dict(env, LD_LIBRARY_PATH='/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/lib/x86_64-linux-gnu', DEBUGINFOD_URLS='')
        write_json(OUT / 'scope.json', {'before': before, 'command': perf_command,
            'boot_id': Path('/proc/sys/kernel/random/boot_id').read_text().strip()})
        print('Capturing client and gateway scheduler events', flush=True)
        with (OUT / 'perf-record.log').open('w') as log:
            record = subprocess.Popen(perf_command, env=perf_env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            require(record.wait(timeout=35) == 0, 'perf capture failed')
        after = {role: identity(pid) for role, pid in found.items()}
        require(before == after, 'target generation, threads, affinity or namespace changed')
        write_json(OUT / 'scope-after.json', after)
        require(bench.wait(timeout=60) == 0, 'benchmark failed')
    decoded = subprocess.run([PERF, 'script', '--show-lost-events', '--ns', '-i', str(OUT / 'private-perf.data'),
                              '-F', 'time,event,trace'], env=perf_env, capture_output=True, text=True, check=True)
    require('LOST' not in decoded.stdout.upper(), 'lost events invalidate attribution')
    # Non-target task names are unnecessary for target scheduling attribution.
    safe = re.sub(r'(comm=|prev_comm=|next_comm=).*?(?= (?:pid|prev_pid|next_pid)=)', r'\1<task>', decoded.stdout)
    (OUT / 'events.txt').write_text(safe)
    (OUT / 'decode.log').write_text(decoded.stderr)
    attrs = subprocess.run([PERF, 'evlist', '-v', '-i', str(OUT / 'private-perf.data')], env=perf_env,
                           capture_output=True, text=True, check=True)
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
