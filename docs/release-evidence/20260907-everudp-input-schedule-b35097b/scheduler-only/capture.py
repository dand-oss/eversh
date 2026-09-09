#!/usr/bin/env python3
"""One bounded scheduler diagnostic of the exact echo client; no payload capture."""
import json
import os
from pathlib import Path
import subprocess
import time

root = Path('/tmp/eversh-input-schedule.NayKlQ')
repo = Path('/home/appsmith/asv/ports/repo/eversh/.claude/worktrees/eversh-5fc-everudp-WORK')
build = Path('/tmp/eversh-handoff-clock.QyrQ5W/diagnostic')
binary = build / 'artifacts/bin/everudp-floor'
perf = '/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/bin/perf'
base = ['sudo', '-n', 'env', 'LD_LIBRARY_PATH=/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/lib/x86_64-linux-gnu', 'DEBUGINFOD_URLS=', perf]
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip() == '23a3a82' or subprocess.check_output(['git','rev-parse','--short','HEAD'],cwd=repo,text=True).strip() == '23a3a82'
assert not subprocess.check_output(['git','status','--porcelain'],cwd=repo)

def clients():
    found = []
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal():
            continue
        try:
            if not os.path.samefile(item/'exe', binary):
                continue
            args = (item/'cmdline').read_bytes().split(b'\0')
            if len(args) > 1 and args[1] == b'client':
                found.append(int(item.name))
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            pass
    return found

assert not clients(), 'another matching floor client exists; refuse ambiguous capture'
bench_command = ['sudo','-n','env',f'EVERUDP_PERF_BUILD={build}','EVERUDP_FLOOR_TRACE=1',
                 'bash',str(repo/'crates/everudp/tests/net/bench-performance-block.sh'),
                 '200','0','91401',str(root/'measurement'),'everudp-floor,zmosh-udp']
with (root/'benchmark.log').open('w') as log:
    bench = subprocess.Popen(bench_command,cwd=repo,stdout=log,stderr=subprocess.STDOUT)
    deadline = time.monotonic()+60
    while True:
        assert bench.poll() is None, 'benchmark ended before capture'
        assert time.monotonic() < deadline, 'client discovery timeout'
        found = clients()
        assert len(found) <= 1, 'ambiguous client'
        if found and (root/'measurement/everudp-floor/window/start.go').exists():
            pid = found[0]
            break
        time.sleep(.01)
    # The tracepoint payload filters refer to the selected target, not the
    # task emitting the wakeup. No unfiltered scheduler event is enabled.
    command = base + ['record','-a','--synth','no','--clockid','mono',
                     '-e','sched:sched_waking','--filter',f'pid == {pid}',
                     '-e','sched:sched_wakeup','--filter',f'pid == {pid}',
                     '-e','sched:sched_switch','--filter',f'prev_pid == {pid} || next_pid == {pid}',
                     '-o',str(root/'perf.data'),'--','/usr/bin/sleep','10']
    with (root/'perf-record.log').open('w') as output:
        subprocess.run(command,stdout=output,stderr=subprocess.STDOUT,check=True)
    assert pid in clients(), 'client ended before bounded capture completed'
    identity = json.loads((build/'provenance.json').read_text())['source']
    metadata = {'status':'DIAGNOSTIC','qualification':'NOT_APPLICABLE','target_pid':pid,
                'clock':'CLOCK_MONOTONIC','source_build':identity,'duration_seconds':10,
                'command':command,'scope':'only target PID scheduler events; no stacks, payloads or inherited counters'}
    (root/'capture.json').write_text(json.dumps(metadata,indent=2)+'\n')
    with (root/'scheduler.txt').open('w') as output, (root/'perf-script.log').open('w') as error:
        subprocess.run(base+['script','--ns','-i',str(root/'perf.data'),'-F','time,event,trace'],stdout=output,stderr=error,check=True)
    print('scheduler capture finished',pid,flush=True)
    assert bench.wait(timeout=120)==0, 'benchmark failed'
print('diagnostic block completed',flush=True)
