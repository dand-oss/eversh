#!/usr/bin/env python3
"""Bounded matched-client scheduler/read diagnostics, not qualification."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
repo = Path('/home/appsmith/asv/ports/repo/eversh/.claude/worktrees/eversh-5fc-everudp-WORK')
build = Path('/tmp/eversh-handoff-clock.QyrQ5W/diagnostic')
perf = '/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/bin/perf'
base = ['sudo','-n','env','LD_LIBRARY_PATH=/tmp/eversh-profile-tools.m4Ikm3/extracted/usr/lib/x86_64-linux-gnu','DEBUGINFOD_URLS=',perf]
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip() == sys.argv[1]
assert not subprocess.check_output(['git','status','--porcelain'],cwd=repo)

def identity():
    ns = Path('/proc/self/ns/time').stat()
    return {'boot_id':Path('/proc/sys/kernel/random/boot_id').read_text().strip(),
            'time_namespace_dev':ns.st_dev,'time_namespace_ino':ns.st_ino}

def clients(label, role):
    found=[]
    for item in Path('/proc').iterdir():
        if not item.name.isdecimal(): continue
        try:
            if not os.path.samefile(item/'exe',build/'artifacts/bin'/label): continue
            args=(item/'cmdline').read_bytes().split(b'\0')
            if len(args)>1 and args[1]==role.encode(): found.append(int(item.name))
        except (FileNotFoundError,PermissionError,ProcessLookupError): pass
    return found

def capture(label,role,bench):
    deadline=time.monotonic()+90
    while True:
        assert bench.poll() is None,'benchmark ended before capture'
        assert time.monotonic()<deadline,'target discovery timeout'
        found=clients(label,role)
        assert len(found)<=1,'ambiguous target'
        if found and (root/'measurement'/label/'window/start.go').exists(): break
        time.sleep(.01)
    pid=found[0]
    directory=root/label
    directory.mkdir()
    start_identity=identity()
    target_namespace=Path(f'/proc/{pid}/ns/time').stat()
    assert (target_namespace.st_dev,target_namespace.st_ino)==(start_identity['time_namespace_dev'],start_identity['time_namespace_ino'])
    start_stat=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]
    def process_metadata():
        stdin = Path(f'/proc/{pid}/fd/0').stat()
        key = lambda value: (value.st_dev, value.st_ino, value.st_mode, value.st_rdev)
        aliases = []
        for descriptor in Path(f'/proc/{pid}/fd').iterdir():
            try:
                if key(descriptor.stat()) == key(stdin): aliases.append(int(descriptor.name))
            except FileNotFoundError: pass
        return {'stdin_identity': dict(zip(('dev','ino','mode','rdev'), key(stdin))),
                'stdin_alias_fds': sorted(aliases),
                'tids': sorted(int(t.name) for t in Path(f'/proc/{pid}/task').iterdir()),
                'affinity': sorted(os.sched_getaffinity(pid))}
    process_start = process_metadata()
    command=base+['record','-a','--synth','no','--clockid','mono',
                  '-e','sched:sched_waking','--filter',f'pid == {pid}',
                  '-e','sched:sched_wakeup','--filter',f'pid == {pid}',
                  '-e','sched:sched_switch','--filter',f'prev_pid == {pid} || next_pid == {pid}',
                  '-e','syscalls:sys_enter_read','--filter',f'common_pid == {pid}',
                  '-e','syscalls:sys_exit_read','--filter',f'common_pid == {pid}',
                  '-o',str(directory/'perf.data'),'--','/usr/bin/sleep','10']
    with (directory/'record.log').open('w') as log:
        subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
    assert pid in clients(label,role),'target exited during capture'
    assert identity()==start_identity,'clock identity changed'
    assert Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]==start_stat,'PID generation changed'
    process_end = process_metadata()
    assert process_end == process_start, 'process descriptors, threads or affinity changed'
    decoded=subprocess.run(base+['script','--show-lost-events','--ns','-i',str(directory/'perf.data'),'-F','time,event,trace'],capture_output=True,text=True,check=True)
    # Read entry tracepoint stores a buffer address, not its contents. Strip
    # addresses from exported text; raw perf data remains private temporary data.
    safe=re.sub(r'buf: 0x[0-9a-fA-F]+, ', '', decoded.stdout)
    assert 'LOST' not in safe.upper(),'lost events invalidate capture'
    (directory/'events.txt').write_text(safe)
    (directory/'decode.log').write_text(decoded.stderr)
    attrs=subprocess.run(base+['evlist','-v','-i',str(directory/'perf.data')],capture_output=True,text=True,check=True)
    (directory/'events-attributes.txt').write_text(attrs.stdout)
    metadata={'status':'DIAGNOSTIC','qualification':'NOT_APPLICABLE','target_pid':pid,
              'process_start_ticks':start_stat,'clock_identity':start_identity,
              'process_start':process_start,'process_end':process_end,
              'clock':'CLOCK_MONOTONIC','duration_seconds':10,'command':command,
              'source_build':json.loads((build/'provenance.json').read_text())['source'],
              'scope':'target PID scheduler and read syscall boundaries only; no payloads or stacks; buffer addresses redacted from exported text'}
    (directory/'capture.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print('captured',label,pid,flush=True)

assert not clients('everudp-floor','client') and not clients('zmosh-udp','attach')
cmd=['sudo','-n','env',f'EVERUDP_PERF_BUILD={build}','EVERUDP_FLOOR_TRACE=1','bash',
     str(repo/'crates/everudp/tests/net/bench-performance-block.sh'),'200','0','91403',
     str(root/'measurement'),'zmosh-udp,everudp-floor']
with (root/'benchmark.log').open('w') as log:
    bench=subprocess.Popen(cmd,cwd=repo,stdout=log,stderr=subprocess.STDOUT)
    capture('zmosh-udp','attach',bench)
    capture('everudp-floor','client',bench)
    assert bench.wait(timeout=90)==0,'benchmark failed'
print('matched scheduler diagnostic complete',flush=True)
