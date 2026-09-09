#!/usr/bin/env python3
"""Reproduce diagnostic reports using the b35097b analyzer implementations."""
import hashlib
import json
from pathlib import Path
import re
from statistics import median
import sys

root = Path(__file__).resolve().parent
sys.path.insert(0, str(root.parents[2] / 'crates/everudp/tests/net'))
from analyze_input_schedule import analyze_paths
from analyze_read_schedule import analyze

def read(path):
    return json.loads(path.read_text())

provenance = read(root / 'build-provenance.json')
assert provenance['source']['head_sha'] == '04a04ed8c3156d943fc3584cfa92cd4483fa4bc8'
digest = hashlib.sha256((root / 'build-provenance.json').read_bytes()).hexdigest()
reports = {}
base = root / 'scheduler-only'
meta = read(base / 'capture.json')
candidate = base / 'measurement/everudp-floor'
report = analyze_paths(candidate / 'result.json', candidate / 'client-trace.json',
                       candidate / 'client-trace.json.server.json', base / 'scheduler.txt', meta['target_pid'])
assert report['status'] == 'DIAGNOSTIC', report
reports['scheduler-only'] = report

for order, seed in (('forward', 91402), ('reverse', 91403)):
    base = root / order
    manifest = read(base / 'measurement/manifest.json')
    assert manifest['build']['provenance_sha256'] == digest
    assert not manifest['source']['dirty']
    assert manifest['seeds']['client'] == seed and manifest['trials_per_candidate'] == 200
    expected = ['everudp-floor', 'zmosh-udp']
    assert manifest['order'] == (expected if order == 'forward' else expected[::-1])
    for name, fd in (('everudp-floor', 13), ('zmosh-udp', 0)):
        capture = read(base / name / 'capture.json')
        result = read(base / 'measurement' / name / 'result.json')
        assert capture['clock_identity'] == result['clock_identity']
        assert capture['clock'] == 'CLOCK_MONOTONIC'
        assert capture['source_build'] == provenance['source']
        command = capture['command']
        filters = [command[i+1] for i, value in enumerate(command) if value == '--filter']
        pid = capture['target_pid']
        assert filters == [f'pid == {pid}', f'pid == {pid}',
                           f'prev_pid == {pid} || next_pid == {pid}',
                           f'common_pid == {pid}', f'common_pid == {pid}']
        attrs = (base / name / 'events-attributes.txt').read_text().splitlines()
        for event in ('sched:sched_waking', 'sched:sched_wakeup', 'sched:sched_switch',
                      'syscalls:sys_enter_read', 'syscalls:sys_exit_read'):
            matches = [line for line in attrs if line.startswith(event + ':')]
            assert len(matches) == 1 and 'use_clockid: 1' in matches[0]
            assert re.search(r'(?:, )clockid: 1(?:,|$)', matches[0])
        if order == 'reverse':
            assert capture['process_start'] == capture['process_end']
            assert capture['process_start']['tids'] == [pid]
            assert fd in capture['process_start']['stdin_alias_fds']
        text = (base / name / 'events.txt').read_text()
        assert 'buf:' not in text and 'LOST' not in text.upper()
        report = analyze(result, text, pid, fd)
        assert report['status'] == 'DIAGNOSTIC', report
        report['descriptor_evidence'] = ('recorded stdin identity alias' if order == 'reverse'
                                         else 'temporal/code mapping only; identity not captured')
        reports[f'{order}/{name}'] = report

summary = {}
for name, report in reports.items():
    rows = [row['intervals_ns'] for row in report['rows'] if row['status'] == 'included']
    values = {}
    for key in rows[0]:
        if isinstance(rows[0][key], dict):
            values[key] = {bound: median(row[key][bound] for row in rows) / 1000
                           for bound in ('lower', 'upper')}
        else:
            values[key] = median(row[key] for row in rows) / 1000
    summary[name] = {'included': len(rows), 'excluded': len(report['rows']) - len(rows),
                     'median_us': values}
print(json.dumps({'status': 'DIAGNOSTIC', 'qualification': 'NOT_APPLICABLE',
                  'integration_authorized': False, 'summary': summary, 'reports': reports}, indent=2))
