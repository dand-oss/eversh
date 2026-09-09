"""Diagnostic scheduler waits inside public terminal intervals, not qualification."""
import argparse
import json
from pathlib import Path
import statistics

from analyze_input_schedule import _LINE, _WAKE, _SWITCH
from stream_floor_blocks import public_samples
from stream_floor_evidence import require, sealed


def timelines(text, targets):
    """Return per-target runnable intervals and conservative event coverage."""
    require(len(set(targets.values())) == len(targets), 'duplicate target PID')
    states = {pid: {'state': 'unknown', 'start': None, 'first': None,
                    'last': None, 'waits': []} for pid in targets.values()}
    previous = -1
    for line in text.splitlines():
        match = _LINE.fullmatch(line.strip())
        require(match is not None, 'malformed scheduler event')
        timestamp = int(match['seconds']) * 1_000_000_000 + int(match['fraction'])
        require(timestamp >= previous, 'scheduler time regressed')
        previous = timestamp
        kind, body = match['kind'], match['body']
        if kind == 'sched_switch':
            fields = _SWITCH.fullmatch(body)
            require(fields is not None, 'malformed switch')
            old, new = int(fields['prev_pid']), int(fields['next_pid'])
            require(old != new and (old in states or new in states), 'unscoped switch')
            changes = []
            if old in states:
                changes.append((old, 'out', fields['prev_state']))
            if new in states:
                changes.append((new, 'in', None))
        else:
            fields = _WAKE.fullmatch(body)
            require(fields is not None and int(fields['pid']) in states, 'unscoped wake')
            changes = [(int(fields['pid']), kind, None)]
        for pid, event, old_state in changes:
            item = states[pid]
            if item['first'] is None:
                item['first'] = timestamp
            item['last'] = timestamp
            if event == 'sched_waking':
                # Waking precedes successful enqueue; it is not runnable time.
                continue
            if event == 'in':
                require(item['state'] != 'running', 'missing switch-out event')
                if item['state'] == 'runnable':
                    item['waits'].append((item['start'], timestamp))
                item['state'], item['start'] = 'running', timestamp
            elif event == 'out':
                require(item['state'] in ('unknown', 'running'), 'missing switch-in event')
                item['state'] = 'runnable' if old_state.startswith('R') else 'sleeping'
                item['start'] = timestamp
            elif item['state'] not in ('running', 'runnable'):
                item['state'], item['start'] = 'runnable', timestamp
    for item in states.values():
        require(item['first'] is not None, 'target has no events')
        if item['state'] == 'runnable':
            item['waits'].append((item['start'], item['last']))
    return {role: states[pid] for role, pid in targets.items()}


def correlate(boundaries, tracks):
    start = max(track['first'] for track in tracks.values())
    end = min(track['last'] for track in tracks.values())
    rows = []
    for trial in boundaries:
        low, high = trial['send_ns'], trial['accepted_ns']
        require(high > low, 'invalid public interval')
        row = {'trial': trial['trial'], 'latency_ns': high - low}
        if low < start or high > end:
            row['excluded'] = 'outside conservative scheduler coverage'
        else:
            row['runnable_wait_ns'] = {
                role: sum(max(0, min(high, b) - max(low, a)) for a, b in track['waits'])
                for role, track in tracks.items()
            }
            require(all(0 <= wait <= high - low for wait in row['runnable_wait_ns'].values()),
                    'overlapping or invalid scheduler waits')
        rows.append(row)
    return rows


def analyze(directory):
    sealed(directory)
    read = lambda name: json.loads((directory / name).read_text())
    require(read('receipt.json')['status'] == 'CAPTURED', 'capture is not validated')
    scope = read('scope.json')
    require(scope['before'] == read('scope-after.json'), 'target identity changed')
    attrs = (directory / 'events-attributes.txt').read_text().splitlines()
    event_attrs = [line for line in attrs if line.startswith('sched:')]
    require(len(event_attrs) == 3 and all('use_clockid: 1' in line and 'clockid: 1' in line
            for line in event_attrs), 'scheduler clock is not monotonic')
    result = read('measurement/everudp/result.json')
    public_samples(result)
    clock = result['clock_identity']
    require(clock['boot_id'] == scope['boot_id'], 'boot differs')
    require(all(target['time_namespace'] == [clock['time_namespace_dev'], clock['time_namespace_ino']]
            for target in scope['before'].values()), 'clock namespace differs')
    targets = {role: value['pid'] for role, value in scope['before'].items()}
    tracks = timelines((directory / 'events.txt').read_text(), targets)
    rows = correlate(result['public_boundaries'], tracks)
    included = [row for row in rows if 'excluded' not in row]
    groups = {}
    for name, members in (('all', included), ('over_2ms', [r for r in included if r['latency_ns'] > 2_000_000]),
                          ('at_most_2ms', [r for r in included if r['latency_ns'] <= 2_000_000])):
        groups[name] = {'trials': len(members)}
        if members:
            groups[name]['latency_median_ns'] = statistics.median(r['latency_ns'] for r in members)
            groups[name]['runnable_wait_median_ns'] = {
                role: statistics.median(r['runnable_wait_ns'][role] for r in members) for role in targets}
    return {'status': 'DIAGNOSTIC', 'production_qualification': False,
            'scope': 'target main threads only; do not sum independent process waits or infer exclusive network cost',
            'threshold_note': '2ms grouping is exploratory, not an acceptance threshold',
            'source': read('build-provenance.json')['source'],
            'groups': groups, 'excluded_trials': len(rows) - len(included), 'rows': rows}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('capture', type=Path)
    args = parser.parse_args()
    print(json.dumps(analyze(args.capture), indent=2, sort_keys=True))
