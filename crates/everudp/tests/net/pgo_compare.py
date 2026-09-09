"""Full frozen numerical comparison, explicitly not release qualification."""
import argparse
import hashlib
import itertools
import json
import os
from pathlib import Path
import shutil
import subprocess


def schedule():
    names = ('everudp', 'zmosh-udp', 'zmosh-quic')
    return [(loss, base + ordinal, ','.join(order))
            for loss, base in ((0, 920000), (5, 930000))
            for ordinal, order in enumerate(itertools.permutations(names), 1)]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args):
    source, candidate, controls, out = args.source, args.candidate, args.controls, args.output
    if not all(path.is_absolute() for path in (source, candidate, controls, out)):
        raise ValueError('absolute paths required')
    if os.geteuid() != 0:
        raise ValueError('root required for namespace benchmark')
    for bundle in (candidate, controls):
        subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=bundle, check=True, stdout=subprocess.DEVNULL)
    build = json.loads((candidate / 'pgo-build.json').read_text())
    control = json.loads((controls / 'provenance.json').read_text())
    if build['status'] != 'BUILT' or build['plan']['phase'] not in ('baseline', 'use'):
        raise ValueError('only successful noninstrumented builds can be compared')
    head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip()
    tree = subprocess.check_output(['git', 'rev-parse', 'HEAD^{tree}'], cwd=source, text=True).strip()
    if build['source'] != {'head_sha': head, 'tree_sha': tree}:
        raise ValueError('candidate source identity mismatch')
    if subprocess.check_output(['git', 'status', '--porcelain'], cwd=source):
        raise ValueError('clean benchmark source required')
    binary = Path(build['binary'])
    if digest(binary) != build['binary_sha256']:
        raise ValueError('candidate binary changed')
    out.mkdir(mode=0o755, parents=True, exist_ok=False)
    bundle = out / 'experimental-build'
    artifacts = bundle / 'artifacts/bin'
    artifacts.mkdir(parents=True)
    receipt = {'schema_version': 1, 'qualification': False, 'status': 'FAILED',
               'candidate': build, 'control_provenance_sha256': digest(controls / 'provenance.json'),
               'runner_sha256': digest(Path(__file__).resolve()), 'blocks': []}
    try:
        for name in ('zmosh-udp', 'zmosh-quic', 'zmosh-quic-bridge', 'pty-bench', 'pty-echo'):
            recorded = control['artifacts'][name]
            original = controls / recorded['path']
            if digest(original) != recorded['sha256']:
                raise ValueError('control artifact changed')
            shutil.copy2(original, artifacts / name)
        shutil.copy2(binary, artifacts / 'everudp')
        receipt['artifacts'] = {p.name: digest(p) for p in sorted(artifacts.iterdir())}
        # No provenance.json: the unchanged release qualifier must reject this experiment.
        (bundle / 'experiment.json').write_text(json.dumps(receipt, indent=2) + '\n')
        net = source / 'crates/everudp/tests/net'
        env = dict(os.environ, EVERUDP_PERF_BUILD=str(bundle), EVERUDP_ALLOW_UNSEALED_BUILD='1',
                   EVERUDP_BENCH_CPUSET='40,42,44,46')
        for loss, seed, order in schedule():
            block = out / f'loss{loss}-{seed}'
            print(f'PGO comparison loss={loss} seed={seed} order={order}', flush=True)
            with (out / f'block-{seed}.log').open('xb') as log:
                subprocess.run([str(net / 'bench-performance-block.sh'), '200', str(loss), str(seed),
                                str(block), order], env=env, stdout=log, stderr=log, check=True)
            receipt['blocks'].append(str(block))
        # allow-smoke only admits the experimental build identity; trials, orders,
        # seeds, bootstrap count and numerical thresholds remain frozen in full.
        subprocess.run(['/usr/bin/python3', '-B', str(net / 'analyze-performance.py'),
                        *receipt['blocks'], '--trials', '200', '--bootstrap', '20000',
                        '--allow-smoke', '--output', str(out / 'analysis.json')], check=True)
        analysis = json.loads((out / 'analysis.json').read_text())
        receipt['numerical_gates_pass'] = analysis['verdict']['all_four_comparisons_pass']
        receipt['status'] = 'COMPARED'
    except Exception as error:
        receipt['error_type'] = type(error).__name__
    finally:
        (out / 'experiment-receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
        files = sorted(p for p in out.rglob('*') if p.is_file() and p.name != 'SHA256SUMS')
        (out / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.relative_to(out)}\n' for p in files))
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source', 'candidate', 'controls', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    result = run(parser.parse_args())
    print(json.dumps({'status': result['status'], 'qualification': False,
                      'numerical_gates_pass': result.get('numerical_gates_pass')}))
    raise SystemExit(0 if result['status'] == 'COMPARED' else 1)
