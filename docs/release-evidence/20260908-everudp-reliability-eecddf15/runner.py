import hashlib
import json
from pathlib import Path
import subprocess

source = Path('/tmp/eversh-pgo-source')
binary = Path('/tmp/everudp-pgo-baseline/target/x86_64-unknown-linux-gnu/release/everudp')
root = Path('/tmp/everudp-full-reliability-eecddf15')
root.mkdir(mode=0o700, exist_ok=False)
digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
receipt = {'status': 'FAILED', 'scope': 'full reliability only', 'product_qualification': False,
           'source_sha': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=source, text=True).strip(),
           'binary_sha256': digest(binary), 'runner_sha256': digest(Path(__file__))}
assert receipt['source_sha'] == 'eecddf15f4d8eb72f0f887cc5ec6ac5bae614bc5'
assert receipt['binary_sha256'] == 'a70b52c3851e7723282ec4c79a85b6809057d475a04266e1c7520d40ea19dd04'
assert not subprocess.check_output(['git', 'status', '--porcelain'], cwd=source)
command = ['sudo', '-n', '/usr/bin/env', '-u', 'EVERUDP_ONLY', '-u', 'EVERUDP_ALLOW_DIRTY',
           '-u', 'EVERUDP_RUN_12H_SOAK', 'EVERUDP_SMOKE=0', f'EVERUDP_BIN={binary}',
           '/usr/bin/bash', str(source / 'crates/everudp/tests/net/test-reliability.sh'), str(root / 'gate')]
receipt['command'] = command
try:
    with (root / 'runner.log').open('xb') as log:
        result = subprocess.run(command, cwd=source, stdout=log, stderr=log)
    receipt['exit_code'] = result.returncode
    assert digest(binary) == receipt['binary_sha256']
    if result.returncode == 0:
        gate = json.loads((root / 'gate/receipt.json').read_text())
        assert gate['verdict'] == 'PASS' and gate['smoke'] is False
        subprocess.run(['sha256sum', '-c', 'SHA256SUMS'], cwd=root / 'gate', check=True, stdout=subprocess.DEVNULL)
        receipt['status'] = 'PASS'
except Exception as error:
    receipt['error_type'] = type(error).__name__
finally:
    (root / 'receipt.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    files = [root / 'receipt.json', root / 'runner.log']
    (root / 'SHA256SUMS').write_text(''.join(f'{digest(p)}  {p.name}\n' for p in files if p.exists()))
print(json.dumps({'status': receipt['status'], 'product_qualification': False}))
raise SystemExit(0 if receipt['status'] == 'PASS' else 1)
