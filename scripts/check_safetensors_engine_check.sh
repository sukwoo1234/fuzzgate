#!/usr/bin/env bash
# Exercise the real engine-check script with inert parser/engine fixtures.
# No native build, fuzzing, AFL++ tooling, or network is used.
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
python3 - "$PROJECT_ROOT" <<'PY'
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

project = Path(sys.argv[1]).resolve()
work = Path(tempfile.mkdtemp(prefix='st-engine-check-'))
passed = 0
failures = []

def executable(path, body):
    path.write_text(f'#!{sys.executable}\n' + body)
    path.chmod(0o755)

def check(name, mode='clean', options=None, *, empty=False, require_aflpp=False):
    root = work / name
    root.mkdir()
    for directory in ('bin', 'seeds', 'malformed', 'tmp with spaces'):
        (root / directory).mkdir()
    # Tool discovery must not depend on whether the host has cargo-afl installed.
    for command in ('bash', 'mktemp', 'cp', 'ls', 'find', 'wc', 'grep', 'rm',
                    'mkdir', 'head', 'tr', 'cat'):
        source = shutil.which(command)
        assert source, f'missing test dependency: {command}'
        (root / 'bin' / command).symlink_to(source)
    if not empty:
        (root / 'seeds/good.safetensors').write_bytes(b'good fixture')
    (root / 'malformed/bad.safetensors').write_bytes(b'malformed fixture')
    executable(root / 'fuzzer', '''import json, os, sys
from pathlib import Path
artifact = Path(next(arg.split('=', 1)[1] for arg in sys.argv if arg.startswith('-artifact_prefix=')))
corpus = Path(sys.argv[-1])
root = Path(os.environ['CHECK_ROOT'])
(root / 'seen.json').write_text(json.dumps({'lsan': os.environ.get('LSAN_OPTIONS'),
    'artifact': str(artifact), 'corpus': str(corpus),
    'inputs': sorted(p.name for p in corpus.iterdir())}))
print('fixture engine diagnostic', flush=True)
mode = os.environ['CHECK_MODE']
if mode in ('crash', 'empty-crash', 'lsan', 'artifact-success'):
    (artifact / 'crash-fixture').write_bytes(b'bad input' if mode in ('crash', 'artifact-success') else b'')
if mode == 'lsan':
    print('==123==LeakSanitizer has encountered a fatal error.', file=sys.stderr)
    print('==123==HINT: LeakSanitizer does not work under ptrace (strace, gdb, etc)', file=sys.stderr)
sys.exit(77 if mode in ('crash', 'empty-crash', 'lsan') else 42 if mode == 'exit' else 0)
''')
    executable(root / 'replay', '''import os, sys
from pathlib import Path
good = Path(sys.argv[1]).name == 'good.safetensors'
print('fixture replay diagnostic', flush=True)
mode = os.environ['CHECK_MODE']
sys.exit(10 if good and mode == 'good-replay-fail' else
         0 if good or mode == 'bad-replay-fail' else 9)
''')
    env = dict(PATH=str(root / 'bin'), HOME=str(root), PROJECT_ROOT=str(project),
               FUZZER=str(root / 'fuzzer'), REPLAY=str(root / 'replay'),
               SEED_DIR=str(root / 'seeds'), MAL_DIR=str(root / 'malformed'),
               TMPDIR=str(root / 'tmp with spaces'), RUNS='2',
               CHECK_ROOT=str(root), CHECK_MODE=mode)
    if options is not None:
        env['LSAN_OPTIONS'] = options
    command = ['bash', str(project / 'scripts/check_safetensors_native_engines.sh')]
    if require_aflpp:
        command.append('--require-aflpp')
    result = subprocess.run(command, env=env, cwd=root, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15)
    (root / 'output.log').write_text(result.stdout)
    seen = json.loads((root / 'seen.json').read_text()) if (root / 'seen.json').exists() else None
    expected_failure = mode != 'clean' or empty or require_aflpp
    assert result.returncode == (1 if expected_failure else 0), (result.returncode, result.stdout)
    if seen:
        assert seen['inputs'] == ['good.safetensors'], seen
    if not expected_failure:
        assert seen['lsan'] == ('detect_leaks=0' if options is None else options), seen
        assert not list((root / 'tmp with spaces').iterdir()), 'successful check left temp data'
        assert 'LSAN_OPTIONS=' in result.stdout, 'effective leak-check policy is not visible'
        return
    match = re.search(r'evidence preserved: (.+)', result.stdout)
    assert match, result.stdout
    evidence = Path(match.group(1))
    assert evidence.is_dir(), f'failure evidence deleted: {evidence}'
    assert evidence.is_relative_to(root / 'tmp with spaces'), evidence
    if empty:
        assert seen is None, 'fuzzer ran without seeds'
        assert 'no seeds' in result.stdout
        return
    assert 'fixture engine diagnostic' in (evidence / 'libfuzzer.log').read_text()
    assert (Path(seen['corpus']) / 'good.safetensors').read_bytes() == b'good fixture'
    if mode in ('crash', 'empty-crash', 'lsan', 'artifact-success'):
        artifact = Path(seen['artifact']) / 'crash-fixture'
        assert artifact.is_file(), 'crash evidence deleted'
        assert artifact.read_bytes() == (b'bad input' if mode in ('crash', 'artifact-success') else b'')
    if mode == 'lsan':
        assert 'LeakSanitizer runtime failed' in result.stdout, result.stdout
        assert 'ptrace' in (evidence / 'libfuzzer.log').read_text()
    elif mode == 'empty-crash':
        assert 'LeakSanitizer runtime failed' not in result.stdout, 'empty input was classified as infrastructure'
    elif mode == 'exit':
        assert 'exited 42' in result.stdout, result.stdout
    elif mode in ('good-replay-fail', 'bad-replay-fail'):
        log = 'replay-good.log' if mode == 'good-replay-fail' else 'replay-malformed.log'
        assert 'fixture replay diagnostic' in (evidence / log).read_text()
    if require_aflpp:
        assert 'AFL++ tooling missing' in result.stdout, result.stdout

cases = [
    ('default-policy', {}),
    ('explicit-policy', dict(options='detect_leaks=1:verbosity=1')),
    ('explicit-empty-policy', dict(options='')),
    ('crash-preserved', dict(mode='crash')),
    ('empty-crash-preserved', dict(mode='empty-crash')),
    ('lsan-environment-failure', dict(mode='lsan', options='detect_leaks=1')),
    ('nonzero-no-artifact', dict(mode='exit')),
    ('artifact-despite-success', dict(mode='artifact-success')),
    ('good-replay-failure', dict(mode='good-replay-fail')),
    ('bad-replay-failure', dict(mode='bad-replay-fail')),
    ('no-seeds', dict(empty=True)),
    ('required-aflpp-missing', dict(require_aflpp=True)),
]
for name, kwargs in cases:
    try:
        check(name, **kwargs)
        passed += 1
        print(f'PASS {name}', flush=True)
    except Exception as error:
        failures.append(name)
        print(f'FAIL {name}: {error}', flush=True)
print(f'[st-engine-check] {passed}/{len(cases)} passed', flush=True)
if failures:
    print(f'[st-engine-check] evidence preserved: {work}', flush=True)
    sys.exit(1)
shutil.rmtree(work)
PY
