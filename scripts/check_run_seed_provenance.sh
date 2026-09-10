#!/usr/bin/env bash
# R18: real launchers and status writer, inert engines and a one-run fixture clock.
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
python3 - "$PROJECT_ROOT" "$TOOL_BIN" <<'PY'
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

project, tool = map(lambda p: Path(p).resolve(), sys.argv[1:])
work = Path(tempfile.mkdtemp(prefix='run-seed-provenance-'))
failures = []
passed = 0

def executable(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    path.chmod(0o755)

def setup(name, derived=True):
    root = work / name
    (root / 'seeds/gguf').mkdir(parents=True)
    (root / 'seeds/gguf/seed.gguf').write_bytes(b'invalid fixture input')
    if derived:
        (root / 'data/corpus/gguf-libfuzzer').mkdir(parents=True)
        (root / 'data/corpus/gguf-libfuzzer/seed.gguf').write_bytes(b'reduced fixture')
    shutil.copytree(project / 'scripts', root / 'scripts')
    executable(root / 'harnesses/libfuzzer/gguf_loader_fuzzer', '#!/bin/sh\nexit 0\n')
    executable(root / 'bin/date', '''#!/bin/bash
if [[ "$*" == '+%s' ]]; then
  if [[ -e "$DATA_DIR/ticked" ]]; then echo 1; else echo 0; fi
else
  exec /bin/date "$@"
fi
''')
    executable(root / 'bin/tool', '''#!/bin/bash
"$CHECK_REAL_TOOL" "$@"
rc=$?
touch "$DATA_DIR/ticked"
exit "$rc"
''')
    executable(root / 'bin/curl', '#!/bin/sh\necho "unexpected notification" >&2\nexit 99\n')
    env = dict(PATH=f'{root}/bin:{os.environ["PATH"]}', HOME=str(root),
               WORKDIR=str(root), TOOL_BIN=str(root / 'bin/tool'),
               CHECK_REAL_TOOL=str(tool), DATA_DIR=str(root / 'out'),
               HOOK_FILE=str(root / 'no-hook'), DISCORD_WEBHOOK='', LOOP_SLEEP_SEC='0',
               TOOL_AFLPP_CMD='true', GGUF_LIBFUZZER_CORPUS_CAP='1048576')
    return root, env

def run(root, env, args):
    result = subprocess.run(list(map(str, args)), cwd=root, env=env,
                            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=20)
    with (root / 'commands.log').open('a') as log:
        log.write(f'{args!r}\nrc={result.returncode}\n{result.stdout}\n')
    assert result.returncode == 0, (result.returncode, result.stdout[-3000:])
    return result.stdout

def status(data, corpus, fixture):
    paths = list((data / 'runs').glob('run-*/status.json'))
    assert len(paths) == 1, paths
    body = json.loads(paths[0].read_text())
    assert body['corpus_dir'] == str(corpus), body
    assert body['seed_fixture'] == (None if fixture is None else str(fixture)), body
    assert body['total'] == 1 and body['failed'] == 0, body
    return paths[0]

def direct(name, backend, supplied):
    root, env = setup(name)
    corpus = root / 'caller "corpus"\\\t\n\x01'
    shutil.copytree(root / 'seeds/gguf', corpus)
    source = root / 'source "fixture"\\\t\n\x02'
    env['TOOL_LIBFUZZER_CMD'] = 'true'
    args = [tool, '--data-dir', root / 'out', 'run', '--target', 'gguf',
            '--backend', backend, '--workers', '1', '--restart-limit', '0',
            '--corpus-dir', corpus]
    if supplied:
        args += ['--seed-fixture', source]
    run(root, env, args)
    status(root / 'out', corpus, source if supplied else None)

def launcher(name, derived=True, explicit=False, supplied=False, backend='libfuzzer'):
    root, env = setup(name, derived)
    # Ambient shell state must not invent provenance for an explicit corpus.
    env['SEED_FIXTURE'] = '/stale/fixture'
    corpus = root / 'seeds/gguf'
    fixture = corpus
    args = ['bash', root / 'scripts/run_long.sh', '--target', 'gguf',
            '--backend', backend, '--duration-seconds', '1', '--tag', name, '--workers', '1']
    if explicit:
        corpus = root / 'caller corpus'
        shutil.copytree(root / 'seeds/gguf', corpus)
        args += ['--corpus-dir', corpus]
        fixture = None
        if supplied:
            fixture = root / 'seeds/gguf'
            args += ['--seed-fixture', fixture]
    elif backend == 'libfuzzer':
        corpus = root / 'data/corpus/libfuzzer/gguf'
        fixture = root / ('data/corpus/gguf-libfuzzer' if derived else 'seeds/gguf')
    else:
        # The launcher uses this relative spelling for non-libFuzzer defaults.
        corpus = Path('seeds/gguf')
        fixture = corpus
    run(root, env, args)
    status(root / 'out', corpus, fixture)
    if explicit:
        assert not (root / 'data/corpus/libfuzzer/gguf').exists()

def campaign(mode, cli=False):
    name = f'campaign-{mode}-{cli}'
    root, env = setup(name)
    if cli:
        # tool campaign passes its own executable to the loop; wrap the launcher's
        # tool invocation only to advance the fixture clock after the real run.
        original = (root / 'scripts/run_backend_loop.sh').read_text()
        (root / 'scripts/run_backend_loop.sh').write_text(
            original.replace('"${cmd[@]}"', '"${cmd[@]}"; touch "$DATA_DIR/ticked"'))
        args = [tool, 'campaign']
    else:
        args = ['bash', root / 'scripts/run_campaign.sh']
    args += ['--mode', mode, '--target', 'gguf', '--duration-seconds', '1',
             '--campaign-id', name, '--backends', 'libfuzzer,aflpp',
             '--corpus-dir', root / 'seeds/gguf', '--data-root', root / 'campaigns']
    run(root, env, args)
    base = root / 'campaigns' / name
    manifest = json.loads((base / 'manifest.json').read_text())
    assert manifest['corpus_source'] == str(root / 'seeds/gguf')
    for backend in ['libfuzzer', 'aflpp']:
        arm = base / 'arms' / backend
        status(arm / 'data', arm / 'corpus/gguf', base / 'seeds/gguf')

def loop_unknown():
    root, env = setup('loop-unknown')
    env.update(TARGET='gguf', BACKEND='aflpp', CORPUS_DIR=str(root / 'seeds/gguf'),
               WORKERS='1', DURATION_SECONDS='1', TAG='direct-loop')
    run(root, env, ['bash', root / 'scripts/run_backend_loop.sh'])
    status(root / 'out', root / 'seeds/gguf', None)

def ops_libfuzzer(derived):
    root, env = setup(f'ops-libfuzzer-{derived}', derived)
    env.update(PROJECT_ROOT=str(root), TARGET='gguf', WORKERS='1',
               FUZZ_LOOP_MAX_ITERATIONS='1', TOOL_BIN=str(tool))
    run(root, env, ['bash', project / 'ops/scripts/fuzz-loop-libfuzzer.sh'])
    status(root / 'data', root / 'data/corpus/libfuzzer/gguf',
           root / ('data/corpus/gguf-libfuzzer' if derived else 'seeds/gguf'))

def compatibility():
    root, env = setup('compatibility')
    data = root / 'out'
    corpus = root / 'seeds/gguf'
    run(root, env, [tool, '--data-dir', data, 'run', '--target', 'gguf',
                   '--backend', 'aflpp', '--workers', '1', '--corpus-dir', corpus,
                   '--seed-fixture', corpus])
    path = status(data, corpus, corpus)
    current = json.loads(path.read_text())
    # Unknown additive fields must not disturb the existing dashboard or export.
    # A legacy status lacking both fields must still work unchanged as well.
    for label in ['current', 'legacy']:
        if label == 'legacy':
            del current['corpus_dir']
            del current['seed_fixture']
            path.write_text(json.dumps(current, indent=2) + '\n')
        dashboard = run(root, env, [tool, '--data-dir', data, 'dashboard', '--format', 'json'])
        snapshot = json.loads(dashboard)
        assert snapshot['run_state']['target'] == 'gguf', snapshot
        assert snapshot['run_state']['total'] == '1', snapshot
        out = root / f'export-{label}'
        result = subprocess.run([
            'bash', str(project / 'scripts/export_experiment_summary.sh'),
            '--experiment-id', label, '--machine-label', 'fixture', '--target', 'gguf',
            '--backend', 'aflpp', '--duration-hours', '1', '--out-dir', str(out),
            '--data-dir', str(data), '--corpus-dir', str(corpus),
            '--run-status-file', str(path)], cwd=project, env=env,
            text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=20)
        (root / f'export-{label}.log').write_text(result.stdout)
        assert result.returncode == 0, result.stdout
        assert (out / 'run-status.json').read_bytes() == path.read_bytes()

cases = [
    ('direct-unknown', lambda: direct('direct-unknown', 'libfuzzer', False)),
    ('direct-source-escaping', lambda: direct('direct-source-escaping', 'libfuzzer', True)),
    ('local-source-escaping', lambda: direct('local-source-escaping', 'local-harness', True)),
    ('default-derived', lambda: launcher('default-derived')),
    ('default-fallback', lambda: launcher('default-fallback', derived=False)),
    ('explicit-unknown', lambda: launcher('explicit-unknown', explicit=True)),
    ('explicit-source', lambda: launcher('explicit-source', explicit=True, supplied=True)),
    ('aflpp-default', lambda: launcher('aflpp-default', backend='aflpp')),
    ('campaign-serial', lambda: campaign('serial')),
    ('campaign-parallel', lambda: campaign('parallel')),
    ('campaign-cli', lambda: campaign('serial', cli=True)),
    ('loop-unknown', loop_unknown),
    ('reader-export-compatibility', compatibility),
    ('ops-libfuzzer-derived', lambda: ops_libfuzzer(True)),
    ('ops-libfuzzer-fallback', lambda: ops_libfuzzer(False)),
]
for name, check in cases:
    try:
        check()
        passed += 1
        print(f'[run-seed-provenance] PASS {name}', flush=True)
    except Exception as error:
        failures.append(name)
        print(f'[run-seed-provenance] FAIL {name}: {error}', flush=True)
print(f'[run-seed-provenance] {passed}/{len(cases)} passed', flush=True)
if failures:
    print(f'[run-seed-provenance] evidence preserved: {work}', flush=True)
    sys.exit(1)
shutil.rmtree(work)
PY
