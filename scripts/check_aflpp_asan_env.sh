#!/usr/bin/env bash
# Exercise the real tool with an AFL++ option-check fixture; optionally use host AFL++.
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
python3 - "$PROJECT_ROOT" "$TOOL_BIN" "$@" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile

project, tool = map(lambda p: Path(p).resolve(), sys.argv[1:3])
args = sys.argv[3:]
if args not in ([], ['--require-aflpp']):
    sys.exit('usage: check_aflpp_asan_env.sh [--require-aflpp]')
work = Path(tempfile.mkdtemp(prefix='aflpp-asan-env-'))
print(f'[aflpp-asan-env] evidence: {work}', flush=True)
defaults = 'abort_on_error=1:symbolize=0:disable_coredump=1'
corpus = work / 'corpus'
corpus.mkdir()
(corpus / 'seed').write_bytes(b'A')
fixture = work / 'engine.py'
fixture.write_text('''import json, os, resource, sys
from pathlib import Path
run, backend = sys.argv[1:]
options = os.environ.get('ASAN_OPTIONS')
Path(run, 'environment.json').write_text(json.dumps({
    'asan': options, 'core_limit': resource.getrlimit(resource.RLIMIT_CORE)[0]}))
# AFL++ v4.09c src/afl-fuzz-init.c check_asan_opts (normal non-debug build).
# This fixture checks startup only; it does not represent a real fuzzing run.
if backend == 'aflpp' and options is not None:
    for required in ['abort_on_error=1', 'symbolize=0']:
        if required not in options:
            sys.exit('Custom ASAN_OPTIONS set without ' + required + ' - please fix!')
''')
env_base = {k: v for k, v in os.environ.items()
            if not k.startswith(('TOOL_', 'AFL_', 'ASAN_', 'LSAN_', 'MSAN_'))}
env_base.update(TOOL_BACKEND_TRIAGE_MAX_CRASHES='0', TOOL_AFLPP_MODE='blackbox')
results = []

def logged(command, log, env, timeout=20):
    with log.open('w') as stream:
        proc = subprocess.Popen(list(map(str, command)), cwd=project, env=env,
                                stdout=stream, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            return proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
            raise AssertionError(f'timed out: {log}')

def run_case(name, supplied, expected, backend='aflpp', prefix='', native=None):
    root = work / name
    root.mkdir()
    data = root / 'data'
    env = dict(env_base)
    if supplied is not None:
        env['ASAN_OPTIONS'] = supplied
    command = (f'{shlex.quote(sys.executable)} {shlex.quote(str(fixture))} '
               '{run_dir} ' + backend)
    if native:
        afl, target = native
        command = (f'{shlex.quote(afl)} -i {shlex.quote(str(corpus))} '
                   '-o {run_dir}/afl-out -V 3 -m 128 -- '
                   f'{shlex.quote(str(target))} @@')
        env.update(AFL_NO_UI='1', AFL_SKIP_CPUFREQ='1', AFL_NO_AFFINITY='1',
                   AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES='1')
    env['TOOL_AFLPP_CMD' if backend == 'aflpp' else 'TOOL_LIBFUZZER_CMD'] = prefix + command
    rc = logged([tool, '--data-dir', data, '--seeds-dir', work / 'seeds',
                 'run', '--target', 'onnx', '--backend', backend, '--workers', '1',
                 '--timeout-sec', '10', '--restart-limit', '0', '--corpus-dir', corpus],
                root / 'tool.log', env)
    paths = list(data.glob('runs/run-*/status.json'))
    assert len(paths) == 1, (rc, paths)
    run = paths[0].parent
    status = json.loads(paths[0].read_text())
    failed = int(backend == 'aflpp' and any(
        flag not in expected for flag in ['abort_on_error=1', 'symbolize=0']))
    assert rc == (5 if failed else 0), (rc, status)
    assert (status['total'], status['success'], status['failed']) == (1, 1-failed, failed), status
    for key in ['timeout', 'worker_errors', 'job_errors', 'backend_crash_scan_errors',
                'backend_crashes_triaged', 'backend_crash_triage_errors']:
        assert status[key] == 0, (key, status)
    events = [json.loads(line) for line in (data / 'metrics/events.jsonl').read_text().splitlines()]
    assert len(events) == 1, events
    event = events[0]
    assert (event['kind'], event['total'], event['errors'], event['successful_runs_proxy']) == (
        'run-backend', 1, failed, 1-failed), event
    if not native:
        observed = json.loads((run / 'environment.json').read_text())
        assert observed['asan'] == expected, observed
        if shutil.which('prlimit'):
            assert observed['core_limit'] == 0, observed
    else:
        stats_paths = list(run.glob('afl-out/*/fuzzer_stats'))
        assert len(stats_paths) == 1, stats_paths
        stats = dict(line.split(':', 1) for line in stats_paths[0].read_text().splitlines() if ':' in line)
        stats = {k.strip(): v.strip() for k, v in stats.items()}
        assert int(stats['execs_done']) > 0, stats
        assert status['backend_crash_artifacts'] > 0, status
        manifest = json.loads((run / 'backend-crashes/manifest.json').read_text())
        assert manifest['discovered'] == len(manifest['artifacts']) == status['backend_crash_artifacts']
        assert all(a['triage_status'] == 'skipped_limit' for a in manifest['artifacts'])
        (root / 'native-proof.json').write_text(json.dumps(stats, indent=2) + '\n')
    if failed:
        assert 'Custom ASAN_OPTIONS set without' in (run / 'logs/backend-engine-w1.log').read_text()
    proof = {'tool_rc': rc, 'native': native is not None}
    if native:
        proof.update(execs_done=int(stats['execs_done']),
                     crash_artifacts=status['backend_crash_artifacts'])
    return proof

def check(name, *args, **kwargs):
    try:
        proof = run_case(name, *args, **kwargs)
        results.append(dict(proof, case=name, passed=True))
        print(f'[aflpp-asan-env] PASS {name}', flush=True)
    except Exception as error:
        results.append({'case': name, 'passed': False, 'error': str(error)})
        print(f'[aflpp-asan-env] FAIL {name}: {error}', flush=True)

check('unset', None, defaults)
check('empty', '', defaults)
check('whitespace', ' \t ', defaults)
check('explicit-valid', 'abort_on_error=1:symbolize=0:detect_leaks=0',
      'abort_on_error=1:symbolize=0:detect_leaks=0:disable_coredump=1')
check('explicit-core', 'abort_on_error=1:symbolize=0:disable_coredump=0',
      'abort_on_error=1:symbolize=0:disable_coredump=0')
check('explicit-incomplete', 'detect_leaks=0', 'detect_leaks=0:disable_coredump=1')
check('explicit-no-abort', 'abort_on_error=0:symbolize=0',
      'abort_on_error=0:symbolize=0:disable_coredump=1')
check('explicit-symbolize', 'abort_on_error=1:symbolize=1',
      'abort_on_error=1:symbolize=1:disable_coredump=1')
check('template-override', None, 'abort_on_error=1:symbolize=0:detect_leaks=0',
      prefix='ASAN_OPTIONS=abort_on_error=1:symbolize=0:detect_leaks=0 ')
check('libfuzzer-unset', None, 'disable_coredump=1', backend='libfuzzer')
check('libfuzzer-explicit', 'symbolize=1', 'symbolize=1:disable_coredump=1', backend='libfuzzer')

metadata = {'tool_sha256': hashlib.sha256(tool.read_bytes()).hexdigest(),
            'run_source_sha256': hashlib.sha256((project / 'src/run.rs').read_bytes()).hexdigest()}
if args and all(item['passed'] for item in results):
    try:
        metadata['host'] = platform.node()
        metadata['kernel'] = platform.release()
        metadata['allowed_cpus'] = len(os.sched_getaffinity(0))
        metadata['memory_kib'] = {line.split(':')[0]: int(line.split()[1]) for line in
                                  Path('/proc/meminfo').read_text().splitlines()
                                  if line.split(':')[0] in {'MemTotal', 'MemAvailable'}}
        metadata['tmp_free_bytes'] = shutil.disk_usage(work).free
        afl = shutil.which('afl-fuzz')
        compiler = shutil.which('afl-clang-fast') or shutil.which('afl-clang-fast++')
        assert afl and compiler, 'host AFL++ tools missing; no installation attempted'
        source, target = work / 'target.c', work / 'target'
        source.write_text('#include <stdio.h>\n#include <stdlib.h>\n'
                          'int main(int argc, char **argv) {\n'
                          'if (argc != 2) return 2; FILE *f = fopen(argv[1], "rb");\n'
                          'if (!f) return 2; int c = fgetc(f); fclose(f);\n'
                          'if (c != EOF && c != 65) abort(); return 0; }\n')
        assert logged([compiler, '-O0', source, '-o', target], work / 'compile.log', env_base) == 0
        metadata.update({name: {'path': str(path), 'sha256': hashlib.sha256(Path(path).read_bytes()).hexdigest()}
                         for name, path in [('afl', afl), ('compiler', compiler), ('target', target)]})
        for name, supplied, expected in [('native-unset', None, defaults), ('native-empty', '', defaults),
                                        ('native-explicit', defaults + ':detect_leaks=0', defaults + ':detect_leaks=0')]:
            check(name, supplied, expected, native=(afl, target))
    except Exception as error:
        results.append({'case': 'native-setup', 'passed': False, 'error': str(error)})
        print(f'[aflpp-asan-env] FAIL native-setup: {error}', flush=True)
passed = sum(item['passed'] for item in results)
summary = dict(metadata, cases=results, evidence=str(work),
               scope='Startup environment contract; optional synthetic C target, not parser qualification.')
(work / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
if args:
    print(json.dumps(summary, indent=2), flush=True)
print(f'[aflpp-asan-env] {passed}/{len(results)} passed; evidence preserved: {work}', flush=True)
sys.exit(0 if passed == len(results) else 1)
PY
