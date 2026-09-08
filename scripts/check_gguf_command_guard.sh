#!/usr/bin/env bash
# GGUF campaign overrides must be refused before seeding or starting a backend.
# Uses an isolated launcher fixture; no native engine or network is needed.
set -euo pipefail
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
python3 - "$PROJECT_ROOT" <<'PY'
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

project = Path(sys.argv[1])
work = Path(tempfile.mkdtemp(prefix='gguf-command-guard-'))
failures = []
count = 0

def check(name, override, target='gguf', backend='libfuzzer', native=True):
    global count
    count += 1
    root = work / name
    seed = root / 'seeds' / target
    seed.mkdir(parents=True)
    (seed / 'seed').write_text('fixture seed\n')
    scripts = root / 'scripts'
    scripts.mkdir()
    probe = root / 'probe'
    (scripts / 'run_backend_loop.sh').write_text(
        '#!/usr/bin/env bash\nprintf "%s" "${TOOL_LIBFUZZER_CMD:-}" > "$GUARD_PROBE"\n')
    driver = root / 'harnesses/libfuzzer/gguf_loader_fuzzer'
    if native:
        driver.parent.mkdir(parents=True)
        driver.write_text('#!/usr/bin/env bash\nexit 0\n')
        driver.chmod(0o755)
    env = {
        'PATH': os.environ['PATH'], 'HOME': str(root), 'WORKDIR': str(root),
        'DATA_DIR': str(root / 'output'), 'GUARD_PROBE': str(probe),
        'HOOK_FILE': str(root / 'no-hook'), 'DISCORD_WEBHOOK': '',
        'R28_EXTRA': '-rss_limit_mb=0 -malloc_limit_mb=0',
        'TOOL_AFLPP_CMD': 'true',
    }
    if override is not None:
        env['TOOL_LIBFUZZER_CMD'] = override
    result = subprocess.run(
        ['bash', str(project / 'scripts/run_long.sh'), '--target', target,
         '--backend', backend, '--duration-seconds', '1', '--tag', name],
        cwd=root, env=env, capture_output=True, text=True, timeout=10)
    output = result.stdout + result.stderr
    (root / 'launcher.log').write_text(output)
    rejected = target == 'gguf' and backend == 'libfuzzer' and bool(override)
    try:
        if rejected:
            assert result.returncode == 2, f'expected rc2, got rc{result.returncode}'
            assert not probe.exists(), 'backend started'
            assert not (root / 'data').exists(), 'working corpus was created'
            assert not (root / 'output').exists(), 'run output was created'
            assert 'does not accept TOOL_LIBFUZZER_CMD' in output, 'missing refusal reason'
            assert 'unset TOOL_LIBFUZZER_CMD' in output, 'missing recovery instruction'
        else:
            assert result.returncode == 0, f'expected rc0, got rc{result.returncode}'
            assert probe.exists(), 'backend did not start'
            command = probe.read_text()
            if target == 'gguf' and backend == 'libfuzzer':
                for option in ('-rss_limit_mb=2048', '-malloc_limit_mb=2048'):
                    assert command.split().count(option) == 1, f'wrong limit: {command}'
                mode = 'native' if native else 'blackbox'
                assert f'libfuzzer_mode={mode}' in output, f'wrong mode: {output}'
            else:
                assert command == override, 'unrelated override changed'
        assert not (root / 'shell-executed').exists(), 'override executed during validation'
        assert (seed / 'seed').read_text() == 'fixture seed\n', 'seed changed'
    except AssertionError as exc:
        failures.append(f'{name}: {exc}')
        print(f'[gguf-command-guard] FAIL {failures[-1]}')
    else:
        print(f'[gguf-command-guard] PASS {name}')

bounded = 'true -rss_limit_mb=2048 -malloc_limit_mb=2048 {corpus_dir}'
check('multiline', bounded + ' \\\n-rss_limit_mb=0 -malloc_limit_mb=0')
check('quoted', bounded + " '-rss_limit_mb=0' '-malloc_limit_mb=0'")
check('expanded', bounded + ' $R28_EXTRA')
check('substitution', bounded + ' $(touch shell-executed)')
check('bounded', bounded)
check('missing-limits', 'true {corpus_dir}')
check('duplicate', bounded + ' -rss_limit_mb=0')
check('whitespace', ' \t\n')
check('default-native', None)
check('empty-native', '')
check('default-blackbox', None, native=False)
check('onnx-custom', bounded, target='onnx')
check('safetensors-custom', bounded, target='safetensors')
check('gguf-aflpp', bounded, backend='aflpp')
check('gguf-local', bounded, backend='local-harness')
if failures:
    print(f'[gguf-command-guard] {len(failures)}/{count} failed; evidence: {work}')
    sys.exit(1)
shutil.rmtree(work)
print(f'[gguf-command-guard] PASS: {count} cases')
PY
