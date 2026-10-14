#!/usr/bin/env python3
"""Black-box contract tests for the FND-03 format acceptance runner.

The tests use only private temporary fixtures.  They deliberately exercise
false-pass cases: empty or incomplete suites, a final successful task after an
earlier failure, skipped work, bounded subprocess failures, interrupted runs,
and an injected atomic-record commit failure.
"""

from __future__ import annotations

from contextlib import redirect_stderr
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path(
    os.environ.get(
        "FORMAT_ACCEPTANCE_RUNNER_UNDER_TEST",
        ROOT / "scripts" / "check_format_acceptance.py",
    )
).resolve()
TARGET = "onnx"
SUITE = "unit"
RESULT_ENV = "FORMAT_ACCEPTANCE_RESULT_PATH"
HOOK_ENV = "FORMAT_ACCEPTANCE_TEST_HOOK"
STATUS_NAMES = ("pass", "fail", "blocked", "not_run", "inconclusive")
SUMMARY_COUNTS = {name: 0 for name in STATUS_NAMES}
RECORD_FIELDS = {
    "schema_version",
    "requirement_id",
    "task_id",
    "status",
    "reason",
    "expected",
    "observed",
    "command_argv",
    "command_executable",
    "identity_files",
    "cwd",
    "allowed_env",
    "tool_commit",
    "dirty_diff_sha256",
    "validation_run_id",
    "profile_sha256",
    "corpus_index_sha256",
    "start_utc",
    "end_utc",
    "elapsed_ms",
    "exit_code",
    "signal",
    "stdout",
    "stderr",
    "result",
    "artifacts",
}


class TestFailure(AssertionError):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TestFailure(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_json(path: Path) -> dict[str, Any]:
    require(path.is_file(), f"missing JSON file: {path}")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TestFailure(f"invalid JSON file {path}: {error}") from error
    require(isinstance(value, dict), f"JSON root is not an object: {path}")
    return value


def load_runner_library() -> Any:
    path = RUNNER.parent / "lib" / "format_acceptance.py"
    name = f"_format_acceptance_selftest_{os.getpid()}"
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, f"could not load runner library: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def process_alive(pid: int) -> bool:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except (FileNotFoundError, ProcessLookupError):
        return False
    except OSError:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        return True
    fields = text.split()
    return len(fields) < 3 or fields[2] != "Z"


def process_parent_pid(pid: int) -> int | None:
    try:
        fields = Path(f"/proc/{pid}/stat").read_text(encoding="ascii").split()
        return int(fields[3]) if len(fields) > 3 else None
    except (FileNotFoundError, OSError, ValueError):
        return None


def read_pids(path: Path) -> list[int]:
    if not path.is_file():
        return []
    result: list[int] = []
    for value in path.read_text(encoding="ascii").splitlines():
        try:
            result.append(int(value))
        except ValueError:
            pass
    return result


def kill_fixture_processes(path: Path) -> None:
    for pid in reversed(read_pids(path)):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass


def wait_processes_gone(path: Path, seconds: float = 3.0) -> None:
    pids = read_pids(path)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline and any(process_alive(pid) for pid in pids):
        time.sleep(0.03)
    live = [pid for pid in pids if process_alive(pid)]
    require(not live, f"fixture process tree survived: {live}")


FIXTURE_SOURCE = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

RESULT_ENV = "FORMAT_ACCEPTANCE_RESULT_PATH"

def emit(status, reason, expected=None, observed=None, artifacts=None):
    path = os.environ.get(RESULT_ENV)
    if not path:
        print("missing FORMAT_ACCEPTANCE_RESULT_PATH", file=sys.stderr)
        raise SystemExit(70)
    value = {
        "schema_version": "1",
        "status": status,
        "reason": reason,
        "expected": expected,
        "observed": observed,
        "validation_run_id": os.environ.get("TOOL_VALIDATION_RUN"),
        "corpus_index_sha256": None,
        "artifacts": list(artifacts or []),
    }
    with open(path, "x", encoding="utf-8") as handle:
        json.dump(value, handle, sort_keys=True)
        handle.write("\n")

mode = sys.argv[1]
args = sys.argv[2:]
if mode == "pass":
    emit("pass", "fixture passed", "pass", "pass")
    print("ok")
    raise SystemExit(0)
if mode == "pass-with-skip":
    emit("pass", "fixture incorrectly claimed pass while skipping", "pass", "skip")
    print("SKIP: fixture prerequisite absent")
    raise SystemExit(0)
if mode == "pass-with-skip-count":
    emit("pass", "fixture incorrectly claimed pass with a skip count", "pass", "skip")
    print("[fixture] pass=1 fail=0 skip=1")
    raise SystemExit(0)
if mode == "pass-with-pytest-skip":
    emit("pass", "fixture incorrectly claimed pass with pytest skips", "pass", "skip")
    print("1 passed, 1 skipped in 0.01s")
    raise SystemExit(0)
if mode == "pass-without-measurement":
    emit("pass", "fixture omitted its measurement")
    raise SystemExit(0)
if mode == "stale-result":
    path = os.environ[RESULT_ENV]
    Path(path).write_text(
        json.dumps({
            "schema_version": "1",
            "status": "pass",
            "reason": "replayed result without this run's nonce",
            "expected": "fresh",
            "observed": "stale",
            "corpus_index_sha256": None,
            "artifacts": [],
        }, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    raise SystemExit(0)
if mode == "profile-binding":
    expected_path = str(Path(args[0]).resolve())
    actual_path = os.environ.get("TOOL_TARGET_PROFILE")
    actual_hash = os.environ.get("TOOL_PROFILE_SHA256")
    validation_id = os.environ.get("TOOL_VALIDATION_RUN")
    digest = hashlib.sha256(Path(expected_path).read_bytes()).hexdigest()
    observed = {
        "path": actual_path,
        "sha256": actual_hash,
        "validation_run": validation_id,
    }
    if actual_path == expected_path and actual_hash == digest and validation_id:
        emit("pass", "profile identity reached the child", "bound", observed)
        raise SystemExit(0)
    emit("fail", "profile identity was not bound into the child", "bound", observed)
    raise SystemExit(1)
if mode == "fail":
    emit("fail", "fixture found a mismatch", "pass", "fail")
    print("fixture failure", file=sys.stderr)
    raise SystemExit(1)
if mode == "fail-flood-stdout":
    emit("fail", "fixture found a mismatch before flooding output", "pass", "fail")
    sys.stdout.write("F" * 65536)
    sys.stdout.flush()
    raise SystemExit(1)
if mode == "literal-arguments":
    expected_args = ["--verdict=fail", "unit"]
    if args == expected_args:
        emit("fail", "literal arguments retained their declared meaning", expected_args, args)
        raise SystemExit(1)
    emit("pass", "literal arguments were rewritten", expected_args, args)
    raise SystemExit(0)
if mode == "blocked":
    emit("blocked", "fixture prerequisite absent", "available", None)
    raise SystemExit(2)
if mode == "inconclusive":
    emit("inconclusive", "fixture evidence was insufficient", "measured", None)
    raise SystemExit(2)
if mode == "ok-only":
    print("ok")
    raise SystemExit(0)
if mode == "skip-only":
    print("SKIP: fixture prerequisite absent")
    raise SystemExit(0)
if mode == "duplicate-key-result":
    path = os.environ[RESULT_ENV]
    Path(path).write_text(
        '{"schema_version":"1","status":"pass","status":"fail",'
        '"reason":"duplicate","expected":null,"observed":null,'
        '"corpus_index_sha256":null,"artifacts":[]}\n',
        encoding="utf-8",
    )
    raise SystemExit(0)
if mode == "mark-pass":
    Path(args[0]).write_text("spawned\n", encoding="utf-8")
    emit("pass", "marked and passed", "spawned", "spawned")
    raise SystemExit(0)
if mode == "mutate-profile":
    with open(args[0], "ab") as handle:
        handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    emit("pass", "profile was changed by the fixture", "unchanged", "changed")
    raise SystemExit(0)
if mode == "fail-and-mutate-profile":
    with open(args[0], "ab") as handle:
        handle.write(b"\n")
        handle.flush()
        os.fsync(handle.fileno())
    emit("fail", "fixture found a mismatch before changing the profile", "pass", "fail")
    raise SystemExit(1)
if mode == "hang":
    ready, pid_file = map(Path, args)
    child = subprocess.Popen([sys.executable, "-B", "-c", "import time; time.sleep(60)"])
    pid_file.write_text(f"{os.getpid()}\n{child.pid}\n", encoding="ascii")
    ready.write_text("ready\n", encoding="ascii")
    while True:
        time.sleep(60)
if mode == "pass-with-orphan":
    pid_file = Path(args[0])
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid_file.write_text(f"{child.pid}\n", encoding="ascii")
    emit("pass", "parent passed after spawning a descendant", "reaped", "running")
    raise SystemExit(0)
if mode == "pass-with-detached-orphan":
    pid_file = Path(args[0])
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", "import time; time.sleep(60)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid_file.write_text(f"{child.pid}\n", encoding="ascii")
    emit("pass", "parent passed after spawning a detached descendant", "reaped", "detached")
    raise SystemExit(0)
if mode == "pass-with-detached-term-ignorer":
    pid_file, ready = map(Path, args)
    code = (
        "import pathlib, signal, time; "
        "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        f"pathlib.Path({str(ready)!r}).write_text('ready\\n'); "
        "time.sleep(60)"
    )
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", code],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    pid_file.write_text(f"{child.pid}\n", encoding="ascii")
    deadline = time.monotonic() + 3.0
    while not ready.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    emit("pass", "parent passed with a detached TERM-ignoring child", "reaped", "detached")
    raise SystemExit(0)
if mode == "signal-mask":
    blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    observed = sorted(int(value) for value in blocked)
    if all(value not in blocked for value in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)):
        emit("pass", "task inherited an unblocked control-signal mask", [], observed)
        raise SystemExit(0)
    emit("fail", "task inherited blocked control signals", [], observed)
    raise SystemExit(1)
if mode == "artifact-via-symlink":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    (task_dir / "escape").symlink_to(Path(args[0]), target_is_directory=True)
    emit(
        "pass",
        "fixture tried to escape its task directory",
        "contained",
        "symlink",
        ["escape/proof.bin"],
    )
    raise SystemExit(0)
if mode == "hardlink-artifact":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    os.link(args[0], task_dir / "proof.bin")
    emit("pass", "fixture linked an external artifact", "private", "hardlink", ["proof.bin"])
    raise SystemExit(0)
if mode == "write-artifact":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    relative = args[0]
    (task_dir / relative).write_bytes(b"original artifact\n")
    emit("pass", "artifact created", "original", "original", [relative])
    raise SystemExit(0)
if mode == "mutate-file":
    Path(args[0]).write_bytes(b"mutated after publication\n")
    emit("pass", "prior file mutated", "mutated", "mutated")
    raise SystemExit(0)
if mode == "switch-symlink":
    alias, replacement = map(Path, args)
    alias.unlink()
    alias.symlink_to(replacement, target_is_directory=True)
    emit("pass", "path alias switched after runner setup", "canonical", "switched")
    raise SystemExit(0)
if mode == "switch-executable":
    root = Path(args[0])
    alias, replacement = root / args[1], root / args[2]
    alias.unlink()
    alias.symlink_to(replacement)
    emit("pass", "command alias switched after preflight", "pinned", "switched")
    raise SystemExit(0)
if mode == "replace-file":
    target, replacement = map(Path, args)
    target.write_bytes(replacement.read_bytes())
    emit("pass", "fixture replaced a later task file", "pinned", "replaced")
    raise SystemExit(0)
if mode == "rewrite-restore-mtime":
    target = Path(args[0])
    before = target.stat()
    original = target.read_bytes()
    replacement = bytes((value ^ 1) for value in original)
    target.write_bytes(replacement)
    os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    emit("pass", "fixture rewrote identity bytes and restored mtime", "unchanged", "rewritten")
    raise SystemExit(0)
if mode == "write-undeclared":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    (task_dir / "undeclared.bin").write_bytes(b"not in the artifact contract\n")
    emit("pass", "fixture wrote undeclared evidence", "declared only", "extra")
    raise SystemExit(0)
if mode == "forge-candidate":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    (evidence_dir / "qualification.candidate.json").write_text(
        '{"status":"verified"}\n', encoding="utf-8"
    )
    emit("pass", "fixture forged a qualification candidate", "absent", "forged")
    raise SystemExit(0)
if mode == "forge-summary":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    (evidence_dir / "summary.json").write_text(
        '{"schema_version":"1","state":"complete","overall_status":"pass"}\n',
        encoding="utf-8",
    )
    emit("pass", "fixture preempted the terminal summary", "absent", "forged")
    raise SystemExit(0)
if mode == "forge-summary-lock-root":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    (evidence_dir / "summary.json").write_text(
        '{"schema_version":"1","state":"complete","overall_status":"pass"}\n',
        encoding="utf-8",
    )
    evidence_dir.chmod(0o500)
    emit("pass", "fixture forged a summary and locked the root", "absent", "forged")
    raise SystemExit(0)
if mode == "huge-skip-count":
    print("skip=" + "9" * 5000)
    emit("pass", "fixture reported a huge skip count", "no skips", "huge skip")
    raise SystemExit(0)
if mode == "replace-evidence-root":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    backup = Path(args[0])
    task_id = os.environ["FORMAT_ACCEPTANCE_TASK_ID"]
    evidence_dir.rename(backup)
    evidence_dir.mkdir(mode=0o755)
    for name in ("records", "logs", "tasks", "requirements"):
        (evidence_dir / name).mkdir(mode=0o755)
    (evidence_dir / "tasks" / task_id).mkdir(mode=0o755)
    (evidence_dir / "run.json").write_bytes((backup / "run.json").read_bytes())
    emit("pass", "fixture replaced the evidence root", "same inode", "replacement")
    raise SystemExit(0)
if mode == "replace-evidence-with-symlink":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    backup, external = map(Path, args)
    task_id = os.environ["FORMAT_ACCEPTANCE_TASK_ID"]
    evidence_dir.rename(backup)
    for name in ("records", "logs", "tasks", "requirements"):
        (external / name).mkdir(parents=True, exist_ok=True)
    (external / "tasks" / task_id).mkdir(mode=0o700)
    (external / "summary.json").write_text(
        '{"schema_version":"1","state":"complete","overall_status":"pass"}\n',
        encoding="utf-8",
    )
    evidence_dir.symlink_to(external, target_is_directory=True)
    emit("pass", "fixture replaced the evidence root with a symlink", "directory", "symlink")
    raise SystemExit(0)
if mode == "replace-evidence-parent-with-symlink":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    parent = evidence_dir.parent
    moved_parent, external = map(Path, args)
    emit("pass", "fixture is replacing the evidence parent", "stable parent", "replacement")
    (evidence_dir / "summary.json").write_text(
        '{"schema_version":"1","state":"complete","overall_status":"pass"}\n',
        encoding="utf-8",
    )
    external.mkdir(parents=True)
    (external / evidence_dir.name).write_text("external sentinel\n", encoding="utf-8")
    parent.rename(moved_parent)
    parent.symlink_to(external, target_is_directory=True)
    raise SystemExit(0)
if mode == "replace-evidence-parent-with-directory":
    task_dir = Path(os.environ["FORMAT_ACCEPTANCE_TASK_DIR"])
    evidence_dir = task_dir.parents[1]
    parent = evidence_dir.parent
    moved_parent, replacement_parent = map(Path, args)
    emit("pass", "fixture is replacing the evidence parent", "stable parent", "replacement")
    (evidence_dir / "summary.json").write_text(
        '{"schema_version":"1","state":"complete","overall_status":"pass"}\n',
        encoding="utf-8",
    )
    parent.rename(moved_parent)
    replacement_parent.rename(parent)
    raise SystemExit(0)
if mode == "flood-stdout":
    sys.stdout.write("O" * 65536)
    sys.stdout.flush()
    emit("pass", "stdout flood finished", "bounded", "overflow")
    raise SystemExit(0)
if mode == "flood-stderr":
    sys.stderr.write("E" * 65536)
    sys.stderr.flush()
    emit("pass", "stderr flood finished", "bounded", "overflow")
    raise SystemExit(0)
print(f"unknown fixture mode: {mode}", file=sys.stderr)
raise SystemExit(64)
'''


class Fixture:
    def __init__(self, root: Path):
        self.root = root
        self.fixture = root / "fixture_task.py"
        self.fixture.write_text(FIXTURE_SOURCE, encoding="utf-8")
        self.fixture.chmod(0o700)

    def profile(self, directory: Path, target_id: str = TARGET) -> Path:
        directory.mkdir(parents=True, exist_ok=True)
        binary_hash = sha256_file(self.fixture)
        depth = {
            "onnx": "session",
            "gguf": "metadata",
            "safetensors": "deserialize",
        }.get(target_id, "session")
        value = {
            "schema_version": "1",
            "target_id": target_id,
            "format_revision": "selftest-v1",
            "loader_id": "selftest-loader",
            "loader_version": "1",
            "source_artifacts": [
                {
                    "url": "https://example.invalid/selftest-source",
                    "tag": "selftest-v1",
                    "resolved_commit": "0" * 40,
                    "sha256": binary_hash,
                    "size_bytes": self.fixture.stat().st_size,
                }
            ],
            "patches": [],
            "toolchain": {
                key: {"version": "1", "path": str(self.fixture), "sha256": binary_hash}
                for key in ("compiler", "linker", "engine", "rust")
            },
            "sanitizer_policy": {
                "compile_flags": ["-fno-omit-frame-pointer"],
                "recovery": "abort",
                "runtime_env": {"SELFTEST_SANITIZER": "1"},
                "rust_panic": "abort",
            },
            "binaries": [
                {
                    "role": "replay",
                    "path": str(self.fixture),
                    "sha256": binary_hash,
                    "argv": ["{input}"],
                    "linked_libraries": [],
                }
            ],
            "input_kind": {"kind": "single", "extensions": ["onnx"], "subformats": []},
            "depth": depth,
            "engine_capabilities": [
                {
                    "backend": "local-harness",
                    "binary_role": "replay",
                    "required_mode": "native",
                    "instrumentation_scope": "selftest",
                }
            ],
            "limits": {
                "max_input_bytes": 1048576,
                "memory_bytes": 1073741824,
                "input_timeout_ms": 1000,
                "block_timeout_ms": 30000,
                "threads": 1,
                "workers": 1,
            },
            "coverage_scope": {
                "unit": "source-line",
                "include_sources": ["selftest"],
                "exclude_sources": [],
            },
        }
        # Keep parity with the FND-01 profile shape: python is explicitly nullable and
        # environment is an allowlist, not an inherited process dump.
        value["toolchain"]["python"] = None
        value["toolchain"]["environment"] = {}
        path = directory / "profile.json"
        write_json(path, value)
        return path

    def task(
        self,
        task_id: str,
        requirement_id: str,
        mode: str,
        *arguments: Path | str,
        timeout_ms: int = 2000,
        stdout_limit_bytes: int = 4096,
        stderr_limit_bytes: int = 4096,
        depends_on: list[str] | None = None,
    ) -> dict[str, Any]:
        return {
            "task_id": task_id,
            "requirement_id": requirement_id,
            "command_argv": [
                str(Path(sys.executable).resolve()),
                "-B",
                str(self.fixture),
                mode,
                *(str(value) for value in arguments),
            ],
            "cwd": str(self.root),
            "identity_files": [
                {"path": str(self.fixture.resolve()), "sha256": sha256_file(self.fixture)}
            ],
            "allowed_env": {},
            "timeout_ms": timeout_ms,
            "stdout_limit_bytes": stdout_limit_bytes,
            "stderr_limit_bytes": stderr_limit_bytes,
            "depends_on": list(depends_on or []),
            "corpus_index_sha256": None,
            "artifacts": [],
        }

    def requirements(
        self,
        directory: Path,
        requirement_map: list[tuple[str, list[str]]],
        tasks: list[dict[str, Any]],
    ) -> Path:
        for task in tasks:
            cwd = Path(task["cwd"])
            identities = {
                str(Path(row["path"]).resolve(strict=True)): row
                for row in task.get("identity_files", [])
            }
            for argument in task["command_argv"][1:]:
                if argument.startswith("@") and len(argument) > 1:
                    forms = [argument[1:]]
                elif argument.startswith("-") and "=" in argument:
                    _prefix, value = argument.split("=", 1)
                    forms = [value] if value else []
                elif argument.startswith("-"):
                    forms = []
                else:
                    forms = [argument]
                for path_text in forms:
                    candidate = Path(path_text)
                    requested = candidate if candidate.is_absolute() else cwd / candidate
                    try:
                        resolved = requested.resolve(strict=True)
                    except (OSError, RuntimeError):
                        continue
                    try:
                        metadata = resolved.stat()
                    except OSError:
                        continue
                    if stat.S_ISREG(metadata.st_mode):
                        identities[str(resolved)] = {
                            "path": str(resolved),
                            "sha256": sha256_file(resolved),
                        }
            task["identity_files"] = [identities[key] for key in sorted(identities)]
        path = directory / "requirements.json"
        write_json(
            path,
            {
                "schema_version": "1",
                "target_id": TARGET,
                "suite": SUITE,
                "profile_sha256": sha256_file(directory / "profile" / "profile.json"),
                "requirements": [
                    {
                        "requirement_id": requirement_id,
                        "required_task_ids": task_ids,
                    }
                    for requirement_id, task_ids in requirement_map
                ],
                "tasks": tasks,
            },
        )
        return path


class AcceptanceSelftest:
    def __init__(self, fixture: Fixture):
        self.fixture = fixture
        self.next_case = 0

    def case_dir(self, label: str) -> Path:
        self.next_case += 1
        path = self.fixture.root / f"case-{self.next_case:02d}-{label}"
        path.mkdir()
        return path

    def invoke(
        self,
        case: Path,
        profile: Path,
        requirements: Path,
        *,
        evidence_name: str = "evidence",
        extra_env: dict[str, str] | None = None,
        outer_timeout: float = 10.0,
    ) -> subprocess.CompletedProcess[bytes]:
        evidence = case / evidence_name
        env = os.environ.copy()
        env.pop(HOOK_ENV, None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        if extra_env:
            env.update(extra_env)
        command = self.command(profile, requirements, evidence)
        try:
            return subprocess.run(
                command,
                cwd=ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=outer_timeout,
            )
        except subprocess.TimeoutExpired as error:
            raise TestFailure(f"runner exceeded outer timeout: {command}") from error

    @staticmethod
    def command(profile: Path, requirements: Path, evidence: Path) -> list[str]:
        return [
            sys.executable,
            "-B",
            str(RUNNER),
            "--target",
            TARGET,
            "--profile",
            str(profile.absolute()),
            "--suite",
            SUITE,
            "--evidence-dir",
            str(evidence.absolute()),
            "--requirements",
            str(requirements.absolute()),
        ]

    @staticmethod
    def explain(completed: subprocess.CompletedProcess[bytes]) -> str:
        stdout = completed.stdout.decode("utf-8", "replace")[-800:]
        stderr = completed.stderr.decode("utf-8", "replace")[-800:]
        return f"rc={completed.returncode} stdout={stdout!r} stderr={stderr!r}"

    def expect_rc(self, completed: subprocess.CompletedProcess[bytes], expected: int) -> None:
        require(
            completed.returncode == expected,
            f"expected rc={expected}; {self.explain(completed)}",
        )

    @staticmethod
    def record(evidence: Path, task_id: str) -> dict[str, Any]:
        value = read_json(evidence / "records" / f"{task_id}.json")
        missing = sorted(RECORD_FIELDS - value.keys())
        require(not missing, f"record {task_id} misses fields: {missing}")
        require(value["schema_version"] == "1", f"record schema mismatch for {task_id}")
        require(value["task_id"] == task_id, f"record ID mismatch for {task_id}")
        require(value["status"] in STATUS_NAMES, f"invalid record status: {value['status']}")
        for stream in ("stdout", "stderr"):
            stream_value = value[stream]
            require(isinstance(stream_value, dict), f"{task_id} {stream} is not an object")
            require(
                {"path", "sha256", "size_bytes", "truncated"} <= stream_value.keys(),
                f"{task_id} {stream} metadata is incomplete",
            )
        return value

    @staticmethod
    def expect_summary(
        evidence: Path,
        overall_status: str,
        **expected_counts: int,
    ) -> dict[str, Any]:
        summary = read_json(evidence / "summary.json")
        require(summary.get("state") == "complete", "final summary is not complete")
        require(
            summary.get("overall_status") == overall_status,
            f"overall status is {summary.get('overall_status')!r}, expected {overall_status!r}",
        )
        observed = summary.get("counts")
        require(isinstance(observed, dict), "summary counts are missing")
        expected = dict(SUMMARY_COUNTS)
        expected.update(expected_counts)
        require(observed == expected, f"counts differ: {observed!r} != {expected!r}")
        require(summary.get("required_task_ids"), "summary omitted required task IDs")
        require(summary.get("required_requirement_ids"), "summary omitted requirement IDs")
        profile_hash = summary.get("profile_sha256")
        require(
            isinstance(profile_hash, str) and len(profile_hash) == 64,
            "summary profile hash is missing",
        )
        return summary

    @staticmethod
    def expect_preflight_refusal(case: Path, completed: subprocess.CompletedProcess[bytes]) -> None:
        require(completed.returncode == 64, AcceptanceSelftest.explain(completed))
        evidence = case / "evidence"
        require(
            not (evidence / "summary.json").exists(),
            "invalid request produced a final summary",
        )

    def make_single(
        self,
        label: str,
        mode: str,
        *,
        timeout_ms: int = 2000,
        stdout_limit_bytes: int = 4096,
        stderr_limit_bytes: int = 4096,
        arguments: tuple[Path | str, ...] = (),
    ) -> tuple[Path, Path, Path]:
        case = self.case_dir(label)
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task(
            "task-one",
            "Q01",
            mode,
            *arguments,
            timeout_ms=timeout_ms,
            stdout_limit_bytes=stdout_limit_bytes,
            stderr_limit_bytes=stderr_limit_bytes,
        )
        requirements = self.fixture.requirements(case, [("Q01", ["task-one"])], [task])
        return case, profile, requirements

    def all_pass(self) -> None:
        case = self.case_dir("all-pass")
        profile = self.fixture.profile(case / "profile")
        tasks = [
            self.fixture.task("pass-one", "Q01", "profile-binding", profile),
            self.fixture.task("pass-two", "Q02", "pass"),
        ]
        requirements = self.fixture.requirements(
            case, [("Q01", ["pass-one"]), ("Q02", ["pass-two"])], tasks
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 0)
        summary = self.expect_summary(case / "evidence", "pass", **{"pass": 2})
        require(summary["profile_sha256"] == sha256_file(profile), "wrong profile hash")
        for task_id in ("pass-one", "pass-two"):
            record = self.record(case / "evidence", task_id)
            require(record["status"] == "pass", f"{task_id} did not pass")
            mode = stat.S_IMODE((case / "evidence" / "records" / f"{task_id}.json").stat().st_mode)
            require(mode == 0o600, f"record mode is {mode:o}, expected 600")
        evidence_mode = stat.S_IMODE((case / "evidence").stat().st_mode)
        require(evidence_mode == 0o700, f"evidence mode is {evidence_mode:o}, expected 700")
        require(
            not (case / "evidence" / "qualification.candidate.json").exists(),
            "partial Q coverage produced a qualification candidate",
        )

    def validation_run_ids_are_unique(self) -> None:
        case = self.case_dir("unique-validation-run")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("bound", "Q01", "profile-binding", profile)
        requirements = self.fixture.requirements(
            case, [("Q01", ["bound"])], [task]
        )
        first = self.invoke(case, profile, requirements, evidence_name="evidence-a")
        second = self.invoke(case, profile, requirements, evidence_name="evidence-b")
        self.expect_rc(first, 0)
        self.expect_rc(second, 0)
        first_record = self.record(case / "evidence-a", "bound")
        second_record = self.record(case / "evidence-b", "bound")
        first_id = first_record.get("observed", {}).get("validation_run")
        second_id = second_record.get("observed", {}).get("validation_run")
        require(isinstance(first_id, str) and first_id, "first validation run ID is missing")
        require(isinstance(second_id, str) and second_id, "second validation run ID is missing")
        require(first_id != second_id, "independent acceptance runs reused a validation-run ID")

    def executable_is_pinned_before_tasks(self) -> None:
        case = self.case_dir("executable-pin")
        profile = self.fixture.profile(case / "profile")
        alias = case / "task-command"
        alias.symlink_to(self.fixture.fixture)
        replacement = case / "replacement.py"
        marker = case / "replacement-ran"
        replacement.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran\\n', encoding='utf-8')\n"
            "value = {'schema_version':'1','status':'pass','reason':'replacement ran',"
            "'expected':'pinned','observed':'replacement','validation_run_id':"
            "os.environ.get('TOOL_VALIDATION_RUN'),'corpus_index_sha256':None,'artifacts':[]}\n"
            "pathlib.Path(os.environ['FORMAT_ACCEPTANCE_RESULT_PATH']).write_text("
            "json.dumps(value) + '\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        replacement.chmod(0o700)
        first = self.fixture.task(
            "switcher",
            "Q01",
            "switch-executable",
            case,
            alias.name,
            replacement.name,
        )
        second = self.fixture.task("pinned", "Q02", "pass", depends_on=["switcher"])
        second["command_argv"] = [str(alias), "pass"]
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["switcher"]), ("Q02", ["pinned"])],
            [first, second],
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)
        require(not marker.exists(), "task command followed a replaced executable alias")

    def direct_shebang_executable_is_refused(self) -> None:
        case = self.case_dir("direct-shebang-executable")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("direct-script", "Q01", "pass")
        task["command_argv"] = [str(self.fixture.fixture.resolve()), "pass"]
        requirements = self.fixture.requirements(
            case, [("Q01", ["direct-script"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def interpreter_script_is_pinned_before_tasks(self) -> None:
        case = self.case_dir("interpreter-script-pin")
        profile = self.fixture.profile(case / "profile")
        marker = case / "replacement-ran"
        victim = case / "victim.py"
        victim.write_text("raise SystemExit(97)\n", encoding="utf-8")
        replacement = case / "replacement.py"
        replacement.write_text(
            "import json, os, pathlib\n"
            f"pathlib.Path({str(marker)!r}).write_text('ran\\n', encoding='utf-8')\n"
            "value={'schema_version':'1','status':'pass','reason':'replacement ran',"
            "'expected':'pinned','observed':'replacement','validation_run_id':"
            "os.environ.get('TOOL_VALIDATION_RUN'),'corpus_index_sha256':None,'artifacts':[]}\n"
            "pathlib.Path(os.environ['FORMAT_ACCEPTANCE_RESULT_PATH']).write_text("
            "json.dumps(value)+'\\n', encoding='utf-8')\n",
            encoding="utf-8",
        )
        first = self.fixture.task("replacer", "Q01", "replace-file", victim, replacement)
        second = self.fixture.task("pinned-script", "Q02", "pass", depends_on=["replacer"])
        second["command_argv"] = [str(Path(sys.executable).resolve()), "-B", str(victim)]
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["replacer"]), ("Q02", ["pinned-script"])],
            [first, second],
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(not marker.exists(), "interpreter followed a replaced script")

    def interpreter_script_identity_is_required(self) -> None:
        case = self.case_dir("missing-script-identity")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("missing-pin", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["missing-pin"])], [task])
        value = read_json(requirements)
        value["tasks"][0]["identity_files"] = []
        write_json(requirements, value)
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def python_module_mode_is_refused(self) -> None:
        case = self.case_dir("python-module-mode")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("module-mode", "Q01", "pass")
        task["command_argv"] = [
            str(Path(sys.executable).resolve()),
            "-B",
            "-m",
            "replaceable_module",
        ]
        requirements = self.fixture.requirements(case, [("Q01", ["module-mode"])], [task])
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def identity_file_hash_is_verified(self) -> None:
        case = self.case_dir("identity-hash")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("wrong-hash", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["wrong-hash"])], [task])
        value = read_json(requirements)
        value["tasks"][0]["identity_files"][0]["sha256"] = "1" * 64
        write_json(requirements, value)
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def hardlink_identity_alias_is_refused(self) -> None:
        case = self.case_dir("identity-hardlink")
        profile = self.fixture.profile(case / "profile")
        alias = case / "fixture-hardlink.py"
        os.link(self.fixture.fixture, alias)
        task = self.fixture.task("duplicate-inode", "Q01", "pass")
        task["identity_files"].append(
            {"path": str(alias), "sha256": sha256_file(alias)}
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["duplicate-inode"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def relative_identity_path_is_canonicalized(self) -> None:
        case = self.case_dir("relative-identity")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("relative-pin", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["relative-pin"])], [task])
        value = read_json(requirements)
        value["tasks"][0]["identity_files"][0]["path"] = self.fixture.fixture.name
        write_json(requirements, value)
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 0)
        record = self.record(case / "evidence", "relative-pin")
        require(
            record["identity_files"][0]["path"] == str(self.fixture.fixture.resolve()),
            "relative identity path was not canonicalized",
        )

    def attached_option_file_is_pinned(self) -> None:
        case = self.case_dir("attached-option-file")
        profile = self.fixture.profile(case / "profile")
        config = case / "validator.cfg"
        config.write_text("strict=true\n", encoding="utf-8")
        task = self.fixture.task("option-file", "Q01", "pass", f"--config={config}")
        requirements = self.fixture.requirements(case, [("Q01", ["option-file"])], [task])
        value = read_json(requirements)
        value["tasks"][0]["identity_files"] = [
            row
            for row in value["tasks"][0]["identity_files"]
            if row["path"] != str(config.resolve())
        ]
        write_json(requirements, value)
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def interpreter_options_keep_their_meaning(self) -> None:
        case = self.case_dir("interpreter-option")
        profile = self.fixture.profile(case / "profile")
        option_named_file = self.fixture.root / "-B"
        option_named_file.write_text("raise SystemExit(97)\n", encoding="utf-8")
        task = self.fixture.task("option-safe", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["option-safe"])], [task])
        value = read_json(requirements)
        value["tasks"][0]["identity_files"].append(
            {"path": str(option_named_file), "sha256": sha256_file(option_named_file)}
        )
        write_json(requirements, value)
        try:
            completed = self.invoke(case, profile, requirements)
        finally:
            option_named_file.unlink()
        self.expect_rc(completed, 0)
        record = self.record(case / "evidence", "option-safe")
        require(record["command_argv"][1] == "-B", "interpreter option was rewritten as a file")

    def file_like_arguments_keep_their_meaning(self) -> None:
        case = self.case_dir("literal-file-like-arguments")
        profile = self.fixture.profile(case / "profile")
        option_value = self.fixture.root / "fail"
        subcommand = self.fixture.root / "unit"
        option_value.write_text("unrelated identity file\n", encoding="utf-8")
        subcommand.write_text("unrelated identity file\n", encoding="utf-8")
        task = self.fixture.task(
            "literal-args", "Q01", "literal-arguments", "--verdict=fail", "unit"
        )
        requirements = self.fixture.requirements(case, [("Q01", ["literal-args"])], [task])
        try:
            completed = self.invoke(case, profile, requirements)
        finally:
            option_value.unlink()
            subcommand.unlink()
        self.expect_rc(completed, 1)
        record = self.record(case / "evidence", "literal-args")
        require(
            record["command_argv"][-2:] == ["--verdict=fail", "unit"],
            "file-like literal arguments were rewritten",
        )

    def loader_environment_is_refused(self) -> None:
        case = self.case_dir("loader-environment")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("loader-env", "Q01", "pass")
        task["allowed_env"] = {"LD_PRELOAD": "/tmp/replaceable.so"}
        requirements = self.fixture.requirements(case, [("Q01", ["loader-env"])], [task])
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

        path_case = self.case_dir("executable-search-environment")
        profile = self.fixture.profile(path_case / "profile")
        task = self.fixture.task("path-env", "Q01", "pass")
        task["allowed_env"] = {"PATH": str(path_case)}
        requirements = self.fixture.requirements(
            path_case, [("Q01", ["path-env"])], [task]
        )
        completed = self.invoke(path_case, profile, requirements)
        self.expect_preflight_refusal(path_case, completed)

    def all_requirements_remain_evidence_only(self) -> None:
        case = self.case_dir("qualification-evidence-only")
        profile = self.fixture.profile(case / "profile")
        tasks = [
            self.fixture.task(
                f"task-q{number:02d}", f"Q{number:02d}", "pass", f"q{number:02d}"
            )
            for number in range(1, 13)
        ]
        requirement_map = [
            (f"Q{number:02d}", [f"task-q{number:02d}"])
            for number in range(1, 13)
        ]
        requirements = self.fixture.requirements(case, requirement_map, tasks)
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 0)
        self.expect_summary(case / "evidence", "pass", **{"pass": 12})
        require(
            not (case / "evidence" / "qualification.candidate.json").exists(),
            "one synthetic suite produced a qualification candidate",
        )
        for number in range(1, 13):
            requirement_id = f"Q{number:02d}"
            aggregate_path = case / "evidence" / "requirements" / f"{requirement_id}.json"
            aggregate = read_json(aggregate_path)
            require(aggregate.get("requirement_id") == requirement_id, "aggregate requirement ID mismatch")
            require(aggregate.get("status") == "pass", "aggregate did not preserve pass")
            require(aggregate.get("suite") == SUITE, "aggregate suite mismatch")
            require(aggregate.get("profile_sha256") == sha256_file(profile), "aggregate profile mismatch")
            require(aggregate.get("requirements_sha256") == sha256_file(requirements), "requirements hash missing")
            records = aggregate.get("records")
            require(isinstance(records, list) and records, "aggregate omitted records")
            for record_row in records:
                record_path = case / "evidence" / "records" / f"{record_row['task_id']}.json"
                require(
                    record_row.get("record_sha256") == sha256_file(record_path),
                    "aggregate record hash mismatch",
                )
                require(
                    read_json(record_path).get("profile_sha256") == aggregate.get("profile_sha256"),
                    "record profile identity is not bound to its aggregate",
                )
            validator = aggregate.get("validator")
            require(isinstance(validator, dict), "aggregate omitted validator identity")
            entrypoint = validator.get("entrypoint")
            library = validator.get("library")
            require(isinstance(entrypoint, dict) and isinstance(library, dict), "validator file identities missing")
            require(entrypoint.get("sha256") == sha256_file(RUNNER), "entrypoint hash mismatch")
            library_path = ROOT / "scripts" / "lib" / "format_acceptance.py"
            require(library.get("sha256") == sha256_file(library_path), "library hash mismatch")
            combined_payload = {
                "protocol_version": validator.get("protocol_version"),
                "files": [
                    {"name": "entrypoint", "sha256": entrypoint["sha256"]},
                    {"name": "library", "sha256": library["sha256"]},
                ],
            }
            combined = hashlib.sha256(
                json.dumps(
                    combined_payload, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            ).hexdigest()
            require(
                validator.get("combined_sha256") == combined,
                "aggregate validator composite hash mismatch",
            )
        require(
            not (profile.parent / "qualification.json").exists(),
            "runner installed qualification beside the live profile",
        )

    def explicit_fail(self) -> None:
        case, profile, requirements = self.make_single("fail", "fail")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 1)
        self.expect_summary(case / "evidence", "fail", fail=1)
        require(self.record(case / "evidence", "task-one")["status"] == "fail", "fail lost")

    def explicit_fail_survives_missing_artifact(self) -> None:
        case = self.case_dir("fail-missing-artifact")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("failing-task", "Q01", "fail")
        task["artifacts"] = ["failure-detail.json"]
        requirements = self.fixture.requirements(
            case, [("Q01", ["failing-task"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 1)
        self.expect_summary(case / "evidence", "fail", fail=1)
        record = self.record(case / "evidence", "failing-task")
        require(record["status"] == "fail", "explicit failure was erased by missing detail")
        require(record["artifacts"][0]["missing"] is True, "missing failure artifact was not recorded")

    def explicit_fail_survives_identity_change(self) -> None:
        case = self.case_dir("fail-identity-change")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task(
            "fail-and-mutate", "Q01", "fail-and-mutate-profile", profile
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["fail-and-mutate"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 1)
        self.expect_summary(case / "evidence", "fail", fail=1)
        record = self.record(case / "evidence", "fail-and-mutate")
        require(record["status"] == "fail", "identity change erased an explicit fail")

    def explicit_fail_survives_output_limit(self) -> None:
        case, profile, requirements = self.make_single(
            "fail-output-limit", "fail-flood-stdout", stdout_limit_bytes=4096
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 1)
        self.expect_summary(case / "evidence", "fail", fail=1)
        record = self.record(case / "evidence", "task-one")
        require(record["status"] == "fail", "output limit erased an explicit fail")
        require(record["stdout"]["truncated"] is True, "fixture did not cross output limit")

    def explicit_blocked(self) -> None:
        case, profile, requirements = self.make_single("blocked", "blocked")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", blocked=1)

    def blocked_dependency_is_not_run(self) -> None:
        case = self.case_dir("not-run")
        profile = self.fixture.profile(case / "profile")
        marker = case / "dependent-spawned"
        tasks = [
            self.fixture.task("prerequisite", "Q01", "blocked"),
            self.fixture.task(
                "dependent",
                "Q02",
                "mark-pass",
                marker,
                depends_on=["prerequisite"],
            ),
        ]
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["prerequisite"]), ("Q02", ["dependent"])],
            tasks,
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", blocked=1, not_run=1)
        require(not marker.exists(), "dependent task ran after a blocked prerequisite")
        require(self.record(case / "evidence", "dependent")["status"] == "not_run", "not_run lost")

    def explicit_inconclusive(self) -> None:
        case, profile, requirements = self.make_single("inconclusive", "inconclusive")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)

    def zero_checks(self) -> None:
        case = self.case_dir("zero")
        profile = self.fixture.profile(case / "profile")
        requirements = self.fixture.requirements(case, [], [])
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)

    def artifact_path_collisions_are_refused(self) -> None:
        prefix_case = self.case_dir("artifact-prefix-collision")
        profile = self.fixture.profile(prefix_case / "profile")
        prefix_task = self.fixture.task("collision", "Q01", "pass")
        prefix_task["artifacts"] = ["proof", "proof/detail.json"]
        prefix_requirements = self.fixture.requirements(
            prefix_case, [("Q01", ["collision"])], [prefix_task]
        )
        self.expect_preflight_refusal(
            prefix_case, self.invoke(prefix_case, profile, prefix_requirements)
        )

        result_case = self.case_dir("artifact-result-collision")
        profile = self.fixture.profile(result_case / "profile")
        result_task = self.fixture.task("collision", "Q01", "pass")
        result_task["artifacts"] = ["result.json"]
        result_requirements = self.fixture.requirements(
            result_case, [("Q01", ["collision"])], [result_task]
        )
        self.expect_preflight_refusal(
            result_case, self.invoke(result_case, profile, result_requirements)
        )

    def missing_required_id(self) -> None:
        case = self.case_dir("missing-id")
        profile = self.fixture.profile(case / "profile")
        marker = case / "spawned"
        tasks = [self.fixture.task("actual-task", "Q01", "mark-pass", marker)]
        requirements = self.fixture.requirements(
            case, [("Q01", ["required-but-missing"])], tasks
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)
        require(not marker.exists(), "task ran before missing ID rejection")

    def duplicate_task_id(self) -> None:
        case = self.case_dir("duplicate-task")
        profile = self.fixture.profile(case / "profile")
        marker_a, marker_b = case / "spawned-a", case / "spawned-b"
        tasks = [
            self.fixture.task("duplicate", "Q01", "mark-pass", marker_a),
            self.fixture.task("duplicate", "Q01", "mark-pass", marker_b),
        ]
        requirements = self.fixture.requirements(case, [("Q01", ["duplicate"])], tasks)
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)
        require(not marker_a.exists() and not marker_b.exists(), "duplicate task ran")

    def duplicate_requirement_id(self) -> None:
        case = self.case_dir("duplicate-requirement")
        profile = self.fixture.profile(case / "profile")
        markers = [case / "spawned-a", case / "spawned-b"]
        tasks = [
            self.fixture.task("task-a", "Q01", "mark-pass", markers[0]),
            self.fixture.task("task-b", "Q01", "mark-pass", markers[1]),
        ]
        requirements = self.fixture.requirements(
            case, [("Q01", ["task-a"]), ("Q01", ["task-b"])], tasks
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)
        require(not any(path.exists() for path in markers), "duplicate requirement ran tasks")

    def missing_result_record(self) -> None:
        case, profile, requirements = self.make_single("missing-result", "ok-only")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        record = self.record(case / "evidence", "task-one")
        require(record["status"] == "inconclusive", "record-free rc0 became pass")

    def duplicate_key_result(self) -> None:
        case, profile, requirements = self.make_single(
            "duplicate-key-result", "duplicate-key-result"
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(self.record(case / "evidence", "task-one")["status"] == "inconclusive", "duplicate JSON key passed")

    def last_ok_does_not_win(self) -> None:
        case = self.case_dir("last-ok")
        profile = self.fixture.profile(case / "profile")
        tasks = [
            self.fixture.task("first-fails", "Q01", "fail"),
            self.fixture.task("last-passes", "Q02", "pass"),
        ]
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["first-fails"]), ("Q02", ["last-passes"])],
            tasks,
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 1)
        self.expect_summary(
            case / "evidence", "fail", **{"pass": 1, "fail": 1}
        )
        require(self.record(case / "evidence", "first-fails")["status"] == "fail", "first failure lost")
        require(self.record(case / "evidence", "last-passes")["status"] == "pass", "last pass missing")

    def skip_is_not_pass(self) -> None:
        case, profile, requirements = self.make_single("skip", "pass-with-skip")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(self.record(case / "evidence", "task-one")["status"] != "pass", "skip became pass")

    def skip_count_is_not_pass(self) -> None:
        case, profile, requirements = self.make_single(
            "skip-count", "pass-with-skip-count"
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(self.record(case / "evidence", "task-one")["status"] != "pass", "positive skip count became pass")

    def pytest_skip_count_is_not_pass(self) -> None:
        case, profile, requirements = self.make_single(
            "pytest-skip-count", "pass-with-pytest-skip"
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(self.record(case / "evidence", "task-one")["status"] != "pass", "pytest skip count became pass")

    def huge_skip_count_is_bounded(self) -> None:
        case, profile, requirements = self.make_single(
            "huge-skip-count", "huge-skip-count", stdout_limit_bytes=8192
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)

    def pass_requires_measurement(self) -> None:
        case, profile, requirements = self.make_single(
            "pass-without-measurement", "pass-without-measurement"
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        record = self.record(case / "evidence", "task-one")
        require(record["status"] == "inconclusive", "unmeasured result became pass")

    def stale_result_is_inconclusive(self) -> None:
        case, profile, requirements = self.make_single("stale-result", "stale-result")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        record = self.record(case / "evidence", "task-one")
        require(record["status"] == "inconclusive", "stale result became pass")

    def wrong_profile(self) -> None:
        case = self.case_dir("wrong-profile")
        profile = self.fixture.profile(case / "profile", target_id="gguf")
        marker = case / "spawned"
        task = self.fixture.task("must-not-run", "Q01", "mark-pass", marker)
        requirements = self.fixture.requirements(case, [("Q01", ["must-not-run"])], [task])
        completed = self.invoke(case, profile, requirements)
        self.expect_preflight_refusal(case, completed)
        require(not marker.exists(), "wrong-profile task was started")

        hash_case = self.case_dir("wrong-profile-hash")
        hash_profile = self.fixture.profile(hash_case / "profile")
        hash_marker = hash_case / "spawned"
        hash_task = self.fixture.task("must-not-run", "Q01", "mark-pass", hash_marker)
        hash_requirements = self.fixture.requirements(
            hash_case, [("Q01", ["must-not-run"])], [hash_task]
        )
        value = read_json(hash_requirements)
        value["profile_sha256"] = "a" * 64
        write_json(hash_requirements, value)
        hash_completed = self.invoke(hash_case, hash_profile, hash_requirements)
        self.expect_preflight_refusal(hash_case, hash_completed)
        require(not hash_marker.exists(), "wrong profile hash started a task")

    def timeout_kills_process_tree(self) -> None:
        case = self.case_dir("timeout")
        profile = self.fixture.profile(case / "profile")
        ready, pids = case / "ready", case / "pids"
        task = self.fixture.task(
            "times-out", "Q01", "hang", ready, pids, timeout_ms=300
        )
        requirements = self.fixture.requirements(case, [("Q01", ["times-out"])], [task])
        try:
            completed = self.invoke(case, profile, requirements)
            self.expect_rc(completed, 2)
            self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
            record = self.record(case / "evidence", "times-out")
            require(record["status"] == "inconclusive", "timeout became pass/fail")
            require("timeout" in record["reason"].lower(), "timeout reason was not recorded")
            wait_processes_gone(pids)
        finally:
            kill_fixture_processes(pids)

    def successful_task_reaps_process_group_descendants(self) -> None:
        case = self.case_dir("successful-orphan")
        profile = self.fixture.profile(case / "profile")
        pids = case / "pids"
        task = self.fixture.task(
            "spawns-orphan", "Q01", "pass-with-orphan", pids
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["spawns-orphan"])], [task]
        )
        try:
            completed = self.invoke(case, profile, requirements)
            self.expect_rc(completed, 0)
            self.expect_summary(case / "evidence", "pass", **{"pass": 1})
            wait_processes_gone(pids)
        finally:
            kill_fixture_processes(pids)

    def successful_task_reaps_detached_descendants(self) -> None:
        case = self.case_dir("successful-detached-orphan")
        profile = self.fixture.profile(case / "profile")
        pids = case / "pids"
        task = self.fixture.task(
            "spawns-detached-orphan", "Q01", "pass-with-detached-orphan", pids
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["spawns-detached-orphan"])], [task]
        )
        try:
            completed = self.invoke(case, profile, requirements)
            self.expect_rc(completed, 0)
            self.expect_summary(case / "evidence", "pass", **{"pass": 1})
            wait_processes_gone(pids)
        finally:
            kill_fixture_processes(pids)

    def task_control_signals_are_unblocked(self) -> None:
        case, profile, requirements = self.make_single("signal-mask", "signal-mask")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 0)
        self.expect_summary(case / "evidence", "pass", **{"pass": 1})

    def signal_scope_failure_restores_subreaper(self) -> None:
        module = load_runner_library()
        before = module._child_subreaper_state()
        observed: list[BaseException] = []

        def enter_in_thread() -> None:
            try:
                module._SignalScope().__enter__()
            except BaseException as error:
                observed.append(error)

        thread = threading.Thread(target=enter_in_thread)
        thread.start()
        thread.join(timeout=2.0)
        require(not thread.is_alive(), "signal-scope thread did not finish")
        require(observed and isinstance(observed[0], ValueError), "non-main signal setup did not fail")
        require(
            module._child_subreaper_state() == before,
            "failed signal-scope entry leaked the child-subreaper state",
        )

    def inherited_blocked_signal_is_unblocked(self) -> None:
        case = self.case_dir("blocked-parent-signal")
        profile = self.fixture.profile(case / "profile")
        ready, pids = case / "ready", case / "pids"
        task = self.fixture.task(
            "hangs", "Q01", "hang", ready, pids, timeout_ms=10000
        )
        requirements = self.fixture.requirements(case, [("Q01", ["hangs"])], [task])
        evidence = case / "evidence"
        launcher = (
            "import os, signal, sys; "
            "signal.pthread_sigmask(signal.SIG_BLOCK, "
            "{signal.SIGTERM, signal.SIGINT, signal.SIGHUP}); "
            "os.execv(sys.argv[1], sys.argv[1:])"
        )
        process = subprocess.Popen(
            [sys.executable, "-B", "-c", launcher, *self.command(profile, requirements, evidence)],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not ready.exists() and process.poll() is None:
                time.sleep(0.03)
            require(ready.exists(), "runner never reached the blocked-signal task")
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5.0)
            completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.expect_rc(completed, 2)
            wait_processes_gone(pids)
            require(not (evidence / "summary.json").exists(), "blocked SIGTERM produced a summary")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            kill_fixture_processes(pids)

    def sighup_reaps_the_task_process_tree(self) -> None:
        case = self.case_dir("runner-sighup")
        profile = self.fixture.profile(case / "profile")
        ready, pids = case / "ready", case / "pids"
        task = self.fixture.task(
            "hangs", "Q01", "hang", ready, pids, timeout_ms=10000
        )
        requirements = self.fixture.requirements(case, [("Q01", ["hangs"])], [task])
        evidence = case / "evidence"
        process = subprocess.Popen(
            self.command(profile, requirements, evidence),
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not ready.exists() and process.poll() is None:
                time.sleep(0.03)
            require(ready.exists(), "runner never reached the SIGHUP test task")
            process.send_signal(signal.SIGHUP)
            stdout, stderr = process.communicate(timeout=5.0)
            completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.expect_rc(completed, 2)
            wait_processes_gone(pids)
            require(not (evidence / "summary.json").exists(), "SIGHUP produced a summary")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            kill_fixture_processes(pids)

    def cleanup_signal_still_reaps_detached_descendants(self) -> None:
        case = self.case_dir("cleanup-signal-race")
        profile = self.fixture.profile(case / "profile")
        pids, ready = case / "pids", case / "ready"
        task = self.fixture.task(
            "detached-term-ignorer",
            "Q01",
            "pass-with-detached-term-ignorer",
            pids,
            ready,
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["detached-term-ignorer"])], [task]
        )
        evidence = case / "evidence"
        process = subprocess.Popen(
            self.command(profile, requirements, evidence),
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            child_pid: int | None = None
            while time.monotonic() < deadline and process.poll() is None:
                values = read_pids(pids)
                if ready.exists() and values:
                    child_pid = values[0]
                    if process_parent_pid(child_pid) == process.pid:
                        break
                time.sleep(0.005)
            require(child_pid is not None, "detached child PID was not published")
            require(
                process_parent_pid(child_pid) == process.pid,
                "detached child was not adopted before cleanup signal",
            )
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5.0)
            completed = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
            self.expect_rc(completed, 2)
            wait_processes_gone(pids)
            require(not (evidence / "summary.json").exists(), "interrupted cleanup produced a summary")
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            kill_fixture_processes(pids)

    def artifact_parent_symlink_is_inconclusive(self) -> None:
        case = self.case_dir("artifact-parent-symlink")
        profile = self.fixture.profile(case / "profile")
        outside = case / "outside"
        outside.mkdir()
        (outside / "proof.bin").write_bytes(b"outside task directory\n")
        task = self.fixture.task(
            "symlink-artifact", "Q01", "artifact-via-symlink", outside
        )
        task["artifacts"] = ["escape/proof.bin"]
        requirements = self.fixture.requirements(
            case, [("Q01", ["symlink-artifact"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        record = self.record(case / "evidence", "symlink-artifact")
        require(record["status"] == "inconclusive", "symlinked artifact became pass")
        require(not (case / "evidence" / "summary.json").exists(), "symlink artifact retained a summary")

    def hardlinked_artifact_is_inconclusive(self) -> None:
        case = self.case_dir("artifact-hardlink")
        profile = self.fixture.profile(case / "profile")
        outside = case / "outside.bin"
        outside.write_bytes(b"external artifact\n")
        task = self.fixture.task(
            "hardlink-artifact", "Q01", "hardlink-artifact", outside
        )
        task["artifacts"] = ["proof.bin"]
        requirements = self.fixture.requirements(
            case, [("Q01", ["hardlink-artifact"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        record = self.record(case / "evidence", "hardlink-artifact")
        require(record["status"] == "inconclusive", "hardlinked artifact became pass")
        require(not (case / "evidence" / "summary.json").exists(), "hardlink artifact retained a summary")

    def published_artifact_is_reaudited(self) -> None:
        case = self.case_dir("artifact-reaudit")
        profile = self.fixture.profile(case / "profile")
        artifact_path = case / "evidence" / "tasks" / "producer" / "proof.bin"
        producer = self.fixture.task("producer", "Q01", "write-artifact", "proof.bin")
        producer["artifacts"] = ["proof.bin"]
        mutator = self.fixture.task(
            "mutator", "Q02", "mutate-file", artifact_path, depends_on=["producer"]
        )
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["producer"]), ("Q02", ["mutator"])],
            [producer, mutator],
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(
            not (case / "evidence" / "summary.json").exists(),
            "mutated published artifact produced a complete summary",
        )
        require(
            read_json(case / "evidence" / "run.json").get("state") == "incomplete",
            "mutated artifact run was marked complete",
        )

    def run_manifest_is_reaudited(self) -> None:
        case = self.case_dir("run-manifest-reaudit")
        profile = self.fixture.profile(case / "profile")
        run_path = case / "evidence" / "run.json"
        task = self.fixture.task("mutates-run", "Q01", "mutate-file", run_path)
        requirements = self.fixture.requirements(
            case, [("Q01", ["mutates-run"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(
            not (case / "evidence" / "summary.json").exists(),
            "mutated run manifest produced a complete summary",
        )

    def forged_summary_is_removed(self) -> None:
        case, profile, requirements = self.make_single("forged-summary", "forge-summary")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(
            not (case / "evidence" / "summary.json").exists(),
            "untrusted terminal summary survived an incomplete run",
        )

    def undeclared_evidence_is_rejected(self) -> None:
        case, profile, requirements = self.make_single("undeclared-evidence", "write-undeclared")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(not (case / "evidence" / "summary.json").exists(), "extra evidence retained a summary")

    def forged_qualification_candidate_is_removed(self) -> None:
        case, profile, requirements = self.make_single("forged-candidate", "forge-candidate")
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        evidence = case / "evidence"
        require(not (evidence / "summary.json").exists(), "forged candidate retained a summary")
        require(
            not (evidence / "qualification.candidate.json").exists(),
            "forged qualification candidate survived cleanup",
        )

    def setup_failure_removes_terminal_markers(self) -> None:
        module = load_runner_library()
        case = self.case_dir("setup-terminal-cleanup")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("setup-failure", "Q01", "pass")
        requirements = self.fixture.requirements(
            case, [("Q01", ["setup-failure"])], [task]
        )
        evidence = case / "evidence"
        original = module._atomic_write

        def fail_run_manifest(
            directory: Path,
            name: str,
            data: bytes,
            *,
            inject_failure: bool = False,
        ) -> Path:
            if name == "run.json":
                (directory / "summary.json").write_text("forged summary\n", encoding="utf-8")
                (directory / "qualification.candidate.json").write_text(
                    "forged candidate\n", encoding="utf-8"
                )
                raise module.EvidenceError("injected run manifest failure")
            return original(directory, name, data, inject_failure=inject_failure)

        module._atomic_write = fail_run_manifest
        try:
            with redirect_stderr(io.StringIO()):
                result = module.run_acceptance(
                    target=TARGET,
                    profile_path=profile,
                    suite=SUITE,
                    evidence_dir=evidence,
                    requirements_path=requirements,
                    entrypoint_path=RUNNER,
                )
        finally:
            module._atomic_write = original
        require(result == 2, f"setup failure returned rc={result}")
        require(not (evidence / "summary.json").exists(), "setup failure retained a summary")
        require(
            not (evidence / "qualification.candidate.json").exists(),
            "setup failure retained a qualification candidate",
        )

    def locked_forged_summary_is_removed(self) -> None:
        case, profile, requirements = self.make_single(
            "locked-forged-summary", "forge-summary-lock-root"
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        evidence = case / "evidence"
        try:
            require(not (evidence / "summary.json").exists(), "locked forged summary survived cleanup")
            require(
                stat.S_IMODE(evidence.stat().st_mode) == 0o700,
                "cleanup did not restore the private evidence-root mode",
            )
        finally:
            evidence.chmod(0o700)

    def artifact_budget_is_applied_before_hash(self) -> None:
        module = load_runner_library()
        observed_limits: list[int] = []
        original = module._measure_beneath_regular
        simulated_size = 700 * 1024 * 1024

        def fake_measure(
            _root: Path,
            _relative: str,
            _label: str,
            maximum: int,
            *,
            allow_empty: bool = True,
        ) -> tuple[str, int]:
            del allow_empty
            observed_limits.append(maximum)
            if simulated_size > maximum:
                raise module.ConfigurationError("simulated aggregate limit")
            return "1" * 64, simulated_size

        module._measure_beneath_regular = fake_measure
        try:
            budget = module._ArtifactBudget(module.MAX_TOTAL_ARTIFACT_BYTES)
            _records, error = module._artifact_records(
                Path("/tmp/fake-task"),
                ("a.bin", "b.bin"),
                ("a.bin", "b.bin"),
                budget,
            )
        finally:
            module._measure_beneath_regular = original
        require(error is not None, "aggregate overflow was not reported")
        require(
            observed_limits == [
                module.MAX_TOTAL_ARTIFACT_BYTES,
                module.MAX_TOTAL_ARTIFACT_BYTES - simulated_size,
            ],
            f"artifact hashing ignored the remaining budget: {observed_limits}",
        )

        observed_limits.clear()
        module._measure_beneath_regular = fake_measure
        try:
            shared_budget = module._ArtifactBudget(module.MAX_TOTAL_ARTIFACT_BYTES)
            _first_records, first_error = module._artifact_records(
                Path("/tmp/task-one"), ("a.bin",), ("a.bin",), shared_budget
            )
            _second_records, second_error = module._artifact_records(
                Path("/tmp/task-two"), ("b.bin",), ("b.bin",), shared_budget
            )
        finally:
            module._measure_beneath_regular = original
        require(first_error is None, f"first task unexpectedly exhausted budget: {first_error}")
        require(second_error is not None, "run-wide artifact overflow was not reported")
        require(
            observed_limits == [
                module.MAX_TOTAL_ARTIFACT_BYTES,
                module.MAX_TOTAL_ARTIFACT_BYTES - simulated_size,
            ],
            f"artifact budget reset between tasks: {observed_limits}",
        )

    def unchanged_execution_identity_avoids_rehash(self) -> None:
        module = load_runner_library()
        case = self.case_dir("identity-metadata-fast-path")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("identity", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["identity"])], [task])
        snapshot = module._read_regular(requirements, "requirements")
        parsed = module._parse_requirements(snapshot)
        original = module._measure_regular

        def unexpected_rehash(*_args: Any, **_kwargs: Any) -> tuple[str, int]:
            raise TestFailure("unchanged execution identity was rehashed")

        module._measure_regular = unexpected_rehash
        try:
            error = module._task_identity_error(parsed.tasks[0])
        finally:
            module._measure_regular = original
        require(error is None, f"unchanged identity was rejected: {error}")

    def restored_mtime_does_not_hide_identity_change(self) -> None:
        case = self.case_dir("identity-ctime-drift")
        profile = self.fixture.profile(case / "profile")
        victim = case / "identity.bin"
        victim.write_bytes(b"original identity bytes\n")
        task = self.fixture.task(
            "rewrite-identity", "Q01", "rewrite-restore-mtime", victim
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["rewrite-identity"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(
            self.record(case / "evidence", "rewrite-identity")["status"] == "inconclusive",
            "ctime drift was accepted after mtime restoration",
        )

    def git_diff_failure_is_unavailable(self) -> None:
        module = load_runner_library()
        commit = "1" * 40
        calls = iter(
            [
                subprocess.CompletedProcess([], 0, (commit + "\n").encode("ascii"), b""),
                subprocess.CompletedProcess([], 128, b"", b"fatal: bad object HEAD\n"),
            ]
        )
        original = module.subprocess.run
        module.subprocess.run = lambda *args, **kwargs: next(calls)
        try:
            observed = module._git_identity(Path("/tmp"))
        finally:
            module.subprocess.run = original
        require(observed == ("unavailable", None), f"git diff failure looked clean: {observed}")

        calls = iter(
            [
                subprocess.CompletedProcess([], 0, (commit + "\n").encode("ascii"), b""),
                subprocess.CompletedProcess([], 1, b"", b""),
            ]
        )
        original_diff = module._git_diff_identity
        module.subprocess.run = lambda *args, **kwargs: next(calls)
        module._git_diff_identity = lambda *_args, **_kwargs: (True, None)
        try:
            observed = module._git_identity(Path("/tmp"))
        finally:
            module._git_diff_identity = original_diff
            module.subprocess.run = original
        require(observed == ("unavailable", None), f"empty dirty diff looked clean: {observed}")

    def untracked_source_is_in_git_identity(self) -> None:
        module = load_runner_library()
        case = self.case_dir("untracked-source-identity")
        repository = case / "repository"
        repository.mkdir()
        environment = os.environ.copy()
        environment.update(
            {
                "GIT_AUTHOR_NAME": "selftest",
                "GIT_AUTHOR_EMAIL": "selftest@example.invalid",
                "GIT_COMMITTER_NAME": "selftest",
                "GIT_COMMITTER_EMAIL": "selftest@example.invalid",
            }
        )

        def git(*arguments: str) -> None:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=repository,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            require(completed.returncode == 0, self.explain(completed))

        git("init", "-q")
        (repository / "tracked.txt").write_text("baseline\n", encoding="utf-8")
        git("add", "tracked.txt")
        git("commit", "-q", "-m", "baseline")
        (repository / "scripts").mkdir()
        source = repository / "scripts" / "untracked.py"
        source.write_text("VALUE = 1\n", encoding="utf-8")
        commit, first_hash = module._git_identity(repository)
        require(commit != "unavailable" and first_hash is not None, "untracked source looked clean")
        source.write_text("VALUE = 2\n", encoding="utf-8")
        second_commit, second_hash = module._git_identity(repository)
        require(second_commit == commit, "source edit changed the commit identity")
        require(second_hash is not None and second_hash != first_hash, "untracked source edit kept one identity")

    def malformed_unicode_is_refused(self) -> None:
        module = load_runner_library()
        try:
            module._require_string("\ud800", "probe")
        except module.ConfigurationError:
            pass
        else:
            raise TestFailure("lone surrogate was accepted as a requirements string")
        try:
            module._canonical_json({"reason": "\ud800"})
        except module.EvidenceError:
            pass
        else:
            raise TestFailure("lone surrogate evidence escaped the serializer contract")

        case = self.case_dir("surrogate-argv")
        profile = self.fixture.profile(case / "profile")
        task = self.fixture.task("unicode", "Q01", "pass")
        requirements = self.fixture.requirements(case, [("Q01", ["unicode"])], [task])
        evidence = case / "evidence"
        command = self.command(profile, requirements, evidence)
        command[command.index(TARGET)] = os.fsdecode(b"bad\xff")
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        require(completed.returncode == 64, self.explain(completed))
        require(not evidence.exists(), "malformed Unicode created evidence")

    def requirement_evidence_is_reaudited(self) -> None:
        module = load_runner_library()
        case = self.case_dir("requirement-reaudit")
        requirements_dir = case / "requirements"
        requirements_dir.mkdir()
        evidence = requirements_dir / "Q01.json"
        evidence.write_bytes(b'{"status":"pass"}\n')
        expected = sha256_file(evidence)
        evidence.write_bytes(b'{"status":"forged"}\n')
        try:
            module._audit_requirement_evidence(requirements_dir, {"Q01": expected})
        except module.EvidenceError:
            pass
        else:
            raise TestFailure("mutated requirement evidence passed final re-audit")

    def symlinked_input_ancestors_are_canonicalized(self) -> None:
        profile_case = self.case_dir("profile-ancestor-symlink")
        real_profile_dir = profile_case / "real-profile"
        real_profile = self.fixture.profile(real_profile_dir)
        profile_alias = profile_case / "profile"
        profile_alias.symlink_to(real_profile_dir, target_is_directory=True)
        marker = profile_case / "spawned"
        task = self.fixture.task("runs-once", "Q01", "mark-pass", marker)
        requirements = self.fixture.requirements(
            profile_case, [("Q01", ["runs-once"])], [task]
        )
        linked_profile = profile_alias / real_profile.name
        completed = self.invoke(profile_case, linked_profile, requirements)
        self.expect_rc(completed, 0)
        require(marker.exists(), "canonicalized profile run did not start")
        run = read_json(profile_case / "evidence" / "run.json")
        require(run.get("profile_path") == str(real_profile), "profile ancestor was not canonicalized")

        requirements_case = self.case_dir("requirements-ancestor-symlink")
        profile = self.fixture.profile(requirements_case / "profile")
        requirements_real_dir = requirements_case / "real-requirements"
        requirements_real_dir.mkdir()
        marker = requirements_case / "spawned"
        task = self.fixture.task("runs-once", "Q01", "mark-pass", marker)
        requirements = self.fixture.requirements(
            requirements_case, [("Q01", ["runs-once"])], [task]
        )
        moved = requirements_real_dir / requirements.name
        requirements.rename(moved)
        requirements_alias = requirements_case / "requirements-alias"
        requirements_alias.symlink_to(requirements_real_dir, target_is_directory=True)
        linked_requirements = requirements_alias / moved.name
        completed = self.invoke(requirements_case, profile, linked_requirements)
        self.expect_rc(completed, 0)
        require(marker.exists(), "canonicalized requirements run did not start")
        run = read_json(requirements_case / "evidence" / "run.json")
        require(run.get("requirements_path") == str(moved), "requirements ancestor was not canonicalized")

    def evidence_ancestor_symlink_is_canonicalized(self) -> None:
        case = self.case_dir("evidence-ancestor-symlink")
        profile = self.fixture.profile(case / "profile")
        outside_b = case / "outside-b"
        (outside_b / "nested").mkdir(parents=True)
        alias = case / "alias"
        task = self.fixture.task("switches-alias", "Q01", "switch-symlink", alias, outside_b)
        requirements = self.fixture.requirements(
            case, [("Q01", ["switches-alias"])], [task]
        )
        outside = case / "outside"
        nested = outside / "nested"
        nested.mkdir(parents=True)
        alias.symlink_to(outside, target_is_directory=True)
        evidence = alias / "nested" / "evidence"
        completed = subprocess.run(
            self.command(profile, requirements, evidence),
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.expect_rc(completed, 0)
        self.expect_summary(nested / "evidence", "pass", **{"pass": 1})
        require(
            not (outside_b / "nested" / "evidence").exists(),
            "runner followed a changed evidence ancestor",
        )

    def replaced_evidence_root_is_incomplete(self) -> None:
        case = self.case_dir("replaced-evidence-root")
        profile = self.fixture.profile(case / "profile")
        backup = case / "original-evidence"
        task = self.fixture.task(
            "replaces-root", "Q01", "replace-evidence-root", backup
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["replaces-root"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(not (case / "evidence" / "summary.json").exists(), "replacement tree was completed")
        require(not (backup / "summary.json").exists(), "moved original tree was completed")

    def symlink_replaced_evidence_root_is_removed(self) -> None:
        case = self.case_dir("symlink-replaced-evidence-root")
        profile = self.fixture.profile(case / "profile")
        backup = case / "original-evidence"
        external = case / "external"
        external.mkdir()
        task = self.fixture.task(
            "replaces-root",
            "Q01",
            "replace-evidence-with-symlink",
            backup,
            external,
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["replaces-root"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        require(
            not os.path.lexists(case / "evidence"),
            "replacement evidence symlink survived cleanup",
        )
        require(not (backup / "summary.json").exists(), "moved original tree retained a summary")

    def replaced_parent_symlink_preserves_external_path(self) -> None:
        case = self.case_dir("replace-evidence-parent-symlink")
        profile = self.fixture.profile(case / "profile")
        moved_parent = self.fixture.root / "moved-parent"
        external = self.fixture.root / "external-parent"
        task = self.fixture.task(
            "replace-parent",
            "Q01",
            "replace-evidence-parent-with-symlink",
            moved_parent,
            external,
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["replace-parent"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        sentinel = external / "evidence"
        require(sentinel.is_file(), "cleanup followed a replaced ancestor into external data")
        require(
            sentinel.read_text(encoding="utf-8") == "external sentinel\n",
            "external sentinel content changed",
        )
        require(
            not (moved_parent / "evidence" / "summary.json").exists(),
            "held evidence directory retained a forged summary",
        )

    def replaced_parent_directory_preserves_external_path(self) -> None:
        case = self.case_dir("replace-evidence-parent-directory")
        profile = self.fixture.profile(case / "profile")
        moved_parent = self.fixture.root / "moved-directory-parent"
        replacement_parent = self.fixture.root / "replacement-parent"
        replacement_parent.mkdir()
        (replacement_parent / "evidence").write_text(
            "external directory sentinel\n", encoding="utf-8"
        )
        task = self.fixture.task(
            "replace-parent",
            "Q01",
            "replace-evidence-parent-with-directory",
            moved_parent,
            replacement_parent,
        )
        requirements = self.fixture.requirements(
            case, [("Q01", ["replace-parent"])], [task]
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        sentinel = case / "evidence"
        require(sentinel.is_file(), "cleanup deleted data under a replacement parent")
        require(
            sentinel.read_text(encoding="utf-8") == "external directory sentinel\n",
            "replacement-parent sentinel content changed",
        )
        require(
            not (moved_parent / "evidence" / "summary.json").exists(),
            "held evidence directory retained a forged summary",
        )

    def internal_error_is_incomplete(self) -> None:
        code = f'''\
import sys
sys.path.insert(0, {str((ROOT / "scripts").resolve())!r})
import check_format_acceptance as cli
def explode(**_kwargs):
    raise RuntimeError("synthetic internal failure")
cli.run_acceptance = explode
raise SystemExit(cli.main([
    "--target", "onnx",
    "--profile", "/tmp/profile.json",
    "--suite", "unit",
    "--requirements", "/tmp/requirements.json",
    "--evidence-dir", "/tmp/evidence-never-created",
]))
'''
        completed = subprocess.run(
            [sys.executable, "-B", "-c", code],
            cwd=ROOT,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=5,
        )
        require(completed.returncode == 2, self.explain(completed))

    def missing_tool_commit_blocks_completion(self) -> None:
        case = self.case_dir("missing-tool-commit")
        profile = self.fixture.profile(case / "profile")
        tasks = [
            self.fixture.task(f"task-q{number:02d}", f"Q{number:02d}", "pass")
            for number in range(1, 13)
        ]
        requirement_map = [
            (f"Q{number:02d}", [f"task-q{number:02d}"])
            for number in range(1, 13)
        ]
        requirements = self.fixture.requirements(case, requirement_map, tasks)

        installed = case / "installed" / "scripts"
        installed_lib = installed / "lib"
        installed_lib.mkdir(parents=True)
        installed_runner = installed / "check_format_acceptance.py"
        installed_runner.write_bytes(RUNNER.read_bytes())
        installed_runner.chmod(0o700)
        source_library = ROOT / "scripts" / "lib" / "format_acceptance.py"
        (installed_lib / "format_acceptance.py").write_bytes(source_library.read_bytes())

        evidence = case / "evidence"
        command = [
            sys.executable,
            "-B",
            str(installed_runner),
            "--target",
            TARGET,
            "--profile",
            str(profile.resolve()),
            "--suite",
            SUITE,
            "--evidence-dir",
            str(evidence.resolve()),
            "--requirements",
            str(requirements.resolve()),
        ]
        completed = subprocess.run(
            command,
            cwd=case,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
        self.expect_rc(completed, 2)
        summary = self.expect_summary(evidence, "incomplete", **{"pass": 12})
        require("tool commit" in str(summary.get("identity_error", "")), "missing tool identity was not recorded")
        require(
            not (evidence / "qualification.candidate.json").exists(),
            "missing tool identity produced a qualification candidate",
        )

    def stdout_is_bounded(self) -> None:
        case, profile, requirements = self.make_single(
            "stdout-bound", "flood-stdout", stdout_limit_bytes=4096
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        record = self.record(case / "evidence", "task-one")
        require(record["stdout"]["size_bytes"] <= 4096, "stdout log exceeded its cap")
        require(record["stdout"]["truncated"] is True, "stdout overflow was not marked")

    def stderr_is_bounded(self) -> None:
        case, profile, requirements = self.make_single(
            "stderr-bound", "flood-stderr", stderr_limit_bytes=4096
        )
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        record = self.record(case / "evidence", "task-one")
        require(record["stderr"]["size_bytes"] <= 4096, "stderr log exceeded its cap")
        require(record["stderr"]["truncated"] is True, "stderr overflow was not marked")

    def profile_change_is_inconclusive(self) -> None:
        case = self.case_dir("profile-change")
        profile = self.fixture.profile(case / "profile")
        original_hash = sha256_file(profile)
        task = self.fixture.task("mutates-profile", "Q01", "mutate-profile", profile)
        requirements = self.fixture.requirements(case, [("Q01", ["mutates-profile"])], [task])
        completed = self.invoke(case, profile, requirements)
        self.expect_rc(completed, 2)
        self.expect_summary(case / "evidence", "incomplete", inconclusive=1)
        require(sha256_file(profile) != original_hash, "fixture did not mutate the profile")
        record = self.record(case / "evidence", "mutates-profile")
        require(record["status"] == "inconclusive", "changed profile retained pass")
        require(record["profile_sha256"] == original_hash, "original profile identity was lost")

    def runner_interruption_stays_incomplete(self) -> None:
        case = self.case_dir("runner-interrupt")
        profile = self.fixture.profile(case / "profile")
        ready, pids = case / "ready", case / "pids"
        tasks = [
            self.fixture.task("finished", "Q01", "pass"),
            self.fixture.task("interrupted", "Q02", "hang", ready, pids, timeout_ms=10000),
        ]
        requirements = self.fixture.requirements(
            case, [("Q01", ["finished"]), ("Q02", ["interrupted"])], tasks
        )
        evidence = case / "evidence"
        env = os.environ.copy()
        env.pop(HOOK_ENV, None)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        process = subprocess.Popen(
            self.command(profile, requirements, evidence),
            cwd=ROOT,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and not ready.exists() and process.poll() is None:
                time.sleep(0.03)
            require(ready.exists(), "runner never reached the interruptible task")
            process.send_signal(signal.SIGTERM)
            try:
                stdout, stderr = process.communicate(timeout=5.0)
            except subprocess.TimeoutExpired as error:
                os.killpg(process.pid, signal.SIGKILL)
                process.communicate()
                raise TestFailure("runner ignored SIGTERM") from error
            completed = subprocess.CompletedProcess(
                process.args, process.returncode, stdout, stderr
            )
            self.expect_rc(completed, 2)
            require(self.record(evidence, "finished")["status"] == "pass", "closed record was lost")
            run = read_json(evidence / "run.json")
            require(run.get("state") == "incomplete", "interrupted run was marked complete")
            summary_path = evidence / "summary.json"
            if summary_path.exists():
                require(
                    read_json(summary_path).get("overall_status") != "pass",
                    "interrupted run produced a pass summary",
                )
            wait_processes_gone(pids)
        finally:
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait()
            kill_fixture_processes(pids)

    def atomic_record_failure_preserves_incomplete(self) -> None:
        case = self.case_dir("atomic-failure")
        profile = self.fixture.profile(case / "profile")
        tasks = [
            self.fixture.task("atomic-first", "Q01", "pass"),
            self.fixture.task("atomic-second", "Q02", "pass"),
        ]
        requirements = self.fixture.requirements(
            case,
            [("Q01", ["atomic-first"]), ("Q02", ["atomic-second"])],
            tasks,
        )
        completed = self.invoke(
            case,
            profile,
            requirements,
            extra_env={HOOK_ENV: "fail-record-replace:atomic-second"},
        )
        self.expect_rc(completed, 2)
        require(self.record(case / "evidence", "atomic-first")["status"] == "pass", "first record was lost")
        require(
            not (case / "evidence" / "records" / "atomic-second.json").exists(),
            "failed atomic replace exposed a final second record",
        )
        run = read_json(case / "evidence" / "run.json")
        require(run.get("state") == "incomplete", "write failure was marked complete")
        summary_path = case / "evidence" / "summary.json"
        require(not summary_path.exists(), "write failure produced a final summary")
        temporary = list((case / "evidence").rglob("*.tmp*"))
        require(not temporary, f"atomic failure left temporary files: {temporary}")

        # A production runner may contain this fail-closed hook, but it must not
        # accept arbitrary actions or turn a malformed hook into successful evidence.
        unknown = self.invoke(
            case,
            profile,
            requirements,
            evidence_name="unknown-hook-evidence",
            extra_env={HOOK_ENV: "make-everything-pass"},
        )
        require(unknown.returncode == 64, f"unknown test hook was accepted: {self.explain(unknown)}")
        require(
            not (case / "unknown-hook-evidence" / "summary.json").exists(),
            "unknown test hook produced a summary",
        )


CASES: list[tuple[str, str]] = [
    ("all required tasks pass", "all_pass"),
    ("validation run IDs are unique", "validation_run_ids_are_unique"),
    ("symlink task executables are refused", "executable_is_pinned_before_tasks"),
    ("direct shebang executables are refused", "direct_shebang_executable_is_refused"),
    ("interpreter scripts are pinned", "interpreter_script_is_pinned_before_tasks"),
    ("interpreter script identity is required", "interpreter_script_identity_is_required"),
    ("Python module mode is refused", "python_module_mode_is_refused"),
    ("identity file hashes are verified", "identity_file_hash_is_verified"),
    ("hardlink identity aliases are refused", "hardlink_identity_alias_is_refused"),
    ("relative identity paths are canonicalized", "relative_identity_path_is_canonicalized"),
    ("attached option files are pinned", "attached_option_file_is_pinned"),
    ("interpreter options keep their meaning", "interpreter_options_keep_their_meaning"),
    ("file-like arguments keep their meaning", "file_like_arguments_keep_their_meaning"),
    ("loader environment is refused", "loader_environment_is_refused"),
    ("Q01-Q12 remain per-suite evidence only", "all_requirements_remain_evidence_only"),
    ("explicit fail returns rc1", "explicit_fail"),
    ("explicit fail survives missing artifact", "explicit_fail_survives_missing_artifact"),
    ("explicit fail survives identity change", "explicit_fail_survives_identity_change"),
    ("explicit fail survives output limits", "explicit_fail_survives_output_limit"),
    ("blocked returns rc2", "explicit_blocked"),
    ("blocked dependency becomes not_run", "blocked_dependency_is_not_run"),
    ("inconclusive returns rc2", "explicit_inconclusive"),
    ("zero checks are refused", "zero_checks"),
    ("artifact path collisions are refused", "artifact_path_collisions_are_refused"),
    ("missing required ID is refused", "missing_required_id"),
    ("duplicate task ID is refused", "duplicate_task_id"),
    ("duplicate requirement ID is refused", "duplicate_requirement_id"),
    ("rc0 without a result record is incomplete", "missing_result_record"),
    ("duplicate-key result JSON is incomplete", "duplicate_key_result"),
    ("the final ok cannot erase an earlier failure", "last_ok_does_not_win"),
    ("skip output is not pass", "skip_is_not_pass"),
    ("positive skip count is not pass", "skip_count_is_not_pass"),
    ("pytest skip count is not pass", "pytest_skip_count_is_not_pass"),
    ("huge skip counts stay bounded", "huge_skip_count_is_bounded"),
    ("pass requires a measurement", "pass_requires_measurement"),
    ("stale result is incomplete", "stale_result_is_inconclusive"),
    ("wrong profile is refused before spawn", "wrong_profile"),
    ("timeout kills the task process tree", "timeout_kills_process_tree"),
    (
        "successful task reaps process-group descendants",
        "successful_task_reaps_process_group_descendants",
    ),
    (
        "successful task reaps detached descendants",
        "successful_task_reaps_detached_descendants",
    ),
    ("task control signals are unblocked", "task_control_signals_are_unblocked"),
    ("failed signal setup restores subreaper", "signal_scope_failure_restores_subreaper"),
    ("inherited blocked signals are unblocked", "inherited_blocked_signal_is_unblocked"),
    ("SIGHUP reaps the task process tree", "sighup_reaps_the_task_process_tree"),
    (
        "cleanup signals still reap detached descendants",
        "cleanup_signal_still_reaps_detached_descendants",
    ),
    ("artifact parent symlink is incomplete", "artifact_parent_symlink_is_inconclusive"),
    ("hardlinked artifact is incomplete", "hardlinked_artifact_is_inconclusive"),
    ("published artifacts are reaudited", "published_artifact_is_reaudited"),
    ("run manifest is reaudited", "run_manifest_is_reaudited"),
    ("forged summary is removed", "forged_summary_is_removed"),
    ("undeclared evidence is rejected", "undeclared_evidence_is_rejected"),
    ("forged qualification candidate is removed", "forged_qualification_candidate_is_removed"),
    ("setup failure removes terminal markers", "setup_failure_removes_terminal_markers"),
    ("locked forged summary is removed", "locked_forged_summary_is_removed"),
    ("artifact budget applies before hashing", "artifact_budget_is_applied_before_hash"),
    ("unchanged execution identity avoids rehash", "unchanged_execution_identity_avoids_rehash"),
    (
        "restored mtime does not hide identity changes",
        "restored_mtime_does_not_hide_identity_change",
    ),
    ("git diff failure is unavailable", "git_diff_failure_is_unavailable"),
    ("untracked source is in git identity", "untracked_source_is_in_git_identity"),
    ("malformed Unicode is refused safely", "malformed_unicode_is_refused"),
    ("requirement evidence is reaudited", "requirement_evidence_is_reaudited"),
    ("symlinked input ancestors are canonicalized", "symlinked_input_ancestors_are_canonicalized"),
    ("evidence ancestor symlink is canonicalized", "evidence_ancestor_symlink_is_canonicalized"),
    ("replaced evidence root is incomplete", "replaced_evidence_root_is_incomplete"),
    ("symlink-replaced evidence root is removed", "symlink_replaced_evidence_root_is_removed"),
    (
        "replaced parent symlink preserves external data",
        "replaced_parent_symlink_preserves_external_path",
    ),
    (
        "replaced parent directory preserves external data",
        "replaced_parent_directory_preserves_external_path",
    ),
    ("stdout is bounded", "stdout_is_bounded"),
    ("stderr is bounded", "stderr_is_bounded"),
    ("profile mutation invalidates pass", "profile_change_is_inconclusive"),
    ("mid-run termination remains incomplete", "runner_interruption_stays_incomplete"),
    ("atomic record failure remains incomplete", "atomic_record_failure_preserves_incomplete"),
    ("missing tool commit blocks completion", "missing_tool_commit_blocks_completion"),
    ("internal runner errors are incomplete", "internal_error_is_incomplete"),
]


def main() -> int:
    passed = 0
    failed = 0
    if not RUNNER.is_file():
        for label, _ in CASES:
            failed += 1
            print(f"  FAIL {label}: runner missing: {RUNNER}")
        print(f"[format-acceptance-selftest] pass={passed} fail={failed}")
        return 1

    with tempfile.TemporaryDirectory(prefix="format-acceptance-selftest-") as raw_work:
        work = Path(raw_work)
        fixture = Fixture(work)
        tests = AcceptanceSelftest(fixture)
        for label, method_name in CASES:
            try:
                method: Callable[[], None] = getattr(tests, method_name)
                method()
            except Exception as error:  # Each case must report independently.
                failed += 1
                print(f"  FAIL {label}: {error}")
            else:
                passed += 1
                print(f"  ok   {label}")

    print(f"[format-acceptance-selftest] pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
