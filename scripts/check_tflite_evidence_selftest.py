#!/usr/bin/env python3
"""Fast positive and negative controls for TFL Q10/Q11 evidence."""

from __future__ import annotations

import argparse
import copy
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def load(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


baseline = load("tflite_evidence_baseline", SCRIPTS / "measure_format_baseline.py")


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def run(self, label: str, function: Callable[[], None]) -> None:
        try:
            function()
        except Exception as error:
            self.failed += 1
            print(f"[tflite-evidence] fail: {label}: {error}", file=sys.stderr)
        else:
            self.passed += 1
            print(f"[tflite-evidence] ok: {label}")


def canonical(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def operation(document: dict[str, Any], name: str, **changes: Any) -> dict[str, Any]:
    identity = document["identity"]
    fixed = identity["fixed"]
    duration = 21_600.0 if name in {"single_worker_soak", "parallel_soak"} else 60.0
    worker_count = 2 if name == "parallel_soak" else 1
    outcome = "worker_failure" if name == "fault_injection" else "completed"
    started = datetime(2026, 10, 22, tzinfo=timezone.utc)
    ended = started + timedelta(seconds=duration)
    command = copy.deepcopy(identity["candidate_command"])
    if name in {"single_worker_soak", "parallel_soak"}:
        fuzzer = next(
            row
            for row in identity["candidate_profile"]["binaries"]
            if row["role"] == "fuzzer"
        )
        command = {
            **command,
            "argv": [
                fuzzer["path"],
                "{corpus_dir}",
                "-print_final_stats=1",
                "-max_total_time=21600",
            ],
            "executable_sha256": fuzzer["sha256"],
        }
    value = {
        "schema_version": "tflite-v7-operation-v1",
        "operation": name,
        "mode": "real",
        "target_id": fixed["target_id"],
        "tool_commit": identity["candidate_tool_commit"],
        "dirty_diff_sha256": identity["candidate_dirty_diff_sha256"],
        "profile_sha256": identity["candidate_profile_sha256"],
        "command": command,
        "command_sha256": hashlib.sha256(canonical(command)).hexdigest(),
        "corpus_before_sha256": fixed["corpus_sha256"],
        "corpus_after_sha256": fixed["corpus_sha256"],
        "started_utc": started.isoformat().replace("+00:00", "Z"),
        "ended_utc": ended.isoformat().replace("+00:00", "Z"),
        "duration_seconds": duration,
        "target_api_calls": 1,
        "worker_count": worker_count,
        "expected_outcome": outcome,
        "observed_outcome": outcome,
        "exit_code": 1 if name == "fault_injection" else 0,
        "signal": None,
        "residual_processes": 0,
        "resource_samples": [
            {
                "elapsed_seconds": 0.0,
                "peak_rss_bytes": 1,
                "log_bytes": 1,
                "disk_bytes": 1,
                "owned_processes": worker_count,
            },
            {
                "elapsed_seconds": duration,
                "peak_rss_bytes": 1,
                "log_bytes": 1,
                "disk_bytes": 1,
                "owned_processes": 0,
            },
        ],
        "budgets": {
            "peak_rss_bytes": fixed["memory_limit_bytes"] * worker_count,
            "log_bytes": 1_048_576,
            "disk_bytes": 1_048_576,
        },
        "artifacts": [
            {"path": f"raw/{name}.log", "sha256": "a" * 64, "size_bytes": 1}
        ],
    }
    value.update(changes)
    return value


def pass_row(value: dict[str, Any]) -> dict[str, Any]:
    raw = canonical(value).decode("utf-8")
    return {
        "status": "pass",
        "reason": None,
        "evidence_sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
        "raw_json": raw,
    }


def operation_document(name: str = "actual_parser_performance", **changes: Any) -> dict[str, Any]:
    document = baseline._valid_document()
    identity = document["identity"]
    identity["candidate_profile"] = copy.deepcopy(identity["baseline_profile"])
    fuzzer = {
        "role": "fuzzer",
        "path": "/opt/onnx/fuzzer",
        "sha256": "3" * 64,
        "argv": ["{corpus_dir}"],
        "linked_libraries": [],
    }
    identity["baseline_profile"]["binaries"].append(copy.deepcopy(fuzzer))
    identity["candidate_profile"]["binaries"].append(copy.deepcopy(fuzzer))
    baseline._refresh_profile_snapshot(document, "baseline")
    baseline._refresh_profile_snapshot(document, "candidate")
    identity["allowed_profile_differences"] = []
    identity["candidate_command"] = copy.deepcopy(identity["baseline_command"])
    baseline._refresh_command_snapshot(document, "candidate")
    identity["candidate_tool_commit"] = identity["baseline_tool_commit"]
    identity["candidate_source_state"] = "clean"
    identity["candidate_dirty_diff_raw_text"] = None
    identity["candidate_dirty_diff_sha256"] = None
    identity["candidate_source_artifacts"] = copy.deepcopy(identity["baseline_source_artifacts"])
    identity["allowed_tool_changes"] = []
    for sample in [document["warmups"][2], *(pair["candidate"] for pair in document["comparison"])]:
        sample["tool_commit"] = identity["candidate_tool_commit"]
        sample["dirty_diff_sha256"] = None
    snapshot = baseline._correctness_snapshot_object(document, "candidate")
    snapshot["tool_commit"] = identity["candidate_tool_commit"]
    snapshot["dirty_diff_sha256"] = None
    baseline._store_correctness_snapshot(document, "candidate", snapshot)
    document["mode"] = "real"
    baseline._refresh_measurement_context(document)
    document["operations"][name] = pass_row(operation(document, name, **changes))
    return document


def expect_contract_error(document: dict[str, Any], needle: str) -> None:
    try:
        baseline.evaluate_document(document)
    except baseline.ContractError as error:
        if needle not in str(error):
            raise AssertionError(f"wrong refusal: {error}") from error
    else:
        raise AssertionError(f"invalid evidence was accepted; wanted {needle!r}")


def valid_raw_operation_is_accepted() -> None:
    result = baseline.evaluate_document(operation_document())
    if result["operations"]["actual_parser_performance"]["status"] != "pass":
        raise AssertionError("strict raw operation did not retain its derived pass")


def tampered_raw_operation_is_rejected() -> None:
    document = operation_document()
    row = document["operations"]["actual_parser_performance"]
    row["raw_json"] = row["raw_json"].replace('"target_api_calls":1', '"target_api_calls":2')
    expect_contract_error(document, "evidence_sha256")


def short_operation_is_rejected() -> None:
    expect_contract_error(operation_document(duration_seconds=59.0), "duration_seconds")


def zero_api_operation_is_rejected() -> None:
    expect_contract_error(operation_document(target_api_calls=0), "target_api_calls")


def residual_process_is_rejected() -> None:
    expect_contract_error(operation_document(residual_processes=1), "residual_processes")


def corpus_mutation_is_rejected() -> None:
    expect_contract_error(operation_document(corpus_after_sha256="b" * 64), "corpus")


def wrong_commit_is_rejected() -> None:
    expect_contract_error(operation_document(tool_commit="c" * 40), "tool_commit")


def wrong_profile_is_rejected() -> None:
    expect_contract_error(operation_document(profile_sha256="c" * 64), "profile_sha256")


def wrong_soak_binary_role_is_rejected() -> None:
    document = operation_document()
    value = operation(document, "single_worker_soak")
    value["command"] = copy.deepcopy(document["identity"]["candidate_command"])
    value["command_sha256"] = hashlib.sha256(canonical(value["command"])).hexdigest()
    document["operations"]["single_worker_soak"] = pass_row(value)
    expect_contract_error(document, "profile-pinned fuzzer")


def collector_performance_cli_runs_workload() -> None:
    collector = load_collector()
    parsed = collector.build_parser().parse_args(
        ["performance", "--run-root", "/tmp/tflite-evidence-cli"]
    )
    if parsed.function is not collector.performance or hasattr(parsed, "observations"):
        raise AssertionError("performance still imports caller-authored observations")


def memory_controller_is_enabled_for_private_sample_leaves() -> None:
    collector = load_collector()
    sample_id = "controller-enabled-sample"
    with tempfile.TemporaryDirectory(prefix="tflite-cgroup-controller-") as raw:
        parent = Path(raw)
        manager = parent / f"tflite-collector-{os.getpid()}"
        sample = parent / sample_id
        pids = {
            parent: [os.getpid(), os.getppid()],
            manager: [],
        }
        memory_enabled = False
        events: list[str] = []
        original_mkdir = Path.mkdir
        original_tokens = collector._cgroup_tokens
        original_pids = collector._cgroup_pids
        original_write = collector._write_cgroup_value

        def seeded_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
            original_mkdir(path, *args, **kwargs)
            if path == sample and memory_enabled:
                (path / "memory.peak").write_text("0\n", encoding="ascii")

        def fake_tokens(path: Path, _label: str) -> set[str]:
            if path == parent / "cgroup.controllers":
                return {"cpu", "memory", "pids"}
            if path == parent / "cgroup.subtree_control":
                return {"memory"} if memory_enabled else set()
            raise AssertionError(f"unexpected token read: {path}")

        def fake_pids(path: Path, _label: str) -> list[int]:
            group = path.parent
            if group not in pids:
                raise AssertionError(f"unexpected PID read: {path}")
            return list(pids[group])

        def fake_write(path: Path, value: str, _label: str) -> None:
            nonlocal memory_enabled
            if path == manager / "cgroup.procs":
                pid = int(value)
                pids[parent].remove(pid)
                pids[manager].append(pid)
                events.append(f"move-in:{pid}")
                return
            if path == parent / "cgroup.procs":
                pid = int(value)
                pids[manager].remove(pid)
                pids[parent].append(pid)
                events.append(f"move-out:{pid}")
                return
            if path == parent / "cgroup.subtree_control" and value == "+memory":
                if pids[parent]:
                    raise AssertionError("memory controller enabled before parent was empty")
                memory_enabled = True
                (manager / "memory.peak").write_text("0\n", encoding="ascii")
                events.append("enable-memory")
                return
            if path == parent / "cgroup.subtree_control" and value == "-memory":
                memory_enabled = False
                (manager / "memory.peak").unlink()
                events.append("disable-memory")
                return
            raise AssertionError(f"unexpected cgroup write: {path}={value!r}")

        try:
            Path.mkdir = seeded_mkdir
            collector._cgroup_tokens = fake_tokens
            collector._cgroup_pids = fake_pids
            collector._write_cgroup_value = fake_write
            with collector.MemoryCgroupSession(parent) as sample_parent:
                if sample_parent != parent or not memory_enabled or pids[parent]:
                    raise AssertionError("collector did not prepare an empty controller parent")
                group = collector.SampleCgroup(sample_parent, sample_id, 1_073_741_824)
                if not (group.path / "memory.peak").is_file():
                    raise AssertionError("private sample leaf lacks memory.peak after activation")
                (group.path / "memory.peak").unlink()
                group.path.rmdir()
        finally:
            Path.mkdir = original_mkdir
            collector._cgroup_tokens = original_tokens
            collector._cgroup_pids = original_pids
            collector._write_cgroup_value = original_write
            (sample / "memory.peak").unlink(missing_ok=True)
            if sample.exists():
                sample.rmdir()
            if manager.exists():
                manager.rmdir()
        if memory_enabled or pids[manager] or sorted(pids[parent]) != sorted((os.getpid(), os.getppid())):
            raise AssertionError("collector did not restore the delegated parent")
        if events[-3:] != [
            "disable-memory",
            f"move-out:{os.getpid()}",
            f"move-out:{os.getppid()}",
        ]:
            raise AssertionError(f"wrong cgroup cleanup order: {events}")


def read_only_cgroup_limit_still_collects_peak() -> None:
    collector = load_collector()
    sample_id = "read-only-memory-limit"
    with tempfile.TemporaryDirectory(prefix="tflite-read-only-cgroup-") as raw:
        parent = Path(raw)
        leaf = parent / sample_id
        original_mkdir = Path.mkdir
        original_write_text = Path.write_text

        def seeded_mkdir(path: Path, *args: Any, **kwargs: Any) -> None:
            original_mkdir(path, *args, **kwargs)
            if path == leaf:
                original_write_text(path / "memory.max", "max\n", encoding="ascii")
                original_write_text(path / "memory.peak", "0\n", encoding="ascii")

        def deny_limit_write(path: Path, *args: Any, **kwargs: Any) -> int:
            if path == leaf / "memory.max":
                raise PermissionError(13, "read-only delegated resource control", str(path))
            return original_write_text(path, *args, **kwargs)

        try:
            Path.mkdir = seeded_mkdir
            Path.write_text = deny_limit_write
            group = collector.SampleCgroup(parent, sample_id, 1_073_741_824)
        finally:
            Path.mkdir = original_mkdir
            Path.write_text = original_write_text
            for name in ("memory.max", "memory.peak"):
                (leaf / name).unlink(missing_ok=True)
            if leaf.exists():
                leaf.rmdir()
        if group.path != leaf:
            raise AssertionError("collector changed the private sample cgroup identity")


def collector_builds_nonqualifying_selftest_observations() -> None:
    collector = load_collector()

    class FakeCgroup:
        def __init__(self, parent: Path, sample_id: str, _memory_limit: int) -> None:
            self.path = parent / sample_id

        def child_setup(self) -> None:
            os.setsid()

        def pids(self) -> list[int]:
            return []

        def finish(self) -> tuple[int, str]:
            return 0, "4096\n"

    with tempfile.TemporaryDirectory(prefix="tflite-performance-builder-") as raw:
        root = Path(raw)
        replay = root / "replay"
        replay.write_text(
            "#!/usr/bin/python3\n"
            "import pathlib,sys\n"
            "if pathlib.Path(sys.argv[1]).read_bytes() == b'ok':\n"
            " print('TFLITE_LOAD_OK stage=allocate_tensors inputs=1 outputs=1 tensors=1 threads=1')\n"
            " print('TFLITE_ACCESS_OK tensors=1 constants=0 constant_bytes=0')\n"
            " raise SystemExit(0)\n"
            "print('TFLITE_LOAD_REJECT stage=load_allocate reason=fixture', file=sys.stderr)\n"
            "raise SystemExit(9)\n",
            encoding="utf-8",
        )
        replay.chmod(0o700)
        fuzzer = root / "fuzzer"
        fuzzer.write_bytes(replay.read_bytes())
        fuzzer.chmod(0o700)
        target_root = Path(
            os.environ.get(
                "TFLITE_TARGET_ROOT",
                str(ROOT / "data/targets/tflite/v2.20.0"),
            )
        )
        profile = json.loads((target_root / "profile.json").read_text(encoding="utf-8"))
        profile["binaries"] = [
            {
                "role": "replay",
                "path": str(replay),
                "sha256": hashlib.sha256(replay.read_bytes()).hexdigest(),
                "argv": ["{input}"],
                "linked_libraries": [],
            },
            {
                "role": "fuzzer",
                "path": str(fuzzer),
                "sha256": hashlib.sha256(fuzzer.read_bytes()).hexdigest(),
                "argv": ["{corpus_dir}"],
                "linked_libraries": [],
            },
        ]
        profile_path = root / "profile.json"
        profile_path.write_bytes(canonical(profile))
        corpus = root / "corpus"
        corpus.mkdir()
        accepted = corpus / "accepted.tflite"
        rejected = corpus / "rejected.tflite"
        accepted.write_bytes(b"ok")
        rejected.write_bytes(b"reject")
        corpus_index = corpus / "index.json"
        corpus_index.write_bytes(
            canonical(
                {
                    "schema_version": "format-performance-corpus-v1",
                    "inputs": [
                        {
                            "path": accepted.name,
                            "sha256": hashlib.sha256(accepted.read_bytes()).hexdigest(),
                            "expected_outcome": "accepted",
                            "expected_exit_code": 0,
                            "target_api_stage": "target-parser",
                            "minimum_target_api_calls": 1,
                            "required_api_events": ["LoadAndAllocate"],
                            "zero_call_reason": None,
                            "throughput_order_index": 1,
                            "throughput_exclusion_reason": None,
                            "latency_probe_order_index": 1,
                            "latency_exclusion_reason": None,
                        },
                        {
                            "path": rejected.name,
                            "sha256": hashlib.sha256(rejected.read_bytes()).hexdigest(),
                            "expected_outcome": "rejected",
                            "expected_exit_code": 9,
                            "target_api_stage": "target-parser",
                            "minimum_target_api_calls": 1,
                            "required_api_events": ["LoadAndAllocate"],
                            "zero_call_reason": None,
                            "throughput_order_index": 2,
                            "throughput_exclusion_reason": None,
                            "latency_probe_order_index": None,
                            "latency_exclusion_reason": "rejected correctness-only fixture",
                        },
                    ],
                }
            )
        )
        evidence_root = root / "evidence"
        evidence_root.mkdir()
        run_root = root / "run"
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip()
        corpus_sha, _ = collector.audit_corpus(corpus_index)
        collector.prepare(
            argparse.Namespace(
                run_root=run_root,
                profile=profile_path,
                replay=replay,
                corpus_index=corpus_index,
                corpus_sha256=corpus_sha,
                evidence_root=evidence_root,
                comparison_id="collector-builder-selftest",
                expected_commit=commit,
                mode="selftest",
                peak_rss_bytes=1_073_741_824,
                log_bytes=1_048_576,
                disk_bytes=1_048_576,
            )
        )
        prepared = collector.read_prepare(run_root, recheck=True)
        original_cgroup = collector.SampleCgroup
        collector.SampleCgroup = FakeCgroup
        try:
            document = collector._performance_document(
                prepared,
                Path("/sys/fs/cgroup/tflite-selftest"),
                mode="selftest",
                sample_seconds=0.0,
                latency_batch_iterations=1,
            )
        finally:
            collector.SampleCgroup = original_cgroup
        result = baseline.evaluate_document(document)
        if (
            document["mode"] != "selftest"
            or document["identity"]["allowed_profile_differences"]
            or document["identity"]["allowed_tool_changes"]
            or result["operations"]["actual_parser_performance"]["status"] != "pending"
        ):
            raise AssertionError("selftest builder crossed the actual-evidence boundary")


def zero_byte_artifact_is_preserved() -> None:
    document = operation_document(
        artifacts=[
            {
                "path": "raw/empty.log",
                "sha256": hashlib.sha256(b"").hexdigest(),
                "size_bytes": 0,
            }
        ]
    )
    result = baseline.evaluate_document(document)
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-empty-") as raw:
        destination = baseline.publish_evidence(document, result, Path(raw))
        operation_raw = json.loads(
            (destination / "operations" / "actual_parser_performance.json").read_text(
                encoding="utf-8"
            )
        )
        if operation_raw["artifacts"][0]["size_bytes"] != 0:
            raise AssertionError("zero-byte artifact metadata was not preserved")


def runner_advertises_explicit_bundles() -> None:
    completed = subprocess.run(
        [sys.executable, "-B", str(SCRIPTS / "run_tflite_qualification.py"), "--help"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or "--q10-evidence" not in output or "--q11-evidence" not in output:
        raise AssertionError("qualification runner cannot consume explicit Q10/Q11 bundles")


def load_collector() -> Any:
    path = SCRIPTS / "collect_tflite_evidence.py"
    if not path.is_file() or path.is_symlink():
        raise AssertionError("collector is missing")
    return load("tflite_evidence_collector", path)


def publish_q10_bundle(root: Path) -> tuple[Path, dict[str, Any]]:
    document = operation_document()
    result = baseline.evaluate_document(document)
    destination = baseline.publish_evidence(document, result, root)
    return destination, document


def complete_bundle_is_revalidated() -> None:
    collector = load_collector()
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-valid-") as raw:
        destination, document = publish_q10_bundle(Path(raw))
        collector.validate_bundle(
            destination,
            requirement="Q10",
            expected_commit=document["identity"]["candidate_tool_commit"],
            expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
        )


def q10_bundle_cannot_satisfy_q11() -> None:
    collector = load_collector()
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-swap-") as raw:
        destination, document = publish_q10_bundle(Path(raw))
        try:
            collector.validate_bundle(
                destination,
                requirement="Q11",
                expected_commit=document["identity"]["candidate_tool_commit"],
                expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
            )
        except collector.EvidenceError as error:
            if "Q11" not in str(error):
                raise AssertionError(f"wrong Q10/Q11 swap refusal: {error}") from error
        else:
            raise AssertionError("Q10-only bundle was accepted for Q11")


def complete_q11_bundle_is_revalidated() -> None:
    collector = load_collector()
    document = operation_document()
    for name in (
        "engine_smoke",
        "single_worker_soak",
        "parallel_soak",
        "fault_injection",
    ):
        document["operations"][name] = pass_row(operation(document, name))
    result = baseline.evaluate_document(document)
    if result["gate_status"] != "pass":
        raise AssertionError(f"complete Q11 fixture did not pass aggregate validation: {result}")
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-q11-") as raw:
        destination = baseline.publish_evidence(document, result, Path(raw))
        collector.validate_bundle(
            destination,
            requirement="Q11",
            expected_commit=document["identity"]["candidate_tool_commit"],
            expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
            require_current_aa=True,
        )


def qualification_task_revalidates_bundle() -> None:
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-task-") as raw:
        root = Path(raw)
        destination, document = publish_q10_bundle(root)
        result = root / "task-result.json"
        environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "FORMAT_ACCEPTANCE_RESULT_PATH": str(result),
            "TOOL_VALIDATION_RUN": "tflite-evidence-selftest",
        }
        completed = subprocess.run(
            [
                sys.executable,
                "-B",
                str(SCRIPTS / "tflite_qualification_task.py"),
                "evidence",
                "--bundle",
                str(destination),
                "--requirement",
                "Q10",
                "--expected-commit",
                document["identity"]["candidate_tool_commit"],
                "--expected-profile-sha256",
                document["identity"]["candidate_profile_sha256"],
                "--require-current-aa",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise AssertionError(f"evidence task rc={completed.returncode}: {completed.stderr}")
        value = json.loads(result.read_text(encoding="utf-8"))
        if value.get("status") != "pass":
            raise AssertionError(f"evidence task did not issue pass: {value}")


def qualification_runner_pins_complete_bundle() -> None:
    collector = load_collector()
    runner = load("tflite_evidence_runner_pinning", SCRIPTS / "run_tflite_qualification.py")
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-runner-") as raw:
        root = Path(raw)
        destination, document = publish_q10_bundle(root)
        files = collector.validate_bundle(
            destination,
            requirement="Q10",
            expected_commit=document["identity"]["candidate_tool_commit"],
            expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
        )
        task = runner.task(
            ROOT,
            root,
            Path(sys.executable).resolve(strict=True),
            "Q10",
            None,
            "unused",
            {"LC_ALL": "C"},
            destination,
            files,
            document["identity"]["candidate_tool_commit"],
            document["identity"]["candidate_profile_sha256"],
        )
        pinned = {Path(row["path"]) for row in task["identity_files"]}
        missing = set(files) - pinned
        if missing or len(task["identity_files"]) > 64:
            raise AssertionError(
                f"runner did not pin the complete bundle: missing={sorted(map(str, missing))}"
            )


def identity_limit_fails_closed() -> None:
    runner = load("tflite_evidence_runner", SCRIPTS / "run_tflite_qualification.py")
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-identities-") as raw:
        root = Path(raw)
        paths = [root / f"identity-{index:03d}" for index in range(65)]
        try:
            runner.identity_paths(ROOT, root, None, paths)
        except runner.RunError as error:
            if "exceeds FND-03 limit" not in str(error):
                raise AssertionError(f"wrong identity-limit refusal: {error}") from error
        else:
            raise AssertionError("identity inventory above 64 was truncated or accepted")


def partial_index_is_rejected() -> None:
    collector = load_collector()
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-partial-") as raw:
        destination, document = publish_q10_bundle(Path(raw))
        (destination / "evaluation.json").unlink()
        try:
            collector.validate_bundle(
                destination,
                requirement="Q10",
                expected_commit=document["identity"]["candidate_tool_commit"],
                expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
            )
        except collector.EvidenceError as error:
            if not any(
                needle in str(error)
                for needle in ("inventory", "missing", "could not inspect")
            ):
                raise AssertionError(f"wrong partial-index refusal: {error}") from error
        else:
            raise AssertionError("partial complete index was accepted")


def overwrite_is_rejected() -> None:
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-overwrite-") as raw:
        root = Path(raw)
        destination, document = publish_q10_bundle(root)
        before = (destination / "index.json").read_bytes()
        try:
            baseline.publish_evidence(document, baseline.evaluate_document(document), root)
        except baseline.EvidenceError:
            pass
        else:
            raise AssertionError("existing bundle was overwritten")
        if (destination / "index.json").read_bytes() != before:
            raise AssertionError("existing bundle changed after overwrite refusal")


def bundle_symlink_is_rejected() -> None:
    collector = load_collector()
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-link-") as raw:
        root = Path(raw)
        destination, document = publish_q10_bundle(root)
        target = destination / "evaluation.json"
        copied = root / "outside.json"
        copied.write_bytes(target.read_bytes())
        target.unlink()
        target.symlink_to(copied)
        try:
            collector.validate_bundle(
                destination,
                requirement="Q10",
                expected_commit=document["identity"]["candidate_tool_commit"],
                expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
            )
        except collector.EvidenceError as error:
            if "symlink" not in str(error) and "regular" not in str(error):
                raise AssertionError(f"wrong symlink refusal: {error}") from error
        else:
            raise AssertionError("linked bundle member was accepted")


def selftest_bundle_is_rejected() -> None:
    collector = load_collector()
    document = operation_document()
    document["mode"] = "selftest"
    for row in document["operations"].values():
        row.update({"status": "pending", "reason": "selftest", "evidence_sha256": None, "raw_json": None})
    baseline._refresh_measurement_context(document)
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-selftest-") as raw:
        destination = baseline.publish_evidence(document, baseline.evaluate_document(document), Path(raw))
        try:
            collector.validate_bundle(
                destination,
                requirement="Q10",
                expected_commit=document["identity"]["candidate_tool_commit"],
                expected_profile_sha256=document["identity"]["candidate_profile_sha256"],
            )
        except collector.EvidenceError as error:
            if "selftest" not in str(error) and "real" not in str(error):
                raise AssertionError(f"wrong selftest refusal: {error}") from error
        else:
            raise AssertionError("selftest bundle was accepted as actual evidence")


def collector_state_machine_selftest_is_nonqualifying() -> None:
    collector = load_collector()
    with tempfile.TemporaryDirectory(prefix="tflite-evidence-state-") as raw:
        root = Path(raw)
        evidence_root = root / "evidence"
        evidence_root.mkdir()
        corpus_root = root / "corpus"
        corpus_root.mkdir()
        model = corpus_root / "model.tflite"
        model.write_bytes(b"fixture-model")
        corpus_index = corpus_root / "index.json"
        corpus_index.write_bytes(
            canonical(
                {
                    "schema_version": "format-performance-corpus-v1",
                    "inputs": [
                        {
                            "path": model.name,
                            "sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
                            "expected_outcome": "accepted",
                            "expected_exit_code": 0,
                            "target_api_stage": "target-parser",
                            "minimum_target_api_calls": 1,
                            "required_api_events": ["LoadAndAllocate"],
                            "zero_call_reason": None,
                            "throughput_order_index": 1,
                            "throughput_exclusion_reason": None,
                            "latency_probe_order_index": 1,
                            "latency_exclusion_reason": None,
                        }
                    ],
                }
            )
        )
        corpus_sha, _ = collector.audit_corpus(corpus_index)
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            text=True,
            check=True,
        ).stdout.strip()
        run_root = root / "run"
        target_root = Path(
            os.environ.get(
                "TFLITE_TARGET_ROOT",
                str(ROOT / "data/targets/tflite/v2.20.0"),
            )
        )
        replay_path = Path(
            os.environ.get(
                "TFLITE_REPLAY",
                str(ROOT / "harnesses/tflite/tflite_loader_replay"),
            )
        )
        profile_document = json.loads(
            (target_root / "profile.json").read_text(encoding="utf-8")
        )
        replay_row = next(
            row for row in profile_document["binaries"] if row.get("role") == "replay"
        )
        replay_row["path"] = str(replay_path.resolve(strict=True))
        replay_row["sha256"] = hashlib.sha256(replay_path.read_bytes()).hexdigest()
        if not any(row.get("role") == "fuzzer" for row in profile_document["binaries"]):
            fuzzer_path = Path(sys.executable).resolve(strict=True)
            profile_document["binaries"].append(
                {
                    "role": "fuzzer",
                    "path": str(fuzzer_path),
                    "sha256": hashlib.sha256(fuzzer_path.read_bytes()).hexdigest(),
                    "argv": ["{corpus_dir}"],
                    "linked_libraries": [],
                }
            )
        profile_path = root / "profile.json"
        profile_path.write_bytes(canonical(profile_document))
        prepared = argparse.Namespace(
            run_root=run_root,
            profile=profile_path,
            replay=replay_path,
            corpus_index=corpus_index,
            corpus_sha256=corpus_sha,
            evidence_root=evidence_root,
            comparison_id="collector-selftest",
            expected_commit=commit,
            mode="selftest",
            peak_rss_bytes=1_073_741_824,
            log_bytes=1_048_576,
            disk_bytes=1_048_576,
        )
        collector.prepare(prepared)
        operation_root = run_root / "operations" / "engine_smoke"
        operation_root.mkdir(parents=True)
        child_code = (
            "import time; "
            "time.sleep(0.03); "
            "print('TFLITE_LOAD_OK stage=allocate_tensors inputs=1 outputs=1 tensors=1 threads=1'); "
            "print('TFLITE_ACCESS_OK tensors=1 constants=0 constant_bytes=0')"
        )
        command = {
            "argv": [str(Path(sys.executable).resolve(strict=True)), "-c", child_code],
            "cwd": str(root),
            "allowed_env": {},
        }
        (operation_root / "command.json").write_bytes(canonical(command))
        ready_read_fd, ready_write_fd = os.pipe()
        supervisor = subprocess.Popen(
            [
                sys.executable,
                "-B",
                str(SCRIPTS / "collect_tflite_evidence.py"),
                "_supervise",
                "--run-root",
                str(run_root),
                "--operation",
                "engine_smoke",
                "--sample-seconds",
                "0.01",
                "--ready-fd",
                str(ready_write_fd),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            pass_fds=(ready_write_fd,),
            close_fds=True,
        )
        os.close(ready_write_fd)
        try:
            collector._wait_for_supervisor_ready(supervisor, ready_read_fd)
        finally:
            os.close(ready_read_fd)
        if supervisor.wait() != 0 or not (operation_root / "operation.json").is_file():
            raise AssertionError("selftest supervisor did not preserve raw operation evidence")
        raw_operation = json.loads(
            (operation_root / "operation.json").read_text(encoding="utf-8")
        )
        artifact_paths = {row["path"] for row in raw_operation["artifacts"]}
        if raw_operation["target_api_calls"] != 1 or any(
            path.startswith("child-result") for path in artifact_paths
        ):
            raise AssertionError("supervisor trusted a child result instead of raw log markers")
        controller = {
            "schema_version": "tflite-operation-controller-v1",
            "state": "running",
            "operation": "engine_smoke",
            "supervisor_pid": os.getpid(),
            "supervisor_start_ticks": collector.process_start_ticks(os.getpid()),
            "operation_root": str(operation_root),
            "command_sha256": hashlib.sha256(canonical(command)).hexdigest(),
            "started_utc": "2026-10-22T00:00:00Z",
        }
        (operation_root / "controller.json").write_bytes(canonical(controller))
        before = {
            path.relative_to(run_root).as_posix(): (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in run_root.rglob("*")
            if path.is_file()
        }
        output = io.StringIO()
        with redirect_stdout(output):
            status_rc = collector.status(
                argparse.Namespace(run_root=run_root, operation="engine_smoke")
            )
        after = {
            path.relative_to(run_root).as_posix(): (path.stat().st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in run_root.rglob("*")
            if path.is_file()
        }
        if status_rc != 0 or '"state": "running"' not in output.getvalue() or before != after:
            raise AssertionError("status was not a read-only supervisor identity check")
        try:
            collector.soak_start(
                argparse.Namespace(
                    run_root=run_root,
                    command=operation_root / "command.json",
                    operation="engine_smoke",
                    sample_seconds=0.01,
                )
            )
        except collector.EvidenceError as error:
            if "selftest" not in str(error):
                raise AssertionError(f"wrong selftest start refusal: {error}") from error
        else:
            raise AssertionError("selftest run root started a qualifying operation")
        model.write_bytes(b"mutated-fixture-model")
        try:
            collector.read_prepare(run_root, recheck=True)
        except collector.EvidenceError as error:
            if "corpus" not in str(error):
                raise AssertionError(f"wrong corpus mutation refusal: {error}") from error
        else:
            raise AssertionError("collector accepted a changed prepared corpus")


def supervisor_readiness_is_confirmed_before_start_returns() -> None:
    collector = load("tflite_evidence_collector_readiness", SCRIPTS / "collect_tflite_evidence.py")
    read_fd, write_fd = os.pipe()

    class RunningSupervisor:
        @staticmethod
        def poll() -> None:
            return None

    def publish_ready() -> None:
        time.sleep(0.05)
        os.write(write_fd, b"READY\n")
        os.close(write_fd)

    publisher = threading.Thread(target=publish_ready)
    publisher.start()
    started = time.monotonic()
    try:
        collector._wait_for_supervisor_ready(RunningSupervisor(), read_fd, timeout=1.0)
    finally:
        os.close(read_fd)
        publisher.join()
    if time.monotonic() - started < 0.04:
        raise AssertionError("collector returned before the supervisor installed signal handlers")


CASES = (
    ("valid raw operation is derived as pass", valid_raw_operation_is_accepted),
    ("tampered raw operation is refused", tampered_raw_operation_is_rejected),
    ("short operation is refused", short_operation_is_rejected),
    ("zero target API operation is refused", zero_api_operation_is_rejected),
    ("residual process is refused", residual_process_is_rejected),
    ("corpus mutation is refused", corpus_mutation_is_rejected),
    ("wrong commit is refused", wrong_commit_is_rejected),
    ("wrong profile is refused", wrong_profile_is_rejected),
    ("wrong soak binary role is refused", wrong_soak_binary_role_is_rejected),
    ("performance CLI runs workload directly", collector_performance_cli_runs_workload),
    (
        "memory controller is enabled for private sample leaves",
        memory_controller_is_enabled_for_private_sample_leaves,
    ),
    (
        "read-only cgroup limit still permits peak collection",
        read_only_cgroup_limit_still_collects_peak,
    ),
    (
        "performance builder selftest stays nonqualifying",
        collector_builds_nonqualifying_selftest_observations,
    ),
    ("zero-byte artifact metadata is preserved", zero_byte_artifact_is_preserved),
    ("runner accepts explicit Q10/Q11 bundles", runner_advertises_explicit_bundles),
    ("complete bundle is revalidated", complete_bundle_is_revalidated),
    ("Q10 bundle cannot satisfy Q11", q10_bundle_cannot_satisfy_q11),
    ("complete Q11 bundle is revalidated", complete_q11_bundle_is_revalidated),
    ("qualification task revalidates bundle", qualification_task_revalidates_bundle),
    ("qualification runner pins complete bundle", qualification_runner_pins_complete_bundle),
    ("identity inventory above 64 fails closed", identity_limit_fails_closed),
    ("partial index is refused", partial_index_is_rejected),
    ("existing destination is immutable", overwrite_is_rejected),
    ("bundle symlink is refused", bundle_symlink_is_rejected),
    ("selftest cannot qualify", selftest_bundle_is_rejected),
    ("collector state selftest stays nonqualifying", collector_state_machine_selftest_is_nonqualifying),
    (
        "supervisor readiness is confirmed before start returns",
        supervisor_readiness_is_confirmed_before_start_returns,
    ),
)


def main() -> int:
    checks = Checks()
    for label, function in CASES:
        checks.run(label, function)
    print(f"[tflite-evidence] pass={checks.passed} fail={checks.failed}")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
