#!/usr/bin/env python3
"""Fast OVI-07 negative controls; never collect real Q10/Q11 evidence."""

from __future__ import annotations

import importlib.util
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"


def load(name: str, path: Path) -> Any:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"could not load {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


class Checks:
    def __init__(self) -> None:
        self.passed = 0
        self.failed = 0

    def run(self, label: str, function: Callable[[], None]) -> None:
        try:
            function()
        except Exception as error:
            self.failed += 1
            print(f"[openvino-qualification] fail: {label}: {error}", file=sys.stderr)
        else:
            self.passed += 1
            print(f"[openvino-qualification] ok: {label}")


def openvino_profile_shape_is_supported() -> None:
    baseline = load("openvino_qualification_baseline", SCRIPTS / "measure_format_baseline.py")
    profile = baseline._valid_document()["identity"]["baseline_profile"]
    profile["target_id"] = "openvino-ir"
    profile["format_revision"] = "ir-v11"
    profile["loader_id"] = "openvino-ir-frontend"
    profile["loader_version"] = "2026.4.1"
    profile["input_kind"] = {
        "kind": "fzb1",
        "extensions": ["fzb"],
        "subformats": ["model.bin", "model.xml"],
    }
    profile["depth"] = "read-validate-constants"
    profile["engine_capabilities"] = [{
        "backend": "local-harness",
        "binary_role": "replay",
        "required_mode": "native",
        "instrumentation_scope": "openvino-core+ir-frontend",
    }]
    profile["coverage_scope"] = {
        "unit": "source-line",
        "include_sources": ["src/core", "src/frontends/ir"],
        "exclude_sources": [],
    }
    baseline._validate_target_profile_shape(profile, "OpenVINO profile")


def target_neutral_operation_schema_is_supported() -> None:
    baseline = load("openvino_operation_baseline", SCRIPTS / "measure_format_baseline.py")
    document = baseline._valid_document()
    identity = document["identity"]
    raw = {
        "schema_version": "format-v7-operation-v1",
        "operation": "actual_parser_performance",
        "mode": "real",
        "target_id": identity["fixed"]["target_id"],
        "tool_commit": identity["candidate_tool_commit"],
        "dirty_diff_sha256": identity["candidate_dirty_diff_sha256"],
        "profile_sha256": identity["candidate_profile_sha256"],
        "command": identity["candidate_command"],
        "command_sha256": identity["candidate_command_sha256"],
        "corpus_before_sha256": identity["fixed"]["corpus_sha256"],
        "corpus_after_sha256": identity["fixed"]["corpus_sha256"],
        "started_utc": "2026-10-25T00:00:00Z",
        "ended_utc": "2026-10-25T00:01:00Z",
        "duration_seconds": 60.0,
        "target_api_calls": 1,
        "worker_count": 1,
        "expected_outcome": "completed",
        "observed_outcome": "completed",
        "exit_code": 0,
        "signal": None,
        "residual_processes": 0,
        "resource_samples": [
            {
                "elapsed_seconds": 0.0,
                "peak_rss_bytes": 1,
                "log_bytes": 1,
                "disk_bytes": 1,
                "owned_processes": 1,
            },
            {
                "elapsed_seconds": 60.0,
                "peak_rss_bytes": 1,
                "log_bytes": 1,
                "disk_bytes": 1,
                "owned_processes": 0,
            },
        ],
        "budgets": {
            "peak_rss_bytes": identity["fixed"]["memory_limit_bytes"],
            "log_bytes": 1_048_576,
            "disk_bytes": 1_048_576,
        },
        "artifacts": [{"path": "raw/run.log", "sha256": "a" * 64, "size_bytes": 1}],
    }
    baseline._validate_operation_raw(
        raw,
        name="actual_parser_performance",
        identity=identity,
    )


def openvino_evidence_contract_exists() -> None:
    collector = load("openvino_qualification_collector", SCRIPTS / "collect_tflite_evidence.py")
    contract = collector.target_contract("openvino-ir")
    if contract.target_id != "openvino-ir" or contract.api_event != "ReadValidateConstants":
        raise AssertionError("OpenVINO evidence contract has the wrong identity")


def bundle_rejection_is_not_an_ir_frontend_call() -> None:
    collector = load("openvino_marker_collector", SCRIPTS / "collect_tflite_evidence.py")
    contract = collector.target_contract("openvino-ir")
    bundle = b"OPENVINO_LOAD_REJECT stage=bundle reason=missing-bin\n"
    frontend = b"OPENVINO_LOAD_REJECT stage=frontend reason=invalid-ir\n"
    accepted = b"OPENVINO_LOAD_OK stage=read_validate_constants nodes=4\n"
    observed = tuple(len(contract.load_marker.findall(value)) for value in (bundle, frontend, accepted))
    if observed != (0, 1, 1):
        raise AssertionError(f"wrong OpenVINO target-call counts: {observed}")


def ovi07_entrypoints_exist() -> None:
    required = (
        "build_openvino_qualification_profile.py",
        "build_openvino_performance_corpus.py",
        "collect_openvino_evidence.py",
        "openvino_qualification_task.py",
        "qualify_openvino.py",
        "run_openvino_qualification.py",
    )
    missing = [name for name in required if not (SCRIPTS / name).is_file()]
    if missing:
        raise AssertionError(f"missing OVI-07 entrypoints: {missing}")


def collector_help_names_openvino() -> None:
    completed = subprocess.run(
        [sys.executable, "-B", str(SCRIPTS / "collect_openvino_evidence.py"), "--help"],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        raise AssertionError(
            f"collector help failed rc={completed.returncode}: {output[-500:]}"
        )
    if "OpenVINO Q10/Q11 evidence" not in output or "TFL Q10/Q11 evidence" in output:
        raise AssertionError("collector help does not identify the OpenVINO evidence contract")


def collector_early_failure_names_openvino() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPTS / "collect_openvino_evidence.py"),
            "prepare",
            "--run-root",
            "/does-not-exist/openvino-run",
            "--profile",
            "/does-not-exist/openvino-profile.json",
            "--replay",
            "/does-not-exist/openvino-replay",
            "--corpus-index",
            "/does-not-exist/openvino-corpus.json",
            "--corpus-sha256",
            "0" * 64,
            "--evidence-root",
            "/does-not-exist/openvino-evidence",
            "--comparison-id",
            "openvino-early-failure",
            "--expected-commit",
            "0" * 40,
            "--log-bytes",
            "1",
            "--disk-bytes",
            "1",
        ],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 1:
        raise AssertionError(f"collector early failure returned rc={completed.returncode}")
    if "[openvino-evidence] fail:" not in completed.stderr:
        raise AssertionError(
            f"collector used the wrong failure label: {completed.stderr.strip()}"
        )


def qualification_profile_binds_ovi06_and_ovi05() -> None:
    builder = load(
        "openvino_qualification_profile_builder",
        SCRIPTS / "build_openvino_qualification_profile.py",
    )
    with tempfile.TemporaryDirectory(prefix="openvino-profile-selftest-") as temporary:
        root = Path(temporary).resolve()
        replay = root / "replay"
        fuzzer = root / "openvino_ir_loader_fuzzer"
        loader = root / "libtool_openvino_loader.a"
        core = root / "libopenvino.so"
        frontend = root / "libopenvino_ir_frontend.so"
        for path, payload in (
            (replay, b"replay\n"),
            (fuzzer, b"fuzzer\n"),
            (loader, b"loader\n"),
            (core, b"core\n"),
            (frontend, b"frontend\n"),
        ):
            path.write_bytes(payload)
            path.chmod(0o700)

        def identity(path: Path) -> dict[str, str]:
            return {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        execution = {
            "schema_version": "1",
            "target_id": "openvino-ir",
            "loader_version": "2026.4.1",
            "source_artifacts": [builder.PRIMARY_SOURCE],
            "patches": [],
            "input_kind": {
                "kind": "fzb1",
                "extensions": ["fzb"],
                "subformats": ["model.bin", "model.xml"],
            },
            "depth": "read-validate-constants",
            "engine_capabilities": [builder.CAPABILITY],
            "binaries": [
                {
                    "role": "replay",
                    **identity(replay),
                    "argv": ["{input}"],
                    "linked_libraries": [],
                }
            ],
        }
        guided = {
            "schema_version": "openvino-ir-instrumentation-v1",
            "target": "openvino-ir",
            "target_version": "2026.4.1",
            "mode": "guided",
            "components": {
                "core": identity(core),
                "ir_frontend": identity(frontend),
                "driver": identity(fuzzer),
            },
        }
        execution_path = root / "execution.json"
        guided_path = root / "guided.json"
        execution_path.write_text(json.dumps(execution), encoding="utf-8")
        guided_path.write_text(json.dumps(guided), encoding="utf-8")
        profile = builder.build_profile(execution_path, guided_path)
        roles = {row["role"] for row in profile["binaries"]}
        if roles != {"replay", "fuzzer"}:
            raise AssertionError(f"unexpected qualification roles: {sorted(roles)}")
        fuzzer_row = next(row for row in profile["binaries"] if row["role"] == "fuzzer")
        if fuzzer_row["linked_libraries"][-1] != identity(loader):
            raise AssertionError("guided common-loader identity was not bound")
        guided["components"]["driver"]["sha256"] = "0" * 64
        guided_path.write_text(json.dumps(guided), encoding="utf-8")
        try:
            builder.build_profile(execution_path, guided_path)
        except builder.ProfileError as error:
            if "identity mismatch" not in str(error):
                raise
        else:
            raise AssertionError("tampered guided driver identity was accepted")


def performance_corpus_preserves_api_boundary() -> None:
    builder = load(
        "openvino_performance_corpus_builder",
        SCRIPTS / "build_openvino_performance_corpus.py",
    )
    collector = load(
        "openvino_corpus_collector", SCRIPTS / "collect_tflite_evidence.py"
    )
    with tempfile.TemporaryDirectory(prefix="openvino-corpus-selftest-") as temporary:
        root = Path(temporary).resolve()
        fixtures = root / "fixtures"
        fixtures.mkdir()
        rows = []
        for index, (name, (outcome, purpose)) in enumerate(builder.FIXTURES.items()):
            payload = f"fixture-{index}\n".encode()
            (fixtures / name).write_bytes(payload)
            rows.append(
                {
                    "name": name,
                    "expected_outcome": outcome,
                    "purpose": purpose,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
        fixture_index = fixtures / "index.json"
        fixture_index.write_text(
            json.dumps(
                {
                    "schema_version": "openvino-ir-fixture-index-v1",
                    "bundle_format": "FZB1",
                    "openvino_source": {
                        "version": builder.VERSION,
                        "resolved_commit": builder.RESOLVED_COMMIT,
                        "archive_sha256": builder.ARCHIVE_SHA256,
                    },
                    "fixtures": rows,
                }
            ),
            encoding="utf-8",
        )
        output = root / "performance-corpus"
        index_path, aggregate = builder.build(fixture_index, output)
        document, _payload = collector._corpus_document(
            {"target_id": "openvino-ir", "corpus_index": str(index_path)}
        )
        missing = next(
            row for row in document["inputs"] if row["path"] == "missing-bin.fzb"
        )
        accepted = [
            row for row in document["inputs"] if row["expected_outcome"] == "accepted"
        ]
        if (
            missing["target_api_stage"] != "pre-parser-reject"
            or missing["required_api_events"]
        ):
            raise AssertionError("wrapper rejection crossed the target API boundary")
        if [row["throughput_order_index"] for row in accepted] != [1, 2, 3]:
            raise AssertionError("accepted performance order is not deterministic")
        observed, _identities = collector.audit_corpus(index_path)
        if observed != aggregate:
            raise AssertionError("corpus aggregate identity disagrees with collector")
        try:
            builder.build(fixture_index, output)
        except builder.CorpusError as error:
            if "already exists" not in str(error):
                raise
        else:
            raise AssertionError("performance corpus was overwritten")


def qualification_assembler_negative_controls() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPTS / "check_tflite_qualification_selftest.py"),
            "--assembler",
            str(SCRIPTS / "qualify_openvino.py"),
            "--target-id",
            "openvino-ir",
        ],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0 or (
        "[openvino-qualification] pass=9 fail=0" not in completed.stdout
    ):
        raise AssertionError(
            f"assembler controls failed rc={completed.returncode}: "
            f"{(completed.stdout + completed.stderr)[-1000:]}"
        )


def main() -> int:
    checks = Checks()
    checks.run("FND-05 accepts the OpenVINO target/depth", openvino_profile_shape_is_supported)
    checks.run("V7 raw operation schema is target-neutral", target_neutral_operation_schema_is_supported)
    checks.run("collector exposes the OpenVINO API-marker contract", openvino_evidence_contract_exists)
    checks.run(
        "bundle rejection is not counted as an IR frontend API call",
        bundle_rejection_is_not_an_ir_frontend_call,
    )
    checks.run("OVI-07 qualification entrypoints exist", ovi07_entrypoints_exist)
    checks.run("collector help names the OpenVINO contract", collector_help_names_openvino)
    checks.run(
        "collector early failures retain the OpenVINO contract",
        collector_early_failure_names_openvino,
    )
    checks.run(
        "qualification profile binds OVI-06 replay and OVI-05 guided identities",
        qualification_profile_binds_ovi06_and_ovi05,
    )
    checks.run(
        "performance corpus preserves the wrapper/target API boundary",
        performance_corpus_preserves_api_boundary,
    )
    checks.run(
        "qualification assembler rejects partial, dirty, mixed, and tampered evidence",
        qualification_assembler_negative_controls,
    )
    print(f"[openvino-qualification] pass={checks.passed} fail={checks.failed}")
    return 0 if checks.failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
