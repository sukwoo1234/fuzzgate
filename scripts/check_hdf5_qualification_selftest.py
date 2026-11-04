#!/usr/bin/env python3
"""Negative controls for the HDF-07 qualification pipeline."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from typing import Any, Callable


ROOT = Path(__file__).resolve().parent.parent
SCRIPTS = ROOT / "scripts"
REQUIRED_ENTRYPOINTS = (
    "build_hdf5_qualification_profile.py",
    "build_hdf5_performance_corpus.py",
    "collect_hdf5_evidence.py",
    "hdf5_qualification_task.py",
    "qualify_hdf5.py",
    "run_hdf5_qualification.py",
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError(f"could not load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def profile_shape_is_supported() -> None:
    baseline = load("hdf5_qualification_baseline", SCRIPTS / "measure_format_baseline.py")
    profile = baseline._valid_document()["identity"]["baseline_profile"]
    profile.update(
        {
            "target_id": "hdf5-weights",
            "format_revision": "hdf5-2.2.0-numeric-datasets-v1",
            "loader_id": "hdf5-file-image-numeric-dataset",
            "loader_version": "2.2.0",
            "input_kind": {
                "kind": "single",
                "extensions": ["h5"],
                "subformats": ["numeric-dataset"],
            },
            "depth": "read-numeric-datasets",
            "engine_capabilities": [
                {
                    "backend": "local-harness",
                    "binary_role": "replay",
                    "required_mode": "native",
                    "instrumentation_scope": "hdf5-core+high-level-file-image",
                }
            ],
            "coverage_scope": {
                "unit": "source-line",
                "include_sources": [
                    "src/H5Fio.c",
                    "src/H5Dio.c",
                    "src/H5Dchunk.c",
                    "src/H5Z.c",
                    "src/H5Zshuffle.c",
                    "src/H5Zfletcher32.c",
                ],
                "exclude_sources": [],
            },
        }
    )
    baseline._validate_target_profile_shape(profile, "HDF5 profile")


def marker_contract_distinguishes_results() -> None:
    collector = load("hdf5_marker_collector", SCRIPTS / "collect_tflite_evidence.py")
    contract = collector.target_contract("hdf5-weights")
    accepted = (
        b"HDF5_RESULT classification=accepted stage=complete reason=loaded\n"
        b"HDF5_ACCESS_OK datasets=1 attributes=0 h5dread_calls=1\n"
    )
    unsupported = (
        b"HDF5_RESULT classification=unsupported_feature "
        b"stage=filter_policy reason=filter_unavailable_for_decode\n"
    )
    malformed = (
        b"HDF5_RESULT classification=target_reject "
        b"stage=H5LTopen_file_image reason=file_rejected\n"
    )
    observed = (
        bool(contract.load_ok_marker.search(accepted)),
        bool(contract.access_ok_marker.search(accepted)),
        bool(contract.load_reject_marker.search(unsupported)),
        bool(contract.load_reject_marker.search(malformed)),
        len(contract.load_marker.findall(unsupported)),
    )
    if observed != (True, True, True, True, 1):
        raise AssertionError(f"wrong HDF5 result classification: {observed}")


def collector_cli_names_hdf5() -> None:
    completed = subprocess.run(
        [sys.executable, "-B", str(SCRIPTS / "collect_hdf5_evidence.py"), "--help"],
        cwd=ROOT,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0 or "HDF5 Q10/Q11 evidence" not in output:
        raise AssertionError(f"collector help has the wrong contract: {output[-500:]}")


def collector_early_failure_names_hdf5() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPTS / "collect_hdf5_evidence.py"),
            "prepare",
            "--run-root",
            "/does-not-exist/hdf5-run",
            "--profile",
            "/does-not-exist/hdf5-profile.json",
            "--replay",
            "/does-not-exist/hdf5-replay",
            "--corpus-index",
            "/does-not-exist/hdf5-corpus.json",
            "--corpus-sha256",
            "0" * 64,
            "--evidence-root",
            "/does-not-exist/hdf5-evidence",
            "--comparison-id",
            "hdf5-early-failure",
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
    if completed.returncode != 1 or "[hdf5-evidence] fail:" not in completed.stderr:
        raise AssertionError(
            f"collector early failure used the wrong identity: {completed.stderr[-500:]}"
        )


def qualification_profile_binds_hdf06_and_hdf05() -> None:
    builder = load(
        "hdf5_qualification_profile_builder",
        SCRIPTS / "build_hdf5_qualification_profile.py",
    )
    with tempfile.TemporaryDirectory(prefix="hdf5-profile-selftest-") as temporary:
        root = Path(temporary).resolve()
        files = {
            name: root / name
            for name in (
                "replay",
                "hdf5_loader_fuzzer",
                "libtool_hdf5_loader.a",
                "libhdf5.so",
                "libhdf5_hl.so",
            )
        }
        for name, path in files.items():
            path.write_bytes((name + "\n").encode())
            path.chmod(0o700)

        def identity(path: Path) -> dict[str, str]:
            return {
                "path": str(path),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }

        build = {
            "schema_version": "hdf5-weights-build-profile-v1",
            "target_id": "hdf5-weights",
            "target_version": builder.VERSION,
            "status": "provisioned",
            "execution_profile_ready": False,
            "source_artifacts": [{"name": "hdf5", **builder.PRIMARY_SOURCE}],
            "patches": [],
            "filter_contract": builder.FILTER_CONTRACT,
        }
        build_path = root / "build-profile.json"
        build_path.write_text(json.dumps(build), encoding="utf-8")
        execution = {
            "schema_version": "1",
            "target_id": "hdf5-weights",
            "loader_version": builder.VERSION,
            "source_artifacts": [builder.PRIMARY_SOURCE],
            "patches": [],
            "input_kind": builder.INPUT_KIND,
            "depth": "read-numeric-datasets",
            "engine_capabilities": [builder.CAPABILITY],
            "binaries": [
                {
                    "role": "replay",
                    **identity(files["replay"]),
                    "argv": ["{input}"],
                    "linked_libraries": [],
                }
            ],
        }
        guided = {
            "schema_version": "hdf5-weights-instrumentation-v1",
            "target": "hdf5-weights",
            "target_version": builder.VERSION,
            "mode": "guided",
            "normal_build_profile": identity(build_path),
            "components": {
                "core": identity(files["libhdf5.so"]),
                "high_level": identity(files["libhdf5_hl.so"]),
                "driver": identity(files["hdf5_loader_fuzzer"]),
            },
        }
        execution_path = root / "execution.json"
        guided_path = root / "guided.json"
        execution_path.write_text(json.dumps(execution), encoding="utf-8")
        guided_path.write_text(json.dumps(guided), encoding="utf-8")
        profile = builder.build_profile(execution_path, guided_path, build_path)
        if [row["role"] for row in profile["binaries"]] != ["replay", "fuzzer"]:
            raise AssertionError("qualification profile has the wrong binary roles")
        fuzzer = profile["binaries"][1]
        if fuzzer["linked_libraries"][-1] != identity(files["libtool_hdf5_loader.a"]):
            raise AssertionError("guided common-loader identity was not bound")
        guided["components"]["driver"]["sha256"] = "0" * 64
        guided_path.write_text(json.dumps(guided), encoding="utf-8")
        try:
            builder.build_profile(execution_path, guided_path, build_path)
        except builder.ProfileError as error:
            if "identity mismatch" not in str(error):
                raise
        else:
            raise AssertionError("tampered guided driver identity was accepted")


def performance_corpus_preserves_hdf5_boundary() -> None:
    builder = load(
        "hdf5_performance_corpus_builder",
        SCRIPTS / "build_hdf5_performance_corpus.py",
    )
    collector = load("hdf5_corpus_collector", SCRIPTS / "collect_tflite_evidence.py")
    with tempfile.TemporaryDirectory(prefix="hdf5-corpus-selftest-") as temporary:
        root = Path(temporary).resolve()
        fixtures = root / "fixtures"
        fixtures.mkdir()
        rows = []
        for index, (name, (classification, outcome)) in enumerate(
            builder.FIXTURES.items()
        ):
            payload = f"fixture-{index}\n".encode()
            (fixtures / name).write_bytes(payload)
            rows.append(
                {
                    "file": name,
                    "classification": classification,
                    "expected_api_outcome": outcome,
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size_bytes": len(payload),
                }
            )
        manifest = fixtures / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema_version": "hdf5-weights-fixture-manifest-v1",
                    "target_id": "hdf5-weights",
                    "target_version": builder.VERSION,
                    "hdf5_source": {
                        "version": builder.VERSION,
                        "resolved_commit": builder.RESOLVED_COMMIT,
                        "archive_sha256": builder.ARCHIVE_SHA256,
                        "archive_size_bytes": builder.ARCHIVE_SIZE,
                    },
                    "fixtures": rows,
                }
            ),
            encoding="utf-8",
        )
        index_path, aggregate = builder.build(manifest, root / "corpus")
        document, _payload = collector._corpus_document(
            {"target_id": "hdf5-weights", "corpus_index": str(index_path)}
        )
        accepted = [
            row for row in document["inputs"] if row["expected_outcome"] == "accepted"
        ]
        unsupported = next(
            row for row in document["inputs"] if row["path"] == "unsupported-filter.h5"
        )
        if [row["throughput_order_index"] for row in accepted] != [1, 2, 3, 4]:
            raise AssertionError("accepted HDF5 performance order is not deterministic")
        if (
            unsupported["expected_outcome"] != "rejected"
            or unsupported["throughput_order_index"] is not None
            or unsupported["required_api_events"] != ["ReadNumericDatasets"]
        ):
            raise AssertionError("unsupported filter was mislabeled as performance support")
        observed, _identities = collector.audit_corpus(index_path)
        if observed != aggregate:
            raise AssertionError("corpus aggregate identity disagrees with collector")


ADDITIONAL_CHECKS: tuple[tuple[str, Callable[[], None]], ...] = (
    ("FND-05 accepts the HDF5 target/depth", profile_shape_is_supported),
    ("HDF5 result markers preserve accepted/rejected meaning", marker_contract_distinguishes_results),
    ("collector help names the HDF5 contract", collector_cli_names_hdf5),
    ("collector early failure retains the HDF5 identity", collector_early_failure_names_hdf5),
    ("qualification profile binds HDF-06 and HDF-05 identities", qualification_profile_binds_hdf06_and_hdf05),
    ("performance corpus keeps unsupported filters out of support", performance_corpus_preserves_hdf5_boundary),
)


def main() -> int:
    passed = 0
    failed = 0

    for name in REQUIRED_ENTRYPOINTS:
        path = SCRIPTS / name
        if path.is_file():
            passed += 1
            print(f"[hdf5-qualification] ok: entrypoint exists: {name}")
        else:
            failed += 1
            print(
                f"[hdf5-qualification] fail: missing entrypoint: {name}",
                file=sys.stderr,
            )

    try:
        qualifier = load("hdf5_qualification_common", SCRIPTS / "qualify_tflite.py")
        contract = qualifier.HDF5_CONTRACT
        assert contract.target_id == "hdf5-weights"
        assert contract.depth == "read-numeric-datasets"
    except (AttributeError, AssertionError) as error:
        failed += 1
        print(
            f"[hdf5-qualification] fail: common qualifier lacks the HDF5 contract: {error}",
            file=sys.stderr,
        )
    else:
        passed += 1
        print("[hdf5-qualification] ok: common qualifier has the HDF5 contract")

    try:
        collector = load(
            "hdf5_qualification_collector", SCRIPTS / "collect_tflite_evidence.py"
        )
        contract = collector.target_contract("hdf5-weights")
        assert contract.api_event == "ReadNumericDatasets"
    except (collector.EvidenceError if "collector" in locals() else RuntimeError, AssertionError) as error:
        failed += 1
        print(
            f"[hdf5-qualification] fail: evidence collector lacks the HDF5 contract: {error}",
            file=sys.stderr,
        )
    else:
        passed += 1
        print("[hdf5-qualification] ok: evidence collector has the HDF5 contract")

    try:
        scope = load("hdf5_qualification_scope", SCRIPTS / "check_hdf5_scope.py")
        issuer = load("hdf5_qualification_issuer", SCRIPTS / "qualify_hdf5.py")
        target_spec, build_profile, execution_profile = scope.valid_documents()
        build_profile.update(copy.deepcopy(issuer.BUILD_IDENTITY))
        issuer.validate_support_scope(target_spec, build_profile, execution_profile)
    except (AttributeError, AssertionError, RuntimeError) as error:
        failed += 1
        print(
            f"[hdf5-qualification] fail: valid HDF5-only scope was rejected: {error}",
            file=sys.stderr,
        )
    else:
        passed += 1
        print("[hdf5-qualification] ok: valid HDF5-only scope is accepted")

        negative_controls = (
            (
                "unsupported filter cannot be mislabeled supported",
                lambda spec, build, profile: build["filter_contract"].__setitem__(
                    "deflate", "supported"
                ),
            ),
            (
                "Keras target cannot be mislabeled as HDF5",
                lambda spec, build, profile: spec.__setitem__("target_id", "keras-v3"),
            ),
            (
                "Keras loader cannot be issued as HDF5",
                lambda spec, build, profile: profile.__setitem__(
                    "loader_id", "keras-load-model"
                ),
            ),
            (
                "immutable build profile cannot be promoted",
                lambda spec, build, profile: build.__setitem__(
                    "execution_profile_ready", True
                ),
            ),
        )
        for label, mutate in negative_controls:
            candidate_spec = copy.deepcopy(target_spec)
            candidate_build = copy.deepcopy(build_profile)
            candidate_profile = copy.deepcopy(execution_profile)
            mutate(candidate_spec, candidate_build, candidate_profile)
            try:
                issuer.validate_support_scope(
                    candidate_spec, candidate_build, candidate_profile
                )
            except RuntimeError:
                passed += 1
                print(f"[hdf5-qualification] ok: {label}")
            else:
                failed += 1
                print(
                    f"[hdf5-qualification] fail: {label}",
                    file=sys.stderr,
                )

    completed = subprocess.run(
        [
            sys.executable,
            "-B",
            str(SCRIPTS / "check_tflite_qualification_selftest.py"),
            "--assembler",
            str(SCRIPTS / "qualify_hdf5.py"),
            "--target-id",
            "hdf5-weights",
        ],
        cwd=ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    if (
        completed.returncode == 0
        and "[hdf5-qualification] pass=9 fail=0" in completed.stdout.splitlines()
    ):
        passed += 1
        print(
            "[hdf5-qualification] ok: missing, tampered, mixed, and incomplete Q evidence is rejected"
        )
    else:
        failed += 1
        print(
            "[hdf5-qualification] fail: shared evidence negative controls failed",
            file=sys.stderr,
        )

    for label, check in ADDITIONAL_CHECKS:
        try:
            check()
        except Exception as error:
            failed += 1
            print(f"[hdf5-qualification] fail: {label}: {error}", file=sys.stderr)
        else:
            passed += 1
            print(f"[hdf5-qualification] ok: {label}")

    print(f"[hdf5-qualification] pass={passed} fail={failed}")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
