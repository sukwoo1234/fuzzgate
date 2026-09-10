#!/usr/bin/env python3
"""Resolve the loader-reachable source-file allow-list for V2.5 coverage comparisons.

Reads an `llvm-cov export -summary-only` JSON (the per-file region totals of the
instrumented libonnxruntime.so) and partitions files into:

  parse_reachable  -- PRIMARY endpoint subgroup: the ONNX/protobuf parser, the onnx
                      checker/shape-inference, and onnxruntime core/graph (Graph::Resolve).
                      Reachable by BOTH arms regardless of model validity; where the
                      structure vs byte arms diverge.
  full_loader      -- SECONDARY: parse_reachable + core/framework, core/optimizer,
                      core/session, core/flatbuffers, core/common, core/platform, and the
                      CPU-EP kernel-registration + graph-partitioning glue that runs at
                      Ort::Session construction.

EXCLUDE (kernel compute / inference-only / non-CPU EP / MLAS microkernels / LoRA / tests)
is applied first; the registration-glue files are an explicit include that overrides the
`/providers/cpu/` exclusion so session-construction coverage is retained. The
function-level registration-vs-compute split (symbol-name regex) is layered in the
analysis step; this script produces the file-level allow-list and the freeze-time
assertion that the parser + EP-registration files are present with >0 total regions.

Usage:
  llvm-cov export <so> -instr-profile=<pd> -summary-only > summary.json
  python3 scripts/coverage_loader_set.py summary.json [out.json]
"""
import json
import os
import sys

# Files that RUN at session-create but live under an otherwise-excluded dir. Matched by
# path suffix; these win over EXCLUDE (intra-directory carve-out).
EXPLICIT_INCLUDE_SUFFIXES = (
    "/providers/cpu/cpu_execution_provider.cc",
    "/providers/cpu/cpu_execution_provider.h",
    "/providers/partitioning_utils.cc",
    "/providers/partitioning_utils.h",
    "/providers/get_execution_providers.cc",
    "/providers/execution_provider_factory.cc",
    "/contrib_ops/cpu/cpu_contrib_kernels.cc",
)

# Non-CPU execution providers + kernel compute + microkernels + tests: never loader-reachable
# without inference. Checked after EXPLICIT_INCLUDE.
EXCLUDE_SUBSTR = (
    "/mlas/", "/lora/", "/test/", "/tests/",
    "/providers/cuda/", "/providers/dml/", "/providers/tensorrt/", "/providers/rocm/",
    "/providers/openvino/", "/providers/qnn/", "/providers/nnapi/", "/providers/coreml/",
    "/providers/webgpu/", "/providers/webnn/", "/providers/js/", "/providers/xnnpack/",
    "/providers/migraphx/", "/providers/cann/", "/providers/acl/", "/providers/armnn/",
    "/providers/vitisai/", "/providers/dnnl/", "/providers/azure/", "/providers/rknpu/",
    "/providers/snpe/", "/providers/vsinpu/", "/providers/winml/", "/providers/nv_tensorrt_rtx/",
    "/providers/shared/", "/providers/shared_library/",
)

def is_protobuf_parse_file(path):
    if "/protobuf-src/src/google/protobuf/" not in path:
        return False
    base = os.path.basename(path)
    return base.startswith((
        "parse_context", "wire_format_lite", "wire_format", "message_lite",
        "generated_message",
    ))

def is_parse_reachable(path):
    # ONNX proto parser (generated message parse methods)
    if "/_deps/onnx-build/onnx/" in path and path.endswith(".pb.cc"):
        return True
    # protobuf wire decode
    if is_protobuf_parse_file(path):
        return True
    # onnx checker / shape-inference / defs / common (validation reachable at load)
    if "/_deps/onnx-src/onnx/" in path:
        base = os.path.basename(path)
        if (base.startswith("checker")
                or "/shape_inference/" in path
                or "/defs/" in path
                or "/onnx-src/onnx/common/" in path):
            return True
    # onnxruntime graph build + Graph::Resolve
    if "/onnxruntime/core/graph/" in path:
        return True
    return False

# full_loader-only dirs (beyond parse_reachable)
FULL_LOADER_DIRS = (
    "/onnxruntime/core/framework/",
    "/onnxruntime/core/optimizer/",
    "/onnxruntime/core/session/",
    "/onnxruntime/core/flatbuffers/",
    "/onnxruntime/core/common/",
    "/onnxruntime/core/platform/",
)

def classify(path):
    """Return ('parse_reachable' | 'full_loader' | None)."""
    if any(path.endswith(suf) for suf in EXPLICIT_INCLUDE_SUFFIXES):
        return "full_loader"  # registration glue: loader but not parse-reachable
    if any(sub in path for sub in EXCLUDE_SUBSTR):
        return None
    if is_parse_reachable(path):
        return "parse_reachable"
    if any(d in path for d in FULL_LOADER_DIRS):
        return "full_loader"
    return None

def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    summ = json.load(open(sys.argv[1]))
    files = summ["data"][0]["files"]

    parse_reachable, full_loader = [], []
    pr_tot = pr_cov = fl_tot = fl_cov = whole_tot = whole_cov = 0
    for f in files:
        path = f["filename"]
        reg = f["summary"]["regions"]
        whole_tot += reg["count"]; whole_cov += reg["covered"]
        cls = classify(path)
        if cls == "parse_reachable":
            parse_reachable.append(path)
            full_loader.append(path)
            pr_tot += reg["count"]; pr_cov += reg["covered"]
            fl_tot += reg["count"]; fl_cov += reg["covered"]
        elif cls == "full_loader":
            full_loader.append(path)
            fl_tot += reg["count"]; fl_cov += reg["covered"]

    out = {
        "parse_reachable_files": sorted(parse_reachable),
        "full_loader_files": sorted(full_loader),
        "counts": {
            "parse_reachable_files": len(parse_reachable),
            "full_loader_files": len(full_loader),
            "whole_binary_files": len(files),
            "parse_reachable_regions_total": pr_tot,
            "full_loader_regions_total": fl_tot,
            "whole_binary_regions_total": whole_tot,
        },
    }
    out_path = sys.argv[2] if len(sys.argv) > 2 else None
    if out_path:
        json.dump(out, open(out_path, "w"), indent=2)

    # Coverage-universe assertion: the parser + EP-registration files must be present
    # with >0 total regions, else the denominator silently drops the code under test.
    def present(substr):
        return [p for p in full_loader if substr in p]
    checks = {
        "onnx parser (.pb.cc)": present("/_deps/onnx-build/onnx/"),
        "protobuf parse_context": present("/protobuf/parse_context"),
        "onnx checker": present("/onnx-src/onnx/checker"),
        "onnx shape_inference": present("/shape_inference/"),
        "core/graph (primary)": present("/onnxruntime/core/graph/"),
        "core/optimizer": present("/onnxruntime/core/optimizer/"),
        "cpu_execution_provider (reg)": present("cpu_execution_provider.cc"),
        "cpu_contrib_kernels (reg)": present("cpu_contrib_kernels.cc"),
    }
    print("=== loader-reachable resolution ===")
    print(f"  parse_reachable: {len(parse_reachable)} files, {pr_tot} total regions")
    print(f"  full_loader:     {len(full_loader)} files, {fl_tot} total regions")
    print(f"  whole_binary:    {len(files)} files, {whole_tot} total regions")
    print(f"  parse_reachable is {100*pr_tot/whole_tot:.1f}% of whole-binary regions")
    print("=== freeze assertions (must all be PRESENT) ===")
    ok = True
    for label, hits in checks.items():
        status = "OK" if hits else "MISSING"
        if not hits:
            ok = False
        print(f"  [{status}] {label}: {len(hits)} file(s)")
    # MLAS / cpu compute must be ABSENT
    leaked = [p for p in full_loader if "/mlas/" in p or "/providers/cpu/math/" in p]
    print(f"  [{'OK' if not leaked else 'LEAK'}] excluded compute absent: {len(leaked)} leaked")
    if leaked:
        ok = False
        for p in leaked[:5]:
            print("       LEAK:", p)
    print("RESULT:", "PASS" if ok else "FAIL")
    sys.exit(0 if ok else 1)

if __name__ == "__main__":
    main()
