#!/usr/bin/env python3
"""Validate coverage records for the BASE-02 ONNX malformed fixtures."""

import json
from pathlib import Path
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_onnx_parse_labels.py <harness-records.jsonl>", file=sys.stderr)
        return 2
    records = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
    by_name = {Path(record["path"]).name: record for record in records}
    expected = {
        "a_trunc32.onnx",
        "b_zero128.onnx",
        "c_random128.onnx",
        "d_min.onnx",
        "e_onebyte.onnx",
    }
    if set(by_name) != expected or len(records) != len(expected):
        print("unexpected fixture set or duplicate records", file=sys.stderr)
        return 1
    for name in sorted(expected - {"d_min.onnx"}):
        record = by_name[name]
        if (
            "protobuf parsing failed" not in record["error"].casefold()
            or record["session_ok"] is not False
            or record["parse_ok"] is not False
        ):
            print(f"wire parse failure misclassified: {name}: {record}", file=sys.stderr)
            return 1
    minimum = by_name["d_min.onnx"]
    if minimum["session_ok"] is not False or minimum["parse_ok"] is not True:
        print(f"post-parse rejection misclassified: {minimum}", file=sys.stderr)
        return 1
    print("ONNX parse labels: 4 wire failures and 1 post-parse rejection classified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
