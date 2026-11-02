#!/usr/bin/env python3
"""Regression entry point for the HDF-05 instrumentation evidence gate."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys


def main() -> int:
    project = Path(__file__).resolve().parent.parent
    checker = project / "scripts/check_hdf5_instrumentation.py"
    required = (
        project / "scripts/build_hdf5_guided.sh",
        project / "scripts/build_coverage_hdf5.sh",
        project / "scripts/run_coverage_hdf5.sh",
        project / "scripts/lib/hdf5_variant_build.sh",
    )
    missing = [str(path.relative_to(project)) for path in (checker, *required) if not path.is_file()]
    if missing:
        print(
            "[hdf5-instrumentation-test] fail: missing HDF-05 implementation: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1

    completed = subprocess.run(
        [sys.executable, "-B", str(checker), "--selftest"],
        cwd=project,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    expected = "[hdf5-instrumentation-selftest] pass=9 fail=0"
    if completed.returncode != 0 or expected not in completed.stdout.splitlines():
        print(
            "[hdf5-instrumentation-test] fail: checker selftest did not prove all RED controls\n"
            f"rc={completed.returncode}\nstdout={completed.stdout}\nstderr={completed.stderr}",
            file=sys.stderr,
        )
        return 1

    print("[hdf5-instrumentation-test] pass=1 fail=0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
