#!/usr/bin/env bash
# FND-02 cross-language FZB1 codec and private-staging contract.
# Writes only below a private mktemp directory.
set -euo pipefail
ulimit -c 0 || true

export LC_ALL=C
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/model-bundle-check-XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); printf '  ok   %s\n' "$*"; }
bad() { FAIL=$((FAIL + 1)); printf '  FAIL %s\n' "$*" >&2; }

for command in python3 rustc sha256sum stat cmp timeout mkfifo; do
  if ! command -v "$command" >/dev/null 2>&1; then
    printf '[model-bundle] fail: required command is unavailable: %s\n' "$command" >&2
    exit 1
  fi
done
if command -v clang++ >/dev/null 2>&1; then
  CXX=clang++
elif command -v g++ >/dev/null 2>&1; then
  CXX=g++
else
  printf '[model-bundle] fail: a C++17 compiler (clang++ or g++) is required\n' >&2
  exit 1
fi

for source in src/model_bundle.rs harnesses/common/model_bundle.h scripts/model_bundle.py; do
  if [[ ! -f "$PROJECT_ROOT/$source" ]]; then
    printf '[model-bundle] fail: required implementation is missing: %s\n' "$source" >&2
    exit 1
  fi
done

cp "$PROJECT_ROOT/src/model_bundle.rs" "$WORK/model_bundle.rs"
cat >"$WORK/rust_probe.rs" <<'RS'
#[allow(dead_code)]
#[path = "model_bundle.rs"]
mod model_bundle;

use std::{env, fs, os::unix::fs::PermissionsExt, process};

fn reject(message: impl std::fmt::Display) -> ! {
    eprintln!("rejected: {message}");
    process::exit(9);
}

fn run() -> Result<(), String> {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let command = args.first().map(String::as_str).ok_or("missing command")?;
    match command {
        "encode" => {
            if args.len() < 3 { return Err("encode needs OUTPUT NAME=PATH...".into()); }
            let mut owned = Vec::new();
            for item in &args[2..] {
                let (name, path) = item.split_once('=').ok_or("entry needs NAME=PATH")?;
                owned.push((name.to_string(), fs::read(path).map_err(|e| e.to_string())?));
            }
            let borrowed = owned.iter().map(|(n, d)| (n.as_str(), d.as_slice())).collect::<Vec<_>>();
            let bytes = model_bundle::encode(&borrowed)?;
            fs::write(&args[1], bytes).map_err(|e| e.to_string())?;
        }
        "list" => {
            if args.len() < 2 { return Err("list needs BUNDLE [ALLOW...]".into()); }
            let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
            let entries = if args.len() == 2 {
                model_bundle::decode(&bytes)?
            } else {
                model_bundle::decode_with_allowlist(
                    &bytes,
                    &args[2..].iter().map(String::as_str).collect::<Vec<_>>(),
                )?
            };
            for entry in entries {
                println!("{}\t{}", entry.name(), entry.data().len());
            }
        }
        "roundtrip" => {
            if args.len() != 3 { return Err("roundtrip needs INPUT OUTPUT".into()); }
            let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
            let entries = model_bundle::decode(&bytes)?;
            let borrowed = entries.iter().map(|e| (e.name(), e.data())).collect::<Vec<_>>();
            fs::write(&args[2], model_bundle::encode(&borrowed)?).map_err(|e| e.to_string())?;
        }
        "stage-check" => {
            if args.len() < 5 { return Err("stage-check needs BUNDLE PARENT NAME ALLOW...".into()); }
            let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
            let original = bytes.clone();
            let allowlist = args[4..].iter().map(String::as_str).collect::<Vec<_>>();
            let entries = model_bundle::decode_with_allowlist(&bytes, &allowlist)?;
            let staged = model_bundle::stage_bundle(
                &bytes,
                std::path::Path::new(&args[2]),
                &args[3],
                &allowlist,
            )?;
            if fs::metadata(staged.root()).map_err(|e| e.to_string())?.permissions().mode() & 0o777 != 0o700 {
                return Err("staging root mode is not 0700".into());
            }
            for entry in entries {
                let path = staged.root().join(entry.name());
                let mut directory = staged.root().to_path_buf();
                let components = std::path::Path::new(entry.name()).components().collect::<Vec<_>>();
                for component in &components[..components.len() - 1] {
                    directory.push(component.as_os_str());
                    if fs::metadata(&directory).map_err(|e| e.to_string())?.permissions().mode() & 0o777 != 0o700 {
                        return Err(format!("staged directory mode is not 0700: {}", directory.display()));
                    }
                }
                if fs::read(&path).map_err(|e| e.to_string())? != entry.data() {
                    return Err(format!("staged content differs: {}", entry.name()));
                }
                if fs::metadata(&path).map_err(|e| e.to_string())?.permissions().mode() & 0o777 != 0o600 {
                    return Err(format!("staged file mode is not 0600: {}", entry.name()));
                }
            }
            if bytes != original { return Err("source bundle bytes changed".into()); }
            let root = staged.root().to_path_buf();
            drop(staged);
            if root.exists() { return Err("owned staging root was not cleaned".into()); }
        }
        _ => return Err(format!("unknown command: {command}")),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run() { reject(error); }
}
RS

cat >"$WORK/cpp_probe.cc" <<'CPP'
#include "harnesses/common/model_bundle.h"

#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using tool::model_bundle::EntryInput;
using tool::model_bundle::EntryView;

[[noreturn]] void Reject(const std::string& message) {
  std::cerr << "rejected: " << message << "\n";
  std::exit(9);
}

std::vector<std::uint8_t> Read(const std::string& path) {
  std::ifstream input(path, std::ios::binary);
  if (!input) Reject("cannot read " + path);
  return std::vector<std::uint8_t>(std::istreambuf_iterator<char>(input), {});
}

void Write(const std::string& path, const std::vector<std::uint8_t>& bytes) {
  std::ofstream output(path, std::ios::binary | std::ios::trunc);
  if (!output) Reject("cannot write " + path);
  if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<std::streamsize>::max())) {
    Reject("output is too large for streamsize");
  }
  output.write(reinterpret_cast<const char*>(bytes.data()),
               static_cast<std::streamsize>(bytes.size()));
  if (!output) Reject("short write to " + path);
}

int main(int argc, char** argv) {
  if (argc < 2) Reject("missing command");
  const std::string command = argv[1];
  std::string error;
  if (command == "encode") {
    if (argc < 5) Reject("encode needs OUTPUT NAME=PATH...");
    struct Owned { std::string name; std::string data; };
    std::vector<Owned> owned;
    for (int i = 3; i < argc; ++i) {
      const std::string specification = argv[i];
      const std::size_t split = specification.find('=');
      if (split == std::string::npos) Reject("entry needs NAME=PATH");
      const auto bytes = Read(specification.substr(split + 1));
      owned.push_back({specification.substr(0, split),
                       std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size())});
    }
    std::vector<EntryInput> entries;
    for (const auto& entry : owned) entries.push_back({entry.name, entry.data});
    std::vector<std::uint8_t> output;
    if (!tool::model_bundle::Encode(entries, &output, &error)) Reject(error);
    Write(argv[2], output);
  } else if (command == "alias") {
    std::vector<std::uint8_t> output(32, 0xa5);
    const std::string expected(reinterpret_cast<const char*>(output.data()), output.size());
    const std::vector<EntryInput> input = {
        {"payload", std::string_view(reinterpret_cast<const char*>(output.data()), output.size())}};
    if (!tool::model_bundle::Encode(input, &output, &error)) Reject(error);
    std::vector<EntryView> decoded;
    if (!tool::model_bundle::Decode(output.data(), output.size(), &decoded, &error)) Reject(error);
    if (decoded.size() != 1 || decoded[0].name != "payload" ||
        std::string(reinterpret_cast<const char*>(decoded[0].data), decoded[0].size) != expected) {
      Reject("self-alias encode changed payload bytes");
    }
    if (tool::model_bundle::Decode(nullptr, 8, &decoded, &error)) {
      Reject("non-empty null input was accepted");
    }
    if (tool::model_bundle::AppendLe(&output, 0, 9)) {
      Reject("invalid little-endian width was accepted");
    }
  } else if (command == "list" || command == "roundtrip") {
    if ((command == "list" && argc < 3) || (command == "roundtrip" && argc != 4)) {
      Reject("invalid parser arguments");
    }
    const auto bytes = Read(argv[2]);
    std::vector<EntryView> entries;
    bool accepted = false;
    if (command == "list" && argc > 3) {
      std::vector<std::string_view> allowlist;
      for (int i = 3; i < argc; ++i) allowlist.emplace_back(argv[i]);
      accepted = tool::model_bundle::DecodeWithAllowlist(
          bytes.data(), bytes.size(), allowlist, &entries, &error);
    } else {
      accepted = tool::model_bundle::Decode(bytes.data(), bytes.size(), &entries, &error);
    }
    if (!accepted) Reject(error);
    if (command == "list") {
      for (const auto& entry : entries) std::cout << entry.name << '\t' << entry.size << '\n';
    } else {
      std::vector<EntryInput> input;
      for (const auto& entry : entries) {
        input.push_back({entry.name,
                         std::string_view(reinterpret_cast<const char*>(entry.data), entry.size)});
      }
      std::vector<std::uint8_t> output;
      if (!tool::model_bundle::Encode(input, &output, &error)) Reject(error);
      Write(argv[3], output);
    }
  } else {
    Reject("unknown command");
  }
  return 0;
}
CPP

rustc --edition=2021 -Awarnings "$WORK/rust_probe.rs" -o "$WORK/rust_probe"
rustc --edition=2021 --test -Awarnings "$WORK/model_bundle.rs" -o "$WORK/rust_tests"
"$CXX" -std=c++17 -O1 -g -Wall -Wextra -Wconversion -Wsign-conversion \
  -Wpedantic -Werror -fno-pie -no-pie \
  -fsanitize=address,undefined -fno-sanitize-recover=all \
  -I"$PROJECT_ROOT" "$WORK/cpp_probe.cc" -o "$WORK/cpp_probe"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1"
export UBSAN_OPTIONS="halt_on_error=1"

timeout --signal=KILL 20s "$WORK/cpp_probe" alias
ok "C++ encoder is safe when output aliases input storage"

"$WORK/rust_tests" --list >"$WORK/rust-tests.list"
for required_test in \
  tests::golden_encoding_is_stable \
  tests::rejects_duplicate_and_out_of_order_names \
  tests::staging_does_not_follow_a_preplanted_intermediate_symlink \
  tests::staging_refuses_symlink_in_an_intermediate_parent_component \
  tests::staging_cleanup_never_deletes_a_replacement_directory; do
  if ! grep -Fq "$required_test: test" "$WORK/rust-tests.list"; then
    bad "required Rust contract test is missing: $required_test"
  fi
done
timeout --signal=KILL 30s "$WORK/rust_tests" >"$WORK/rust-tests.log"
RUST_COUNT="$(sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' "$WORK/rust-tests.log")"
if [[ -n "$RUST_COUNT" ]]; then
  ok "Rust contract tests $RUST_COUNT/$RUST_COUNT with required identities"
else
  bad "Rust contract test summary is missing"
fi

python3 -B - "$WORK/canonical.fzb" <<'PY'
import base64
import pathlib
import sys

encoded = "RlpCTkRMMQACAAAACQAEAAAAAAAAAG1vZGVsLmJpbgD/EAoJAAcAAAAAAAAAbW9kZWwueG1sPG5ldC8+Cg=="
pathlib.Path(sys.argv[1]).write_bytes(base64.b64decode(encoded))
PY
CANONICAL_SHA="$(sha256sum "$WORK/canonical.fzb" | awk '{print $1}')"
if [[ "$(stat -c %s "$WORK/canonical.fzb")" == 61 && \
      "$CANONICAL_SHA" == 20e1dda019d297b895509872228dfadb1760afbaf326d5ba1b9f9c3f23389e76 ]]; then
  ok "independent 61-byte canonical oracle"
else
  bad "canonical oracle size/hash"
fi

printf '\x00\xff\x10\x0a' >"$WORK/model.bin"
printf '<net/>\n' >"$WORK/model.xml"
: >"$WORK/empty.bin"

python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/python.fzb" \
  --entry "model.xml=$WORK/model.xml" --entry "model.bin=$WORK/model.bin"
"$WORK/rust_probe" encode "$WORK/rust.fzb" \
  "model.xml=$WORK/model.xml" "model.bin=$WORK/model.bin"
"$WORK/cpp_probe" encode "$WORK/cpp.fzb" \
  "model.xml=$WORK/model.xml" "model.bin=$WORK/model.bin"
for implementation in python rust cpp; do
  if cmp -s "$WORK/canonical.fzb" "$WORK/$implementation.fzb"; then
    ok "$implementation encoder matches canonical bytes"
  else
    bad "$implementation encoder differs from canonical bytes"
  fi
done

cat >"$WORK/expected.list" <<'EOF'
model.bin	4
model.xml	7
EOF
python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$WORK/canonical.fzb" \
  --allow model.xml --allow model.bin >"$WORK/python.list"
"$WORK/rust_probe" list "$WORK/canonical.fzb" model.xml model.bin >"$WORK/rust.list"
"$WORK/cpp_probe" list "$WORK/canonical.fzb" model.xml model.bin >"$WORK/cpp.list"
for implementation in python rust cpp; do
  if cmp -s "$WORK/expected.list" "$WORK/$implementation.list"; then
    ok "$implementation parser agrees on canonical entries"
  else
    bad "$implementation parser listing differs"
  fi
done

"$WORK/rust_probe" roundtrip "$WORK/canonical.fzb" "$WORK/rust-roundtrip.fzb"
"$WORK/cpp_probe" roundtrip "$WORK/canonical.fzb" "$WORK/cpp-roundtrip.fzb"
for implementation in rust cpp; do
  if cmp -s "$WORK/canonical.fzb" "$WORK/$implementation-roundtrip.fzb"; then
    ok "$implementation canonical roundtrip"
  else
    bad "$implementation canonical roundtrip differs"
  fi
done

for implementation in python rust cpp; do
  case "$implementation" in
    python)
      python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/empty-python.fzb" \
        --entry "model.xml=$WORK/model.xml" --entry "model.bin=$WORK/empty.bin" ;;
    rust)
      "$WORK/rust_probe" encode "$WORK/empty-rust.fzb" \
        "model.xml=$WORK/model.xml" "model.bin=$WORK/empty.bin" ;;
    cpp)
      "$WORK/cpp_probe" encode "$WORK/empty-cpp.fzb" \
        "model.xml=$WORK/model.xml" "model.bin=$WORK/empty.bin" ;;
  esac
done
if cmp -s "$WORK/empty-python.fzb" "$WORK/empty-rust.fzb" && \
   cmp -s "$WORK/empty-python.fzb" "$WORK/empty-cpp.fzb"; then
  ok "three encoders preserve empty content identically"
else
  bad "empty-content encoding differs"
fi

python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/nested.fzb" \
  --entry "nested/model.bin=$WORK/model.bin" --entry "nested/model.xml=$WORK/model.xml"
mkdir "$WORK/python-restrict-parent" "$WORK/rust-restrict-parent"
( umask 0777; timeout --signal=KILL 20s python3 -B \
    "$PROJECT_ROOT/scripts/model_bundle.py" unpack "$WORK/nested.fzb" \
    --output-dir "$WORK/python-restrict-parent/stage" \
    --allow nested/model.bin --allow nested/model.xml )
if [[ "$(stat -c %a "$WORK/python-restrict-parent/stage")" == 700 && \
      "$(stat -c %a "$WORK/python-restrict-parent/stage/nested")" == 700 && \
      "$(stat -c %a "$WORK/python-restrict-parent/stage/nested/model.bin")" == 600 ]]; then
  ok "Python staging restores 0700/0600 under umask 0777"
else
  bad "Python restrictive-umask staging modes"
fi
( umask 0777; timeout --signal=KILL 20s "$WORK/rust_probe" stage-check \
    "$WORK/nested.fzb" "$WORK/rust-restrict-parent" stage \
    nested/model.bin nested/model.xml )
if [[ -z "$(find "$WORK/rust-restrict-parent" -mindepth 1 -print -quit)" ]]; then
  ok "Rust staging restores modes and cleans its owned root under umask 0777"
else
  bad "Rust restrictive-umask staging left residue"
fi

python3 -B - "$PROJECT_ROOT/scripts/model_bundle.py" "$WORK" <<'PY'
import importlib.util
from pathlib import Path
import shutil
import sys

spec = importlib.util.spec_from_file_location("model_bundle_under_test", sys.argv[1])
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)
work = Path(sys.argv[2])

# Force a swap after an owned file exists. Cleanup must follow the held root fd,
# preserve the unrelated replacement, and report rejection instead of false success.
destination = work / "swap-stage"
moved = work / "swap-stage-owned"
real_fsync = module.os.fsync
triggered = False
def swap_stage(fd):
    global triggered
    if not triggered:
        triggered = True
        destination.rename(moved)
        destination.mkdir()
        (destination / "victim").write_bytes(b"unrelated")
    return real_fsync(fd)
module.os.fsync = swap_stage
try:
    try:
        module._stage_entries([("file", b"owned")], destination)
    except module.BundleError:
        pass
    else:
        raise AssertionError("root replacement was reported as successful staging")
finally:
    module.os.fsync = real_fsync
assert (destination / "victim").read_bytes() == b"unrelated"
assert moved.is_dir() and not (moved / "file").exists()

# Apply the same identity rule to pack output cleanup.
output = work / "swap-output.fzb"
moved_output = work / "swap-output-owned.fzb"
triggered = False
def swap_output(fd):
    global triggered
    if not triggered:
        triggered = True
        output.rename(moved_output)
        output.write_bytes(b"unrelated")
    return real_fsync(fd)
module.os.fsync = swap_output
try:
    try:
        module._write_new_file(output, b"owned")
    except module.BundleError:
        pass
    else:
        raise AssertionError("output replacement was reported as a successful write")
finally:
    module.os.fsync = real_fsync
assert output.read_bytes() == b"unrelated"
assert moved_output.read_bytes() == b"owned"

shutil.rmtree(destination)
shutil.rmtree(moved)
output.unlink()
moved_output.unlink()
PY
ok "Python cleanup follows owned descriptors and preserves path replacements"

python3 -B - "$WORK/malformed" <<'PY'
from pathlib import Path
import struct
import sys

root = Path(sys.argv[1])
root.mkdir()
magic = b"FZBNDL1\0"

def raw(entries):
    out = bytearray(magic + struct.pack("<I", len(entries)))
    for name, data in entries:
        out += struct.pack("<HQ", len(name), len(data)) + name + data
    return bytes(out)

valid = raw([(b"model.bin", b"B"), (b"model.xml", b"X")])
cases = {
    "absolute": raw([(b"/abs", b"")]),
    "backslash": raw([(b"a\\b", b"")]),
    "bad-magic": b"XZBNDL1\0" + valid[8:],
    "count-0": magic + struct.pack("<I", 0),
    "count-65": magic + struct.pack("<I", 65),
    "data-max": magic + struct.pack("<I", 1) + struct.pack("<HQ", 1, 2**64 - 1) + b"a",
    "depth-9": raw([(b"a/b/c/d/e/f/g/h/i", b"")]),
    "dot": raw([(b".", b"")]),
    "drive": raw([(b"C:drive", b"")]),
    "duplicate": raw([(b"a", b"1"), (b"a", b"2")]),
    "empty-segment": raw([(b"a//b", b"")]),
    "name-0": magic + struct.pack("<I", 1) + struct.pack("<HQ", 0, 0),
    "name-241": raw([(b"a" * 241, b"")]),
    "non-ascii": raw([(b"bad\xff", b"")]),
    "nul": raw([(b"bad\0name", b"")]),
    "out-of-order": raw([(b"b", b"1"), (b"a", b"2")]),
    "parent": raw([(b"a/../b", b"")]),
    "prefix-conflict": raw([(b"a", b"1"), (b"a/b", b"2")]),
    "prefix-conflict-interposed": raw([(b"a", b"1"), (b"a-", b"2"), (b"a/b", b"3")]),
    "trailing": valid + b"x",
    "truncated-data": raw([(b"a", b"xyz")])[:-1],
    "truncated-entry-header": magic + struct.pack("<I", 1) + b"\x01",
    "truncated-magic": magic[:7],
    "truncated-name": magic + struct.pack("<I", 1) + struct.pack("<HQ", 3, 0) + b"ab",
}
for name, data in cases.items():
    (root / f"{name}.fzb").write_bytes(data)
(root / "oversized.fzb").write_bytes(b"\0" * (64 * 1024 * 1024 + 1))
(root / "missing.fzb").write_bytes(raw([(b"model.xml", b"X")]))
(root / "extra.fzb").write_bytes(raw([(b"extra", b"E"), (b"model.bin", b"B"), (b"model.xml", b"X")]))
boundary = root.parent / "boundary"
boundary.mkdir()
(boundary / "entries-64.fzb").write_bytes(raw([(f"n{i:02}".encode(), b"") for i in range(64)]))
(boundary / "name-240.fzb").write_bytes(raw([(b"a" * 240, b"")]))
max_data = 64 * 1024 * 1024 - len(magic) - 4 - 2 - 8 - 1
(boundary / "bytes-64m.fzb").write_bytes(raw([(b"a", b"\0" * max_data)]))
PY

is_rc9() {
  local log="$1" rc=0
  shift
  timeout --signal=KILL 20s "$@" >"$log.out" 2>"$log.err" || rc=$?
  if [[ "$rc" -eq 9 ]] && grep -qi 'reject' "$log.err"; then
    return 0
  fi
  printf '       rc=%s command=' "$rc" >&2
  printf ' %q' "$@" >&2
  printf '\n' >&2
  sed -n '1,4p' "$log.err" | sed 's/^/       /' >&2
  return 1
}

negative_rc=0
timeout --signal=KILL 20s true || negative_rc=$?
if [[ "$negative_rc" -eq 9 ]]; then
  bad "rc=9 gate negative control accepted rc=0"
else
  ok "rc=9 gate negative control"
fi

mapfile -t MALFORMED < <(find "$WORK/malformed" -maxdepth 1 -type f -name '*.fzb' \
  ! -name 'missing.fzb' ! -name 'extra.fzb' -printf '%f\n' | sort)
if [[ "${#MALFORMED[@]}" == 25 ]]; then
  ok "malformed corpus has 25 independent cases"
else
  bad "malformed corpus count ${#MALFORMED[@]} (expected 25)"
fi
for filename in "${MALFORMED[@]}"; do
  path="$WORK/malformed/$filename"
  if ! is_rc9 "$WORK/python-${filename%.fzb}" \
      python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$path"; then
    bad "Python did not precheck-reject $filename with rc=9"
  fi
  if ! is_rc9 "$WORK/rust-${filename%.fzb}" "$WORK/rust_probe" list "$path"; then
    bad "Rust did not precheck-reject $filename with rc=9"
  fi
  if ! is_rc9 "$WORK/cpp-${filename%.fzb}" "$WORK/cpp_probe" list "$path"; then
    bad "C++ did not precheck-reject $filename with rc=9"
  fi
done
if [[ "$FAIL" -eq 0 ]]; then
  ok "Rust/C++/Python reject all malformed framing cases with rc=9"
fi

boundary_failed=0
for path in "$WORK"/boundary/*.fzb; do
  timeout --signal=KILL 30s python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$path" \
    >/dev/null || boundary_failed=1
  timeout --signal=KILL 30s "$WORK/rust_probe" list "$path" >/dev/null || boundary_failed=1
  timeout --signal=KILL 30s "$WORK/cpp_probe" list "$path" >/dev/null || boundary_failed=1
done
if [[ "$boundary_failed" -eq 0 ]]; then
  ok "three parsers accept exact 64-entry, 240-byte-name, and 64 MiB boundaries"
else
  bad "one parser rejected an exact valid boundary"
fi

for kind in missing extra; do
  path="$WORK/malformed/$kind.fzb"
  python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$path" >/dev/null
  "$WORK/rust_probe" list "$path" >/dev/null
  "$WORK/cpp_probe" list "$path" >/dev/null
  for implementation in python rust cpp; do
    case "$implementation" in
      python) command=(python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$path" --allow model.bin --allow model.xml) ;;
      rust) command=("$WORK/rust_probe" list "$path" model.bin model.xml) ;;
      cpp) command=("$WORK/cpp_probe" list "$path" model.bin model.xml) ;;
    esac
    if ! is_rc9 "$WORK/$implementation-allow-$kind" "${command[@]}"; then
      bad "$implementation did not reject target-$kind allowlist with rc=9"
    fi
  done
done
if [[ "$FAIL" -eq 0 ]]; then ok "generic-valid missing/extra bundles fail exact target allowlists"; fi

BEFORE_SHA="$(sha256sum "$WORK/canonical.fzb" | awk '{print $1}')"
( umask 000; python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" unpack "$WORK/canonical.fzb" \
    --output-dir "$WORK/unpacked" --allow model.bin --allow model.xml )
AFTER_SHA="$(sha256sum "$WORK/canonical.fzb" | awk '{print $1}')"
if [[ "$BEFORE_SHA" == "$AFTER_SHA" && "$(stat -c %a "$WORK/unpacked")" == 700 && \
      "$(stat -c %a "$WORK/unpacked/model.bin")" == 600 && \
      "$(stat -c %a "$WORK/unpacked/model.xml")" == 600 ]] && \
   cmp -s "$WORK/model.bin" "$WORK/unpacked/model.bin" && \
   cmp -s "$WORK/model.xml" "$WORK/unpacked/model.xml"; then
  ok "Python no-follow staging preserves hash/content and exact 0700/0600 modes"
else
  bad "Python staging contract"
fi
python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/python-roundtrip.fzb" \
  --entry "model.bin=$WORK/unpacked/model.bin" --entry "model.xml=$WORK/unpacked/model.xml"
if cmp -s "$WORK/canonical.fzb" "$WORK/python-roundtrip.fzb"; then
  ok "Python unpack/pack canonical roundtrip"
else
  bad "Python unpack/pack changed canonical bytes"
fi

if is_rc9 "$WORK/existing-destination" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" unpack "$WORK/canonical.fzb" \
      --output-dir "$WORK/unpacked" --allow model.bin --allow model.xml; then
  ok "existing staging destination is refused"
else
  bad "existing staging destination was not refused with rc=9"
fi
mkdir "$WORK/outside"
printf unchanged >"$WORK/outside/sentinel"
ln -s "$WORK/outside" "$WORK/stage-link"
if is_rc9 "$WORK/symlink-destination" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" unpack "$WORK/canonical.fzb" \
      --output-dir "$WORK/stage-link" --allow model.bin --allow model.xml && \
   [[ "$(cat "$WORK/outside/sentinel")" == unchanged ]]; then
  ok "symlink staging destination is refused without outside writes"
else
  bad "symlink staging destination safety"
fi
mkdir -p "$WORK/intended" "$WORK/outside/sub"
ln -s "$WORK/outside" "$WORK/intended/link"
if is_rc9 "$WORK/intermediate-parent-symlink" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" unpack "$WORK/canonical.fzb" \
      --output-dir "$WORK/intended/link/sub/escaped" --allow model.bin --allow model.xml && \
   [[ ! -e "$WORK/outside/sub/escaped" ]]; then
  ok "intermediate parent symlink is refused without outside writes"
else
  bad "intermediate parent symlink safety"
fi

mkfifo "$WORK/bundle.fifo"
if is_rc9 "$WORK/fifo-input" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" list "$WORK/bundle.fifo"; then
  ok "FIFO input is rejected without blocking"
else
  bad "FIFO input did not return rc=9 within the timeout"
fi

ln -s "$WORK/model.bin" "$WORK/source-link"
if is_rc9 "$WORK/symlink-source" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/from-link.fzb" \
      --entry "model.bin=$WORK/source-link" --entry "model.xml=$WORK/model.xml"; then
  ok "symlink pack source is refused"
else
  bad "symlink pack source was not refused with rc=9"
fi
ln "$WORK/model.bin" "$WORK/source-hardlink"
if timeout --signal=KILL 20s python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack \
    --output "$WORK/from-hardlink.fzb" \
    --entry "model.bin=$WORK/source-hardlink" --entry "model.xml=$WORK/model.xml" && \
   cmp -s "$WORK/from-hardlink.fzb" "$WORK/canonical.fzb"; then
  ok "hard-linked source is snapshotted as bytes without link representation"
else
  bad "hard-linked source byte snapshot"
fi
rm "$WORK/source-hardlink"
printf occupied >"$WORK/existing-output.fzb"
if is_rc9 "$WORK/existing-output" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/existing-output.fzb" \
      --entry "model.bin=$WORK/model.bin" --entry "model.xml=$WORK/model.xml"; then
  ok "existing pack output is refused"
else
  bad "existing pack output was not refused with rc=9"
fi
printf outside >"$WORK/output-sentinel"
ln -s "$WORK/output-sentinel" "$WORK/output-link.fzb"
if is_rc9 "$WORK/symlink-output" \
    python3 -B "$PROJECT_ROOT/scripts/model_bundle.py" pack --output "$WORK/output-link.fzb" \
      --entry "model.bin=$WORK/model.bin" --entry "model.xml=$WORK/model.xml" && \
   [[ "$(cat "$WORK/output-sentinel")" == outside ]]; then
  ok "symlink pack output is refused without overwrite"
else
  bad "symlink pack output safety"
fi

printf '[model-bundle] result: %d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
