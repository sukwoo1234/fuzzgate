#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
WORK="$(mktemp -d)"
trap 'rm -rf -- "$WORK"' EXIT

version_root="$WORK/data/targets/llama.cpp/b7921"
source_dir="$version_root/source"
mkdir -p "$source_dir" "$WORK/bin"
archive="$source_dir/b7921.tar.gz"
printf 'original fixture bytes\n' >"$archive"
expected_sha="$(sha256sum "$archive" | cut -d' ' -f1)"
cat >"$version_root/meta.json" <<EOF
{"target":"llama.cpp","version":"b7921","downloaded_sha256":"$expected_sha"}
EOF

# An intact fixture must get as far as extraction. The fake tar makes this test
# independent of a compiler, target source tree, and network access.
cat >"$WORK/bin/tar" <<'EOF'
#!/usr/bin/env bash
printf 'called\n' >"$TAR_MARKER"
exit 42
EOF
chmod +x "$WORK/bin/tar"
export PATH="$WORK/bin:$PATH"
export TAR_MARKER="$WORK/tar-called"

rc=0
bash "$PROJECT_ROOT/scripts/build_prepared_target.sh" "$WORK/data" gguf b7921 \
  >"$WORK/valid.stdout" 2>"$WORK/valid.stderr" || rc=$?
[[ "$rc" -eq 42 && -f "$TAR_MARKER" ]] || {
  echo "[prepared-integrity-test] valid archive did not reach tar (rc=$rc)" >&2
  exit 1
}

rm -f "$TAR_MARKER"
rm -rf "$version_root/build-src-plain"
printf 'tampered fixture bytes\n' >"$archive"
rc=0
bash "$PROJECT_ROOT/scripts/build_prepared_target.sh" "$WORK/data" gguf b7921 \
  >"$WORK/tampered.stdout" 2>"$WORK/tampered.stderr" || rc=$?
if [[ "$rc" -eq 0 || -f "$TAR_MARKER" || -e "$version_root/build-src-plain" ]] \
    || ! grep -q 'sha256 mismatch' "$WORK/tampered.stderr"; then
  echo "[prepared-integrity-test] tampered archive was not rejected before extraction (rc=$rc)" >&2
  cat "$WORK/tampered.stderr" >&2
  exit 1
fi

echo '[prepared-integrity-test] PASS: intact archive reaches extraction; tampered archive is rejected before extraction'
