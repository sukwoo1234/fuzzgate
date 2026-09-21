#!/usr/bin/env bash
set -euo pipefail

WORKDIR="${WORKDIR:-$PWD}"
PROJECT_ROOT="${PROJECT_ROOT:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)}"
TOOL_BIN="${TOOL_BIN:-$PROJECT_ROOT/target/debug/tool}"
# R92/R94: the server below used to be started with `cargo run --offline --`, which reads no
# TOOL_BIN and builds the binary inside the gate. Both consequences were measured 2026-09-19
# on a tree extracted with `git archive HEAD`, with TOOL_BIN pointed at a path that does not
# exist. First pass: exit 1 after 5.2s with the build still at "Compiling tool v0.1.0",
# because the healthz wait below allows 25 x 0.2s = 5s - the verdict was the build cache's,
# not the routes' (R94). Second pass over that same tree: rc=0, and it left behind a
# target/debug/tool the tree had never had - one gate manufacturing the precondition four
# other gates refuse over, which is R92's mechanism. Driving a binary the caller names
# removes both: nothing compiles inside the wait, and nothing is installed.
# The cost is the one the other four subjects already pay - a stale target/debug/tool is
# driven as it is, so building it is the operator's step. That makes the placeholder check
# below stricter rather than weaker: dashboard_html_template() reads templates/dashboard.html
# off disk at request time, so an unrebuilt binary now also reads as the drift it names.
# Not a skip: this gate drives the real tool, so without the binary it observes nothing, and
# a gate that reports anything other than a refusal when it observed nothing is the failure
# mode this suite exists to stop - the wording is check_aflpp_asan_env.sh:12-15's. R86.
if [[ ! -x "$TOOL_BIN" ]]; then
  printf '[ui-check] fail: tool binary not executable: %s\n' "$TOOL_BIN" >&2
  printf '[ui-check] build it with `cargo build` or point TOOL_BIN at one; this gate cannot run\n' >&2
  exit 1
fi

# R5: this check used to run against the operator's real ./data on the campaign
# port, and it calls state-writing routes. It also overwrote the per-user token
# file, so running it while a dashboard was up logged the operator out. Everything
# it touches now lives in a throwaway tree.
WORK="$(mktemp -d)"
# Installed immediately: everything between here and the full cleanup below can
# exit, and each of those paths used to leak the temp tree.
trap 'rm -rf "$WORK"' EXIT
DATA_DIR="${DATA_DIR:-$WORK/data}"
SEEDS_DIR="${SEEDS_DIR:-$WORK/seeds}"
# The logs are the evidence for a failure, so they must OUTLIVE the throwaway tree.
# Isolating the data dir is the point of R5; the logs do not need to be inside it.
LOG_DIR="${LOG_DIR:-$(mktemp -d -t tool-ui-check-XXXXXX)}"
# Resolve existing symlinks and harmless path spelling differences before any
# mkdir. The previous string-prefix guard ran after mkdir and could leave a new
# directory under the operator's data tree even when it refused the test.
OPERATOR_DATA_ROOT="$(realpath -m -- "$WORKDIR/data")"
RESOLVED_DATA_DIR="$(realpath -m -- "$DATA_DIR")"
RESOLVED_LOG_DIR="$(realpath -m -- "$LOG_DIR")"
case "$RESOLVED_DATA_DIR" in
  "$OPERATOR_DATA_ROOT"|"$OPERATOR_DATA_ROOT"/*)
    echo "[FAIL] the check must not run against the operator data dir: $DATA_DIR" >&2
    exit 1
    ;;
esac
case "$RESOLVED_LOG_DIR" in
  "$OPERATOR_DATA_ROOT"|"$OPERATOR_DATA_ROOT"/*)
    echo "[FAIL] the check must not write logs into the operator data dir: $LOG_DIR" >&2
    exit 1
    ;;
esac
mkdir -p "$DATA_DIR" "$SEEDS_DIR/onnx" "$LOG_DIR" "$WORK/run"

# The token file lives under XDG_RUNTIME_DIR. Point it at the throwaway tree and
# remember the operator's own file so the run can prove it left it alone.
# Mirrors token_file_path() in src/ui/server.rs exactly - the fallback file has a
# different name, so re-deriving it loosely watched a path the tool never writes.
if [[ -n "${XDG_RUNTIME_DIR:-}" ]]; then
  ORIG_TOKEN_FILE="$XDG_RUNTIME_DIR/tool-ui-token"
else
  ORIG_TOKEN_FILE="$HOME/.cache/tool/ui-token"
fi
ORIG_TOKEN_SUM=""
if [[ -f "$ORIG_TOKEN_FILE" ]]; then
  ORIG_TOKEN_SUM="$(sha256sum "$ORIG_TOKEN_FILE" | cut -d' ' -f1)"
fi
export XDG_RUNTIME_DIR="$WORK/run"

# Older runs of this check left a data/ui-check directory behind. Remember its
# state so the run can prove it did not add to or modify it.
# A whole-tree stamp: a directory's own mtime does not change when a file inside it
# is rewritten, so watching one subdirectory proved much less than the message said.
DATA_TREE_STAMP_BEFORE="$WORK/data-tree-before.txt"
if [[ -e "$WORKDIR/data" || -L "$WORKDIR/data" ]]; then
  find -L "$WORKDIR/data" -printf '%p\t%T@\t%s\n' | sort > "$DATA_TREE_STAMP_BEFORE"
else
  printf 'absent\n' > "$DATA_TREE_STAMP_BEFORE"
fi

# An ephemeral port, so a running campaign dashboard on 8787 is not in the way.
pick_port() {
  python3 - <<'PYEOF' 2>/dev/null || echo 18787
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PYEOF
}
BIND="${BIND:-127.0.0.1:$(pick_port)}"
BASE_URL="http://${BIND}"

SERVER_LOG="${LOG_DIR}/ui-serve.log"
# A3: the control endpoints need this token. Setting it here also exercises the documented
# override; without it the server generates one and leaves it in a 0600 file.
export TOOL_UI_TOKEN="${TOOL_UI_TOKEN:-check-ui-routes-token}"
AUTH=(-H "X-Tool-Token: ${TOOL_UI_TOKEN}")
CHECK_LOG="${LOG_DIR}/ui-routes-check.log"

cleanup() {
  if [[ -n "${SERVER_PID:-}" ]]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  rm -rf "$WORK"
  echo "[ui-check] logs kept at: $LOG_DIR" >&2
}
trap cleanup EXIT

cd "$WORKDIR"

# Enough of a tree that the entity-detail assertions still assert something.
printf 'seed' > "$SEEDS_DIR/onnx/seed.onnx"
# All four entity kinds: the detail routes were rewritten this stage, and without a
# fixture for a kind the dashboard renders no link and the assertion below silently
# skips - which is how reports and coverage stopped being checked at all.
mkdir -p "$DATA_DIR/runs/run-1" "$DATA_DIR/triage/triage-1" \
         "$DATA_DIR/reports/report-1" "$DATA_DIR/coverage/coverage-1"
printf '{"run_id": "run-1", "total": 1, "success": 1}\n' > "$DATA_DIR/runs/run-1/status.json"
printf '{"triage_id": "triage-1", "verdict": "not_reproduced", "attempts": []}\n' \
  > "$DATA_DIR/triage/triage-1/summary.json"
printf '# Report report-1\n' > "$DATA_DIR/reports/report-1/report.md"
printf '{"report_id": "report-1"}\n' > "$DATA_DIR/reports/report-1/meta.json"
printf '{"coverage_id": "coverage-1", "coverage_kind": "proxy"}\n' \
  > "$DATA_DIR/coverage/coverage-1/summary.json"

"$TOOL_BIN" --data-dir "$DATA_DIR" --seeds-dir "$SEEDS_DIR" \
  ui-serve --bind "$BIND" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

wait_for_server() {
  local max_tries="${1:-25}"
  local i=1
  while [[ "$i" -le "$max_tries" ]]; do
    if curl -fsS "${BASE_URL}/healthz" >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" >/dev/null 2>&1; then
      echo "[FAIL] ui-serve exited before healthz became ready" | tee -a "$CHECK_LOG"
      echo "[FAIL] server_log: $SERVER_LOG" | tee -a "$CHECK_LOG"
      tail -n 30 "$SERVER_LOG" | sed 's/^/[server] /' | tee -a "$CHECK_LOG"
      return 1
    fi
    sleep 0.2
    i=$((i + 1))
  done
  echo "[FAIL] ui-serve healthz not ready in time" | tee -a "$CHECK_LOG"
  echo "[FAIL] server_log: $SERVER_LOG" | tee -a "$CHECK_LOG"
  tail -n 30 "$SERVER_LOG" | sed 's/^/[server] /' | tee -a "$CHECK_LOG"
  return 1
}

check_url() {
  local url="$1"
  shift
  if curl -fsS --max-time 10 "$@" "$url" >/dev/null; then
    echo "[OK] $url" | tee -a "$CHECK_LOG"
  else
    echo "[FAIL] $url" | tee -a "$CHECK_LOG"
    return 1
  fi
}

: >"$CHECK_LOG"
wait_for_server
check_url "${BASE_URL}/healthz"
check_url "${BASE_URL}/dashboard.html"
check_url "${BASE_URL}/dashboard.json"
check_url "${BASE_URL}/assets/dashboard.css"
check_url "${BASE_URL}/control/status"
check_url "${BASE_URL}/replay/status"
check_url "${BASE_URL}/target/status" "${AUTH[@]}"
check_url "${BASE_URL}/target/build/status" "${AUTH[@]}"

# Asserts the exact HTTP status of a request that must be refused before anything is spawned.
check_status() {
  local expected="$1"
  local method="$2"
  local url="$3"
  local label="$4"
  shift 4
  local got
  got="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -X "$method" "$@" "$url" || true)"
  if [[ "$got" == "$expected" ]]; then
    echo "[OK] $label -> $got" | tee -a "$CHECK_LOG"
  else
    echo "[FAIL] $label -> expected $expected, got $got" | tee -a "$CHECK_LOG"
    return 1
  fi
}

# A2: a newline in a query value used to inject an extra `pid=` line into the state file, which
# /target/stop then handed to kill. A16: `version` reached build_prepared_target.sh's rm -rf.
check_rejected_inputs() {
  check_status 400 POST "${BASE_URL}/target/prepare?target=onnx&version=x%0Apid%3D1234" \
    "A2 newline in version" "${AUTH[@]}"
  check_status 400 POST "${BASE_URL}/target/prepare?target=onnx&source_url=file%3A%2F%2F%2Fetc%2Fpasswd" \
    "source_url must be http(s)" "${AUTH[@]}"
  check_status 400 POST "${BASE_URL}/target/build/start?target=onnx&version=..%2F..%2F..%2Ftmp%2Fpwn" \
    "A16 traversal in build version" "${AUTH[@]}"
  check_status 400 POST "${BASE_URL}/replay/start?target=onnx&input=%2Fetc%2Fpasswd" \
    "A14 replay input outside the data dir" "${AUTH[@]}"
  check_status 400 POST "${BASE_URL}/replay/start?target=onnx&triage_id=..%2F..%2Fetc" \
    "A14 triage id must not leave the triage tree" "${AUTH[@]}"
  # A handler error used to close the connection with zero bytes (curl exit 52) instead of a status.
  check_status 500 GET "${BASE_URL}/file?path=%2Fetc%2Fpasswd" "a refused file view answers a status"
  local state="$DATA_DIR/ui-target/prepare-target.state"
  if [[ -f "$state" ]] && grep -qx 'pid=1234' "$state"; then
    echo "[FAIL] A2 injected a pid line into $state" | tee -a "$CHECK_LOG"
    return 1
  fi
  echo "[OK] no injected pid line in the prepare state" | tee -a "$CHECK_LOG"
}

check_rejected_inputs

# A3: every mutating endpoint used to be reachable by any page the user had open.
check_authorization() {
  check_status 403 POST "${BASE_URL}/target/prepare?target=onnx" "A3 no token"
  check_status 403 POST "${BASE_URL}/target/prepare?target=onnx" "A3 wrong token" \
    -H "X-Tool-Token: not-the-token"
  check_status 403 POST "${BASE_URL}/target/prepare?target=onnx" "A3 cross-origin form post" \
    "${AUTH[@]}" -H "Origin: http://evil.example"
  check_status 403 POST "${BASE_URL}/target/prepare?target=onnx" "A3 cross-origin referer" \
    "${AUTH[@]}" -H "Referer: http://evil.example/x.html"
  check_status 403 GET "${BASE_URL}/target/status" "A3 state-changing GET needs the token"
  # DNS rebinding: the page is same-origin after the rebind, so the Host is the only tell.
  check_status 403 GET "${BASE_URL}/healthz" "A3 rebound host" -H "Host: evil.example"
  # The token must not be sitting in a file the unauthenticated /file route can serve.
  local token_file
  token_file="$(sed -n 's/^\[ui\] token file: //p' "$SERVER_LOG" | head -n 1)"
  if [[ -z "$token_file" || ! -f "$token_file" ]]; then
    echo "[FAIL] the server did not report a token file" | tee -a "$CHECK_LOG"
    return 1
  fi
  local mode
  mode="$(stat -c '%a' "$token_file")"
  if [[ "$mode" != "600" ]]; then
    echo "[FAIL] token file $token_file has mode $mode, expected 600" | tee -a "$CHECK_LOG"
    return 1
  fi
  case "$token_file" in
    "$DATA_DIR/"*)
      echo "[FAIL] token file $token_file is inside the data dir /file can serve" | tee -a "$CHECK_LOG"
      return 1
      ;;
  esac
  if grep -q "$TOOL_UI_TOKEN" "$SERVER_LOG"; then
    echo "[FAIL] the server printed the token into $SERVER_LOG" | tee -a "$CHECK_LOG"
    return 1
  fi
  echo "[OK] token lives in $token_file (mode $mode), not in the log" | tee -a "$CHECK_LOG"
}

check_authorization

# A4: a client that opens the socket and sends nothing used to block the single-threaded accept
# loop. A client that dribbles a partial head never trips the per-read timeout, so it also has to
# be bounded. In both cases the dashboard must still answer promptly, not merely eventually.
check_slow_clients_do_not_block() {
  local host="${BIND%:*}"
  local port="${BIND##*:}"
  local rc=0
  # 3 silent connections and 3 that send an unterminated head
  local fds=(9 8 7 6 5 4)
  local i=0
  for fd in "${fds[@]}"; do
    if ! eval "exec ${fd}<>/dev/tcp/${host}/${port}" 2>/dev/null; then
      echo "[FAIL] could not open connection ${fd} to ${BIND}" | tee -a "$CHECK_LOG"
      return 1
    fi
    if [[ "$i" -ge 3 ]]; then
      printf 'GET /healthz HTTP/1.1\r\nHost: %s\r\n' "$BIND" >&"$fd" || true
    fi
    i=$((i + 1))
  done
  if curl -fsS --max-time 2 "${BASE_URL}/healthz" >/dev/null 2>&1; then
    echo "[OK] silent and half-open clients do not block the dashboard" | tee -a "$CHECK_LOG"
  else
    echo "[FAIL] a slow client blocked the dashboard" | tee -a "$CHECK_LOG"
    rc=1
  fi
  for fd in "${fds[@]}"; do
    eval "exec ${fd}<&-" 2>/dev/null || true
    eval "exec ${fd}>&-" 2>/dev/null || true
  done
  return "$rc"
}

check_slow_clients_do_not_block

dash_html="$(curl -fsS --max-time 10 "${BASE_URL}/dashboard.html")"

# A placeholder that survives into the served page means the binary and templates/dashboard.html
# have drifted apart, which silently breaks whatever that placeholder drives.
if printf '%s' "$dash_html" | grep -q '{{[a-z_]*}}'; then
  echo "[FAIL] dashboard.html still carries an unsubstituted placeholder:" | tee -a "$CHECK_LOG"
  printf '%s' "$dash_html" | grep -o '{{[a-z_]*}}' | sort -u | tee -a "$CHECK_LOG"
  exit 1
fi
echo "[OK] every dashboard placeholder is substituted" | tee -a "$CHECK_LOG"
run_path="$(printf '%s' "$dash_html" | sed -n 's/.*href="\(\/*run\/[^"]*\)".*/\1/p' | head -n 1)"
triage_path="$(printf '%s' "$dash_html" | sed -n 's/.*href="\(\/*triage\/[^"]*\)".*/\1/p' | head -n 1)"
report_path="$(printf '%s' "$dash_html" | sed -n 's/.*href="\(\/*report\/[^"]*\)".*/\1/p' | head -n 1)"
coverage_path="$(printf '%s' "$dash_html" | sed -n 's/.*href="\(\/*coverage\/[^"]*\)".*/\1/p' | head -n 1)"

for kind in run triage report coverage; do
  eval "path=\"\${${kind}_path}\""
  if [[ -z "$path" ]]; then
    echo "[FAIL] the dashboard exposed no /${kind}/<id> link to check" | tee -a "$CHECK_LOG"
    exit 1
  fi
  check_url "${BASE_URL}${path}"
done

# R5: the operator's own token file must be exactly as it was.
if [[ -n "$ORIG_TOKEN_SUM" ]]; then
  now_sum="$(sha256sum "$ORIG_TOKEN_FILE" 2>/dev/null | cut -d' ' -f1 || true)"
  if [[ "$now_sum" != "$ORIG_TOKEN_SUM" ]]; then
    echo "[FAIL] the check rewrote the operator token file $ORIG_TOKEN_FILE" | tee -a "$CHECK_LOG"
    exit 1
  fi
  echo "[OK] the operator token file was left alone" | tee -a "$CHECK_LOG"
elif [[ -e "$ORIG_TOKEN_FILE" ]]; then
  echo "[FAIL] the check created a token file at $ORIG_TOKEN_FILE" | tee -a "$CHECK_LOG"
  exit 1
else
  echo "[OK] no operator token file was created" | tee -a "$CHECK_LOG"
fi

DATA_TREE_STAMP_AFTER="$WORK/data-tree-after.txt"
if [[ -e "$WORKDIR/data" || -L "$WORKDIR/data" ]]; then
  find -L "$WORKDIR/data" -printf '%p\t%T@\t%s\n' | sort > "$DATA_TREE_STAMP_AFTER"
else
  printf 'absent\n' > "$DATA_TREE_STAMP_AFTER"
fi
if ! diff -q "$DATA_TREE_STAMP_BEFORE" "$DATA_TREE_STAMP_AFTER" >/dev/null; then
  echo "[FAIL] the check changed the operator data dir:" | tee -a "$CHECK_LOG"
  diff "$DATA_TREE_STAMP_BEFORE" "$DATA_TREE_STAMP_AFTER" | head -n 20 | tee -a "$CHECK_LOG"
  exit 1
fi
echo "[OK] the operator data dir is unchanged (name, mtime and size, entire tree)" | tee -a "$CHECK_LOG"

echo "[ui-check] done"
echo "server_log: $SERVER_LOG"
echo "check_log: $CHECK_LOG"
