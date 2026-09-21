use std::fs;
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::common::AppPaths;
use crate::dashboard_data::collect_dashboard_snapshot;
use crate::json_utils::{extract_json_string_literal, html_escape, json_escape, url_encode};

/// A4: a client that opens the socket and then goes quiet must not be able to hold a slot
/// forever, and a slow reader must not wedge a writer.
const READ_TIMEOUT_SECS: u64 = 5;
const WRITE_TIMEOUT_SECS: u64 = 5;
/// SO_SNDTIMEO restarts on every partial write, so a peer that reads one byte per window held its
/// thread and one of the in-flight slots for as long as it liked. The whole response gets one
/// wall-clock budget, the same way the request head does.
const WRITE_DEADLINE: Duration = Duration::from_secs(15);
/// Connections are handled on their own threads, so the number of them in flight is capped
/// rather than left to the peer.
const MAX_IN_FLIGHT_CONNECTIONS: usize = 64;

/// A4 again: the state lock must not be held while the response is written, or a peer that stops
/// reading parks every other state request behind it for the whole write timeout. Handlers build
/// their response and hand it back; the connection writes it after the lock is gone. It also
/// makes them testable without a socket.
struct Response {
    status: String,
    content_type: String,
    body: String,
}

fn respond(status: &str, content_type: &str, body: &str) -> Result<Response, String> {
    Ok(Response {
        status: status.to_string(),
        content_type: content_type.to_string(),
        body: body.to_string(),
    })
}

/// Serialises every handler that reads or writes the UI state files or spawns a job. Only the
/// read-only views (dashboard, file, entity) run concurrently, which is what A4 needs: one
/// stalled or slow request no longer blocks the rest of the dashboard.
static STATE_LOCK: Mutex<()> = Mutex::new(());

fn lock_state() -> MutexGuard<'static, ()> {
    STATE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Releases its slot even if the connection thread unwinds.
struct InFlightGuard(Arc<AtomicUsize>);

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Where the token is left for the operator. Deliberately NOT under the data dir: /file?path=
/// serves the data dir unauthenticated, and the project's own check script points the server's
/// stdout at data/ui-check/ui-serve.log, so anything printed there is one request away from being
/// handed back. Only the path is printed.
fn token_file_path() -> PathBuf {
    if let Some(dir) = std::env::var_os("XDG_RUNTIME_DIR") {
        return PathBuf::from(dir).join("tool-ui-token");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home)
            .join(".cache")
            .join("tool")
            .join("ui-token");
    }
    std::env::temp_dir().join(format!("tool-ui-token-{}", std::process::id()))
}

fn write_token_file(path: &Path, token: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("failed to create '{}': {e}", parent.display()))?;
    }
    let _ = fs::remove_file(path);
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("failed to create token file '{}': {e}", path.display()))?;
    file.write_all(token.as_bytes())
        .map_err(|e| format!("failed to write token file '{}': {e}", path.display()))
}

fn generate_token() -> Result<String, String> {
    let mut file = fs::File::open("/dev/urandom")
        .map_err(|e| format!("failed to open /dev/urandom for the UI token: {e}"))?;
    let mut bytes = [0u8; 32];
    file.read_exact(&mut bytes)
        .map_err(|e| format!("failed to read /dev/urandom for the UI token: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

fn ui_security(bind: &str) -> Result<UiSecurity, String> {
    let allowed_hosts = match std::env::var("TOOL_UI_ALLOWED_HOSTS") {
        Ok(value) if !value.trim().is_empty() => value
            .split(',')
            .map(|h| h.trim().to_ascii_lowercase())
            .filter(|h| !h.is_empty())
            .collect(),
        _ => allowed_hosts_for_bind(bind).ok_or_else(|| {
            format!(
                "'{bind}' has no host allowlist to derive; the dashboard spawns build and fuzzing \
                 jobs, so binding it beyond loopback needs TOOL_UI_ALLOWED_HOSTS=<host[:port],...> \
                 set explicitly"
            )
        })?,
    };
    let token = match std::env::var("TOOL_UI_TOKEN") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => generate_token()?,
    };
    Ok(UiSecurity {
        token,
        allowed_hosts,
    })
}

pub(crate) fn run_ui_server(app_paths: &AppPaths, bind: &str) -> Result<(), String> {
    let security = Arc::new(ui_security(bind)?);
    let token_path = token_file_path();
    write_token_file(&token_path, &security.token)?;

    let listener = TcpListener::bind(bind).map_err(|e| format!("failed to bind '{bind}': {e}"))?;
    println!("[ui] listening on http://{bind}");
    println!("[ui] token file: {}", token_path.display());
    println!(
        "[ui] control endpoints require header 'X-Tool-Token: <that file>' and a same-origin request"
    );
    println!(
        "[ui] endpoints: /healthz, /dashboard.json, /dashboard.html, /file?path=..., /control/status, /replay/status, /target/status, /target/build/status"
    );

    let paths = Arc::new(app_paths.clone());
    let in_flight = Arc::new(AtomicUsize::new(0));

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ui] accept error: {e}");
                continue;
            }
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(WRITE_TIMEOUT_SECS)));

        if in_flight.load(Ordering::SeqCst) >= MAX_IN_FLIGHT_CONNECTIONS {
            let _ = write_response(
                &mut stream,
                "503 Service Unavailable",
                "text/plain; charset=utf-8",
                "too many connections\n",
            );
            continue;
        }
        in_flight.fetch_add(1, Ordering::SeqCst);
        let guard = InFlightGuard(Arc::clone(&in_flight));
        let paths = Arc::clone(&paths);
        let security = Arc::clone(&security);
        if let Err(e) = thread::Builder::new()
            .name("ui-conn".to_string())
            .spawn(move || {
                let _guard = guard;
                if let Err(e) = handle_connection(&paths, &security, &mut stream) {
                    eprintln!("[ui] request error: {e}");
                }
            })
        {
            eprintln!("[ui] failed to spawn connection thread: {e}");
        }
    }
    Ok(())
}

/// A4: the request head has to be read in full before anything is decided from it, so that a
/// head split across TCP segments does not lose its headers, and it has to be bounded so that a
/// client that never sends the blank line cannot make the server buffer without limit.
const MAX_REQUEST_HEAD_BYTES: usize = 32 * 1024;
/// The read timeout bounds a single read syscall, not the connection, so a client that dribbles a
/// byte just inside it can hold a thread and one of the in-flight slots indefinitely. The head has
/// its own wall-clock budget.
pub(crate) const HEAD_DEADLINE: Duration = Duration::from_secs(10);

struct RequestHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

/// `Ok(None)` means the peer closed without sending a byte - a browser preconnect, not an
/// error worth logging.
fn read_request_head<R: Read>(
    reader: &mut R,
    max_bytes: usize,
    deadline: Duration,
) -> Result<Option<String>, String> {
    let started = Instant::now();
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        if head_terminator(&head).is_some() {
            break;
        }
        if head.len() >= max_bytes {
            return Err(format!("request head exceeds {max_bytes} bytes"));
        }
        if started.elapsed() > deadline {
            return Err(format!("request head not complete within {deadline:?}"));
        }
        let read = reader
            .read(&mut buf)
            .map_err(|e| format!("failed to read request: {e}"))?;
        if read == 0 {
            if head.is_empty() {
                return Ok(None);
            }
            return Err("request head ended before the blank line".to_string());
        }
        head.extend_from_slice(&buf[..read]);
    }
    let end = head_terminator(&head).unwrap_or(head.len());
    Ok(Some(String::from_utf8_lossy(&head[..end]).into_owned()))
}

/// Returns the offset just past the blank line that ends the head, accepting both CRLF and the
/// bare-LF form some clients send.
fn head_terminator(head: &[u8]) -> Option<usize> {
    if let Some(end) = head
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
    {
        return Some(end);
    }
    // A bare LF pair ends the head only for a client that speaks bare LF throughout. Honouring it
    // inside a CRLF head would let `X-Pad: \n\n` hide every header after it.
    if head.contains(&b'\r') {
        return None;
    }
    head.windows(2).position(|w| w == b"\n\n").map(|i| i + 2)
}

fn parse_request_head(head: &str) -> Option<RequestHead> {
    let mut lines = head.lines();
    let first_line = lines.next()?;
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_string();
    let path = parts.next().unwrap_or("/").to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    Some(RequestHead {
        method,
        path,
        headers,
    })
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k == name)
        .map(|(_, v)| v.as_str())
}

/// A3: every mutating endpoint was reachable with no authentication, no CSRF token and no origin
/// check, so any page the user had open could start or stop a fuzzing run and spawn build scripts
/// against the dashboard. /control/start and /control/stop have no browser client at all - the
/// template never calls them - so the endpoint with the largest blast radius is gated hardest at
/// no cost to the UI.
pub(crate) struct UiSecurity {
    token: String,
    /// A FIXED allowlist. Comparing Origin against the Host the caller sent would match by
    /// construction under DNS rebinding, and a rebound page is same-origin, so it could simply
    /// read the token out of /dashboard.html and use it.
    allowed_hosts: Vec<String>,
}

/// The loopback spellings a browser may send for a loopback bind. Returns None when the bind has
/// no safe allowlist to derive - binding the control plane to every interface is a decision the
/// operator has to make explicitly.
fn allowed_hosts_for_bind(bind: &str) -> Option<Vec<String>> {
    let (host, port) = match bind.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => (h, p),
        _ => return None,
    };
    let host = host
        .trim_matches(|c| c == '[' || c == ']')
        .to_ascii_lowercase();
    if host.is_empty() || host == "0.0.0.0" || host == "::" || host == "*" {
        return None;
    }
    let mut names = vec![
        host.clone(),
        "127.0.0.1".to_string(),
        "localhost".to_string(),
    ];
    if !names.iter().any(|n| n == "::1") {
        names.push("::1".to_string());
    }
    let mut out = Vec::new();
    for name in names {
        let bare = if name.contains(':') {
            format!("[{name}]")
        } else {
            name.clone()
        };
        if !out.contains(&bare) {
            out.push(bare.clone());
        }
        let with_port = format!("{bare}:{port}");
        if !out.contains(&with_port) {
            out.push(with_port);
        }
    }
    Some(out)
}

/// Only the endpoints that change something need the token. The two target status GETs are on the
/// list because they reconcile and rewrite their state file, which is the very guard the token is
/// there to protect, and a plain GET is reachable cross-origin with no headers at all.
fn route_changes_state(method: &str, path: &str) -> bool {
    let path = path.split('?').next().unwrap_or(path);
    if method == "POST" {
        return path.starts_with("/control/")
            || path.starts_with("/replay/")
            || path.starts_with("/target/");
    }
    matches!(path, "/target/status" | "/target/build/status")
}

fn secret_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn origin_is_ours(value: &str, allowed_hosts: &[String]) -> bool {
    let rest = match value.split_once("://") {
        Some(("http", rest)) | Some(("https", rest)) => rest,
        _ => return false,
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
    allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(authority))
}

fn authorize(security: &UiSecurity, request: &RequestHead) -> Result<(), &'static str> {
    // Checked on every route, reads included: /dashboard.html carries the token and /file serves
    // the data dir, so a rebound origin must not reach them either.
    let host = header_value(&request.headers, "host").unwrap_or_default();
    if !security
        .allowed_hosts
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
    {
        return Err("host_not_allowed");
    }
    if !route_changes_state(&request.method, &request.path) {
        return Ok(());
    }
    for header in ["origin", "referer"] {
        if let Some(value) = header_value(&request.headers, header) {
            if !value.is_empty() && !origin_is_ours(value, &security.allowed_hosts) {
                return Err("cross_origin");
            }
        }
    }
    let presented = header_value(&request.headers, "x-tool-token").unwrap_or_default();
    if !secret_eq(presented, &security.token) {
        return Err("missing_or_bad_token");
    }
    Ok(())
}

fn handle_connection(
    app_paths: &AppPaths,
    security: &UiSecurity,
    stream: &mut TcpStream,
) -> Result<(), String> {
    let Some(head) = read_request_head(stream, MAX_REQUEST_HEAD_BYTES, HEAD_DEADLINE)? else {
        return Ok(());
    };
    let Some(request) = parse_request_head(&head) else {
        return Ok(());
    };
    let response = respond_to_request(app_paths, security, &request);
    write_response(
        stream,
        &response.status,
        &response.content_type,
        &response.body,
    )
}

/// Every failure used to close the connection with zero bytes, so a caller saw "empty reply from
/// server" instead of a status - for an unreadable file, a path outside the data dir, or a
/// request head that never arrived.
fn respond_to_request(
    app_paths: &AppPaths,
    security: &UiSecurity,
    request: &RequestHead,
) -> Response {
    if let Err(reason) = authorize(security, request) {
        return Response {
            status: "403 Forbidden".to_string(),
            content_type: "application/json; charset=utf-8".to_string(),
            body: format!("{{\"error\":\"{reason}\"}}"),
        };
    }
    match route_request(app_paths, security, request) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("[ui] request error: {e}");
            Response {
                status: "500 Internal Server Error".to_string(),
                content_type: "application/json; charset=utf-8".to_string(),
                body: "{\"error\":\"internal_error\"}".to_string(),
            }
        }
    }
}

fn route_request(
    app_paths: &AppPaths,
    security: &UiSecurity,
    request: &RequestHead,
) -> Result<Response, String> {
    let method = request.method.as_str();
    let raw_path = request.path.as_str();

    if raw_path.starts_with("/control/") {
        return handle_control_route(app_paths, method, raw_path);
    }
    if raw_path.starts_with("/replay/") {
        return handle_replay_route(app_paths, method, raw_path);
    }
    if raw_path.starts_with("/target/") {
        return handle_target_route(app_paths, method, raw_path);
    }

    if method != "GET" {
        return respond(
            "405 Method Not Allowed",
            "text/plain; charset=utf-8",
            "method not allowed\n",
        );
    }

    if raw_path.starts_with("/file?") {
        return handle_file_view(app_paths, raw_path);
    }
    if let Some(asset_name) = raw_path.strip_prefix("/assets/") {
        return handle_asset_view(asset_name);
    }
    if let Some(id) = raw_path.strip_prefix("/run/") {
        return handle_entity_view(app_paths, "run", id);
    }
    if let Some(id) = raw_path.strip_prefix("/triage/") {
        return handle_entity_view(app_paths, "triage", id);
    }
    if let Some(id) = raw_path.strip_prefix("/report/") {
        return handle_entity_view(app_paths, "report", id);
    }
    if let Some(id) = raw_path.strip_prefix("/coverage/") {
        return handle_entity_view(app_paths, "coverage", id);
    }

    match raw_path {
        "/healthz" => respond("200 OK", "text/plain; charset=utf-8", "ok\n"),
        "/dashboard.json" => {
            let snap = collect_dashboard_snapshot(app_paths)?;
            let body = super::dashboard::render_dashboard_json(&snap);
            respond("200 OK", "application/json; charset=utf-8", &body)
        }
        "/dashboard.html" | "/" => {
            let snap = collect_dashboard_snapshot(app_paths)?;
            // Substituted here and only here: render_dashboard_html also backs
            // `tool dashboard --format html --out <path>`, which writes to a file that is often
            // inside the data dir and therefore readable through /file?path=.
            let body = super::dashboard::render_dashboard_html(&snap)
                .replace("{{ui_csrf_token}}", &html_escape(&security.token));
            respond("200 OK", "text/html; charset=utf-8", &body)
        }
        _ => respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    }
}

fn handle_control_route(
    app_paths: &AppPaths,
    method: &str,
    raw_path: &str,
) -> Result<Response, String> {
    let _state = lock_state();
    reap_children();
    match (method, raw_path.split('?').next().unwrap_or(raw_path)) {
        ("GET", "/control/status") => handle_control_status(app_paths),
        ("POST", "/control/start") => handle_control_start(app_paths, raw_path),
        ("POST", "/control/stop") => handle_control_stop(app_paths),
        _ => respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    }
}

fn handle_replay_route(
    app_paths: &AppPaths,
    method: &str,
    raw_path: &str,
) -> Result<Response, String> {
    let _state = lock_state();
    reap_children();
    match (method, raw_path.split('?').next().unwrap_or(raw_path)) {
        ("GET", "/replay/status") => handle_replay_status(app_paths),
        ("POST", "/replay/start") => handle_replay_start(app_paths, raw_path),
        ("POST", "/replay/stop") => handle_replay_stop(app_paths),
        _ => respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    }
}

fn handle_target_route(
    app_paths: &AppPaths,
    method: &str,
    raw_path: &str,
) -> Result<Response, String> {
    let _state = lock_state();
    reap_children();
    match (method, raw_path.split('?').next().unwrap_or(raw_path)) {
        ("GET", "/target/build/status") => handle_target_build_status(app_paths),
        ("POST", "/target/build/start") => handle_target_build_start(app_paths, raw_path),
        ("POST", "/target/build/stop") => handle_target_build_stop(app_paths),
        ("GET", "/target/status") => handle_target_status(app_paths),
        ("POST", "/target/prepare") => handle_target_prepare(app_paths, raw_path),
        ("POST", "/target/stop") => handle_target_stop(app_paths),
        _ => respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    }
}

fn handle_control_status(app_paths: &AppPaths) -> Result<Response, String> {
    let state = read_control_state(app_paths)?;
    let running = running_job_pid(state.pid, state.pid_start).is_some();
    let mut body = String::new();
    body.push_str("{\"schema_version\":\"1.0\"");
    body.push_str(&format!(
        ",\"running\":{}",
        if running { "true" } else { "false" }
    ));
    if let Some(pid) = state.pid {
        body.push_str(&format!(",\"pid\":{pid}"));
    } else {
        body.push_str(",\"pid\":null");
    }
    if let Some(started_at) = state.started_at {
        body.push_str(&format!(",\"started_at\":{started_at}"));
    } else {
        body.push_str(",\"started_at\":null");
    }
    body.push_str(&format!(",\"duration_seconds\":{}", state.duration_seconds));
    body.push_str(&format!(",\"target\":\"{}\"", json_escape(&state.target)));
    body.push_str(&format!(",\"backend\":\"{}\"", json_escape(&state.backend)));
    body.push_str(&format!(
        ",\"log_file\":\"{}\"",
        json_escape(&state.log_file)
    ));
    body.push('}');
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_replay_status(app_paths: &AppPaths) -> Result<Response, String> {
    let state = read_replay_state(app_paths)?;
    let running = running_job_pid(state.pid, state.pid_start).is_some();
    let summary_path = if running {
        String::new()
    } else {
        extract_replay_summary_path(&state.log_file).unwrap_or_default()
    };
    let verdict = if running {
        String::new()
    } else {
        extract_replay_verdict(&state.log_file).unwrap_or_default()
    };
    let mut body = String::new();
    body.push_str("{\"schema_version\":\"1.0\"");
    body.push_str(&format!(
        ",\"running\":{}",
        if running { "true" } else { "false" }
    ));
    if let Some(pid) = state.pid {
        body.push_str(&format!(",\"pid\":{pid}"));
    } else {
        body.push_str(",\"pid\":null");
    }
    if let Some(started_at) = state.started_at {
        body.push_str(&format!(",\"started_at\":{started_at}"));
    } else {
        body.push_str(",\"started_at\":null");
    }
    body.push_str(&format!(",\"target\":\"{}\"", json_escape(&state.target)));
    body.push_str(&format!(",\"input\":\"{}\"", json_escape(&state.input)));
    body.push_str(&format!(
        ",\"log_file\":\"{}\"",
        json_escape(&state.log_file)
    ));
    body.push_str(&format!(
        ",\"summary_path\":\"{}\"",
        json_escape(&summary_path)
    ));
    body.push_str(&format!(",\"verdict\":\"{}\"", json_escape(&verdict)));
    body.push('}');
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_status(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_target_prepare_state(app_paths)?;
    let running = running_job_pid(state.pid, state.pid_start).is_some();
    if !running
        && state.pid.is_some()
        && matches!(state.last_result.as_str(), "running" | "starting")
    {
        state.pid = None;
        state.pid_start = None;
        state.started_at = None;
        if log_contains(&state.log_file, "[prepare-target] done") {
            state.last_result = "success".to_string();
            state.last_message = "prepare target completed".to_string();
        } else {
            state.last_result = "error".to_string();
            state.last_message = extract_target_error_message(&state.log_file)
                .unwrap_or_else(|| "target prepare failed".to_string());
        }
        write_target_prepare_state(app_paths, &state)?;
    }
    let meta_path = if running {
        String::new()
    } else {
        extract_log_value(&state.log_file, "meta: ").unwrap_or_default()
    };
    let downloaded_file = if running {
        String::new()
    } else {
        extract_log_value(&state.log_file, "file: ").unwrap_or_default()
    };
    let sha256 = if running {
        String::new()
    } else {
        extract_log_value(&state.log_file, "sha256: ").unwrap_or_default()
    };
    let mut body = String::new();
    body.push_str("{\"schema_version\":\"1.0\"");
    body.push_str(&format!(
        ",\"running\":{}",
        if running { "true" } else { "false" }
    ));
    if let Some(pid) = state.pid {
        body.push_str(&format!(",\"pid\":{pid}"));
    } else {
        body.push_str(",\"pid\":null");
    }
    if let Some(started_at) = state.started_at {
        body.push_str(&format!(",\"started_at\":{started_at}"));
    } else {
        body.push_str(",\"started_at\":null");
    }
    body.push_str(&format!(",\"target\":\"{}\"", json_escape(&state.target)));
    body.push_str(&format!(",\"version\":\"{}\"", json_escape(&state.version)));
    body.push_str(&format!(
        ",\"source_url\":\"{}\"",
        json_escape(&state.source_url)
    ));
    body.push_str(&format!(
        ",\"log_file\":\"{}\"",
        json_escape(&state.log_file)
    ));
    body.push_str(&format!(",\"meta_path\":\"{}\"", json_escape(&meta_path)));
    body.push_str(&format!(
        ",\"downloaded_file\":\"{}\"",
        json_escape(&downloaded_file)
    ));
    body.push_str(&format!(",\"sha256\":\"{}\"", json_escape(&sha256)));
    body.push_str(&format!(
        ",\"result\":\"{}\"",
        json_escape(if running {
            "running"
        } else {
            &state.last_result
        })
    ));
    body.push_str(&format!(
        ",\"message\":\"{}\"",
        json_escape(if running {
            "target prepare running"
        } else {
            &state.last_message
        })
    ));
    body.push('}');
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_build_status(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_target_build_state(app_paths)?;
    let running = running_job_pid(state.pid, state.pid_start).is_some();
    if !running
        && state.pid.is_some()
        && matches!(state.last_result.as_str(), "running" | "starting")
    {
        state.pid = None;
        state.pid_start = None;
        state.started_at = None;
        if log_contains(&state.log_file, "[target-build] done") {
            state.last_result = "success".to_string();
            state.last_message = "target build completed".to_string();
        } else {
            state.last_result = "error".to_string();
            state.last_message = extract_target_error_message(&state.log_file)
                .unwrap_or_else(|| "target build failed".to_string());
        }
        write_target_build_state(app_paths, &state)?;
    }
    let build_dir = if running {
        String::new()
    } else {
        extract_log_value(&state.log_file, "build_dir: ").unwrap_or_default()
    };
    let artifact = if running {
        String::new()
    } else {
        extract_log_value(&state.log_file, "artifact: ").unwrap_or_default()
    };
    let mut body = String::new();
    body.push_str("{\"schema_version\":\"1.0\"");
    body.push_str(&format!(
        ",\"running\":{}",
        if running { "true" } else { "false" }
    ));
    if let Some(pid) = state.pid {
        body.push_str(&format!(",\"pid\":{pid}"));
    } else {
        body.push_str(",\"pid\":null");
    }
    if let Some(started_at) = state.started_at {
        body.push_str(&format!(",\"started_at\":{started_at}"));
    } else {
        body.push_str(",\"started_at\":null");
    }
    body.push_str(&format!(",\"target\":\"{}\"", json_escape(&state.target)));
    body.push_str(&format!(",\"version\":\"{}\"", json_escape(&state.version)));
    body.push_str(&format!(
        ",\"log_file\":\"{}\"",
        json_escape(&state.log_file)
    ));
    body.push_str(&format!(",\"build_dir\":\"{}\"", json_escape(&build_dir)));
    body.push_str(&format!(",\"artifact\":\"{}\"", json_escape(&artifact)));
    body.push_str(&format!(
        ",\"result\":\"{}\"",
        json_escape(if running {
            "running"
        } else {
            &state.last_result
        })
    ));
    body.push_str(&format!(
        ",\"message\":\"{}\"",
        json_escape(if running {
            "target build running"
        } else {
            &state.last_message
        })
    ));
    body.push('}');
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_replay_start(app_paths: &AppPaths, raw_path: &str) -> Result<Response, String> {
    let current = read_replay_state(app_paths)?;
    if running_job_pid(current.pid, current.pid_start).is_some() {
        return respond(
            "409 Conflict",
            "application/json; charset=utf-8",
            "{\"error\":\"replay_already_running\"}",
        );
    }

    let triage_id = match extract_query_param(raw_path, "triage_id") {
        Some(value) => url_decode(value).ok_or_else(|| "invalid url encoding".to_string())?,
        None => String::new(),
    };
    let input_value = extract_query_param(raw_path, "input").unwrap_or("");
    if triage_id.is_empty() && input_value.is_empty() {
        return bad_request("missing_input");
    }
    let input_path = if triage_id.is_empty() {
        let decoded_input =
            url_decode(input_value).ok_or_else(|| "invalid url encoding".to_string())?;
        if !is_safe_query_value(&decoded_input) {
            return bad_request("invalid_input");
        }
        resolve_replay_input(app_paths, &decoded_input)
    } else {
        resolve_triage_input(app_paths, &triage_id)
    };
    let Some(input_path) = input_path else {
        return bad_request("invalid_input");
    };

    let target = match extract_query_param(raw_path, "target").unwrap_or("onnx") {
        "onnx" | "gguf" | "safetensors" => {
            extract_query_param(raw_path, "target").unwrap_or("onnx")
        }
        _ => {
            return respond(
                "400 Bad Request",
                "application/json; charset=utf-8",
                "{\"error\":\"invalid_target\"}",
            )
        }
    };
    let repro_retries =
        match bounded_count_param(extract_query_param(raw_path, "repro_retries"), 1, 100, "3") {
            Some(value) => value,
            None => return bad_request("invalid_repro_retries"),
        };
    let Some(timeout_sec) = positive_timeout_sec_param(extract_query_param(raw_path, "timeout_sec"))
    else {
        return bad_request("invalid_timeout_sec");
    };

    let replay_dir = app_paths.data_dir.join("ui-replay");
    fs::create_dir_all(&replay_dir).map_err(|e| {
        format!(
            "failed to create replay dir '{}': {e}",
            replay_dir.display()
        )
    })?;
    let log_path = replay_dir.join("replay.log");
    let log_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
        .map_err(|e| format!("failed to open replay log '{}': {e}", log_path.display()))?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| format!("failed to clone replay log handle: {e}"))?;

    let cwd = std::env::current_dir().map_err(|e| format!("failed to get current dir: {e}"))?;
    let mut cmd = tool_child_command(app_paths)?;
    cmd.current_dir(&cwd)
        .arg("triage")
        .arg("--target")
        .arg(target)
        .arg("--input")
        .arg(&input_path)
        .arg("--repro-retries")
        .arg(repro_retries)
        .arg("--timeout-sec")
        .arg(timeout_sec)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));
    let child = spawn_job(&mut cmd).map_err(|e| format!("failed to start replay triage: {e}"))?;
    let pid = child.id();
    register_child(child);

    let state = ReplayState {
        pid: Some(pid),
        pid_start: process_start_ticks(pid),
        started_at: Some(now_unix()),
        target: target.to_string(),
        input: input_path.display().to_string(),
        log_file: log_path.display().to_string(),
    };
    write_replay_state(app_paths, &state)?;

    let body = format!(
        "{{\"ok\":true,\"running\":true,\"pid\":{},\"target\":\"{}\",\"input\":\"{}\"}}",
        pid,
        json_escape(target),
        json_escape(&state.input),
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_prepare(app_paths: &AppPaths, raw_path: &str) -> Result<Response, String> {
    let current = read_target_prepare_state(app_paths)?;
    if running_job_pid(current.pid, current.pid_start).is_some() {
        return respond(
            "409 Conflict",
            "application/json; charset=utf-8",
            "{\"error\":\"target_prepare_already_running\"}",
        );
    }

    let target = match extract_query_param(raw_path, "target").unwrap_or("onnx") {
        "onnx" | "gguf" | "safetensors" => {
            extract_query_param(raw_path, "target").unwrap_or("onnx")
        }
        _ => {
            return respond(
                "400 Bad Request",
                "application/json; charset=utf-8",
                "{\"error\":\"invalid_target\"}",
            )
        }
    };
    let version = match extract_query_param(raw_path, "version") {
        Some(value) => url_decode(value).ok_or_else(|| "invalid version encoding".to_string())?,
        None => String::new(),
    };
    let version = version.trim().to_string();
    if !is_safe_version(&version) {
        return bad_request("invalid_version");
    }
    let source_url = match extract_query_param(raw_path, "source_url") {
        Some(value) => {
            url_decode(value).ok_or_else(|| "invalid source url encoding".to_string())?
        }
        None => String::new(),
    };
    let source_url = source_url.trim().to_string();
    if !is_safe_source_url(&source_url) {
        return bad_request("invalid_source_url");
    }

    let target_dir = app_paths.data_dir.join("ui-target");
    fs::create_dir_all(&target_dir).map_err(|e| {
        format!(
            "failed to create target dir '{}': {e}",
            target_dir.display()
        )
    })?;
    let log_path = target_dir.join("prepare-target.log");
    let log_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
        .map_err(|e| format!("failed to open target log '{}': {e}", log_path.display()))?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| format!("failed to clone target log handle: {e}"))?;

    let cwd = std::env::current_dir().map_err(|e| format!("failed to get current dir: {e}"))?;
    let mut cmd = tool_child_command(app_paths)?;
    cmd.current_dir(&cwd)
        .arg("prepare-target")
        .arg("--target")
        .arg(target);
    if !version.is_empty() {
        cmd.arg("--version").arg(&version);
    }
    if !source_url.is_empty() {
        cmd.arg("--source-url").arg(&source_url);
    }
    cmd.stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));

    let child =
        spawn_job(&mut cmd).map_err(|e| format!("failed to spawn target prepare command: {e}"))?;
    let pid = child.id();
    register_child(child);

    let state = TargetPrepareState {
        pid: Some(pid),
        pid_start: process_start_ticks(pid),
        started_at: Some(now_unix()),
        target: target.to_string(),
        version,
        source_url,
        log_file: log_path.display().to_string(),
        last_result: "running".to_string(),
        last_message: "target prepare running".to_string(),
    };
    write_target_prepare_state(app_paths, &state)?;

    let body = format!(
        "{{\"ok\":true,\"pid\":{},\"target\":\"{}\",\"version\":\"{}\"}}",
        pid,
        json_escape(target),
        json_escape(&state.version)
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_build_start(app_paths: &AppPaths, raw_path: &str) -> Result<Response, String> {
    let current = read_target_build_state(app_paths)?;
    if running_job_pid(current.pid, current.pid_start).is_some() {
        return respond(
            "409 Conflict",
            "application/json; charset=utf-8",
            "{\"error\":\"target_build_already_running\"}",
        );
    }

    let target = match extract_query_param(raw_path, "target").unwrap_or("gguf") {
        "gguf" | "onnx" | "safetensors" => {
            extract_query_param(raw_path, "target").unwrap_or("gguf")
        }
        _ => {
            return respond(
                "400 Bad Request",
                "application/json; charset=utf-8",
                "{\"error\":\"invalid_target\"}",
            )
        }
    };
    let version = match extract_query_param(raw_path, "version") {
        Some(value) => url_decode(value).ok_or_else(|| "invalid version encoding".to_string())?,
        None => latest_prepared_version(app_paths, target).unwrap_or_default(),
    };
    let version = version.trim().to_string();
    if !is_safe_version(&version) {
        return bad_request("invalid_version");
    }

    let build_dir = app_paths.data_dir.join("ui-target-build");
    fs::create_dir_all(&build_dir).map_err(|e| {
        format!(
            "failed to create target build dir '{}': {e}",
            build_dir.display()
        )
    })?;
    let log_path = build_dir.join("target-build.log");
    let log_file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&log_path)
        .map_err(|e| {
            format!(
                "failed to open target build log '{}': {e}",
                log_path.display()
            )
        })?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| format!("failed to clone target build log handle: {e}"))?;

    let cwd = std::env::current_dir().map_err(|e| format!("failed to get current dir: {e}"))?;
    let mut cmd = Command::new("bash");
    cmd.current_dir(&cwd)
        .arg("scripts/build_prepared_target.sh")
        .arg(&app_paths.data_dir)
        .arg(target)
        .arg(&version)
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));

    let child =
        spawn_job(&mut cmd).map_err(|e| format!("failed to spawn target build command: {e}"))?;
    let pid = child.id();
    register_child(child);

    let state = TargetBuildState {
        pid: Some(pid),
        pid_start: process_start_ticks(pid),
        started_at: Some(now_unix()),
        target: target.to_string(),
        version,
        log_file: log_path.display().to_string(),
        last_result: "running".to_string(),
        last_message: "target build running".to_string(),
    };
    write_target_build_state(app_paths, &state)?;

    let body = format!(
        "{{\"ok\":true,\"pid\":{},\"target\":\"{}\",\"version\":\"{}\"}}",
        pid,
        json_escape(target),
        json_escape(&state.version)
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_replay_stop(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_replay_state(app_paths)?;
    let mut was_running = false;
    if let Some(pid) = running_job_pid(state.pid, state.pid_start) {
        was_running = signal_job(pid, SIGTERM);
    }
    state.pid = None;
    state.pid_start = None;
    write_replay_state(app_paths, &state)?;
    let body = format!(
        "{{\"ok\":true,\"running\":false,\"stopped\":{}}}",
        if was_running { "true" } else { "false" }
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_stop(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_target_prepare_state(app_paths)?;
    if let Some(pid) = running_job_pid(state.pid, state.pid_start) {
        signal_job(pid, SIGTERM);
    }
    state.pid = None;
    state.pid_start = None;
    state.started_at = None;
    state.last_result = "stopped".to_string();
    state.last_message = "target prepare stopped".to_string();
    write_target_prepare_state(app_paths, &state)?;
    let body = format!(
        "{{\"ok\":true,\"target\":\"{}\"}}",
        json_escape(&state.target)
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_target_build_stop(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_target_build_state(app_paths)?;
    if let Some(pid) = running_job_pid(state.pid, state.pid_start) {
        signal_job(pid, SIGTERM);
    }
    state.pid = None;
    state.pid_start = None;
    state.started_at = None;
    state.last_result = "stopped".to_string();
    state.last_message = "target build stopped".to_string();
    write_target_build_state(app_paths, &state)?;
    let body = format!(
        "{{\"ok\":true,\"target\":\"{}\"}}",
        json_escape(&state.target)
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_control_start(app_paths: &AppPaths, raw_path: &str) -> Result<Response, String> {
    let current = read_control_state(app_paths)?;
    if running_job_pid(current.pid, current.pid_start).is_some() {
        return respond(
            "409 Conflict",
            "application/json; charset=utf-8",
            "{\"error\":\"already_running\"}",
        );
    }

    let target = extract_query_param(raw_path, "target").unwrap_or("onnx");
    let backend = extract_query_param(raw_path, "backend").unwrap_or("local-harness");
    let Some(duration_seconds) = bounded_count_param(
        extract_query_param(raw_path, "duration_seconds"),
        1,
        MAX_DURATION_SECONDS,
        "3600",
    ) else {
        return bad_request("invalid_duration_seconds");
    };
    let Some(workers) = bounded_count_param(extract_query_param(raw_path, "workers"), 1, 256, "2")
    else {
        return bad_request("invalid_workers");
    };
    let Some(timeout_sec) = positive_timeout_sec_param(extract_query_param(raw_path, "timeout_sec"))
    else {
        return bad_request("invalid_timeout_sec");
    };
    let Some(restart_limit) =
        bounded_count_param(extract_query_param(raw_path, "restart_limit"), 0, 1000, "1")
    else {
        return bad_request("invalid_restart_limit");
    };

    if !matches!(target, "onnx" | "gguf" | "safetensors") {
        return respond(
            "400 Bad Request",
            "application/json; charset=utf-8",
            "{\"error\":\"invalid_target\"}",
        );
    }
    if !matches!(backend, "local-harness" | "aflpp" | "libfuzzer") {
        return respond(
            "400 Bad Request",
            "application/json; charset=utf-8",
            "{\"error\":\"invalid_backend\"}",
        );
    }

    let control_dir = app_paths.data_dir.join("ui-control");
    fs::create_dir_all(&control_dir).map_err(|e| {
        format!(
            "failed to create control dir '{}': {e}",
            control_dir.display()
        )
    })?;
    let log_path = control_dir.join("run-backend-loop.log");
    let log_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| format!("failed to open control log '{}': {e}", log_path.display()))?;
    let log_file_err = log_file
        .try_clone()
        .map_err(|e| format!("failed to clone control log handle: {e}"))?;

    let cwd = std::env::current_dir().map_err(|e| format!("failed to get current dir: {e}"))?;
    let tool_bin =
        std::env::current_exe().map_err(|e| format!("failed to resolve current exe: {e}"))?;
    let corpus_dir = app_paths.seeds_dir.join(target);
    let mut cmd = Command::new("bash");
    cmd.arg("scripts/run_backend_loop.sh")
        .current_dir(&cwd)
        .env("WORKDIR", cwd.as_os_str())
        .env("DATA_DIR", app_paths.data_dir.as_os_str())
        .env("TOOL_BIN", tool_bin.as_os_str())
        .env("TARGET", target)
        .env("BACKEND", backend)
        .env("CORPUS_DIR", corpus_dir.as_os_str())
        .env("DURATION_SECONDS", duration_seconds)
        .env("WORKERS", workers)
        .env("TIMEOUT_SEC", timeout_sec)
        .env("RESTART_LIMIT", restart_limit)
        .env("LOG_DIR", control_dir.as_os_str())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::from(log_file_err));
    if let Some(max_jobs) = extract_query_param(raw_path, "max_jobs") {
        let Some(checked) = bounded_count_param(Some(max_jobs), 1, MAX_JOBS_LIMIT, "") else {
            return bad_request("invalid_max_jobs");
        };
        cmd.env("MAX_JOBS", checked);
    }
    let child = spawn_job(&mut cmd).map_err(|e| format!("failed to start run loop script: {e}"))?;
    let pid = child.id();
    register_child(child);

    let state = ControlState {
        pid: Some(pid),
        pid_start: process_start_ticks(pid),
        started_at: Some(now_unix()),
        duration_seconds: duration_seconds.parse::<u64>().unwrap_or(3600),
        target: target.to_string(),
        backend: backend.to_string(),
        log_file: log_path.display().to_string(),
    };
    write_control_state(app_paths, &state)?;

    let body = format!(
        "{{\"ok\":true,\"running\":true,\"pid\":{},\"target\":\"{}\",\"backend\":\"{}\"}}",
        pid,
        json_escape(target),
        json_escape(backend),
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

fn handle_control_stop(app_paths: &AppPaths) -> Result<Response, String> {
    let mut state = read_control_state(app_paths)?;
    let mut was_running = false;
    if let Some(pid) = running_job_pid(state.pid, state.pid_start) {
        was_running = signal_job(pid, SIGTERM);
    }
    state.pid = None;
    state.pid_start = None;
    write_control_state(app_paths, &state)?;
    let body = format!(
        "{{\"ok\":true,\"running\":false,\"stopped\":{}}}",
        if was_running { "true" } else { "false" }
    );
    respond("200 OK", "application/json; charset=utf-8", &body)
}

struct ControlState {
    pid: Option<u32>,
    /// Start time of `pid`, so a recycled pid cannot pass for our job.
    pid_start: Option<u64>,
    started_at: Option<u64>,
    duration_seconds: u64,
    target: String,
    backend: String,
    log_file: String,
}

struct ReplayState {
    pid: Option<u32>,
    /// Start time of `pid`, so a recycled pid cannot pass for our job.
    pid_start: Option<u64>,
    started_at: Option<u64>,
    target: String,
    input: String,
    log_file: String,
}

struct TargetPrepareState {
    pid: Option<u32>,
    /// Start time of `pid`, so a recycled pid cannot pass for our job.
    pid_start: Option<u64>,
    started_at: Option<u64>,
    target: String,
    version: String,
    source_url: String,
    log_file: String,
    last_result: String,
    last_message: String,
}

struct TargetBuildState {
    pid: Option<u32>,
    /// Start time of `pid`, so a recycled pid cannot pass for our job.
    pid_start: Option<u64>,
    started_at: Option<u64>,
    target: String,
    version: String,
    log_file: String,
    last_result: String,
    last_message: String,
}

fn read_control_state(app_paths: &AppPaths) -> Result<ControlState, String> {
    let state_path = app_paths.data_dir.join("ui-control").join("control.state");
    if !state_path.exists() {
        return Ok(ControlState {
            pid: None,
            pid_start: None,
            started_at: None,
            duration_seconds: 3600,
            target: "onnx".to_string(),
            backend: "local-harness".to_string(),
            log_file: app_paths
                .data_dir
                .join("ui-control")
                .join("run-backend-loop.log")
                .display()
                .to_string(),
        });
    }
    let content = fs::read_to_string(&state_path).map_err(|e| {
        format!(
            "failed to read control state '{}': {e}",
            state_path.display()
        )
    })?;
    let mut out = ControlState {
        pid: None,
        pid_start: None,
        started_at: None,
        duration_seconds: 3600,
        target: "onnx".to_string(),
        backend: "local-harness".to_string(),
        log_file: app_paths
            .data_dir
            .join("ui-control")
            .join("run-backend-loop.log")
            .display()
            .to_string(),
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "pid" => out.pid = v.parse::<u32>().ok(),
            "pid_start" => out.pid_start = v.parse::<u64>().ok(),
            "started_at" => out.started_at = v.parse::<u64>().ok(),
            "duration_seconds" => out.duration_seconds = v.parse::<u64>().unwrap_or(3600),
            "target" => out.target = decode_state_value(v),
            "backend" => out.backend = decode_state_value(v),
            "log_file" => out.log_file = decode_state_value(v),
            _ => {}
        }
    }
    Ok(out)
}

fn read_replay_state(app_paths: &AppPaths) -> Result<ReplayState, String> {
    let state_path = app_paths.data_dir.join("ui-replay").join("replay.state");
    if !state_path.exists() {
        return Ok(ReplayState {
            pid: None,
            pid_start: None,
            started_at: None,
            target: "onnx".to_string(),
            input: String::new(),
            log_file: app_paths
                .data_dir
                .join("ui-replay")
                .join("replay.log")
                .display()
                .to_string(),
        });
    }
    let content = fs::read_to_string(&state_path).map_err(|e| {
        format!(
            "failed to read replay state '{}': {e}",
            state_path.display()
        )
    })?;
    let mut out = ReplayState {
        pid: None,
        pid_start: None,
        started_at: None,
        target: "onnx".to_string(),
        input: String::new(),
        log_file: app_paths
            .data_dir
            .join("ui-replay")
            .join("replay.log")
            .display()
            .to_string(),
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "pid" => out.pid = v.parse::<u32>().ok(),
            "pid_start" => out.pid_start = v.parse::<u64>().ok(),
            "started_at" => out.started_at = v.parse::<u64>().ok(),
            "target" => out.target = decode_state_value(v),
            "input" => out.input = decode_state_value(v),
            "log_file" => out.log_file = decode_state_value(v),
            _ => {}
        }
    }
    Ok(out)
}

fn read_target_prepare_state(app_paths: &AppPaths) -> Result<TargetPrepareState, String> {
    let state_path = app_paths
        .data_dir
        .join("ui-target")
        .join("prepare-target.state");
    if !state_path.exists() {
        return Ok(TargetPrepareState {
            pid: None,
            pid_start: None,
            started_at: None,
            target: "onnx".to_string(),
            version: String::new(),
            source_url: String::new(),
            log_file: app_paths
                .data_dir
                .join("ui-target")
                .join("prepare-target.log")
                .display()
                .to_string(),
            last_result: "idle".to_string(),
            last_message: "ready".to_string(),
        });
    }
    let content = fs::read_to_string(&state_path).map_err(|e| {
        format!(
            "failed to read target prepare state '{}': {e}",
            state_path.display()
        )
    })?;
    let mut out = TargetPrepareState {
        pid: None,
        pid_start: None,
        started_at: None,
        target: "onnx".to_string(),
        version: String::new(),
        source_url: String::new(),
        log_file: app_paths
            .data_dir
            .join("ui-target")
            .join("prepare-target.log")
            .display()
            .to_string(),
        last_result: "idle".to_string(),
        last_message: "ready".to_string(),
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "pid" => out.pid = v.parse::<u32>().ok(),
            "pid_start" => out.pid_start = v.parse::<u64>().ok(),
            "started_at" => out.started_at = v.parse::<u64>().ok(),
            "target" => out.target = decode_state_value(v),
            "version" => out.version = decode_state_value(v),
            "source_url" => out.source_url = decode_state_value(v),
            "log_file" => out.log_file = decode_state_value(v),
            "last_result" => out.last_result = decode_state_value(v),
            "last_message" => out.last_message = decode_state_value(v),
            _ => {}
        }
    }
    Ok(out)
}

fn read_target_build_state(app_paths: &AppPaths) -> Result<TargetBuildState, String> {
    let state_path = app_paths
        .data_dir
        .join("ui-target-build")
        .join("target-build.state");
    if !state_path.exists() {
        return Ok(TargetBuildState {
            pid: None,
            pid_start: None,
            started_at: None,
            target: "gguf".to_string(),
            version: String::new(),
            log_file: app_paths
                .data_dir
                .join("ui-target-build")
                .join("target-build.log")
                .display()
                .to_string(),
            last_result: "idle".to_string(),
            last_message: "ready".to_string(),
        });
    }
    let content = fs::read_to_string(&state_path).map_err(|e| {
        format!(
            "failed to read target build state '{}': {e}",
            state_path.display()
        )
    })?;
    let mut out = TargetBuildState {
        pid: None,
        pid_start: None,
        started_at: None,
        target: "gguf".to_string(),
        version: String::new(),
        log_file: app_paths
            .data_dir
            .join("ui-target-build")
            .join("target-build.log")
            .display()
            .to_string(),
        last_result: "idle".to_string(),
        last_message: "ready".to_string(),
    };
    for line in content.lines() {
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        match k {
            "pid" => out.pid = v.parse::<u32>().ok(),
            "pid_start" => out.pid_start = v.parse::<u64>().ok(),
            "started_at" => out.started_at = v.parse::<u64>().ok(),
            "target" => out.target = decode_state_value(v),
            "version" => out.version = decode_state_value(v),
            "log_file" => out.log_file = decode_state_value(v),
            "last_result" => out.last_result = decode_state_value(v),
            "last_message" => out.last_message = decode_state_value(v),
            _ => {}
        }
    }
    Ok(out)
}

/// A truncating write leaves the file empty for a moment; a crash there reads back as "no job"
/// and orphans a running one. Write beside the file and rename over it instead.
fn write_state_file(path: &Path, body: &str) -> Result<(), String> {
    let tmp = path.with_extension("state.tmp");
    fs::write(&tmp, body).map_err(|e| format!("failed to write state '{}': {e}", tmp.display()))?;
    fs::rename(&tmp, path)
        .map_err(|e| format!("failed to move state into place '{}': {e}", path.display()))
}

fn write_control_state(app_paths: &AppPaths, state: &ControlState) -> Result<(), String> {
    let control_dir = app_paths.data_dir.join("ui-control");
    fs::create_dir_all(&control_dir).map_err(|e| {
        format!(
            "failed to create control dir '{}': {e}",
            control_dir.display()
        )
    })?;
    let state_path = control_dir.join("control.state");
    let pid_text = state.pid.map(|v| v.to_string()).unwrap_or_default();
    let pid_start_text = state.pid_start.map(|v| v.to_string()).unwrap_or_default();
    let started_at_text = state.started_at.map(|v| v.to_string()).unwrap_or_default();
    let body = format!(
        "pid={}\npid_start={}\nstarted_at={}\nduration_seconds={}\ntarget={}\nbackend={}\nlog_file={}\n",
        pid_text,
        pid_start_text,
        started_at_text,
        state.duration_seconds,
        encode_state_value(&state.target),
        encode_state_value(&state.backend),
        encode_state_value(&state.log_file)
    );
    write_state_file(&state_path, &body)
}

fn write_replay_state(app_paths: &AppPaths, state: &ReplayState) -> Result<(), String> {
    let replay_dir = app_paths.data_dir.join("ui-replay");
    fs::create_dir_all(&replay_dir).map_err(|e| {
        format!(
            "failed to create replay dir '{}': {e}",
            replay_dir.display()
        )
    })?;
    let state_path = replay_dir.join("replay.state");
    let pid_text = state.pid.map(|v| v.to_string()).unwrap_or_default();
    let pid_start_text = state.pid_start.map(|v| v.to_string()).unwrap_or_default();
    let started_at_text = state.started_at.map(|v| v.to_string()).unwrap_or_default();
    let body = format!(
        "pid={}\npid_start={}\nstarted_at={}\ntarget={}\ninput={}\nlog_file={}\n",
        pid_text,
        pid_start_text,
        started_at_text,
        encode_state_value(&state.target),
        encode_state_value(&state.input),
        encode_state_value(&state.log_file)
    );
    write_state_file(&state_path, &body)
}

fn write_target_prepare_state(
    app_paths: &AppPaths,
    state: &TargetPrepareState,
) -> Result<(), String> {
    let target_dir = app_paths.data_dir.join("ui-target");
    fs::create_dir_all(&target_dir).map_err(|e| {
        format!(
            "failed to create target dir '{}': {e}",
            target_dir.display()
        )
    })?;
    let state_path = target_dir.join("prepare-target.state");
    let pid_text = state.pid.map(|v| v.to_string()).unwrap_or_default();
    let pid_start_text = state.pid_start.map(|v| v.to_string()).unwrap_or_default();
    let started_at_text = state.started_at.map(|v| v.to_string()).unwrap_or_default();
    let body = format!(
        "pid={}\npid_start={}\nstarted_at={}\ntarget={}\nversion={}\nsource_url={}\nlog_file={}\nlast_result={}\nlast_message={}\n",
        pid_text,
        pid_start_text,
        started_at_text,
        encode_state_value(&state.target),
        encode_state_value(&state.version),
        encode_state_value(&state.source_url),
        encode_state_value(&state.log_file),
        encode_state_value(&state.last_result),
        encode_state_value(&state.last_message)
    );
    write_state_file(&state_path, &body)
}

fn write_target_build_state(app_paths: &AppPaths, state: &TargetBuildState) -> Result<(), String> {
    let target_dir = app_paths.data_dir.join("ui-target-build");
    fs::create_dir_all(&target_dir).map_err(|e| {
        format!(
            "failed to create target build dir '{}': {e}",
            target_dir.display()
        )
    })?;
    let state_path = target_dir.join("target-build.state");
    let pid_text = state.pid.map(|v| v.to_string()).unwrap_or_default();
    let pid_start_text = state.pid_start.map(|v| v.to_string()).unwrap_or_default();
    let started_at_text = state.started_at.map(|v| v.to_string()).unwrap_or_default();
    let body = format!(
        "pid={}\npid_start={}\nstarted_at={}\ntarget={}\nversion={}\nlog_file={}\nlast_result={}\nlast_message={}\n",
        pid_text,
        pid_start_text,
        started_at_text,
        encode_state_value(&state.target),
        encode_state_value(&state.version),
        encode_state_value(&state.log_file),
        encode_state_value(&state.last_result),
        encode_state_value(&state.last_message)
    );
    write_state_file(&state_path, &body)
}

fn extract_replay_summary_path(log_file: &str) -> Option<String> {
    let body = fs::read_to_string(log_file).ok()?;
    for line in body.lines().rev() {
        if let Some(path) = line.strip_prefix("summary: ") {
            return Some(path.trim().to_string());
        }
    }
    None
}

fn extract_replay_verdict(log_file: &str) -> Option<String> {
    let body = fs::read_to_string(log_file).ok()?;
    for line in body.lines().rev() {
        if let Some(v) = line.strip_prefix("verdict: ") {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn extract_log_value(log_file: &str, prefix: &str) -> Option<String> {
    let body = fs::read_to_string(log_file).ok()?;
    for line in body.lines().rev() {
        if let Some(v) = line.strip_prefix(prefix) {
            return Some(v.trim().to_string());
        }
    }
    None
}

fn log_contains(log_file: &str, needle: &str) -> bool {
    fs::read_to_string(log_file)
        .map(|body| body.contains(needle))
        .unwrap_or(false)
}

fn extract_target_error_message(log_file: &str) -> Option<String> {
    let body = fs::read_to_string(log_file).ok()?;
    for line in body.lines().rev() {
        if let Some(msg) = line
            .split_once("prepare-target error: ")
            .map(|(_, v)| v.trim())
        {
            return Some(msg.to_string());
        }
        if line.contains("source URL") || line.contains("download failed") {
            return Some(line.trim().to_string());
        }
    }
    body.lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
}

fn latest_prepared_version(app_paths: &AppPaths, target: &str) -> Option<String> {
    let target_name = target_storage_name(target)?;
    let target_root = app_paths.data_dir.join("targets").join(target_name);
    let mut versions = fs::read_dir(target_root)
        .ok()?
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_dir())
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect::<Vec<_>>();
    versions.sort();
    versions.pop()
}

fn target_storage_name(target: &str) -> Option<&'static str> {
    match target {
        "gguf" => Some("llama.cpp"),
        "onnx" => Some("onnxruntime"),
        "safetensors" => Some("safetensors"),
        _ => None,
    }
}

fn tool_child_command(app_paths: &AppPaths) -> Result<Command, String> {
    let mut cmd = Command::new(tool_binary_path()?);
    cmd.arg("--data-dir")
        .arg(&app_paths.data_dir)
        .arg("--seeds-dir")
        .arg(&app_paths.seeds_dir);
    Ok(cmd)
}

fn tool_binary_path() -> Result<PathBuf, String> {
    if let Some(value) = std::env::var_os("TOOL_BIN") {
        let path = PathBuf::from(value);
        if !path.as_os_str().is_empty() {
            return Ok(path);
        }
    }
    std::env::current_exe().map_err(|e| format!("failed to resolve current executable: {e}"))
}

/// R2: every job the dashboard starts was spawned and then forgotten, so an exited child stayed
/// a zombie. Keeping the handles lets the server reap them, which is also what frees the pid.
static SPAWNED_CHILDREN: Mutex<Vec<Child>> = Mutex::new(Vec::new());

fn register_child(child: Child) {
    let mut children = SPAWNED_CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    children.push(child);
}

fn reap_children() {
    let mut children = SPAWNED_CHILDREN.lock().unwrap_or_else(|e| e.into_inner());
    children.retain_mut(|child| !matches!(child.try_wait(), Ok(Some(_))));
}

pub(crate) const SIGTERM: i32 = 15;

unsafe extern "C" {
    fn kill(pid: i32, sig: i32) -> i32;
    fn setsid() -> i32;
}

/// Jobs are started in their own session, so the whole job - the wrapper script and everything it
/// runs - can be signalled as one group without the signal reaching the server, which would
/// otherwise share its process group with them.
fn spawn_job(cmd: &mut Command) -> std::io::Result<Child> {
    unsafe {
        cmd.pre_exec(|| {
            if setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.spawn()
}

/// Signals the job's whole process group. A job started by `spawn_job` leads its group, so its
/// pid doubles as the group id; a job recorded by an older build may not, so fall back to the
/// single process rather than signalling a group the server could be in.
fn signal_job(pid: u32, sig: i32) -> bool {
    let pid = pid as i32;
    if process_pgid(pid as u32) == Some(pid as u32) && unsafe { kill(-pid, sig) } == 0 {
        return true;
    }
    unsafe { kill(pid, sig) == 0 }
}

/// Field n of /proc/<pid>/stat, counting from 1 as procfs does. The command name sits in
/// parentheses and may contain spaces and parentheses, so the fields after it are found from the
/// LAST ')': the next token is field 3.
fn proc_stat_field(pid: u32, field: usize) -> Option<String> {
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = stat.rfind(')')?;
    stat[after_comm + 1..]
        .split_whitespace()
        .nth(field.checked_sub(3)?)
        .map(|v| v.to_string())
}

fn process_pgid(pid: u32) -> Option<u32> {
    proc_stat_field(pid, 5)?.parse().ok()
}

/// Field 22 of /proc/<pid>/stat: the process start time in clock ticks since boot. It is unique
/// per process for the life of the boot, so it tells a recycled pid from the job we started.
fn process_start_ticks(pid: u32) -> Option<u64> {
    proc_stat_field(pid, 22)?.parse().ok()
}

/// The pid of the job a state file describes - but only when that process is still running and is
/// still the same process we started. A state file with no recorded start time predates this
/// check, so it cannot prove anything and is treated as "no job": reported as not running, and
/// never signalled.
fn running_job_pid(pid: Option<u32>, pid_start: Option<u64>) -> Option<u32> {
    let pid = pid?;
    let recorded = pid_start?;
    if process_start_ticks(pid) != Some(recorded) {
        return None;
    }
    if !is_process_alive(pid) {
        return None;
    }
    Some(pid)
}

/// The state letter of /proc/<pid>/stat. The command name sits in parentheses and may itself
/// contain spaces and parentheses, so the fields after it are found from the LAST ')'.
fn process_state(pid: u32) -> Option<char> {
    proc_stat_field(pid, 3)?.chars().next()
}

/// R2: `kill -0` succeeds for a zombie, so an exited-but-unreaped job read as still running and
/// the dashboard never left "running". A zombie has exited; only a real state counts as alive.
fn is_process_alive(pid: u32) -> bool {
    if Path::new("/proc").is_dir() {
        return match process_state(pid) {
            Some(state) => state != 'Z',
            None => false,
        };
    }
    Command::new("kill")
        .arg("-0")
        .arg(pid.to_string())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn handle_entity_view(app_paths: &AppPaths, kind: &str, id: &str) -> Result<Response, String> {
    // These were literal "./data/..." strings resolved against the working
    // directory, so every detail page 500'd under `tool --data-dir X ui-serve`
    // while the list page above it still linked to them.
    let entity = |dir: &str, file: &str| {
        app_paths
            .data_dir
            .join(dir)
            .join(id)
            .join(file)
            .display()
            .to_string()
    };
    let (title, main_rel_path, extra_rel_paths) = match kind {
        "run" => (
            format!("Run Detail: {id}"),
            entity("runs", "status.json"),
            vec![entity("runs", "logs/backend-engine-w1.log")],
        ),
        "triage" => (
            format!("Triage Detail: {id}"),
            entity("triage", "summary.json"),
            vec![entity("triage", "attempt-1.log")],
        ),
        "report" => (
            format!("Report Detail: {id}"),
            entity("reports", "report.md"),
            vec![entity("reports", "meta.json")],
        ),
        "coverage" => (
            format!("Coverage Detail: {id}"),
            entity("coverage", "summary.json"),
            vec![],
        ),
        _ => return respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    };

    let main_file = resolve_safe_data_path(&app_paths.data_dir, &main_rel_path)?;
    let main_content = fs::read_to_string(&main_file)
        .map_err(|e| format!("failed to read '{}': {e}", main_file.display()))?;

    let mut extras_html = String::new();
    for extra in extra_rel_paths {
        if let Ok(extra_path) = resolve_safe_data_path(&app_paths.data_dir, &extra) {
            if extra_path.exists() {
                let href = format!("/file?path={}", url_encode(&extra));
                extras_html.push_str(&format!(
                    "<li><a href=\"{}\">{}</a></li>",
                    html_escape(&href),
                    html_escape(&extra)
                ));
            }
        }
    }
    let extras_section = if extras_html.is_empty() {
        String::new()
    } else {
        format!("<h3>Related Files</h3><ul>{extras_html}</ul>")
    };

    let html = format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>{}</title><style>body{{font-family:Segoe UI,system-ui,sans-serif;margin:0;background:#eef2f7;color:#111827}}.wrap{{max-width:1100px;margin:0 auto;padding:14px}}.top{{position:sticky;top:0;background:#eef2f7cc;backdrop-filter:blur(4px);padding-bottom:10px}}.card{{background:#fff;border:1px solid #d4dee8;border-radius:12px;padding:14px;box-shadow:0 4px 12px rgba(16,24,40,.04)}}pre{{white-space:pre-wrap;word-break:break-word;background:#f8fafc;border:1px solid #e2e8f0;padding:12px;border-radius:10px;max-height:68vh;overflow:auto}}a{{color:#0b5563;text-decoration:none}}ul{{margin:8px 0 12px 16px;padding:0}}li{{margin:4px 0}}.meta{{font-size:12px;color:#4b5563}}@media (max-width:640px){{.wrap{{padding:10px}}h2{{font-size:18px}}pre{{font-size:11px}}}}</style></head><body><div class=\"wrap\"><div class=\"top\"><p><a href=\"/dashboard.html\">← dashboard</a></p><h2>{}</h2><p class=\"meta\">{}</p></div><div class=\"card\">{}<pre>{}</pre></div></div></body></html>",
        html_escape(&title),
        html_escape(&title),
        html_escape(&main_rel_path),
        extras_section,
        html_escape(&main_content)
    );

    respond("200 OK", "text/html; charset=utf-8", &html)
}

fn handle_file_view(app_paths: &AppPaths, raw_path: &str) -> Result<Response, String> {
    let Some(path_value) = extract_query_param(raw_path, "path") else {
        return respond(
            "400 Bad Request",
            "text/plain; charset=utf-8",
            "missing query parameter: path\n",
        );
    };
    let decoded = url_decode(path_value).ok_or_else(|| "invalid url encoding".to_string())?;
    let resolved = resolve_safe_data_path(&app_paths.data_dir, &decoded)?;
    let body = fs::read_to_string(&resolved)
        .map_err(|e| format!("failed to read '{}': {e}", resolved.display()))?;
    respond("200 OK", "text/plain; charset=utf-8", &body)
}

fn handle_asset_view(asset_name: &str) -> Result<Response, String> {
    let (rel_path, content_type) = match asset_name {
        "dashboard.css" => ("templates/assets/dashboard.css", "text/css; charset=utf-8"),
        _ => return respond("404 Not Found", "text/plain; charset=utf-8", "not found\n"),
    };
    let body = fs::read_to_string(rel_path)
        .map_err(|e| format!("failed to read asset '{rel_path}': {e}"))?;
    respond("200 OK", content_type, &body)
}

// A2: every state file is a line-based `key=value` list, so a value that carries a line break
// used to inject a whole extra line - an attacker-chosen `pid=` that /target/stop then handed to
// kill. Values are refused at the door, and what does get written is encoded so that a path that
// legitimately contains a line break still cannot forge a line.
fn bad_request(error: &str) -> Result<Response, String> {
    respond(
        "400 Bad Request",
        "application/json; charset=utf-8",
        &format!("{{\"error\":\"{error}\"}}"),
    )
}

fn is_safe_query_value(value: &str) -> bool {
    !value.chars().any(|c| c.is_control())
}

fn encode_state_value(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for c in raw.chars() {
        match c {
            '%' => out.push_str("%25"),
            '\n' => out.push_str("%0A"),
            '\r' => out.push_str("%0D"),
            c => out.push(c),
        }
    }
    out
}

/// Decodes byte by byte. This reads files this build did not necessarily write - every value the
/// previous build wrote was raw - so it must survive a '%' next to a multi-byte character rather
/// than slicing the string at an offset that only happens to be in range.
fn decode_state_value(encoded: &str) -> String {
    let bytes = encoded.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            match &bytes[i..i + 3] {
                b"%25" => {
                    out.push(b'%');
                    i += 3;
                    continue;
                }
                b"%0A" => {
                    out.push(b'\n');
                    i += 3;
                    continue;
                }
                b"%0D" => {
                    out.push(b'\r');
                    i += 3;
                    continue;
                }
                _ => {}
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A16: `version` becomes VERSION_ROOT="$TARGET_ROOT/$VERSION" in
/// scripts/build_prepared_target.sh, which then rm -rf's a directory under it, so anything that
/// can leave the targets tree - or be read as an option - is refused. Real labels look like
/// `v1.23.2`, `b7921`, `v0.7.0`.
fn is_safe_version(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 128 || value.contains("..") {
        return false;
    }
    let mut chars = value.chars();
    let first = chars.next().unwrap_or('\0');
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
}

/// The source URL is handed to the downloader as an argument, so it has to be a real http(s)
/// URL rather than a local path or something that reads as an option.
fn is_safe_source_url(value: &str) -> bool {
    if value.is_empty() {
        return true;
    }
    if value.len() > 2048 || value.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    value.starts_with("http://") || value.starts_with("https://")
}

/// The worker/duration/retry knobs were passed on verbatim, so a value that is not a plain
/// count - "--data-dir", a negative number, an absurd fleet size - reached a Command argument or
/// a bash script's environment as given.
const MAX_DURATION_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_JOBS_LIMIT: u64 = 10_000_000;

/// A numeric query value, or None when it cannot be used.
///
/// R4: an unparsable or out-of-range value used to become the default silently, so
/// an operator who mistyped a worker count got a job running with a different one
/// and nothing said so. A zero worker count or job budget is refused by the CLI
/// too, hence `min`; restart_limit legitimately allows zero.
fn bounded_count_param<'a>(
    raw: Option<&'a str>,
    min: u64,
    max: u64,
    default: &'a str,
) -> Option<&'a str> {
    let Some(value) = raw else {
        return Some(default);
    };
    match value.parse::<u64>() {
        Ok(n) if n >= min && n <= max => Some(value),
        _ => None,
    }
}

// A29: `timeout_sec=0` means "no time limit" to the shell wrapper and is rejected by the
// run/triage pipelines, so a query value that is not a positive integer falls back to the
// documented default instead of spawning a job that can only fail.
fn positive_timeout_sec_param(raw: Option<&str>) -> Option<&str> {
    bounded_count_param(raw, 1, u64::MAX, "30")
}

fn extract_query_param<'a>(path: &'a str, key: &str) -> Option<&'a str> {
    let query = path.split_once('?')?.1;
    for part in query.split('&') {
        // A15: `?` here abandoned the whole query at the first pair without '=', so every later
        // parameter silently read as absent.
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(v);
        }
    }
    None
}

fn url_decode(input: &str) -> Option<String> {
    let mut out = Vec::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let h1 = from_hex(bytes[i + 1])?;
                let h2 = from_hex(bytes[i + 2])?;
                out.push((h1 << 4) | h2);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn from_hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The dashboard's replay button names the triage record, not a path: the input is read back out
/// of the summary the tool itself wrote. That keeps the caller from choosing which file gets fed
/// to triage (A14) while still replaying a PoC the researcher triaged from outside the data dir.
fn resolve_triage_input(app_paths: &AppPaths, triage_id: &str) -> Option<PathBuf> {
    if triage_id.is_empty()
        || triage_id == "not_available"
        || !triage_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || triage_id.contains("..")
    {
        return None;
    }
    let summary_rel = app_paths
        .data_dir
        .join("triage")
        .join(triage_id)
        .join("summary.json");
    let summary_path =
        resolve_safe_data_path(&app_paths.data_dir, &summary_rel.display().to_string()).ok()?;
    let summary = fs::read_to_string(summary_path).ok()?;
    let recorded = extract_json_string_literal(&summary, "input")?;
    let path = fs::canonicalize(recorded).ok()?;
    path.is_file().then_some(path)
}

/// A14: replay/start used to accept any path that existed and was a file, so `tool triage` could
/// be aimed at anything the server could read. Crash inputs the dashboard offers live under the
/// data dir and corpus entries under the seeds dir; a PoC kept anywhere else is replayed with the
/// CLI, which is not reachable from a web page.
fn resolve_replay_input(app_paths: &AppPaths, requested: &str) -> Option<PathBuf> {
    for root in [&app_paths.data_dir, &app_paths.seeds_dir] {
        if let Ok(resolved) = resolve_safe_data_path(root, requested) {
            if resolved.is_file() {
                return Some(resolved);
            }
        }
    }
    None
}

fn resolve_safe_data_path(data_dir: &Path, requested: &str) -> Result<PathBuf, String> {
    let data_canon = fs::canonicalize(data_dir).map_err(|e| {
        format!(
            "failed to canonicalize data dir '{}': {e}",
            data_dir.display()
        )
    })?;

    let req_path = Path::new(requested);
    let candidate = if req_path.is_absolute() {
        req_path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("failed to get current dir: {e}"))?
            .join(req_path)
    };
    let canon = fs::canonicalize(&candidate).map_err(|e| {
        format!(
            "failed to canonicalize requested path '{}': {e}",
            candidate.display()
        )
    })?;

    if !canon.starts_with(&data_canon) {
        return Err(format!(
            "requested path is outside data dir: {}",
            candidate.display()
        ));
    }
    Ok(canon)
}

fn write_all_before_deadline<W: Write>(
    writer: &mut W,
    bytes: &[u8],
    deadline: Duration,
) -> Result<(), String> {
    let started = Instant::now();
    let mut written = 0usize;
    while written < bytes.len() {
        if started.elapsed() > deadline {
            return Err(format!("response not written within {deadline:?}"));
        }
        match writer.write(&bytes[written..]) {
            Ok(0) => return Err("peer stopped accepting the response".to_string()),
            Ok(n) => written += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                        | std::io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(format!("failed to write response: {e}")),
        }
    }
    Ok(())
}

fn write_response(
    stream: &mut TcpStream,
    status: &str,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    write_all_before_deadline(stream, response.as_bytes(), WRITE_DEADLINE)
}

#[cfg(test)]
mod tests {
    use super::{
        allowed_hosts_for_bind, authorize, secret_eq, write_all_before_deadline, UiSecurity,
    };
    use super::{
        bounded_count_param, decode_state_value, encode_state_value, extract_query_param,
        is_process_alive, is_safe_query_value, is_safe_source_url, is_safe_version,
        parse_request_head, positive_timeout_sec_param, proc_stat_field, process_pgid,
        process_start_ticks, process_state, read_request_head, reap_children, register_child,
        resolve_replay_input, resolve_triage_input, respond_to_request, running_job_pid,
        signal_job, spawn_job, HEAD_DEADLINE, SIGTERM,
    };
    use crate::common::{now_unix_millis, AppPaths};
    use std::fs;
    use std::io::Write;
    use std::path::PathBuf;
    use std::process::Command;

    fn unique_tmp_dir(label: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("tool_ui_{}_{}", label, now_unix_millis()));
        fs::create_dir_all(&p).expect("create tmp dir");
        p
    }

    // A4: the old server did one 4 KiB read() and looked only at the first line, so a request
    // whose head arrived in several TCP segments lost its headers. The head has to be read
    // until the blank line before anything may be decided from it.
    #[test]
    fn request_head_is_read_until_the_blank_line_even_across_reads() {
        struct Chunked(Vec<&'static [u8]>);
        impl std::io::Read for Chunked {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                let chunk = self.0.remove(0);
                buf[..chunk.len()].copy_from_slice(chunk);
                Ok(chunk.len())
            }
        }
        let mut reader = Chunked(vec![
            b"POST /control/start?target=onnx HTT",
            b"P/1.1\r\nHost: 127.0.0.1:8787\r\nX-Tool-",
            b"Token: abc\r\n\r\n",
        ]);
        let head = read_request_head(&mut reader, 32 * 1024, HEAD_DEADLINE)
            .expect("head")
            .expect("head present");
        assert!(head.ends_with("\r\n\r\n"), "head was {head:?}");
        let parsed = parse_request_head(&head).expect("parsed");
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.path, "/control/start?target=onnx");
    }

    // set_read_timeout bounds one read syscall, not the connection, so a client dribbling a byte
    // just under that timeout held its thread and its slot for days and a handful of them took
    // every slot the server has.
    #[test]
    fn a_head_that_arrives_too_slowly_is_given_up_on() {
        struct Dribble;
        impl std::io::Read for Dribble {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(20));
                buf[0] = b'x';
                Ok(1)
            }
        }
        let started = std::time::Instant::now();
        let result = read_request_head(
            &mut Dribble,
            32 * 1024,
            std::time::Duration::from_millis(100),
        );
        assert!(
            result.is_err(),
            "a head that never ends must be given up on"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the deadline must actually fire: {:?}",
            started.elapsed()
        );
    }

    // A bare LF pair inside a CRLF head would otherwise end the head early and hide every header
    // after it - including the Origin the CSRF check reads.
    #[test]
    fn a_bare_lf_does_not_end_a_crlf_head() {
        let mut reader: &[u8] =
            b"GET / HTTP/1.1\r\nX-Pad: \n\nOrigin: http://evil.example\r\nHost: 127.0.0.1\r\n\r\n";
        let head = read_request_head(&mut reader, 32 * 1024, HEAD_DEADLINE)
            .expect("head")
            .expect("head present");
        assert!(
            head.contains("Origin: http://evil.example"),
            "the head stopped early: {head:?}"
        );
    }

    // A15: `?` inside the loop abandoned the whole query at the first pair without '=', so
    // /replay/start?flag&input=x reported a missing input.
    #[test]
    fn a_valueless_query_pair_does_not_hide_the_rest() {
        assert_eq!(
            extract_query_param("/replay/start?flag&input=x&target=onnx", "input"),
            Some("x")
        );
        assert_eq!(
            extract_query_param("/replay/start?flag&input=x&target=onnx", "target"),
            Some("onnx")
        );
        assert_eq!(extract_query_param("/replay/start?flag", "input"), None);
        assert_eq!(extract_query_param("/replay/start", "input"), None);
    }

    #[test]
    fn a_head_without_a_blank_line_is_an_error_not_a_silent_truncation() {
        let mut reader: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: x\r\n";
        assert!(read_request_head(&mut reader, 32 * 1024, HEAD_DEADLINE).is_err());
    }

    // A browser preconnect opens the socket and closes it again; that is not a request error.
    #[test]
    fn a_connection_that_sends_nothing_is_not_an_error() {
        let mut reader: &[u8] = b"";
        assert_eq!(
            read_request_head(&mut reader, 32 * 1024, HEAD_DEADLINE),
            Ok(None)
        );
    }

    // A4: an oversized head must be refused rather than buffered without bound.
    #[test]
    fn an_oversized_request_head_is_refused() {
        let mut long = String::from("GET / HTTP/1.1\r\n");
        for i in 0..500 {
            long.push_str(&format!("X-Pad-{i}: {}\r\n", "a".repeat(64)));
        }
        long.push_str("\r\n");
        let mut reader = long.as_bytes();
        assert!(read_request_head(&mut reader, 4096, HEAD_DEADLINE).is_err());
    }

    // A2: the state files are line based, so a value carrying a newline injected extra lines -
    // notably an attacker-chosen `pid=`, which /target/stop then passed to kill.
    #[test]
    fn a_value_with_a_line_break_is_not_an_acceptable_query_value() {
        assert!(is_safe_query_value("v1.23.2"));
        assert!(is_safe_query_value("https://example.com/a?b=c"));
        assert!(is_safe_query_value(""));
        assert!(!is_safe_query_value("x\npid=1234"));
        assert!(!is_safe_query_value("x\rpid=1234"));
        assert!(!is_safe_query_value("x\u{7f}y"));
        assert!(!is_safe_query_value("x\u{0}y"));
    }

    // A2 defence in depth: even a legitimate path that happens to contain a newline must not be
    // able to forge a second `pid=` line, and it must survive the round trip unchanged.
    #[test]
    fn state_values_round_trip_through_the_line_based_files() {
        for raw in [
            "/data/x.onnx",
            "/data/we\nird\npid=1234",
            "/data/100%25done",
            "/data/pl%ain",
            "",
        ] {
            let encoded = encode_state_value(raw);
            assert!(!encoded.contains('\n'), "{encoded:?} still holds a newline");
            assert!(!encoded.contains('\r'), "{encoded:?} still holds a CR");
            assert_eq!(decode_state_value(&encoded), raw);
        }
    }

    // The decoder reads files this build did not necessarily write - the old build wrote every
    // value raw - and it sliced the string at i+3 after a bounds check only, so a '%' next to a
    // multi-byte character panicked the connection thread. read_*_state runs before any handler
    // that could repair the file, so the panic repeated on every poll with no way out.
    #[test]
    fn a_legacy_state_value_with_a_percent_next_to_a_multibyte_character_decodes() {
        assert_eq!(
            decode_state_value("https://x/100%한글.tar.gz"),
            "https://x/100%한글.tar.gz"
        );
        assert_eq!(decode_state_value("build 50%✓ done"), "build 50%✓ done");
        assert_eq!(decode_state_value("%"), "%");
        assert_eq!(decode_state_value("%2"), "%2");
        assert_eq!(decode_state_value("%한"), "%한");
        assert_eq!(decode_state_value("a%25한"), "a%한");
        assert_eq!(decode_state_value("한%0A글"), "한\n글");
    }

    // The write side had only SO_SNDTIMEO, which restarts on every partial write, so a peer that
    // reads one byte per timeout window held its thread and its in-flight slot for as long as it
    // liked - 64 of them and every other request gets the 503.
    #[test]
    fn a_peer_that_never_finishes_reading_does_not_hold_its_slot_forever() {
        struct Trickle;
        impl Write for Trickle {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(10));
                Ok(buf.len().min(1))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        struct Stalled;
        impl Write for Stalled {
            fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
                std::thread::sleep(std::time::Duration::from_millis(10));
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let body = "x".repeat(64 * 1024);
        let budget = std::time::Duration::from_millis(100);

        let started = std::time::Instant::now();
        assert!(write_all_before_deadline(&mut Trickle, body.as_bytes(), budget).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        let started = std::time::Instant::now();
        assert!(write_all_before_deadline(&mut Stalled, body.as_bytes(), budget).is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(5));

        // A peer that reads normally still gets the whole body.
        let mut sink = Vec::new();
        write_all_before_deadline(&mut sink, body.as_bytes(), budget).expect("full write");
        assert_eq!(sink.len(), body.len());
    }

    // A16: `version` reached scripts/build_prepared_target.sh as VERSION_ROOT="$TARGET_ROOT/$VERSION",
    // which is then rm -rf'd, so traversal out of the targets tree has to be refused here.
    #[test]
    fn only_a_plain_version_label_is_accepted() {
        assert!(is_safe_version("v1.23.2"));
        assert!(is_safe_version("b7921"));
        assert!(is_safe_version("v0.7.0"));
        assert!(is_safe_version("1.0.0+rc1"));
        assert!(is_safe_version(""));
        assert!(!is_safe_version("../../../tmp/pwn"));
        assert!(!is_safe_version(".."));
        assert!(!is_safe_version("a/b"));
        assert!(!is_safe_version("a\\b"));
        assert!(!is_safe_version("-rf"));
        assert!(!is_safe_version("v1..2"));
        assert!(!is_safe_version("v 1"));
        assert!(!is_safe_version(&"v".repeat(200)));
    }

    #[test]
    fn only_an_http_source_url_is_accepted() {
        assert!(is_safe_source_url("https://example.com/model.onnx"));
        assert!(is_safe_source_url("http://127.0.0.1:8080/a.tar.gz"));
        assert!(is_safe_source_url(""));
        assert!(!is_safe_source_url("file:///etc/passwd"));
        assert!(!is_safe_source_url("ftp://example.com/x"));
        assert!(!is_safe_source_url("https://exa mple.com/x"));
        assert!(!is_safe_source_url("-oremote"));
    }

    // The numeric knobs went straight into Command args and into env for a bash script with no
    // parse at all, so a value like "--data-dir" or an absurd count was passed on as given.
    #[test]
    fn numeric_query_values_are_bounded_before_they_reach_a_command() {
        assert_eq!(bounded_count_param(Some("4"), 0, 64, "2"), Some("4"));
        assert_eq!(bounded_count_param(Some("0"), 0, 64, "2"), Some("0"));
        assert_eq!(bounded_count_param(Some("65"), 0, 64, "2"), None);
        assert_eq!(bounded_count_param(Some("-1"), 0, 64, "2"), None);
        assert_eq!(bounded_count_param(Some("--data-dir"), 0, 64, "2"), None);
        assert_eq!(bounded_count_param(Some(""), 0, 64, "2"), None);
        assert_eq!(bounded_count_param(None, 0, 64, "2"), Some("2"));
    }

    // R4: an unparsable or out-of-range numeric query value silently became the
    // default, so an operator who mistyped --workers got a job that ran with a
    // different worker count than they asked for and no way to notice. max_jobs
    // already returned 400; the rest did not.
    #[test]
    fn an_unusable_numeric_query_value_is_rejected_not_defaulted() {
        use super::bounded_count_param;

        assert_eq!(bounded_count_param(Some("4"), 1, 64, "2"), Some("4"));
        assert_eq!(bounded_count_param(None, 1, 64, "2"), Some("2"));
        assert_eq!(bounded_count_param(Some("abc"), 1, 64, "2"), None);
        assert_eq!(bounded_count_param(Some("-1"), 1, 64, "2"), None);
        assert_eq!(bounded_count_param(Some("--data-dir"), 1, 64, "2"), None);
        assert_eq!(bounded_count_param(Some(""), 1, 64, "2"), None);
        assert_eq!(bounded_count_param(Some("65"), 1, 64, "2"), None);
    }

    // A zero worker count or job budget is refused by the CLI, so the dashboard
    // would spawn a job that can only fail. restart_limit legitimately allows zero.
    #[test]
    fn a_count_the_cli_refuses_is_refused_at_the_door() {
        use super::bounded_count_param;

        assert_eq!(bounded_count_param(Some("0"), 1, 256, "2"), None);
        assert_eq!(bounded_count_param(Some("0"), 0, 1000, "1"), Some("0"));
    }

    fn secured(token: &str) -> UiSecurity {
        UiSecurity {
            token: token.to_string(),
            allowed_hosts: allowed_hosts_for_bind("127.0.0.1:8787").expect("allowlist"),
        }
    }

    fn head(method: &str, path: &str, extra: &str) -> super::RequestHead {
        parse_request_head(&format!(
            "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:8787\r\n{extra}\r\n"
        ))
        .expect("request")
    }

    // A3: the bind address alone is not the allowlist - operators type localhost:8787 - and the
    // allowlist must be fixed, never derived from the Host the caller sent, or a rebound
    // evil.example:8787 matches itself and the whole check passes by construction.
    #[test]
    fn the_host_allowlist_is_fixed_and_covers_the_usual_loopback_spellings() {
        let hosts = allowed_hosts_for_bind("127.0.0.1:8787").expect("allowlist");
        for expected in [
            "127.0.0.1",
            "127.0.0.1:8787",
            "localhost",
            "localhost:8787",
            "[::1]",
            "[::1]:8787",
        ] {
            assert!(hosts.iter().any(|h| h == expected), "missing {expected}");
        }
        assert!(!hosts.iter().any(|h| h.contains("evil")));
        // Binding to the world has no safe allowlist to derive.
        assert!(allowed_hosts_for_bind("0.0.0.0:8787").is_none());
        assert!(allowed_hosts_for_bind("[::]:8787").is_none());
    }

    #[test]
    fn a_request_for_another_host_is_refused_on_every_route() {
        let sec = secured("tok");
        for path in ["/healthz", "/dashboard.html", "/control/status"] {
            let mut request = head("GET", path, "");
            request.headers = vec![("host".to_string(), "evil.example".to_string())];
            assert_eq!(
                authorize(&sec, &request),
                Err("host_not_allowed"),
                "{path} accepted a rebound host"
            );
        }
        let mut no_host = head("GET", "/healthz", "");
        no_host.headers.clear();
        assert_eq!(authorize(&sec, &no_host), Err("host_not_allowed"));
    }

    // A3: every mutating endpoint was reachable by any page the user had open - and so were the
    // two status GETs, which rewrite their state file.
    #[test]
    fn a_mutating_request_needs_the_token() {
        let sec = secured("s3cret");
        assert_eq!(
            authorize(&sec, &head("POST", "/control/start", "")),
            Err("missing_or_bad_token")
        );
        assert_eq!(
            authorize(
                &sec,
                &head("POST", "/control/start", "X-Tool-Token: wrong\r\n")
            ),
            Err("missing_or_bad_token")
        );
        assert_eq!(
            authorize(
                &sec,
                &head("POST", "/control/start", "x-tool-token: s3cret\r\n")
            ),
            Ok(())
        );
        // A GET that rewrites its state file is a mutating endpoint.
        assert_eq!(
            authorize(&sec, &head("GET", "/target/status", "")),
            Err("missing_or_bad_token")
        );
        assert_eq!(
            authorize(&sec, &head("GET", "/target/build/status", "")),
            Err("missing_or_bad_token")
        );
        // Pure reads stay open to the browser that loaded the page.
        assert_eq!(authorize(&sec, &head("GET", "/control/status", "")), Ok(()));
        assert_eq!(authorize(&sec, &head("GET", "/dashboard.html", "")), Ok(()));
    }

    #[test]
    fn a_cross_origin_caller_is_refused_even_holding_the_token() {
        let sec = secured("s3cret");
        assert_eq!(
            authorize(
                &sec,
                &head(
                    "POST",
                    "/control/start",
                    "X-Tool-Token: s3cret\r\nOrigin: http://evil.example\r\n"
                )
            ),
            Err("cross_origin")
        );
        assert_eq!(
            authorize(
                &sec,
                &head(
                    "POST",
                    "/control/start",
                    "X-Tool-Token: s3cret\r\nReferer: http://evil.example/x.html\r\n"
                )
            ),
            Err("cross_origin")
        );
        assert_eq!(
            authorize(
                &sec,
                &head(
                    "POST",
                    "/control/start",
                    "X-Tool-Token: s3cret\r\nOrigin: http://127.0.0.1:8787\r\n"
                )
            ),
            Ok(())
        );
        assert_eq!(
            authorize(
                &sec,
                &head(
                    "POST",
                    "/control/start",
                    "X-Tool-Token: s3cret\r\nReferer: http://localhost:8787/dashboard.html\r\n"
                )
            ),
            Ok(())
        );
    }

    #[test]
    fn secrets_compare_without_leaking_where_they_differ() {
        assert!(secret_eq("abc", "abc"));
        assert!(!secret_eq("abc", "abd"));
        assert!(!secret_eq("abc", "ab"));
        assert!(!secret_eq("", "a"));
        assert!(secret_eq("", ""));
    }

    // The entity routes and the dashboard's file links were built from the literal
    // "./data/...", resolved against the working directory - so `tool --data-dir X
    // ui-serve` served 500s for every run, triage, report and coverage detail page
    // while the list pages above them still showed the entries.
    #[test]
    fn entity_routes_follow_the_configured_data_dir() {
        let root = unique_tmp_dir("entity-data-dir");
        let app_paths = AppPaths {
            data_dir: root.join("elsewhere"),
            seeds_dir: root.join("seeds"),
        };
        let triage_dir = app_paths.data_dir.join("triage").join("triage-x");
        fs::create_dir_all(&triage_dir).expect("triage dir");
        fs::write(
            triage_dir.join("summary.json"),
            "{\"verdict\": \"marker-9f3a\"}",
        )
        .expect("write summary");
        let run_dir = app_paths.data_dir.join("runs").join("run-7");
        fs::create_dir_all(&run_dir).expect("run dir");
        fs::write(run_dir.join("status.json"), "{\"total\": 41}").expect("write status");

        let sec = secured("tok");
        let triage = respond_to_request(&app_paths, &sec, &request("GET", "/triage/triage-x"));
        assert_eq!(triage.status, "200 OK", "{}", triage.body);
        assert!(triage.body.contains("marker-9f3a"), "{}", triage.body);

        let run = respond_to_request(&app_paths, &sec, &request("GET", "/run/run-7"));
        assert_eq!(run.status, "200 OK", "{}", run.body);
        assert!(run.body.contains("41"), "{}", run.body);

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_target_prepare_passes_configured_paths_to_child() {
        use std::os::unix::fs::PermissionsExt;

        let root = unique_tmp_dir("target-prepare-paths");
        let app_paths = AppPaths {
            data_dir: root.join("configured-data"),
            seeds_dir: root.join("configured-seeds"),
        };
        let argv_file = root.join("child-argv");
        let fake_tool = root.join("fake-tool");
        fs::write(
            &fake_tool,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\n",
                argv_file.display()
            ),
        )
        .expect("write fake tool");
        fs::set_permissions(&fake_tool, fs::Permissions::from_mode(0o755))
            .expect("make fake tool executable");

        let previous_tool = std::env::var_os("TOOL_BIN");
        std::env::set_var("TOOL_BIN", &fake_tool);
        let response = super::handle_target_prepare(&app_paths, "/target/prepare?target=onnx");
        if let Some(value) = previous_tool {
            std::env::set_var("TOOL_BIN", value);
        } else {
            std::env::remove_var("TOOL_BIN");
        }
        assert_eq!(response.expect("prepare response").status, "200 OK");

        for _ in 0..50 {
            if argv_file.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        let argv = fs::read_to_string(&argv_file).expect("child recorded argv");
        assert_eq!(
            argv.lines().collect::<Vec<_>>(),
            vec![
                "--data-dir",
                app_paths.data_dir.to_str().expect("data dir is UTF-8"),
                "--seeds-dir",
                app_paths.seeds_dir.to_str().expect("seeds dir is UTF-8"),
                "prepare-target",
                "--target",
                "onnx",
            ]
        );
        reap_children();
        fs::remove_dir_all(&root).expect("remove fake tool and output");
    }

    fn request(method: &str, path: &str) -> super::RequestHead {
        head(method, path, "")
    }

    // The handlers used to write straight to the socket while holding the state lock, so a peer
    // that stopped reading parked every other state request behind it. They build a response now,
    // which is also the only reason this test can exist without a socket.
    #[test]
    fn a_handler_builds_its_response_without_a_socket() {
        let root = unique_tmp_dir("respond");
        let app_paths = AppPaths {
            data_dir: root.join("data"),
            seeds_dir: root.join("seeds"),
        };
        fs::create_dir_all(&app_paths.data_dir).expect("data dir");

        let sec = secured("tok");
        let ok = respond_to_request(&app_paths, &sec, &request("GET", "/control/status"));
        assert_eq!(ok.status, "200 OK");
        assert!(ok.body.contains("\"running\":false"), "{}", ok.body);

        let missing = respond_to_request(&app_paths, &sec, &request("GET", "/nope"));
        assert_eq!(missing.status, "404 Not Found");

        // A failure is a status, not an empty reply.
        let outside = respond_to_request(
            &app_paths,
            &sec,
            &request("GET", "/file?path=%2Fetc%2Fpasswd"),
        );
        assert_eq!(outside.status, "500 Internal Server Error");
        assert!(outside.body.contains("internal_error"), "{}", outside.body);

        let _ = fs::remove_dir_all(&root);
    }

    // The dashboard offers "replay the latest reproduced crash", and the crash that summary
    // records may sit outside the data dir - a PoC the researcher triaged from the CLI. Confining
    // a caller-supplied path (A14) is right, but the button must still work, so the request names
    // the triage record and the server reads the input out of the summary the tool itself wrote.
    #[test]
    fn a_replay_can_name_a_triage_record_instead_of_a_path() {
        let root = unique_tmp_dir("replay-id");
        let data_dir = root.join("data");
        let outside = root.join("outside");
        fs::create_dir_all(data_dir.join("triage").join("triage-1")).expect("triage dir");
        fs::create_dir_all(&outside).expect("outside dir");
        let poc = outside.join("poc.onnx");
        fs::write(&poc, b"x").expect("write poc");
        fs::write(
            data_dir
                .join("triage")
                .join("triage-1")
                .join("summary.json"),
            format!(
                "{{\"schema_version\": \"1.1\", \"input\": \"{}\"}}",
                poc.display()
            ),
        )
        .expect("write summary");
        let app_paths = AppPaths {
            data_dir: data_dir.clone(),
            seeds_dir: root.join("seeds"),
        };

        assert_eq!(
            resolve_triage_input(&app_paths, "triage-1").as_deref(),
            Some(poc.canonicalize().expect("canonical poc").as_path()),
            "the input recorded by the tool itself is trusted provenance"
        );
        assert!(resolve_triage_input(&app_paths, "missing").is_none());
        assert!(
            resolve_triage_input(&app_paths, "../../etc").is_none(),
            "a triage id must not walk out of the triage tree"
        );
        assert!(resolve_triage_input(&app_paths, "a/b").is_none());
        assert!(resolve_triage_input(&app_paths, "").is_none());
        assert!(resolve_triage_input(&app_paths, "not_available").is_none());

        let _ = fs::remove_dir_all(&root);
    }

    // R2: the server never wait()s the children it spawns, so an exited child stays a zombie -
    // and `kill -0` reports a zombie as alive, which froze replay/prepare/build at "running"
    // forever. A zombie is a dead process; the registry then reaps it for real.
    #[test]
    fn an_unreaped_child_that_has_exited_is_not_alive() {
        let child = Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn");
        let pid = child.id();

        let mut became_zombie = false;
        for _ in 0..200 {
            if process_state(pid) == Some('Z') {
                became_zombie = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(became_zombie, "the child never turned into a zombie");
        assert!(
            !is_process_alive(pid),
            "a zombie is an exited process, not a running one"
        );

        register_child(child);
        reap_children();
        assert!(
            process_state(pid).is_none(),
            "the registry must reap the child so the pid is released"
        );
    }

    fn process_ppid(pid: u32) -> Option<u32> {
        proc_stat_field(pid, 4)?.parse().ok()
    }

    fn child_of(pid: u32) -> Option<u32> {
        for entry in fs::read_dir("/proc").ok()? {
            let entry = entry.ok()?;
            let name = entry.file_name().into_string().ok()?;
            let Ok(candidate) = name.parse::<u32>() else {
                continue;
            };
            if process_ppid(candidate) == Some(pid) {
                return Some(candidate);
            }
        }
        None
    }

    fn wait_until_gone(pid: u32) -> bool {
        for _ in 0..300 {
            match process_state(pid) {
                None | Some('Z') => return true,
                _ => std::thread::sleep(std::time::Duration::from_millis(10)),
            }
        }
        false
    }

    // The run loop script runs `tool run` in the foreground, so SIGTERM to the script's own pid
    // left the fuzzer running: the dashboard said stopped, the machine kept fuzzing, and the next
    // start passed the 409 guard and ran a second pipeline over the same data dir.
    #[test]
    fn stopping_a_job_reaches_the_work_it_started_not_just_the_wrapper() {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c").arg("/bin/sleep 60; true");
        let child = spawn_job(&mut cmd).expect("spawn");
        let pid = child.id();

        assert_eq!(
            process_pgid(pid),
            Some(pid),
            "a job must lead its own process group, or signalling the group hits the server too"
        );
        assert_ne!(
            process_pgid(std::process::id()),
            Some(pid),
            "the server must not be in the job's group"
        );

        let mut grandchild = None;
        for _ in 0..300 {
            grandchild = child_of(pid);
            if grandchild.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let grandchild = grandchild.expect("the wrapper never started its work");

        assert!(
            signal_job(pid, SIGTERM),
            "the group signal must be delivered"
        );
        assert!(wait_until_gone(pid), "the wrapper survived the stop");
        assert!(
            wait_until_gone(grandchild),
            "the work the wrapper started survived the stop"
        );

        register_child(child);
        reap_children();
    }

    // Pid numbers are reused, and a state file outlives the server, so "the recorded pid is
    // alive" is not the same as "our job is still running" - without an identity check
    // /control/stop is a SIGTERM aimed at whatever now holds that number.
    #[test]
    fn a_recycled_pid_is_not_the_job_we_started() {
        let me = std::process::id();
        let ticks = process_start_ticks(me).expect("own start ticks");
        assert_eq!(running_job_pid(Some(me), Some(ticks)), Some(me));
        assert_eq!(
            running_job_pid(Some(me), Some(ticks + 1)),
            None,
            "a different process now holds that pid"
        );
        assert_eq!(
            running_job_pid(Some(me), None),
            None,
            "a state file with no recorded start time cannot prove the pid is ours"
        );
        assert_eq!(running_job_pid(None, Some(ticks)), None);
    }

    // A14: replay/start only checked exists()+is_file(), so `tool triage` could be pointed at any
    // file the server could read. The dashboard's own replay button sends a path under the data
    // dir, so confining it there (and to the seeds dir) keeps that flow working.
    #[test]
    fn replay_input_is_confined_to_the_data_and_seeds_directories() {
        let root = unique_tmp_dir("a14");
        let data_dir = root.join("data");
        let seeds_dir = root.join("seeds");
        let outside_dir = root.join("outside");
        for dir in [&data_dir, &seeds_dir, &outside_dir] {
            fs::create_dir_all(dir).expect("create dir");
        }
        let inside = data_dir.join("crash.onnx");
        fs::write(&inside, b"x").expect("write inside");
        let seed = seeds_dir.join("seed.onnx");
        fs::write(&seed, b"x").expect("write seed");
        let outside = outside_dir.join("secret");
        fs::write(&outside, b"x").expect("write outside");
        let link = data_dir.join("link");
        std::os::unix::fs::symlink(&outside, &link).expect("symlink");

        let app_paths = AppPaths {
            data_dir: data_dir.clone(),
            seeds_dir: seeds_dir.clone(),
        };

        assert!(resolve_replay_input(&app_paths, &inside.display().to_string()).is_some());
        assert!(resolve_replay_input(&app_paths, &seed.display().to_string()).is_some());
        assert!(resolve_replay_input(&app_paths, &outside.display().to_string()).is_none());
        assert!(
            resolve_replay_input(&app_paths, &link.display().to_string()).is_none(),
            "a symlink inside the data dir must not lead outside it"
        );
        assert!(resolve_replay_input(&app_paths, "/etc/passwd").is_none());
        assert!(resolve_replay_input(
            &app_paths,
            &data_dir.join("../outside/secret").display().to_string()
        )
        .is_none());
        assert!(
            resolve_replay_input(&app_paths, &data_dir.display().to_string()).is_none(),
            "a directory is not a replayable input"
        );

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_request_line_without_a_path_falls_back_to_root() {
        let parsed = parse_request_head("GET\r\n\r\n").expect("parsed");
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/");
    }

    // A29: 0 (and anything unparseable) means "no time limit" downstream and is
    // rejected by the pipelines, so the UI refuses it rather than handing it on.
    #[test]
    fn a_non_positive_timeout_query_is_refused() {
        assert_eq!(positive_timeout_sec_param(Some("45")), Some("45"));
        assert_eq!(positive_timeout_sec_param(Some("1")), Some("1"));
        assert_eq!(positive_timeout_sec_param(Some("0")), None);
        assert_eq!(positive_timeout_sec_param(Some("-5")), None);
        assert_eq!(positive_timeout_sec_param(Some("abc")), None);
        assert_eq!(positive_timeout_sec_param(Some("")), None);
        assert_eq!(positive_timeout_sec_param(None), Some("30"));
    }
}
