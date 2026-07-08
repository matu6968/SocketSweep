// ============================================================================
// lib.rs — SocketSweep Tauri Bridge (Phase 2)
// ============================================================================
// Orchestrates the C++ Android daemon via ADB and communicates with it
// over a TCP tunnel.  All commands return Result<String, String> so the
// React frontend can display meaningful error messages.
//
// Wire protocol (matches Phase 1 daemon):
//   → "PING\n"              ← {"status":"ok","message":"pong"}
//   → "SCAN [path]\n"       ← {"status":"ok","scan_time_ms":…,"tree":{…}}
//   → "PUT <path> <size> [mtime atime]\n" + binary ← {"status":"ok","bytes_written":…}
//   → "GET <path>\n"            ← {"status":"ok","size":…,"mtime_sec":…} + binary
//   → "SHUTDOWN\n"          ← {"status":"ok","message":"shutting down"}
// ============================================================================

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use filetime::{FileTime, set_file_times};
use serde::Deserialize;
use tauri::Emitter;

// ── Constants ───────────────────────────────────────────────────────────────

const DAEMON_PORT: u16 = 5050;
const DAEMON_ADDR: &str = "127.0.0.1:5050";
const DEVICE_BIN_PATH: &str = "/data/local/tmp/socketsweep_daemon";
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const TCP_READ_TIMEOUT: Duration = Duration::from_secs(120); // scans can be slow
const UPLOAD_CHUNK_SIZE: usize = 256 * 1024;

/// Tracks the root path of the last successful scan so we can prevent its deletion.
static SCAN_ROOT: Mutex<Option<String>> = Mutex::new(None);

// ── Resource Resolution ─────────────────────────────────────────────────────

use tauri::Manager;

fn get_bundled_binary(app: &tauri::AppHandle, name: &str) -> Result<std::path::PathBuf, String> {
    let resource_dir = app.path().resource_dir().map_err(|e| format!("Failed to get resource dir: {}", e))?;

    // On Windows, host-native binaries like ADB use a .exe extension.
    // Try the .exe variant first, then fall back to the extensionless name
    // (needed for cross-platform binaries like the Android daemon).
    #[cfg(target_os = "windows")]
    {
        let exe_path = resource_dir.join("bin").join(format!("{name}.exe"));
        if exe_path.exists() {
            return Ok(exe_path);
        }
    }

    let path = resource_dir.join("bin").join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(format!("Bundled binary '{}' not found at {:?}", name, path))
    }
}

// ── ADB helper ──────────────────────────────────────────────────────────────

/// Run an ADB command and return its stdout. Maps any failure to a
/// human-readable `Err(String)`.
fn adb(adb_path: &std::path::Path, args: &[&str]) -> Result<String, String> {
    use std::io::Read;
    use std::time::{Duration, Instant};

    let mut child = Command::new(adb_path)
        .args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to execute adb binary at {:?}: {}", adb_path, e))?;

    let mut stdout_pipe = child.stdout.take().unwrap();
    let mut stderr_pipe = child.stderr.take().unwrap();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stdout_pipe.read_to_end(&mut buf);
        buf
    });

    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr_pipe.read_to_end(&mut buf);
        buf
    });

    let timeout_secs = 15;
    let timeout = Duration::from_secs(timeout_secs);
    let start = Instant::now();
    let status;

    loop {
        if let Some(s) = child.try_wait().map_err(|e| format!("Failed to wait on adb process: {}", e))? {
            status = s;
            break;
        }
        if start.elapsed() > timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("ADB command timed out after {} seconds. Please reconnect your device and try again.", timeout_secs));
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    let stdout_bytes = stdout_thread.join().unwrap_or_default();
    let stderr_bytes = stderr_thread.join().unwrap_or_default();

    let stdout = String::from_utf8_lossy(&stdout_bytes).to_string();
    let stderr = String::from_utf8_lossy(&stderr_bytes).to_string();

    if !status.success() {
        let combined = format!("{stdout} {stderr}").to_lowercase();
        if combined.contains("no devices") || combined.contains("device not found") {
            return Err("No Android device detected. Connect your phone via USB and enable USB Debugging.".into());
        }
        if combined.contains("unauthorized") {
            return Err("USB Debugging not authorised. Check the confirmation dialog on your phone.".into());
        }
        return Err(format!(
            "adb {} failed (exit {}):\n{stderr}",
            args.join(" "),
            status.code().unwrap_or(-1)
        ));
    }

    Ok(stdout)
}

// ── TCP helper ──────────────────────────────────────────────────────────────

/// Send a one-line command to the daemon and read the full response.
fn daemon_command(cmd: &str) -> Result<String, String> {
    let mut stream = TcpStream::connect_timeout(
        &DAEMON_ADDR.parse().unwrap(),
        TCP_CONNECT_TIMEOUT,
    )
    .map_err(|e| format!("Cannot connect to daemon at {DAEMON_ADDR}: {e}"))?;

    stream
        .set_read_timeout(Some(TCP_READ_TIMEOUT))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let payload = if cmd.ends_with('\n') {
        cmd.to_string()
    } else {
        format!("{cmd}\n")
    };
    stream
        .write_all(payload.as_bytes())
        .map_err(|e| format!("Failed to send command to daemon: {e}"))?;

    let mut response_bytes = Vec::with_capacity(1024 * 1024);
    stream
        .read_to_end(&mut response_bytes)
        .map_err(|e| format!("Failed to read daemon response: {e}"))?;

    let response = String::from_utf8_lossy(&response_bytes).trim().to_string();
    Ok(response)
}

fn upload_timeout_for_size(size: u64) -> Duration {
    let sec = 60 + (size / (1024 * 1024)) * 5;
    Duration::from_secs(sec.min(3600))
}

fn transfer_timeout_for_size(size: u64) -> Duration {
    upload_timeout_for_size(size)
}

fn is_allowed_device_path(path: &str) -> bool {
    path.starts_with("/sdcard/") || path == "/sdcard"
        || path.starts_with("/storage/emulated/0/") || path == "/storage/emulated/0"
}

fn join_device_path(base: &str, relative: &str) -> String {
    let base = base.trim_end_matches('/');
    let relative = relative.trim_start_matches('/');
    if relative.is_empty() {
        base.to_string()
    } else {
        format!("{base}/{relative}")
    }
}

#[derive(Clone, Copy, Debug)]
struct TimestampPair {
    secs: i64,
    nsecs: u32,
}

impl TimestampPair {
    fn zero() -> Self {
        Self { secs: 0, nsecs: 0 }
    }
}

fn system_time_to_pair(time: SystemTime) -> TimestampPair {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    TimestampPair {
        secs: duration.as_secs() as i64,
        nsecs: duration.subsec_nanos(),
    }
}

fn read_local_timestamps(path: &Path) -> (TimestampPair, TimestampPair) {
    let metadata = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(_) => return (TimestampPair::zero(), TimestampPair::zero()),
    };

    let mtime = metadata
        .modified()
        .ok()
        .map(system_time_to_pair)
        .unwrap_or_else(TimestampPair::zero);

    let atime = metadata
        .accessed()
        .ok()
        .map(system_time_to_pair)
        .unwrap_or(mtime);

    (mtime, atime)
}

fn json_i64(value: &serde_json::Value, key: &str) -> i64 {
    value
        .get(key)
        .and_then(|v| v.as_i64())
        .unwrap_or(0)
}

fn json_u32(value: &serde_json::Value, key: &str) -> u32 {
    value
        .get(key)
        .and_then(|v| v.as_u64())
        .map(|v| v as u32)
        .unwrap_or(0)
}

fn apply_local_file_timestamps(
    path: &Path,
    mtime_sec: i64,
    mtime_nsec: u32,
    atime_sec: i64,
    atime_nsec: u32,
) {
    if mtime_sec <= 0 {
        return;
    }

    let mtime = FileTime::from_unix_time(mtime_sec, mtime_nsec);
    let atime = if atime_sec > 0 {
        FileTime::from_unix_time(atime_sec, atime_nsec)
    } else {
        mtime
    };

    if set_file_times(path, atime, mtime).is_err() {
        return;
    }

    #[cfg(windows)]
    set_windows_creation_time(path, mtime);
}

#[cfg(windows)]
fn set_windows_creation_time(path: &Path, mtime: FileTime) {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::FILETIME;
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, SetFileTime, FILE_FLAG_BACKUP_SEMANTICS, FILE_GENERIC_WRITE,
        FILE_SHARE_READ, OPEN_EXISTING,
    };

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        return;
    }

    let stamp = mtime.to_windows();
    let filetime = FILETIME {
        dwLowDateTime: stamp as u32,
        dwHighDateTime: (stamp >> 32) as u32,
    };

    unsafe {
        SetFileTime(
            handle,
            &filetime,
            std::ptr::null(),
            std::ptr::null(),
        );
        windows_sys::Win32::Foundation::CloseHandle(handle);
    }
}

fn read_response_line(stream: &mut TcpStream) -> Result<String, String> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        stream
            .read_exact(&mut byte)
            .map_err(|e| format!("Failed to read daemon response: {e}"))?;
        if byte[0] == b'\n' {
            break;
        }
        if byte[0] != b'\r' {
            line.push(byte[0]);
        }
    }
    String::from_utf8(line).map_err(|e| format!("Invalid daemon response: {e}"))
}

fn collect_upload_entries(
    local_paths: &[String],
    dest_dir: &str,
) -> Result<Vec<(PathBuf, String)>, String> {
    let mut entries = Vec::new();

    for local_path in local_paths {
        let path = Path::new(local_path);
        if !path.exists() {
            return Err(format!("Local path not found: {local_path}"));
        }

        if path.is_file() {
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| format!("Invalid file name: {local_path}"))?;
            entries.push((path.to_path_buf(), join_device_path(dest_dir, file_name)));
        } else if path.is_dir() {
            collect_dir_entries(path, path, dest_dir, &mut entries)?;
        }
    }

    Ok(entries)
}

fn collect_dir_entries(
    root: &Path,
    current: &Path,
    dest_dir: &str,
    entries: &mut Vec<(PathBuf, String)>,
) -> Result<(), String> {
    for entry in std::fs::read_dir(current)
        .map_err(|e| format!("Failed to read directory {}: {e}", current.display()))?
    {
        let entry = entry.map_err(|e| format!("Failed to read directory entry: {e}"))?;
        let entry_path = entry.path();
        if entry_path.is_dir() {
            collect_dir_entries(root, &entry_path, dest_dir, entries)?;
        } else if entry_path.is_file() {
            let relative = entry_path
                .strip_prefix(root)
                .map_err(|e| format!("Failed to compute relative path: {e}"))?;
            let relative_str = relative
                .to_str()
                .ok_or_else(|| format!("Invalid path: {}", entry_path.display()))?
                .replace('\\', "/");
            entries.push((
                entry_path,
                join_device_path(dest_dir, &relative_str),
            ));
        }
    }
    Ok(())
}

fn emit_upload_progress(
    app: &tauri::AppHandle,
    local_path: &str,
    dest_path: &str,
    bytes_sent: u64,
    total: u64,
    file_index: usize,
    file_count: usize,
) {
    let percent = if total == 0 {
        100.0
    } else {
        (bytes_sent as f64 / total as f64) * 100.0
    };
    let _ = app.emit(
        "upload-progress",
        serde_json::json!({
            "file": local_path,
            "dest_path": dest_path,
            "bytes_sent": bytes_sent,
            "total": total,
            "percent": percent,
            "file_index": file_index,
            "file_count": file_count,
        }),
    );
}

fn daemon_upload(
    app: &tauri::AppHandle,
    local_path: &Path,
    dest_path: &str,
    file_index: usize,
    file_count: usize,
) -> Result<u64, String> {
    if !is_allowed_device_path(dest_path) {
        return Err(format!("Destination path not allowed: {dest_path}"));
    }

    let metadata = std::fs::metadata(local_path)
        .map_err(|e| format!("Failed to read {}: {e}", local_path.display()))?;
    if !metadata.is_file() {
        return Err(format!("Not a file: {}", local_path.display()));
    }

    let size = metadata.len();
    let local_display = local_path.to_string_lossy().to_string();
    let (mtime, atime) = read_local_timestamps(local_path);

    let mut stream = TcpStream::connect_timeout(
        &DAEMON_ADDR.parse().unwrap(),
        TCP_CONNECT_TIMEOUT,
    )
    .map_err(|e| format!("Cannot connect to daemon at {DAEMON_ADDR}: {e}"))?;

    stream
        .set_read_timeout(Some(upload_timeout_for_size(size)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let header = format!(
        "PUT {dest_path} {size} {} {} {} {}\n",
        mtime.secs, mtime.nsecs, atime.secs, atime.nsecs
    );
    stream
        .write_all(header.as_bytes())
        .map_err(|e| format!("Failed to send upload header: {e}"))?;

    let mut file = BufReader::new(
        File::open(local_path)
            .map_err(|e| format!("Failed to open {}: {e}", local_path.display()))?,
    );
    let mut buffer = vec![0u8; UPLOAD_CHUNK_SIZE];
    let mut bytes_sent = 0u64;

    emit_upload_progress(
        app,
        &local_display,
        dest_path,
        bytes_sent,
        size,
        file_index,
        file_count,
    );

    while bytes_sent < size {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("Failed to read {}: {e}", local_display))?;
        if read == 0 {
            return Err(format!("Unexpected end of file: {local_display}"));
        }

        stream
            .write_all(&buffer[..read])
            .map_err(|e| format!("Failed to send file data: {e}"))?;
        bytes_sent += read as u64;

        emit_upload_progress(
            app,
            &local_display,
            dest_path,
            bytes_sent,
            size,
            file_index,
            file_count,
        );
    }

    let response = read_response_line(&mut stream)?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("Invalid upload response: {e}"))?;

    if parsed.get("status").and_then(|v| v.as_str()) != Some("ok") {
        let message = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Upload failed");
        return Err(message.to_string());
    }

    Ok(parsed
        .get("bytes_written")
        .and_then(|v| v.as_u64())
        .unwrap_or(bytes_sent))
}

fn read_exact(stream: &mut TcpStream, buf: &mut [u8]) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = stream
            .read(&mut buf[filled..])
            .map_err(|e| format!("Failed to read file data: {e}"))?;
        if n == 0 {
            return Err("Download interrupted".into());
        }
        filled += n;
    }
    Ok(())
}

fn emit_download_progress(
    app: &tauri::AppHandle,
    device_path: &str,
    local_path: &str,
    bytes_received: u64,
    total: u64,
    file_index: usize,
    file_count: usize,
) {
    let percent = if total == 0 {
        100.0
    } else {
        (bytes_received as f64 / total as f64) * 100.0
    };
    let _ = app.emit(
        "download-progress",
        serde_json::json!({
            "device_path": device_path,
            "local_path": local_path,
            "bytes_received": bytes_received,
            "total": total,
            "percent": percent,
            "file_index": file_index,
            "file_count": file_count,
        }),
    );
}

fn daemon_download(
    app: &tauri::AppHandle,
    device_path: &str,
    local_path: &Path,
    file_index: usize,
    file_count: usize,
) -> Result<u64, String> {
    if !is_allowed_device_path(device_path) {
        return Err(format!("Source path not allowed: {device_path}"));
    }

    let mut stream = TcpStream::connect_timeout(
        &DAEMON_ADDR.parse().unwrap(),
        TCP_CONNECT_TIMEOUT,
    )
    .map_err(|e| format!("Cannot connect to daemon at {DAEMON_ADDR}: {e}"))?;

    stream
        .set_read_timeout(Some(TCP_READ_TIMEOUT))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    let header = format!("GET {device_path}\n");
    stream
        .write_all(header.as_bytes())
        .map_err(|e| format!("Failed to send download request: {e}"))?;

    let response = read_response_line(&mut stream)?;
    let parsed: serde_json::Value = serde_json::from_str(&response)
        .map_err(|e| format!("Invalid download response: {e}"))?;

    if parsed.get("status").and_then(|v| v.as_str()) != Some("ok") {
        let message = parsed
            .get("message")
            .and_then(|v| v.as_str())
            .unwrap_or("Download failed");
        return Err(message.to_string());
    }

    let size = parsed
        .get("size")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "Download response missing size".to_string())?;

    stream
        .set_read_timeout(Some(transfer_timeout_for_size(size)))
        .map_err(|e| format!("Failed to set read timeout: {e}"))?;

    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create {}: {e}", parent.display()))?;
    }

    let mut file = File::create(local_path)
        .map_err(|e| format!("Failed to create {}: {e}", local_path.display()))?;
    let local_display = local_path.to_string_lossy().to_string();
    let mut buffer = vec![0u8; UPLOAD_CHUNK_SIZE];
    let mut bytes_received = 0u64;

    emit_download_progress(
        app,
        device_path,
        &local_display,
        bytes_received,
        size,
        file_index,
        file_count,
    );

    while bytes_received < size {
        let remaining = (size - bytes_received) as usize;
        let chunk = remaining.min(buffer.len());
        read_exact(&mut stream, &mut buffer[..chunk])?;
        file.write_all(&buffer[..chunk])
            .map_err(|e| format!("Failed to write {}: {e}", local_display))?;
        bytes_received += chunk as u64;

        emit_download_progress(
            app,
            device_path,
            &local_display,
            bytes_received,
            size,
            file_index,
            file_count,
        );
    }
    drop(file);

    apply_local_file_timestamps(
        local_path,
        json_i64(&parsed, "mtime_sec"),
        json_u32(&parsed, "mtime_nsec"),
        json_i64(&parsed, "atime_sec"),
        json_u32(&parsed, "atime_nsec"),
    );

    Ok(bytes_received)
}

fn trigger_media_scan(app: &tauri::AppHandle, device_paths: &[String]) {
    let adb_path = match get_bundled_binary(app, "adb") {
        Ok(path) => path,
        Err(_) => return,
    };

    for path in device_paths {
        let uri = format!("file://{path}");
        let _ = adb(
            &adb_path,
            &[
                "shell",
                "am",
                "broadcast",
                "-a",
                "android.intent.action.MEDIA_SCANNER_SCAN_FILE",
                "-d",
                &uri,
            ],
        );
    }
}

// ── Tauri Commands ──────────────────────────────────────────────────────────

#[tauri::command]
fn check_adb(app: tauri::AppHandle) -> Result<String, String> {
    let adb_path = get_bundled_binary(&app, "adb")?;
    let version = adb(&adb_path, &["version"])?;
    let first_line = version.lines().next().unwrap_or("unknown").to_string();
    Ok(first_line)
}

#[tauri::command]
fn init_daemon(app: tauri::AppHandle) -> Result<String, String> {
    let adb_path = get_bundled_binary(&app, "adb")?;
    let daemon_src = get_bundled_binary(&app, "daemon")?;

    // 1 — Verify ADB is reachable and a device is connected.
    adb(&adb_path, &["version"])?;
    let devices = adb(&adb_path, &["devices"])?;
    let connected = devices
        .lines()
        .filter(|l| l.contains("device") && !l.starts_with("List"))
        .count();
    if connected == 0 {
        return Err(
            "No Android device detected. Connect your phone via USB and enable USB Debugging.".into(),
        );
    }

    // 2 — Kill any zombie daemon before we push/start.
    let _ = adb(&adb_path, &["shell", "pkill -f socketsweep_daemon || true"]);

    // 2.5 — Automate MANAGE_EXTERNAL_STORAGE permission for the shell user.
    let _ = adb(&adb_path, &["shell", "appops set com.android.shell MANAGE_EXTERNAL_STORAGE allow"]);

    // 4 — Push binary to device.
    adb(&adb_path, &["push", &daemon_src.to_string_lossy(), DEVICE_BIN_PATH])?;

    // 5 — Make it executable.
    adb(&adb_path, &["shell", "chmod", "+x", DEVICE_BIN_PATH])?;

    // 5 — Kill any previously running instance (ignore errors).
    let _ = adb(&adb_path, &["shell", "pkill", "-f", "socketsweep_daemon"]);
    std::thread::sleep(Duration::from_millis(300));

    // 6 — Start the daemon in the background on the device.
    let start_cmd = format!("nohup {DEVICE_BIN_PATH} > /dev/null 2>&1 & echo $!; exit");
    let pid_output = adb(&adb_path, &["shell", &start_cmd])?;
    let pid = pid_output.trim().to_string();

    // 7 — Set up the USB TCP tunnel.
    adb(&adb_path, &["forward", &format!("tcp:{DAEMON_PORT}"), &format!("tcp:{DAEMON_PORT}")])?;

    // 8 — Ping-Retry loop.
    let mut pong = String::new();
    let mut connected_daemon = false;
    for _ in 0..15 {
        std::thread::sleep(Duration::from_millis(150));
        match daemon_command("PING") {
            Ok(res) => {
                pong = res;
                connected_daemon = true;
                break;
            }
            Err(_) => continue,
        }
    }

    if !connected_daemon {
        return Err("Daemon started but failed to respond to PING over TCP tunnel.".into());
    }

    Ok(format!(
        "{{\"daemon_pid\":\"{pid}\",\"ping_response\":{pong}}}"
    ))
}

#[tauri::command]
fn run_scan(path: Option<String>) -> Result<String, String> {
    let effective_root = match path {
        Some(ref p) if !p.is_empty() => p.clone(),
        _ => "/sdcard".to_string(), // daemon default
    };
    let cmd = format!("SCAN {effective_root}");
    let response = daemon_command(&cmd)?;

    // Store the scan root so delete_item can guard against it.
    if let Ok(mut root) = SCAN_ROOT.lock() {
        *root = Some(effective_root);
    }

    Ok(response)
}

#[tauri::command]
fn ping_daemon() -> Result<String, String> {
    daemon_command("PING")
}

#[tauri::command]
fn stop_daemon(app: tauri::AppHandle) -> Result<String, String> {
    let adb_path = get_bundled_binary(&app, "adb")?;
    let response = daemon_command("SHUTDOWN").unwrap_or_else(|_| "daemon already stopped".into());
    let _ = adb(&adb_path, &["forward", "--remove", &format!("tcp:{DAEMON_PORT}")]);
    let _ = adb(&adb_path, &["shell", "rm", DEVICE_BIN_PATH]);
    Ok(response)
}

#[tauri::command]
fn delete_item(path: String) -> Result<String, String> {
    // Prevent deletion of the scan root directory.
    if let Ok(root) = SCAN_ROOT.lock() {
        if let Some(ref scan_root) = *root {
            if path == *scan_root {
                return Err("Cannot delete the scan root directory.".into());
            }
        }
    }
    daemon_command(&format!("DELETE {path}"))
}

#[tauri::command]
fn upload_file(
    app: tauri::AppHandle,
    local_path: String,
    dest_path: String,
) -> Result<String, String> {
    let bytes = daemon_upload(&app, Path::new(&local_path), &dest_path, 1, 1)?;
    trigger_media_scan(&app, &[dest_path.clone()]);
    Ok(serde_json::json!({
        "status": "ok",
        "bytes_written": bytes,
        "path": dest_path,
    })
    .to_string())
}

#[tauri::command]
fn upload_files(
    app: tauri::AppHandle,
    local_paths: Vec<String>,
    dest_dir: String,
) -> Result<String, String> {
    let dest_dir = dest_dir.trim_end_matches('/').to_string();
    if !is_allowed_device_path(&dest_dir) {
        return Err(format!("Destination directory not allowed: {dest_dir}"));
    }
    if local_paths.is_empty() {
        return Err("No files selected for upload.".into());
    }

    let entries = collect_upload_entries(&local_paths, &dest_dir)?;
    if entries.is_empty() {
        return Err("No files found to upload.".into());
    }

    let file_count = entries.len();
    let mut uploaded = 0usize;
    let mut failed = 0usize;
    let mut total_bytes = 0u64;
    let mut uploaded_paths = Vec::new();
    let mut results = Vec::new();

    for (index, (local_path, device_path)) in entries.iter().enumerate() {
        match daemon_upload(
            &app,
            local_path,
            device_path,
            index + 1,
            file_count,
        ) {
            Ok(bytes) => {
                uploaded += 1;
                total_bytes += bytes;
                uploaded_paths.push(device_path.clone());
                results.push(serde_json::json!({
                    "local_path": local_path.to_string_lossy(),
                    "dest_path": device_path,
                    "bytes_written": bytes,
                    "status": "ok",
                }));
            }
            Err(err) => {
                failed += 1;
                results.push(serde_json::json!({
                    "local_path": local_path.to_string_lossy(),
                    "dest_path": device_path,
                    "status": "error",
                    "message": err,
                }));
            }
        }
    }

    trigger_media_scan(&app, &uploaded_paths);

    Ok(serde_json::json!({
        "status": if failed == 0 { "ok" } else { "partial" },
        "uploaded": uploaded,
        "failed": failed,
        "total_bytes": total_bytes,
        "files": results,
    })
    .to_string())
}

#[derive(Debug, Deserialize)]
struct DownloadEntry {
    device_path: String,
    relative_path: String,
}

#[tauri::command]
fn download_file(
    app: tauri::AppHandle,
    device_path: String,
    dest_dir: String,
) -> Result<String, String> {
    let dest_dir = dest_dir.trim_end_matches('/');
    let file_name = Path::new(&device_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| format!("Invalid device path: {device_path}"))?;
    let local_path = PathBuf::from(dest_dir).join(file_name);
    let bytes = daemon_download(&app, &device_path, &local_path, 1, 1)?;
    Ok(serde_json::json!({
        "status": "ok",
        "bytes_received": bytes,
        "local_path": local_path.to_string_lossy(),
        "device_path": device_path,
    })
    .to_string())
}

#[tauri::command]
fn download_files(
    app: tauri::AppHandle,
    entries: Vec<DownloadEntry>,
    dest_dir: String,
) -> Result<String, String> {
    let dest_dir = dest_dir.trim_end_matches('/');
    if dest_dir.is_empty() {
        return Err("Destination directory is required.".into());
    }
    if entries.is_empty() {
        return Err("No files selected for download.".into());
    }

    let dest_root = PathBuf::from(dest_dir);
    std::fs::create_dir_all(&dest_root)
        .map_err(|e| format!("Failed to create {}: {e}", dest_root.display()))?;

    let file_count = entries.len();
    let mut downloaded = 0usize;
    let mut failed = 0usize;
    let mut total_bytes = 0u64;
    let mut results = Vec::new();

    for (index, entry) in entries.iter().enumerate() {
        if !is_allowed_device_path(&entry.device_path) {
            failed += 1;
            results.push(serde_json::json!({
                "device_path": entry.device_path,
                "relative_path": entry.relative_path,
                "status": "error",
                "message": "Source path not allowed",
            }));
            continue;
        }

        let local_path = dest_root.join(&entry.relative_path);
        match daemon_download(
            &app,
            &entry.device_path,
            &local_path,
            index + 1,
            file_count,
        ) {
            Ok(bytes) => {
                downloaded += 1;
                total_bytes += bytes;
                results.push(serde_json::json!({
                    "device_path": entry.device_path,
                    "local_path": local_path.to_string_lossy(),
                    "relative_path": entry.relative_path,
                    "bytes_received": bytes,
                    "status": "ok",
                }));
            }
            Err(err) => {
                failed += 1;
                results.push(serde_json::json!({
                    "device_path": entry.device_path,
                    "relative_path": entry.relative_path,
                    "status": "error",
                    "message": err,
                }));
            }
        }
    }

    Ok(serde_json::json!({
        "status": if failed == 0 { "ok" } else { "partial" },
        "downloaded": downloaded,
        "failed": failed,
        "total_bytes": total_bytes,
        "dest_dir": dest_dir,
        "files": results,
    })
    .to_string())
}

// ── Tauri entry point ───────────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            check_adb,
            init_daemon,
            run_scan,
            ping_daemon,
            stop_daemon,
            delete_item,
            upload_file,
            upload_files,
            download_file,
            download_files,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
