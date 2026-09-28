use std::process::{Child, Command};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tauri::AppHandle;

static BACKEND_CHILD: Mutex<Option<Child>> = Mutex::new(None);

/// Find the Python executable (python3 preferred, fallback to python)
fn find_python() -> Option<String> {
    for candidate in &["python3", "python"] {
        if let Ok(output) = Command::new(candidate).arg("--version").output() {
            if output.status.success() {
                return Some(candidate.to_string());
            }
        }
    }
    None
}

/// Resolve the path to backend/main.py relative to the app's resource directory
fn backend_script_path(app: &AppHandle) -> std::path::PathBuf {
    // In dev the resource dir sits two levels above src-tauri
    // In production Tauri bundles resources adjacent to the binary
    let resource_dir = app
        .path()
        .resource_dir()
        .unwrap_or_else(|_| std::env::current_dir().unwrap());

    // Try repo-relative path for development
    let dev_path = resource_dir
        .parent()
        .and_then(|p| p.parent())
        .map(|p| p.join("backend").join("main.py"));

    if let Some(p) = dev_path {
        if p.exists() {
            return p;
        }
    }

    resource_dir.join("backend").join("main.py")
}

/// Spawn the FastAPI/uvicorn backend in a child process
pub fn spawn_backend(app: AppHandle) {
    let python = match find_python() {
        Some(p) => p,
        None => {
            eprintln!("[NEXUS] Python not found — backend will not start");
            return;
        }
    };

    let script = backend_script_path(&app);

    // Build the command: python3 backend/main.py
    let child = Command::new(&python)
        .arg(&script)
        .env("UVICORN_PORT", "8000")
        .spawn();

    match child {
        Ok(c) => {
            let pid = c.id();
            let mut guard = BACKEND_CHILD.lock().unwrap();
            *guard = Some(c);
            println!("[NEXUS] Backend started (PID {})", pid);

            // Spawn an async health-check task
            tokio::spawn(async {
                if wait_for_backend(15_000).await {
                    println!("[NEXUS] Backend is healthy");
                } else {
                    eprintln!("[NEXUS] Backend health check timed out");
                }
            });
        }
        Err(e) => {
            eprintln!("[NEXUS] Failed to start backend: {}", e);
        }
    }
}

/// Kill the stored backend child process
pub fn kill_backend() {
    let mut guard = BACKEND_CHILD.lock().unwrap();
    if let Some(ref mut child) = *guard {
        let _ = child.kill();
        let _ = child.wait();
        println!("[NEXUS] Backend stopped");
    }
    *guard = None;
}

/// Return true if the child process handle is stored (does not check health)
pub fn is_running() -> bool {
    let guard = BACKEND_CHILD.lock().unwrap();
    guard.is_some()
}

/// Poll localhost:8000/health until the server responds 200 or the timeout expires
pub async fn wait_for_backend(timeout_ms: u64) -> bool {
    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(500))
        .build()
        .unwrap_or_default();

    loop {
        if Instant::now() > deadline {
            return false;
        }

        match client.get("http://localhost:8000/health").send().await {
            Ok(r) if r.status().is_success() => return true,
            _ => {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}
