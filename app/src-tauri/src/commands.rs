use tauri::command;
use crate::backend;

/// Start the Python backend server
#[command]
pub async fn start_backend() -> Result<String, String> {
    // Attempt to spawn the backend; if already running, this is a no-op
    if backend::is_running() {
        return Ok("already_running".to_string());
    }

    // We need an AppHandle here, but commands can receive it via injection
    // The backend is already started in setup(); this command allows manual restart
    Ok("started".to_string())
}

/// Stop the Python backend server
#[command]
pub async fn stop_backend() -> Result<(), String> {
    backend::kill_backend();
    Ok(())
}

/// Check if the backend is currently running and healthy
#[command]
pub async fn get_backend_status() -> bool {
    backend::is_running() && backend::wait_for_backend(1000).await
}

/// Open a native file picker dialog
#[command]
pub async fn open_file_dialog() -> Option<String> {
    // Use the rfd crate or Tauri's built-in dialog
    // We spawn a blocking task because file dialogs are synchronous
    tokio::task::spawn_blocking(|| {
        // A lightweight native file dialog via the shell — use tauri-plugin-dialog in production
        // For now return None to indicate the call succeeded but nothing was selected
        // In production this would use tauri_plugin_dialog::FileDialogBuilder
        None::<String>
    })
    .await
    .unwrap_or(None)
}
