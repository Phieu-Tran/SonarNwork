use std::sync::{Mutex, MutexGuard};

use sonar_tools::history::HistoryService;
use tauri::Manager;

pub use sonar_tools::history::{RunComparison, SaveRunInput, SavedRun, SavedRunSummary};

#[derive(Default)]
pub struct HistoryState {
    gate: Mutex<()>,
}

fn service(app: &tauri::AppHandle) -> Result<HistoryService, String> {
    app.path()
        .app_data_dir()
        .map(HistoryService::new)
        .map_err(|error| format!("could not resolve application data directory: {error}"))
}

fn lock_store(state: &HistoryState) -> Result<MutexGuard<'_, ()>, String> {
    state
        .gate
        .lock()
        .map_err(|_| "saved diagnostics store lock is poisoned".to_owned())
}

#[tauri::command]
pub fn save_probe_run(
    app: tauri::AppHandle,
    state: tauri::State<'_, HistoryState>,
    input: SaveRunInput,
) -> Result<SavedRunSummary, String> {
    let _guard = lock_store(&state)?;
    service(&app)?.save(input)
}

#[tauri::command]
pub fn list_probe_runs(
    app: tauri::AppHandle,
    state: tauri::State<'_, HistoryState>,
    query: Option<String>,
) -> Result<Vec<SavedRunSummary>, String> {
    let _guard = lock_store(&state)?;
    service(&app)?.list(query.as_deref())
}

#[tauri::command]
pub fn get_probe_run(
    app: tauri::AppHandle,
    state: tauri::State<'_, HistoryState>,
    id: String,
) -> Result<SavedRun, String> {
    let _guard = lock_store(&state)?;
    service(&app)?.get(&id)
}

#[tauri::command]
pub fn delete_probe_run(
    app: tauri::AppHandle,
    state: tauri::State<'_, HistoryState>,
    id: String,
) -> Result<(), String> {
    let _guard = lock_store(&state)?;
    service(&app)?.delete(&id)
}

#[tauri::command]
pub fn compare_probe_runs(
    app: tauri::AppHandle,
    state: tauri::State<'_, HistoryState>,
    left_id: String,
    right_id: String,
) -> Result<RunComparison, String> {
    let _guard = lock_store(&state)?;
    service(&app)?.compare(&left_id, &right_id)
}
