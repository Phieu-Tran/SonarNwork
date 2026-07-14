use std::{path::PathBuf, sync::Mutex};

use sonar_tools::operations::{
    capture_runtime_status as shared_capture_runtime_status,
    list_capture_interfaces as shared_list_capture_interfaces, OperationsService,
};
use tauri::{Emitter, Manager};

pub use sonar_tools::operations::{
    CaptureInterface, CaptureRequest, CaptureResult, CaptureRuntime, InventorySnapshot,
    MonitorConfig, StartMonitorRequest, TimelineEvent,
};

#[derive(Default)]
pub struct OperationsState {
    service: Mutex<Option<OperationsService>>,
}

fn service(app: &tauri::AppHandle, state: &OperationsState) -> Result<OperationsService, String> {
    let mut slot = state
        .service
        .lock()
        .map_err(|_| "operations service is poisoned")?;
    if let Some(service) = slot.as_ref() {
        return Ok(service.clone());
    }
    let data_dir = app
        .path()
        .app_data_dir()
        .map_err(|error| error.to_string())?;
    let event_app = app.clone();
    let next = OperationsService::with_event_sink(data_dir, move |event| {
        let _ = event_app.emit("operations-event", event);
    });
    *slot = Some(next.clone());
    Ok(next)
}

#[tauri::command]
pub fn capture_runtime_status() -> CaptureRuntime {
    shared_capture_runtime_status()
}

#[tauri::command]
pub fn list_capture_interfaces() -> Result<Vec<CaptureInterface>, String> {
    shared_list_capture_interfaces()
}

#[tauri::command]
pub async fn capture_packets(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
    request: CaptureRequest,
) -> Result<CaptureResult, String> {
    let service = service(&app, &state)?;
    tauri::async_runtime::spawn_blocking(move || service.capture_packets(request))
        .await
        .map_err(|error| error.to_string())?
}

#[tauri::command]
pub fn open_capture_handoff(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
    path: PathBuf,
) -> Result<(), String> {
    service(&app, &state)?.open_capture_handoff(path)
}

#[tauri::command]
pub fn collect_device_inventory(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
) -> Result<InventorySnapshot, String> {
    service(&app, &state)?.collect_device_inventory()
}

#[tauri::command]
pub fn start_monitor(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
    request: StartMonitorRequest,
) -> Result<MonitorConfig, String> {
    service(&app, &state)?.start_monitor(request)
}

#[tauri::command]
pub fn stop_monitor(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
    monitor_id: String,
) -> Result<(), String> {
    service(&app, &state)?.stop_monitor(&monitor_id)
}

#[tauri::command]
pub fn list_monitors(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
) -> Result<Vec<MonitorConfig>, String> {
    service(&app, &state)?.list_monitors()
}

#[tauri::command]
pub fn list_timeline(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
) -> Result<Vec<TimelineEvent>, String> {
    service(&app, &state)?.list_timeline()
}

#[tauri::command]
pub fn clear_timeline(
    app: tauri::AppHandle,
    state: tauri::State<'_, OperationsState>,
) -> Result<(), String> {
    service(&app, &state)?.clear_timeline()
}

pub fn resume_monitors(app: tauri::AppHandle) -> Result<(), String> {
    let state = app.state::<OperationsState>();
    service(&app, &state)?.resume_monitors()
}
