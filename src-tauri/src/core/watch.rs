use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tauri::{AppHandle, Manager, Emitter};
use crate::AppState;

/// Global flag to control watch mode
static WATCH_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Watch mode event payload
#[derive(Clone, serde::Serialize)]
pub struct WatchEvent {
    pub event_type: String,
    pub message: String,
    pub severity: String,
    pub timestamp: String,
    pub data: Option<serde_json::Value>,
}

/// Start watch mode - continuous background monitoring
#[tauri::command]
pub async fn start_watch_mode(app: AppHandle) -> Result<String, String> {
    if WATCH_ACTIVE.load(Ordering::SeqCst) {
        return Err("Watch mode already active".to_string());
    }
    
    WATCH_ACTIVE.store(true, Ordering::SeqCst);
    
    let app_handle = app.clone();
    
    // Spawn background task
    tokio::spawn(async move {
        println!("[WATCH] Mode activated - Starting continuous monitoring");
        
        while WATCH_ACTIVE.load(Ordering::SeqCst) {
            // Analyze current network state
            if let Some(state) = app_handle.try_state::<AppState>() {
                // Get stats
                let (packet_count, device_count) = {
                    let stats_guard = state.stats.lock().unwrap();
                    let devices_guard = state.devices.lock().unwrap();
                    (stats_guard.total_packets, devices_guard.len())
                };
                
                // Get alerts from database
                let alerts = state.db.get_recent_alerts(5).unwrap_or_default();
                let threat_count = alerts.len();
                
                // Emit periodic status update
                let event = WatchEvent {
                    event_type: "status".to_string(),
                    message: format!("Packets: {} | Devices: {} | Threats: {}", packet_count, device_count, threat_count),
                    severity: "info".to_string(),
                    timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                    data: Some(serde_json::json!({
                        "packets": packet_count,
                        "devices": device_count,
                        "threats": threat_count
                    })),
                };
                
                let _ = app_handle.emit("watch_status", &event);
                
                // Emit threat events for recent alerts
                for alert in alerts.iter() {
                    let threat_event = WatchEvent {
                        event_type: "threat".to_string(),
                        message: format!("{}: {}", alert.title, alert.description),
                        severity: alert.level.clone(),
                        timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
                        data: Some(serde_json::json!({
                            "source_ip": alert.source_ip,
                            "threat_type": alert.title
                        })),
                    };
                    
                    let _ = app_handle.emit("watch_threat", &threat_event);
                }
            }
            
            // Sleep for 5 seconds before next check
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        
        println!("[WATCH] Mode deactivated");
    });
    
    Ok("Watch mode started".to_string())
}

/// Stop watch mode
#[tauri::command]
pub fn stop_watch_mode() -> Result<String, String> {
    if !WATCH_ACTIVE.load(Ordering::SeqCst) {
        return Err("Watch mode not active".to_string());
    }
    
    WATCH_ACTIVE.store(false, Ordering::SeqCst);
    Ok("Watch mode stopped".to_string())
}

/// Get current watch mode status
#[tauri::command]
pub fn get_watch_status() -> bool {
    WATCH_ACTIVE.load(Ordering::SeqCst)
}
