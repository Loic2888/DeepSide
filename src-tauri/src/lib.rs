pub mod ai;
pub mod core;
pub mod data;
pub mod models;
pub mod database;
pub mod proxy;

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
use std::sync::{Arc, Mutex};
use tauri::{
    AppHandle, Manager,
    tray::{TrayIconBuilder, MouseButton, MouseButtonState, TrayIconEvent},
    menu::{Menu, MenuItem},
    WindowEvent,
};
use crate::models::monitor::{NetworkStats, Device};
use crate::core::sniffer;
use crate::database::Database;
use crate::core::arp::ArpSpoofer;
use crate::core::geoip::GeoIpEngine;

// Global Application State
pub struct AppState {
    pub stats: Arc<Mutex<NetworkStats>>,
    pub devices: Arc<Mutex<Vec<Device>>>,
    pub db: Arc<Database>,
    pub arp: Arc<ArpSpoofer>,
    pub geoip: Arc<GeoIpEngine>,
}

#[tauri::command]
fn start_sniffing(app: AppHandle, state: tauri::State<AppState>) -> Result<String, String> {
    let stats = state.stats.clone();
    let devices = state.devices.clone();
    let db = state.db.clone();
    
    // Spawn the sniffer thread
    std::thread::spawn(move || {
        if let Err(e) = sniffer::run_sniffer(&app, stats, devices, db) {
            eprintln!("Sniffer Error: {}", e);
        }
    });

    Ok("Sniffer started".to_string())
}

#[tauri::command]
fn get_alerts(state: tauri::State<AppState>) -> Result<Vec<crate::models::monitor::Alert>, String> {
    state.db.get_recent_alerts(10).map_err(|e| e.to_string())
}

#[tauri::command]
fn get_devices(state: tauri::State<AppState>) -> Result<Vec<crate::models::monitor::Device>, String> {
    state.db.get_all_devices().map_err(|e| e.to_string())
}

#[tauri::command]
fn get_credentials(state: tauri::State<AppState>, limit: i64) -> Result<Vec<crate::models::monitor::Credential>, String> {
    state.db.get_credentials(limit).map_err(|e| e.to_string())
}

#[tauri::command]
async fn start_arp(
    state: tauri::State<'_, AppState>, 
    target_ip: String, 
    target_mac: String, 
    gateway_ip: String, 
    gateway_mac: String
) -> Result<String, String> {
    state.arp.start(target_ip, target_mac, gateway_ip, gateway_mac).await?;
    Ok("ARP Spoofing Started".to_string())
}

#[tauri::command]
fn stop_arp(state: tauri::State<AppState>) -> Result<String, String> {
    state.arp.stop();
    Ok("ARP Spoofing Stopped".to_string())
}

#[tauri::command]
fn reset_network(state: tauri::State<AppState>) -> Result<String, String> {
    // 1. Clear DB
    state.db.clear_devices().map_err(|e| e.to_string())?;

    // 2. Clear In-Memory
    state.devices.lock().unwrap().clear();

    Ok("Network data reset successfully".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let app_handle = app.handle();
             // Standard App Data Dir (e.g., AppData/Roaming/DeepSide)
            let app_dir = app_handle.path().app_data_dir().expect("failed to get app data dir");
            std::fs::create_dir_all(&app_dir).expect("failed to create app data dir");
            let db_path = app_dir.join("deepside.db");
            
            let db = Arc::new(Database::new(db_path.to_str().unwrap()).expect("failed to init db"));
            
            // Clear old data on startup (Fresh Session)
            db.clear_devices().expect("failed to clear old devices");

            // Load history (should be empty now, or we can remove this line)
            let devices = db.get_all_devices().unwrap_or_default();
            println!("System Init: Cleared DB. Loaded {} devices.", devices.len());

            app.manage(AppState {
                stats: Arc::new(Mutex::new(NetworkStats::default())),
                devices: Arc::new(Mutex::new(devices)),
                db: db,
                arp: Arc::new(crate::core::arp::ArpSpoofer::new()),
                geoip: Arc::new(crate::core::geoip::GeoIpEngine::new(&app_handle)),
            });

            // ============================================
            // SYSTEM TRAY SETUP
            // ============================================
            let show_item = MenuItem::with_id(app, "show", "Afficher DeepSide", true, None::<&str>)?;
            let quit_item = MenuItem::with_id(app, "quit", "Quitter", true, None::<&str>)?;
            
            let menu = Menu::with_items(app, &[&show_item, &quit_item])?;
            
            let _tray = TrayIconBuilder::new()
                .icon(app.default_window_icon().unwrap().clone())
                .menu(&menu)
                .tooltip("DeepSide - Sentinel Actif")
                .on_menu_event(|app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    // Double-click to show window
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .on_window_event(|window, event| {
            // Minimize to tray instead of closing
            if let WindowEvent::CloseRequested { api, .. } = event {
                if window.label() == "main" {
                    let _ = window.hide();
                    api.prevent_close();
                }
            }
        })
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            start_sniffing,
            crate::core::tools::run_ping_sweep,
            crate::core::tools::run_port_scan,
            crate::core::tools::toggle_block,
            crate::proxy::server::run_proxy_server,
            crate::ai::ask_ai,
            crate::ai::check_ai_status,
            // get_alerts, // Removed as per instruction to replace with crate::core::tools::get_alerts
            get_devices,
            get_credentials,
            start_arp,
            stop_arp,
            crate::core::geoip::get_geoip,
            crate::core::whois::get_whois,
            crate::core::phishing::analyze_url,
            // Network Analysis Tools
            crate::core::dns::dns_lookup,
            crate::core::dns::reverse_dns,
            crate::core::traceroute::traceroute,
            crate::core::banner::grab_banner,
            crate::core::ssl::analyze_ssl,
            // Forensics Tools

            // Intelligence Tools
            crate::core::virustotal::virustotal_check,
            crate::core::threatintel::check_threat_intel,
            crate::core::shodan::shodan_lookup,
            crate::core::shodan::shodan_search,
            // Vulnerability Scanning
            crate::core::vulnscan::vuln_scan,
            crate::core::vulnscan::quick_vuln_scan,
            // Configuration
            crate::core::config::save_api_keys,
            crate::core::config::load_api_keys,
            crate::core::config::get_api_key,
            // Export
            crate::core::export::export_report_pdf,
            // Watch Mode
            crate::core::watch::start_watch_mode,
            crate::core::watch::stop_watch_mode,
            crate::core::watch::get_watch_status,
            get_alerts,
            reset_network
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
