use tauri::{AppHandle, Manager};
use std::fs::File;
use std::io::Write;

/// Export packet capture to PCAP file
#[tauri::command]
pub async fn export_pcap(app: AppHandle, filename: String) -> Result<String, String> {
    // Get app data directory
    let app_dir = app.path().app_data_dir()
        .map_err(|e| e.to_string())?;
    
    let captures_dir = app_dir.join("captures");
    std::fs::create_dir_all(&captures_dir).map_err(|e| e.to_string())?;
    
    let filepath = captures_dir.join(&filename);
    
    // Create PCAP file header (standard format)
    let mut file = File::create(&filepath).map_err(|e| e.to_string())?;
    
    // PCAP Global Header
    let global_header: [u8; 24] = [
        0xd4, 0xc3, 0xb2, 0xa1, // Magic number (little endian)
        0x02, 0x00,             // Version major (2)
        0x04, 0x00,             // Version minor (4)
        0x00, 0x00, 0x00, 0x00, // Timezone (GMT)
        0x00, 0x00, 0x00, 0x00, // Timestamp accuracy
        0x00, 0x00, 0x01, 0x00, // Snaplen (65536)
        0x01, 0x00, 0x00, 0x00, // Link type (Ethernet)
    ];
    
    file.write_all(&global_header).map_err(|e| e.to_string())?;
    
    // Note: In a real implementation, we would write captured packets here
    // For now, we create an empty but valid PCAP file
    
    Ok(filepath.to_string_lossy().to_string())
}

/// Get list of saved captures
#[tauri::command]
pub async fn list_captures(app: AppHandle) -> Result<Vec<String>, String> {
    let app_dir = app.path().app_data_dir()
        .map_err(|e| e.to_string())?;
    
    let captures_dir = app_dir.join("captures");
    
    if !captures_dir.exists() {
        return Ok(vec![]);
    }
    
    let entries: Vec<String> = std::fs::read_dir(&captures_dir)
        .map_err(|e| e.to_string())?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "pcap"))
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    
    Ok(entries)
}
