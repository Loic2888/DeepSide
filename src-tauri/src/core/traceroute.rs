use std::process::Command;

#[derive(serde::Serialize, Clone)]
pub struct TracerouteHop {
    pub hop: u32,
    pub ip: String,
    pub hostname: Option<String>,
    pub rtt_ms: Option<f64>,
}

/// Traceroute - Show network path to target
#[tauri::command]
pub async fn traceroute(target: String) -> Result<Vec<TracerouteHop>, String> {
    // Use tracert on Windows
    let output = Command::new("tracert")
        .args(["-d", "-h", "15", &target]) // -d = no DNS, -h 15 = max 15 hops
        .output()
        .map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut hops = Vec::new();
    
    for line in stdout.lines() {
        // Parse tracert output lines like "  1     1 ms     1 ms     1 ms  192.168.1.1"
        let line = line.trim();
        if line.is_empty() || line.starts_with("Tracing") || line.starts_with("over") || line.starts_with("Trace") {
            continue;
        }
        
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 5 {
            if let Ok(hop_num) = parts[0].parse::<u32>() {
                // Find IP address (last valid IP-like string)
                let ip = parts.last()
                    .filter(|s| s.contains('.') || **s == "*")
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "*".to_string());
                
                // Parse RTT (first numeric ms value)
                let rtt = parts.iter()
                    .find(|p| p.ends_with("ms") || p.parse::<f64>().is_ok())
                    .and_then(|p| p.trim_end_matches("ms").parse::<f64>().ok());
                
                hops.push(TracerouteHop {
                    hop: hop_num,
                    ip,
                    hostname: None,
                    rtt_ms: rtt,
                });
            }
        }
    }
    
    Ok(hops)
}
