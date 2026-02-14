use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};
use tokio::net::TcpStream;
use futures::stream::{self, StreamExt};

// --- 1. PING SWEEP ---

#[tauri::command]
pub async fn run_ping_sweep(app: AppHandle, subnet: String) -> Result<String, String> {
    // Expected subnet format: "192.168.1."
    // We will scan 1..255
    
    let subnet_base = if subnet.ends_with('.') { subnet } else { format!("{}.", subnet) };
    let temp_results = Arc::new(Mutex::new(Vec::new()));

    // Create a stream of IPs to scan
    let ips: Vec<String> = (1..255).map(|i| format!("{}{}", subnet_base, i)).collect();
    
    // Process in parallel (batches of 50)
    stream::iter(ips)
        .for_each_concurrent(50, |ip| {
            let app_handle = app.clone();
            let results = temp_results.clone();
            async move {
                // Windows Ping: -n 1 -w 200 (200ms timeout per IP for speed, total 255 IPs)
                #[cfg(target_os = "windows")]
                let cmd = "ping";
                #[cfg(not(target_os = "windows"))]
                let cmd = "ping";

                let output = Command::new(cmd)
                    .args(&["-n", "1", "-w", "200", &ip])
                    .output();

                if let Ok(out) = output {
                    let s = String::from_utf8_lossy(&out.stdout);
                    // Check for TTL (Time To Live) which signals a reply, works in most langs including FR
                    if s.contains("TTL=") || s.contains("ttl=") { 
                        // Alive!
                        println!("Ping Alive: {}", ip);
                        app_handle.emit("scan-result", ip.clone()).unwrap_or(());
                        results.lock().unwrap().push(ip.clone());
                    }
                }
            }
        }).await;

    let count = temp_results.lock().unwrap().len();
    Ok(format!("Sweep Complete. Found {} devices.", count))
}

// --- 2. PORT SCANNER ---

#[tauri::command]
pub async fn run_port_scan(target: String) -> Result<Vec<u16>, String> {
    let common_ports: Vec<u16> = vec![
        21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5900, 8080
    ];
    
    let results = Arc::new(Mutex::new(Vec::new()));

    stream::iter(common_ports)
        .for_each_concurrent(20, |port| {
            let target_ip = target.clone();
            let res_lock = results.clone();
            async move {
                let addr = format!("{}:{}", target_ip, port);
                // Try connect with timeout
                let timeout = tokio::time::timeout(
                    Duration::from_millis(1000), 
                    TcpStream::connect(&addr)
                ).await;

                if let Ok(Ok(_)) = timeout {
                    // Connected
                    res_lock.lock().unwrap().push(port);
                }
            }
        }).await;

    // Retrieve and sort
    let mut open_ports = results.lock().unwrap().clone();
    open_ports.sort();
    
    Ok(open_ports)
}

// --- 3. KILL SWITCH (FIREWALL) ---

#[tauri::command]
pub async fn toggle_block(ip: String, block: bool) -> Result<String, String> {
    let rule_name = format!("DeepSide_Block_{}", ip);
    
    if block {
        // ADD RULE
        // netsh advfirewall firewall add rule name="..." dir=in action=block remoteip=...
        
        let out = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=in",
                "action=block",
                &format!("remoteip={}", ip)
            ])
            .output()
            .map_err(|e| e.to_string())?;
            
        // Also block OUT
        let _ = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "add", "rule",
                &format!("name={}", rule_name),
                "dir=out", 
                "action=block",
                &format!("remoteip={}", ip)
            ])
            .output();

        if out.status.success() {
            Ok(format!("Target {} BLOCKED.", ip))
        } else {
            Err(String::from_utf8_lossy(&out.stderr).to_string())
        }
    } else {
        // DELETE RULE
        let out = Command::new("netsh")
            .args(&[
                "advfirewall", "firewall", "delete", "rule",
                &format!("name={}", rule_name)
            ])
            .output()
            .map_err(|e| e.to_string())?;

        if out.status.success() {
            Ok(format!("Target {} UNBLOCKED.", ip))
        } else {
            // It might fail if rule doesn't exist, which is fine
            Ok(format!("Target {} Unblocked (Rules cleared).", ip))
        }
    }
}
