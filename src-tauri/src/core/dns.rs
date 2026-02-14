use std::net::ToSocketAddrs;
use std::process::Command;

#[derive(serde::Serialize, Clone)]
pub struct DnsResult {
    pub record_type: String,
    pub values: Vec<String>,
    pub error: Option<String>,
}

/// DNS Lookup - Resolve domain to IP addresses
#[tauri::command]
pub async fn dns_lookup(domain: String, record_type: String) -> Result<DnsResult, String> {
    match record_type.as_str() {
        "A" | "AAAA" => {
            // Use standard library for A/AAAA records
            let addr = format!("{}:80", domain);
            match addr.to_socket_addrs() {
                Ok(addrs) => {
                    let ips: Vec<String> = addrs
                        .filter(|a| {
                            if record_type == "A" { a.is_ipv4() } else { a.is_ipv6() }
                        })
                        .map(|a| a.ip().to_string())
                        .collect();
                    
                    if ips.is_empty() {
                        Ok(DnsResult {
                            record_type,
                            values: vec![],
                            error: Some("No records found".to_string()),
                        })
                    } else {
                        Ok(DnsResult {
                            record_type,
                            values: ips,
                            error: None,
                        })
                    }
                }
                Err(e) => Ok(DnsResult {
                    record_type,
                    values: vec![],
                    error: Some(e.to_string()),
                }),
            }
        }
        "MX" | "TXT" | "NS" | "CNAME" | "SOA" => {
            // Use nslookup for other record types (Windows compatible)
            let output = Command::new("nslookup")
                .args(["-type=".to_string() + &record_type, domain.clone()])
                .output()
                .map_err(|e| e.to_string())?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            
            if !output.status.success() {
                return Ok(DnsResult {
                    record_type,
                    values: vec![],
                    error: Some(stderr.to_string()),
                });
            }
            
            // Parse nslookup output
            let values: Vec<String> = stdout
                .lines()
                .filter(|line| {
                    // Filter relevant lines based on record type
                    match record_type.as_str() {
                        "MX" => line.contains("mail exchanger"),
                        "TXT" => line.contains("text ="),
                        "NS" => line.contains("nameserver"),
                        "CNAME" => line.contains("canonical name"),
                        "SOA" => line.contains("primary name server"),
                        _ => false,
                    }
                })
                .map(|s| s.trim().to_string())
                .collect();
            
            Ok(DnsResult {
                record_type,
                values,
                error: None,
            })
        }
        "PTR" => {
            // Reverse DNS lookup
            let output = Command::new("nslookup")
                .arg(&domain)
                .output()
                .map_err(|e| e.to_string())?;
            
            let stdout = String::from_utf8_lossy(&output.stdout);
            
            let values: Vec<String> = stdout
                .lines()
                .filter(|line| line.contains("name ="))
                .map(|s| s.split("name =").last().unwrap_or("").trim().to_string())
                .collect();
            
            Ok(DnsResult {
                record_type,
                values,
                error: None,
            })
        }
        _ => Err(format!("Unsupported record type: {}", record_type)),
    }
}

/// Reverse DNS - IP to hostname
#[tauri::command]
pub async fn reverse_dns(ip: String) -> Result<String, String> {
    let output = Command::new("nslookup")
        .arg(&ip)
        .output()
        .map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    for line in stdout.lines() {
        if line.contains("name =") {
            if let Some(name) = line.split("name =").last() {
                return Ok(name.trim().trim_end_matches('.').to_string());
            }
        }
    }
    
    Err("No PTR record found".to_string())
}
