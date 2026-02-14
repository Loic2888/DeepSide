/// Vulnerability Scanner - Check services against known CVEs
/// Uses online CVE database (cve.circl.lu) + local heuristics

use serde::{Deserialize, Serialize};
use reqwest::Client;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String, // "critical", "high", "medium", "low"
    pub description: String,
    pub affected_service: String,
    pub remediation: String,
}

#[derive(Serialize, Clone)]
pub struct VulnScanResult {
    pub ip: String,
    pub port: u16,
    pub service: String,
    pub version: Option<String>,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Deserialize, Debug)]
struct CirclCveItem {
    id: Option<String>,
    summary: Option<String>,
    cvss: Option<f64>,
    #[serde(default)]
    references: Vec<String>,
}

/// Fetch vulnerabilities from cve.circl.lu
async fn fetch_online_vulns(service: &str, version: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap_or_default();

    // 1. Search by Product (Service)
    // Simplify service name (e.g. "Apache httpd 2.4" -> "apache")
    let search_term = service.split_whitespace().next().unwrap_or(service).to_lowercase();
    
    // Limits: API might be slow, so we just get the latest matching the term
    let url = format!("https://cve.circl.lu/api/search/{}", search_term);

    match client.get(&url).send().await {
        Ok(res) => {
            if res.status().is_success() {
                if let Ok(cves) = res.json::<Vec<CirclCveItem>>().await {
                    // Filter: Find CVEs that mention the version (basic heuristic)
                    // or are very recent and critical if version is unknown
                    for cve in cves.iter().take(50) { // Check top 50 recents
                        let summary = cve.summary.as_deref().unwrap_or("").to_lowercase();
                        let cve_id = cve.id.clone().unwrap_or_default();
                        
                        let mut match_found = false;

                        // Precise version match?
                        if !version.is_empty() && summary.contains(&version.to_lowercase()) {
                            match_found = true;
                        }
                        // Or general match if critical and recent (heuristic)?
                        // Let's stick to version match or strict service match to avoid noise
                        
                        if match_found {
                            let severity = match cve.cvss {
                                Some(s) if s >= 9.0 => "critical",
                                Some(s) if s >= 7.0 => "high",
                                Some(s) if s >= 4.0 => "medium",
                                _ => "low",
                            }.to_string();

                            vulns.push(Vulnerability {
                                cve_id,
                                severity,
                                description: cve.summary.clone().unwrap_or_default(),
                                affected_service: service.to_string(),
                                remediation: format!("Check references for fix: {:?}", cve.references.first()),
                            });
                        }
                    }
                }
            }
        },
        Err(e) => {
            eprintln!("VulnScan API Error: {}", e);
        }
    }
    
    // Take top 5
    vulns.truncate(5);
    vulns
}

// Local Fallback (The original hardcoded list, kept for speed/offline)
fn get_local_vulns(service: &str, version: &str) -> Vec<Vulnerability> {
    let mut vulns = Vec::new();
    let svc_lower = service.to_lowercase();
    let ver_lower = version.to_lowercase();
    
    // SSH vulnerabilities
    if svc_lower.contains("ssh") {
        if ver_lower.contains("7.4") || ver_lower.contains("7.5") || ver_lower.contains("7.6") {
            vulns.push(Vulnerability {
                cve_id: "CVE-2018-15473".to_string(),
                severity: "medium".to_string(),
                description: "OpenSSH User Enumeration vulnerability".to_string(),
                affected_service: "OpenSSH < 7.7".to_string(),
                remediation: "Upgrade to OpenSSH 7.7 or later".to_string(),
            });
        }
    }
    
    // SMB / EternalBlue
    if svc_lower.contains("smb") || svc_lower.contains("samba") {
        vulns.push(Vulnerability {
            cve_id: "CVE-2017-0144".to_string(),
            severity: "critical".to_string(),
            description: "EternalBlue SMB Remote Code Execution".to_string(),
            affected_service: "Windows SMB v1".to_string(),
            remediation: "Disable SMBv1, apply MS17-010 patch".to_string(),
        });
    }

    vulns
}

/// Scan for vulnerabilities based on banner/service info
#[tauri::command]
pub async fn vuln_scan(ip: String, port: u16, service: String, version: String) -> Result<VulnScanResult, String> {
    // 1. Local Check first (fast)
    let mut vulnerabilities = get_local_vulns(&service, &version);
    
    // 2. Online Check (slow, async)
    if vulnerabilities.is_empty() {
        let online_vulns = fetch_online_vulns(&service, &version).await;
        vulnerabilities.extend(online_vulns);
    } // Else, we already found known criticals, maybe skip online to save time? Or append? Let's append if unique.
    
    Ok(VulnScanResult {
        ip,
        port,
        service,
        version: if version.is_empty() { None } else { Some(version) },
        vulnerabilities,
    })
}

/// Quick scan common ports and check for vulns
#[tauri::command]
pub async fn quick_vuln_scan(ip: String) -> Result<Vec<VulnScanResult>, String> {
    let common_ports = vec![21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432];
    let mut results = Vec::new();
    
    // Create async tasks for imports
    // Since we are inside async fn, we can iterate
    
    for port in common_ports {
        // Try to connect and grab banner
        let addr = format!("{}:{}", ip, port);
        // Timeout 500ms for speed
        if let Ok(mut stream) = tokio::time::timeout(
            Duration::from_millis(500), 
            tokio::net::TcpStream::connect(&addr)
        ).await {
            match stream {
                Ok(mut s) => {
                    use tokio::io::AsyncReadExt;
                    let mut buffer = [0u8; 256];
                    let banner = if let Ok(n) = s.read(&mut buffer).await {
                        String::from_utf8_lossy(&buffer[..n]).to_string()
                    } else {
                        String::new()
                    };
                    
                    let service = detect_service_from_banner(&banner, port);
                    let version = extract_version(&banner);
                    
                    // Call the full scanner logic
                    if let Ok(res) = vuln_scan(ip.clone(), port, service, version).await {
                         if !res.vulnerabilities.is_empty() {
                             results.push(res);
                         }
                    }
                },
                Err(_) => {} // Conn failed
            }
        }
    }
    
    Ok(results)
}

fn detect_service_from_banner(banner: &str, port: u16) -> String {
    let b = banner.to_lowercase();
    if b.contains("ssh") { return "SSH".to_string(); }
    if b.contains("ftp") { return "FTP".to_string(); }
    if b.contains("http") { return "HTTP".to_string(); }
    if b.contains("smtp") { return "SMTP".to_string(); }
    if b.contains("mysql") { return "MySQL".to_string(); }
    
    // Fallback to port-based detection
    match port {
        21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        80 | 8080 => "HTTP".to_string(),
        443 => "HTTPS".to_string(),
        445 => "SMB".to_string(),
        3306 => "MySQL".to_string(),
        3389 => "RDP".to_string(),
        5432 => "PostgreSQL".to_string(),
        _ => format!("Port {}", port),
    }
}

fn extract_version(banner: &str) -> String {
    let chars: Vec<char> = banner.chars().collect();
    for i in 0..chars.len().saturating_sub(2) {
        if chars[i].is_ascii_digit() && chars.get(i+1) == Some(&'.') {
             let mut end = i + 1;
             while end < chars.len() && (chars[end].is_ascii_digit() || chars[end] == '.') {
                 end += 1;
             }
             if end > i + 2 { // At least X.Y
                 return chars[i..end].iter().collect();
             }
        }
    }
    String::new()
}
