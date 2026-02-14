/// Threat Intelligence Feed - Check IPs against known threat databases
/// Uses free APIs: AbuseIPDB, Feodo Tracker, etc.

#[derive(serde::Serialize, Clone)]
pub struct ThreatIntel {
    pub ip: String,
    pub is_malicious: bool,
    pub threat_types: Vec<String>,
    pub sources: Vec<String>,
    pub confidence: i32, // 0-100
    pub last_seen: Option<String>,
}

/// Check IP against free threat intelligence feeds
#[tauri::command]
pub async fn check_threat_intel(ip: String) -> Result<ThreatIntel, String> {
    let client = reqwest::Client::new();
    let mut threat_types = Vec::new();
    let mut sources = Vec::new();
    let mut is_malicious = false;
    let mut confidence = 0;
    
    // Check Feodo Tracker (Free, no API key needed)
    // This is a list of known botnet C2 IPs
    let feodo_response = client
        .get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
        .send()
        .await;
    
    if let Ok(resp) = feodo_response {
        if let Ok(text) = resp.text().await {
            if text.lines().any(|line| line.trim() == ip) {
                is_malicious = true;
                threat_types.push("Botnet C2".to_string());
                sources.push("Feodo Tracker".to_string());
                confidence = 90;
            }
        }
    }
    
    // Check URLhaus (Free, no API key needed)
    let urlhaus_response = client
        .get("https://urlhaus.abuse.ch/downloads/text/")
        .send()
        .await;
    
    if let Ok(resp) = urlhaus_response {
        if let Ok(text) = resp.text().await {
            if text.contains(&ip) {
                is_malicious = true;
                threat_types.push("Malware Distribution".to_string());
                sources.push("URLhaus".to_string());
                confidence = std::cmp::max(confidence, 85);
            }
        }
    }
    
    // Check if IP is in Tor exit node list (informational)
    let tor_response = client
        .get("https://check.torproject.org/torbulkexitlist")
        .send()
        .await;
    
    if let Ok(resp) = tor_response {
        if let Ok(text) = resp.text().await {
            if text.lines().any(|line| line.trim() == ip) {
                threat_types.push("Tor Exit Node".to_string());
                sources.push("Tor Project".to_string());
                // Tor nodes aren't necessarily malicious, just noted
            }
        }
    }
    
    Ok(ThreatIntel {
        ip,
        is_malicious,
        threat_types,
        sources,
        confidence,
        last_seen: Some(chrono::Local::now().format("%Y-%m-%d %H:%M").to_string()),
    })
}
