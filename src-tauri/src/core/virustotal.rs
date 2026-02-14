/// VirusTotal API Integration
/// Note: Requires API key to be set in environment or config

#[derive(serde::Serialize, Clone)]
pub struct VirusTotalResult {
    pub target: String,
    pub target_type: String, // "ip", "domain", "hash"
    pub malicious: i32,
    pub suspicious: i32,
    pub harmless: i32,
    pub undetected: i32,
    pub reputation: Option<i32>,
    pub tags: Vec<String>,
    pub error: Option<String>,
}

/// Check IP, domain, or file hash against VirusTotal
#[tauri::command]
pub async fn virustotal_check(target: String, target_type: String, api_key: String) -> Result<VirusTotalResult, String> {
    if api_key.is_empty() {
        return Ok(VirusTotalResult {
            target,
            target_type,
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            reputation: None,
            tags: vec![],
            error: Some("API key required".to_string()),
        });
    }
    
    let endpoint = match target_type.as_str() {
        "ip" => format!("https://www.virustotal.com/api/v3/ip_addresses/{}", target),
        "domain" => format!("https://www.virustotal.com/api/v3/domains/{}", target),
        "hash" => format!("https://www.virustotal.com/api/v3/files/{}", target),
        _ => return Err("Invalid target type. Use 'ip', 'domain', or 'hash'".to_string()),
    };
    
    let client = reqwest::Client::new();
    let response = client
        .get(&endpoint)
        .header("x-apikey", &api_key)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    
    if !response.status().is_success() {
        return Ok(VirusTotalResult {
            target,
            target_type,
            malicious: 0,
            suspicious: 0,
            harmless: 0,
            undetected: 0,
            reputation: None,
            tags: vec![],
            error: Some(format!("API error: {}", response.status())),
        });
    }
    
    let json: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    
    // Parse analysis stats
    let stats = json.get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("last_analysis_stats"));
    
    let (malicious, suspicious, harmless, undetected) = if let Some(s) = stats {
        (
            s.get("malicious").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            s.get("suspicious").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            s.get("harmless").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
            s.get("undetected").and_then(|v| v.as_i64()).unwrap_or(0) as i32,
        )
    } else {
        (0, 0, 0, 0)
    };
    
    let reputation = json.get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("reputation"))
        .and_then(|r| r.as_i64())
        .map(|r| r as i32);
    
    let tags: Vec<String> = json.get("data")
        .and_then(|d| d.get("attributes"))
        .and_then(|a| a.get("tags"))
        .and_then(|t| t.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    Ok(VirusTotalResult {
        target,
        target_type,
        malicious,
        suspicious,
        harmless,
        undetected,
        reputation,
        tags,
        error: None,
    })
}
