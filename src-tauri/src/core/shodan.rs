/// Shodan Integration - Search for exposed devices and services
/// Requires Shodan API key

#[derive(serde::Serialize, Clone)]
pub struct ShodanResult {
    pub ip: String,
    pub ports: Vec<u16>,
    pub hostnames: Vec<String>,
    pub org: Option<String>,
    pub isp: Option<String>,
    pub os: Option<String>,
    pub vulns: Vec<String>,
    pub last_update: Option<String>,
    pub error: Option<String>,
}

/// Lookup IP on Shodan
#[tauri::command]
pub async fn shodan_lookup(ip: String, api_key: String) -> Result<ShodanResult, String> {
    if api_key.is_empty() {
        return Ok(ShodanResult {
            ip,
            ports: vec![],
            hostnames: vec![],
            org: None,
            isp: None,
            os: None,
            vulns: vec![],
            last_update: None,
            error: Some("API key required. Get free key at shodan.io".to_string()),
        });
    }
    
    let url = format!("https://api.shodan.io/shodan/host/{}?key={}", ip, api_key);
    
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    
    if !response.status().is_success() {
        let status = response.status();
        return Ok(ShodanResult {
            ip,
            ports: vec![],
            hostnames: vec![],
            org: None,
            isp: None,
            os: None,
            vulns: vec![],
            last_update: None,
            error: Some(format!("Shodan API error: {}", status)),
        });
    }
    
    let json: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    
    // Parse response
    let ports: Vec<u16> = json.get("ports")
        .and_then(|p| p.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_u64().map(|n| n as u16)).collect())
        .unwrap_or_default();
    
    let hostnames: Vec<String> = json.get("hostnames")
        .and_then(|h| h.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    let vulns: Vec<String> = json.get("vulns")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    
    Ok(ShodanResult {
        ip,
        ports,
        hostnames,
        org: json.get("org").and_then(|v| v.as_str()).map(|s| s.to_string()),
        isp: json.get("isp").and_then(|v| v.as_str()).map(|s| s.to_string()),
        os: json.get("os").and_then(|v| v.as_str()).map(|s| s.to_string()),
        vulns,
        last_update: json.get("last_update").and_then(|v| v.as_str()).map(|s| s.to_string()),
        error: None,
    })
}

/// Search Shodan for devices
#[tauri::command]
pub async fn shodan_search(query: String, api_key: String) -> Result<Vec<ShodanResult>, String> {
    if api_key.is_empty() {
        return Err("API key required".to_string());
    }
    
    let url = format!(
        "https://api.shodan.io/shodan/host/search?key={}&query={}",
        api_key,
        urlencoding::encode(&query)
    );
    
    let client = reqwest::Client::new();
    let response = client.get(&url).send().await.map_err(|e| e.to_string())?;
    
    if !response.status().is_success() {
        return Err(format!("Shodan API error: {}", response.status()));
    }
    
    let json: serde_json::Value = response.json().await.map_err(|e| e.to_string())?;
    
    let results: Vec<ShodanResult> = json.get("matches")
        .and_then(|m| m.as_array())
        .map(|arr| {
            arr.iter().take(10).map(|m| {
                ShodanResult {
                    ip: m.get("ip_str").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                    ports: vec![m.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16],
                    hostnames: m.get("hostnames")
                        .and_then(|h| h.as_array())
                        .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_string())).collect())
                        .unwrap_or_default(),
                    org: m.get("org").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    isp: m.get("isp").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    os: m.get("os").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    vulns: vec![],
                    last_update: None,
                    error: None,
                }
            }).collect()
        })
        .unwrap_or_default();
    
    Ok(results)
}
