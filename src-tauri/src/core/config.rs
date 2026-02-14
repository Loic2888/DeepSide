/// API Keys Configuration Management
use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use tauri::Manager;

#[derive(Serialize, Deserialize, Clone, Default)]
pub struct ApiKeys {
    pub virustotal: Option<String>,
    pub shodan: Option<String>,
    pub abuseipdb: Option<String>,
    pub groq: Option<String>,
}

fn get_config_path(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    let app_dir = app.path().app_data_dir().map_err(|e| e.to_string())?;
    fs::create_dir_all(&app_dir).map_err(|e| e.to_string())?;
    Ok(app_dir.join("api_keys.json"))
}

fn load_env_keys() -> ApiKeys {
    let mut keys = ApiKeys::default();
    if let Ok(content) = fs::read_to_string(".env") {
        for line in content.lines() {
            let parts: Vec<&str> = line.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim();
                let val = parts[1].trim().to_string();
                if val.is_empty() { continue; }
                match key {
                    "VIRUSTOTAL_API_KEY" => keys.virustotal = Some(val),
                    "SHODAN_API_KEY" => keys.shodan = Some(val),
                    "ABUSEIPDB_API_KEY" => keys.abuseipdb = Some(val),
                    "GROQ_API_KEY" => keys.groq = Some(val),
                    _ => {}
                }
            }
        }
    }
    keys
}

/// Save API keys to config file
#[tauri::command]
pub async fn save_api_keys(app: tauri::AppHandle, keys: ApiKeys) -> Result<String, String> {
    let path = get_config_path(&app)?;
    let json = serde_json::to_string_pretty(&keys).map_err(|e| e.to_string())?;
    fs::write(&path, json).map_err(|e| e.to_string())?;
    Ok("API keys saved successfully".to_string())
}

/// Load API keys from config file or .env
#[tauri::command]
pub async fn load_api_keys(app: tauri::AppHandle) -> Result<ApiKeys, String> {
    // 1. Try .env first (Project relative)
    let env_keys = load_env_keys();
    if env_keys.virustotal.is_some() || env_keys.shodan.is_some() || env_keys.abuseipdb.is_some() || env_keys.groq.is_some() {
        return Ok(env_keys);
    }

    // 2. Fallback to AppData json
    let path = get_config_path(&app)?;
    if !path.exists() {
        return Ok(ApiKeys::default());
    }
    
    let content = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let keys: ApiKeys = serde_json::from_str(&content).map_err(|e| e.to_string())?;
    Ok(keys)
}

/// Get a specific API key
#[tauri::command]
pub async fn get_api_key(app: tauri::AppHandle, service: String) -> Result<Option<String>, String> {
    let keys = load_api_keys(app).await?;
    
    match service.as_str() {
        "virustotal" => Ok(keys.virustotal),
        "shodan" => Ok(keys.shodan),
        "abuseipdb" => Ok(keys.abuseipdb),
        "groq" => Ok(keys.groq),
        _ => Err(format!("Unknown service: {}", service)),
    }
}
