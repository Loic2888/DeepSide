use whois_rust::{WhoIs, WhoIsLookupOptions};
use tauri::command;

#[command]
pub async fn get_whois(target: String) -> Result<String, String> {
    // Basic Whois lookup
    // In a real app, we might want to load servers.json from a file
    // For now, we use the default built-in list or a simple embedded one if the crate supports it via helper,
    // but whois-rust usually needs a server list.
    
    // Quick fix: The crate requires loading a JSON server definitions file.
    // Since we don't want to bundle a huge json right now, we can try a direct socket approach for common TLDs
    // OR just use the library correctly by downloading the json.
    
    // Better approach for "Instant" tool: Use `WhoIs::from_string` with minimal config 
    // or just assume standard servers for now. 
    
    // Actually, `whois-rust` needs a server map.
    // Let's use a simplified approach or just a raw TCP 43 dump if the crate is too heavy on config.
    
    // Alternative: Raw TCP Connect to whois.iana.org then follow referral.
    // Let's try standard whois-rust usage.
    
    let whois_servers = r#"{
        "com": "whois.verisign-grs.com",
        "net": "whois.verisign-grs.com",
        "org": "whois.pir.org",
        "io": "whois.nic.io",
        "ai": "whois.nic.ai",
        "fr": "whois.nic.fr"
    }"#;
    
    let whois = WhoIs::from_string(whois_servers).map_err(|e| e.to_string())?;
    
    // Determine TLD or IP
    let result = whois.lookup(WhoIsLookupOptions::from_string(&target).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    
    Ok(result)
}
