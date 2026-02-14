use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(serde::Serialize, Clone)]
pub struct BannerResult {
    pub ip: String,
    pub port: u16,
    pub banner: Option<String>,
    pub service: Option<String>,
    pub error: Option<String>,
}

/// Banner Grabbing - Connect to port and read service banner
#[tauri::command]
pub async fn grab_banner(ip: String, port: u16) -> Result<BannerResult, String> {
    let addr = format!("{}:{}", ip, port);
    
    // Connect with timeout
    let stream = TcpStream::connect_timeout(
        &addr.parse().map_err(|e: std::net::AddrParseError| e.to_string())?,
        Duration::from_secs(3)
    );
    
    match stream {
        Ok(mut sock) => {
            sock.set_read_timeout(Some(Duration::from_secs(2))).ok();
            sock.set_write_timeout(Some(Duration::from_secs(2))).ok();
            
            // For HTTP, send a request
            if port == 80 || port == 8080 {
                let request = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", ip);
                sock.write_all(request.as_bytes()).ok();
            }
            
            // Read banner
            let mut buffer = [0u8; 1024];
            match sock.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    let banner = String::from_utf8_lossy(&buffer[..n])
                        .trim()
                        .chars()
                        .take(256) // Limit banner size
                        .collect::<String>();
                    
                    // Detect service from banner
                    let service = detect_service(&banner, port);
                    
                    Ok(BannerResult {
                        ip,
                        port,
                        banner: Some(banner),
                        service: Some(service),
                        error: None,
                    })
                }
                _ => {
                    // No banner but port is open
                    Ok(BannerResult {
                        ip,
                        port,
                        banner: None,
                        service: Some(guess_service_by_port(port)),
                        error: None,
                    })
                }
            }
        }
        Err(e) => {
            Ok(BannerResult {
                ip,
                port,
                banner: None,
                service: None,
                error: Some(e.to_string()),
            })
        }
    }
}

fn detect_service(banner: &str, port: u16) -> String {
    let banner_lower = banner.to_lowercase();
    
    if banner_lower.contains("ssh") {
        if let Some(ver) = banner.split_whitespace().find(|s| s.starts_with("SSH-")) {
            return format!("SSH ({} )", ver);
        }
        return "SSH".to_string();
    }
    if banner_lower.contains("http") {
        if let Some(server) = banner.lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .map(|l| l.split(':').skip(1).collect::<Vec<_>>().join(":").trim().to_string()) {
            return format!("HTTP ({})", server);
        }
        return "HTTP".to_string();
    }
    if banner_lower.contains("ftp") {
        return "FTP".to_string();
    }
    if banner_lower.contains("smtp") || banner_lower.contains("mail") {
        return "SMTP".to_string();
    }
    if banner_lower.contains("mysql") {
        return "MySQL".to_string();
    }
    if banner_lower.contains("postgresql") || banner_lower.contains("postgres") {
        return "PostgreSQL".to_string();
    }
    if banner_lower.contains("redis") {
        return "Redis".to_string();
    }
    if banner_lower.contains("mongodb") {
        return "MongoDB".to_string();
    }
    
    guess_service_by_port(port)
}

fn guess_service_by_port(port: u16) -> String {
    match port {
        20 | 21 => "FTP".to_string(),
        22 => "SSH".to_string(),
        23 => "Telnet".to_string(),
        25 => "SMTP".to_string(),
        53 => "DNS".to_string(),
        80 | 8080 => "HTTP".to_string(),
        110 => "POP3".to_string(),
        143 => "IMAP".to_string(),
        443 | 8443 => "HTTPS".to_string(),
        445 => "SMB".to_string(),
        1433 => "MSSQL".to_string(),
        3306 => "MySQL".to_string(),
        3389 => "RDP".to_string(),
        5432 => "PostgreSQL".to_string(),
        5900 => "VNC".to_string(),
        6379 => "Redis".to_string(),
        27017 => "MongoDB".to_string(),
        _ => format!("Unknown ({})", port),
    }
}
