use std::process::Command;

#[derive(serde::Serialize, Clone)]
pub struct SslResult {
    pub host: String,
    pub port: u16,
    pub valid: bool,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub expires: Option<String>,
    pub protocol: Option<String>,
    pub cipher: Option<String>,
    pub warnings: Vec<String>,
    pub error: Option<String>,
}

/// SSL/TLS Analyzer - Check certificate and connection security
#[tauri::command]
pub async fn analyze_ssl(host: String, port: u16) -> Result<SslResult, String> {
    // Use PowerShell to check SSL certificate (Windows compatible)
    let script = format!(
        r#"
        try {{
            $tcpClient = New-Object System.Net.Sockets.TcpClient
            $tcpClient.Connect("{}", {})
            $sslStream = New-Object System.Net.Security.SslStream($tcpClient.GetStream(), $false, {{ $true }})
            $sslStream.AuthenticateAsClient("{}")
            $cert = $sslStream.RemoteCertificate
            $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
            
            @{{
                Subject = $cert2.Subject
                Issuer = $cert2.Issuer
                NotAfter = $cert2.NotAfter.ToString("yyyy-MM-dd")
                Protocol = $sslStream.SslProtocol.ToString()
                CipherAlgorithm = $sslStream.CipherAlgorithm.ToString()
                Valid = $cert2.Verify()
            }} | ConvertTo-Json
            
            $sslStream.Close()
            $tcpClient.Close()
        }} catch {{
            @{{ Error = $_.Exception.Message }} | ConvertTo-Json
        }}
        "#,
        host, port, host
    );
    
    let output = Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .map_err(|e| e.to_string())?;
    
    let stdout = String::from_utf8_lossy(&output.stdout);
    
    // Parse JSON output
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(error) = json.get("Error").and_then(|v| v.as_str()) {
            return Ok(SslResult {
                host,
                port,
                valid: false,
                issuer: None,
                subject: None,
                expires: None,
                protocol: None,
                cipher: None,
                warnings: vec![],
                error: Some(error.to_string()),
            });
        }
        
        let mut warnings = Vec::new();
        
        // Check expiry
        if let Some(expires) = json.get("NotAfter").and_then(|v| v.as_str()) {
            if let Ok(exp_date) = chrono::NaiveDate::parse_from_str(expires, "%Y-%m-%d") {
                let today = chrono::Local::now().date_naive();
                let days_left = (exp_date - today).num_days();
                if days_left < 0 {
                    warnings.push("Certificate EXPIRED!".to_string());
                } else if days_left < 30 {
                    warnings.push(format!("Certificate expires in {} days", days_left));
                }
            }
        }
        
        // Check protocol
        if let Some(proto) = json.get("Protocol").and_then(|v| v.as_str()) {
            if proto.contains("Ssl3") || proto.contains("Tls10") || proto.contains("Tls11") {
                warnings.push(format!("Weak protocol: {}", proto));
            }
        }
        
        Ok(SslResult {
            host,
            port,
            valid: json.get("Valid").and_then(|v| v.as_bool()).unwrap_or(false),
            issuer: json.get("Issuer").and_then(|v| v.as_str()).map(|s| s.to_string()),
            subject: json.get("Subject").and_then(|v| v.as_str()).map(|s| s.to_string()),
            expires: json.get("NotAfter").and_then(|v| v.as_str()).map(|s| s.to_string()),
            protocol: json.get("Protocol").and_then(|v| v.as_str()).map(|s| s.to_string()),
            cipher: json.get("CipherAlgorithm").and_then(|v| v.as_str()).map(|s| s.to_string()),
            warnings,
            error: None,
        })
    } else {
        Ok(SslResult {
            host,
            port,
            valid: false,
            issuer: None,
            subject: None,
            expires: None,
            protocol: None,
            cipher: None,
            warnings: vec![],
            error: Some("Failed to parse SSL info".to_string()),
        })
    }
}
