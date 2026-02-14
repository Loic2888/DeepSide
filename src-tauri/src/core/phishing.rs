use strsim::levenshtein;
use url::Url;

#[derive(serde::Serialize)]
pub struct PhishingResult {
    pub risk_score: u8, // 0-100
    pub risk_level: String, // "SAFE", "SUSPICIOUS", "HIGH_RISK"
    pub reasons: Vec<String>,
}

const KNOWN_DOMAINS: &[&str] = &[
    "google.com", "facebook.com", "amazon.com", "twitter.com", "linkedin.com",
    "github.com", "microsoft.com", "apple.com", "netflix.com", "paypal.com"
];

const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "login", "signin", "update", "verify", "secure", "account", "billing", "invoice"
];

#[tauri::command]
pub fn analyze_url(url_str: String) -> PhishingResult {
    let mut score = 0;
    let mut reasons = Vec::new();

    // 1. Basic URL Parsing
    let parsed = match Url::parse(&url_str) {
        Ok(u) => u,
        Err(_) => return PhishingResult { risk_score: 100, risk_level: "INVALID".to_string(), reasons: vec!["Invalid URL format".to_string()] }
    };

    let domain = parsed.host_str().unwrap_or("");

    // 2. Typosquatting Check
    for &known in KNOWN_DOMAINS {
        if domain != known {
            let dist = levenshtein(domain, known);
            if dist == 1 || dist == 2 { // Very close match
                score += 50;
                reasons.push(format!("Typosquatting detected: similar to {}", known));
            }
        }
    }

    // 3. Keyword in Domain (Subdomain or confusing path)
    for &kw in SUSPICIOUS_KEYWORDS {
        if domain.contains(kw) && !KNOWN_DOMAINS.contains(&domain) {
             score += 20;
             reasons.push(format!("Suspicious keyword '{}' in domain", kw));
        }
    }

    // 4. Entropy / Randomness (Simple heuristic: length and numbers)
    let num_count = domain.chars().filter(|c| c.is_numeric()).count();
    if domain.len() > 30 {
        score += 10;
        reasons.push("Lengthy domain name".to_string());
    }
    if num_count > 5 {
        score += 20;
        reasons.push("High number density in domain".to_string());
    }

    // 5. Structure Check
    if parsed.scheme() == "http" {
        score += 10;
        reasons.push("Insecure connection (HTTP)".to_string());
    }
    if parsed.username() != "" {
        score += 40;
        reasons.push("Embedded credentials in URL".to_string());
    }

    // Final Assessment
    let risk_level = if score >= 60 { "HIGH_RISK" }
                     else if score >= 30 { "SUSPICIOUS" }
                     else { "SAFE" };

    PhishingResult {
        risk_score: score.min(100),
        risk_level: risk_level.to_string(),
        reasons
    }
}
