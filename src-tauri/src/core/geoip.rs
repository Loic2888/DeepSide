use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::fs;
use maxminddb::geoip2;
use tauri::{AppHandle, Manager};
use std::io::Write;

pub struct GeoIpEngine {
    reader: Arc<Mutex<Option<maxminddb::Reader<Vec<u8>>>>>,
    db_path: PathBuf,
}

impl GeoIpEngine {
    pub fn new(app_handle: &AppHandle) -> Self {
        let app_dir = app_handle.path().app_data_dir().unwrap_or(PathBuf::from("."));
        // Ensure dir exists
        let _ = fs::create_dir_all(&app_dir);
        let db_path = app_dir.join("GeoLite2-City.mmdb");

        let engine = GeoIpEngine {
            reader: Arc::new(Mutex::new(None)),
            db_path: db_path.clone(),
        };

        // Try load immediately
        if db_path.exists() {
             engine.load();
        } else {
            // Spawn download in background
            let engine_clone = engine.clone();
            tauri::async_runtime::spawn(async move {
                println!("GeoIP DB missing. Downloading...");
                if let Ok(_) = engine_clone.download_db().await {
                    engine_clone.load();
                }
            });
        }

        engine
    }

    fn clone(&self) -> Self {
        GeoIpEngine {
            reader: self.reader.clone(),
            db_path: self.db_path.clone(),
        }
    }

    pub fn load(&self) {
        match maxminddb::Reader::open_readfile(&self.db_path) {
            Ok(reader) => {
                println!("GeoIP DB loaded successfully.");
                *self.reader.lock().unwrap() = Some(reader);
            },
            Err(e) => println!("Failed to load GeoIP DB: {}", e),
        }
    }

    pub async fn download_db(&self) -> Result<(), String> {
        // Public mirror for GeoLite2 (Testing only)
        let url = "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb";
        
        let response = reqwest::get(url).await.map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(format!("Download failed: {}", response.status()));
        }

        let bytes = response.bytes().await.map_err(|e| e.to_string())?;
        let mut file = fs::File::create(&self.db_path).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;

        println!("GeoIP DB downloaded to {:?}", self.db_path);
        Ok(())
    }

    pub fn lookup(&self, ip_str: &str) -> (String, String) {
        let guard = self.reader.lock().unwrap();
        if let Some(reader) = &*guard {
            let ip: std::net::IpAddr = match ip_str.parse() {
                Ok(i) => i,
                Err(_) => return ("Invalid IP".to_string(), "".to_string()),
            };

            match reader.lookup::<geoip2::City>(ip) {
                Ok(city) => {
                     // CAREFUL EXTRACTION
                     let country = city.country.as_ref()
                        .and_then(|c| c.names.as_ref())
                        .and_then(|n| n.get("en"))
                        .map(|s| (*s).to_string())
                        .unwrap_or_else(|| "Unknown".to_string());

                     let iso = city.country.as_ref()
                        .and_then(|c| c.iso_code)
                        .map(|s| s.to_string())
                        .unwrap_or_else(|| "".to_string());
                        
                     (country, iso)
                },
                Err(_) => ("Not Found".to_string(), "".to_string()),
            }
        } else {
            ("DB Not Loaded".to_string(), "".to_string())
        }
    }
}

// Commands
#[tauri::command]
pub async fn get_geoip(state: tauri::State<'_, crate::AppState>, ip: String) -> Result<serde_json::Value, String> {
    let (country, iso) = state.geoip.lookup(&ip);
    Ok(serde_json::json!({ "country": country, "iso": iso }))
}
