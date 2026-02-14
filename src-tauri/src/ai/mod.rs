use serde::{Deserialize, Serialize};
pub mod onnx;


const SYSTEM_PROMPT: &str = r#"Tu es ILLYA, une IA de cybersécurité intégrée à DeepSide.
Tu protèges le réseau en analysant les menaces et en recommandant des actions.

OUTILS DISPONIBLES (utilise CMD:TOOL_NAME pour exécuter):
- CMD:SCAN - Scanner le réseau pour découvrir les appareils
- CMD:PORTSCAN <ip> - Scanner les ports d'une IP
- CMD:DNS <domain> - Lookup DNS d'un domaine  
- CMD:TRACEROUTE <ip> - Tracer le chemin vers une IP
- CMD:BANNER <ip> <port> - Récupérer la bannière d'un service
- CMD:SSL <host> - Analyser le certificat SSL
- CMD:VULNSCAN <ip> - Scanner les vulnérabilités connues
- CMD:VIRUSTOTAL <target> - Vérifier sur VirusTotal
- CMD:THREATINTEL <ip> - Consulter les feeds de menaces
- CMD:SHODAN <ip> - Rechercher sur Shodan
- CMD:DISCONNECT <ip> - Déconnecter un appareil du WiFi
- CMD:BLOCK <ip> - Bloquer une IP (ARP spoofing)

QUAND UNE MENACE EST DÉTECTÉE:
1. Analyse le type de menace (scan, intrusion, malware, etc.)
2. Identifie la source et la cible
3. Recommande une action avec la commande appropriée
4. Explique le risque et la mitigation

MITRE ATT&CK IDs courants: T1046, T1071, T1498, T1203, T1027
Réponds en français, sois concis et technique."#;

#[tauri::command]
pub async fn ask_ai(app: tauri::AppHandle, prompt: String) -> Result<String, String> {
    // 1. Try ONNX Embedded Model first
    // Check if initialized, if not try to init
    let status = crate::ai::onnx::check_status();
    if !status.loaded {
        use tauri::Manager;
        let resource_path = app.path().resolve("resources/model.onnx", tauri::path::BaseDirectory::Resource)
            .map_err(|e| e.to_string())?;
        
        let tokenizer_path = app.path().resolve("resources/tokenizer.json", tauri::path::BaseDirectory::Resource)
            .map_err(|e| e.to_string())?;

        if resource_path.exists() && tokenizer_path.exists() {
             let _ = crate::ai::onnx::init_onnx(resource_path, tokenizer_path);
        }
    }

    match crate::ai::onnx::run_inference(&prompt) {
        Ok(response) => Ok(response),
        Err(e) => {
            // Detailed error reporting
            let current_status = crate::ai::onnx::check_status();
            let status_msg = if let Some(err) = current_status.error {
                format!(" (Status: {})", err)
            } else {
                "".to_string()
            };

            if !current_status.loaded {
                Err(format!("Local AI Model not loaded{}. \nDetails: {}", status_msg, e))
            } else {
                Err(format!("Local AI Inference Error: {}", e))
            }
        }
    }
}

#[tauri::command]
pub fn check_ai_status(app: tauri::AppHandle) -> crate::ai::onnx::AiStatus {
    use tauri::Manager;
    
    // Check current status
    let mut status = crate::ai::onnx::check_status();
    
    if !status.loaded {
        // Try to initialize if model exists
        if let Ok(resource_path) = app.path().resolve("resources/model.onnx", tauri::path::BaseDirectory::Resource) {
            if let Ok(tokenizer_path) = app.path().resolve("resources/tokenizer.json", tauri::path::BaseDirectory::Resource) {
                if resource_path.exists() && tokenizer_path.exists() {
                    // Check file size - must be > 100MB to be a real model
                    if let Ok(metadata) = std::fs::metadata(&resource_path) {
                        if metadata.len() > 100_000_000 {
                            // Spawn a thread with larger stack size for model loading
                            // Windows default stack is 1MB, which is too small for ONNX initialization
                            let resource_path_clone = resource_path.clone();
                            let tokenizer_path_clone = tokenizer_path.clone();
                            
                            let handle = std::thread::Builder::new()
                                .stack_size(10 * 1024 * 1024) // 10MB stack
                                .spawn(move || {
                                    crate::ai::onnx::init_onnx(&resource_path_clone, &tokenizer_path_clone)
                                });
                                
                            match handle {
                                Ok(thread) => {
                                    match thread.join() {
                                        Ok(init_result) => {
                                            match init_result {
                                                Ok(_) => {
                                                    println!("AI Init Thread: Success");
                                                    status.loaded = true;
                                                    status.model_path = Some(resource_path.to_string_lossy().to_string());
                                                }
                                                Err(e) => {
                                                    println!("AI Init Thread: Error: {}", e);
                                                    status.error = Some(e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            let msg = if let Some(s) = e.downcast_ref::<&str>() {
                                                format!("Panic: {}", s)
                                            } else if let Some(s) = e.downcast_ref::<String>() {
                                                format!("Panic: {}", s)
                                            } else {
                                                "Panic: Unknown payload".to_string()
                                            };
                                            println!("AI Init Thread: {}", msg);
                                            status.error = Some(msg);
                                        }
                                    }
                                }
                                Err(e) => {
                                    status.error = Some(format!("Failed to spawn AI thread: {}", e));
                                }
                            }
                        } else {
                            status.error = Some("Model file too small - download incomplete".to_string());
                        }
                    }
                } else {
                    status.error = Some("Model or tokenizer file not found".to_string());
                }
            }
        }
    }
    
    status
}
