use std::sync::{Arc, atomic::{AtomicBool, Ordering}};

pub struct ArpSpoofer {
    running: Arc<AtomicBool>,
}

impl ArpSpoofer {
    pub fn new() -> Self {
        ArpSpoofer {
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start(&self, target_ip: String, _target_mac: String, gateway_ip: String, _gateway_mac: String) -> Result<(), String> {
        println!("ARP Spoofing (STUB) Started: {} -> {}", target_ip, gateway_ip);
        Ok(())
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
