use crate::models::monitor::PacketInfo;
use std::collections::{HashMap, HashSet};

// MITRE T1046: Port Scanning
// MITRE T1498: Network Denial of Service (SYN Flood)

struct ScanState {
    ports: HashSet<u16>,
    last_update: u64,
}

struct FloodState {
    syn_count: u32,
    start_time: u64,
}

pub struct ThreatEngine {
    whitelist: HashSet<String>,
    // Key: "src_ip->dst_ip"
    port_scan_state: HashMap<String, ScanState>,
    // Key: "src_ip"
    syn_flood_state: HashMap<String, FloodState>,
}

impl ThreatEngine {
    pub fn new() -> Self {
        ThreatEngine {
            whitelist: HashSet::new(),
            port_scan_state: HashMap::new(),
            syn_flood_state: HashMap::new(),
        }
    }

    pub fn analyze(&mut self, packet: &PacketInfo) -> Option<String> {
        // 0. Cleanup Old State (Garbage Collection every ~1000 calls or simply check on access)
        // For simplicity, we just operate on current packet context. Real GC would be separate thread or infrequent.
        
        // 1. Noise Filter (Broadcast/Multicast)
        if packet.dst_ip == "255.255.255.255" || packet.dst_ip.starts_with("224.") || packet.dst_ip.starts_with("239.") {
            return None;
        }

        // 2. Check Whitelist
        if self.whitelist.contains(&packet.src_ip) {
            return None;
        }
        
        let mut alert = None;
        let now = packet.timestamp;

        // 2. T1046: Port Scan Detection
        // Logic: > 20 unique ports touched in < 60 seconds (Backend sends all, Frontend filters for UX)
        // Ignored Ports: 1900 (SSDP), 5353 (mDNS) - Common noise matches
        if packet.protocol == "TCP" || packet.protocol == "UDP" {
            let port = packet.dst_port;
            
            // Ignore noisy discovery protocols
            if port == 1900 || port == 5353 || port == 67 || port == 68 {
                return None;
            }

            let key = format!("{}->{}", packet.src_ip, packet.dst_ip);

            let state = self.port_scan_state.entry(key.clone()).or_insert(ScanState {
                ports: HashSet::new(),
                last_update: now,
            });

            // Reset if window expired (60s)
            if now > state.last_update + 60 {
                state.ports.clear();
                state.last_update = now;
            }

            if state.ports.insert(port) {
                // New port accessed
                state.last_update = now; // Keep window open if active

                let count = state.ports.len();
                // Threshold 20 (Low) to let Frontend decide
                if count == 20 {
                    alert = Some(format!("MITRE T1046 (Port Scan): {} -> {} (20 ports/min)", packet.src_ip, packet.dst_ip));
                } else if count > 20 && count % 20 == 0 {
                     alert = Some(format!("MITRE T1046 (Port Scan): {} -> {} ({} ports/min)", packet.src_ip, packet.dst_ip, count));
                }
            }
        }

        // 3. T1498: SYN Flood Detection
        // Logic: > 100 SYN packets in 1 second from same IP
        if let Some(flags) = &packet.tcp_flags {
            if flags.contains("SYN") && !flags.contains("ACK") {
                let key = packet.src_ip.clone();
                let state = self.syn_flood_state.entry(key.clone()).or_insert(FloodState {
                    syn_count: 0,
                    start_time: now,
                });

                // Reset bucket if second passed
                if now > state.start_time + 1 {
                    state.syn_count = 0;
                    state.start_time = now;
                }

                state.syn_count += 1;

                if state.syn_count == 100 {
                     alert = Some(format!("MITRE T1498 (DoS): SYN Flood from {} (100 SYNs/sec)", packet.src_ip));
                }
            }
        }

        alert
    }
}
