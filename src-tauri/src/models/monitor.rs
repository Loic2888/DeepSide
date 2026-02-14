use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: String,
    pub mac: String,
    pub hostname: Option<String>,
    pub manufacturer: Option<String>,
    pub first_seen: u64, // Timestamp
    pub last_seen: u64, // Timestamp
    #[serde(default)]
    pub packets: u64,
    #[serde(default)]
    pub last_packet: Option<u64>,
    pub os_guess: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketInfo {
    pub timestamp: u64,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_mac: Option<String>,
    pub dst_mac: Option<String>,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub length: usize,
    pub tcp_flags: Option<String>,
    pub dns_query: Option<String>,
    pub icmp_type: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkStats {
    pub total_packets: u64,
    pub active_devices: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: i64,
    pub timestamp: i64,
    pub level: String,
    pub title: String,
    pub description: String,
    pub source_ip: String,
    pub destination_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: i64,
    pub timestamp: i64,
    pub source_ip: String,
    pub service: String,
    pub username: String,
    pub password: String,
    pub captured_data: String,
}
