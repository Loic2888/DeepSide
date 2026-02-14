use pcap::{Device as PcapDevice, Capture};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter};
use crate::models::monitor::{NetworkStats, Device};
use crate::database::Database;
// use crate::models::monitor::PacketInfo;

pub fn run_sniffer(
    app: &AppHandle,
    stats: Arc<Mutex<NetworkStats>>,
    devices: Arc<Mutex<Vec<Device>>>,
    db: Arc<Database>,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. List all devices to find the best one
    let device_list = PcapDevice::list()?;
    println!("Available Network Devices:");
    for d in &device_list {
         println!(" - {} ({:?})", d.name, d.desc);
    }

    // Smart Selection: Find the most likely physical network interface
    let mut main_device = None;
    
    // Priority 1: Physical adapters (Wi-Fi, Ethernet, Wireless) with an IP, excluding virtual ones
    for d in &device_list {
        let desc = d.desc.clone().unwrap_or_default().to_lowercase();
        if !d.addresses.is_empty() && 
           (desc.contains("wi-fi") || desc.contains("ethernet") || desc.contains("wireless") || desc.contains("intel") || desc.contains("realtek")) &&
           !desc.contains("virtual") && !desc.contains("hyper-v") && !desc.contains("loopback") && !desc.contains("miniport") {
            main_device = Some(d.clone());
            break;
        }
    }

    // Priority 2: Any device with an IP that isn't virtual/loopback
    if main_device.is_none() {
        for d in &device_list {
            let desc = d.desc.clone().unwrap_or_default().to_lowercase();
            if !d.addresses.is_empty() && !desc.contains("virtual") && !desc.contains("hyper-v") && !desc.contains("loopback") {
                main_device = Some(d.clone());
                break;
            }
        }
    }

    // Priority 3: Fallback to the first one with an IP
    if main_device.is_none() {
        main_device = device_list.into_iter().find(|d| !d.addresses.is_empty());
    }

    let main_device = main_device.ok_or("No active network device found (no IP assigned)")?;

    println!("Selected active device: {} ({:?})", main_device.name, main_device.desc);

    // Get Local IP for Whitelisting & UI
    let local_ip_str = main_device.addresses.iter()
        .find(|a| a.addr.is_ipv4())
        .map(|a| a.addr.to_string())
        .unwrap_or_else(|| "0.0.0.0".to_string());
    
    // Emit Local IP to Frontend
    let _ = app.emit("local-ip", local_ip_str.clone());

    // 2. Open capture
    let mut cap = Capture::from_device(main_device.name.as_str())?
        .promisc(true) // Promiscuous mode
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    let mut packet_count = 0;
    let mut threat_engine = crate::core::threats::ThreatEngine::new();
    
    loop {
        // 3. Capture packet
        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                // Debug log every 50 packets
                if packet_count % 50 == 0 {
                    println!("Captured {} packets on {}", packet_count, main_device.desc.as_deref().unwrap_or("Unknown"));
                }

                // 4. Update Stats
                {
                    let mut stats_lock = stats.lock().unwrap();
                    stats_lock.total_packets += 1;
                    
                    // Emit live stats update
                    if packet_count % 5 == 0 { // More frequent updates for smooth graph
                        app.emit("network-stats", stats_lock.clone())
                           .unwrap_or_else(|e| eprintln!("Event error: {}", e));
                    }
                }

                // 5. Deep Packet Inspection (DPI)
                match etherparse::PacketHeaders::from_ethernet_slice(packet.data) {
                    Ok(headers) => {
                         let mut src_ip = "0.0.0.0".to_string();
                         let mut dst_ip = "0.0.0.0".to_string();
                         let mut proto = "Unknown".to_string();
                         let size = packet.header.len as usize;
                         
                         // IP Layer (0.13 API uses `ip`)
                         if let Some(ref ip) = headers.ip {
                             match ip {
                                 etherparse::IpHeader::Version4(ipv4, _) => {
                                     let s = ipv4.source;
                                     let d = ipv4.destination;
                                     src_ip = format!("{}.{}.{}.{}", s[0], s[1], s[2], s[3]);
                                     dst_ip = format!("{}.{}.{}.{}", d[0], d[1], d[2], d[3]);
                                 },
                                 etherparse::IpHeader::Version6(_ipv6, _) => {
                                     src_ip = "IPv6".to_string();
                                     dst_ip = "IPv6".to_string();
                                 }
                             }
                         }

                         // Transport Layer
                         let mut src_port: u16 = 0;
                         let mut dst_port: u16 = 0;
                         let mut tcp_flags = None;
                         
                         if let Some(transport) = headers.transport {
                             match transport {
                                 etherparse::TransportHeader::Tcp(tcp) => {
                                     proto = "TCP".to_string();
                                     src_port = tcp.source_port;
                                     dst_port = tcp.destination_port;
                                     // Flags
                                     let mut flags = Vec::new();
                                     if tcp.syn { flags.push("SYN"); }
                                     if tcp.ack { flags.push("ACK"); }
                                     if tcp.fin { flags.push("FIN"); }
                                     if tcp.rst { flags.push("RST"); }
                                     if tcp.psh { flags.push("PSH"); }
                                     if tcp.urg { flags.push("URG"); }
                                     if !flags.is_empty() {
                                         tcp_flags = Some(flags.join("|"));
                                     }
                                 },
                                 etherparse::TransportHeader::Udp(udp) => {
                                     proto = "UDP".to_string();
                                     src_port = udp.source_port;
                                     dst_port = udp.destination_port;
                                 },
                                 etherparse::TransportHeader::Icmpv4(_) => proto = "ICMP".to_string(),
                                 etherparse::TransportHeader::Icmpv6(_) => proto = "ICMPv6".to_string(),
                             }
                         }

                         // Construct PacketInfo for Threat Engine
                         let packet_info = crate::models::monitor::PacketInfo {
                             timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                             src_ip: src_ip.clone(),
                             dst_ip: dst_ip.clone(),
                             src_mac: None, 
                             dst_mac: None,
                             src_port,
                             dst_port,
                             protocol: proto.clone(),
                             length: size,
                             tcp_flags: tcp_flags.clone(),
                             dns_query: None, 
                             icmp_type: None, 
                         };

                         // Emit interesting traffic flows to frontend (skip broadcast/local only)
                         // Only emit TCP SYN (new connections), UDP on common ports, or periodically
                         let is_new_conn = tcp_flags.as_ref().map_or(false, |f| f.contains("SYN") && !f.contains("ACK"));
                         let is_interesting_udp = proto == "UDP" && (dst_port == 53 || dst_port == 443 || dst_port == 80 || src_port == 53);
                         let is_interesting_tcp = proto == "TCP" && (dst_port == 80 || dst_port == 443 || dst_port == 22 || dst_port == 21 || dst_port == 3389);
                         
                         if (is_new_conn || is_interesting_udp || (is_interesting_tcp && packet_count % 10 == 0)) 
                            && src_ip != "0.0.0.0" && dst_ip != "0.0.0.0" 
                            && src_ip != "IPv6" && dst_ip != "255.255.255.255" {
                             let flow_msg = format!("{} {}:{} → {}:{}", 
                                 proto, src_ip, src_port, dst_ip, dst_port);
                             let _ = app.emit("traffic-flow", flow_msg);
                         }

                         // DPI: Credential Harvesting & Payload Analysis
                         if proto == "TCP" && size > 54 && size < 1500 { // Ignore huge downloads, focus on command streams
                             let payload = &packet.data[packet.header.len as usize..]; // Approximate payload start
                             if !payload.is_empty() {
                                 let payload_str = String::from_utf8_lossy(payload);
                                 
                                 // Regex Patterns for Credentials
                                 // 1. Basic Auth (HTTP)
                                 if payload_str.contains("Authorization: Basic ") {
                                     if let Some(pos) = payload_str.find("Basic ") {
                                         let part = &payload_str[pos+6..];
                                         let end = part.find("\r\n").unwrap_or(part.len());
                                         let token = &part[..end];
                                         // Decode Base64 (simple crate like base64 or manual attempt? better to just save string for now)
                                         // For this phase, we save the token string.
                                         let cred = crate::models::monitor::Credential {
                                             id: 0, // Auto-increment
                                             timestamp: packet_info.timestamp as i64,
                                             source_ip: src_ip.clone(),
                                             service: "HTTP Basic".to_string(),
                                             username: "decode_me".to_string(),
                                             password: token.to_string(),
                                             captured_data: token.to_string(),
                                         };
                                         let _ = db.save_credential(&cred);
                                         let _ = app.emit("credential-captured", cred);
                                         println!("!!! CAPTURED HTTP AUTH !!!");
                                     }
                                 }
                                 
                                 // 2. FTP/POP3 User/Pass
                                 if payload_str.starts_with("USER ") {
                                     let username = payload_str[5..].trim().to_string();
                                     // Store partial cred, wait for PASS? Simplified: Store as 'USER attempt'
                                     let cred = crate::models::monitor::Credential {
                                             id: 0,
                                             timestamp: packet_info.timestamp as i64,
                                             source_ip: src_ip.clone(),
                                             service: "FTP/POP3".to_string(),
                                             username: username.clone(),
                                             password: "WAITING_FOR_PASS".to_string(),
                                             captured_data: payload_str.to_string(),
                                     };
                                     let _ = db.save_credential(&cred);
                                     let _ = app.emit("credential-captured", cred);
                                 } else if payload_str.starts_with("PASS ") {
                                     let password = payload_str[5..].trim().to_string();
                                     let cred = crate::models::monitor::Credential {
                                             id: 0,
                                             timestamp: packet_info.timestamp as i64,
                                             source_ip: src_ip.clone(),
                                             service: "FTP/POP3".to_string(),
                                             username: "UNKNOWN".to_string(),
                                             password: password.clone(),
                                             captured_data: payload_str.to_string(),
                                     };
                                     let _ = db.save_credential(&cred);
                                     let _ = app.emit("credential-captured", cred);
                                     println!("!!! CAPTURED PLAINTEXT PASSWORD !!!");
                                 }
                             }
                         }

                         // Analyze for Threats
                         // Self-Whitelisting: Ignore traffic FROM our own IP (outgoing scans) AND generic IPv6 strings
                         if src_ip != local_ip_str && src_ip != "IPv6" {
                             if let Some(alert) = threat_engine.analyze(&packet_info) {
                                 println!("!!! THREAT DETECTED: {} !!!", alert);
                                 
                                 // Save to DB
                             // Derive simplified title from alert string
                             let title = if alert.contains("Port Scan") { "Port Scan Detected" }
                                         else if alert.contains("DoS") { "DoS Attack Detected" }
                                         else { "Network Threat" };

                             let _ = db.save_alert(
                                 title,
                                 &alert,
                                 &packet_info.src_ip,
                                 &packet_info.dst_ip
                             );

                             // Emit to Frontend
                             let _ = app.emit("threat-alert", alert);
                         }
                         }

                         // Device Detection (Enabled & Enhanced)
                         if let Some(eth) = headers.link {
                                let src_mac = format!("{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}", 
                                    eth.source[0], eth.source[1], eth.source[2], eth.source[3], eth.source[4], eth.source[5]);

                                // Passive OS Fingerprinting (TTL)
                                let mut os_candidate = None;
                                if let Some(ref ip) = headers.ip {
                                    if let etherparse::IpHeader::Version4(ipv4, _) = ip {
                                        let ttl = ipv4.time_to_live;
                                        // Simple Heuristic
                                        if ttl <= 64 { os_candidate = Some("Linux/Android/iOS".to_string()); }
                                        else if ttl <= 128 { os_candidate = Some("Windows".to_string()); }
                                        else { os_candidate = Some("Cisco/Network".to_string()); }
                                    }
                                }

                                // Update Device List
                                {
                                    let mut devices_lock = devices.lock().unwrap();
                                    if let Some(existing) = devices_lock.iter_mut().find(|d| d.mac == src_mac) {
                                        existing.last_seen = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                        existing.packets += 1;
                                        if existing.os_guess.is_none() && os_candidate.is_some() {
                                            existing.os_guess = os_candidate;
                                        }
                                    } else if src_ip != "0.0.0.0" && src_ip != "IPv6" && src_mac != "00:00:00:00:00:00" {
                                        // New Device
                                        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                                        let new_device = Device {
                                            ip: src_ip.clone(),
                                            mac: src_mac.clone(),
                                            hostname: None,
                                            manufacturer: None,
                                            first_seen: now,
                                            last_seen: now,
                                            packets: 1,
                                            last_packet: None,
                                            os_guess: os_candidate,
                                        };
                                        devices_lock.push(new_device.clone());
                                        let _ = db.save_device(&new_device);
                                        let _ = app.emit("new-device", new_device);
                                    }
                                }
                         }
                    },
                    Err(_) => {
                        // Parse error, ignore
                    }
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                continue;
            }
            Err(e) => {
                eprintln!("Packet capture error: {}", e);
            }
        }
    }
}
