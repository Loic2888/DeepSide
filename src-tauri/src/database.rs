use rusqlite::{params, Connection, Result};
use std::sync::Mutex;
use crate::models::monitor::{Device, Alert};

pub struct Database {
    conn: Mutex<Connection>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        let db = Database {
            conn: Mutex::new(conn),
        };
        db.init()?;
        Ok(db)
    }

    fn init(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        
        // Devices Table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL,
                manufacturer TEXT,
                first_seen INTEGER,
                last_seen INTEGER,
                status TEXT DEFAULT 'online',
                notes TEXT
            )",
            [],
        )?;

        // Alerts Table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                level TEXT,
                title TEXT,
                description TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                resolved INTEGER DEFAULT 0
            )",
            [],
        )?;

        Ok(())
    }

    pub fn save_device(&self, device: &Device) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO devices (mac, ip, manufacturer, first_seen, last_seen, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                last_seen = excluded.last_seen,
                status = excluded.status",
            params![
                device.mac,
                device.ip,
                device.manufacturer,
                (device.first_seen as i64),
                (device.last_seen as i64),
                "online"
            ],
        )?;
        Ok(())
    }

    pub fn save_alert(&self, title: &str, description: &str, src_ip: &str, dst_ip: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        
        let level = if title.contains("DoS") { "CRITICAL" } else { "WARNING" };

        conn.execute(
            "INSERT INTO alerts (timestamp, level, title, description, source_ip, destination_ip, resolved)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
            params![
                (now as i64),
                level,
                title,
                description,
                src_ip,
                dst_ip
            ],
        )?;
        Ok(())
    }

    pub fn get_all_devices(&self) -> Result<Vec<Device>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT mac, ip, manufacturer, first_seen, last_seen FROM devices")?;
        
        let device_iter = stmt.query_map([], |row| {
            Ok(Device {
                ip: row.get(1)?,
                mac: row.get(0)?,
                hostname: None,
                manufacturer: row.get(2)?,
                first_seen: row.get::<_, i64>(3)? as u64,
                last_seen: row.get::<_, i64>(4)? as u64,
                packets: 0, // Not persisted for now
                last_packet: None,
                os_guess: None,
            })
        })?;

        let mut devices = Vec::new();
        for device in device_iter {
            devices.push(device?);
        }
        Ok(devices)
    }

    pub fn clear_devices(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM devices", [])?;
        // Optional: Keep whitelisted devices? For now, clear all.
        Ok(())
    }


    pub fn get_recent_alerts(&self, limit: i64) -> Result<Vec<Alert>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, level, title, description, source_ip, destination_ip 
             FROM alerts 
             ORDER BY timestamp DESC 
             LIMIT ?1"
        )?;

        let alert_iter = stmt.query_map([limit], |row| {
            Ok(Alert {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                level: row.get(2)?,
                title: row.get(3)?,
                description: row.get(4)?,
                source_ip: row.get(5)?,
                destination_ip: row.get(6)?, // Option handles NULL
            })
        })?;

        let mut alerts = Vec::new();
        for alert in alert_iter {
            alerts.push(alert?);
        }
        Ok(alerts)
    }

    pub fn save_credential(&self, cred: &crate::models::monitor::Credential) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO credentials (timestamp, source_ip, service, username, password, captured_data)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                cred.timestamp,
                cred.source_ip,
                cred.service,
                cred.username,
                cred.password,
                cred.captured_data
            ],
        )?;
        Ok(())
    }

    pub fn get_credentials(&self, limit: i64) -> Result<Vec<crate::models::monitor::Credential>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, timestamp, source_ip, service, username, password, captured_data 
             FROM credentials 
             ORDER BY timestamp DESC 
             LIMIT ?1"
        )?;

        let cred_iter = stmt.query_map([limit], |row| {
            Ok(crate::models::monitor::Credential {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                source_ip: row.get(2)?,
                service: row.get(3)?,
                username: row.get(4)?,
                password: row.get(5)?,
                captured_data: row.get(6)?,
            })
        })?;

        let mut creds = Vec::new();
        for cred in cred_iter {
            creds.push(cred?);
        }
        Ok(creds)
    }
}
