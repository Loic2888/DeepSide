import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import { WebviewWindow } from "@tauri-apps/api/webviewWindow";

// ============================================
// THREAT CLASSIFICATION ENGINE (No AI - Fast)
// ============================================

// Cumulative IP tracking (50+50+50 = 150)
interface IpActivity {
  scanCount: number;       // Cumulated port scans
  connectionCount: number; // Total connections
  lastSeen: number;        // Timestamp
  alerts: string[];        // Alert IDs
}
const ipActivityLog = new Map<string, IpActivity>();

function updateIpActivity(ip: string, type: 'scan' | 'connection', count: number = 1): IpActivity {
  const now = Date.now();
  const existing = ipActivityLog.get(ip) || { scanCount: 0, connectionCount: 0, lastSeen: now, alerts: [] };

  // Reset if > 30 min since last activity (sliding window)
  if (now - existing.lastSeen > 1800000) {
    existing.scanCount = 0;
    existing.connectionCount = 0;
  }

  if (type === 'scan') existing.scanCount += count;
  if (type === 'connection') existing.connectionCount += count;
  existing.lastSeen = now;

  ipActivityLog.set(ip, existing);
  return existing;
}

// Decision types
type ThreatAction = 'FALSE_POSITIVE' | 'SURVEILLANCE' | 'BLOCK' | 'ASK_AI';
interface ThreatDecision {
  action: ThreatAction;
  reason: string;
  mitre_id?: string;
}

// MITRE ATT&CK Rule-Based Classification
function classifyThreat(threatType: string, sourceIp: string, details: any = {}): ThreatDecision {
  const activity = ipActivityLog.get(sourceIp) || { scanCount: 0, connectionCount: 0, lastSeen: 0, alerts: [] };

  // T1046 - Port Scan
  if (threatType.includes('Scan') || threatType.includes('scan')) {
    if (activity.scanCount < 50) {
      return { action: 'FALSE_POSITIVE', reason: `< 50 ports cumulés (${activity.scanCount})`, mitre_id: 'T1046' };
    }
    if (activity.scanCount > 500) {
      // CRITICAL: Ne pas bloquer auto, demander analyse IA + approbation user
      return { action: 'ASK_AI', reason: `⚠️ CRITIQUE: > 500 ports cumulés (${activity.scanCount}) - Analyse IA requise`, mitre_id: 'T1046' };
    }
    if (activity.scanCount >= 50 && activity.scanCount <= 200) {
      return { action: 'SURVEILLANCE', reason: `Zone intermédiaire (${activity.scanCount} ports)`, mitre_id: 'T1046' };
    }
    return { action: 'ASK_AI', reason: `Zone grise (${activity.scanCount} ports)`, mitre_id: 'T1046' };
  }

  // T1498 - DoS/DDoS - CRITIQUE mais pas de blocage auto
  if (threatType.includes('Flood') || threatType.includes('DoS') || threatType.includes('DDoS')) {
    return { action: 'ASK_AI', reason: '🚨 DoS/Flood détecté - Analyse IA urgente requise', mitre_id: 'T1498' };
  }

  // T1110 - Brute Force
  if (threatType.includes('Brute') || threatType.includes('Auth') || threatType.includes('Login')) {
    const attempts = details.attempts || activity.connectionCount;
    if (attempts > 5) {
      return { action: 'ASK_AI', reason: `🚨 > 5 tentatives brute force (${attempts}) - Analyse IA requise`, mitre_id: 'T1110' };
    }
    return { action: 'SURVEILLANCE', reason: `${attempts} tentatives`, mitre_id: 'T1110' };
  }

  // T1040 - Network Sniffing / ARP - CRITIQUE
  if (threatType.includes('ARP') || threatType.includes('Sniff') || threatType.includes('MITM')) {
    return { action: 'ASK_AI', reason: '🚨 ARP Spoofing / Sniffing détecté - Analyse IA urgente', mitre_id: 'T1040' };
  }

  // T1071 - DNS Suspicious
  if (threatType.includes('DNS') && (threatType.includes('tunnel') || threatType.includes('suspicious'))) {
    return { action: 'SURVEILLANCE', reason: 'Activité DNS suspecte', mitre_id: 'T1071' };
  }

  // T1048 - Data Exfiltration - CRITIQUE
  if (threatType.includes('Exfil') || (details.bytes_out && details.bytes_out > 10000000)) {
    return { action: 'ASK_AI', reason: '🚨 Exfiltration de données suspectée - Analyse IA urgente', mitre_id: 'T1048' };
  }

  // T1219 - Remote Access Tools - CRITIQUE
  if (threatType.includes('RAT') || threatType.includes('Remote Access') || threatType.includes('Backdoor')) {
    return { action: 'ASK_AI', reason: '🚨 Outil d\'accès distant détecté - Analyse IA urgente', mitre_id: 'T1219' };
  }

  // T1102 - C2 Communication - CRITIQUE
  if (threatType.includes('C2') || threatType.includes('Command') || threatType.includes('Beacon')) {
    return { action: 'ASK_AI', reason: '🚨 Communication C2 suspectée - Analyse IA urgente', mitre_id: 'T1102' };
  }

  // T1133 - External Remote Services
  if (threatType.includes('RDP') || threatType.includes('SSH') || threatType.includes('VNC')) {
    if (details.external) {
      return { action: 'SURVEILLANCE', reason: 'Accès distant externe détecté', mitre_id: 'T1133' };
    }
  }

  // Unknown - Ask AI
  return { action: 'ASK_AI', reason: 'Type de menace non classifié', mitre_id: 'N/A' };
}

// URL Blacklist (energy-efficient)
const PHISHING_PATTERNS = [
  /login.*\..*\./, /secure.*-/, /account.*verify/i, /paypal.*\d/i,
  /microsoft.*login/i, /google.*signin/i, /apple.*id/i, /bank.*secure/i
];
const KNOWN_MALICIOUS_DOMAINS = new Set([
  'malware.com', 'phishing-site.net', 'evil.org', 'steal-data.com'
]);

function analyzeUrl(url: string): { suspicious: boolean; reason: string } {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // Check blacklist
    if (KNOWN_MALICIOUS_DOMAINS.has(domain)) {
      return { suspicious: true, reason: 'Domaine malveillant connu' };
    }

    // Check patterns
    for (const pattern of PHISHING_PATTERNS) {
      if (pattern.test(url)) {
        return { suspicious: true, reason: 'Pattern phishing détecté' };
      }
    }

    // Check suspicious TLDs
    if (domain.endsWith('.tk') || domain.endsWith('.ml') || domain.endsWith('.ga') || domain.endsWith('.cf')) {
      return { suspicious: true, reason: 'TLD suspect' };
    }

    return { suspicious: false, reason: 'OK' };
  } catch {
    return { suspicious: false, reason: 'URL invalide' };
  }
}

// Threat Log for history
interface ThreatLogEntry {
  id: string;
  timestamp: string;
  title: string;
  source_ip: string;
  mitre_id: string;
  action: ThreatAction;
  reason: string;
  status: 'pending' | 'resolved' | 'false_positive' | 'blocked' | 'watching';
}
const threatLog: ThreatLogEntry[] = [];

function addToThreatLog(entry: Omit<ThreatLogEntry, 'id' | 'timestamp'>): ThreatLogEntry {
  const logEntry: ThreatLogEntry = {
    id: `TL-${Date.now()}`,
    timestamp: new Date().toLocaleTimeString(),
    ...entry
  };
  threatLog.unshift(logEntry); // Most recent first
  if (threatLog.length > 100) threatLog.pop(); // Keep last 100
  return logEntry;
}

// State
let packetCount = 0;
const devices = new Map<string, any>();
let currentLocalIp = "192.168.1.0"; // Default, updated by event

// DOM Elements
const elPackets = document.getElementById("val-packets");
const elTargets = document.getElementById("val-targets");
const elList = document.getElementById("device-list");
const elChat = document.getElementById("chat-output");
const elActivityLog = document.getElementById("activity-log");

function updateStats() {
  if (elPackets) elPackets.innerText = packetCount.toLocaleString();
  if (elTargets) elTargets.innerText = devices.size.toString();
}

function logChat(msg: string, type: 'system' | 'user' | 'ai' | 'proxy-log' = 'system') {
  if (!elChat) return;
  const div = document.createElement("div");
  div.className = `line ${type}`;
  div.innerText = msg;
  elChat.appendChild(div);
  elChat.scrollTop = elChat.scrollHeight;
}

function logActivity(msg: string, type: 'scan' | 'device' | 'threat' | 'proxy' | 'ai' | 'system' = 'system') {
  if (!elActivityLog) return;
  const time = new Date().toLocaleTimeString('fr-FR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const div = document.createElement("div");
  div.className = `activity-entry ${type}`;
  div.innerHTML = `<span class="activity-entry-time">${time}</span>${msg}`;
  if (elActivityLog.children.length > 50) {
    elActivityLog.removeChild(elActivityLog.children[0]);
  }
  elActivityLog.appendChild(div);
  elActivityLog.scrollTop = elActivityLog.scrollHeight;
}

function addDeviceRow(device: any) {
  if (!elList) return;
  const macClean = device.mac.replace(/:/g, '');
  if (document.getElementById(`row-${macClean}`)) return;

  const div = document.createElement("div");
  div.className = "list-row";
  div.id = `row-${macClean}`;

  let vendor = device.manufacturer || "Unknown";
  if (vendor.length > 20) vendor = vendor.substring(0, 17) + "...";

  div.innerHTML = `
        <div style="flex: 1">
            <span style="color: var(--accent-2); font-weight: bold;">${device.ip}</span> 
            <span id="flag-${macClean}" style="font-size: 12px; cursor: help;"></span><br>
            <span style="color: #666; font-size: 11px;">${device.mac}</span>
        </div>
        <div style="text-align: right; min-width: 140px;">
            <div style="color: var(--text-dim); font-size: 11px; margin-bottom: 4px;">${vendor}</div>
            <div style="color: var(--accent); font-size: 10px; margin-bottom: 4px;">${device.os_guess || ''}</div>
            <div style="display: flex; gap: 4px; justify-content: flex-end;">
                <button class="btn-disconnect" id="disc-${macClean}" onclick="window.disconnectDevice('${device.ip}', '${device.mac}')" title="Disconnect from WiFi">⚡</button>
                <button class="btn-block" id="btn-${macClean}" onclick="window.toggleBlock('${device.ip}', '${macClean}', '${device.mac}')">BLOCK</button>
            </div>
        </div>
    `;

  elList.prepend(div);

  invoke("get_geoip", { ip: device.ip }).then((res: any) => {
    const elFlag = document.getElementById(`flag-${macClean}`);
    if (elFlag && res.iso) {
      elFlag.innerText = `[${res.iso}]`;
      elFlag.title = res.country;
    }
  }).catch(() => { });
}

(window as any).switchTab = (tabId: string) => {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  document.getElementById(`nav-${tabId}`)?.classList.add('active');

  const views = ['dashboard', 'evidence', 'map', 'settings'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    if (el) el.style.display = 'none';
  });

  const activeEl = document.getElementById(`view-${tabId}`);
  if (activeEl) {
    activeEl.style.display = 'flex';
    if (tabId === 'evidence') loadEvidence();
  }
};

async function loadEvidence() {
  const list = document.getElementById('evidence-list');
  if (!list) return;
  try {
    const creds = await invoke('get_credentials', { limit: 50 }) as any[];
    const elCreds = document.getElementById('val-creds');
    if (elCreds) elCreds.innerText = creds.length.toString();
    if (creds.length === 0) {
      list.innerHTML = '<div style="padding: 20px; text-align: center; color: #666;">No credentials captured yet.</div>';
      return;
    }
    list.innerHTML = creds.map((c: any) => `
            <div class="list-row" style="border-left: 3px solid ${c.username === 'decode_me' ? '#aa00ff' : '#ff3333'};">
                <div style="width: 15%; color: #666;">${new Date(c.timestamp * 1000).toLocaleTimeString()}</div>
                <div style="width: 15%; color: #fff;">${c.source_ip}</div>
                <div style="width: 15%; color: #00ccff;">${c.service}</div>
                <div style="width: 25%; color: #fff;">User: <span style="color: #ffae00">${c.username}</span></div>
                <div style="flex-grow: 1; color: #ff3333; font-weight: bold; filter: blur(4px); transition: 0.3s; cursor: pointer;" onclick="this.style.filter='none'">
                    ${c.password}
                </div>
            </div>
        `).join('');
  } catch (e) { console.error("Failed to load evidence", e); }
}
(window as any).loadEvidence = loadEvidence;

(window as any).toggleBlock = async (ip: string, macId: string, rawMac: string) => {
  const btn = document.getElementById(`btn-${macId}`);
  if (!btn) return;
  const isBlocked = btn.classList.contains("blocked");
  const cmd = isBlocked ? "UNBLOCK" : "BLOCK";
  logChat(`Initiating ${cmd} for ${ip}...`, "system");
  try {
    if (!isBlocked) {
      await invoke("start_arp", { targetIp: ip, targetMac: rawMac, gatewayIp: "192.168.1.1", gatewayMac: "00:00:00:00:00:00" });
      btn.innerText = "UNBLOCK";
      btn.classList.add("blocked");
      document.getElementById(`row-${macId}`)?.classList.add("row-blocked");
      logChat(`ARP Attack Started on ${ip}`, "system");
    } else {
      await invoke("stop_arp");
      btn.innerText = "BLOCK";
      btn.classList.remove("blocked");
      document.getElementById(`row-${macId}`)?.classList.remove("row-blocked");
      logChat(`ARP Attack Stopped`, "system");
    }
  } catch (e) { logChat(`Error: ${e}`, "system"); }
};

(window as any).disconnectDevice = async (ip: string, mac: string) => {
  const macClean = mac.replace(/:/g, '');
  const btn = document.getElementById(`disc-${macClean}`);
  if (btn) {
    btn.classList.add("disconnecting");
    btn.innerText = "⏳";
  }
  logChat(`⚡ Disconnecting ${ip} from WiFi...`, "system");
  logActivity(`⚡ Déconnexion WiFi: ${ip}`, 'threat');
  try {
    await invoke("start_arp", { targetIp: ip, targetMac: mac, gatewayIp: "192.168.1.1", gatewayMac: "00:00:00:00:00:00" });
    setTimeout(async () => {
      try {
        await invoke("stop_arp");
        logChat(`✅ ${ip} disconnect complete`, "system");
        if (btn) {
          btn.classList.remove("disconnecting");
          btn.innerText = "⚡";
        }
      } catch (e) { console.error("Stop ARP error:", e); }
    }, 5000);
  } catch (e) {
    logChat(`Disconnect Error: ${e}`, "system");
    if (btn) {
      btn.classList.remove("disconnecting");
      btn.innerText = "⚡";
    }
  }
};

async function init() {

  await listen("network-stats", (e: any) => {
    packetCount = e.payload.total_packets;
    updateStats();
  });

  // Traffic Flow - Real IP connections
  await listen("traffic-flow", (e: any) => {
    const flow = e.payload as string;
    logActivity(`🌐 ${flow}`, 'scan');
  });

  // 1. Listen for Local IP (Moved here for race condition fix)
  await listen("local-ip", (e: any) => {
    const el = document.getElementById("local-ip-display");
    if (el) el.innerText = `Local IP: ${e.payload}`;
    currentLocalIp = e.payload; // Store it!
  });

  // 2. Load Initial Devices (Fix empty list on reload)
  try {
    const initialDevices = await invoke("get_devices") as any[];
    initialDevices.forEach(d => {
      devices.set(d.mac, d);
      addDeviceRow(d);
    });
    updateStats();
  } catch (e) { console.error("Failed to load devices", e); }

  await listen("new-device", (e: any) => {
    devices.set(e.payload.mac, e.payload);
    addDeviceRow(e.payload);
    updateStats();
    logActivity(`📱 Nouvel appareil: ${e.payload.ip} (${e.payload.manufacturer || 'Unknown'})`, 'device');
  });

  await listen("proxy-log", (e: any) => {
    // e.payload is string line
    logChat(e.payload, "proxy-log");
    logActivity(`🔄 ${e.payload}`, 'proxy');
  });

  await listen("credential-captured", (e: any) => {
    // Notification
    showToast(`🔓 CREDENTIAL CAPTURED: ${e.payload.service} from ${e.payload.source_ip}`);
    logChat(`🔓 CREDENTIAL CAPTURED: ${e.payload.username}@${e.payload.service}`, "system");
    logActivity(`🔑 Credential capturé: ${e.payload.username}@${e.payload.service}`, 'threat');

    // Refresh if visible
    const evView = document.getElementById('view-evidence');
    if (evView && evView.style.display !== 'none') {
      loadEvidence();
    }
  });

  // --- AI CHAT HANDLING ---
  const input = document.getElementById("ai-input") as HTMLInputElement;
  input?.addEventListener("keypress", async (e) => {
    if (e.key === "Enter" && input.value.trim()) {
      const prompt = input.value.trim();
      input.value = "";
      logChat(prompt, "user");

      try {
        logChat("Thinking...", "system"); // Loading state

        // 1. Context Generator
        let systemPrompt = `Tu es Illya, Opérateur de la TSCR (Tour de Surveillance et de Contrôle du Réseau).

STYLE DE COMMUNICATION:
- Réponds TOUJOURS en français
- Sois DIRECT et CONCIS (max 3-4 phrases par point)
- Utilise des bullet points pour la clarté
- Cite les codes MITRE ATT&CK quand pertinent (T1046, T1110, etc.)

CAPACITÉS (Mode Agentique):
Tu peux exécuter des commandes en les incluant dans ta réponse. Respecte STRICTEMENT ce format: CMD:ACTION:TARGET (ex: CMD:SCAN:ALL).

COMMANDES DISPONIBLES:
- CMD:SCAN:ALL → Scanner tout le sous-réseau (Ping Sweep)
- CMD:SCAN:<IP> → Scanner les ports d'une IP cible
- CMD:CREDENTIALS:ALL → Afficher les identifiants capturés
- CMD:BLOCK:<IP> → Bloquer l'IP via ARP Spoofing
- CMD:ANALYZE:<URL> → Analyser une URL suspecte
- CMD:IDENTIFY_DEVICE:<IP> → Identifier un appareil par ses ports

EXEMPLE:
"J'ai détecté une activité suspecte.
• Action: SCAN sur l'hôte cible.
CMD:SCAN:192.168.1.50"`;

        let userPrompt = "";

        // Add network context
        if (devices.size > 0) {
          userPrompt += `Detected Devices:\n`;
          let limit = 0;
          devices.forEach((dev) => {
            if (limit < 8) { // Soft limit
              userPrompt += `- ${dev.ip} (${dev.mac}) Vendor: ${dev.manufacturer || "?"}\n`;
              limit++;
            }
          });
        }

        // Add Threat Context
        try {
          const alerts = await invoke("get_alerts") as any[];
          if (alerts && alerts.length > 0) {
            userPrompt += `\nRecent Threats (Analyze these if relevant):\n`;
            alerts.forEach(a => {
              userPrompt += `- [${a.level}] ${a.title}: ${a.description} (Source: ${a.source_ip})\n`;
            });
          }
        } catch (e) { console.error("Failed to fetch alerts for AI context", e); }

        userPrompt += `User Query: ${prompt}`;

        // Construct Phi-3 Instruct Prompt
        const finalPrompt = `<|system|>\n${systemPrompt}<|end|>\n<|user|>\n${userPrompt}<|end|>\n<|assistant|>`;

        const response = (await invoke("ask_ai", { prompt: finalPrompt }) as string).trim();

        // 2. Display Illya's Reasoning
        logChat(response || "(Pas de réponse de l'IA)", "ai");

        if (!response) {
          logChat("⚠️ L'IA n'a pas retourné de réponse.", "system");
          return;
        }

        // 3. Command Execution Loop (Regex)
        // Fixed Regex to support underscores (IDENTIFY_DEVICE) and optional colon/target
        const cmdRegex = /CMD:([A-Z_]+):?([^\s\n]*)/g;
        let match;
        let executedCount = 0;

        while ((match = cmdRegex.exec(response)) !== null) {
          executedCount++;
          const action = match[1];
          const target = (match[2] || "").trim();

          logChat(`⚡ Illya Executing: ${action} ${target ? 'on ' + target : ''}`, "system");
          logActivity(`🤖 CMD: ${action} → ${target}`, 'ai');

          if (action === "NETSCAN" || (action === "SCAN" && target === "ALL")) {
            logChat(`📡 Starting Network Sweep on subnet of ${currentLocalIp}...`, "system");
            logActivity(`📡 Scan réseau démarré`, 'scan');
            try {
              const subnet = currentLocalIp.split('.').slice(0, 3).join('.') + ".";
              const res = await invoke("run_ping_sweep", { subnet: subnet }) as string;
              logChat(res, "system");
            } catch (e) { logChat(`Sweep Failed: ${e}`, "system"); }

          } else if (action === "SCAN" && target !== "ALL") {
            try {
              const ports = await invoke("run_port_scan", { target: target }) as number[];
              logChat(`[SCAN RESULT] ${target} Open Ports: [${ports.join(", ")}]`, "system");
              logActivity(`🔍 Ports ouverts sur ${target}: ${ports.length}`, 'scan');
            } catch (e) { logChat(`Scan Failed: ${e}`, "system"); }

          } else if (action === "CREDENTIALS") {
            logChat(`🔓 Fetching captured credentials...`, "system");
            loadEvidence();

          } else if (action === "IDENTIFY_DEVICE") {
            logChat(`🔍 Identifying Device: ${target}...`, "system");
            try {
              const ports = await invoke("run_port_scan", { target: target }) as number[];
              logChat(`[ID RESULT] ${target} Open Ports: [${ports.join(", ")}]`, "system");
              setTimeout(() => {
                logChat(`[ID RESULT] ${target} Vendor Analysis: Likely Generic/Generic Interface`, "ai");
              }, 1000);
            } catch (e) { logChat(`Identification Failed: ${e}`, "system"); }

          } else if (action === "BLOCK") {
            // Find MAC for IP
            let targetMac = "";
            devices.forEach(d => {
              if (d.ip === target) {
                targetMac = d.mac.replace(/:/g, '');
              }
            });

            if (targetMac) {
              logChat(`⚠️ AI requested BLOCK for ${target}. Waiting for User Approval...`, "system");
              (window as any).showActionPopup({
                threatTitle: "Blocage Requis par IA",
                sourceIp: target,
                mitreId: "AI-CMD",
                aiAnalysis: "L'IA a identifié une menace et recommande le blocage immédiat de cet hôte.",
                solution: `Bloquer ${target}`,
                alertId: `ai-cmd-${Date.now()}`
              });
            } else {
              logChat(`Block Failed: Device ${target} not found in table.`, "system");
            }

          } else if (action === "ANALYZE") {
            try {
              const res = await invoke("analyze_url", { urlStr: target }) as any;
              logChat(`[ANALYSIS] ${target} -> Risk: ${res.risk_score}/100 [${res.risk_level}]`, "system");
              if (res.reasons.length > 0) logChat(`Reasons: ${res.reasons.join(", ")}`, "system");
            } catch (e) { logChat(`Analysis Failed: ${e}`, "system"); }
          }
        }

        if (executedCount === 0 && !response.includes("CMD:")) {
          // If the user seems to want a command but AI didn't provide one
          if (prompt.toLowerCase().includes("scan") || prompt.toLowerCase().includes("identifier") || prompt.toLowerCase().includes("bloquer")) {
            logChat("ℹ️ Illya n'a pas détecté de commande à exécuter. Précisez mieux votre demande.", "system");
          }
        }
      } catch (err) {
        logChat(`Ollama Error: ${err}`, "system");
      }
    }
  });

  // Proxy Toggle
  const proxyToggle = document.getElementById("proxy-toggle");
  proxyToggle?.addEventListener('click', async (e) => {
    e.stopPropagation(); // prevent nav click
    const isActive = proxyToggle.classList.contains("active");
    if (!isActive) {
      try {
        await invoke("run_proxy_server", { port: 8080 });
        proxyToggle.classList.add("active");
        // Update UI to show System Proxy is Active
        logChat("✅ Proxy DeepSide ACTIF (127.0.0.1:8080)", "system");
        logChat("ℹ️ Configurez votre OS/Navigateur sur ce proxy pour intercepter le trafic.", "system");
        showToast("Proxy Actif sur port 8080");
      } catch (err) {
        logChat(`Proxy Error: ${err}`, "system");
      }
    } else {
      logChat("Pour désactiver, redémarrez l'application.", "system");
    }
  });

  // Sentinel Toggle
  const sentinelToggle = document.getElementById("btn-sentinel");
  sentinelToggle?.addEventListener('click', (e) => {
    e.stopPropagation();
    const isActive = sentinelToggle.classList.toggle("active");
    if (isActive) {
      sentinelToggle.classList.add("sentinel-active");
      logChat("🤖 SENTINEL MODE ACTIVATED. Auto-Defense engaged.", "system");
      logActivity("🛡️ Sentinel activé - Défense auto", 'system');
    } else {
      sentinelToggle.classList.remove("sentinel-active");
      logChat("SENTINEL MODE DEACTIVATED.", "system");
      logActivity("⏸️ Sentinel désactivé", 'system');
    }
  });

  // --- THREAT ALERTS (Autonomous Sentinel) ---
  await listen("threat-alert", async (e: any) => {
    const msg = e.payload as string;

    // Parse the alert message to extract info
    const ipMatch = msg.match(/from (\d+\.\d+\.\d+\.\d+)/);
    const sourceIp = ipMatch ? ipMatch[1] : "N/A";
    const portMatch = msg.match(/(\d+)\s*ports?/i);
    const portCount = portMatch ? parseInt(portMatch[1]) : 1;

    // Update cumulative IP tracking
    if (sourceIp !== "N/A") {
      updateIpActivity(sourceIp, 'scan', portCount);
    }

    // Get cumulative activity for this IP
    const activity = ipActivityLog.get(sourceIp);
    const cumulativePorts = activity?.scanCount || portCount;

    // Create a structured alert object
    const alert = {
      id: `alert - ${Date.now()} `,
      title: msg.replace(/from \d+\.\d+\.\d+\.\d+/, '').trim(),
      level: msg.includes("Critical") ? "CRITICAL" : msg.includes("High") ? "HIGH" : "MEDIUM",
      source_ip: sourceIp,
      target_ip: "Local Network",
      mitre_id: msg.includes("Scan") ? "T1046" : msg.includes("Flood") ? "T1498" : "N/A",
      description: `${msg} (Cumulé: ${cumulativePorts} ports)`,
      recommendation: "Analysez l'activité et bloquez si nécessaire.",
      timestamp: new Date().toLocaleTimeString()
    };

    // Register alert for clicking
    (window as any).registerAlert(alert);

    // Check if Sentinel mode is active
    const sentinelBtn = document.getElementById("btn-sentinel");
    const isSentinelActive = sentinelBtn && sentinelBtn.classList.contains("active");

    if (isSentinelActive && sourceIp !== "N/A") {
      // ========== AUTONOMOUS SENTINEL MODE ==========
      logChat(`🔍 Menace repérée: ${alert.title} `, "system");
      logChat(`⚡ Analyse rapide en cours...`, "system");
      logActivity(`⚠️ Menace: ${alert.title} de ${sourceIp}`, 'threat');

      // Use rule-based classification
      const decision = classifyThreat(alert.title, sourceIp, { ports: cumulativePorts });

      // Log to threat history
      const logEntry = addToThreatLog({
        title: alert.title,
        source_ip: sourceIp,
        mitre_id: decision.mitre_id || "N/A",
        action: decision.action,
        reason: decision.reason,
        status: 'pending'
      });

      // Execute action based on decision
      if (decision.action === 'FALSE_POSITIVE') {
        logChat(`✅ Faux positif classé: ${decision.reason}`, "system");
        logEntry.status = 'false_positive';

      } else if (decision.action === 'SURVEILLANCE') {
        logChat(`👁️ Sous surveillance: ${decision.reason}`, "system");
        logEntry.status = 'watching';

      } else if (decision.action === 'ASK_AI') {
        // Analyse IA pour tous les cas non évidents (y compris critiques)
        const isCritical = decision.reason.includes('CRITIQUE') || decision.reason.includes('🚨');

        if (isCritical) {
          logChat(`🚨 MENACE CRITIQUE DÉTECTÉE - Analyse IA en cours...`, "system");
        } else {
          logChat(`🧠 Analyse IA en cours...`, "system");
        }

        try {
          const aiPrompt = `Tu es Illya, analyste cybersécurité.Analyse cette menace de façon CONCISE(5 lignes max):

      IP Source: ${sourceIp}
Activité: ${cumulativePorts} ports scannés(cumulé sur 30 min)
Type: ${alert.title}
MITRE: ${decision.mitre_id}
Raison détection: ${decision.reason}

Réponds avec:
      1. ** Verdict **: Faux positif / Menace réelle / Incertain
2. ** Action recommandée **: Ignorer / Surveiller / BLOQUER(si menace avérée)
3. ** Justification **: 1 - 2 lignes`;

          const response = await invoke("ask_ai", { prompt: aiPrompt }) as string;
          const aiResponse = response.trim();

          // Afficher la réponse IA dans le chat
          logChat(`🤖 ${aiResponse}`, "ai");

          // Parse AI response for status
          const aiLower = aiResponse.toLowerCase();

          if (aiLower.includes('bloquer') || aiLower.includes('block')) {
            // ⚠️ AFFICHER LE POPUP D'ACTION
            logEntry.status = 'pending';

            // Déterminer la solution recommandée
            let solution = `Bloquer l'IP ${sourceIp}`;
            if (aiLower.includes('bannir') || aiLower.includes('ban')) {
              solution = `Bannir définitivement l'IP ${sourceIp}`;
            }

            // Afficher le popup d'action urgente
            (window as any).showActionPopup({
              threatTitle: alert.title,
              sourceIp: sourceIp,
              mitreId: decision.mitre_id || 'N/A',
              aiAnalysis: aiResponse,
              solution: solution,
              alertId: alert.id
            });

          } else if (aiLower.includes('fp') || aiLower.includes('faux positif') || aiLower.includes('ignorer')) {
            logEntry.status = 'false_positive';
          } else {
            logEntry.status = 'watching';
          }
        } catch (err) {
          logChat(`⚠️ IA indisponible - Surveillance par défaut`, "system");
          logEntry.status = 'watching';
        }
      }

      logChat(`📋 [${decision.mitre_id}] Statut: ${logEntry.status}`, "system");

    } else {
      // Manual mode - just show clickable alert
      const chatDiv = document.createElement("div");
      chatDiv.className = "line system threat-clickable";
      chatDiv.style.cursor = "pointer";
      chatDiv.style.borderLeft = "3px solid #ff7b72";
      chatDiv.style.paddingLeft = "8px";
      chatDiv.style.marginTop = "5px";
      chatDiv.innerHTML = `⚠️ <b>${alert.level}</b>: ${alert.title} <span style="color:#666; font-size:10px;">(cliquer pour détails)</span>`;
      chatDiv.onclick = () => (window as any).showThreatDetails(alert.id);

      if (elChat) {
        elChat.appendChild(chatDiv);
        elChat.scrollTop = elChat.scrollHeight;
      }

      showToast(msg);
      logActivity(`⚠️ ${alert.level}: ${alert.title}`, 'threat');
    }

    // Increment stats
    const elThreats = document.getElementById("val-threats");
    if (elThreats) {
      let current = parseInt(elThreats.innerText) || 0;
      elThreats.innerText = (current + 1).toString();
    }
  });


  // --- SCAN RESULTS ---
  await listen("scan-result", (e: any) => {
    const ip = e.payload as string;
    logChat(`[SCAN] Found Device: ${ip}`, "system");
    logActivity(`🔍 Scan: appareil trouvé ${ip}`, 'scan');

    // Update Button State if it was the last one (approximated)
    // Actually run_ping_sweep returns a message when done.
  });
}

function showToast(msg: string) {
  const container = document.getElementById("toast-container");
  if (!container) return;

  const div = document.createElement("div");
  div.className = "toast";
  div.innerText = msg;

  container.appendChild(div);

  // Auto remove after 5s
  setTimeout(() => {
    div.style.opacity = "0";
    setTimeout(() => div.remove(), 300);
  }, 5000);
}

// Start
init();
logActivity("⚡ Système initialisé - TSCR Online", 'system');

// Auto-launch Sentinel, Proxy, and Sniffing on startup (delay for Tauri state init)
setTimeout(async () => {
  // Start network sniffing
  try {
    await invoke("start_sniffing");
    logActivity("📡 Surveillance WiFi active", 'scan');
    logChat("📡 Network Sniffing Started", "system");
  } catch (err) {
    logChat(`Sniffing Error: ${err}`, "system");
    logActivity("❌ Échec démarrage sniffing", 'threat');
  }

  // Auto-activate Sentinel
  const sentinelBtn = document.getElementById("btn-sentinel");
  if (sentinelBtn && !sentinelBtn.classList.contains("active")) {
    sentinelBtn.classList.add("active");
    sentinelBtn.classList.add("sentinel-active");
    logChat("🤖 SENTINEL MODE ACTIVATED. Auto-Defense engaged.", "system");
    logActivity("🛡️ Sentinel activé - Défense auto", 'system');
  }

  // Auto-start Proxy
  const btnProxyAuto = document.getElementById("btn-proxy-ui");
  logChat("🕵️ Starting Proxy Server on Port 8080...", "system");
  try {
    await invoke("run_proxy_server", { port: 8080 });
    logActivity("🕵️ Proxy démarré sur port 8080", 'proxy');
    if (btnProxyAuto) {
      btnProxyAuto.classList.add("active");
      btnProxyAuto.innerHTML = `<span class="icon">🛑</span> STOP PROXY`;
    }
  } catch (e: any) {
    const errStr = String(e);
    // Error 10048 = port already in use = proxy already running
    if (errStr.includes("10048") || errStr.includes("already in use") || errStr.includes("Address already")) {
      logChat("🕵️ Proxy already running on Port 8080", "system");
      logActivity("🕵️ Proxy déjà actif (port 8080)", 'proxy');
      if (btnProxyAuto) {
        btnProxyAuto.classList.add("active");
        btnProxyAuto.innerHTML = `<span class="icon">🛑</span> STOP PROXY`;
      }
    } else {
      logChat(`Proxy Launch Failed: ${e}`, "system");
      logActivity("❌ Échec démarrage proxy", 'threat');
    }
  }

  // Check AI status
  try {
    const aiStatusEl = document.getElementById('status-ai');
    if (aiStatusEl) {
      aiStatusEl.classList.add('loading');
      aiStatusEl.title = 'AI Status: Loading...';
    }

    const aiStatus = await invoke<{ loaded: boolean, error?: string }>('check_ai_status');

    if (aiStatusEl) {
      if (aiStatus.loaded) {
        aiStatusEl.classList.remove('loading');
        aiStatusEl.classList.add('ready');
        aiStatusEl.title = 'AI Status: Ready ✓';
        logActivity("🤖 IA locale chargée", 'ai');
        logChat("🤖 Local AI Engine Ready (ORT 2.0)", "system");
      } else {
        aiStatusEl.classList.remove('loading');
        aiStatusEl.classList.add('error');
        aiStatusEl.title = `AI Status: ${aiStatus.error || 'Model not loaded'}`;
        logActivity(`⚠️ IA non disponible: ${aiStatus.error || 'Erreur inconnue'}`, 'system');
        logChat(`❌ AI Init Error: ${aiStatus.error}`, "system");
      }
    }
  } catch (e: any) {
    const aiStatusEl = document.getElementById('status-ai');
    if (aiStatusEl) {
      aiStatusEl.classList.remove('loading');
      aiStatusEl.classList.add('error');
      aiStatusEl.title = 'AI Status: Check failed';
    }
  }
}, 1000);

// Moved inside init() to ensure early binding

// --- COMMAND CENTER BUTTONS ---

// 1. SCAN NET
// 1. SCAN NET
const btnScan = document.getElementById("btn-scan-net");
btnScan?.addEventListener("click", async () => {
  if (btnScan) btnScan.innerHTML = `<span class="icon">⏳</span> SCANNING...`;
  logChat("⚡ Initiating Full Network Ping Sweep...", "system");
  logActivity("📡 Scan réseau lancé (192.168.1.0/24)", 'scan');
  try {
    await invoke("run_ping_sweep", { subnet: "192.168.1.0/24" });
    // Don't reset button immediately, wait for results? 
    // Actually run_ping_sweep in Rust is async and returns "Sweep Complete" string when done.
    // Intermediate results come via "scan-result" event.
  } catch (e) {
    logChat("Scan start failed: " + e, "system");
    if (btnScan) btnScan.innerHTML = `<span class="icon">📡</span> SCAN`;
  }
});

// 2. PROXY UI (Toggle)
const btnProxy = document.getElementById("btn-proxy-ui");
let proxyRunning = true; // Auto-started on launch
btnProxy?.addEventListener("click", async () => {
  if (!proxyRunning) {
    logChat("🕵️ Starting Proxy Server on Port 8080...", "system");
    logActivity("🕵️ Proxy démarré sur port 8080", 'proxy');
    try {
      await invoke("run_proxy_server", { port: 8080 });
      proxyRunning = true;
      btnProxy.classList.add("active"); // Visual feedback
      btnProxy.innerHTML = `<span class="icon">🛑</span> STOP PROXY`;
    } catch (e) {
      logChat(`Proxy Launch Failed: ${e}`, "system");
      logActivity("❌ Échec démarrage proxy", 'threat');
    }
  } else {
    // Stop not implemented in backend yet, just refreshing UI state for now
    logChat("Stopping Proxy...", "system");
    logActivity("⏹️ Proxy arrêté", 'proxy');
    proxyRunning = false;
    btnProxy.classList.remove("active");
    btnProxy.innerHTML = `<span class="icon">🕵️</span> PROXY`;
  }
});

// 3. MAP POP-OUT (Overlay Button)
document.getElementById("btn-map-popout-overlay")?.addEventListener("click", async () => {
  logChat("Expanding Map to external window...", "system");
  const mapWindow = await WebviewWindow.getByLabel("map")
  if (mapWindow) {
    mapWindow.show();
    mapWindow.setFocus();
  }
});



// --- LOGIC ---

// New Feature: Top 10 Active Targets
function updateTopTargets() {
  // devices is a Map<mac, deviceObj>. We need values.
  const allDevices = Array.from(devices.values());
  // Sort by packets desc
  const topDevices = allDevices.sort((a: any, b: any) => (b.packets || 0) - (a.packets || 0)).slice(0, 10);

  const list = document.getElementById("device-list");
  if (!list) return;

  list.innerHTML = "";
  topDevices.forEach((d: any, i) => {
    const row = document.createElement("div");
    row.className = "list-row";
    if (d.ip === "192.168.1.1") row.style.borderLeft = "3px solid #e0a800"; // Gateway highlight

    const macClean = d.mac.replace(/:/g, '');
    row.innerHTML = `
            <div style="width:30px; font-weight:bold; color:#666;">#${i + 1}</div>
            <div style="flex:2; color:white;">${d.ip}</div>
            <div style="flex:2; font-size:11px; color:#888;">${d.mac}</div>
            <div style="flex:1; color:var(--accent-blue);">${d.packets} pkts</div>
            <div style="flex:1;">
                <button class="btn-mini ${d.blocked ? 'active' : ''}" id="btn-${macClean}" 
                    onclick="window.toggleBlock('${d.ip}', '${macClean}', '${d.mac}')">
                    ${d.blocked ? 'UNBLOCK' : 'BLOCK'}
                </button>
            </div>
        `;
    list.appendChild(row);
  });
}

// Override updateStats to trigger Top Target Update
// Override updateStats to trigger Top Target Update
// const originalUpdateStats = (window as any).updateStats || function () { };
(window as any).updateStats = () => {
  // Update numbers... (existing logic usually just updates DOM IDs)
  // We invoke our new list render here
  updateTopTargets();
};




// ============================================
// NAVIGATION & VIEW SWITCHING
// ============================================

(window as any).switchTab = (tabId: string) => {
  // 1. Update Buttons
  document.querySelectorAll('.nav-btn').forEach(el => el.classList.remove('active'));
  document.getElementById(`nav-${tabId}`)?.classList.add('active');

  // 2. Hide All Views
  const views = ['illya', 'network', 'map'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    if (el) el.style.display = 'none';
  });

  // 3. Show Active View
  const activeEl = document.getElementById(`view-${tabId}`);
  if (activeEl) {
    if (tabId === 'map') {
      activeEl.style.display = 'block';
    } else {
      activeEl.style.display = 'flex';
    }
  }

  // Special init for tabs
  if (tabId === 'evidence') {
    // loadEvidence function is inside loadEvidence scope but attached to window? 
    // Wait, loadEvidence is attached to window.
    if ((window as any).loadEvidence) (window as any).loadEvidence();
  }
};

// ============================================
// MODAL MANAGEMENT & THREAT DETAILS
// ============================================

// Store alerts for clicking
const alertsStore = new Map<string, any>();
let currentThreat: any = null;

// Close Modal
(window as any).closeModal = (modalId: string) => {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'none';
  }
};

// Open Modal
function openModal(modalId: string) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.style.display = 'flex';
  }
}

// Show Help Modal
(window as any).showHelp = () => {
  openModal('help-modal');
};

// Show Threat Details Modal
(window as any).showThreatDetails = (alertId: string) => {
  const alert = alertsStore.get(alertId);
  if (!alert) {
    logChat(`Alerte ${alertId} non trouvée.`, "system");
    return;
  }

  currentThreat = alert;

  // Populate modal
  const levelBadge = document.getElementById('threat-level-badge');
  const title = document.getElementById('threat-title');
  const source = document.getElementById('threat-source');
  const target = document.getElementById('threat-target');
  const mitre = document.getElementById('threat-mitre');
  const time = document.getElementById('threat-time');
  const desc = document.getElementById('threat-description');
  const rec = document.getElementById('threat-recommendation');
  const aiSection = document.getElementById('ai-analysis-section');

  if (levelBadge) {
    levelBadge.textContent = alert.level || 'HIGH';
    levelBadge.className = `threat-level ${(alert.level || 'high').toLowerCase()}`;
  }
  if (title) title.textContent = alert.title || 'Menace Détectée';
  if (source) source.textContent = alert.source_ip || 'N/A';
  if (target) target.textContent = alert.target_ip || 'N/A';
  if (mitre) mitre.textContent = alert.mitre_id || 'N/A';
  if (time) time.textContent = alert.timestamp || new Date().toLocaleTimeString();
  if (desc) desc.textContent = alert.description || 'Aucune description disponible.';
  if (rec) rec.textContent = alert.recommendation || 'Surveillez l\'activité réseau.';

  // Reset AI section
  if (aiSection) aiSection.style.display = 'none';

  // Enable buttons
  const analyzeBtn = document.getElementById('btn-analyze-threat') as HTMLButtonElement;
  if (analyzeBtn) {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<span>🤖</span> Analyse IA';
  }

  openModal('threat-modal');
};

// Analyze Threat with AI
(window as any).analyzeThreatWithAI = async () => {
  if (!currentThreat) return;

  const aiSection = document.getElementById('ai-analysis-section');
  const aiResult = document.getElementById('threat-ai-result');
  const analyzeBtn = document.getElementById('btn-analyze-threat') as HTMLButtonElement;

  if (aiSection) aiSection.style.display = 'block';
  if (aiResult) aiResult.innerHTML = '<span class="ai-loading">🧠 Analyse en cours...</span>';
  if (analyzeBtn) {
    analyzeBtn.disabled = true;
    analyzeBtn.innerHTML = '<span class="ai-loading">⏳</span> Analyse...';
  }

  // Build analysis prompt - Direct and professional like Python version
  const prompt = `Tu es Illya, analyste cybersécurité de la TSCR. Analyse cette menace:

MENACE: ${currentThreat.title}
TYPE MITRE: ${currentThreat.mitre_id || 'N/A'}
SOURCE: ${currentThreat.source_ip || 'N/A'}
CIBLE: ${currentThreat.target_ip || 'N/A'}
DESCRIPTION: ${currentThreat.description || 'N/A'}

Réponds de façon DIRECTE et CONCISE:
1. **Verdict**: Faux positif probable ? Menace réelle ?
2. **Gravité**: Faible / Moyenne / Critique
3. **Action**: Ignorer / Surveiller / Bloquer immédiatement
4. **Explication**: 2-3 lignes max sur le raisonnement.`;

  try {
    const response = await invoke("ask_ai", { prompt }) as string;
    if (aiResult) aiResult.textContent = response.trim();
    logChat(`IA: Analyse de "${currentThreat.title}" terminée.`, "system");
  } catch (e) {
    if (aiResult) aiResult.textContent = `Erreur d'analyse: ${e}`;
  }

  if (analyzeBtn) {
    analyzeBtn.disabled = false;
    analyzeBtn.innerHTML = '<span>🤖</span> Re-analyser';
  }
};

// Block Threat Source IP
(window as any).blockThreatSource = async () => {
  if (!currentThreat || !currentThreat.source_ip) {
    logChat("Aucune IP source à bloquer.", "system");
    return;
  }

  const ip = currentThreat.source_ip;

  // Find MAC
  let targetMac = "";
  let rawMac = "";
  devices.forEach(d => {
    if (d.ip === ip) {
      targetMac = d.mac.replace(/:/g, '');
      rawMac = d.mac;
    }
  });

  if (targetMac) {
    await (window as any).toggleBlock(ip, targetMac, rawMac);
    (window as any).closeModal('threat-modal');
  } else {
    logChat(`MAC non trouvée pour ${ip}. Impossible de bloquer.`, "system");
    showToast(`❌ Impossible de bloquer ${ip}`);
  }
};

// Store and make alerts clickable
(window as any).registerAlert = (alert: any) => {
  const id = alert.id || `alert-${Date.now()}`;
  alert.id = id;
  alert.timestamp = new Date().toLocaleTimeString();
  alertsStore.set(id, alert);
  return id;
};



// End of new-device listener (no content here to replace lines 1209-1222, just removal)

// Close modals on overlay click
document.addEventListener('click', (e) => {
  const target = e.target as HTMLElement;
  if (target.classList.contains('modal-overlay')) {
    target.style.display = 'none';
  }
});

// Close modals with Escape key
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal-overlay').forEach((modal: any) => {
      modal.style.display = 'none';
    });
  }
});

// ============================================
// THREAT LOG FUNCTIONS
// ============================================

// Status display names
const STATUS_DISPLAY: Record<string, { icon: string; label: string }> = {
  false_positive: { icon: '✅', label: 'Faux Positif' },
  blocked: { icon: '🚫', label: 'Bloqué' },
  watching: { icon: '👁️', label: 'Surveillance' },
  pending: { icon: '⏳', label: 'En attente' },
  resolved: { icon: '✔️', label: 'Résolu' }
};

// Show Threat Log Modal
(window as any).showThreatLog = () => {
  const logList = document.getElementById('threat-log-list');
  if (!logList) return;

  if (threatLog.length === 0) {
    logList.innerHTML = '<div class="threat-log-empty">Aucune menace enregistrée</div>';
  } else {
    logList.innerHTML = threatLog.map(entry => {
      const statusInfo = STATUS_DISPLAY[entry.status] || STATUS_DISPLAY.pending;
      return `
        <div class="threat-log-entry">
          <div class="threat-log-time">${entry.timestamp}</div>
          <div class="threat-log-content">
            <div class="threat-log-title">
              ${entry.title}
              <span class="threat-log-mitre">${entry.mitre_id}</span>
            </div>
            <div class="threat-log-ip">${entry.source_ip}</div>
          </div>
          <div class="threat-log-status ${entry.status}">
            ${statusInfo.icon} ${statusInfo.label}
          </div>
        </div>
      `;
    }).join('');
  }

  // Open modal
  const modal = document.getElementById('threat-log-modal');
  if (modal) modal.style.display = 'flex';
};

// Clear Threat Log
(window as any).clearThreatLog = () => {
  threatLog.length = 0;
  const logList = document.getElementById('threat-log-list');
  if (logList) {
    logList.innerHTML = '<div class="threat-log-empty">Log vidé</div>';
  }
  logChat("📋 Threat Log vidé", "system");
};

// Mark current threat as false positive
(window as any).markFalsePositive = () => {
  if (!currentThreat) return;

  // Update threat log entry if exists
  const entry = threatLog.find(e => e.source_ip === currentThreat.source_ip);
  if (entry) {
    entry.status = 'false_positive';
  }

  logChat(`✅ "${currentThreat.title}" marqué comme Faux Positif`, "system");

  // Decrement Global Threat Counter
  const elThreats = document.getElementById("val-threats");
  if (elThreats) {
    let current = parseInt(elThreats.innerText) || 0;
    if (current > 0) {
      elThreats.innerText = (current - 1).toString();
    }
  }

  (window as any).closeModal('threat-modal');
  showToast('✅ Faux Positif classé');
};

// URL Analysis for Proxy (uses local blacklist, no AI)
(window as any).analyzeProxyUrl = (url: string) => {
  const result = analyzeUrl(url);
  if (result.suspicious) {
    logChat(`⚠️ URL suspecte: ${url} - ${result.reason}`, "system");
    showToast(`⚠️ ${result.reason}`);

    // Add to threat log
    addToThreatLog({
      title: `URL Suspecte: ${new URL(url).hostname}`,
      source_ip: 'Proxy',
      mitre_id: 'T1566',
      action: 'SURVEILLANCE',
      reason: result.reason,
      status: 'watching'
    });
  }
  return result;
};

// ============================================
// ACTION POPUP FUNCTIONS
// ============================================

// Store pending action data
interface PendingAction {
  type: 'BLOCK' | 'BAN';
  ip: string;
  mac?: string;
  rawMac?: string;
  alertId: string;
  aiAnalysis: string;
  threatTitle: string;
  mitreId: string;
}
let pendingAction: PendingAction | null = null;

// Show action popup with AI recommendation
(window as any).showActionPopup = (data: {
  threatTitle: string;
  sourceIp: string;
  mitreId: string;
  aiAnalysis: string;
  solution: string;
  alertId: string;
}) => {
  // Fill popup content
  const titleEl = document.getElementById('action-threat-title');
  const ipEl = document.getElementById('action-threat-ip');
  const mitreEl = document.getElementById('action-threat-mitre');
  const aiEl = document.getElementById('action-ai-analysis');
  const solutionEl = document.getElementById('action-solution-text');

  if (titleEl) titleEl.textContent = data.threatTitle;
  if (ipEl) ipEl.textContent = data.sourceIp;
  if (mitreEl) mitreEl.textContent = data.mitreId;
  if (aiEl) aiEl.textContent = data.aiAnalysis;
  if (solutionEl) solutionEl.textContent = data.solution;

  // Find MAC for this IP
  let targetMac = "";
  let rawMac = "";
  devices.forEach(d => {
    if (d.ip === data.sourceIp) {
      targetMac = d.mac.replace(/:/g, '');
      rawMac = d.mac;
    }
  });

  // Store pending action
  pendingAction = {
    type: 'BLOCK',
    ip: data.sourceIp,
    mac: targetMac,
    rawMac: rawMac,
    alertId: data.alertId,
    aiAnalysis: data.aiAnalysis,
    threatTitle: data.threatTitle,
    mitreId: data.mitreId
  };

  // Show popup
  const popup = document.getElementById('action-popup');
  if (popup) popup.style.display = 'flex';

  // Play alert sound (if available)
  try {
    const audio = new Audio('data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1fdH2Onq2poJSBeGtqcYCPn6mtn5eJfnVwdX6Jl6Kop6CWjIF3cG92gYqVn6OinpqUjIR8d3d4fIKKkpqeoJ+cmZWQi4Z/e3h4fIGHj5WaoJ6dnJmWkYyHgnx4d3l8g4mQlpqcnJqYlpOPioV/eHZ2en6Ej5WZm5uampeTkIqGfnd1dn2EipKXmpuamZeTkIuFf3h2eHqAho+UmJudm5qYlZGNh4J8dnV1eoCGjpOYmpuamZiVko2Hgnx3');
    audio.volume = 0.3;
    audio.play().catch(() => { });
  } catch { }
};

// Apply the recommended action (blocking)
(window as any).applyRecommendedAction = async () => {
  if (!pendingAction) return;

  const { ip, mac, rawMac } = pendingAction;

  if (mac && rawMac) {
    // Execute block
    await (window as any).toggleBlock(ip, mac, rawMac);
    logChat(`🛡️ IP ${ip} bloquée avec succès`, "system");
    showToast(`🛡️ ${ip} bloqué`);

    // Update threat log
    const entry = threatLog.find(e => e.source_ip === ip);
    if (entry) entry.status = 'blocked';
  } else {
    logChat(`⚠️ Impossible de bloquer ${ip} - MAC introuvable`, "system");
    showToast(`⚠️ MAC introuvable pour ${ip}`);
  }

  // Close popup
  (window as any).closeModal('action-popup');
  pendingAction = null;
};

// Ignore the recommended action
(window as any).ignoreAction = () => {
  if (pendingAction) {
    logChat(`ℹ️ Action ignorée pour ${pendingAction.ip}`, "system");

    // Update status to watching
    const entry = threatLog.find(e => e.source_ip === pendingAction!.ip);
    if (entry) entry.status = 'watching';
  }

  (window as any).closeModal('action-popup');
  pendingAction = null;
};

// ============================================
// NETWORK MAPPER - Canvas Visualization
// ============================================

interface MapNode {
  id: string;
  ip: string;
  mac: string;
  x: number;
  y: number;
  type: 'gateway' | 'device' | 'local' | 'threat';
  label: string;
  os?: string;
}

let mapNodes: MapNode[] = [];
let mapAnimationFrame: number | null = null;
// Suppress unused warning if logic is not fully implemented yet
console.log("Map anim frame init:", mapAnimationFrame);

function initNetworkMap() {
  const canvas = document.getElementById('network-map-canvas') as HTMLCanvasElement;
  if (!canvas) return;

  const ctxMaybe = canvas.getContext('2d');
  if (!ctxMaybe) return;
  const ctx = ctxMaybe!;

  // Resize canvas to match container
  function resizeCanvas() {
    const container = canvas.parentElement;
    if (container) {
      canvas.width = container.clientWidth;
      canvas.height = container.clientHeight - 40; // minus header
    }
  }
  resizeCanvas();
  window.addEventListener('resize', resizeCanvas);

  // Build nodes from devices
  function updateNodes() {
    mapNodes = [];
    const centerX = canvas.width / 2;
    const centerY = canvas.height / 2;

    // Add gateway at center
    mapNodes.push({
      id: 'gateway',
      ip: '192.168.1.1',
      mac: 'gateway',
      x: centerX,
      y: centerY,
      type: 'gateway',
      label: 'Gateway'
    });

    // Get local IP
    const localIpEl = document.getElementById('local-ip-display');
    const localIp = localIpEl?.innerText.replace('Local IP: ', '') || '';

    // Add devices in a circle around gateway
    const deviceList = Array.from(devices.values());
    const radius = Math.min(canvas.width, canvas.height) * 0.35;

    deviceList.forEach((d, i) => {
      const angle = (i / Math.max(deviceList.length, 1)) * Math.PI * 2 - Math.PI / 2;
      const isLocal = d.ip === localIp;
      const isThreat = threatLog.some(t => t.source_ip === d.ip && t.status === 'blocked');

      mapNodes.push({
        id: d.mac,
        ip: d.ip,
        mac: d.mac,
        x: centerX + Math.cos(angle) * radius,
        y: centerY + Math.sin(angle) * radius,
        type: isLocal ? 'local' : (isThreat ? 'threat' : 'device'),
        label: d.hostname || d.ip,
        os: d.os_guess
      });
    });
  }

  // Draw the map
  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    // Draw grid background
    ctx.strokeStyle = 'rgba(0, 204, 255, 0.05)';
    ctx.lineWidth = 1;
    for (let x = 0; x < canvas.width; x += 30) {
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, canvas.height);
      ctx.stroke();
    }
    for (let y = 0; y < canvas.height; y += 30) {
      ctx.beginPath();
      ctx.moveTo(0, y);
      ctx.lineTo(canvas.width, y);
      ctx.stroke();
    }

    const gateway = mapNodes.find(n => n.type === 'gateway');
    if (!gateway) return;

    // Draw connections (lines from devices to gateway)
    mapNodes.forEach(node => {
      if (node.type === 'gateway') return;

      ctx.beginPath();
      ctx.strokeStyle = node.type === 'threat' ? 'rgba(255, 50, 50, 0.4)' : 'rgba(0, 204, 255, 0.2)';
      ctx.lineWidth = 1;
      ctx.moveTo(gateway.x, gateway.y);
      ctx.lineTo(node.x, node.y);
      ctx.stroke();

      // Animated pulse along line
      const time = Date.now() / 1000;
      const pulsePos = (time * 0.5 + parseInt(node.id.replace(/:/g, ''), 16) * 0.001) % 1;
      const pulseX = gateway.x + (node.x - gateway.x) * pulsePos;
      const pulseY = gateway.y + (node.y - gateway.y) * pulsePos;

      ctx.beginPath();
      ctx.arc(pulseX, pulseY, 2, 0, Math.PI * 2);
      ctx.fillStyle = node.type === 'threat' ? '#ff5555' : '#00ccff';
      ctx.fill();
    });

    // Draw nodes
    mapNodes.forEach(node => {
      const radius = node.type === 'gateway' ? 25 : 15;

      // Glow
      const gradient = ctx.createRadialGradient(node.x, node.y, 0, node.x, node.y, radius * 2);
      const color = node.type === 'gateway' ? '#ffd700' :
        node.type === 'local' ? '#00ff41' :
          node.type === 'threat' ? '#ff3333' : '#00ccff';
      gradient.addColorStop(0, color + '60');
      gradient.addColorStop(1, 'transparent');
      ctx.fillStyle = gradient;
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius * 2, 0, Math.PI * 2);
      ctx.fill();

      // Node circle
      ctx.beginPath();
      ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();
      ctx.strokeStyle = '#fff';
      ctx.lineWidth = 2;
      ctx.stroke();

      // Icon
      ctx.fillStyle = '#000';
      ctx.font = `${radius}px Arial`;
      ctx.textAlign = 'center';
      ctx.textBaseline = 'middle';
      const icon = node.type === 'gateway' ? '🌐' :
        node.type === 'local' ? '💻' :
          node.type === 'threat' ? '⚠️' : '📱';
      ctx.fillText(icon, node.x, node.y);

      // Label
      ctx.fillStyle = '#aaa';
      ctx.font = '10px Consolas';
      ctx.fillText(node.ip, node.x, node.y + radius + 12);
    });

    mapAnimationFrame = requestAnimationFrame(draw);
  }

  // Mouse interaction
  canvas.addEventListener('click', (e) => {
    const rect = canvas.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;

    // Find clicked node
    const clicked = mapNodes.find(n => {
      const radius = n.type === 'gateway' ? 25 : 15;
      return Math.hypot(n.x - x, n.y - y) < radius;
    });

    const popup = document.getElementById('node-info-popup');
    const content = document.getElementById('popup-content');

    if (clicked && popup && content) {
      content.innerHTML = `
        <div class="popup-row"><span class="popup-label">IP:</span> <span class="popup-value">${clicked.ip}</span></div>
        <div class="popup-row"><span class="popup-label">MAC:</span> <span class="popup-value">${clicked.mac}</span></div>
        <div class="popup-row"><span class="popup-label">Type:</span> <span class="popup-value">${clicked.type}</span></div>
        ${clicked.os ? `<div class="popup-row"><span class="popup-label">OS:</span> <span class="popup-value">${clicked.os}</span></div>` : ''}
      `;
      popup.style.display = 'block';
      popup.style.left = `${Math.min(x + 20, canvas.width - 220)}px`;
      popup.style.top = `${Math.min(y, canvas.height - 100)}px`;
    } else if (popup) {
      popup.style.display = 'none';
    }
  });

  // Refresh button
  document.getElementById('btn-refresh-map')?.addEventListener('click', () => {
    updateNodes();
  });

  // Center button
  document.getElementById('btn-center-map')?.addEventListener('click', () => {
    updateNodes();
  });

  // Start
  updateNodes();
  draw();

  // Export updateNodes for external calls
  (window as any).refreshNetworkMap = updateNodes;
}

// Initialize map when view is shown
document.getElementById('nav-map')?.addEventListener('click', () => {
  setTimeout(initNetworkMap, 100);
});

// Also initialize if map view is already visible on load
setTimeout(() => {
  const mapView = document.getElementById('view-map');
  if (mapView && mapView.style.display !== 'none') {
    initNetworkMap();
  }
}, 500);

