# DeepSide - Autonomous Cybersecurity Sentinel

DeepSide is a powerful network surveillance and cybersecurity tool built with **Tauri**, **Rust**, and **Vanilla TypeScript**. It features **ILLYA**, an integrated AI engine (Local ONNX) designed to analyze threats and recommend security actions directly on the user's machine.

## Summary
- [Description](#description)
- [Features](#features)
- [Intelligence Tools](#intelligence-tools)
- [AI Engine (Illya)](#ai-engine-illya)
- [Structure-Project](#structure-project)
- [Installation](#installation)
- [Technologies used](#technologies-used)
- [Authors](#authors)

---

## Description
DeepSide is designed as a "Sentinel" for local networks. It combines low-level packet sniffing (via Rust's `pcap`) with high-level AI analysis. The application identifies every device on the network, monitors traffic in real-time, and detects potential threats like ARP spoofing or suspicious reconnaissance. 

Unlike most security tools, DeepSide processes all sensitive data locally using an embedded ONNX runtime, ensuring that network patterns and captured data never leave your infrastructure unless explicitly requested (e.g., for VirusTotal checks).

---

## Features
* **Real-time Sniffing**: Capture and analyze packets as they flow through the network.
* **Device Discovery**: Automated mapping of all connected devices with MAC/IP resolution.
* **Threat Detection**: Heuristic and AI-driven detection of malicious activities.
* **Network Policing**: Capabilities for ARP spoofing protection and device isolation.
* **Reporting**: Generate detailed security audits in PDF format.

---

## Intelligence Tools
DeepSide integrates with industry-standard intelligence feeds for enhanced context:

| Tool | Purpose |
| --- | --- |
| **VirusTotal** | Scans IPs and domains against 70+ antivirus engines. |
| **Shodan** | Provides context on open ports and services for external IPs. |
| **AbuseIPDB** | Checks for reported malicious activity from global contributors. |
| **Whois** | Retrieves domain and network ownership information. |

---

## AI Engine (Illya)
**Illya** is the brain of DeepSide. It operates as a local inference engine using the **ONNX Runtime**.

### 1. The Inference Loop
* **Initialization**: Loads the ONNX model and tokenizer from the local resources.
* **Processing**: Tokenizes natural language prompts or network alerts.
* **Analysis**: Runs greedy decoding inference to generate technical recommendations.
* **Mitigation**: Outputs specific commands (e.g., `CMD:BLOCK`) that the Rust backend can execute.

### 2. Multi-threaded Safety
The AI engine is managed via a dedicated thread with an expanded stack size (10MB) to handle the complex memory requirements of large language models on Windows.

---

## Structure-project
```
DeepSide/
├── .env                # API Keys (VT, Shodan, etc.)
├── .gitignore          # Protected files configuration
├── README.md           # Documentation
├── src/                # Frontend (TypeScript/HTML)
│   ├── main.ts
│   └── components/
└── src-tauri/          # Backend (Rust)
    ├── src/
    │   ├── ai/         # Illya Engine (ONNX)
    │   ├── core/       # Sniffing, Tools, Config
    │   └── data/       # Persistence
    ├── resources/      # AI Models and GeoIP DB
    └── Cargo.toml
```     

---

## Installation

### 1. Prerequisites
* **Operating System**: Windows (Npcap required) or Linux.
* **Development Environment**: [Rust stable](https://www.rust-lang.org/), [Node.js LTS](https://nodejs.org/).

### 2. Setup Procedure
Clone the repository and enter the directory:
```bash
git clone https://github.com/Loic2888/DeepSide.git
cd DeepSide
```

Initialize your API keys (copy and fill):
```bash
cp .env.example .env
```

Install Node dependencies:
```bash
npm install
```

### 3. Run the Sentinel
Start in development mode:
```bash
npm run tauri dev
```

---

## Technologies Used

<div align="left">
  <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/rust/rust-original.svg\" height=\"40\" alt=\"rust logo\" />
  <img width=\"12\" />
  <img src=\"https://cdn.jsdelivr.net/gh/devicons/devicon/icons/typescript/typescript-original.svg\" height=\"40\" alt=\"typescript logo\" />
  <img width=\"12\" />
  <img src=\"https://cdn.jsdelivr.net/gh/devicons/devicon/icons/html5/html5-original.svg\" height=\"40\" alt=\"html5 logo\" />
  <img width=\"12\" />
  <img src=\"https://raw.githubusercontent.com/tauri-apps/tauri/dev/app-icon.png\" height=\"40\" alt=\"tauri logo\" />
  <img width=\"12\" />
  <img src=\"https://onnxruntime.ai/images/logo.png\" height=\"40\" alt=\"onnx logo\" />
</div>

---

## Authors

- [**Loïc Cerqueira**](https://github.com/Loic2888)
