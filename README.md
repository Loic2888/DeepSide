# DeepSide - Autonomous Cybersecurity Sentinel

DeepSide is a powerful network surveillance and cybersecurity tool built with **Tauri**, **Rust**, and **Vanilla TypeScript**. It features **ILLYA**, an integrated AI engine (Local ONNX) designed to analyze threats and recommend security actions.

## 🚀 Features

- **Real-time Network Monitoring**: Live sniffing and traffic analysis.
- **ILLYA AI Sentinel**: Local AI processing for threat detection and mitigation recommendations.
- **Security Tools**:
  - Network Scan & Port Scanning
  - DNS & Reverse DNS Lookup
  - SSL Certificate Analysis
  - VirusTotal & Shodan Integration
  - ARP Spoofing Detection/Protection
- **Forensics & Intelligence**: Deep packet inspection and threat database integration.
- **Reporting**: Automated PDF report generation (via `printpdf`).

## 🛠️ Setup

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) (latest stable)
- [Node.js](https://nodejs.org/) (LTS)
- [Npcap](https://npcap.com/) (on Windows, for network sniffing)

### API Configuration
DeepSide uses several external services for enhanced intelligence. 
1. Copy `.env.example` to `.env`.
2. Fill in your API keys for VirusTotal, Shodan, and AbuseIPDB.
3. (Optional) Add your Groq API key for future AI features.

### Development
```bash
# Install dependencies
npm install

# Run in development mode
npm run tauri dev
```

### Build
```bash
npm run tauri build
```

## 🧠 AI Engine (ILLYA)
ILLYA uses a local ONNX model for high-performance, private inference.
- **Model**: ONNX format (placed in `src-tauri/resources/model.onnx`)
- **Tokenizer**: `tokenizer.json`

## ⚖️ License
This project is for educational and authorized testing purposes only.

---
*Built with ❤️ by [Your Pseudo/Name]*
