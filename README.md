# NXG SOC Platform 🛡️

A web-based Security Operations Center (SOC) platform for **IP reputation investigation**, **file hash analysis**, **network traffic analysis**, and **DDoS threshold calculation** — powered by multiple threat intelligence sources.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python) ![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

### 🌐 IP Reputation Investigator
- Bulk IP investigation against **AbuseIPDB**, **VirusTotal**, **AlienVault OTX**, and **ip-api**
- Automatic scoring (0–100) with verdict: `MALICIOUS` / `HIGH RISK` / `SUSPICIOUS` / `CLEAN`
- Manual verdict override per IP
- Filter by verdict, score range, and search by IP
- Export results to **PDF report**

### 🔎 Hash Analysis
- Submit MD5 / SHA-1 / SHA-256 file hashes to **VirusTotal**, **Hybrid Analysis**, **AlienVault OTX**, and **ThreatFox**
- Detection count across AV engines
- Export results to **PDF report**

### 📡 Traffic Analysis
- Upload NetFlow/CSV exported from Anti-DDoS appliances (e.g. FortiDDoS)
- Automatic detection of attack indicators: SYN Flood, HTTP Flood, Amplification, UDP Flood, etc.
- Attack score (0–100) with confidence level
- Auto-investigation of top source IPs using threat intel sources
- Dashboard with filters, verdict override, checkboxes, and selective PDF export

### 🧮 DDoS Threshold Calculator
- Calculate detection thresholds for all 52 attack signatures
- Supports **Host (/32)** and **Network (/24)** scopes
- 4 detection modes: Normal, Normal Plus, Rapid, Smart
- Scales automatically with customer bandwidth (Mbps)
- Export thresholds as CSV

### 📖 Scoring Guide
- Full documentation of scoring logic for IP, Hash, and Traffic analysis
- MITRE ATT&CK technique mapping
- CSV export guide for Anti-DDoS dashboards

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.8+, Flask |
| Frontend | Vanilla HTML/CSS/JS (single file) |
| PDF Reports | ReportLab |
| Threat Intel | AbuseIPDB, VirusTotal, AlienVault OTX, Hybrid Analysis, GreyNoise, ThreatFox |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/maulana2230/NXG-SOC-Platform.git
cd NXG-SOC-Platform
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Configure API keys
```bash
cp config.example.json config.json
```
Edit `config.json` and fill in your API keys:
```json
{
  "ABUSEIPDB_KEY":  "your_key_here",
  "VIRUSTOTAL_KEY": "your_key_here",
  "OTX_KEY":        "your_key_here",
  "HA_KEY":         "your_key_here",
  "GREYNOISE_KEY":  "your_key_here",
  "THREATFOX_KEY":  "your_key_here"
}
```

> **Free API keys:**
> - AbuseIPDB → [abuseipdb.com](https://www.abuseipdb.com/register)
> - VirusTotal → [virustotal.com](https://www.virustotal.com/gui/join-us)
> - AlienVault OTX → [otx.alienvault.com](https://otx.alienvault.com/)
> - Hybrid Analysis → [hybrid-analysis.com](https://www.hybrid-analysis.com/signup)
> - GreyNoise → [greynoise.io](https://www.greynoise.io/plans/community)
> - ThreatFox → [abuse.ch](https://abuse.ch/)

### 4. Run the app

**Windows:**
```
START.bat
```

**Manual:**
```bash
python app.py
```

Then open **http://localhost:5000** in your browser.

---

## CSV Format for Traffic Analysis

The Traffic Analysis module accepts NetFlow-style CSV files with the following columns:

| Column | Required | Description |
|--------|----------|-------------|
| `src_ip` | ✅ | Source IP address |
| `dst_ip` | ✅ | Destination IP address |
| `bytes` | ✅ | Bytes transferred |
| `packets` | ✅ | Packet count |
| `protocol` | ✅ | Protocol (TCP/UDP/ICMP) |
| `dst_port` | Optional | Destination port |
| `tcp_flags` | Optional | TCP flag string |
| `start_time` | Optional | Flow start timestamp |
| `end_time` | Optional | Flow end timestamp |

Export this file from your Anti-DDoS dashboard (e.g. FortiDDoS → Event Traffic → Download icon).

---

## Security

- API keys are stored locally in `config.json` (excluded from git via `.gitignore`)
- No data is sent to any third-party except the configured threat intel APIs
- All investigation runs locally on your machine

---

## License

MIT License — free to use, modify, and distribute.
