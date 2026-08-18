# NXG SOC Platform 🛡️

A web-based Security Operations Center (SOC) platform for **IP reputation investigation**, **file hash analysis**, **network traffic analysis**, **full-packet PCAP analysis**, and **DDoS threshold calculation** — powered by multiple threat intelligence sources.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python) ![Flask](https://img.shields.io/badge/Flask-3.0-black?logo=flask) ![Docker](https://img.shields.io/badge/Docker-ready-2496ED?logo=docker&logoColor=white) ![License](https://img.shields.io/badge/License-MIT-green)

---

## Features

### 🌐 IP Reputation Investigator
- Bulk IP investigation against **AbuseIPDB**, **VirusTotal**, **AlienVault OTX**, and **ip-api**
- **CIDR input support** — mix bare IPs and prefixes (e.g. `203.0.113.0/24`); prefixes are auto-expanded into host IPs (network/broadcast excluded, capped at 4096 hosts per prefix)
- Concurrent lookups via a worker pool, with built-in **per-API rate limiting** and automatic **failover to backup keys** when a primary key gets rate-limited
- Automatic scoring (0–100) with verdict: `MALICIOUS` / `HIGH RISK` / `SUSPICIOUS` / `CLEAN`
- Manual verdict override per IP
- Filter by verdict, score range, and search by IP
- Export results to **PDF report**

### 🔎 Hash Analysis
- Submit MD5 / SHA-1 / SHA-256 file hashes to **VirusTotal**, **Hybrid Analysis**, **AlienVault OTX**, and **ThreatFox**
- Detection count across AV engines
- Export results to **PDF report**

### 📡 Traffic Analysis
- Upload NetFlow/CSV exported from Anti-DDoS appliances (Nexusguard Platform)
- Automatic detection of attack indicators: SYN Flood, HTTP Flood, Amplification, UDP Flood, etc.
- Attack score (0–100) with confidence level
- Auto-investigation of top source IPs using threat intel sources
- **Traffic Behavior investigation** — profile any IP (single or bulk) against the last analyzed capture: observed traffic profile, protocols/ports, peak bps/pps, and per-IP behavior verdict with bulk *Apply to Selected* and manual override
- **Auto-Mitigation Policy Template** — concrete mitigation values computed from the capture: top block candidates, recommended filter values, delivery cap to target, whitelist offset, and protection-coverage status (`PROTECTED` / `NOT COVERED`); optionally included in the PDF export
- Dashboard with filters, verdict override, checkboxes, and selective PDF export

### 🧬 PCAP Analysis
- Drag & drop **`.pcap` / `.pcapng`** capture files (classic pcap and pcapng, multiple files at once) — parsed by a **pure-Python parser**, no tshark/scapy/Wireshark install required
- Capture summary: total packets/bytes, duration, protocol distribution, and TCP flag distribution
- **Top conversations** (paginated), top source/destination IPs, and top destination ports
- Extraction of **DNS queries** and **plaintext HTTP requests** (method, host, URI, User-Agent)
- Threat-indicator detection with per-IP scoring and verdicts, plus one-click auto-investigation of suspicious sources against threat intel

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
| PCAP Parsing | Pure Python (`struct`), pcap + pcapng |
| Threat Intel | AbuseIPDB, VirusTotal, AlienVault OTX, Hybrid Analysis, GreyNoise, ThreatFox |

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/maulana2230/NXG-SOC-Platform.git
cd NXG-SOC-Platform
```

### 2. Configure API keys
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

> Each source also supports an optional **backup API key** (e.g. a second account) configured later from the in-app Settings page — the app automatically fails over to it if the primary key gets rate-limited.

> ⚠️ `config.json` holds real secrets and is **git-ignored** — never commit it, and never bypass the ignore with `git add -f`. Only `config.example.json` (placeholders) belongs in the repo.

### 3. Run the app

Pick one of the two options below.

#### Option A — Run with Python directly
```bash
pip install -r requirements.txt
python app.py
```
**Windows shortcut:** double-click `START.bat` (installs dependencies and starts the server for you).

#### Option B — Run with Docker (recommended for servers/deployment)
Requires [Docker](https://docs.docker.com/get-docker/) and the Docker Compose plugin.

```bash
docker compose up -d --build
```

This builds the image and starts the container in the background, using the `Dockerfile` / `docker-compose.yml` in this repo:
- Runs the app under **Gunicorn** (not the Flask dev server) as a **non-root** user
- `config.json` is **bind-mounted** from the host, not baked into the image — your keys stay on disk, never inside an image layer
- The container's root filesystem is **read-only** and Linux capabilities are dropped (`cap_drop: ALL`)
- The port is published as `127.0.0.1:5000:5000` — **loopback only**. The app has no built-in authentication, so put a reverse proxy (nginx/Caddy) with TLS + auth in front of it before exposing it beyond your own machine.

Useful commands:
```bash
docker compose logs -f        # follow logs
docker compose ps             # check container + health status
docker compose down           # stop and remove the container
docker compose up -d --build  # rebuild after pulling code updates
```

Either way, once it's running, open **http://localhost:5000** in your browser.

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

Export this file from your Anti-DDoS dashboard (e.g. Nexusguard → Event Traffic → Download icon).

The analyzed capture is cached in memory, so the **Traffic Behavior** investigator can profile additional IPs against it at any time without re-uploading.

---

## Security

- API keys are stored locally in `config.json` (excluded from git via `.gitignore`)
- No data is sent to any third-party except the configured threat intel APIs
- All investigation runs locally on your machine

---

## License

MIT License — free to use, modify, and distribute.
