# 🛡️ Sentinel NIDS v2.0

<p align="center">
  <strong>A Professional Passive Network Intrusion Detection, Reconnaissance & Ethical Hacking Toolkit</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg?style=flat-square" alt="Version 2.0.0" />
  <img src="https://img.shields.io/badge/python-3.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-brightgreen.svg?style=flat-square" alt="Python Version" />
  <img src="https://img.shields.io/badge/mode-Passive%20Sniffer-success.svg?style=flat-square" alt="Mode Passive" />
  <img src="https://img.shields.io/badge/license-MIT-green.svg?style=flat-square" alt="License MIT" />
  <img src="https://img.shields.io/badge/framework-MITRE%20ATT%26CK%20Mapped-orange.svg?style=flat-square" alt="MITRE ATT&CK" />
</p>

---

## 📌 Overview

**Sentinel NIDS** is a lightweight, high-performance, **passive** Network Intrusion Detection System (NIDS) and Network Intelligence Toolkit built in Python with Scapy, SQLite (WAL mode), Flask-SocketIO, and Rich.

It silently observes network traffic without injecting aggressive packets or degrading bandwidth, builds real-time asset inventories, fingerprints operating systems, tracks TCP sessions, flags known attack tools and cleartext credential leaks, and presents findings in a **live WebSocket browser dashboard** or an **automated HTML pentest report**.

> ⚠️ **Ethical & Defensive Use Only**: Monitor only networks, hosts, and traffic you own or are explicitly authorized to assess. Sentinel NIDS operates in strictly passive mode — it does not alter routing tables, spoof traffic, disconnect devices, or alter firewalls.

---

## ✨ Key Capabilities

### 1. 🕵️ Passive Network Reconnaissance (Silent Asset Discovery)
* **Zero-Touch Host Discovery**: Discovers every communicating IP and MAC on the segment without active ping sweeps.
* **Passive OS Fingerprinting**: Infers operating systems (Linux, Windows, Android, Cisco/Network) using packet IP TTL heuristics.
* **Service & Open Port Mapping**: Detects active listeners and open ports strictly from intercepted TCP `SYN-ACK` handshakes.
* **Banner Grabbing**: Passively extracts HTTP `Server` headers, SSH version banners, and DHCP hostnames.

### 2. ⚔️ Attack Signature & Exploit Detection
* **Nmap Scan Detection**: Flags signature scanning methods including **XMAS**, **NULL**, **FIN**, and aggressive OS detection probes.
* **Man-in-the-Middle (MITM)**: Flags gratuitous ARP reply storms and duplicate rogue DHCP offers.
* **Brute-Force Attacks**: Tracks rapid connection churn and HTTP 401 Unauthorized response storms per target.
* **C2 Malware Beaconing**: Computes inter-arrival intervals and jitter standard deviation to detect periodic outbound malware callbacks.
* **SYN Floods & DoS**: Tracks initial SYN vs. ACK completion ratios within configurable sliding windows.
* **DNS Tunneling / Data Exfiltration**: Scores queries based on Shannon entropy, label length, rate, and unusual record types (`TXT`/`NULL`).
* **Traffic Anomalies**: Rolling Z-score anomaly detector that learns baseline packet rates and flags persistent deviations.

### 3. 🔑 Cleartext Credential Sniffing
* Detects unencrypted authentication attempts across **HTTP Basic Auth**, **FTP**, **Telnet**, **SMTP AUTH**, and default **SNMP** community strings (`public`/`private`).
* **Privacy by Design**: Logs the protocol, target, and username for security auditing, but **never logs raw passwords**.

### 4. 📊 Real-Time Operations & Reporting
* **Live WebSocket Dashboard**: Real-time push notifications via Flask-SocketIO with interactive Chart.js visualizations.
* **Full TCP Session Tracker**: Tracks bidirectional connection state machines (`SYN_SENT` ➔ `ESTABLISHED` ➔ `CLOSED`/`TIMEOUT`) with TLS SNI and HTTP Host correlation.
* **1-Click Pentest Reports**: Exports comprehensive, printable **HTML, Markdown, or JSON** security reports with findings mapped directly to **MITRE ATT&CK** techniques.
* **Webhook & CLI Notifications**: Instant Slack/Discord webhook alerts and terminal bell notifications.

---

## 🏛️ Architecture

```
                       Live Network Traffic (or Replay PCAP)
                                        │
                                        ▼
                             Bounded Packet Queue (20,000)
                                        │
                                 Worker Thread
                                        │
                                [ Packet Parser ]
                     (IP / TCP / UDP / ICMP / HTTP / TLS / DHCP)
                                        │
         ┌──────────────────────────────┼──────────────────────────────┐
         ▼                              ▼                              ▼
 [ Passive Recon ]             [ Session Tracker ]            [ Detection Engine ]
 - Host Discovery              - TCP State Machine            - Heuristic Detectors
 - TTL OS Guessing             - TLS SNI / HTTP Host          - Attack Signatures (Nmap, C2)
 - Service & Banners           - Idle Timeout Eviction        - Credential Sniffer
         │                              │                              │
         └──────────────────────────────┼──────────────────────────────┘
                                        │
                             Asynchronous DB Writer
                                        │
                                        ▼
                            SQLite Database (WAL Mode)
                                        │
             ┌──────────────────────────┴──────────────────────────┐
             ▼                                                     ▼
     Rich Terminal CLI                                   Real-Time Web Dashboard
 (Hosts / Sessions / Reports)                           (WebSocket / Chart.js / REST)
```

---

## 🚀 Installation

### Prerequisites
* **Python 3.9+**
* **Windows**: [Npcap](https://npcap.com/#download) (install with *"WinPcap API-compatible Mode"* enabled)
* **Linux/macOS**: `libpcap` (`sudo apt install libpcap-dev` or `brew install libpcap`)

### Setup

```bash
# 1. Clone the repository
git clone https://github.com/tarunharitas/netisyour.git
cd netisyour

# 2. Create and activate a virtual environment
python -m venv .venv
# On Windows PowerShell:
.\.venv\Scripts\Activate.ps1
# On Linux/macOS:
source .venv/bin/activate

# 3. Upgrade pip and install with development dependencies
python -m pip install --upgrade pip
python -m pip install -e ".[full]"

# 4. Verify test suite
python -m unittest discover -s tests -v
```

---

## ⚡ Quick Start Guide

### 1. Initialize the Database
Creates the SQLite database schema and enables WAL mode:
```bash
sentinel-nids --config config.yaml init-db
```

### 2. Launch the Real-Time Dashboard
Starts the Flask-SocketIO server at `http://127.0.0.1:5000`:
```bash
sentinel-nids --config config.yaml dashboard
```

### 3. Capture Live Traffic (Admin / Sudo required)
In a separate terminal, start capturing packets on your active interface:
```bash
# Windows:
sentinel-nids --config config.yaml monitor --interface "Wi-Fi"

# Linux:
sudo sentinel-nids --config config.yaml monitor --interface "eth0"
```

### 4. Or Replay an Offline PCAP
Analyze existing captures safely offline:
```bash
sentinel-nids --config config.yaml analyze --pcap samples/traffic.pcap
```

---

## 💻 CLI Command Reference

Sentinel NIDS v2.0 features a rich terminal interface with formatted tables, progress indicators, and colored severity panels:

| Command | Description | Example |
|---|---|---|
| `init-db` | Creates database tables and indexes | `sentinel-nids init-db` |
| `monitor` | Captures and analyzes live traffic | `sentinel-nids monitor --interface "Wi-Fi" --count 500` |
| `analyze` | Replays and evaluates an offline PCAP | `sentinel-nids analyze --pcap capture.pcap` |
| `dashboard`| Spins up the real-time WebSocket web UI | `sentinel-nids dashboard` |
| `hosts` | Lists all discovered hosts, guessed OS, and open ports | `sentinel-nids hosts --limit 50` |
| `sessions` | Displays active and completed TCP sessions | `sentinel-nids sessions --state ESTABLISHED` |
| `alerts` | Queries detected security alerts | `sentinel-nids alerts --severity high --status new` |
| `update-alert` | Updates alert investigation state and notes | `sentinel-nids update-alert 12 --status resolved --note "Verified pentest scan"` |
| `report` | Generates a professional pentest assessment report | `sentinel-nids report --format html --output audit.html` |
| `export` | Dumps raw alerts to CSV or JSON | `sentinel-nids export --format json --output alerts.json` |
| `cleanup` | Purges records older than configured retention period | `sentinel-nids cleanup` |

---

## 🎯 Detection Capabilities & MITRE ATT&CK Mapping

Every alert generated includes an explicit severity, confidence rating (0.0 – 1.0), and raw statistical evidence:

| Detection Rule | Category | MITRE ATT&CK Mapping | Description |
|---|---|---|---|
| **ARP Mapping Change** | Spoofing / MITM | T1557 | Existing IP unexpectedly announces a different MAC address |
| **SYN Flood Indicator** | Denial of Service | T1498 | Rapid TCP SYNs with an unusually low 3-way handshake completion ratio |
| **Vertical Port Scan** | Reconnaissance | T1046 | Single source probing multiple distinct ports on one host |
| **Horizontal Port Scan** | Reconnaissance | T1046 | Single source probing a specific port across many distinct subnet hosts |
| **Nmap Scan Indicators** | Reconnaissance | T1046 | Characteristic XMAS (FPU flags), NULL, or FIN scanning probes |
| **Gratuitous ARP Storm** | Credential Access | T1557.002 | Excessive unsolicited ARP replies indicative of cache poisoning |
| **DNS Tunneling** | Exfiltration | T1048 | High Shannon entropy, long subdomain labels, and high query volume |
| **C2 Beaconing Indicator** | Command & Control | T1071 | Outbound connection streams exhibiting low-jitter periodic intervals |
| **Cleartext Credentials** | Credential Access | T1040 | Authentication observed in plain cleartext (HTTP Basic, FTP, Telnet, SNMP) |
| **Traffic Rate Anomaly** | Anomaly / DoS | T1498 | Sustained packet rate deviation exceeding Z-score threshold from baseline |

---

## ⚙️ Configuration (`config.yaml`)

You can tune all detector sensitivities and feature toggles without modifying Python source code:

```yaml
capture:
  interface: "Wi-Fi"
  queue_size: 20000
  stats_interval_seconds: 10

reconnaissance:
  enabled: true
  os_fingerprinting: true
  service_discovery: true

signatures:
  enabled: true
  nmap_detection: true
  c2_beaconing:
    enabled: true
    interval_tolerance: 0.15   # 15% jitter tolerance

credentials:
  enabled: true
  log_usernames: true         # Only logs username, never passwords

notifications:
  enabled: false
  webhook:
    url: "https://hooks.slack.com/services/..."
```

---

## 🔒 Security & Privacy Practices

* **Zero-Payload Storage**: By default, packet bodies are never saved to disk. Only protocol headers and structural metadata are retained.
* **No Password Logging**: Cleartext credential detection inspects packets in memory and records the protocol and target identifier, strictly redacting passwords.
* **Local Binding**: The dashboard binds to `127.0.0.1` by default. Never bind to `0.0.0.0` on untrusted networks without reverse proxy authentication.
* **Pre-Configured `.gitignore`**: Blocks real PCAPs (`*.pcap`), databases (`*.db*`), generated reports, and local keys from being committed.

---

## 📁 Repository Structure

```
netisyour/
├── config.yaml                    # Master runtime configuration
├── pyproject.toml                 # Package definition and dependencies
├── src/
│   └── nids/
│       ├── cli.py                 # Rich terminal interface
│       ├── credentials.py         # Cleartext credential sniffer
│       ├── dashboard.py           # Real-time Flask-SocketIO dashboard
│       ├── database.py            # SQLite engine with WAL mode
│       ├── detectors.py           # Core heuristic detection rules
│       ├── enrichment.py          # Threat intelligence & GeoIP module
│       ├── models.py              # Data structures (PacketRecord, Alert, HostRecord, etc.)
│       ├── notifier.py            # Webhook & terminal alert dispatcher
│       ├── parser.py              # Protocol parser (HTTP, TLS, DHCP, ICMP, DNS)
│       ├── pipeline.py            # Decoupled ingestion & DB writer queue
│       ├── recon.py               # Passive host, OS & service discovery
│       ├── reporter.py            # Pentest report generator (HTML/MD/JSON)
│       ├── sessions.py            # TCP state machine & flow tracker
│       ├── signatures.py          # Attack tool & exploit signature matcher
│       └── templates/             # Modern HTML5 dashboard & report templates
├── tests/                         # Comprehensive unittest suite
└── samples/                       # Sample capture guidelines
```

---

## 📜 License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.
