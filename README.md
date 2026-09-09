# Sentinel NIDS

A lightweight, **passive** Network Intrusion & Anomaly Detection System built with Python, Scapy, SQLite, and Flask.

> **Defensive and educational use only.** Monitor only devices and networks that you own or are explicitly authorized to inspect. Sentinel NIDS never blocks traffic, disconnects Wi-Fi, changes router settings, or generates attacks — it only observes and analyzes.

## What it does

Sentinel NIDS captures live network traffic (or replays a saved PCAP file), normalizes packets into metadata-only records, runs them through a set of explainable detection rules, stores the resulting alerts in SQLite, and shows them in a local browser dashboard.

Detected patterns:

| Detector | Flags |
|---|---|
| ARP mapping change | An IP suddenly resolving to a different MAC address |
| SYN flood indicator | Many SYNs from one source with a low handshake-completion ratio |
| Vertical port scan | One source hitting many ports on one destination |
| Horizontal port scan | One source hitting the same port across many destinations |
| DNS tunneling indicator | Long/high-entropy/high-rate/highly-unique DNS query patterns |
| Traffic rate anomaly | Sustained packet-rate deviation from a learned baseline (z-score) |

Every alert carries a severity, a confidence score, and the evidence (counts, ratios, entropy, etc.) that triggered it — nothing is a black box.

## Architecture

```
Live interface / PCAP file
          │
          ▼
   Bounded queue ──► Worker threads ──► Parser ──► Detection engine ──► SQLite ──► CLI / Dashboard
```

The same `Pipeline` + `DetectionEngine` code path is used for both live capture and offline PCAP analysis, so behavior is identical and results are repeatable.

## Installation

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e .
python -m unittest discover -s tests -v
```

Live capture requires [Npcap](https://npcap.com/) on Windows (or libpcap on Linux/macOS) and typically Administrator/root privileges.

## Quick start

```bash
sentinel-nids --config config.yaml init-db
sentinel-nids --config config.yaml dashboard
# open http://127.0.0.1:5000
```

In another terminal:

```bash
sentinel-nids --config config.yaml monitor --interface "WiFi" --count 100
```

Or analyze a saved capture instead of live traffic:

```bash
sentinel-nids --config config.yaml analyze --pcap samples/traffic.pcap
```

## Commands

```bash
sentinel-nids --config config.yaml init-db
sentinel-nids --config config.yaml monitor --interface "WiFi" --count 100
sentinel-nids --config config.yaml analyze --pcap samples/traffic.pcap
sentinel-nids --config config.yaml dashboard
sentinel-nids --config config.yaml alerts --limit 50
sentinel-nids --config config.yaml alerts --severity high --status new
sentinel-nids --config config.yaml update-alert 4 --status resolved --note "Reviewed"
sentinel-nids --config config.yaml export --format json --output alerts.json
sentinel-nids --config config.yaml export --format csv --output alerts.csv
sentinel-nids --config config.yaml cleanup
```

## Configuration

All detector thresholds live in `config.yaml` — tune sensitivity without touching Python source. See the comments in that file for every option (window sizes, thresholds, cooldowns, DNS allowlist, dashboard host/port, etc.).

## Why zero alerts is often correct

The dashboard counts **security alerts**, not captured packets. 100 successfully processed normal packets can correctly produce zero alerts — that means the pipeline worked and no configured suspicious pattern was found. A good NIDS should not alert on every packet.

## Limitations

- Detects and reports — it does **not** block traffic.
- Encrypted traffic limits application-layer visibility.
- On a switched network, a single host mostly sees traffic addressed to it plus broadcast/multicast.
- NAT can combine multiple users behind one source address.
- Legitimate DHCP changes, failover, telemetry, backups, and authorized scanners can resemble attacks — alerts are indicators for analyst review, not proof.
- The anomaly model uses one overall packet-rate baseline rather than a separate baseline per host.
- The dashboard is a local development server with no multi-user authentication — keep it bound to `127.0.0.1`.

See `docs/PROJECT_REPORT.md` for the full write-up, and the future-scope list there for planned improvements.

## Project structure

```
src/nids/cli.py          Command definitions: monitor, analyze, dashboard, alerts, export, cleanup
src/nids/pipeline.py     Bounded queue, workers, stats windows, graceful shutdown
src/nids/parser.py       Scapy packet -> normalized PacketRecord
src/nids/detectors.py    ARP, SYN flood, scan, DNS tunneling, statistical anomaly logic
src/nids/models.py       PacketRecord and Alert data structures
src/nids/database.py     SQLite schema, alert queries/updates, export, cleanup
src/nids/dashboard.py    Flask pages and JSON API
config.yaml              Runtime settings and detector thresholds
tests/                   Automated unittest suite
docs/PROJECT_REPORT.md   Presentation-ready short report
samples/README.md        Guidance for sanitized PCAP samples
```

## Security & privacy notes before publishing

- Never commit `nids.db`, real PCAP files, exported alerts, tokens, or credentials.
- Keep `.venv/`, `__pycache__/`, `nids.db`, and `*.pcap(ng)` in `.gitignore` (already set up here).
- Bind the dashboard to `127.0.0.1` unless you deliberately deploy it with authentication.
- Only run this against devices/networks you own or are authorized to test.

## License

MIT — see `LICENSE`.
