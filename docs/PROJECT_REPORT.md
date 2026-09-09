# Sentinel NIDS — Project Report

**Prepared for:** Tarun Sharma
**Version:** 1.0.0
**Technology:** Python, Scapy, SQLite, Flask, YAML

## 1. Overview

Sentinel NIDS is a lightweight, passive Network Intrusion Detection System. It observes authorized live network traffic or processes saved PCAP files, extracts network metadata, applies signature-style and statistical detection rules, stores explainable alerts in SQLite, and presents results in a local Flask dashboard.

**Passive** means the system does not block packets, disconnect Wi-Fi, change router settings, modify IP configuration, or generate attacks. It only observes and analyzes.

## 2. Objectives

- Capture packets from a selected interface or PCAP file.
- Normalize raw packets into a consistent internal record.
- Detect ARP mapping changes, SYN flood indicators, vertical/horizontal scans, suspicious DNS behavior, and unusual traffic rates.
- Assign alert severity, confidence, and supporting evidence.
- Store alerts and time-window traffic statistics in SQLite.
- Provide CLI reporting, CSV/JSON export, and a browser dashboard.

## 3. Architecture

```
Live WiFi / Ethernet     Saved PCAP file
          \                    /
           \                  /
              Packet input
                    │
              Bounded queue
                    │
              Worker threads
                    │
              Packet parser
                    │
              Detection engine
              /              \
   Rule-based detection   Statistical anomaly check
              \              /
             Alert + evidence
                    │
              SQLite database
                    │
              CLI / Flask dashboard
```

The same detection engine services both live traffic and offline PCAP analysis, avoiding duplicated logic and making testing repeatable.

| Step | Component | Result |
|---|---|---|
| 1 | Capture | Receives a packet from an interface or PCAP reader |
| 2 | Queue | Buffers packets, separating capture speed from analysis speed |
| 3 | Worker | Takes packets from the queue for processing |
| 4 | Parser | Extracts IPs, ports, flags, MAC addresses, DNS fields, and size |
| 5 | Detector | Updates sliding-window state and checks suspicious patterns |
| 6 | Storage | Saves alerts and aggregate traffic statistics |
| 7 | Dashboard | Reads the database and supports alert review |

## 4. Detection modules

### 4.1 ARP mapping change
Remembers the first observed IP→MAC mapping (or a configured trusted mapping). A later conflicting MAC produces `ARP_MAPPING_CHANGED`. This is an indicator, not proof — DHCP reassignment, device replacement, virtualization, or gateway failover can be legitimate causes.

### 4.2 SYN flood indicator
Tracks initial SYNs and ACK-based completion indicators per source inside a sliding window (default: 10s window, 100+ SYNs, <20% completion ratio). This is a useful educational handshake-completion heuristic, not a full production TCP state machine.

### 4.3 Vertical / horizontal port scans
Counts unique destination ports per host (vertical) and unique destination hosts per port (horizontal) from one source within a time window.

### 4.4 DNS tunneling indicator
Combines several weak signals — long first label, high entropy, high query rate, high name uniqueness, unusual query type — into one score, alerting only once the combined score crosses a threshold. Allowlisted domains are skipped.

### 4.5 Statistical traffic anomaly
Learns a packet-rate baseline (mean/std) from initial windows, then computes a z-score for later windows. An alert fires only after the deviation persists for a configured number of consecutive windows.

## 5. Alerts, database, dashboard

Every detector returns a common `Alert` shape: timestamp, alert_type, severity, confidence, source/destination, description, evidence (JSON), rule_name, status and note. Alert workflow: `new → investigating → resolved | false_positive | ignored`.

SQLite (`nids.db`) stores alerts and traffic-window statistics with parameterized queries and indexes on time/status/severity/type. A `cleanup` command removes data past the configured retention period.

The Flask dashboard runs at `http://127.0.0.1:5000`, showing total/new alert counts, severity breakdown, and recent alert details, with filtering and status/notes editing.

**Why the dashboard can show zero:** it counts security alerts, not captured packets. 100 successfully processed normal packets can correctly produce zero alerts — the pipeline worked and no configured pattern was found.

## 6. Testing

Automated `unittest` tests validate:

| Area | What is checked |
|---|---|
| ARP | First mapping accepted; conflicting mapping alerts |
| SYN | Completed connections suppress a false flood alert |
| Scans | Unique-port threshold produces a vertical scan indicator |
| DNS | Combined suspicious features reach the alert score |
| Database | Alert creation, retrieval, and status updates work |
| Anomaly | A strong packet-rate deviation produces an alert |
| Parser | Constructed TCP/DNS packets normalize correctly |

Run with: `python -m unittest discover -s tests -v`

## 7. Limitations

- Detects and reports; does not block traffic.
- Encrypted traffic limits application-layer visibility.
- A host on a switched network mostly sees traffic addressed to it plus broadcast/multicast.
- NAT may combine multiple users behind one source address.
- Legitimate DHCP changes, failover, telemetry, backups, and authorized scanners can resemble attacks.
- Scapy/Python capture is not guaranteed lossless on high-throughput links.
- The anomaly model is a single overall baseline, not per-host.
- The dashboard has no multi-user authentication.

## 8. Future scope

- Authenticated dashboard with role-based access
- Production WSGI deployment and TLS
- Full TCP state tracking and retransmission handling
- Per-host baselines and richer anomaly features
- Public-suffix-aware DNS parent-domain extraction
- Dedicated ICMPv6 / Neighbor Discovery rules
- PostgreSQL and distributed sensors
- Threat-intelligence enrichment and labeled-dataset evaluation

## 9. Viva preparation

**30-second explanation:** Sentinel NIDS is a lightweight passive network intrusion and anomaly detection system built with Python, Scapy, SQLite, and Flask. It captures authorized live traffic or reads PCAP files, extracts packet metadata, and applies stateful rules for ARP mapping changes, SYN flood indicators, port scans, suspicious DNS behavior, and packet-rate anomalies. Alerts include severity, confidence, and evidence, stored in SQLite and shown through a local dashboard.

| Question | Short answer |
|---|---|
| NIDS vs firewall? | NIDS observes and alerts; a firewall enforces allow/block rules. |
| Why zero alerts? | Traffic was processed but no configured pattern crossed a threshold. |
| Why a queue? | Separates packet capture from slower parsing/detection/storage. |
| What's a false positive? | Legitimate activity that matches a suspicious pattern. |
| Benefit of PCAP mode? | Repeatable, safer offline testing using the same detector engine. |
| Why SQLite? | Lightweight local storage, no separate server required. |
| Why localhost dashboard? | Avoids exposing an unauthenticated dev server to the network. |
| Any ML used? | A rolling statistical z-score model; full ML intentionally skipped for the MVP. |
