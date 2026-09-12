"""Core data structures shared across the capture, detection and storage layers.

v2.0 extends the original PacketRecord and Alert with host inventory,
session tracking, credential detection, and threat enrichment models.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class PacketRecord:
    """A normalized, protocol-agnostic view of a single captured packet.

    Only metadata is kept -- no payload bytes are stored, in line with the
    project's privacy design (see docs/PROJECT_REPORT.md).

    v2.0 adds HTTP, TLS, DHCP and ICMP metadata fields.
    """

    timestamp: float = field(default_factory=time.time)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None  # "TCP", "UDP", "ICMP", "ARP", "DNS", "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # e.g. "S", "SA", "A", "FA"
    packet_size: int = 0
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    arp_op: Optional[str] = None  # "who-has" / "is-at"
    arp_sender_ip: Optional[str] = None
    arp_target_ip: Optional[str] = None

    # -- v2.0 extensions ------------------------------------------------
    # HTTP metadata (cleartext only)
    http_host: Optional[str] = None
    http_method: Optional[str] = None
    http_path: Optional[str] = None
    http_user_agent: Optional[str] = None
    http_server: Optional[str] = None
    http_status_code: Optional[int] = None
    http_content_type: Optional[str] = None
    http_authorization: Optional[str] = None  # auth type only, e.g. "Basic"

    # TLS metadata
    tls_sni: Optional[str] = None
    tls_version: Optional[str] = None
    tls_ja3: Optional[str] = None  # JA3 fingerprint hash
    tls_ja3s: Optional[str] = None  # JA3S (server) fingerprint hash

    # DHCP metadata
    dhcp_hostname: Optional[str] = None
    dhcp_vendor_class: Optional[str] = None
    dhcp_requested_ip: Optional[str] = None
    dhcp_message_type: Optional[str] = None

    # ICMP metadata
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # IPv6 Neighbor Discovery
    ndp_type: Optional[str] = None  # "ns" / "na" / "rs" / "ra"

    # IP-layer metadata
    ip_ttl: Optional[int] = None
    ip_id: Optional[int] = None

    # Raw payload indicators (never stores actual payload)
    has_payload: bool = False
    payload_preview: Optional[str] = None  # first 64 chars of cleartext, if applicable

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """A standardized, explainable detection result.

    Every detector returns this shape so alerts can be stored, displayed and
    exported consistently regardless of which rule produced them.

    v2.0 adds MITRE ATT&CK mapping and alert deduplication counter.
    """

    alert_type: str
    severity: str  # "low" | "medium" | "high" | "critical"
    confidence: float  # 0.0 - 1.0
    rule_name: str
    description: str
    evidence: dict = field(default_factory=dict)
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    timestamp: float = field(default_factory=time.time)
    status: str = "new"  # new -> investigating -> resolved | false_positive | ignored
    note: Optional[str] = None
    id: Optional[int] = None

    # -- v2.0 extensions ------------------------------------------------
    mitre_tactic: Optional[str] = None  # e.g. "Reconnaissance"
    mitre_technique: Optional[str] = None  # e.g. "T1046 Network Service Scanning"
    count: int = 1  # deduplication: how many times this alert has fired
    geo_src: Optional[str] = None  # e.g. "US" or "United States"
    geo_dst: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)

    def evidence_json(self) -> str:
        return json.dumps(self.evidence, default=str)


@dataclass
class HostRecord:
    """A discovered network host, built passively from observed traffic.

    The recon module updates these records as it sees new packets from or to
    a given IP address.
    """

    ip: str
    mac: Optional[str] = None
    hostname: Optional[str] = None  # from DHCP, DNS PTR, NetBIOS
    os_guess: Optional[str] = None  # from TTL heuristic
    ttl: Optional[int] = None
    vendor: Optional[str] = None  # from DHCP vendor class or OUI
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    packet_count: int = 0
    byte_count: int = 0
    open_ports: List[int] = field(default_factory=list)  # ports seen in SYN-ACKs
    services: Dict[int, str] = field(default_factory=dict)  # port -> service name
    banners: Dict[int, str] = field(default_factory=dict)  # port -> banner text
    geo_country: Optional[str] = None
    geo_asn: Optional[str] = None
    is_local: bool = True  # True if RFC1918/link-local

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class SessionRecord:
    """A tracked TCP session from SYN to FIN/RST or timeout.

    The session tracker maintains these in memory and flushes completed or
    timed-out sessions to the database.
    """

    session_id: str  # f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    state: str = "SYN_SENT"  # SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED, RESET, TIMEOUT
    started: float = field(default_factory=time.time)
    ended: Optional[float] = None
    packets_sent: int = 0
    packets_recv: int = 0
    bytes_sent: int = 0
    bytes_recv: int = 0
    http_host: Optional[str] = None
    tls_sni: Optional[str] = None
    tls_ja3: Optional[str] = None
    service: Optional[str] = None  # guessed service name
    id: Optional[int] = None

    @property
    def duration(self) -> Optional[float]:
        if self.ended is not None:
            return self.ended - self.started
        return None

    def to_dict(self) -> dict:
        d = asdict(self)
        d["duration"] = self.duration
        return d


@dataclass
class CredentialRecord:
    """A cleartext credential observation — logs type and username, NEVER password."""

    protocol: str  # "http_basic", "ftp", "telnet", "smtp", "pop3", "imap", "snmp"
    src_ip: str
    dst_ip: str
    dst_port: int
    username: Optional[str] = None  # only if config.credentials.log_usernames is true
    timestamp: float = field(default_factory=time.time)
    description: str = ""
    id: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)
