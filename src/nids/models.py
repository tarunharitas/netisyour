"""Core data structures shared across the capture, detection and storage layers."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class PacketRecord:
    """A normalized, protocol-agnostic view of a single captured packet.

    Only metadata is kept -- no payload bytes are stored, in line with the
    project's privacy design (see docs/PROJECT_REPORT.md).
    """

    timestamp: float = field(default_factory=time.time)
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    protocol: Optional[str] = None  # "TCP", "UDP", "ICMP", "ARP", "OTHER"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    tcp_flags: Optional[str] = None  # e.g. "S", "SA", "A", "FA"
    packet_size: int = 0
    dns_query: Optional[str] = None
    dns_qtype: Optional[str] = None
    arp_op: Optional[str] = None  # "who-has" / "is-at"
    arp_sender_ip: Optional[str] = None
    arp_target_ip: Optional[str] = None

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Alert:
    """A standardized, explainable detection result.

    Every detector returns this shape so alerts can be stored, displayed and
    exported consistently regardless of which rule produced them.
    """

    alert_type: str
    severity: str  # "low" | "medium" | "high"
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

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    def evidence_json(self) -> str:
        return json.dumps(self.evidence, default=str)
