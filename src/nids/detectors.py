"""Detection modules.

Each detector keeps short-term, in-memory state (sliding windows / counters)
and emits a standardized Alert only when its configured thresholds are
crossed. Cooldowns prevent the same detector from spamming duplicate alerts
for an ongoing condition.

These are intentionally explainable, threshold-based detectors rather than a
black-box model: every alert carries the evidence that triggered it.
"""

from __future__ import annotations

import math
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from .models import Alert, PacketRecord


def _entropy(s: str) -> float:
    """Shannon entropy of a string, in bits per character."""
    if not s:
        return 0.0
    freq: Dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    ent = 0.0
    for count in freq.values():
        p = count / n
        ent -= p * math.log2(p)
    return ent


class _CooldownMixin:
    """Shared cooldown bookkeeping so a detector doesn't re-fire every packet."""

    def __init__(self, cooldown_seconds: float):
        self.cooldown_seconds = cooldown_seconds
        self._last_fired: Dict[str, float] = {}

    def _ready(self, key: str, now: float) -> bool:
        last = self._last_fired.get(key)
        if last is None or (now - last) >= self.cooldown_seconds:
            self._last_fired[key] = now
            return True
        return False


class ArpDetector(_CooldownMixin):
    """Flags an IP address that suddenly maps to a different MAC address.

    A mapping change is an indicator, not proof of an attack -- DHCP
    reassignment, device replacement, virtualization or gateway failover can
    all be legitimate causes. Trusted mappings from config are seeded up
    front and never alert unless they actually change.
    """

    def __init__(self, enabled: bool = True, trusted: Optional[Dict[str, str]] = None,
                 cooldown_seconds: float = 30.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.known: Dict[str, str] = dict(trusted or {})

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "ARP":
            return None
        ip = pkt.arp_sender_ip
        mac = pkt.src_mac
        if not ip or not mac:
            return None

        previous = self.known.get(ip)
        if previous is None:
            self.known[ip] = mac
            return None

        if previous.lower() != mac.lower():
            if not self._ready(ip, pkt.timestamp):
                self.known[ip] = mac
                return None
            evidence = {"previous_mac": previous, "new_mac": mac}
            self.known[ip] = mac
            return Alert(
                alert_type="ARP_MAPPING_CHANGED",
                severity="medium",
                confidence=0.6,
                rule_name="arp_mapping_change",
                description=f"IP {ip} changed from MAC {previous} to {mac}.",
                evidence=evidence,
                src_ip=ip,
                timestamp=pkt.timestamp,
            )
        return None


class SynFloodDetector(_CooldownMixin):
    """Flags a source IP sending many SYNs with a low completion ratio.

    A normal TCP connection begins SYN -> SYN-ACK -> ACK. This tracks initial
    SYNs and completion (ACK) indicators per source inside a sliding window.
    This is an educational handshake-completion heuristic, not a full TCP
    state machine.
    """

    def __init__(self, enabled: bool = True, window_seconds: float = 10.0,
                 syn_threshold: int = 100, completion_ratio_threshold: float = 0.2,
                 cooldown_seconds: float = 30.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.syn_threshold = syn_threshold
        self.completion_ratio_threshold = completion_ratio_threshold
        self._syn_events: Dict[str, Deque[float]] = defaultdict(deque)
        self._ack_events: Dict[str, Deque[float]] = defaultdict(deque)

    def _trim(self, dq: Deque[float], now: float) -> None:
        while dq and (now - dq[0]) > self.window_seconds:
            dq.popleft()

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP" or not pkt.src_ip:
            return None

        now = pkt.timestamp
        flags = pkt.tcp_flags or ""

        if flags == "S":
            dq = self._syn_events[pkt.src_ip]
            dq.append(now)
            self._trim(dq, now)
        elif "A" in flags:
            dq = self._ack_events[pkt.src_ip]
            dq.append(now)
            self._trim(dq, now)
        else:
            return None

        syn_count = len(self._syn_events.get(pkt.src_ip, []))
        if syn_count < self.syn_threshold:
            return None

        ack_count = len(self._ack_events.get(pkt.src_ip, []))
        completion_ratio = ack_count / syn_count if syn_count else 0.0
        if completion_ratio >= self.completion_ratio_threshold:
            return None

        if not self._ready(pkt.src_ip, now):
            return None

        evidence = {
            "syn_count": syn_count,
            "ack_count": ack_count,
            "completion_ratio": round(completion_ratio, 3),
            "window_seconds": self.window_seconds,
        }
        return Alert(
            alert_type="SYN_FLOOD_INDICATOR",
            severity="high",
            confidence=0.7,
            rule_name="syn_flood_indicator",
            description=(
                f"{pkt.src_ip} sent {syn_count} SYNs in {self.window_seconds:.0f}s "
                f"with only {completion_ratio:.0%} completion."
            ),
            evidence=evidence,
            src_ip=pkt.src_ip,
            timestamp=now,
        )


class PortScanDetector(_CooldownMixin):
    """Flags vertical scans (many ports, one host) and horizontal scans (one
    port, many hosts) from a single source within a time window.
    """

    def __init__(self, enabled: bool = True, window_seconds: float = 10.0,
                 vertical_unique_ports: int = 15, horizontal_unique_hosts: int = 15,
                 cooldown_seconds: float = 30.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.vertical_unique_ports = vertical_unique_ports
        self.horizontal_unique_hosts = horizontal_unique_hosts
        # src_ip -> deque[(timestamp, dst_ip, dst_port)]
        self._events: Dict[str, Deque[Tuple[float, str, int]]] = defaultdict(deque)

    def _trim(self, dq: Deque[Tuple[float, str, int]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()

    def process(self, pkt: PacketRecord) -> List[Alert]:
        alerts: List[Alert] = []
        if not self.enabled or pkt.protocol != "TCP" or pkt.tcp_flags != "S":
            return alerts
        if not pkt.src_ip or not pkt.dst_ip or pkt.dst_port is None:
            return alerts

        now = pkt.timestamp
        dq = self._events[pkt.src_ip]
        dq.append((now, pkt.dst_ip, pkt.dst_port))
        self._trim(dq, now)

        ports_by_host: Dict[str, set] = defaultdict(set)
        hosts_by_port: Dict[int, set] = defaultdict(set)
        for _, dip, dport in dq:
            ports_by_host[dip].add(dport)
            hosts_by_port[dport].add(dip)

        for dip, ports in ports_by_host.items():
            if len(ports) >= self.vertical_unique_ports:
                key = f"v:{pkt.src_ip}->{dip}"
                if self._ready(key, now):
                    alerts.append(Alert(
                        alert_type="VERTICAL_PORT_SCAN_INDICATOR",
                        severity="medium",
                        confidence=0.65,
                        rule_name="vertical_port_scan",
                        description=(
                            f"{pkt.src_ip} probed {len(ports)} unique ports on {dip} "
                            f"within {self.window_seconds:.0f}s."
                        ),
                        evidence={"unique_ports": len(ports), "window_seconds": self.window_seconds},
                        src_ip=pkt.src_ip,
                        dst_ip=dip,
                        timestamp=now,
                    ))

        for dport, hosts in hosts_by_port.items():
            if len(hosts) >= self.horizontal_unique_hosts:
                key = f"h:{pkt.src_ip}->{dport}"
                if self._ready(key, now):
                    alerts.append(Alert(
                        alert_type="HORIZONTAL_PORT_SCAN_INDICATOR",
                        severity="medium",
                        confidence=0.65,
                        rule_name="horizontal_port_scan",
                        description=(
                            f"{pkt.src_ip} probed port {dport} across {len(hosts)} unique hosts "
                            f"within {self.window_seconds:.0f}s."
                        ),
                        evidence={"unique_hosts": len(hosts), "dst_port": dport,
                                  "window_seconds": self.window_seconds},
                        src_ip=pkt.src_ip,
                        dst_port=dport,
                        timestamp=now,
                    ))

        return alerts


class DnsTunnelingDetector(_CooldownMixin):
    """Combines several weak DNS signals into a single suspicion score.

    No single feature (length, entropy, rate, uniqueness, query type) is
    treated as proof on its own -- tunneling is only flagged when the
    combined score crosses the configured threshold. Allowlisted domains are
    skipped entirely.
    """

    def __init__(self, enabled: bool = True, window_seconds: float = 30.0,
                 long_label_length: int = 30, entropy_threshold: float = 3.5,
                 rate_threshold: int = 30, uniqueness_ratio_threshold: float = 0.8,
                 unusual_qtypes: Optional[List[str]] = None,
                 score_threshold: int = 6, allowlist: Optional[List[str]] = None,
                 cooldown_seconds: float = 60.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.long_label_length = long_label_length
        self.entropy_threshold = entropy_threshold
        self.rate_threshold = rate_threshold
        self.uniqueness_ratio_threshold = uniqueness_ratio_threshold
        self.unusual_qtypes = set(q.upper() for q in (unusual_qtypes or ["TXT", "NULL"]))
        self.score_threshold = score_threshold
        self.allowlist = set(d.lower().rstrip(".") for d in (allowlist or []))
        # parent_domain -> deque[(timestamp, full_query, qtype)]
        self._events: Dict[str, Deque[Tuple[float, str, str]]] = defaultdict(deque)

    @staticmethod
    def _parent_domain(query: str) -> str:
        parts = query.strip(".").split(".")
        if len(parts) <= 2:
            return query.lower()
        return ".".join(parts[-2:]).lower()

    def _is_allowlisted(self, parent: str) -> bool:
        return parent in self.allowlist

    def _trim(self, dq: Deque[Tuple[float, str, str]], now: float) -> None:
        while dq and (now - dq[0][0]) > self.window_seconds:
            dq.popleft()

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled or not pkt.dns_query:
            return None

        query = pkt.dns_query
        parent = self._parent_domain(query)
        if self._is_allowlisted(parent):
            return None

        now = pkt.timestamp
        dq = self._events[parent]
        dq.append((now, query, pkt.dns_qtype or ""))
        self._trim(dq, now)

        first_label = query.split(".")[0] if query else ""
        score = 0
        reasons = []

        if len(first_label) >= self.long_label_length:
            score += 2
            reasons.append("long_first_label")

        ent = _entropy(first_label)
        if ent >= self.entropy_threshold:
            score += 2
            reasons.append("high_entropy")

        rate = len(dq)
        if rate >= self.rate_threshold:
            score += 2
            reasons.append("high_query_rate")

        unique_queries = len(set(q for _, q, _ in dq))
        uniqueness_ratio = unique_queries / rate if rate else 0.0
        if rate >= 5 and uniqueness_ratio >= self.uniqueness_ratio_threshold:
            score += 2
            reasons.append("high_uniqueness")

        if (pkt.dns_qtype or "").upper() in self.unusual_qtypes:
            score += 1
            reasons.append("unusual_qtype")

        if score < self.score_threshold:
            return None
        if not self._ready(parent, now):
            return None

        evidence = {
            "parent_domain": parent,
            "score": score,
            "reasons": reasons,
            "entropy": round(ent, 2),
            "rate_in_window": rate,
            "uniqueness_ratio": round(uniqueness_ratio, 2),
            "window_seconds": self.window_seconds,
            "sample_query": query,
        }
        return Alert(
            alert_type="DNS_TUNNELING_INDICATOR",
            severity="medium",
            confidence=min(0.5 + 0.05 * score, 0.95),
            rule_name="dns_tunneling_indicator",
            description=(
                f"Suspicious DNS pattern for *.{parent} (score {score}): {', '.join(reasons)}."
            ),
            evidence=evidence,
            timestamp=now,
        )


class StatisticalAnomalyDetector(_CooldownMixin):
    """Learns a baseline packet rate, then flags sustained deviations.

    The baseline mean/std is learned from the first `learning_windows`
    windows. After that, each window's z-score is computed; an alert fires
    only once the deviation has persisted for `persistence_windows` in a row,
    which reduces one-off noise.
    """

    def __init__(self, enabled: bool = True, window_seconds: float = 10.0,
                 learning_windows: int = 6, z_score_threshold: float = 3.0,
                 persistence_windows: int = 2, cooldown_seconds: float = 60.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.learning_windows = learning_windows
        self.z_score_threshold = z_score_threshold
        self.persistence_windows = persistence_windows

        self._window_start: Optional[float] = None
        self._count_in_window = 0
        self._history: List[float] = []
        self._consecutive_deviations = 0

    def _finalize_window(self, now: float) -> Optional[Alert]:
        rate = self._count_in_window
        self._history.append(rate)
        self._count_in_window = 0
        self._window_start = now

        if len(self._history) <= self.learning_windows:
            return None

        baseline = self._history[-(self.learning_windows + 1):-1]
        mean = sum(baseline) / len(baseline)
        variance = sum((x - mean) ** 2 for x in baseline) / len(baseline)
        std = math.sqrt(variance)
        if std == 0:
            return None

        z = (rate - mean) / std
        if abs(z) >= self.z_score_threshold:
            self._consecutive_deviations += 1
        else:
            self._consecutive_deviations = 0
            return None

        if self._consecutive_deviations < self.persistence_windows:
            return None
        if not self._ready("global", now):
            return None

        evidence = {
            "current_rate": rate,
            "baseline_mean": round(mean, 2),
            "baseline_std": round(std, 2),
            "z_score": round(z, 2),
            "window_seconds": self.window_seconds,
            "consecutive_windows": self._consecutive_deviations,
        }
        return Alert(
            alert_type="TRAFFIC_RATE_ANOMALY",
            severity="low" if abs(z) < self.z_score_threshold * 1.5 else "medium",
            confidence=min(0.4 + 0.1 * abs(z), 0.9),
            rule_name="statistical_traffic_anomaly",
            description=(
                f"Packet rate deviated {z:.2f} standard deviations from baseline "
                f"for {self._consecutive_deviations} consecutive window(s)."
            ),
            evidence=evidence,
            timestamp=now,
        )

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled:
            return None
        now = pkt.timestamp
        if self._window_start is None:
            self._window_start = now

        alert = None
        if (now - self._window_start) >= self.window_seconds:
            alert = self._finalize_window(now)

        self._count_in_window += 1
        return alert


class DetectionEngine:
    """Runs every configured detector against each packet and collects alerts.

    Constructed once from the parsed config and reused for both live capture
    and PCAP analysis, so behavior is identical in both modes.
    """

    def __init__(self, config: dict):
        arp_cfg = config.get("arp", {})
        syn_cfg = config.get("syn_flood", {})
        scan_cfg = config.get("port_scan", {})
        dns_cfg = config.get("dns", {})
        anomaly_cfg = config.get("anomaly", {})

        self.arp = ArpDetector(
            enabled=arp_cfg.get("enabled", True),
            trusted=arp_cfg.get("trusted_mappings", {}),
            cooldown_seconds=arp_cfg.get("cooldown_seconds", 30),
        )
        self.syn_flood = SynFloodDetector(
            enabled=syn_cfg.get("enabled", True),
            window_seconds=syn_cfg.get("window_seconds", 10),
            syn_threshold=syn_cfg.get("syn_threshold", 100),
            completion_ratio_threshold=syn_cfg.get("completion_ratio_threshold", 0.2),
            cooldown_seconds=syn_cfg.get("cooldown_seconds", 30),
        )
        self.port_scan = PortScanDetector(
            enabled=scan_cfg.get("enabled", True),
            window_seconds=scan_cfg.get("window_seconds", 10),
            vertical_unique_ports=scan_cfg.get("vertical_unique_ports", 15),
            horizontal_unique_hosts=scan_cfg.get("horizontal_unique_hosts", 15),
            cooldown_seconds=scan_cfg.get("cooldown_seconds", 30),
        )
        self.dns_tunneling = DnsTunnelingDetector(
            enabled=dns_cfg.get("enabled", True),
            window_seconds=dns_cfg.get("window_seconds", 30),
            long_label_length=dns_cfg.get("long_label_length", 30),
            entropy_threshold=dns_cfg.get("entropy_threshold", 3.5),
            rate_threshold=dns_cfg.get("rate_threshold", 30),
            uniqueness_ratio_threshold=dns_cfg.get("uniqueness_ratio_threshold", 0.8),
            unusual_qtypes=dns_cfg.get("unusual_qtypes", ["TXT", "NULL"]),
            score_threshold=dns_cfg.get("score_threshold", 6),
            allowlist=dns_cfg.get("allowlist", []),
            cooldown_seconds=dns_cfg.get("cooldown_seconds", 60),
        )
        self.anomaly = StatisticalAnomalyDetector(
            enabled=anomaly_cfg.get("enabled", True),
            window_seconds=anomaly_cfg.get("window_seconds", 10),
            learning_windows=anomaly_cfg.get("learning_windows", 6),
            z_score_threshold=anomaly_cfg.get("z_score_threshold", 3.0),
            persistence_windows=anomaly_cfg.get("persistence_windows", 2),
            cooldown_seconds=anomaly_cfg.get("cooldown_seconds", 60),
        )

    def process(self, pkt: PacketRecord) -> List[Alert]:
        alerts: List[Alert] = []

        a = self.arp.process(pkt)
        if a:
            alerts.append(a)

        a = self.syn_flood.process(pkt)
        if a:
            alerts.append(a)

        alerts.extend(self.port_scan.process(pkt))

        a = self.dns_tunneling.process(pkt)
        if a:
            alerts.append(a)

        a = self.anomaly.process(pkt)
        if a:
            alerts.append(a)

        return alerts
