"""Signature-based detection for known attack tools."""

from typing import List, Optional, Deque, Dict, Tuple
from collections import defaultdict, deque
import time

from .models import Alert, PacketRecord
from .detectors import _CooldownMixin

class NmapDetector(_CooldownMixin):
    """Detects Nmap scans (XMAS, NULL, FIN, OS fingerprinting)."""
    
    def __init__(self, enabled: bool = True, cooldown_seconds: float = 30.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP":
            return None
            
        flags = pkt.tcp_flags or ""
        scan_type = None
        evidence = {"tcp_flags": flags}
        
        if "F" in flags and "P" in flags and "U" in flags:
            scan_type = "XMAS Scan"
        elif not flags:
            scan_type = "NULL Scan"
        elif flags == "F":
            scan_type = "FIN Scan"
        elif ("S" in flags and "F" in flags) or ("S" in flags and "U" in flags and "P" in flags):
            scan_type = "OS Fingerprinting"

        if scan_type:
            if self._ready(f"{pkt.src_ip}->{pkt.dst_ip}:{scan_type}", pkt.timestamp):
                return Alert(
                    alert_type="NMAP_SCAN_INDICATOR",
                    severity="high",
                    confidence=0.8,
                    rule_name="nmap_signature",
                    description=f"Detected Nmap {scan_type} from {pkt.src_ip} to {pkt.dst_ip}.",
                    evidence=evidence,
                    src_ip=pkt.src_ip,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    timestamp=pkt.timestamp,
                    mitre_tactic="Reconnaissance",
                    mitre_technique="T1046 Network Service Discovery"
                )
        return None

class MitmDetector(_CooldownMixin):
    """Detects MITM attacks (Gratuitous ARP storms, Duplicate DHCP, LLMNR/mDNS poisoning)."""
    
    def __init__(self, enabled: bool = True, arp_window_seconds: float = 10.0, arp_threshold: int = 5,
                 cooldown_seconds: float = 30.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.arp_window_seconds = arp_window_seconds
        self.arp_threshold = arp_threshold
        self._arp_replies: Dict[str, Deque[float]] = defaultdict(deque)
        self._dhcp_offers: Dict[str, set] = defaultdict(set)

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled:
            return None
            
        now = pkt.timestamp
        
        if pkt.protocol == "ARP" and pkt.arp_op == "is-at":
            ip = pkt.arp_sender_ip
            if ip:
                dq = self._arp_replies[ip]
                dq.append(now)
                while dq and (now - dq[0]) > self.arp_window_seconds:
                    dq.popleft()
                    
                if len(dq) >= self.arp_threshold:
                    if self._ready(f"arp_storm:{ip}", now):
                        return Alert(
                            alert_type="GRATUITOUS_ARP_STORM",
                            severity="high",
                            confidence=0.8,
                            rule_name="arp_storm",
                            description=f"Gratuitous ARP storm from {ip} ({len(dq)} replies in {self.arp_window_seconds}s).",
                            evidence={"replies": len(dq), "window_seconds": self.arp_window_seconds},
                            src_ip=ip,
                            timestamp=now,
                            mitre_tactic="Credential Access",
                            mitre_technique="T1557.002 ARP Cache Poisoning"
                        )
                        
        if pkt.dhcp_message_type == "OFFER" and pkt.dhcp_requested_ip and pkt.src_ip:
            servers = self._dhcp_offers[pkt.dhcp_requested_ip]
            servers.add(pkt.src_ip)
            if len(servers) > 1:
                if self._ready(f"dhcp_spoof:{pkt.dhcp_requested_ip}", now):
                    return Alert(
                        alert_type="DHCP_SPOOFING_INDICATOR",
                        severity="high",
                        confidence=0.9,
                        rule_name="dhcp_spoofing",
                        description=f"Multiple DHCP offers for IP {pkt.dhcp_requested_ip} from servers: {', '.join(servers)}.",
                        evidence={"servers": list(servers), "requested_ip": pkt.dhcp_requested_ip},
                        timestamp=now,
                        mitre_tactic="Credential Access",
                        mitre_technique="T1557.002 ARP Cache Poisoning"
                    )
            
        return None

class BruteForceDetector(_CooldownMixin):
    """Detects repeated connection attempts or HTTP 401s."""
    
    def __init__(self, enabled: bool = True, window_seconds: float = 60.0, threshold: int = 10,
                 cooldown_seconds: float = 60.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.window_seconds = window_seconds
        self.threshold = threshold
        self._attempts: Dict[Tuple[str, str, int], Deque[float]] = defaultdict(deque)

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled:
            return None
            
        if pkt.protocol != "TCP" or not pkt.src_ip or not pkt.dst_ip or pkt.dst_port is None:
            return None
            
        now = pkt.timestamp
        is_attempt = False
        
        if pkt.tcp_flags == "S":
            is_attempt = True
        elif pkt.http_status_code == 401:
            is_attempt = True
            
        if is_attempt:
            key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port)
            dq = self._attempts[key]
            dq.append(now)
            while dq and (now - dq[0]) > self.window_seconds:
                dq.popleft()
                
            if len(dq) >= self.threshold:
                if self._ready(f"bruteforce:{key}", now):
                    return Alert(
                        alert_type="BRUTE_FORCE_INDICATOR",
                        severity="high",
                        confidence=0.8,
                        rule_name="brute_force",
                        description=f"Brute force indicator: {len(dq)} attempts from {pkt.src_ip} to {pkt.dst_ip}:{pkt.dst_port} in {self.window_seconds}s.",
                        evidence={"attempts": len(dq), "window_seconds": self.window_seconds},
                        src_ip=pkt.src_ip,
                        dst_ip=pkt.dst_ip,
                        dst_port=pkt.dst_port,
                        timestamp=now,
                        mitre_tactic="Credential Access",
                        mitre_technique="T1110 Brute Force"
                    )
        return None

class C2BeaconingDetector(_CooldownMixin):
    """Detects periodic outbound connections."""
    
    def __init__(self, enabled: bool = True, min_connections: int = 10,
                 cooldown_seconds: float = 300.0):
        super().__init__(cooldown_seconds)
        self.enabled = enabled
        self.min_connections = min_connections
        self._connections: Dict[Tuple[str, str], List[float]] = defaultdict(list)

    def process(self, pkt: PacketRecord) -> Optional[Alert]:
        if not self.enabled or pkt.protocol != "TCP" or pkt.tcp_flags != "S":
            return None
            
        if not pkt.src_ip or not pkt.dst_ip:
            return None
            
        now = pkt.timestamp
        key = (pkt.src_ip, pkt.dst_ip)
        conn_list = self._connections[key]
        conn_list.append(now)
        
        if len(conn_list) > self.min_connections * 2:
            conn_list = conn_list[-self.min_connections * 2:]
            self._connections[key] = conn_list
            
        if len(conn_list) >= self.min_connections:
            intervals = [conn_list[i] - conn_list[i-1] for i in range(1, len(conn_list))]
            mean = sum(intervals) / len(intervals)
            if mean > 0:
                variance = sum((x - mean) ** 2 for x in intervals) / len(intervals)
                std = variance ** 0.5
                regularity = std / mean
                
                if regularity < 0.1:
                    if self._ready(f"c2:{key}", now):
                        return Alert(
                            alert_type="C2_BEACONING_INDICATOR",
                            severity="high",
                            confidence=0.85,
                            rule_name="c2_beaconing",
                            description=f"Suspected C2 beaconing from {pkt.src_ip} to {pkt.dst_ip} (interval: {mean:.2f}s, jitter: {regularity:.2f}).",
                            evidence={"mean_interval": mean, "regularity": regularity, "connections": len(conn_list)},
                            src_ip=pkt.src_ip,
                            dst_ip=pkt.dst_ip,
                            timestamp=now,
                            mitre_tactic="Command and Control",
                            mitre_technique="T1071 Application Layer Protocol"
                        )
        return None
