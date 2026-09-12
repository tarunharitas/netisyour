"""Passive network reconnaissance module."""

from typing import List, Optional, Dict
import ipaddress

from .models import PacketRecord, HostRecord

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8080: "HTTP-Proxy",
}

class ReconEngine:
    def __init__(self, config: dict):
        self.config = config.get("reconnaissance", {})
        self.hosts: Dict[str, HostRecord] = {}

    def _get_os_guess(self, ttl: int) -> Optional[str]:
        if ttl is None:
            return None
        if abs(ttl - 32) <= 5:
            return "Windows 95/98"
        elif abs(ttl - 64) <= 5:
            return "Linux/macOS/Android"
        elif abs(ttl - 128) <= 5:
            return "Windows"
        elif abs(ttl - 255) <= 5:
            return "Cisco/Network equipment"
        return None

    def _is_local_ip(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return ip.is_private or ip.is_link_local or ip.is_loopback
        except ValueError:
            return False

    def process(self, pkt: PacketRecord) -> Optional[HostRecord]:
        updated = False
        target_ip = pkt.src_ip
        
        if not target_ip:
            return None

        if target_ip not in self.hosts:
            self.hosts[target_ip] = HostRecord(
                ip=target_ip,
                is_local=self._is_local_ip(target_ip)
            )
            updated = True
            
        host = self.hosts[target_ip]
        
        host.last_seen = pkt.timestamp
        host.packet_count += 1
        host.byte_count += pkt.packet_size
        
        if pkt.src_mac and host.mac != pkt.src_mac:
            host.mac = pkt.src_mac
            updated = True
            
        if pkt.ip_ttl is not None and (host.ttl is None or host.ttl != pkt.ip_ttl):
            host.ttl = pkt.ip_ttl
            new_os = self._get_os_guess(pkt.ip_ttl)
            if new_os and host.os_guess != new_os:
                host.os_guess = new_os
                updated = True

        if pkt.protocol == "TCP" and pkt.tcp_flags and "S" in pkt.tcp_flags and "A" in pkt.tcp_flags:
            if pkt.src_port and pkt.src_port not in host.open_ports:
                host.open_ports.append(pkt.src_port)
                if pkt.src_port in COMMON_PORTS:
                    host.services[pkt.src_port] = COMMON_PORTS[pkt.src_port]
                updated = True

        if pkt.src_port in [80, 443] and pkt.http_server:
            if pkt.src_port not in host.banners or host.banners[pkt.src_port] != pkt.http_server:
                host.banners[pkt.src_port] = pkt.http_server
                updated = True
        
        if pkt.has_payload and pkt.payload_preview and pkt.src_port == 22:
            if "SSH-" in pkt.payload_preview:
                banner = pkt.payload_preview.split("\n")[0].strip()
                if pkt.src_port not in host.banners or host.banners[pkt.src_port] != banner:
                    host.banners[pkt.src_port] = banner
                    updated = True

        if pkt.dhcp_hostname and host.hostname != pkt.dhcp_hostname:
            host.hostname = pkt.dhcp_hostname
            updated = True
            
        if pkt.dhcp_vendor_class and host.vendor != pkt.dhcp_vendor_class:
            host.vendor = pkt.dhcp_vendor_class
            updated = True

        if pkt.dst_ip and pkt.dst_ip not in self.hosts:
            self.hosts[pkt.dst_ip] = HostRecord(
                ip=pkt.dst_ip,
                is_local=self._is_local_ip(pkt.dst_ip),
                mac=pkt.dst_mac
            )
            
        return host if updated else None

    def get_hosts(self) -> List[HostRecord]:
        return list(self.hosts.values())

    def get_host(self, ip: str) -> Optional[HostRecord]:
        return self.hosts.get(ip)
