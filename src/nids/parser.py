"""Converts raw Scapy packets into normalized PacketRecord objects.

Kept isolated from capture and detection logic so it can be unit-tested with
hand-built packets, and so the same parsing code is used for both live
capture and offline PCAP analysis.
"""

from __future__ import annotations

import time
from typing import Optional

from .models import PacketRecord

try:
    from scapy.all import (
        Ether,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        ARP,
        DNS,
        DNSQR,
    )
except Exception:  # pragma: no cover - scapy should always be installed
    Ether = IP = IPv6 = TCP = UDP = ICMP = ARP = DNS = DNSQR = None


# Human-readable TCP flag decoding, matches Scapy's own flag characters.
_TCP_FLAG_ORDER = "FSRPAUECN"


def _tcp_flags_str(flags: int) -> str:
    """Render a Scapy TCP flags field as a short string like 'SA' or 'S'."""
    try:
        bits = int(flags)
    except (TypeError, ValueError):
        return ""
    out = []
    for i, ch in enumerate(_TCP_FLAG_ORDER):
        if bits & (1 << i):
            out.append(ch)
    return "".join(out)


def _dns_qtype_name(qtype: int) -> str:
    mapping = {
        1: "A",
        2: "NS",
        5: "CNAME",
        6: "SOA",
        12: "PTR",
        15: "MX",
        16: "TXT",
        28: "AAAA",
        33: "SRV",
        255: "ANY",
    }
    return mapping.get(int(qtype), str(qtype))


def parse_packet(pkt, capture_time: Optional[float] = None) -> PacketRecord:
    """Parse a single Scapy packet into a PacketRecord.

    Any field that cannot be determined is left as None so downstream
    detectors can decide how to handle missing data.
    """
    timestamp = capture_time
    if timestamp is None:
        packet_time = getattr(pkt, "time", None)
        try:
            timestamp = float(packet_time) if packet_time is not None else time.time()
        except (TypeError, ValueError):
            timestamp = time.time()
    record = PacketRecord(timestamp=timestamp)

    try:
        record.packet_size = len(bytes(pkt))
    except Exception:
        record.packet_size = 0

    if Ether is not None and pkt.haslayer(Ether):
        eth = pkt[Ether]
        record.src_mac = getattr(eth, "src", None)
        record.dst_mac = getattr(eth, "dst", None)

    if ARP is not None and pkt.haslayer(ARP):
        arp = pkt[ARP]
        record.protocol = "ARP"
        record.arp_op = "is-at" if getattr(arp, "op", None) == 2 else "who-has"
        record.arp_sender_ip = getattr(arp, "psrc", None)
        record.arp_target_ip = getattr(arp, "pdst", None)
        record.src_ip = getattr(arp, "psrc", None)
        record.dst_ip = getattr(arp, "pdst", None)
        if getattr(arp, "hwsrc", None):
            record.src_mac = arp.hwsrc
        return record

    ip_layer = None
    if IP is not None and pkt.haslayer(IP):
        ip_layer = pkt[IP]
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]

    if ip_layer is not None:
        record.src_ip = getattr(ip_layer, "src", None)
        record.dst_ip = getattr(ip_layer, "dst", None)

    if TCP is not None and pkt.haslayer(TCP):
        tcp = pkt[TCP]
        record.protocol = "TCP"
        record.src_port = int(tcp.sport)
        record.dst_port = int(tcp.dport)
        record.tcp_flags = _tcp_flags_str(tcp.flags)
    elif UDP is not None and pkt.haslayer(UDP):
        udp = pkt[UDP]
        record.protocol = "UDP"
        record.src_port = int(udp.sport)
        record.dst_port = int(udp.dport)
    elif ICMP is not None and pkt.haslayer(ICMP):
        record.protocol = "ICMP"
    elif ip_layer is not None:
        record.protocol = "OTHER"

    if DNS is not None and pkt.haslayer(DNS):
        dns = pkt[DNS]
        if getattr(dns, "qd", None) is not None and pkt.haslayer(DNSQR):
            qname = pkt[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="ignore")
            record.dns_query = qname.rstrip(".") if qname else None
            record.dns_qtype = _dns_qtype_name(pkt[DNSQR].qtype)
        record.protocol = "DNS"

    return record
