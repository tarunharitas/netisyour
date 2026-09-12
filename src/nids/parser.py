"""Converts raw Scapy packets into normalized PacketRecord objects.

Kept isolated from capture and detection logic so it can be unit-tested with
hand-built packets, and so the same parsing code is used for both live
capture and offline PCAP analysis.
"""

from __future__ import annotations

import time
import hashlib
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
        Raw,
        DHCP,
        BOOTP,
    )
    
    # Optional layers in scapy
    try:
        from scapy.layers.http import HTTPRequest, HTTPResponse
    except ImportError:
        HTTPRequest = HTTPResponse = None
        
    try:
        from scapy.layers.tls.all import TLS, TLSClientHello
        from scapy.layers.tls.extensions import TLS_Ext_ServerName
    except ImportError:
        TLS = TLSClientHello = TLS_Ext_ServerName = None
        
except Exception:  # pragma: no cover - scapy should always be installed
    Ether = IP = IPv6 = TCP = UDP = ICMP = ARP = DNS = DNSQR = Raw = DHCP = BOOTP = None
    HTTPRequest = HTTPResponse = None
    TLS = TLSClientHello = TLS_Ext_ServerName = None


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


def _calculate_ja3(tls_hello) -> Optional[str]:
    try:
        version = str(tls_hello.version) if hasattr(tls_hello, "version") else ""
        ciphers = ""
        if hasattr(tls_hello, "ciphers"):
            ciphers = "-".join(str(c) for c in tls_hello.ciphers)
        exts = ""
        if hasattr(tls_hello, "ext"):
            exts = "-".join(str(e.type) for e in tls_hello.ext)
        curves = ""
        ec_pf = ""
        if hasattr(tls_hello, "ext"):
            for e in tls_hello.ext:
                if getattr(e, "type", None) == 10:
                    if hasattr(e, "groups"):
                        curves = "-".join(str(g) for g in e.groups)
                elif getattr(e, "type", None) == 11:
                    if hasattr(e, "formats"):
                        ec_pf = "-".join(str(f) for f in e.formats)
        ja3_string = f"{version},{ciphers},{exts},{curves},{ec_pf}"
        return hashlib.md5(ja3_string.encode()).hexdigest()
    except Exception:
        return None


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
        record.ip_ttl = getattr(ip_layer, "ttl", None)
        record.ip_id = getattr(ip_layer, "id", None)
    elif IPv6 is not None and pkt.haslayer(IPv6):
        ip_layer = pkt[IPv6]
        record.ip_ttl = getattr(ip_layer, "hlim", None)

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
        icmp = pkt[ICMP]
        record.icmp_type = getattr(icmp, "type", None)
        record.icmp_code = getattr(icmp, "code", None)
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

    if DHCP is not None and pkt.haslayer(DHCP):
        try:
            dhcp = pkt[DHCP]
            for opt in getattr(dhcp, "options", []):
                if isinstance(opt, tuple):
                    if opt[0] == "hostname":
                        record.dhcp_hostname = opt[1].decode("utf-8", errors="ignore") if isinstance(opt[1], bytes) else str(opt[1])
                    elif opt[0] == "vendor_class_id":
                        record.dhcp_vendor_class = opt[1].decode("utf-8", errors="ignore") if isinstance(opt[1], bytes) else str(opt[1])
                    elif opt[0] == "requested_addr":
                        record.dhcp_requested_ip = str(opt[1])
                    elif opt[0] == "message-type":
                        msg_types = {1: "discover", 2: "offer", 3: "request", 4: "decline", 5: "ack", 6: "nak", 7: "release", 8: "inform"}
                        record.dhcp_message_type = msg_types.get(opt[1], str(opt[1]))
        except Exception:
            pass

    if Raw is not None and pkt.haslayer(Raw):
        record.has_payload = True
        try:
            raw_data = pkt[Raw].load
            printable = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_data)
            record.payload_preview = printable[:64]
            
            if record.dst_port == 80 or record.src_port == 80:
                text_data = raw_data.decode("utf-8", errors="ignore")
                lines = text_data.split("\r\n")
                if len(lines) > 0:
                    first_line = lines[0]
                    if first_line.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ")):
                        parts = first_line.split(" ")
                        if len(parts) >= 2:
                            record.http_method = parts[0]
                            record.http_path = parts[1]
                        for line in lines[1:]:
                            if line.lower().startswith("host: "):
                                record.http_host = line[6:].strip()
                            elif line.lower().startswith("user-agent: "):
                                record.http_user_agent = line[12:].strip()
                            elif line.lower().startswith("authorization: "):
                                auth_val = line[15:].strip()
                                record.http_authorization = auth_val.split(" ")[0] if " " in auth_val else auth_val
                    elif first_line.startswith("HTTP/"):
                        parts = first_line.split(" ")
                        if len(parts) >= 2 and parts[1].isdigit():
                            record.http_status_code = int(parts[1])
                        for line in lines[1:]:
                            if line.lower().startswith("server: "):
                                record.http_server = line[8:].strip()
                            elif line.lower().startswith("content-type: "):
                                record.http_content_type = line[14:].strip()
        except Exception:
            pass

    if HTTPRequest is not None and pkt.haslayer(HTTPRequest):
        try:
            http_req = pkt[HTTPRequest]
            record.http_method = getattr(http_req, "Method", b"").decode("utf-8", errors="ignore") or record.http_method
            record.http_path = getattr(http_req, "Path", b"").decode("utf-8", errors="ignore") or record.http_path
            record.http_host = getattr(http_req, "Host", b"").decode("utf-8", errors="ignore") or record.http_host
            record.http_user_agent = getattr(http_req, "User_Agent", b"").decode("utf-8", errors="ignore") or record.http_user_agent
            auth_val = getattr(http_req, "Authorization", b"").decode("utf-8", errors="ignore")
            if auth_val:
                record.http_authorization = auth_val.split(" ")[0] if " " in auth_val else auth_val
        except Exception:
            pass
            
    if HTTPResponse is not None and pkt.haslayer(HTTPResponse):
        try:
            http_res = pkt[HTTPResponse]
            status_code = getattr(http_res, "Status_Code", b"").decode("utf-8", errors="ignore")
            if status_code.isdigit():
                record.http_status_code = int(status_code)
            record.http_server = getattr(http_res, "Server", b"").decode("utf-8", errors="ignore") or record.http_server
            record.http_content_type = getattr(http_res, "Content_Type", b"").decode("utf-8", errors="ignore") or record.http_content_type
        except Exception:
            pass

    if TLSClientHello is not None and pkt.haslayer(TLSClientHello):
        try:
            tls_hello = pkt[TLSClientHello]
            record.tls_version = str(getattr(tls_hello, "version", None))
            record.tls_ja3 = _calculate_ja3(tls_hello)
            
            if hasattr(tls_hello, "ext"):
                for ext in tls_hello.ext:
                    if TLS_Ext_ServerName is not None and isinstance(ext, TLS_Ext_ServerName):
                        if hasattr(ext, "servernames") and len(ext.servernames) > 0:
                            sn = ext.servernames[0]
                            if hasattr(sn, "servername"):
                                record.tls_sni = sn.servername.decode("utf-8", errors="ignore") if isinstance(sn.servername, bytes) else str(sn.servername)
        except Exception:
            pass

    return record
