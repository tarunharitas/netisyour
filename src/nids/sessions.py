"""TCP session state machine."""

from typing import List, Dict, Optional
import time

from .models import PacketRecord, SessionRecord
from .recon import COMMON_PORTS

class SessionTracker:
    def __init__(self, config: dict):
        cfg = config.get("sessions", {})
        self.max_sessions = cfg.get("max_sessions", 10000)
        self.timeout_seconds = cfg.get("timeout_seconds", 300)
        self.sessions: Dict[str, SessionRecord] = {}

    def _get_session_id(self, pkt: PacketRecord) -> Optional[str]:
        if not pkt.src_ip or not pkt.dst_ip or not pkt.src_port or not pkt.dst_port:
            return None
            
        end1 = (pkt.src_ip, pkt.src_port)
        end2 = (pkt.dst_ip, pkt.dst_port)
        
        if end1 < end2:
            return f"{end1[0]}:{end1[1]}->{end2[0]}:{end2[1]}"
        else:
            return f"{end2[0]}:{end2[1]}->{end1[0]}:{end1[1]}"

    def process(self, pkt: PacketRecord) -> List[SessionRecord]:
        completed_sessions = []
        
        if pkt.protocol != "TCP":
            return completed_sessions
            
        session_id = self._get_session_id(pkt)
        if not session_id:
            return completed_sessions
            
        flags = pkt.tcp_flags or ""
        
        if session_id not in self.sessions:
            if "S" in flags and "A" not in flags:
                if len(self.sessions) >= self.max_sessions:
                    expired = self.cleanup_expired()
                    completed_sessions.extend(expired)
                    if len(self.sessions) >= self.max_sessions:
                        return completed_sessions 
                        
                service_port = min(pkt.src_port, pkt.dst_port)
                
                new_session = SessionRecord(
                    session_id=session_id,
                    src_ip=pkt.src_ip,
                    src_port=pkt.src_port,
                    dst_ip=pkt.dst_ip,
                    dst_port=pkt.dst_port,
                    state="SYN_SENT",
                    started=pkt.timestamp,
                    service=COMMON_PORTS.get(service_port)
                )
                new_session._last_seen = pkt.timestamp
                self.sessions[session_id] = new_session
            else:
                return completed_sessions
                
        session = self.sessions[session_id]
        session._last_seen = pkt.timestamp
        
        if pkt.src_ip == session.src_ip:
            session.packets_sent += 1
            session.bytes_sent += pkt.packet_size
        else:
            session.packets_recv += 1
            session.bytes_recv += pkt.packet_size
            
        if not session.http_host and pkt.http_host:
            session.http_host = pkt.http_host
        if not session.tls_sni and pkt.tls_sni:
            session.tls_sni = pkt.tls_sni
        if not session.tls_ja3 and pkt.tls_ja3:
            session.tls_ja3 = pkt.tls_ja3
            
        if session.state == "SYN_SENT":
            if "S" in flags and "A" in flags:
                session.state = "ESTABLISHED"
        elif session.state == "ESTABLISHED":
            if "F" in flags:
                session.state = "FIN_WAIT"
            elif "R" in flags:
                session.state = "RESET"
                session.ended = pkt.timestamp
                completed_sessions.append(session)
                del self.sessions[session_id]
        elif session.state == "FIN_WAIT":
            if "R" in flags or "F" in flags:
                session.state = "CLOSED"
                session.ended = pkt.timestamp
                completed_sessions.append(session)
                del self.sessions[session_id]
                
        return completed_sessions

    def get_active_sessions(self) -> List[SessionRecord]:
        return list(self.sessions.values())

    def cleanup_expired(self) -> List[SessionRecord]:
        now = time.time()
        expired = []
        to_delete = []
        
        for sid, session in self.sessions.items():
            last = getattr(session, '_last_seen', session.started)
                
            if now - last > self.timeout_seconds:
                session.state = "TIMEOUT"
                session.ended = now
                expired.append(session)
                to_delete.append(sid)
                
        for sid in to_delete:
            del self.sessions[sid]
            
        return expired
