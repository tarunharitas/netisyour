"""Sentinel NIDS — passive network intrusion detection & ethical hacking toolkit.

v2.0 adds passive reconnaissance, session tracking, signature-based
detection, credential sniffing, threat enrichment, and a real-time dashboard.
"""

__version__ = "2.0.0"

from .models import PacketRecord, Alert, HostRecord, SessionRecord, CredentialRecord
from .parser import parse_packet
from .detectors import DetectionEngine
from .database import Database
from .pipeline import Pipeline
