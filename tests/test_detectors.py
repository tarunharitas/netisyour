import time
import unittest

from nids.detectors import (
    ArpDetector,
    SynFloodDetector,
    PortScanDetector,
    DnsTunnelingDetector,
    StatisticalAnomalyDetector,
)
from nids.models import PacketRecord


def _pkt(**kwargs) -> PacketRecord:
    defaults = dict(timestamp=time.time())
    defaults.update(kwargs)
    return PacketRecord(**defaults)


class TestArpDetector(unittest.TestCase):
    def test_first_mapping_is_accepted(self):
        d = ArpDetector()
        pkt = _pkt(protocol="ARP", arp_sender_ip="192.168.1.10", src_mac="AA:AA:AA:AA:AA:AA")
        self.assertIsNone(d.process(pkt))

    def test_conflicting_mapping_creates_alert(self):
        d = ArpDetector()
        t0 = time.time()
        d.process(_pkt(protocol="ARP", arp_sender_ip="192.168.1.10",
                        src_mac="AA:AA:AA:AA:AA:AA", timestamp=t0))
        alert = d.process(_pkt(protocol="ARP", arp_sender_ip="192.168.1.10",
                                src_mac="BB:BB:BB:BB:BB:BB", timestamp=t0 + 1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "ARP_MAPPING_CHANGED")


class TestSynFloodDetector(unittest.TestCase):
    def test_completed_connections_suppress_alert(self):
        d = SynFloodDetector(window_seconds=10, syn_threshold=10, completion_ratio_threshold=0.2)
        t0 = time.time()
        alert = None
        for i in range(10):
            alert = d.process(_pkt(protocol="TCP", src_ip="10.0.0.5", tcp_flags="S", timestamp=t0 + i * 0.1))
        # every SYN gets an ACK -> full completion -> no alert
        for i in range(10):
            d.process(_pkt(protocol="TCP", src_ip="10.0.0.5", tcp_flags="A", timestamp=t0 + i * 0.1))
        alert = d.process(_pkt(protocol="TCP", src_ip="10.0.0.5", tcp_flags="S", timestamp=t0 + 1))
        self.assertIsNone(alert)

    def test_low_completion_ratio_triggers_alert(self):
        d = SynFloodDetector(window_seconds=10, syn_threshold=10, completion_ratio_threshold=0.5)
        t0 = time.time()
        alert = None
        for i in range(10):
            alert = d.process(_pkt(protocol="TCP", src_ip="10.0.0.9", tcp_flags="S", timestamp=t0 + i * 0.01))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "SYN_FLOOD_INDICATOR")


class TestPortScanDetector(unittest.TestCase):
    def test_vertical_scan_detected(self):
        d = PortScanDetector(window_seconds=10, vertical_unique_ports=5, horizontal_unique_hosts=100)
        t0 = time.time()
        alerts = []
        for port in range(5):
            alerts = d.process(_pkt(protocol="TCP", tcp_flags="S", src_ip="10.0.0.1",
                                     dst_ip="10.0.0.100", dst_port=1000 + port, timestamp=t0))
        types = [a.alert_type for a in alerts]
        self.assertIn("VERTICAL_PORT_SCAN_INDICATOR", types)


class TestDnsTunnelingDetector(unittest.TestCase):
    def test_suspicious_pattern_reaches_score(self):
        d = DnsTunnelingDetector(rate_threshold=3, score_threshold=4, long_label_length=20,
                                  entropy_threshold=2.0)
        t0 = time.time()
        alert = None
        long_random_labels = [
            "kx8fj29alz7qmw0e", "p93jf8s0alqmzxk1", "z0plakqm93jfslak",
        ]
        for i, label in enumerate(long_random_labels):
            alert = d.process(_pkt(dns_query=f"{label}.tunnel.example.com",
                                    dns_qtype="TXT", timestamp=t0 + i * 0.1))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "DNS_TUNNELING_INDICATOR")

    def test_allowlisted_domain_is_skipped(self):
        d = DnsTunnelingDetector(allowlist=["example.com"], rate_threshold=1, score_threshold=1)
        alert = d.process(_pkt(dns_query="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.example.com", dns_qtype="TXT"))
        self.assertIsNone(alert)


class TestStatisticalAnomalyDetector(unittest.TestCase):
    def test_strong_deviation_produces_alert(self):
        d = StatisticalAnomalyDetector(window_seconds=1, learning_windows=3,
                                        z_score_threshold=2.0, persistence_windows=1)
        t = time.time()
        alert = None
        # Baseline windows with a little natural variance (4, 5, 6 pkts/window),
        # each window closed by a packet arriving >= window_seconds later.
        for window_count in (4, 5, 6, 50):  # last window is the spike
            for _ in range(window_count):
                alert = d.process(_pkt(timestamp=t))
                t += 0.001
            t += 1.05  # jump past the window boundary to force the next finalize
        # One more packet to close out and evaluate the spike window itself.
        alert = d.process(_pkt(timestamp=t))
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "TRAFFIC_RATE_ANOMALY")


if __name__ == "__main__":
    unittest.main()
