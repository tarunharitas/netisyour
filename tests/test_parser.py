import unittest

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR

from nids.parser import parse_packet


class TestParser(unittest.TestCase):
    def test_tcp_packet_is_normalized(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
        record = parse_packet(pkt)
        self.assertEqual(record.protocol, "TCP")
        self.assertEqual(record.src_ip, "10.0.0.1")
        self.assertEqual(record.dst_ip, "10.0.0.2")
        self.assertEqual(record.src_port, 1234)
        self.assertEqual(record.dst_port, 80)
        self.assertEqual(record.tcp_flags, "S")

    def test_dns_query_is_normalized(self):
        pkt = (
            Ether() / IP(src="10.0.0.1", dst="8.8.8.8") /
            UDP(sport=5353, dport=53) /
            DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))
        )
        record = parse_packet(pkt)
        self.assertEqual(record.dns_query, "example.com")
        self.assertEqual(record.dns_qtype, "A")

    def test_capture_timestamp_is_preserved(self):
        pkt = Ether() / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(flags="S")
        pkt.time = 123.45
        record = parse_packet(pkt)
        self.assertEqual(record.timestamp, 123.45)


if __name__ == "__main__":
    unittest.main()
