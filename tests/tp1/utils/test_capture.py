import re
from collections import defaultdict
from unittest.mock import patch
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP
from scapy.packet import Raw
from src.tp1.utils.capture import Capture


def test_capture_init():
    capture = Capture()
    assert capture.interface == ""
    assert capture.summary == {}


def test_given_capture_when_capture_traffic_then_interface_is_set():
    capture = Capture()
    capture.capture_traffic()
    assert capture.interface == ""


@patch("src.tp1.utils.capture.rdpcap")
def test_read_pcap(mock_rdpcap):
    mock_rdpcap.return_value = ["fake_packet"]
    capture = Capture()
    capture.read_pcap("dummy.pcap")
    mock_rdpcap.assert_called_once_with("dummy.pcap")
    assert capture.pkts == ["fake_packet"]


def test_update_stats():
    capture = Capture()
    pkt = Ether() / IP() / TCP(sport=80)
    capture._update_stats(pkt)
    assert capture.protocols["Ethernet"] == 1
    assert capture.protocols["IP"] == 1
    assert capture.protocols["TCP"] == 1
    assert capture.protocols["HTTP"] == 1


def test_detect_arp():
    capture = Capture()
    arp_table = {}

    pkt1 = ARP(op=2, psrc="10.0.0.1", hwsrc="00:11:22:33:44:55")
    capture._detect_arp(pkt1, arp_table)
    assert len(capture.alerts) == 0

    pkt2 = ARP(op=2, psrc="10.0.0.1", hwsrc="AA:BB:CC:DD:EE:FF")
    capture._detect_arp(pkt2, arp_table)
    assert len(capture.alerts) == 1
    assert capture.alerts[0]["type"] == "arp_spoofing"


def test_detect_scan():
    capture = Capture()
    syn_counts = defaultdict(set)
    pkt = IP(src="10.0.0.2") / TCP(flags="S", dport=80)
    capture._detect_scan(pkt, syn_counts)
    assert 80 in syn_counts["10.0.0.2"]


def test_analyze_payload():
    capture = Capture()
    flag_pattern = re.compile(r"ESGI\{.*?}")
    pkt = Ether(src="AA:BB:CC") / IP(src="10.0.0.3") / Raw(load=b"UNION SELECT ESGI{TEST}")
    capture._analyze_payload(pkt, flag_pattern)
    assert capture.alerts[0]["type"] == "sql_injection"
    assert "ESGI{TEST}" in capture.potential_flags["10.0.0.3"]


def test_analyse():
    capture = Capture()
    with patch.object(capture, "_gen_summary") as mock_gen_summary:
        mock_gen_summary.return_value = {"flag": "TEST"}
        capture.analyse("tcp")
        mock_gen_summary.assert_called_once()
        assert capture.summary == {"flag": "TEST"}


def test_get_summary():
    capture = Capture()
    capture.summary = {"test": 123}
    assert capture.get_summary() == {"test": 123}


def test_gen_summary():
    capture = Capture()
    capture.alerts = [{"type": "sql_injection", "attacker": "10.0.0.9"}]
    capture.potential_flags["10.0.0.9"] = ["ESGI{FOUND}"]

    result = capture._gen_summary()
    assert result["flag"] == "ESGI{FOUND}"
    assert len(result["attacks"]) == 1
