import re
from collections import Counter, defaultdict
from scapy.utils import rdpcap
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.dns import DNS
from scapy.packet import Raw
from tp1.utils.config import logger


class Capture:
    def __init__(self) -> None:
        self.interface = ""
        self.pkts = []
        self.protocols = Counter()
        self.alerts = []
        self.potential_flags = defaultdict(list)
        self.summary = {}

    def capture_traffic(self) -> None:
        #Mode fichier pcap
        logger.info("Offline mode")

    def read_pcap(self, pcap_path: str) -> None:
        #Charge le fichier pcap
        logger.info(f"Reading file : {pcap_path}")
        self.pkts = rdpcap(pcap_path)

    def analyse(self, protocols: str = "") -> None:
        #Inspecte chaque packet
        logger.debug(f"Analysis started (parameter : {protocols})")
        arp_table = {}
        syn_counts = defaultdict(set)
        flag_pattern = re.compile(r'ESGI\{.*?}')

        for pkt in self.pkts:
            self._update_stats(pkt)
            self._detect_arp(pkt, arp_table)
            self._detect_scan(pkt, syn_counts)
            self._analyze_payload(pkt, flag_pattern)

        #Ip testé > 10 fois = scanning
        for ip, ports in syn_counts.items():
            if len(ports) > 10:
                self.alerts.append({"type": "port_scan", "attacker": ip})

        self.summary = self._gen_summary()

    def _update_stats(self, pkt) -> None:
        #Incrémentation des compteurs par protocole
        if pkt.haslayer(Ether): self.protocols["Ethernet"] += 1
        if pkt.haslayer(ARP): self.protocols["ARP"] += 1
        if pkt.haslayer(IP): self.protocols["IP"] += 1
        if pkt.haslayer(TCP): self.protocols["TCP"] += 1
        if pkt.haslayer(UDP): self.protocols["UDP"] += 1
        if pkt.haslayer(ICMP): self.protocols["ICMP"] += 1
        if pkt.haslayer(DNS): self.protocols["DNS"] += 1
        if pkt.haslayer(TCP) and (pkt[TCP].sport in [80, 8080] or pkt[TCP].dport in [80, 8080]):
            self.protocols["HTTP"] += 1

    def _detect_arp(self, pkt, arp_table: dict) -> None:
        #Détection d'IP avec plusieurs MAC
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            ip_src, mac_src = pkt[ARP].psrc, pkt[ARP].hwsrc
            if ip_src in arp_table and arp_table[ip_src] != mac_src:
                self.alerts.append({"type": "arp_spoofing", "attacker": mac_src})
            arp_table[ip_src] = mac_src

    def _detect_scan(self, pkt, syn_counts: dict) -> None:
        if pkt.haslayer(IP) and pkt.haslayer(TCP) and pkt[TCP].flags == "S":
            syn_counts[pkt[IP].src].add(pkt[TCP].dport)

    def _analyze_payload(self, pkt, flag_pattern) -> None:
        if not (pkt.haslayer(Raw) and pkt.haslayer(IP)):
            return
        try:
            payload = pkt[Raw].load.decode(errors="ignore")
            sql_sigs = ["union select", "1=1", "or '1'='1", "select * from"]

            if any(sig in payload.lower() for sig in sql_sigs):
                self.alerts.append({"type": "sql_injection", "attacker": pkt[IP].src})

            if match := flag_pattern.search(payload):
                flag_str = match.group(0)
                #Sauvegarde le drapeau en associant IP et MAC
                self.potential_flags[pkt[IP].src].append(flag_str)
                if pkt.haslayer(Ether):
                    self.potential_flags[pkt[Ether].src].append(flag_str)

        except (IndexError, UnicodeDecodeError):
            pass

    def get_summary(self) -> str:
        """
        Return summary
        :return:
        """
        return self.summary

    def _gen_summary(self) -> dict:
        unique_alerts = []
        seen = set()
        attacker_ids = set()

        for alert in self.alerts:
            identifier = (alert["type"], alert["attacker"])
            if identifier not in seen:
                seen.add(identifier)
                unique_alerts.append(alert)
                attacker_ids.add(alert["attacker"])

        final_flag = "Non trouvé"

        #Flag si IP attaquante
        for source_id, flags in self.potential_flags.items():
            if source_id in attacker_ids:
                final_flag = flags[0]
                break

        return {
            "protocols": dict(self.protocols),
            "attacks": unique_alerts,
            "flag": final_flag
        }
