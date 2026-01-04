from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP

from firewall import is_allowed
from ids import detect_intrusion
from response import respond_to_attack
from logger import log_event


def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_port = None

        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        packet_info = {
            "src_ip": src_ip,
            "dst_port": dst_port
        }

        if not is_allowed(packet_info):
            log_event(f"Blocked packet from {src_ip}")
            return

        if detect_intrusion(src_ip):
            respond_to_attack(src_ip)

        log_event(f"Allowed packet from {src_ip}")


def start_sniffing():
    sniff(prn=process_packet, store=False)
