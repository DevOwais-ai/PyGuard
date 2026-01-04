from packet_sniffer import start_sniffing
from firewall import load_rules

print("Starting Integrated Firewall & IDS...")
load_rules()
start_sniffing()
