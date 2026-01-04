from firewall import block_ip
from logger import log_alert

def respond_to_attack(ip):
    block_ip(ip)
    log_alert(f"Auto-blocked IP due to intrusion: {ip}")
