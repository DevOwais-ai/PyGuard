BLOCKED_IPS = set()
BLOCKED_PORTS = set()
ALLOWED_PORTS = set()

def load_rules():
    with open("rules.txt", "r") as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            rule, value = line.split()

            if rule == "BLOCK_IP":
                BLOCKED_IPS.add(value)

            elif rule == "BLOCK_PORT":
                BLOCKED_PORTS.add(int(value))

            elif rule == "ALLOW_PORT":
                ALLOWED_PORTS.add(int(value))

def is_allowed(packet):
    src_ip = packet.get("src_ip")
    dst_port = packet.get("dst_port")

    if src_ip in BLOCKED_IPS:
        return False
    if dst_port in BLOCKED_PORTS:
        return False
    if ALLOWED_PORTS and dst_port not in ALLOWED_PORTS:
        return False
    return True

def block_ip(ip):
    BLOCKED_IPS.add(ip)

