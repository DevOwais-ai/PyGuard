from collections import defaultdict
import time

connection_count = defaultdict(list)
THRESHOLD = 5  # attempts
TIME_WINDOW = 10  # seconds

def detect_intrusion(src_ip):
    current_time = time.time()
    connection_count[src_ip].append(current_time)

    # Remove old entries
    connection_count[src_ip] = [
        t for t in connection_count[src_ip]
        if current_time - t <= TIME_WINDOW
    ]

    if len(connection_count[src_ip]) > THRESHOLD:
        return True

    return False
