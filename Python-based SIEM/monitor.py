import time
import threading
from collections import defaultdict
from datetime import datetime, timedelta

ALERT_THRESHOLD = 5
TIME_WINDOW = timedelta(minutes=1)
LOG_FILE = "logs/auth.log"

alerts = []  # Make sure this is defined here
ip_attempts = defaultdict(list)

def analyze_log_line(line):
    if "Failed login" in line:
        parts = line.split()
        ip = parts[-1]
        timestamp = datetime.now()
        ip_attempts[ip].append(timestamp)

        # Remove old attempts
        ip_attempts[ip] = [t for t in ip_attempts[ip] if t > timestamp - TIME_WINDOW]

        if len(ip_attempts[ip]) >= ALERT_THRESHOLD:
            alert = f"[{timestamp}] ALERT: Brute-force attempt from {ip}"
            print(alert)
            alerts.append(alert)

def monitor_log():
    print("[INFO] Monitoring started.")
    with open(LOG_FILE, "r") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            analyze_log_line(line)

def start_monitoring():
    t = threading.Thread(target=monitor_log, daemon=True)
    t.start()
