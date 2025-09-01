import time
import random
import os

LOG_FILE = "logs/auth.log"
FAKE_IPS = ["192.168.1.10", "192.168.1.12", "10.0.0.5"]

def simulate_attack(ip=None, attempts=10):
    try:
        # Make sure the logs directory exists
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)

        with open(LOG_FILE, "a") as log:
            for i in range(attempts):
                fake_ip = ip if ip else random.choice(FAKE_IPS)
                log_entry = f"{time.ctime()} Failed login from {fake_ip}\n"
                log.write(log_entry)
                print(f"Written log: {log_entry.strip()}")
                time.sleep(0.2)
        print(f"Simulation complete: {attempts} attempts logged.")
    except Exception as e:
        print(f"Error writing to log file: {e}")

if __name__ == "__main__":
    simulate_attack()

