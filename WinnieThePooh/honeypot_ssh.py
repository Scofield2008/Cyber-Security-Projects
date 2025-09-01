import socket
import paramiko
import threading
import os
from datetime import datetime

# ==== Paths ====
KEY_DIR = "keys"
LOG_DIR = "logs"
KEY_PATH = os.path.join(KEY_DIR, "host_rsa.key")
LOG_PATH = os.path.join(LOG_DIR, "attacks.log")

# ==== Ensure directories exist ====
os.makedirs(KEY_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# ==== Host key (persistent) ====
if not os.path.exists(KEY_PATH):
    print("[*] Generating SSH host key (2048-bit RSA)...")
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(KEY_PATH)
host_key = paramiko.RSAKey(filename=KEY_PATH)

# ==== Logging ====
def log_event(text: str):
    line = f"[{datetime.now().isoformat(sep=' ', timespec='seconds')}] {text}"
    print(line)
    with open(LOG_PATH, "a", encoding="utf-8") as f:
        f.write(line + "\n")

# ==== Fake shell responses ====
FAKE_COMMANDS = {
    "help": "Available commands: ls, pwd, whoami, cat /etc/passwd, exit",
    "ls": "honeypot.txt  secrets/  config/  fake_logs/",
    "pwd": "/home/someuser",
    "whoami": "root",
    "cat /etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "someuser:x:1000:1000::/home/someuser:/bin/bash"
    ),
}

PROMPT = "$ "

class SSHServer(paramiko.ServerInterface):
    """
    Paramiko SSH server that:
      - accepts any password (for honeypot purposes)
      - allows PTY and shell requests
    """
    def __init__(self):
        super().__init__()
        self.event = threading.Event()
        self.username = None

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        self.username = username
        log_event(f"Login attempt: user={username!r}, pass={password!r}")
        # Accept everything to reach the fake shell
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    # ✅ allow PTY
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    # ✅ allow shell
    def check_channel_shell_request(self, channel):
        return True

def shell_session(chan: paramiko.Channel, peer: str, username: str):
    """
    Minimal interactive fake shell:
      - shows welcome
      - prompts with "$ "
      - logs each command
      - returns canned outputs
    """
    try:
        chan.send("Welcome to Ubuntu 22.04 LTS\n")
        chan.send("Type 'help' for commands.\n\n")

        # Simple REPL
        while True:
            chan.send(PROMPT)
            data = chan.recv(1024)
            if not data:
                break
            cmd = data.decode("utf-8", errors="ignore").replace("\r", "").strip()

            if not cmd:
                continue

            log_event(f"Command from {peer} ({username}): {cmd}")

            if cmd in FAKE_COMMANDS:
                chan.send(FAKE_COMMANDS[cmd] + "\n")
            elif cmd == "exit" or cmd == "logout" or cmd == "quit":
                chan.send("Goodbye!\n")
                break
            else:
                chan.send(f"bash: {cmd}: command not found\n")

    except Exception as e:
        log_event(f"[!] Shell error for {peer}: {e}")
    finally:
        try:
            chan.close()
        except Exception:
            pass

def handle_client(client_sock: socket.socket, addr):
    peer = f"{addr[0]}:{addr[1]}"
    log_event(f"New connection from {peer}")
    transport = paramiko.Transport(client_sock)
    transport.add_server_key(host_key)
    server = SSHServer()

    try:
        transport.start_server(server=server)
        chan = transport.accept(20)  # wait up to 20s for a channel
        if chan is None:
            log_event(f"No channel from {peer}")
            return

        # Run an interactive fake shell on this channel
        shell_session(chan, peer, server.username or "?")

    except Exception as e:
        log_event(f"[!] Transport error for {peer}: {e}")
    finally:
        try:
            transport.close()
        except Exception:
            pass

def main():
    host = "0.0.0.0"
    port = 2222
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(100)
    print(f"[*] SSH Honeypot listening on {host}:{port} ... (Ctrl+C to stop)")

    try:
        while True:
            client, addr = sock.accept()
            t = threading.Thread(target=handle_client, args=(client, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    finally:
        sock.close()

if __name__ == "__main__":
    main()
