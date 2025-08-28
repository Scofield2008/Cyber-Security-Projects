import os
import re
import requests
import sys
from datetime import datetime

# CONFIG 
DISCORD_WEBHOOK_URL = ""  
LOG_FILE = "dlds_log.txt"


PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws(.{0,20})?(secret|key)(.{0,20})?['\"][0-9a-zA-Z/+]{40}['\"]",
    "Email Address": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    "Password": r"(?i)(password|pwd)[\"'\s:=]+[^\s\"']+",
    "Google API Key": r"AIza[0-9A-Za-z\\-_]{35}",
    "Generic API Key": r"(?i)(api[_-]?key)[\"'\s:=]+[a-zA-Z0-9_\-]{16,}",
    "Social Security Number": r"\b\d{3}-\d{2}-\d{4}\b"
}

def log_finding(file_path, matches):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log:
        log.write(f"[{timestamp}] Sensitive data found in: {file_path}\n")
        for m_type, value in matches:
            log.write(f"    - {m_type}: {value}\n")
        log.write("\n")

def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", errors="ignore") as file:
            content = file.read()
            for name, pattern in PATTERNS.items():
                for match in re.findall(pattern, content):
                    findings.append((name, match.strip()))
    except Exception as e:
        print(f"[ERROR] Cannot read {filepath}: {e}")
    return findings

def send_discord_alert(file, matches):
    if not DISCORD_WEBHOOK_URL:
        return
    content = f" **Sensitive Data Leak Detected in `{file}`**\n"
    for match_type, match in matches:
        content += f"- **{match_type}**: `{match}`\n"
    try:
        requests.post(DISCORD_WEBHOOK_URL, json={"content": content})
    except requests.RequestException as e:
        print(f"[ERROR] Failed to send Discord alert: {e}")

def scan_directory(root_dir):
    print(f"[INFO] Scanning directory: {root_dir}")
    for root, _, files in os.walk(root_dir):
        for file in files:
            filepath = os.path.join(root, file)
            matches = scan_file(filepath)
            if matches:
                print(f"\n[!] Sensitive data found in: {filepath}")
                for m_type, value in matches:
                    print(f"    - {m_type}: {value}")
                log_finding(filepath, matches)
                send_discord_alert(filepath, matches)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python DLDS.py <directory_to_scan>")
        sys.exit(1)

    target_dir = sys.argv[1]
    if not os.path.isdir(target_dir):
        print(f"[ERROR] The path '{target_dir}' is not a valid directory.")
        sys.exit(1)

    # Clear previous log if desired
    with open(LOG_FILE, "w", encoding="utf-8") as log:
        log.write("=== DLDS Scan Log ===\n")

    scan_directory(target_dir)
