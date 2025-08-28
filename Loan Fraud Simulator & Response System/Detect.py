import time
from datetime import datetime, timedelta
import random

# Simulated User Database
users = {
    "user123": {
        "name": "Alice",
        "account_locked": False,
        "last_login_ip": "192.168.1.1",
        "loans": [],
        "verified_identity": True,
    }
}

# Alert system
def alert_admin(user_id, reason):
    print(f"[ALERT] Suspicious activity detected for {user_id}: {reason}")

# Response system
def lock_account(user_id):
    users[user_id]["account_locked"] = True
    print(f"[ACTION] Account {user_id} has been locked.")

# Detection Engine
def detect_account_takeover(user_id, current_ip):
    if users[user_id]["last_login_ip"] != current_ip:
        alert_admin(user_id, "Account takeover suspected (IP mismatch)")
        lock_account(user_id)

def detect_fake_identity(user_id, is_verified):
    if not is_verified:
        alert_admin(user_id, "Fake identity suspected (verification failed)")
        lock_account(user_id)

def detect_loan_stacking(user_id):
    now = datetime.now()
    recent_loans = [loan for loan in users[user_id]["loans"] if now - loan < timedelta(minutes=1)]
    if len(recent_loans) >= 3:
        alert_admin(user_id, "Loan stacking suspected (multiple quick loans)")
        lock_account(user_id)

# Simulate activity
def simulate_activity():
    user_id = "user123"

    print("\n--- Scenario 1: Account Takeover ---")
    detect_account_takeover(user_id, "10.0.0.5")  # new IP

    # Reset user for next test
    users[user_id]["account_locked"] = False
    users[user_id]["last_login_ip"] = "192.168.1.1"

    print("\n--- Scenario 2: Fake Borrower Identity ---")
    detect_fake_identity(user_id, is_verified=False)

    # Reset user for next test
    users[user_id]["account_locked"] = False

    print("\n--- Scenario 3: Loan Stacking ---")
    now = datetime.now()
    users[user_id]["loans"] = [now - timedelta(seconds=10),
                                now - timedelta(seconds=20),
                                now - timedelta(seconds=30)]
    detect_loan_stacking(user_id)

simulate_activity()
