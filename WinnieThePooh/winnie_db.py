# winnie_db.py
import sqlite3
import threading
import time
from typing import Any, Dict

DB_FILE = "winnie.db"
_lock = threading.Lock()

def init_db():
    with _lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS ssh_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            src_ip TEXT,
            username TEXT,
            password TEXT,
            client_banner TEXT,
            extra TEXT
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS http_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp INTEGER,
            src_ip TEXT,
            method TEXT,
            path TEXT,
            headers TEXT,
            body TEXT
        )
        """)
        conn.commit()

def insert(table: str, data: Dict[str, Any]):
    keys = ",".join(data.keys())
    placeholders = ",".join("?" for _ in data)
    values = tuple(data.values())
    with _lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(f"INSERT INTO {table} ({keys}) VALUES ({placeholders})", values)
        conn.commit()

def fetch_recent(table: str, limit=100):
    with _lock, sqlite3.connect(DB_FILE) as conn:
        c = conn.cursor()
        c.execute(f"SELECT * FROM {table} ORDER BY id DESC LIMIT ?", (limit,))
        cols = [d[0] for d in c.description]
        rows = c.fetchall()
    return [dict(zip(cols, r)) for r in rows]

if __name__ == "__main__":
    init_db()
    print("DB initialized")
