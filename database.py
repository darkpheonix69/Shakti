import sqlite3
from datetime import datetime
import os
import logging

DB_DIR = "logs"
DB_PATH = os.path.join(DB_DIR, "wifi_attack_logs.db")

logging.basicConfig(level=logging.INFO)

def ensure_db_dir():
    if not os.path.exists(DB_DIR):
        os.makedirs(DB_DIR)
        logging.info(f"Created directory: {DB_DIR}")

def init_db():
    ensure_db_dir()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    mac TEXT,
                    signal TEXT,
                    channel TEXT,
                    message TEXT
                )
            ''')
            conn.commit()
        logging.info("Database initialized.")
    except Exception as e:
        logging.error(f"Failed to initialize database: {e}")

def insert_log(mac, signal, channel, message):
    ensure_db_dir()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("INSERT INTO logs (timestamp, mac, signal, channel, message) VALUES (?, ?, ?, ?, ?)",
                      (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), mac, signal, channel, message))
            conn.commit()
        logging.info(f"Inserted log for MAC: {mac}")
    except Exception as e:
        logging.error(f"Failed to insert log: {e}")

def fetch_logs(limit=50):
    ensure_db_dir()
    try:
        with sqlite3.connect(DB_PATH) as conn:
            c = conn.cursor()
            c.execute("SELECT timestamp, mac, signal, channel, message FROM logs ORDER BY id DESC LIMIT ?", (limit,))
            rows = c.fetchall()
        return rows
    except Exception as e:
        logging.error(f"Failed to fetch logs: {e}")
        return []
