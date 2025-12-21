import sqlite3
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "threat_logs.db")


# -------------------------------
# AUTO MIGRATION: Adds missing columns
# -------------------------------

REQUIRED_COLUMNS = {
    "vt_malicious": "INTEGER DEFAULT 0",
    "vt_suspicious": "INTEGER DEFAULT 0",
    "country": "TEXT DEFAULT 'Unknown'",
}

def migrate_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Read existing column names
    cur.execute("PRAGMA table_info(logs)")
    existing_columns = [row[1] for row in cur.fetchall()]

    # Add missing columns dynamically
    for col, col_type in REQUIRED_COLUMNS.items():
        if col not in existing_columns:
            print(f"[DB] Adding missing column: {col}")
            cur.execute(f"ALTER TABLE logs ADD COLUMN {col} {col_type}")

    conn.commit()
    conn.close()


# -------------------------------
# INITIAL DB CREATION
# -------------------------------

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Initial table (minimal base structure)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score REAL NOT NULL,
            severity TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()

    # Run migration after creation
    migrate_db()


# -------------------------------
# INSERT LOG
# -------------------------------

def save_log(url, prediction, confidence, risk_score, severity, vt_malicious, vt_suspicious, country):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO logs (url, prediction, confidence, risk_score, severity, vt_malicious, vt_suspicious, country, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        url,
        prediction,
        confidence,
        risk_score,
        severity,
        vt_malicious,
        vt_suspicious,
        country,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ))

    conn.commit()
    conn.close()


# -------------------------------
# READ LOGS
# -------------------------------

def get_logs():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC")
    rows = cur.fetchall()
    conn.close()
    return rows
