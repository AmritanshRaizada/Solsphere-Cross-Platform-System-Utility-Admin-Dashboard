import sqlite3
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./test.db")

def get_db_connection():
    conn = sqlite3.connect(DATABASE_URL.replace("sqlite:///", ""))
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS machines (
            machine_id TEXT PRIMARY KEY,
            hostname TEXT,
            os_name TEXT,
            os_version TEXT,
            last_seen TIMESTAMP,
            latest_hash TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            machine_id TEXT,
            timestamp TEXT,
            payload JSON,
            hash TEXT,
            FOREIGN KEY (machine_id) REFERENCES machines (machine_id)
        )
    """)
    conn.commit()
    conn.close()
