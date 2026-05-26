import os
import sqlite3

DB_PATH = os.getenv("DB_PATH", "security_gateway.db")
_BUSY_TIMEOUT = 5000


def get_connection():
    conn = sqlite3.connect(DB_PATH, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(f"PRAGMA busy_timeout={_BUSY_TIMEOUT}")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def query_sqlite(query: str, args: tuple = (), one: bool = False):
    conn = get_connection()
    try:
        cursor = conn.execute(query, args)
        rv = [dict(row) for row in cursor.fetchall()]
        cursor.close()
        return (rv[0] if rv else None) if one else rv
    except Exception as e:
        print(f"[DATABASE ERROR] Query execution failed: {e}")
        return None
    finally:
        conn.close()


def execute_sqlite(query: str, args: tuple = ()) -> bool:
    conn = get_connection()
    try:
        conn.execute(query, args)
        conn.commit()
        return True
    except Exception as e:
        print(f"[DATABASE ERROR] Write transaction failed: {e}")
        return False
    finally:
        conn.close()


def init_sqlite_tables():
    conn = get_connection()
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS security_events (
                incident_id TEXT PRIMARY KEY,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                source_ip TEXT NOT NULL,
                user_agent TEXT,
                target_uri TEXT NOT NULL,
                malicious_payload TEXT,
                threat_category TEXT NOT NULL,
                mitigation_action TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_id TEXT PRIMARY KEY,
                identifier TEXT NOT NULL UNIQUE,
                pattern TEXT NOT NULL,
                action TEXT NOT NULL,
                category TEXT NOT NULL,
                is_active INTEGER DEFAULT 1,
                blocks_count INTEGER DEFAULT 0,
                severity TEXT NOT NULL,
                description TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mitigation_state (
                id TEXT PRIMARY KEY,
                posture TEXT NOT NULL
            )
        """)
        conn.commit()
        print("[INFO] Database tables synchronized. Scheme: SQLITE")
    except Exception as e:
        print(f"[CRITICAL] Database bootstrapping sequence failed: {e}")
    finally:
        conn.close()
