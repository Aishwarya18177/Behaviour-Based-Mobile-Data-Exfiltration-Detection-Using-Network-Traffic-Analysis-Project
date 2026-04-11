import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "db", "exfil_detector.db")

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS traffic_logs (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            src_ip      TEXT    NOT NULL,
            dst_ip      TEXT    NOT NULL,
            dst_port    INTEGER,
            packet_size INTEGER,
            protocol    TEXT,
            ip_tag      TEXT    DEFAULT 'UNKNOWN'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT    NOT NULL,
            rule_name   TEXT    NOT NULL,
            severity    TEXT    NOT NULL,
            description TEXT,
            src_ip      TEXT    NOT NULL
        )
    """)

    cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_src_ip    ON traffic_logs(src_ip)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_traffic_timestamp  ON traffic_logs(timestamp)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_timestamp   ON alerts(timestamp)")

    conn.commit()
    conn.close()
    print(f"[OK] Database initialised at: {DB_PATH}")

if __name__ == "__main__":
    init_db()
