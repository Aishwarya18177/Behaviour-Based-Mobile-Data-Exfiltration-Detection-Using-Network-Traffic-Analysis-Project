import sqlite3
from datetime import datetime
from db.db_init import get_connection

# ─── WRITE ────────────────────────────────────────────────────────────────────

def insert_traffic(src_ip, dst_ip, dst_port, packet_size, protocol, ip_tag="UNKNOWN"):
    """Insert one captured packet into traffic_logs."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO traffic_logs
           (timestamp, src_ip, dst_ip, dst_port, packet_size, protocol, ip_tag)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (datetime.utcnow().isoformat(), src_ip, dst_ip,
         dst_port, packet_size, protocol, ip_tag)
    )
    conn.commit()
    conn.close()


def insert_alert(rule_name, severity, description, src_ip):
    """Insert a triggered alert into the alerts table."""
    conn = get_connection()
    conn.execute(
        """INSERT INTO alerts
           (timestamp, rule_name, severity, description, src_ip)
           VALUES (?, ?, ?, ?, ?)""",
        (datetime.utcnow().isoformat(), rule_name, severity, description, src_ip)
    )
    conn.commit()
    conn.close()


# ─── READ ─────────────────────────────────────────────────────────────────────

def get_traffic_window(src_ip, minutes=5):
    """
    Return all traffic_logs rows for src_ip within the last `minutes` minutes.
    Each row is a dict: {id, timestamp, src_ip, dst_ip, dst_port,
                         packet_size, protocol, ip_tag}
    """
    conn = get_connection()
    rows = conn.execute(
        """SELECT * FROM traffic_logs
           WHERE src_ip = ?
             AND timestamp >= datetime('now', ? || ' minutes')
           ORDER BY timestamp ASC""",
        (src_ip, f"-{minutes}")
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_all_active_src_ips(minutes=5):
    """Return list of unique src_ips seen in the last `minutes` minutes."""
    conn = get_connection()
    rows = conn.execute(
        """SELECT DISTINCT src_ip FROM traffic_logs
           WHERE timestamp >= datetime('now', ? || ' minutes')""",
        (f"-{minutes}",)
    ).fetchall()
    conn.close()
    return [r["src_ip"] for r in rows]


def get_recent_alerts(limit=50):
    """Return the most recent `limit` alerts, newest first."""
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_stats():
    """Return summary stats for the dashboard API."""
    conn = get_connection()
    total_packets  = conn.execute("SELECT COUNT(*) FROM traffic_logs").fetchone()[0]
    alert_count    = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
    unknown_ips    = conn.execute(
        "SELECT COUNT(DISTINCT dst_ip) FROM traffic_logs WHERE ip_tag='UNKNOWN'"
    ).fetchone()[0]
    conn.close()
    return {"total_packets": total_packets,
            "alert_count":   alert_count,
            "unknown_ips":   unknown_ips}
