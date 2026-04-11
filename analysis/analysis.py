import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.db_helper import get_traffic_window, get_all_active_src_ips


def get_profile(src_ip, minutes=5):
    """
    Analyse recent traffic for a given src_ip and return a behaviour profile.

    Returns a dict:
    {
        upload_bytes       : int   - total bytes sent by this IP in last `minutes` min
        conn_count         : int   - number of outgoing connections
        unique_dst_count   : int   - number of distinct destination IPs contacted
        unknown_ip_count   : int   - how many destinations were tagged UNKNOWN
        night_ratio        : float - fraction of traffic sent between 00:00 and 05:00 UTC
        non_standard_ports : list  - destination ports that are NOT 80 or 443
    }
    """
    rows = get_traffic_window(src_ip, minutes=minutes)

    if not rows:
        return {
            "upload_bytes":        0,
            "conn_count":          0,
            "unique_dst_count":    0,
            "unknown_ip_count":    0,
            "night_ratio":         0.0,
            "non_standard_ports":  []
        }

    # ── upload bytes (packets FROM this IP only) ──────────────────────────────
    outgoing = [r for r in rows if r["src_ip"] == src_ip]
    upload_bytes = sum(r["packet_size"] or 0 for r in outgoing)

    # ── connection count ──────────────────────────────────────────────────────
    conn_count = len(outgoing)

    # ── unique destination IPs ────────────────────────────────────────────────
    dst_ips = set(r["dst_ip"] for r in outgoing)
    unique_dst_count = len(dst_ips)

    # ── unknown IP count ──────────────────────────────────────────────────────
    unknown_ip_count = sum(1 for r in outgoing if r["ip_tag"] == "UNKNOWN")

    # ── night-time ratio (00:00 – 05:00 UTC) ─────────────────────────────────
    night_count = 0
    for r in outgoing:
        try:
            ts = datetime.fromisoformat(r["timestamp"])
            if 0 <= ts.hour < 5:
                night_count += 1
        except Exception:
            pass
    night_ratio = round(night_count / conn_count, 2) if conn_count > 0 else 0.0

    # ── non-standard ports ────────────────────────────────────────────────────
    standard_ports = {80, 443}
    non_standard_ports = list(set(
        r["dst_port"] for r in outgoing
        if r["dst_port"] is not None and r["dst_port"] not in standard_ports
    ))

    return {
        "upload_bytes":        upload_bytes,
        "conn_count":          conn_count,
        "unique_dst_count":    unique_dst_count,
        "unknown_ip_count":    unknown_ip_count,
        "night_ratio":         night_ratio,
        "non_standard_ports":  non_standard_ports
    }


def get_all_profiles(minutes=5):
    """
    Return behaviour profiles for ALL active source IPs in the last `minutes` minutes.
    Used by main.py to scan every active device at once.
    """
    active_ips = get_all_active_src_ips(minutes=minutes)
    profiles = {}
    for ip in active_ips:
        profiles[ip] = get_profile(ip, minutes=minutes)
    return profiles


def print_profile(src_ip, profile):
    """Pretty-print a profile to the console for debugging."""
    print(f"\n  Profile for {src_ip}")
    print(f"  {'-'*40}")
    print(f"  Upload bytes       : {profile['upload_bytes']:,} bytes")
    print(f"  Connections        : {profile['conn_count']}")
    print(f"  Unique dst IPs     : {profile['unique_dst_count']}")
    print(f"  Unknown IPs        : {profile['unknown_ip_count']}")
    print(f"  Night-time ratio   : {profile['night_ratio']:.0%}")
    print(f"  Non-standard ports : {profile['non_standard_ports'] or 'none'}")


if __name__ == "__main__":
    print("[*] Running analysis on last 5 minutes of traffic...\n")
    profiles = get_all_profiles(minutes=5)

    if not profiles:
        print("  No traffic found in the last 5 minutes.")
        print("  Run capture.py first to collect some packets.")
    else:
        print(f"  Found {len(profiles)} active IP(s):\n")
        for ip, profile in profiles.items():
            print_profile(ip, profile)

    print("\n[*] Analysis complete.")