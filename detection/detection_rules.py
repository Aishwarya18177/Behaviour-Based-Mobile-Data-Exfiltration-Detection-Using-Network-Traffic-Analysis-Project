import sys
import os

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ── Thresholds (easy to tune) ─────────────────────────────────────────────────
UPLOAD_BYTES_THRESHOLD    = 500_000   # 500 KB in 5 minutes  → HIGH
CONN_FREQUENCY_THRESHOLD  = 20        # 20+ connections/min  → MEDIUM
NIGHT_RATIO_THRESHOLD     = 0.5       # 50%+ traffic at night → MEDIUM
NON_STANDARD_PORT_SIZES   = 1000      # bytes via weird port  → HIGH
# ─────────────────────────────────────────────────────────────────────────────


def rule_high_volume_upload(profile):
    """
    Rule 1: HIGH
    Triggers when total upload bytes in last 5 min exceeds 500 KB.
    Indicates bulk data exfiltration.
    """
    if profile["upload_bytes"] >= UPLOAD_BYTES_THRESHOLD:
        return {
            "rule_name":   "HIGH_VOLUME_UPLOAD",
            "severity":    "HIGH",
            "description": (
                f"Upload volume {profile['upload_bytes']:,} bytes exceeds "
                f"threshold of {UPLOAD_BYTES_THRESHOLD:,} bytes in 5 minutes."
            )
        }
    return None


def rule_frequent_unknown_connections(profile):
    """
    Rule 2: MEDIUM
    Triggers when 20+ connections made AND more than half go to unknown IPs.
    Indicates repeated communication with suspicious servers.
    """
    if (profile["conn_count"] >= CONN_FREQUENCY_THRESHOLD and
            profile["unknown_ip_count"] > profile["conn_count"] // 2):
        return {
            "rule_name":   "FREQUENT_UNKNOWN_CONNECTIONS",
            "severity":    "MEDIUM",
            "description": (
                f"{profile['unknown_ip_count']} out of {profile['conn_count']} "
                f"connections went to unknown destination IPs."
            )
        }
    return None


def rule_night_time_upload(profile):
    """
    Rule 3: MEDIUM
    Triggers when more than 50% of traffic happens between 00:00 and 05:00 UTC.
    Legitimate apps rarely upload bulk data in the middle of the night.
    """
    if profile["night_ratio"] >= NIGHT_RATIO_THRESHOLD:
        return {
            "rule_name":   "NIGHT_TIME_UPLOAD",
            "severity":    "MEDIUM",
            "description": (
                f"{profile['night_ratio']:.0%} of traffic occurred between "
                f"00:00 and 05:00 UTC — suspicious background activity."
            )
        }
    return None


def rule_new_unknown_destination(profile):
    """
    Rule 4: LOW
    Triggers when any traffic goes to an unknown destination IP.
    A soft warning — useful for awareness.
    """
    if profile["unknown_ip_count"] > 0:
        return {
            "rule_name":   "NEW_UNKNOWN_DESTINATION",
            "severity":    "LOW",
            "description": (
                f"{profile['unknown_ip_count']} packet(s) sent to "
                f"{profile['unique_dst_count']} unknown destination IP(s)."
            )
        }
    return None


def rule_non_standard_port(profile):
    """
    Rule 5: HIGH
    Triggers when data is sent over ports other than 80 (HTTP) or 443 (HTTPS).
    Common in data tunnelling and covert exfiltration.
    """
    suspicious_ports = [
    p for p in profile["non_standard_ports"]
    if p not in (80, 443, 53, 67, 68, 123)
    and p < 49152   # exclude ephemeral/dynamic ports
]
    if suspicious_ports and profile["upload_bytes"] >= NON_STANDARD_PORT_SIZES:
        return {
            "rule_name":   "NON_STANDARD_PORT",
            "severity":    "HIGH",
            "description": (
                f"Data transmitted over non-standard port(s): "
                f"{suspicious_ports}. Possible tunnelling or covert channel."
            )
        }
    return None


# ── Master function called by main.py ─────────────────────────────────────────

ALL_RULES = [
    rule_high_volume_upload,
    rule_frequent_unknown_connections,
    rule_night_time_upload,
    rule_new_unknown_destination,
    rule_non_standard_port,
]

def check_all_rules(profile):
    """
    Run all 5 rules against a behaviour profile.
    Returns a list of alert dicts (empty list = traffic is clean).
    Each alert dict: { rule_name, severity, description }
    """
    alerts = []
    for rule in ALL_RULES:
        result = rule(profile)
        if result is not None:
            alerts.append(result)
    return alerts


# ── Standalone test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("[*] Testing detection rules against live traffic profiles...\n")

    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from analysis.analysis import get_all_profiles

    profiles = get_all_profiles(minutes=30)

    if not profiles:
        print("  No traffic in last 30 minutes. Run capture.py first.")
    else:
        total_alerts = 0
        for ip, profile in profiles.items():
            alerts = check_all_rules(profile)
            if alerts:
                print(f"  [!] Alerts for {ip}:")
                for alert in alerts:
                    sev = alert['severity']
                    tag = f"[{sev}]".ljust(8)
                    print(f"      {tag} {alert['rule_name']}")
                    print(f"             {alert['description']}")
                total_alerts += len(alerts)
            else:
                print(f"  [OK] {ip} - no suspicious activity")

        print(f"\n[*] Done. {total_alerts} alert(s) found across {len(profiles)} IP(s).")
