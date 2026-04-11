import sys
import os
from datetime import datetime, timedelta
from colorama import init, Fore, Style

init(autoreset=True)

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.db_helper import insert_alert, get_recent_alerts

COOLDOWN_MINUTES = 2

_last_alert_times = {}

def _cooldown_key(src_ip, rule_name):
    return f"{src_ip}::{rule_name}"

def _is_on_cooldown(src_ip, rule_name):
    key = _cooldown_key(src_ip, rule_name)
    if key not in _last_alert_times:
        return False
    elapsed = datetime.utcnow() - _last_alert_times[key]
    return elapsed < timedelta(minutes=COOLDOWN_MINUTES)

def _mark_alerted(src_ip, rule_name):
    key = _cooldown_key(src_ip, rule_name)
    _last_alert_times[key] = datetime.utcnow()

def _severity_colour(severity):
    if severity == "HIGH":
        return Fore.RED + Style.BRIGHT
    elif severity == "MEDIUM":
        return Fore.YELLOW + Style.BRIGHT
    elif severity == "LOW":
        return Fore.CYAN + Style.BRIGHT
    return Fore.WHITE

def _print_alert(src_ip, alert):
    severity  = alert["severity"]
    rule_name = alert["rule_name"]
    desc      = alert["description"]
    timestamp = datetime.utcnow().strftime("%H:%M:%S")
    colour    = _severity_colour(severity)

    print(colour + f"\n  [{timestamp}] !! ALERT DETECTED !!")
    print(colour + f"  Severity  : {severity}")
    print(colour + f"  Rule      : {rule_name}")
    print(colour + f"  Source IP : {src_ip}")
    print(colour + f"  Detail    : {desc}")
    print(Style.RESET_ALL + "  " + "-"*50)

def process_alerts(src_ip, alerts):
    """
    Takes a list of alert dicts from detection_rules.check_all_rules()
    and for each one:
      1. Checks cooldown (skip if same rule fired within 2 minutes)
      2. Saves to the alerts table in SQLite
      3. Prints to console with colour
    Returns the number of new alerts actually fired.
    """
    fired = 0
    for alert in alerts:
        rule_name   = alert["rule_name"]
        severity    = alert["severity"]
        description = alert["description"]

        if _is_on_cooldown(src_ip, rule_name):
            continue

        insert_alert(rule_name, severity, description, src_ip)
        _print_alert(src_ip, alert)
        _mark_alerted(src_ip, rule_name)
        fired += 1

    return fired

def print_alert_summary():
    """Print the last 10 alerts from the database — useful for startup."""
    alerts = get_recent_alerts(limit=10)
    if not alerts:
        print("  No alerts in database yet.")
        return
    print(f"\n  Last {len(alerts)} alert(s) from database:")
    print("  " + "-"*50)
    for a in alerts:
        colour = _severity_colour(a["severity"])
        print(colour + f"  [{a['timestamp'][:19]}] {a['severity']:6s} | {a['rule_name']} | {a['src_ip']}")
    print(Style.RESET_ALL)

if __name__ == "__main__":
    print("[*] Alert Manager — testing with simulated alerts\n")

    test_cases = [
        ("192.168.1.99", {
            "rule_name":   "HIGH_VOLUME_UPLOAD",
            "severity":    "HIGH",
            "description": "Upload volume 620,000 bytes exceeds threshold of 500,000 bytes in 5 minutes."
        }),
        ("192.168.1.99", {
            "rule_name":   "FREQUENT_UNKNOWN_CONNECTIONS",
            "severity":    "MEDIUM",
            "description": "35 out of 50 connections went to unknown destination IPs."
        }),
        ("10.0.2.15", {
            "rule_name":   "NEW_UNKNOWN_DESTINATION",
            "severity":    "LOW",
            "description": "8 packet(s) sent to 3 unknown destination IP(s)."
        }),
    ]

    total = 0
    for src_ip, alert in test_cases:
        fired = process_alerts(src_ip, [alert])
        total += fired

    print(f"\n[*] {total} alert(s) saved to database.\n")
    print("[*] Recent alerts in database:")
    print_alert_summary()
