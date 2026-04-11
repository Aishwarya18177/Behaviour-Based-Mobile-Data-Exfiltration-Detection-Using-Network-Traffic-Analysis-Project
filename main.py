import sys
import os
import time
import threading
import logging
from datetime import datetime

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from db.db_init import init_db
from db.db_helper import get_stats
from detection.alert_manager import print_alert_summary

logging.basicConfig(
    filename="system.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

ANALYSIS_INTERVAL_SECONDS = 60
stop_event = threading.Event()


def run_capture():
    """Thread 1 — captures packets continuously."""
    print("[*] Capture thread started...")
    logging.info("Capture thread started")
    try:
        from capture.capture import start_capture
        start_capture()
    except Exception as e:
        print(f"[!] Capture error: {e}")
        logging.error(f"Capture thread error: {e}")


def run_detection_loop():
    """Thread 2 — every 60s: analyse traffic → check rules → fire alerts."""
    print(f"[*] Detection loop started (runs every {ANALYSIS_INTERVAL_SECONDS}s)...")
    logging.info("Detection loop started")

    from analysis.analysis import get_all_profiles
    from detection.detection_rules import check_all_rules
    from detection.alert_manager import process_alerts

    cycle = 0

    while not stop_event.is_set():
        time.sleep(ANALYSIS_INTERVAL_SECONDS)

        if stop_event.is_set():
            break

        cycle += 1
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        print(f"\n[{timestamp}] Running detection cycle #{cycle}...")
        logging.info(f"Detection cycle #{cycle} started")

        try:
            profiles = get_all_profiles(minutes=5)

            if not profiles:
                print(f"  No active traffic found in last 5 minutes.")
                continue

            total_alerts = 0
            for src_ip, profile in profiles.items():
                alerts = check_all_rules(profile)
                if alerts:
                    fired = process_alerts(src_ip, alerts)
                    total_alerts += fired
                    logging.info(f"{fired} alert(s) fired for {src_ip}")

            stats = get_stats()
            print(f"  Scanned {len(profiles)} IP(s) | "
                  f"New alerts: {total_alerts} | "
                  f"Total packets: {stats['total_packets']:,} | "
                  f"Total alerts: {stats['alert_count']}")

            if total_alerts == 0:
                print(f"  All clear — no suspicious activity detected.")

        except Exception as e:
            print(f"[!] Detection error: {e}")
            logging.error(f"Detection cycle error: {e}")


def print_banner():
    print("=" * 60)
    print("   Behaviour-Based Mobile Data Exfiltration Detector")
    print("=" * 60)
    print(f"   Started at : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")
    print(f"   Scan every : {ANALYSIS_INTERVAL_SECONDS} seconds")
    print(f"   Interface  : Wi-Fi")
    print("=" * 60)


def main():
    print_banner()

    print("\n[*] Initialising database...")
    init_db()

    print("\n[*] Recent alerts from previous sessions:")
    print_alert_summary()

    print("[*] Starting detection system — press Ctrl+C to stop\n")
    logging.info("System started")

    capture_thread = threading.Thread(target=run_capture, daemon=True)
    detection_thread = threading.Thread(target=run_detection_loop, daemon=True)

    capture_thread.start()
    time.sleep(2)
    detection_thread.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down...")
        stop_event.set()
        time.sleep(2)
        stats = get_stats()
        print(f"[*] Session summary:")
        print(f"    Total packets captured : {stats['total_packets']:,}")
        print(f"    Total alerts fired     : {stats['alert_count']}")
        print(f"    Unknown IPs seen       : {stats['unknown_ips']}")
        print(f"\n[*] All activity logged to system.log")
        print("[*] Goodbye!")
        logging.info("System stopped by user")


if __name__ == "__main__":
    main()
