print("capture.py starting...")

import pyshark
import sys
import os
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db.db_helper import insert_traffic

INTERFACE = r"\Device\NPF_{C18DB8E1-C4AB-447E-AC75-CB565452B269}"
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

def tag_ip(dst_ip):
    if dst_ip.startswith("192.168.") or dst_ip.startswith("10.") or dst_ip.startswith("127."):
        return "KNOWN"
    known_prefixes = ["8.8.", "1.1.1.", "142.250.", "20.", "13."]
    for prefix in known_prefixes:
        if dst_ip.startswith(prefix):
            return "KNOWN"
    return "UNKNOWN"

def get_protocol(packet):
    try:
        if hasattr(packet, 'tls') or hasattr(packet, 'ssl'): return "HTTPS"
        if hasattr(packet, 'http'): return "HTTP"
        if hasattr(packet, 'tcp'): return "TCP"
        if hasattr(packet, 'udp'): return "UDP"
        return "OTHER"
    except: return "OTHER"

def get_dst_port(packet):
    try:
        if hasattr(packet, 'tcp'): return int(packet.tcp.dstport)
        if hasattr(packet, 'udp'): return int(packet.udp.dstport)
        return None
    except: return None

def get_packet_size(packet):
    try: return int(packet.length)
    except: return 0

def start_capture():
    print(f"[*] Starting live capture on Wi-Fi...")
    print(f"[*] Press Ctrl+C to stop\n")

    try:
        capture = pyshark.LiveCapture(
            interface=INTERFACE,
            tshark_path=TSHARK_PATH,
            bpf_filter="ip"
        )
        print("[*] Capture object created, sniffing now...")
    except Exception as e:
        print(f"[ERROR] Failed to create capture: {e}")
        return

    packet_count = 0

    try:
        for packet in capture.sniff_continuously():
            try:
                if not hasattr(packet, 'ip'):
                    continue

                src_ip      = packet.ip.src
                dst_ip      = packet.ip.dst
                dst_port    = get_dst_port(packet)
                packet_size = get_packet_size(packet)
                protocol    = get_protocol(packet)
                ip_tag      = tag_ip(dst_ip)

                insert_traffic(src_ip, dst_ip, dst_port, packet_size, protocol, ip_tag)

                packet_count += 1
                tag_str = "[KNOWN]  " if ip_tag == "KNOWN" else "[UNKNOWN]"
                print(f"  {tag_str} {src_ip:15s} -> {dst_ip:15s}  {protocol:6s}  {packet_size} bytes")

            except AttributeError:
                continue
            except Exception as e:
                print(f"[!] Packet error: {e}")
                continue

    except KeyboardInterrupt:
        print(f"\n[*] Stopped. Total packets logged: {packet_count}")

if __name__ == "__main__":
    start_capture()