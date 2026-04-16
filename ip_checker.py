import json
import os
import socket

WHITELIST_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.json")

_whitelist = None

def _load_whitelist():
    """Load whitelist.json once and cache it."""
    global _whitelist
    if _whitelist is None:
        try:
            with open(WHITELIST_PATH, "r") as f:
                _whitelist = json.load(f)
        except Exception as e:
            print(f"[!] Could not load whitelist.json: {e}")
            _whitelist = {"trusted_ip_prefixes": [], "trusted_domains": [], "suspicious_ports": []}
    return _whitelist


def is_private_ip(ip):
    """Return True if IP is a private/local address."""
    private_prefixes = ("192.168.", "10.", "172.16.", "127.", "0.0.0.0",
                        "169.254.", "224.", "239.", "255.")
    return any(ip.startswith(p) for p in private_prefixes)


def is_trusted_ip(ip):
    """Return True if IP matches any trusted prefix in whitelist.json."""
    wl = _load_whitelist()
    if is_private_ip(ip):
        return True
    return any(ip.startswith(prefix) for prefix in wl.get("trusted_ip_prefixes", []))


def reverse_dns(ip):
    """
    Try to resolve IP to a hostname.
    Returns hostname string or None if lookup fails.
    """
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname.lower()
    except Exception:
        return None


def is_trusted_domain(hostname):
    """Return True if hostname ends with any trusted domain in whitelist.json."""
    if not hostname:
        return False
    wl = _load_whitelist()
    return any(hostname.endswith(domain) for domain in wl.get("trusted_domains", []))


def is_suspicious_port(port):
    """Return True if port is in the known suspicious ports list."""
    if port is None:
        return False
    wl = _load_whitelist()
    return port in wl.get("suspicious_ports", [])


def tag_ip(dst_ip, dst_port=None):
    """
    Main function — returns a tag for a destination IP:

      KNOWN      — trusted IP prefix or trusted domain
      SUSPICIOUS — known malware/C2 port detected
      UNKNOWN    — not recognised as trusted

    This replaces the simple tag_ip() in capture.py.
    Call this from capture.py for smarter tagging.
    """
    if is_private_ip(dst_ip):
        return "KNOWN"

    if dst_port and is_suspicious_port(dst_port):
        return "SUSPICIOUS"

    if is_trusted_ip(dst_ip):
        return "KNOWN"

    hostname = reverse_dns(dst_ip)
    if is_trusted_domain(hostname):
        return "KNOWN"

    return "UNKNOWN"


def get_ip_info(dst_ip, dst_port=None):
    """
    Return a full info dict about a destination IP.
    Useful for logging and dashboard display.
    """
    hostname = reverse_dns(dst_ip)
    tag = tag_ip(dst_ip, dst_port)
    return {
        "ip":       dst_ip,
        "hostname": hostname or "unknown",
        "tag":      tag,
        "port":     dst_port
    }


if __name__ == "__main__":
    print("[*] Testing ip_checker.py\n")

    test_ips = [
        ("8.8.8.8",        443,  "Google DNS — should be KNOWN"),
        ("192.168.1.1",    None, "Router — should be KNOWN"),
        ("140.82.112.21",  443,  "GitHub — should be KNOWN"),
        ("45.33.32.156",   80,   "Unknown server — should be UNKNOWN"),
        ("185.220.101.1",  4444, "Suspicious port — should be SUSPICIOUS"),
        ("1.1.1.1",        443,  "Cloudflare — should be KNOWN"),
        ("10.0.2.15",      None, "Android emulator — should be KNOWN"),
    ]

    print(f"  {'IP':<20} {'Port':<8} {'Tag':<12} {'Hostname':<30} Notes")
    print(f"  {'-'*20} {'-'*8} {'-'*12} {'-'*30} {'-'*30}")

    for ip, port, notes in test_ips:
        info = get_ip_info(ip, port)
        print(f"  {ip:<20} {str(port):<8} {info['tag']:<12} {info['hostname']:<30} {notes}")

    print("\n[*] Done.")
