# Mobile Exfiltration Detector

Behaviour-Based Mobile Data Exfiltration Detection System Using Network Traffic Analysis.

---

## Team

| Person | Role | Owns |
|--------|------|------|
| You (A) | Detection pipeline | `capture/`, `analysis/`, `detection/`, `main.py`, `whitelist.json` |
| Teammate (B) | Infra + UI | `flask_server/`, `android_app/`, `dashboard/` |
| Both | Shared foundation | `db/db_init.py`, `db/db_helper.py`, `README.md` |

---

## Setup (both teammates run this)

```bash
git clone https://github.com/YOUR_USERNAME/mobile-exfil-detector.git
cd mobile-exfil-detector
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
python db/db_init.py
```

Expected output: `[OK] Database initialised at: db/exfil_detector.db`

---

## Database Schema

### `traffic_logs`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | TEXT | UTC ISO-8601 e.g. `2025-04-11T10:32:00` |
| `src_ip` | TEXT | Source IP (the mobile device) |
| `dst_ip` | TEXT | Destination IP (remote server) |
| `dst_port` | INTEGER | Destination port e.g. 443, 8080 |
| `packet_size` | INTEGER | Packet size in bytes |
| `protocol` | TEXT | `TCP`, `UDP`, `HTTPS` etc. |
| `ip_tag` | TEXT | `KNOWN`, `UNKNOWN`, or `SUSPICIOUS` |

### `alerts`

| Column | Type | Description |
|--------|------|-------------|
| `id` | INTEGER PK | Auto-increment |
| `timestamp` | TEXT | UTC ISO-8601 |
| `rule_name` | TEXT | e.g. `HIGH_VOLUME_UPLOAD` |
| `severity` | TEXT | `HIGH`, `MEDIUM`, or `LOW` |
| `description` | TEXT | Human-readable explanation |
| `src_ip` | TEXT | The source IP that triggered the alert |

---

## Agreed Function Contracts

### `db/db_helper.py` — used by BOTH sides

```python
insert_traffic(src_ip, dst_ip, dst_port, packet_size, protocol, ip_tag="UNKNOWN")
insert_alert(rule_name, severity, description, src_ip)
get_traffic_window(src_ip, minutes=5)   → list[dict]
get_all_active_src_ips(minutes=5)       → list[str]
get_recent_alerts(limit=50)             → list[dict]
get_stats()                             → dict {total_packets, alert_count, unknown_ips}
```

### `analysis/analysis.py` — Person A builds, Person B reads

```python
get_profile(src_ip) → dict {
    upload_bytes:      int,    # total bytes sent in last 5 min
    conn_count:        int,    # number of connections in last 5 min
    unique_dst_count:  int,    # number of distinct destination IPs
    unknown_ip_count:  int,    # destinations tagged UNKNOWN
    night_ratio:       float,  # fraction of traffic between 00:00–05:00
    non_standard_ports: list   # ports that are not 80 or 443
}
```

### `detection/detection_rules.py` — Person A builds, `main.py` calls

```python
check_all_rules(profile) → list[dict]
# Each dict: { rule_name: str, severity: str, description: str }
# Returns empty list [] if traffic is clean
```

### Flask API — Person B builds, Dashboard calls

```
POST /receive                → accepts JSON payload, saves to db, returns 200
GET  /api/traffic            → last 100 traffic_logs rows as JSON
GET  /api/alerts             → last 50 alerts rows as JSON
GET  /api/stats              → { total_packets, alert_count, unknown_ips }
GET  /dashboard              → serves index.html
```

---

## Detection Rules

| Rule name | Trigger condition | Severity |
|-----------|-------------------|----------|
| `HIGH_VOLUME_UPLOAD` | > 500 KB uploaded in 5 min | HIGH |
| `FREQUENT_UNKNOWN_CONNECTIONS` | > 20 connections/min to unknown IP | MEDIUM |
| `NIGHT_TIME_UPLOAD` | Upload between 00:00–05:00 UTC | MEDIUM |
| `NEW_UNKNOWN_DESTINATION` | First-seen unknown destination IP | LOW |
| `NON_STANDARD_PORT` | Upload to port other than 80 or 443 | HIGH |

---

## Project Structure

```
mobile-exfil-detector/
├── capture/
│   └── capture.py           ← Person A: PyShark live capture
├── analysis/
│   └── analysis.py          ← Person A: traffic behaviour metrics
├── detection/
│   ├── detection_rules.py   ← Person A: 5 heuristic rules
│   └── alert_manager.py     ← Person A: writes alerts, console output
├── db/
│   ├── db_init.py           ← SHARED: creates tables
│   └── db_helper.py         ← SHARED: all read/write functions
├── flask_server/
│   └── server.py            ← Person B: Flask API + receiver
├── android_app/             ← Person B: Android Studio project
├── dashboard/
│   └── index.html           ← Person B: live web dashboard
├── whitelist.json           ← Person A: known-safe IPs/domains
├── main.py                  ← Person A: orchestrates all modules
├── requirements.txt
├── .gitignore
└── README.md
```

---

## Running the System

**Terminal 1 — start Flask server (Person B's machine or same machine):**
```bash
python flask_server/server.py
```

**Terminal 2 — start the detection pipeline:**
```bash
python main.py
```

**Then** open the Android emulator, launch the APK, and watch alerts appear in the terminal and at `http://localhost:5000/dashboard`.

---

## Git Workflow

```bash
git pull origin main                      # start of every day
git checkout -b day3-capture-module       # work on a branch
git add capture/capture.py
git commit -m "Day 3: capture.py done"
git push origin day3-capture-module
# when module complete → merge to main
git checkout main && git merge day3-capture-module && git push
```
