import random
from datetime import datetime, timedelta

ips = ["192.168.1.100", "10.0.0.50"]
users = ["admin", "root", "user"]

with open("data/raw/sample_auth.log", "w") as f:
    base_time = datetime(2026, 1, 20, 14, 0, 0)
    # Normal traffic
    for i in range(160):
        t = base_time + timedelta(seconds=i*10)
        ip = random.choice(["192.168.1.1", "10.0.0.10"])
        f.write(f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: Failed password for invalid user guest from {ip} port 22\n")
    
    # Brute-force attack
    attack_time = base_time + timedelta(minutes=5)
    for i in range(7):  # 7 attempts in 90 seconds → should trigger alert
        t = attack_time + timedelta(seconds=i*15)
        f.write(f"{t.strftime('%b %d %H:%M:%S')} server sshd[1234]: Failed password for invalid user {random.choice(users)} from 192.168.1.100 port 22\n")