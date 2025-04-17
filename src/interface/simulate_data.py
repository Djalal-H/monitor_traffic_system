import random
import time
from datetime import datetime
from pymongo import MongoClient

# MongoDB Atlas connection
client = MongoClient(
    "mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster"
)

db = client["wlan"]
threats_collection = db["threats"]
logs_collection = db["logs"]

# === Simulated Data Pools ===
THREAT_TYPES = ["ARP Spoofing", "Rogue AP", "DoS Attack", "WPA2 Crack Attempt", "MITM"]
SOURCE_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.25", "10.0.0.5", "172.16.0.2"]
MACS = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "DE:AD:BE:EF:00:01", "66:77:88:99:AA:BB"]

LOG_MESSAGES = [
    "Isolated device 192.168.1.25 for suspicious activity.",
    "Blocked MAC address AA:BB:CC:DD:EE:FF due to rogue AP detection.",
    "DoS attack mitigated using rule #7.",
    "WPA2 crack attempt detected and logged.",
    "Network scan prevented on port 80.",
    "ARP cache poisoned by 192.168.1.15 — countermeasures deployed."
]

print("🧪 Simulating real-time threats and logs...")

while True:
    now = datetime.now()

    # === Insert threat ===
    threat = {
        "type": random.choice(THREAT_TYPES),
        "source": random.choice(SOURCE_IPS + MACS),
        "confidence": random.randint(70, 99),
        "timestamp": now
    }
    threats_collection.insert_one(threat)
    print(f"✅ Threat inserted: {threat['type']} from {threat['source']}")

    # === Insert log ===
    log = {
        "message": random.choice(LOG_MESSAGES),
        "timestamp": now
    }
    logs_collection.insert_one(log)
    print(f"📝 Log inserted: {log['message']}")

    # Wait before next round
    time.sleep(6)
