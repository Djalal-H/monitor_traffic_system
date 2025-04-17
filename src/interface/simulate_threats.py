import random
import time
from datetime import datetime
from pymongo import MongoClient

# MongoDB Atlas connection string
client = MongoClient("mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster")

db = client["wlan"]
threats_collection = db["threats"]

# Sample data pool
THREAT_TYPES = ["ARP Spoofing", "Rogue AP", "DoS Attack", "WPA2 Crack Attempt", "MITM"]
SOURCE_IPS = ["192.168.1.10", "192.168.1.15", "192.168.1.25", "10.0.0.5", "172.16.0.2"]
MACS = ["00:11:22:33:44:55", "AA:BB:CC:DD:EE:FF", "DE:AD:BE:EF:00:01", "66:77:88:99:AA:BB"]

print("🌐 Simulating threats every 7 seconds...")

while True:
    threat = {
        "type": random.choice(THREAT_TYPES),
        "source": random.choice(SOURCE_IPS + MACS),
        "confidence": random.randint(70, 99),
        "timestamp": datetime.now()
    }

    result = threats_collection.insert_one(threat)
    print(f"✅ Inserted threat {threat['type']} from {threat['source']} at {threat['timestamp']}")
    
    time.sleep(7)
