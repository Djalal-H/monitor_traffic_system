from pymongo import MongoClient
from datetime import datetime

# Correct Atlas URI
client = MongoClient(
    "mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster")

db = client["wlan"]  # Name of your database
threats_collection = db["threats"]  # Name of your collection

# Insert a test threat
result = threats_collection.insert_one({
    "type": "ARP Spoofing",
    "source": "192.168.1.23",
    "confidence": 91,
    "timestamp": datetime.now()
})

print("✅ Inserted:", result.inserted_id)

