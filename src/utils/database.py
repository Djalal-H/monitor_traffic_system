from pymongo import MongoClient
from datetime import datetime

# Correct Atlas URI
client = MongoClient(
    "mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster")

db = client["wlan"]
threats_collection = db["threats"]

# function to insert a threat and it's details to the database


def insert_threat(threat_type, packet, confidence, actions):
    try:
        threats_collection.insert_one({
            "type": threat_type,
            "IP source": packet['ip'],
            "MAC source": packet['wlan.sa'],
            "confidence": confidence,
            "timestamp": datetime.now(),
            "actions": actions,
        })
        return True
    except Exception as e:
        print(f"An error occurred while inserting the threat: {e}")
        return False


def insert_log(message):
    try:
        db.logs.insert_one({
            "message": message,
            "timestamp": datetime.now()
        })
        return True
    except Exception as e:
        print(f"An error occurred while inserting the log: {e}")
        return False
