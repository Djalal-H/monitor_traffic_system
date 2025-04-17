from pymongo import MongoClient
from datetime import datetime

# Correct Atlas URI
client = MongoClient(
    "mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster")

db = client["wlan"]
threats_collection = db["threats"]

# function to insert a threat and its details into the database


def insert_threat(threat_type, packet, confidence, actions):
    try:
        # Ensure 'packet' contains the required fields
        ip_address = packet.get('ip', 'Unknown')
        mac_address = packet.get('wlan.sa', 'Unknown')

        # Ensure actions is a list, otherwise set it to an empty list
        if not isinstance(actions, list):
            actions = []

        # Insert into the threats collection
        threats_collection.insert_one({
            "type": threat_type,
            "IP_source": ip_address,
            "MAC_source": mac_address,
            "confidence": confidence,
            "timestamp": datetime.now(),
            "actions": actions,
        })
        print(f"Threat of type '{threat_type}' inserted successfully.")
        return True
    except Exception as e:
        print(f"An error occurred while inserting the threat: {e}")
        insert_log(f"Error inserting threat: {e}")
        return False


# Function to insert logs into the logs collection
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
