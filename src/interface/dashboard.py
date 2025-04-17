import streamlit as st
import pandas as pd
import time
from datetime import datetime
from pymongo import MongoClient

# === MongoDB Atlas connection ===
client = MongoClient(
    "mongodb+srv://meriemmebarekmansouri:29iaQY5ctCUjahgq@wlancluster.lde9m8t.mongodb.net/?retryWrites=true&w=majority&appName=WLANCluster"
)

db = client["wlan"]
threats_collection = db["threats"]
logs_collection = db["logs"]

# === Streamlit page config ===
st.set_page_config(page_title="WLAN Security Dashboard", layout="wide")
st.title("📡 AI-Powered WLAN Security Dashboard")

# === Sidebar (static) ===
st.sidebar.title("System Info")
st.sidebar.markdown("Status: 🟢 Active")

# === Live-updating content ===
placeholder = st.empty()

while True:
    with placeholder.container():
        # === Threats Table ===
        st.subheader("🚨 Detected Threats")

        raw_threats = list(threats_collection.find().sort(
            "timestamp", -1).limit(10))

        if raw_threats:
            # Convert ObjectId and format timestamp
            for r in raw_threats:
                r["_id"] = str(r["_id"])
                r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")

                # Add the 'actions' field if it exists in the document (handle missing field gracefully)
                r["actions"] = r.get("actions", [])

            # Create DataFrame from full MongoDB records
            df_threats = pd.DataFrame(raw_threats)

            # ✅ Show only selected columns, including the 'actions' column
            display_columns = ["type", "source",
                               "confidence", "timestamp", "actions"]
            st.dataframe(df_threats[display_columns],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No threats detected yet.")

        # === Logs Display ===
        st.subheader("📋 System Logs")

        log_cursor = logs_collection.find().sort("timestamp", -1).limit(10)
        log_entries = list(log_cursor)

        if log_entries:
            # Convert to DataFrame
            for log in log_entries:
                log["_id"] = str(log["_id"])
                if "timestamp" in log:
                    log["timestamp"] = log["timestamp"].strftime(
                        "%Y-%m-%d %H:%M:%S")

            df_logs = pd.DataFrame(log_entries)

            # Only display relevant fields
            display_log_cols = ["timestamp", "message"]
            st.dataframe(df_logs[display_log_cols],
                         use_container_width=True, hide_index=True)
        else:
            st.info("No recent logs.")

        # === Traffic Stats: Real Threat Count Over Time ===
        st.subheader("📈 Threats Detected Per Minute")

        raw_threats = list(threats_collection.find().sort(
            "timestamp", -1).limit(100))

        if raw_threats:
            df = pd.DataFrame(raw_threats)

            if "timestamp" in df.columns:
                df["timestamp"] = pd.to_datetime(df["timestamp"])
                df["minute"] = df["timestamp"].dt.floor("min")
                threats_per_minute = df.groupby(
                    "minute").size().reset_index(name="count")

                st.line_chart(threats_per_minute.set_index("minute"))

                # === Bar Chart: Threat Type Distribution ===
                st.subheader("📊 Threat Type Distribution")

                if "type" in df.columns:
                    type_counts = df["type"].value_counts().reset_index()
                    type_counts.columns = ["Threat Type", "Count"]
                    st.bar_chart(type_counts.set_index("Threat Type"))
                else:
                    st.warning("Threat type field not found in data.")
            else:
                st.warning("Timestamps missing from data.")
        else:
            st.info("No recent threat data available.")

    time.sleep(5)
