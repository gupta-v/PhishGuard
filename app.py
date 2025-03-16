import streamlit as st
import time
import os
import subprocess
from modules.phishing_detection import is_phishing_url, analyze_url
from modules.email_analysis import parse_email_header
from modules.database import get_scan_history, init_db


# Set page configuration to ensure sidebar is visible
st.set_page_config(page_title="PhishGuard Dashboard", layout="wide", initial_sidebar_state="expanded")

# Initialize database on app startup
init_db()

st.title("🚀 PhishGuard - Phishing Simulation & Detection Tool")
st.markdown("A powerful tool to detect phishing threats, analyze emails, and educate users.")

# Ensure "Dashboard" is the default page on first load
if "current_page" not in st.session_state or st.session_state.current_page not in [
    "Dashboard", "Phishing Detection", "Email Header Analysis", "Phishing Simulation", "Training"
]:
    st.session_state.current_page = "Dashboard"

# Sidebar Navigation
st.sidebar.title("Navigation")
menu = st.sidebar.radio(
    "Go to", 
    ["Dashboard", "Phishing Detection", "Email Header Analysis", "Phishing Simulation", "Training"],
    index=["Dashboard", "Phishing Detection", "Email Header Analysis", "Phishing Simulation", "Training"].index(st.session_state.current_page),
    key="current_page"
)

# Dashboard Page (Default Page)
if menu == "Dashboard":
    st.subheader("📊 Overview")
    st.write("Monitor phishing detection activity and scan history.")
    
    col1, col2, col3 = st.columns(3)
    
    # Scan Results
    with col1:
        st.subheader("📜 Recent Scan History")
        history = get_scan_history(limit=5)
        if history:
            for url, is_phish, title, desc, time in history:
                status = "⚠️ Phishing" if is_phish else "✅ Safe"
                st.markdown(f"**🔗 [{url}]({url}) - {status} ({time})**")
                st.write(f"🏷️ **Title:** {title}")
                st.write(f"📝 **Description:** {desc}")
                st.write("---")
        else:
            st.write("No scan history available.")
    
    # CamPhish Reports
    with col2:
        st.subheader("🎭 CamPhish Reports")
        CAMPHISH_PATH = "/home/kali/Downloads/PhishGuard/CamPhish/"
        IP_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.ip.txt")
        LOCATION_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.locations.txt")
        
        st.write("🌍 Captured IPs")
        if os.path.exists(IP_LOG_FILE):
            with open(IP_LOG_FILE, "r") as file:
                st.text("\n".join(file.readlines()[-5:]))
        else:
            st.text("No data available yet.")
        
        st.write("📍 Captured Locations")
        if os.path.exists(LOCATION_LOG_FILE):
            with open(LOCATION_LOG_FILE, "r") as file:
                st.text("\n".join(file.readlines()[-5:]))
        else:
            st.text("No data available yet.")
    
    # BlackEye Reports
    with col3:
        st.subheader("🔥 BlackEye Reports")
        BLACKEYE_PATH = "/home/kali/Downloads/PhishGuard/BlackEye-Python/"
        LOG_FOLDER = os.path.join(BLACKEYE_PATH, "sites/")
        available_sites = [d for d in os.listdir(LOG_FOLDER) if os.path.isdir(os.path.join(LOG_FOLDER, d))]
        
        if available_sites:
            selected_site = st.selectbox("📂 Select Phishing Site:", available_sites)
            if selected_site:
                IP_LOG_FILE = os.path.join(LOG_FOLDER, selected_site, "ip.txt")
                CREDENTIALS_FILE = os.path.join(LOG_FOLDER, selected_site, "usernames.txt")
                
                st.write("🌍 Captured IPs")
                if os.path.exists(IP_LOG_FILE):
                    with open(IP_LOG_FILE, "r") as file:
                        st.text("\n".join(file.readlines()[-5:]))
                else:
                    st.text("No data available yet.")
                
                st.write("🔑 Captured Credentials")
                if os.path.exists(CREDENTIALS_FILE):
                    with open(CREDENTIALS_FILE, "r") as file:
                        st.text("\n".join(file.readlines()[-5:]))
                else:
                    st.text("No data available yet.")
        else:
            st.write("No phishing sites detected.")

# Phishing Detection Page
elif menu == "Phishing Detection":
    st.subheader("🛡️ Phishing URL Scanner")
    url_input = st.text_input("Enter URL to scan:", placeholder="https://example.com")
    
    if st.button("Scan URL"):
        if url_input:
            is_phish = is_phishing_url(url_input)
            analysis = analyze_url(url_input)
            
            if is_phish:
                st.error("⚠️ This URL is flagged as phishing!")
            else:
                st.success("✅ This URL seems safe (Not in blacklist).")
            
            st.write(f"**Title:** {analysis.get('title', 'N/A')}")
            st.write(f"**Meta Description:** {analysis.get('description', 'N/A')}")
            
            if analysis.get("shortened"):
                st.warning("⚠️ This URL appears to be shortened, which is a common phishing tactic.")
        else:
            st.warning("Please enter a valid URL.")
        
    st.subheader("📜 Recent Scan History")
    history = get_scan_history(limit=5)
    if history:
        for url, is_phish, title, desc, time in history:
            status = "⚠️ Phishing" if is_phish else "✅ Safe"
            st.markdown(f"**🔗 [{url}]({url}) - {status} ({time})**")
            st.write(f"🏷️ **Title:** {title}")
            st.write(f"📝 **Description:** {desc}")
            st.write("---")
    else:
            st.write("No scan history available.")

# Email Header Analysis Page
elif menu == "Email Header Analysis":
    st.subheader("📧 Email Header Analyzer")
    email_header = st.text_area("📩 Paste Email Header Here")
    
    if st.button("Analyze Header"):
        if email_header:
            results = parse_email_header(email_header)
            
            st.write(f"**From:** {results.get('from', 'N/A')}")
            st.write(f"**Reply-To:** {results.get('reply_to', 'N/A')}")
            st.write(f"**Return-Path:** {results.get('return_path', 'N/A')}")
            st.write(f"**SPF Record:** {results.get('spf', 'Unknown')}")
            st.write(f"**DKIM Signature:** {results.get('dkim', 'Not Found')}")
            st.write(f"**DMARC Policy:** {results.get('dmarc', 'Unknown')}")
            
            if results["domain_age"] is not None:
                st.write(f"📅 **Domain Age:** {results['domain_age']} days")
                if results['domain_age'] < 30:
                    st.warning("🚨 Domain is newly registered (<30 days old). High risk of phishing.")
            
            if results["warnings"]:
                st.markdown("### 🔍 Security Warnings:")
                for warning in results["warnings"]:
                    st.warning(warning)
                st.error("🚨 Email appears suspicious based on multiple security checks.")
            else:
                st.success("✅ No security issues detected.")
        else:
            st.warning("Please paste an email header to analyze.")

# Phishing Simulation Page
elif menu == "Phishing Simulation":
    st.subheader("🕵️ Phishing Simulation Tools")
    
    # BlackEye Section
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
    st.markdown("## 🔥 Blackeye Phishing Simulation")

    if st.button("Run Blackeye"):
        run_blackeye()

    # Let user select a phishing site from available sites
    available_sites = get_available_sites()
    if available_sites:
        selected_site = st.selectbox("## 📂 Select Phishing Site:", available_sites)

        if selected_site:
            IP_LOG_FILE = os.path.join(LOG_FOLDER, selected_site, "ip.txt")
            CREDENTIALS_FILE = os.path.join(LOG_FOLDER, selected_site, "usernames.txt")

            st.markdown(f"#### 🌍 Captured IPs for {selected_site.capitalize()}")
            st.text("\n".join(get_latest_logs(IP_LOG_FILE)))

            st.markdown(f"#### 🔑 Captured Credentials for {selected_site.capitalize()}")
            st.text("\n".join(get_latest_logs(CREDENTIALS_FILE)))

            # # Auto-refresh logs every 5 seconds using st.rerun()
            # time.sleep(5)
            # st.rerun()
        else:
            st.warning("#### ⚠️ No phishing sites detected. Run Blackeye first!")

    # CamPhish Section
    CAMPHISH_PATH = "/home/kali/Downloads/PhishGuard/CamPhish/"  
    IP_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.ip.txt")  # IP logs
    LOCATION_LOG_FILE = os.path.join(CAMPHISH_PATH, "saved.locations.txt")  # Location logs

    def run_camphish():
        """Launch CamPhish in a normal terminal."""
        st.write("## 🚀 Opening a terminal to run CamPhish...")
        
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
    st.markdown("## 🎭 CamPhish Phishing Simulation")

    if st.button("Run CamPhish"):
        run_camphish()

    st.markdown("#### 🌍 Captured IPs")
    st.text("\n".join(get_latest_logs(IP_LOG_FILE)))

    st.markdown("#### 📍 Captured Locations")
    st.text("\n".join(get_latest_logs(LOCATION_LOG_FILE)))

    # Auto-refresh logs every 5 seconds
    time.sleep(5)
    st.rerun()



# Training Page
elif menu == "Training":
    st.subheader("📖 Phishing Awareness Training")
    st.write("Learn how to recognize phishing threats and test your knowledge.")
    
    # Real-World Phishing Examples
    st.markdown("### 📌 Real-World Phishing Examples")
    examples = [
        ("Fake Bank Email", "Pretending to be from your bank, asking for login credentials.", ["Suspicious sender", "Urgent tone", "Fake login page"]),
        ("Fake Job Offer", "High-paying job scam requesting personal info.", ["Free email domain", "No interview required", "Personal details request"]),
        ("Vishing (Voice Phishing)", "Scammer calls pretending to be from IRS, demanding payment.", ["Threatens legal action", "Asks for personal details", "Pressures for urgent action"]),
        ("Smishing (SMS Phishing)", "Text message from 'Netflix' claiming your subscription is expiring.", ["Generic greeting", "Fake link", "Urgent call to action"]),
        ("CEO Fraud (Whaling)", "A scammer impersonates your CEO requesting a wire transfer.", ["Urgent action", "High-ranking executive", "Request for funds"]),
        ("Tech Support Scam", "A fake call from Microsoft asking for remote access.", ["Caller requests access", "Threatens virus infection", "Asks for payment"]),
    ]
    
    for title, description, signs in examples:
        with st.expander(f"🔹 {title}"):
            st.write(description)
            st.write("**How to spot it?**")
            for sign in signs:
                st.write(f"- {sign}")
    
   # Quiz Section
    st.markdown("### 🎯 Phishing Quiz")
    questions = [
        ("What is a common sign of a phishing email?", ["Bad grammar & urgency", "Sent from government", "Secure HTTPS link"], "Bad grammar & urgency"),
        ("Which URL is likely to be phishing?", ["https://paypal.com", "https://paypa1.com", "https://www.apple.com"], "https://paypa1.com"),
        ("What is vishing?", ["Phishing via email", "Phishing via voice calls", "Phishing via social media"], "Phishing via voice calls"),
        ("What is smishing?", ["Phishing via email", "Phishing via SMS", "Phishing via phone calls"], "Phishing via SMS"),
        ("What should you do if you receive a suspicious email?", ["Click the link to verify", "Report it as phishing", "Reply asking for confirmation"], "Report it as phishing"),
        ("How can you verify a website's legitimacy?", ["Check for HTTPS", "Click any link to test", "Enter credentials to see response"], "Check for HTTPS"),
        ("Which of these is NOT a common phishing method?", ["Vishing (voice phishing)", "Smishing (SMS phishing)", "Pen testing"], "Pen testing"),
        ("What is the best way to check if an email is from a legitimate company?", ["Reply to the email and ask", "Verify the sender’s domain and check for SPF/DKIM/DMARC records", "Click the link and check"], "Verify the sender’s domain and check for SPF/DKIM/DMARC records"),
        ("What should you do if you accidentally click a phishing link?", ["Enter your credentials quickly", "Close the tab and ignore it", "Change your passwords and report the phishing attempt"], "Change your passwords and report the phishing attempt"),
        ("Which of these email attachments is the riskiest?", ["PDF from a known colleague", "ZIP file from an unknown sender", "JPEG image of a product"], "ZIP file from an unknown sender"),
        ("What is a sign of a phishing website?", ["Incorrect grammar and typos in the content", "Uses HTTPS and a padlock symbol", "Has a professional logo"], "Incorrect grammar and typos in the content"),
        ("Which of these is an example of a spear-phishing attack?", ["A generic email from a fake PayPal account", "A targeted email impersonating your boss asking for a money transfer", "An SMS from an unknown number claiming you won a lottery"], "A targeted email impersonating your boss asking for a money transfer")
    ]
    
    score = 0
    for q, options, answer in questions:
        user_answer = st.radio(q, options, index=None)
        if user_answer == answer:
            score += 1
    
    if st.button("Submit Quiz"):
        st.write(f"🎉 Your Score: {score} / {len(questions)}")
        if score == len(questions):
            st.success("✅ Excellent awareness!")
        elif score > 0:
            st.warning("⚠️ Good effort, but room for improvement.")
        else:
            st.error("🚨 You need to learn more about phishing threats.")
    
st.sidebar.info("Select a section to begin.")
