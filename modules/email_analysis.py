import re
import whois
from datetime import datetime

FREE_EMAIL_PROVIDERS = ["gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "aol.com"]

def get_domain_age(domain):
    """Check the domain registration age using WHOIS."""
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.utcnow() - creation_date).days
            return age_days
    except Exception:
        pass
    return None

def parse_email_header(header_text):
    results = {
        "from": None,
        "reply_to": None,
        "return_path": None,
        "spf": "Unknown",
        "dkim": "Not Found",
        "dmarc": "Unknown",
        "spoofed": False,
        "warnings": [],
        "risk_score": 0,
        "domain_age": None
    }

    # Extract key fields
    from_match = re.search(r"From: .*?<(.*?)>", header_text, re.IGNORECASE)
    reply_to_match = re.search(r"Reply-To: .*?<(.*?)>", header_text, re.IGNORECASE)
    return_path_match = re.search(r"Return-Path: <(.*?)>", header_text, re.IGNORECASE)
    spf_match = re.search(r"Received-SPF: (\w+)", header_text, re.IGNORECASE)
    dkim_match = re.search(r"DKIM-Signature:", header_text, re.IGNORECASE)
    dmarc_match = re.search(r"dmarc=(\w+)", header_text, re.IGNORECASE)
    php_mail_match = re.search(r"X-Mailer: PHP|X-PHP-Originating-Script:", header_text, re.IGNORECASE)

    # Assign values
    if from_match:
        results["from"] = from_match.group(1).strip().lower()
    if reply_to_match:
        results["reply_to"] = reply_to_match.group(1).strip().lower()
    if return_path_match:
        results["return_path"] = return_path_match.group(1).strip().lower()
    if spf_match:
        results["spf"] = spf_match.group(1).strip()
    if dkim_match:
        results["dkim"] = "Present"
    if dmarc_match:
        results["dmarc"] = dmarc_match.group(1).strip()

    # Check domain age
    if results["from"]:
        domain = results["from"].split("@")[-1]
        results["domain_age"] = get_domain_age(domain)
        if results["domain_age"] is not None and results["domain_age"] < 30:
            results["warnings"].append("🚨 Domain is newly registered (<30 days old). High risk of phishing.")
            results["risk_score"] += 2
    
    # Spoofing & Mismatch Detection
    if results["from"] and results["reply_to"] and results["reply_to"] != "None":
        if results["from"] != results["reply_to"]:
            results["spoofed"] = True
            results["warnings"].append("🚨 Possible Spoofing Detected: 'Reply-To' is different from 'From'.")
            results["risk_score"] += 2
    if results["from"] and results["return_path"] and results["from"].split("@")[-1] != results["return_path"].split("@")[-1]:
        results["warnings"].append("🚨 Return-Path mismatch with 'From' field. Possible phishing attempt.")
        results["risk_score"] += 2
    
    # SPF & DMARC Checks
    if results["spf"].lower() == "fail":
        results["warnings"].append("❌ SPF check failed. Email source might not be legitimate.")
        results["risk_score"] += 2
    if results["dmarc"].lower() == "fail":
        results["warnings"].append("🚨 DMARC check failed. Email may be spoofed.")
        results["risk_score"] += 2
    if results["dkim"] == "Not Found":
        results["warnings"].append("⚠️ Missing DKIM signature. Email authenticity cannot be verified.")
        results["risk_score"] += 1
    
    # Free email provider detection
    if results["from"] and any(provider in results["from"] for provider in FREE_EMAIL_PROVIDERS):
        results["warnings"].append("⚠️ Sender is using a free email service, which may not be an official organization email.")
        results["risk_score"] += 1
    
    # PHP mail detection
    if php_mail_match:
        results["warnings"].append("🔍 Email appears to be sent via a PHP script, commonly used in phishing emails.")
        results["risk_score"] += 2
    
    return results