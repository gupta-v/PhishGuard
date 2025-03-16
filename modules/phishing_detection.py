import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from modules.database import save_scan_result

# Phishing Database APIs
PHISHING_APIS = [
    "https://openphish.com/feed.txt",
    "https://www.phishtank.com/api_info.php"
     "https://openphish.com/feed.txt",
    "https://phish.sinking.yachts/v2/all",
    "https://urlhaus-api.abuse.ch/v1/urls/recent/"
]

GOOGLE_SAFE_BROWSING_API_KEY = "YOUR_API_KEY"
GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

SHORTENED_URL_SERVICES = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly"]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36"
}

def is_shortened_url(url):
    """Check if a URL is from a known URL shortener."""
    domain = urlparse(url).netloc.lower()
    return any(shortener in domain for shortener in SHORTENED_URL_SERVICES)

def is_phishing_url(url):
    """Check if a URL is in known phishing databases or flagged by Google Safe Browsing."""
    # Check against OpenPhish and PhishTank
    for api in PHISHING_APIS:
        try:
            response = requests.get(api, timeout=5, headers=HEADERS)
            response.raise_for_status()
            phishing_urls = response.text.split("\n")
            if url.strip() in phishing_urls:
                return True
        except requests.exceptions.RequestException:
            pass  # Fail gracefully
    
    # Check against Google Safe Browsing API
    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        response = requests.post(
            f"{GOOGLE_SAFE_BROWSING_URL}?key={GOOGLE_SAFE_BROWSING_API_KEY}",
            json=payload,
            timeout=5
        )
        if response.status_code == 200 and response.json().get("matches"):
            return True
    except requests.exceptions.RequestException:
        pass  # Fail gracefully
    
    return False

def analyze_url(url):
    """Extract page metadata and check if a URL is phishing."""
    try:
        response = requests.get(url, timeout=5, headers=HEADERS)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.text, "html.parser")
        title = soup.title.string.strip() if soup.title else "No Title"
        meta_desc = soup.find("meta", {"name": "description"})
        description = meta_desc["content"].strip() if meta_desc else "No Description"
        
        # Extract OpenGraph description if available
        og_desc = soup.find("meta", property="og:description")
        if og_desc and og_desc.get("content"):
            description = og_desc["content"].strip()
        
        # Check for phishing
        is_phish = is_phishing_url(url)
        
        # Save the result in the database
        save_scan_result(url, is_phish, title, description)
        
        return {
            "title": title,
            "description": description,
            "is_phishing": is_phish,
            "shortened": is_shortened_url(url)
        }
    except requests.exceptions.RequestException as e:
        return {"error": f"Request failed: {e}"}
    except Exception as e:
        return {"error": f"Unexpected error: {e}"}