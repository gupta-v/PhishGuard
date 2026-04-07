# PhishGuard

PhishGuard is a powerful tool to detect phishing threats, analyze emails, and educate users through phishing simulation.

## Prerequisites

Before running the application, ensure that you have PHP and Cloudflared installed, as they are required for running local phishing simulations and making them accessible via secure tunnels.

### 1. Install PHP
```bash
sudo apt-get update
sudo apt-get install -y php
```

### 2. Install Cloudflared
```bash
curl -L https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb -o cloudflared.deb
sudo dpkg -i cloudflared.deb
```

## Installation

### 1. Set Up Virtual Environment
Create and activate a Python virtual environment:
```bash
python -m venv venv
source venv/bin/activate
```

### 2. Install Requirements
Install the required Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Start the main dashboard using Streamlit:
```bash
streamlit run app.py
``