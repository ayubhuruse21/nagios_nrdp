import os
import sys
import time
import requests
from collections import defaultdict
from scapy.all import sniff, IP
import re

# Configuration
THRESHOLD = 5
TIME_WINDOW = 300  # 5 minutes in seconds
NRDP_URL = "http://10.0.0.152/nrdp/"
TOKEN = "Logserver"
LOG_FILE = "/var/log/auth.log"  # Log file for failed login attempts
print(f"THRESHOLD: {THRESHOLD} attempts within {TIME_WINDOW} seconds")

# Function to send notifications to Nagios via NRDP
def send_nrdp_notification(ip_address, alert_type, details):
    payload = {
        "token": TOKEN,
        "cmd": "submitcheck",
        "hostname": "Failed Login Detector",
        "service": f"{alert_type}: {ip_address}",
        "state": 1 if alert_type == "Warning" else 2,  # 1 for warning, 2 for critical
        "output": f"{alert_type} detected from IP: {ip_address}. Details: {details}"
    }
    try:
        response = requests.post(NRDP_URL, data=payload)
        if response.status_code == 200:
            print(f"Notification sent to Nagios for IP: {ip_address}")
        else:
            print(f"Failed to send notification to Nagios: {response.text}")
    except Exception as e:
        print(f"Error sending notification to Nagios: {e}")

# Parse logs for failed login attempts
def parse_logs():
    with open(LOG_FILE, "r") as file:
        lines = file.readlines()
        
    return lines

# Process logs for failed login attempts
def process_log_for_failed_logins(lines):
    failed_logins = defaultdict(list)
    for line in lines:
        if 'Failed password' in line:
            match = re.search(r'from (\S+)', line)
            if match:
                ip_address = match.group(1)
                failed_logins[ip_address].append(time.time())
                
    return failed_logins

# Packet callback function to capture network traffic (optional)
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        current_time = time.time()

        # Record the attempt
        failed_attempts[src_ip].append(current_time)

        # Keep only attempts within the last 5 minutes
        failed_attempts[src_ip] = [timestamp for timestamp in failed_attempts[src_ip] if current_time - timestamp <= TIME_WINDOW]

        # Check if the IP has reached the warning threshold
        if len(failed_attempts[src_ip]) == THRESHOLD and src_ip not in blocked_ips:
            print(f"Warning: {src_ip} has reached {THRESHOLD} failed login attempts")
            send_nrdp_notification(src_ip, "Warning", f"{THRESHOLD} failed login attempts within {TIME_WINDOW} seconds")

        # Check if the IP has exceeded the threshold
        if len(failed_attempts[src_ip]) > THRESHOLD and src_ip not in blocked_ips:
            print(f"Blocking IP: {src_ip} due to {len(failed_attempts[src_ip])} failed attempts")
            os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
            blocked_ips.add(src_ip)
            send_nrdp_notification(src_ip, "Critical", f"Exceeded {THRESHOLD} failed login attempts")

# Main function to monitor and process login attempts
if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script requires root privileges.")
        sys.exit(1)

    failed_attempts = defaultdict(list)
    blocked_ips = set()

    print("Monitoring failed login attempts...")

    # This part reads logs and checks for failed login attempts
    while True:
        lines = parse_logs()
        failed_logins = process_log_for_failed_logins(lines)

        # Process the failed login attempts and apply threshold logic
        for ip, attempts in failed_logins.items():
            current_time = time.time()
            attempts = [t for t in attempts if current_time - t <= TIME_WINDOW]

            # If the number of failed attempts exceeds the threshold
            if len(attempts) >= THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip} due to {len(attempts)} failed login attempts")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                blocked_ips.add(ip)
                send_nrdp_notification(ip, "Critical", f"Exceeded {THRESHOLD} failed login attempts")

        # Sleep for a short period to avoid excessive CPU usage
        time.sleep(10)  # Sleep for 10 seconds before checking logs again

    # Optionally, sniff for network traffic (e.g., SSH failed login packets)
    # sniff(filter="ip", prn=packet_callback)  # Uncomment this line if you want to use packet sniffing
