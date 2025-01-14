import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP
from optparse import OptionParser

state_ok = 0
state_warning = 1
state_critical = 2

THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")

def packet_callback(packet):
    src_ip = packet[IP].src
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        threat_detected = False  # Flag to track if any threat is detected

        for ip, count in packet_count.items():
            packet_rate = count / time_interval
            if packet_rate > THRESHOLD:
                print(f"IP: {ip}, Packet rate: {packet_rate}, Critical Stage: {state_critical}")
                threat_detected = True

        if not threat_detected:
            print("No threat detected")

        # Reset counters every second
        packet_count.clear()
        start_time[0] = current_time

def nagios_exit(state, message):
    print(message)
    sys.exit(state)

if __name__ == "__main__":
    # Parse command-line options
    parser = OptionParser("usage: %prog [options] ARG1 ARG2 FOR EXAMPLE: -c 300 -w 200 -t 50")
    parser.add_option("-c", "--critical", type="int", dest="crit", help="The value to consider a very high connection in the web server")
    parser.add_option("-w", "--warning", type="int", dest="warn", help="The value to consider a high connection in the web server")
    parser.add_option("-t", "--threshold", type="int", dest="threshold", help="Set the packet rate threshold for detecting DDoS-like behavior")
    parser.add_option("-V", "--version", action="store_true", dest="version", help="Show the current version number of the program and exit")
    parser.add_option("-A", "--author", action="store_true", dest="author", help="Show author information and exit")
    (opts, args) = parser.parse_args()

    # Display author and version information
    if opts.author:
        print("Author: Your Name")
        sys.exit()
    if opts.version:
        print(f"check_ddos.py version 1.0")
        sys.exit()

    # Ensure critical is not lower than warning
    if opts.crit and opts.warn:
        if opts.crit < opts.warn:
            print("Critical value < Warning value, please check your config")
            sys.exit(state_critical)
    else:
        if not opts.crit or not opts.warn:
            print("Please provide both -c and -w arguments. Example: -c 300 -w 200")
            sys.exit(state_critical)

    # Set thresholds based on input arguments, or use defaults
    if opts.threshold:
        THRESHOLD = opts.threshold
    else:
        print(f"No threshold provided. Using default threshold: {THRESHOLD}")

    print(f"Monitoring network traffic with a threshold of {THRESHOLD} packets/second...")
    
    # Start monitoring
    try:
        packet_count = defaultdict(int)
        start_time = [time.time()]
        sniff(filter="ip", prn=packet_callback)
    except KeyboardInterrupt:
        nagios_exit(state_ok, "OK: Monitoring stopped by user.")
    except Exception as e:
        nagios_exit(state_critical, f"CRITICAL: An error occurred - {str(e)}")
