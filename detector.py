from scapy.all import sniff
from collections import defaultdict
import time

THRESHOLD = 100  # packets per IP per second, tweak as needed

packet_counts = defaultdict(int)

def detect_dos(pkt):
    if pkt.haslayer('IP'):
        ip = pkt['IP'].src
        packet_counts[ip] += 1

def monitor_traffic(duration=1):
    start = time.time()
    while True:
        sniff(prn=detect_dos, timeout=duration)
        end = time.time()
        duration_sec = end - start

        if duration_sec >= duration:
            for ip, count in packet_counts.items():
                if count > THRESHOLD:
                    print(f"[!] DOS ATTACK DETECTED from {ip}: {count} packets in {duration_sec:.2f} seconds")
            packet_counts.clear()
            start = time.time()

if __name__ == "__main__":
    print("Starting DOS detection... Press Ctrl+C to stop.")
    try:
        monitor_traffic()
    except KeyboardInterrupt:
        print("\nStopping DOS detection.")


