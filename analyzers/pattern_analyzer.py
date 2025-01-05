from collections import Counter
from scapy.all import Packet

ip_counter = Counter()

def analyze_patterns(packet: Packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        ip_counter[ip_layer.src] += 1

        if ip_counter[ip_layer.src] > 10:
            print(f"[!] Potential DDoS Source Detected: {ip_layer.src} ({ip_counter[ip_layer.src]} packets)")
