from scapy.all import Packet

def analyze_ips(packet: Packet, suspicious_ips: set):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        if ip_layer.src in suspicious_ips or ip_layer.dst in suspicious_ips:
            print(f"[!] Suspicious IP Detected: {ip_layer.src} -> {ip_layer.dst}")
