import json
from scapy.all import sniff

captured_packets = []

def process_packet(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        packet_info = {
            "source": ip_layer.src,
            "destination": ip_layer.dst,
            "protocol": ip_layer.proto
        }
        captured_packets.append(packet_info)
        print(f"[+] Packet: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

print("Starting network traffic capture...")
sniff(filter="ip", prn=process_packet, count=10)

with open("captured_traffic.json", "w") as json_file:
    json.dump(captured_packets, json_file, indent=4)
print("Captured packets saved to 'captured_traffic.json'")
