from scapy.all import sniff

def process_packet(packet):
    if packet.haslayer('IP'):
        ip_layer = packet['IP']
        print(f"[+] Packet: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto}")

print("Starting network traffic capture...")
sniff(filter="ip", prn=process_packet, count=10)