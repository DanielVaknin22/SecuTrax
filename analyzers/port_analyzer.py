from scapy.all import Packet

def analyze_ports(packet: Packet, common_ports: set):
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        tcp_layer = packet['TCP']
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport

        if src_port not in common_ports and dst_port not in common_ports:
            print(f"[!] Suspicious Port Detected: {packet['IP'].src}:{src_port} -> {packet['IP'].dst}:{dst_port}")
