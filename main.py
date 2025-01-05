from scapy.all import sniff
from analyzers.port_analyzer import analyze_ports
from analyzers.ip_analyzer import analyze_ips
from analyzers.pattern_analyzer import analyze_patterns
from utils.constants import COMMON_PORTS, SUSPICIOUS_IPS
from utils.helpers import print_banner

def main():
    print_banner()
    print("Select analysis type:")
    print("1. Analyze Ports")
    print("2. Analyze IPs")
    print("3. Detect Traffic Patterns (e.g., DDoS)")
    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        print("Starting port analysis...")
        sniff(filter="tcp", prn=lambda p: analyze_ports(p, COMMON_PORTS), count=20)
    elif choice == "2":
        print("Starting IP analysis...")
        sniff(filter="ip", prn=lambda p: analyze_ips(p, SUSPICIOUS_IPS), count=20)
    elif choice == "3":
        print("Starting pattern detection...")
        sniff(filter="ip", prn=analyze_patterns, count=50)
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()
