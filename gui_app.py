import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff
from threading import Thread
from analyzers.port_analyzer import analyze_ports
from analyzers.ip_analyzer import analyze_ips
from analyzers.pattern_analyzer import analyze_patterns
from utils.constants import COMMON_PORTS, SUSPICIOUS_IPS

class NetworkTrafficApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecuTrax - Network Traffic Analyzer")
        self.root.geometry("600x400")

        self.selected_analysis = tk.StringVar(value="Ports")
        self.is_sniffing = False

        # Dropdown menu
        self.analysis_menu = tk.OptionMenu(
            root, self.selected_analysis, "Ports", "IPs", "Patterns"
        )
        self.analysis_menu.pack(pady=10)

        # Buttons
        self.start_button = tk.Button(root, text="Start Analysis", command=self.start_analysis)
        self.start_button.pack(pady=5)

        self.stop_button = tk.Button(root, text="Stop Analysis", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(pady=5)

        # Output text box
        self.output_box = scrolledtext.ScrolledText(root, width=70, height=15)
        self.output_box.pack(pady=10)

    def start_analysis(self):
        self.is_sniffing = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.output_box.insert(tk.END, "Starting analysis...\n")
        self.output_box.see(tk.END)

        # Start sniffing in a separate thread
        analysis_type = self.selected_analysis.get()
        self.sniff_thread = Thread(target=self.sniff_packets, args=(analysis_type,))
        self.sniff_thread.daemon = True
        self.sniff_thread.start()

    def stop_analysis(self):
        self.is_sniffing = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.output_box.insert(tk.END, "Stopping analysis...\n")
        self.output_box.see(tk.END)

    def sniff_packets(self, analysis_type):
        def callback(packet):
            if analysis_type == "Ports":
                analyze_ports(packet, COMMON_PORTS)
            elif analysis_type == "IPs":
                analyze_ips(packet, SUSPICIOUS_IPS)
            elif analysis_type == "Patterns":
                analyze_patterns(packet)
            # Add results to the output box
            self.output_box.insert(tk.END, f"Packet analyzed: {packet.summary()}\n")
            self.output_box.see(tk.END)

        # Sniff packets until stopped
        while self.is_sniffing:
            sniff(filter="ip", prn=callback, count=1, store=False)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficApp(root)
    root.mainloop()
