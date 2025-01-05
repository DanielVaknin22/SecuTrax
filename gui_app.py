import tkinter as tk
from tkinter import scrolledtext, messagebox
from tkinter import ttk
from scapy.all import sniff
from threading import Thread
from analyzers.port_analyzer import analyze_ports
from analyzers.ip_analyzer import analyze_ips
from analyzers.pattern_analyzer import analyze_patterns
from utils.constants import COMMON_PORTS, SUSPICIOUS_IPS
from table_view import display_table
from report_generator import save_to_csv
from alerts import alert_suspicious_traffic

class NetworkTrafficApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecuTrax - Network Traffic Analyzer")
        self.root.geometry("800x600")

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

        # Buttons for CSV and Popup
        self.save_button = tk.Button(root, text="Save Results as CSV", command=self.save_csv)
        self.save_button.pack(pady=5)

        # Treeview for displaying packet data
        self.tree = ttk.Treeview(root, columns=("Source", "Destination", "Protocol"), show="headings")
        self.tree.heading("Source", text="Source IP")
        self.tree.heading("Destination", text="Destination IP")
        self.tree.heading("Protocol", text="Protocol")
        self.tree.pack(pady=10, fill=tk.BOTH, expand=True)

        # Store captured packets for CSV saving and table display
        self.packet_data = []

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
            packet_info = {
                "source": packet[1].src,
                "destination": packet[1].dst,
                "protocol": packet[1].proto,
            }
            # Analyze based on selected analysis type
            if analysis_type == "Ports":
                analyze_ports(packet, COMMON_PORTS)
            elif analysis_type == "IPs":
                analyze_ips(packet, SUSPICIOUS_IPS)
            elif analysis_type == "Patterns":
                analyze_patterns(packet)

            # Add results to the output box
            self.output_box.insert(tk.END, f"Packet analyzed: {packet.summary()}\n")
            self.output_box.see(tk.END)

            # Display packet data in the table
            self.tree.insert("", "end", values=(packet_info["source"], packet_info["destination"], packet_info["protocol"]))

            # Store packet data for CSV and display
            self.packet_data.append(packet_info)

            # Check for suspicious traffic
            if packet_info["source"] in SUSPICIOUS_IPS or packet_info["destination"] in SUSPICIOUS_IPS:
                alert_suspicious_traffic(packet_info)

        # Sniff packets until stopped
        while self.is_sniffing:
            sniff(filter="ip", prn=callback, count=1, store=False)

    def save_csv(self):
        save_to_csv(self.packet_data)
        self.output_box.insert(tk.END, "Results saved as CSV file.\n")
        self.output_box.see(tk.END)

    def display_table(self):
        display_table(self.packet_data)

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkTrafficApp(root)
    root.mainloop()
