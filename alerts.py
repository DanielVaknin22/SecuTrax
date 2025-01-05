from tkinter import messagebox

def alert_suspicious_traffic(packet):
    source = packet["source"]
    destination = packet["destination"]
    message = f"Suspicious traffic detected!\nSource: {source}\nDestination: {destination}"
    messagebox.showwarning("Alert", message)

suspicious_packet = {"source": "192.168.1.10", "destination": "192.168.1.20"}
alert_suspicious_traffic(suspicious_packet)
