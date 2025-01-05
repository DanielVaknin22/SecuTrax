import csv

def save_to_csv(data, filename="analysis_results.csv"):
    with open(filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["Source IP", "Destination IP", "Protocol"])
        for packet in data:
            writer.writerow([packet["source"], packet["destination"], packet["protocol"]])
    print(f"Results saved to {filename}")

example_data = [
    {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": "TCP"},
    {"source": "192.168.1.3", "destination": "192.168.1.4", "protocol": "UDP"},
]

save_to_csv(example_data)
