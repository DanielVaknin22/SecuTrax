from tkinter import Tk, ttk


def display_table(data):
    table_window = Tk()
    table_window.title("Traffic Analysis Results")

    tree = ttk.Treeview(table_window, columns=("Source", "Destination", "Protocol"), show="headings")
    tree.heading("Source", text="Source IP")
    tree.heading("Destination", text="Destination IP")
    tree.heading("Protocol", text="Protocol")

    for packet in data:
        tree.insert("", "end", values=(packet["source"], packet["destination"], packet["protocol"]))

    tree.pack(expand=True, fill="both")
    table_window.mainloop()

example_data = [
    {"source": "192.168.1.1", "destination": "192.168.1.2", "protocol": "TCP"},
    {"source": "192.168.1.3", "destination": "192.168.1.4", "protocol": "UDP"},
]

display_table(example_data)
