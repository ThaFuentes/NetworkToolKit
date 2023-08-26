import tkinter as tk
from scapy.all import sniff
import psutil
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
import threading
from scapy.layers.inet import ICMP
from scapy.packet import Raw
from tkinter import filedialog
from datetime import datetime, timezone, timedelta
import pytz
from base64 import b64decode

packet_info_buffer = []

continue_sniffing = True


def update_time():
    while True:
        output_text.delete("id", "info")
        root.update()
        time.sleep(1)


def format_timestamp(timestamp):
    selected_timezone = timezone_var.get()
    tz = pytz.timezone(selected_timezone)
    local_time = datetime.fromtimestamp(timestamp, tz=tz)
    return local_time.strftime('%Y-%m-%d %H:%M:%S %Z')


def get_adapters():
    return [i for i in psutil.net_if_addrs()]


def decode_payload(payload):
    try:
        # Try to decode using UTF-8
        decoded_payload = payload.decode('utf-8')
    except UnicodeDecodeError:
        # If that fails, display the hexadecimal representation
        decoded_payload = "Payload could not be decoded, Hex dump: " + payload.hex()

    return decoded_payload


def packet_callback(packet):
    timestamp = packet.time

    # Ethernet Layer Details
    ether_type = packet[Ether].type
    src_mac = packet[Ether].src
    dst_mac = packet[Ether].dst

    layer2_details = f"\tEther type: {ether_type}\n" \
                     f"\tSrc MAC: {src_mac}\n" \
                     f"\tDst MAC: {dst_mac}\n"

    # Extract common IP details
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    ip_flags = translate_ip_flags(packet[IP].flags)
    layer3_details = f"\tversion: {packet[IP].version}\n" \
                     f"\tsrc: {src_ip}\n" \
                     f"\tdst: {dst_ip}\n" \
                     f"\tttl: {packet[IP].ttl}\n" \
                     f"\tflags: {ip_flags}\n"

    # ICMP Details
    icmp_details = ""
    if ICMP in packet:
        icmp_type = packet[ICMP].type
        icmp_code = packet[ICMP].code
        icmp_details = f"\tICMP type: {icmp_type}\n" \
                       f"\tICMP code: {icmp_code}\n"

    # Layer 4 details
    layer4_details, src_port, dst_port = get_layer4_details(packet)

    # Payload Data (if applicable)
    payload_details = get_payload_details(packet)

    # Call the insert_details function with all required parameters
    insert_details(output_text, timestamp, layer2_details, layer3_details, icmp_details, layer4_details,
                   payload_details, src_ip, dst_ip, src_port, dst_port)


def get_layer4_details(packet):
    layer4_details = ""
    src_port = None
    dst_port = None
    if TCP in packet or UDP in packet:
        layer = TCP if TCP in packet else UDP
        src_port = packet[layer].sport
        dst_port = packet[layer].dport
        layer4_details = f"\tsrc port: {src_port}\n" \
                         f"\tdst port: {dst_port}\n"

        # Extract additional TCP details if available
        if TCP in packet:
            tcp_flags = translate_tcp_flags(packet[TCP].flags)
            layer4_details += f"\tflags: {tcp_flags}\n"
    return layer4_details, src_port, dst_port


def insert_details(output_text, timestamp, layer2_details, layer3_details, icmp_details, layer4_details,
                   payload_details, src_ip, dst_ip, src_port, dst_port):
    details = "Packet Timestamp: " + f"{format_timestamp(timestamp)}\n" + \
              layer2_details + layer3_details + icmp_details + layer4_details
    output_text.insert(tk.END, details, "id")

    # Highlight src IP
    output_text.insert(tk.END, f"\tsrc: {src_ip}\n", 'orange')

    # Highlight dst IP
    output_text.insert(tk.END, f"\tdst: {dst_ip}\n", 'orange')

    # Highlight src port
    output_text.insert(tk.END, f"\tsrc port: {src_port}\n", 'red')

    # Highlight dst port
    output_text.insert(tk.END, f"\tdst port: {dst_port}\n", 'red')

    output_text.insert(tk.END, payload_details + "\n", "id")
    output_text.see(tk.END)  # Scroll down to the newest info
    packet_info_buffer.append(details)  # Append details to the packet_info_buffer


def get_payload_details(packet):
    payload_details = ""
    if Raw in packet:
        payload_data = packet[Raw].load
        payload_data_str = payload_data.decode(errors='ignore')

        if 'HTTP/' in payload_data_str:
            http_lines = payload_data_str.split('\r\n')
            for idx, line in enumerate(http_lines):
                if line.startswith('X-Friendly-Name: '):
                    friendly_name_b64 = line.split(': ')[1]
                    friendly_name = b64decode(friendly_name_b64).decode(errors='ignore')
                    http_lines[idx] = f'X-Friendly-Name: {friendly_name}'
                elif line.startswith('User-Agent: '):
                    user_agent_line = '\t' + line
                    http_lines[idx] = user_agent_line
                    output_text.tag_add('orange', output_text.index(tk.END) + '-1c', output_text.index(tk.END))
                    continue

            payload_details = '\n'.join('\t' + line for line in http_lines)
        else:
            payload_details = f"Payload Data: {payload_data}"
    return payload_details


def translate_tcp_flags(flags):
    flag_str = []
    if flags & 0x01: flag_str.append('FIN')
    if flags & 0x02: flag_str.append('SYN')
    if flags & 0x04: flag_str.append('RST')
    if flags & 0x08: flag_str.append('PSH')
    if flags & 0x10: flag_str.append('ACK')
    if flags & 0x20: flag_str.append('URG')
    return ', '.join(flag_str)


def translate_ip_flags(flags):
    flag_str = []
    if flags & 0x02: flag_str.append('DF')
    if flags & 0x01: flag_str.append('MF')
    return ', '.join(flag_str)


def start_sniffing():
    global continue_sniffing  # Declare the variable as global
    global sniffing_status_label
    selected_adapter = adapter_var.get()
    print(f"Starting sniffing on {selected_adapter}")  # Print the starting message
    sniffing_status_label.config(text=f"Started On {selected_adapter}")
    continue_sniffing = True
    try:
        sniff_thread = threading.Thread(
            target=lambda: sniff(iface=selected_adapter, prn=packet_callback, filter="ip", store=0,
                                 stop_filter=lambda x: not continue_sniffing))
        sniff_thread.start()
    except Exception as e:
        print("Error starting sniffing thread:", e)


def stop_sniffing():
    global continue_sniffing  # Declare the variable as global
    global sniffing_status_label
    sniffing_status_label.config(text="Stopped Sniffin")
    continue_sniffing = False  # Modify the global variable
    print("Stopped sniffing.")


def save_to_file():
    global packet_info_buffer

    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

    if file_path:
        with open(file_path, 'w') as file:
            file.write('\n'.join(packet_info_buffer))
        print(f"Saved to {file_path}")


root = tk.Tk()
root.title("Network Packet Sniffer")
root.configure(bg="black")

# Welcome banner
welcome_label = tk.Label(root, text="Welcome to Network Packet Sniffer", bg="black", fg="green",
                         font=("Helvetica", 16))
welcome_label.grid(row=1, column=0, columnspan=2, pady=10)
# Sniffing status label
sniffing_status_label = tk.Label(root, text="", bg="black", fg="green")  # Adjust the style as needed
sniffing_status_label.grid(row=0, column=0, columnspan=2)

# Timezone selection
timezone_frame = tk.Frame(root, bg="black")
timezone_frame.grid(row=4, column=0, columnspan=2, pady=5)

timezone_label = tk.Label(timezone_frame, text="Select Timezone: ", bg="black", fg="green")
timezone_label.grid(row=0, column=0)

timezone_var = tk.StringVar(root)
timezone_var.set("UTC")  # Default timezone
timezone_dropdown = tk.OptionMenu(timezone_frame, timezone_var, *pytz.country_timezones['US'])
timezone_dropdown.config(bg="black", fg="green")
timezone_dropdown.grid(row=0, column=1)

# Adapter selection
adapter_frame = tk.Frame(root, bg="black")
adapter_frame.grid(row=2, column=0, columnspan=2, pady=5)

adapter_label = tk.Label(adapter_frame, text="Select Adapter: ", bg="black", fg="green")
adapter_label.grid(row=0, column=0)

adapter_var = tk.StringVar(root)
adapter_var.set(get_adapters()[0])  # default value
adapter_dropdown = tk.OptionMenu(adapter_frame, adapter_var, *get_adapters())
adapter_dropdown.config(bg="black", fg="green")
adapter_dropdown.grid(row=0, column=1)

output_text = tk.Text(root, bg="black", fg="blue", width=75, height=28)
output_text.grid(row=6, column=0, columnspan=2)
output_text.tag_config('orange', foreground='orange')
output_text.tag_config('purple', foreground='purple')
output_text.tag_config('green', foreground='green')
output_text.tag_config('red', foreground='red')
buttons_frame = tk.Frame(root, bg="black")
buttons_frame.grid(row=3, column=0, columnspan=2, pady=5)

start_button = tk.Button(buttons_frame, text="Start Sniffing", command=start_sniffing, bg="black", fg="green")
start_button.grid(row=0, column=0, padx=5)

stop_button = tk.Button(buttons_frame, text="Stop Sniffing", command=stop_sniffing, bg="black", fg="green")
stop_button.grid(row=0, column=1, padx=5)

save_button = tk.Button(buttons_frame, text="Save to File", command=save_to_file, bg="black", fg="green")
save_button.grid(row=0, column=2, padx=5)  # Add this button

root.mainloop()
