import ctypes
import tkinter as tk
import logging
import json
import bcrypt
import psutil
import socket
import threading
import requests
import subprocess
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp
import os
import sys
import platform

active_ip = ''


def load_credentials():
    try:
        with open('credentials.txt', 'r') as file:
            username = file.readline().strip()
            password = file.readline().strip()
            return username, password
    except FileNotFoundError:
        return None, None


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)


def wifi_tools():
    logging.info('Net Tools button clicked')
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'network_gui.py')
    print("Attempting to launch:", sys.executable, script_path)  # Diagnostic print
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch network_gui.py:", str(e))


def ping_host(host, text_widget):
    if platform.system() == "Windows":
        result = subprocess.run(['ping', '-n', '4', host], stdout=subprocess.PIPE, text=True, encoding='utf-8')
    else:
        result = subprocess.run(['ping', '-c', '4', host], stdout=subprocess.PIPE, text=True, encoding='utf-8')

    append_to_widget(text_widget, result.stdout)


def whois_search(domain, text_widget):
    wsl_command = f"wsl whois {domain}"
    result = subprocess.run(wsl_command, stdout=subprocess.PIPE, text=True, shell=True)
    append_to_widget(text_widget, result.stdout)


def get_nmap(ip):
    ip_range = f"{ip}/24"  # Appending "/24" to scan the entire subnet
    result = subprocess.run(['nmap', '-T4', '-F', ip_range], stdout=subprocess.PIPE, text=True, encoding='utf-8')
    return result.stdout


def open_nmap_scan(text_widget, entry_widget):
    ip = get_active_ip(entry_widget)  # Passing the correct argument
    results = get_nmap(ip)  # Running the nmap scan
    display_nmap_results(text_widget, results, entry_widget)  # Passing the entry widget


def display_nmap_results(text_widget, results, entry_widget):
    ip_range = get_active_ip(entry_widget)  # Calling the function with the correct argument
    nmap_text = get_nmap(ip_range)
    text_widget.delete('1.0', tk.END)

    colors = ['blue', 'green', 'purple', 'red', 'orange']
    for index, line in enumerate(nmap_text.splitlines()):
        color = colors[index % len(colors)]  # Cycle through the colors
        text_widget.insert(tk.END, line + '\n')
        text_widget.tag_add(color, f"{index + 1}.0", f"{index + 1}.end")
        text_widget.tag_config(color, foreground=color)


def get_netstat_ano():
    result = subprocess.run(['netstat', '-ano'], stdout=subprocess.PIPE, text=True, encoding='utf-8')
    return result.stdout


def update_text_with_netstat(text_widget):  # text_widget is a parameter
    ano_text = get_netstat_ano()
    text_widget.delete('1.0', tk.END)
    colors = ['blue', 'green', 'purple', 'red']
    for index, line in enumerate(ano_text.splitlines()):
        color = colors[index % len(colors)]  # Cycle through the colors
        text_widget.insert(tk.END, line + '\n')
        text_widget.tag_add(color, f"{index + 1}.0", f"{index + 1}.end")
        text_widget.tag_config(color, foreground=color)


def get_ipconfig():
    if os.name == 'nt':  # Windows
        result = subprocess.run(['ipconfig', '/all'], stdout=subprocess.PIPE, text=True, encoding='utf-8')
        return result.stdout
    else:  # Unix/Linux/Mac
        result = subprocess.run(['ifconfig', '-a'], stdout=subprocess.PIPE, text=True, encoding='utf-8')
        return result.stdout


def display_ipconfig(text_widget):
    text_widget.delete("1.0", tk.END)
    ipconfig_text = get_ipconfig()
    text_widget.insert(tk.END, ipconfig_text)
    colors = ['blue', 'green', 'purple', 'red']
    for index, line in enumerate(ipconfig_text.splitlines()):
        color = colors[index % len(colors)]  # Cycle through the colors
        text_widget.insert(tk.END, line + '\n')
        text_widget.tag_add(color, f"{index + 1}.0", f"{index + 1}.end")
        text_widget.tag_config(color, foreground=color)


def run_command(command, text_widget):
    cmd = ' '.join(command)
    full_cmd = f'{sys.executable} -c "import subprocess; subprocess.run([\'{cmd}\'], shell=True)"'
    full_command = f'runas /user:Administrator "{full_cmd}"'
    result = subprocess.run(full_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    output = result.stdout + result.stderr
    text_widget.delete('1.0', tk.END)
    text_widget.insert(tk.END, output)


def flush_dns(middle_text_top):
    result = os.popen('ipconfig /flushdns').read()
    middle_text_top.insert(tk.END, result)


def ipconfig_release(text_widget):
    result = subprocess.run(['ipconfig', '/release'], stdout=subprocess.PIPE, text=True, encoding='utf-8')
    append_to_widget(text_widget, result.stdout)


def ipconfig_renew(text_widget):
    result = subprocess.run(['ipconfig', '/renew'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            encoding='utf-8')
    output = result.stdout + result.stderr

    if not output.strip():
        output = "Renewal successful!"  # If there's no output, indicate success

    append_to_widget(text_widget, output)


def display_netstat(right_text_widget):
    cmd = ['netstat', '-b']
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    output = result.stdout + result.stderr
    lines = output.split('\n')

    right_text_widget.tag_configure("EXE", foreground="blue")

    for line in lines:
        if '.exe' in line:
            right_text_widget.insert(tk.END, line + '\n', "EXE")
        else:
            right_text_widget.insert(tk.END, line + '\n')

    right_text_widget.see(tk.END)  # Scrolls to the end of the widget


def get_mac_vendor(mac):
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    return "Unknown"


def get_active_ip(entry_widget):
    ip_address = entry_widget.get()
    return ip_address


def get_active_connections():
    connections = psutil.net_connections(kind='inet')

    # Define a dictionary to map common port numbers to their corresponding services
    port_services = {
        20: 'FTP Data',
        21: 'FTP Control',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        67: 'DHCP Server',
        68: 'DHCP Client',
        69: 'TFTP',
        80: 'HTTP',
        88: 'Kerberos',
        110: 'POP3',
        119: 'NNTP',
        123: 'NTP',
        135: 'MS RPC',
        137: 'NetBIOS',
        138: 'NetBIOS',
        139: 'NetBIOS',
        143: 'IMAP',
        161: 'SNMP',
        162: 'SNMP Trap',
        389: 'LDAP',
        443: 'HTTPS',
        445: 'SMB',
        465: 'SMTPS',
        514: 'Syslog',
        587: 'SMTP (Submission)',
        636: 'LDAPS',
        993: 'IMAPS',
        995: 'POP3S',
        1433: 'SQL Server',
        1521: 'Oracle',
        3306: 'MySQL',
        3389: 'RDP',
        5060: 'SIP',
        5061: 'SIPS',
        5432: 'PostgreSQL',
        5500: 'VNC',
        5900: 'VNC',
        8080: 'HTTP (Alternate)',
        8443: 'HTTPS (Alternate)'
        # Add more port-to-service mappings as needed
    }

    # Sort connections by the local port number
    connections = sorted(connections, key=lambda conn: conn.laddr.port)

    result = "Active Network Connections:\n---------------------------\n"
    for conn in connections:
        local_port = conn.laddr.port
        service_name = port_services.get(local_port, 'Unknown')  # Fetch the service name, if known
        remote_address = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
        result += f"Local: {conn.laddr.ip}:{local_port} ({service_name}) --> Remote: {remote_address}  Status: {conn.status}\n"

    return result


def display_connections(text_widget):
    text_widget.delete("1.0", tk.END)
    connections_text = get_active_connections()
    connections_lines = connections_text.split("\n")

    for line in connections_lines:
        is_external = "N/A" not in line and "Remote: " in line and not line.startswith("Active Network Connections")
        is_listening = "Status: LISTEN" in line

        if is_external:
            remote_ip = line.split("Remote: ")[1].split(":")[0]
            # Check if the connection is using an internal or loopback IP address
            if (remote_ip.startswith("192.168.") or
                    remote_ip.startswith("10.") or
                    remote_ip.startswith("127.") or
                    any(remote_ip.startswith(f"172.{i}.") for i in range(16, 32))):
                is_external = False

        if is_listening:
            text_widget.insert(tk.END, line + "\n", 'red')
        elif is_external:
            text_widget.insert(tk.END, line + " (External Connection)\n", 'blue')
        else:
            text_widget.insert(tk.END, line + "\n")

    # Tag to change the color of external connections
    text_widget.tag_config('blue', foreground='blue')
    # Tag to change the color of listening connections
    text_widget.tag_config('red', foreground='red')


def get_ip_and_subnet_mask(interface_name=None):
    for interface, addrs in psutil.net_if_addrs().items():
        if interface_name and interface != interface_name:
            continue
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                return addr.address, addr.netmask
    return None, None


def scan_network(ip_range, text_widget):
    arp_request = ARP(pdst=ip_range)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame / arp_request

    result = srp(packet, timeout=2, verbose=0)[0]

    scan_results = "Devices Detected:\n-----------------\n"
    for sent, received in result:
        host_found_message = f"Host found: {received.psrc}\n"
        text_widget.insert(tk.END, host_found_message)
        scan_results += host_found_message

    return scan_results


def get_wifi_interface():
    interfaces = psutil.net_if_addrs()
    wifi_interface = None

    print("Available network interfaces:")
    for interface in interfaces.keys():
        print(f"- {interface}")

    selected_interface = input("Please enter the WiFi interface name: ").strip()
    if selected_interface in interfaces:
        wifi_interface = selected_interface
        print(f"Selected interface: {wifi_interface}")
    else:
        print("Invalid interface name. Please make sure to enter the correct name.")

    return wifi_interface


def scan_network_results(text_widget, selected_interface):
    text_widget.delete("1.0", tk.END)
    text_widget.insert(tk.END, "Scanning network, please wait...\n")
    threading.Thread(target=perform_scan, args=(text_widget, selected_interface), daemon=True).start()


def get_network_interfaces():
    interfaces = [interface for interface, _ in psutil.net_if_addrs().items() if interface != 'lo']
    return interfaces


def perform_scan(text_widget, selected_interface):
    # Clear the previous scan results
    text_widget.delete("1.0", tk.END)

    # Get the local IP address and subnet mask
    ip, subnet_mask = get_ip_and_subnet_mask(selected_interface)

    # If the IP or subnet mask is not found, inform the user and return
    if ip is None or subnet_mask is None:
        text_widget.insert(tk.END, f"No valid network interface found for {selected_interface}.\n")
        return

    # Inform the user that the scan has started
    text_widget.insert(tk.END, f"Scanning network {ip} with subnet mask {subnet_mask}...\n")

    # Define the IP range for scanning, assuming a /24 subnet
    ip_range = ip.rsplit('.', 1)[0] + '.1/24'

    # Perform the scan using the existing code for ARP requests
    answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range), timeout=2, verbose=False,
                      iface=selected_interface)

    # Display the scan results
    text_widget.insert(tk.END, "Devices found:\n")
    for sent, received in answered:
        text_widget.insert(tk.END, f"IP: {received.psrc} MAC: {received.hwsrc}\n")

    text_widget.insert(tk.END, "Scan completed.\n")


def save_credentials():
    if save_creds_var.get():
        username = username_entry_main.get()
        password = password_entry.get()  # Get the actual password from the entry
        with open('credentials.txt', 'w') as file:
            file.write(f"{username}\n{password}")


def save_user(username, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        with open('users.json', 'r') as file:
            users = json.load(file)
    except FileNotFoundError:
        users = {}

    users[username] = {'password': hashed_password.decode('utf-8')}

    with open('users.json', 'w') as file:
        json.dump(users, file)


def load_users():
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def login():
    username = username_entry_main.get()
    password = password_entry.get().encode('utf-8')
    users = load_users()
    if username in users and bcrypt.checkpw(password, users[username]['password'].encode('utf-8')):
        status_label.config(text="Login successful!")
        if save_creds_var.get():
            save_credentials()  # Save credentials if the checkbox is checked
        main_gui()
        if 'register_window' in globals() and register_window.winfo_exists():
            register_window.destroy()
    else:
        status_label.config(text="Login failed!")


def handle_register(username_entry, password_entry, confirm_password_entry, status_label, register_window):
    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()

    if password != confirm_password:
        status_label.config(text="Passwords do not match")
        return

    save_user(username, password)
    status_label.config(text="Registration successful!")

    # Close the registration window
    register_window.destroy()

    # Fill the username entry field in the main window
    username_entry_main.insert(0, username)


def register():
    register_window = tk.Tk()
    register_window.state('zoomed')
    register_window.configure(bg='black')

    welcome_label = tk.Label(register_window, text="Welcome to FVS Network Tools", fg="green", bg="black",
                             font=("Helvetica", 20))
    welcome_label.pack(pady=10)

    instruction_label = tk.Label(register_window, text="Register Below", fg="green", bg="black")
    instruction_label.pack(pady=5)

    username_label = tk.Label(register_window, text="Username:", fg="green", bg="black")
    username_label.pack()
    username_entry = tk.Entry(register_window, fg="green", bg="black")
    username_entry.pack()

    password_label = tk.Label(register_window, text="Password:", fg="green", bg="black")
    password_label.pack()
    password_entry = tk.Entry(register_window, show="*", fg="green", bg="black")
    password_entry.pack()

    confirm_password_label = tk.Label(register_window, text="Confirm Password:", fg="green", bg="black")
    confirm_password_label.pack()
    confirm_password_entry = tk.Entry(register_window, show="*", fg="green", bg="black")
    confirm_password_entry.pack()

    status_label = tk.Label(register_window, text="", fg="green", bg="black")
    status_label.pack()

    register_button = tk.Button(register_window, text="Register", fg="green", bg="black",
                                command=lambda: handle_register(username_entry, password_entry, confirm_password_entry,
                                                                status_label, register_window))

    register_button.pack()

    register_window.mainloop()


def append_to_widget(widget, text):
    widget.delete("1.0", tk.END)  # Clear existing content
    widget.insert(tk.END, text)
    widget.see(tk.END)  # Scrolls to the end of the widget


def open_task_manager():
    os.system("start taskmgr /7")


def main_gui():
    logging.basicConfig(filename='app.log', level=logging.INFO)
    logging.info('Starting main_gui function')

    global active_ip
    global app
    app.destroy()

    new_window = tk.Tk()
    new_window.title("FVS Network Tools")
    new_window.state('zoomed')

    # Top Frame
    top_frame = tk.Frame(new_window, bg="black")
    top_frame.pack(fill=tk.X)

    # IP Actions Menu
    ip_actions_menu_button = tk.Menubutton(top_frame, text="IP Actions", bg="black", fg="green")
    ip_actions_menu_button.pack(side=tk.LEFT, padx=10)
    ip_actions_menu = tk.Menu(ip_actions_menu_button, tearoff=0, bg="black", fg="green")
    ip_actions_menu_button.config(menu=ip_actions_menu)
    ip_actions_menu.add_command(label="IP Configuration", command=lambda: display_ipconfig(middle_text_top))
    ip_actions_menu.add_command(label="Release IP", command=lambda: ipconfig_release(middle_text_top))
    ip_actions_menu.add_command(label="Renew IP", command=lambda: ipconfig_renew(middle_text_top))
    ip_actions_menu.add_command(label="Flush DNS", command=lambda: flush_dns(middle_text_top))

    # Interface Dropdown
    interfaces = get_network_interfaces()
    selected_interface = tk.StringVar(new_window)
    selected_interface.set(interfaces[0])
    interface_dropdown = tk.OptionMenu(top_frame, selected_interface, *interfaces)
    interface_dropdown.config(bg="black", fg="green")
    interface_dropdown.pack(side=tk.LEFT, padx=10)

    # Toolbar Buttons
    toolbar_buttons = [
        ("Scan Network", lambda: scan_network_results(middle_text_top, selected_interface.get())),
        ("Active Connections", lambda: display_connections(middle_text_top)),
        ("Netstat -b", lambda: display_netstat(right_text)),
        ("Netstat -ano", lambda: update_text_with_netstat(right_text)),
        ("Open Nmap Scan", lambda: open_nmap_scan(middle_text_top, input_entry)),
        ("Ping", lambda: ping_host(input_entry.get(), middle_text_bottom)),
        ("WHOIS", lambda: whois_search(input_entry.get(), middle_text_bottom)),
        ("Net Tools", wifi_tools),
        ("Process ID Check", open_task_manager)
    ]

    for label, command in toolbar_buttons:
        tk.Button(top_frame, text=label, command=command, bg="black", fg="green").pack(side=tk.LEFT, padx=10)

    # Main Paned Window
    main_paned = tk.PanedWindow(new_window, orient=tk.HORIZONTAL)
    main_paned.pack(fill=tk.BOTH, expand=True)

    # Middle Paned Window
    middle_paned = tk.PanedWindow(main_paned, orient=tk.VERTICAL)
    main_paned.add(middle_paned)

    middle_frame_top = tk.Frame(middle_paned, bg="black")
    middle_paned.add(middle_frame_top)
    middle_frame_bottom = tk.Frame(middle_paned, bg="black")
    middle_paned.add(middle_frame_bottom)

    # Right Frame
    right_frame = tk.Frame(main_paned, width=200, bg="black")
    main_paned.add(right_frame)

    # Entry and Text Widgets
    input_entry = tk.Entry(middle_frame_bottom)
    input_entry.pack()
    middle_scrollbar = tk.Scrollbar(middle_frame_top)
    middle_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    middle_text_top = tk.Text(middle_frame_top, bg="black", fg="green", yscrollcommand=middle_scrollbar.set)
    middle_text_top.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    middle_scrollbar.config(command=middle_text_top.yview)
    right_scrollbar = tk.Scrollbar(right_frame)
    right_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    right_text = tk.Text(right_frame, bg="black", fg="green", yscrollcommand=right_scrollbar.set)
    right_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
    right_scrollbar.config(command=right_text.yview)
    middle_text_bottom = tk.Text(middle_frame_bottom, bg="black", fg="green")
    middle_text_bottom.pack(fill=tk.BOTH, expand=True)

    new_window.mainloop()


def animate_status():
    messages = ["SCAN NETWORK", "ACTIVE CONNECTIONS", "IP CONFIGURATION", "IP RELEASE", "IP RENEW", "NETSTAT -b",
                "NETSTAT -anon", "OPEN Nmap", "PING", "WHOIS", "NET TOOLS", "PROCESS ID CHECK", "PASS GENERATOR",
                "PACKET SNIFFER", "NETSH", "PASS GENERATING WIFI BRUTE FORCER", "PASS-LIST WIFI BRUTE FORCER"
                                                                                "SHOW WIFI PROFILE(WITH LOCAL PASSWORD)",
                "SHOW BSSID", ]
    current_message = status_label.cget("text")
    next_index = (messages.index(current_message) + 1) % len(messages)
    status_label.config(text=messages[next_index])
    app.after(1000, animate_status)


app = tk.Tk()
app.state('zoomed')
app.configure(bg='black')

welcome_label = tk.Label(app, text="Welcome To FVS Networking Tools", fg="green", bg="black", font=("Helvetica", 20))
welcome_label.pack(pady=10)

status_label = tk.Label(app, text="SCAN NETWORK", fg="green", bg="black", font=("Helvetica", 16))
status_label.pack(pady=10)

username_label = tk.Label(app, text="Username:", fg="green", bg="black")
username_label.pack()
username_entry_main = tk.Entry(app, fg="green", bg="black")  # This will be the main username entry
username_entry_main.pack()

password_label = tk.Label(app, text="Password:", fg="green", bg="black")
password_label.pack()
password_entry = tk.Entry(app, show="*", fg="green", bg="black")
password_entry.pack()

username, password = load_credentials()
if username and password:
    username_entry_main.insert(0, username)
    password_entry.insert(0, password)  # Insert the actual password

save_creds_var = tk.IntVar(app)  # Associate IntVar with the app
save_creds_checkbox = tk.Checkbutton(app, text="Save Username", variable=save_creds_var, fg="green",
                                     bg="black")
save_creds_checkbox.pack()

login_button = tk.Button(app, text="Login", command=login, fg="green", bg="black")
login_button.pack()

register_button = tk.Button(app, text="Register", command=register, fg="green", bg="black")
register_button.pack()

# Call the animate_status function after setting up the rest of the GUI
animate_status()

app.mainloop()
