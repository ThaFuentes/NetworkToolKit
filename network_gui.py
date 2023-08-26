import ctypes
import sys
import tkinter as tk
import subprocess
import os


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)


def launch_wifi():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi.py')
    print("Attempting to launch:", sys.executable, script_path)  # Diagnostic print
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch wifi.py:", str(e))


def launch_ssid_login():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi_login.py')
    print("Attempting to launch:", sys.executable, script_path)  # Diagnostic print
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch wifi_login.py:", str(e))


def launch_wifi_pwlist():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wifi_crack_pwlist.py')
    print("Attempting to launch:", sys.executable, script_path)  # Diagnostic print
    try:
        subprocess.Popen([sys.executable, script_path], shell=True)
    except Exception as e:
        print("Failed to launch wifi_crack_pwlist.py:", str(e))


def execute_netsh_command():
    wifi_name = variable_input.get()
    if wifi_name:
        command = f'netsh wlan show profile "{wifi_name}" key=clear'
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate()
        output_text.insert(tk.END, output.decode("utf-8"))
        if error:
            output_text.insert(tk.END, error.decode("utf-8"))
    else:
        output_text.insert(tk.END, "Please enter a Wi-Fi name.\n")
    append_to_widget(output_text, output)
    append_to_widget(output_text, error)


def show_bssid_networks():
    command = 'netsh wlan show networks mode=bssid'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    append_to_widget(output_text, output)
    append_to_widget(output_text, error)


def show_wifi_profiles():
    command = 'netsh wlan show profiles'
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = process.communicate()
    output_text.insert(tk.END, output.decode("utf-8"))
    if error:
        output_text.insert(tk.END, error.decode("utf-8"))
    append_to_widget(output_text, output)
    append_to_widget(output_text, error)


def append_to_widget(widget, content):
    widget.insert(tk.END, content)
    widget.yview_moveto(1)  # Scroll to the bottom


def launch_net_sniffer():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'net_monitor.py')
    print("Attempting to launch:", sys.executable, script_path)
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print("Failed to launch net_sniffer.py:", str(e))


def launch_password():
    script_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'password.py')
    print("Attempting to launch:", sys.executable, script_path)
    try:
        subprocess.Popen([sys.executable, script_path])
    except Exception as e:
        print("Failed to launch password.py:", str(e))


root = tk.Tk()
root.title("FVS Network Tools Menu")
root.configure(bg="black")

welcome_label = tk.Label(root, text="Welcome To FVS Network Tools", fg="green", bg="black", font=("Helvetica", 16))
welcome_label.pack(pady=20)

button_frame_top = tk.Frame(root, bg="black")
button_frame_top.pack(side=tk.TOP, fill=tk.BOTH, padx=10, pady=10)

wifi_button = tk.Button(button_frame_top, text="Pass Gen Wi-Fi Brute Forcer", fg="green", bg="black",
                        command=launch_wifi)
wifi_button.grid(row=0, column=0, padx=5)

wifi_button_pwlist = tk.Button(button_frame_top, text="Pass List Wi-Fi Brute Forcer", fg="green", bg="black",
                               command=launch_wifi_pwlist)
wifi_button_pwlist.grid(row=0, column=1, padx=5)

show_profiles_button = tk.Button(button_frame_top, text="Show Wi-Fi Profiles", fg="green", bg="black",
                                 command=show_wifi_profiles)
show_profiles_button.grid(row=0, column=2, padx=5)

bssid_button = tk.Button(button_frame_top, text="Show BSSID Networks", fg="green", bg="black",
                         command=show_bssid_networks)
bssid_button.grid(row=0, column=3, padx=5)

output_text = tk.Text(root, height=20, width=75, wrap=tk.WORD, fg="green", bg="black")
output_text.pack()

variable_label = tk.Label(root, text="Profile Name For netsh Button:", fg="green", bg="black")
variable_label.pack(pady=5)

variable_input = tk.Entry(root, fg="green", bg="black")
variable_input.pack()

netsh_button = tk.Button(root, text="Run NETSH Command", fg="green", bg="black", command=execute_netsh_command)
netsh_button.pack(pady=5)

button_frame_bottom = tk.Frame(root, bg="black")
button_frame_bottom.pack(side=tk.BOTTOM, fill=tk.BOTH, padx=10, pady=10)

password_button = tk.Button(button_frame_bottom, text="Password Tools", fg="green", bg="black", command=launch_password)
password_button.pack(side=tk.LEFT, padx=5)

net_sniffer_button = tk.Button(button_frame_bottom, text="Network Monitor", fg="green", bg="black", command=launch_net_sniffer)
net_sniffer_button.pack(side=tk.LEFT, padx=5)

exit_button = tk.Button(button_frame_bottom, text="Exit", fg="red", bg="black", command=root.quit)
exit_button.pack(side=tk.RIGHT, padx=5)

ssid_pass_button = tk.Button(button_frame_bottom, text="Wifi SSID/Pass Login", fg="green", bg="black",
                             command=launch_ssid_login)
ssid_pass_button.pack(side=tk.RIGHT, padx=5)

root.mainloop()
