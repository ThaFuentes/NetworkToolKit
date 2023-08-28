import tkinter as tk
from pywifi import const, PyWiFi, Profile
import time


def clear_output():
    output_field.delete(1.0, tk.END)


def connect_saved_profile(ssid, password):
    connect_to_wifi(ssid, password)


def remove_saved_profile(ssid):
    try:
        with open("saved_profiles.txt", "r") as file:
            profiles = [line.strip() for line in file.readlines()]

        # Removing profiles that match the specified SSID
        profiles = [profile for profile in profiles if profile.split(':')[0] != ssid]

        with open("saved_profiles.txt", "w") as file:
            file.write("\n".join(profiles))

        output_field.insert(tk.END, f"Removed profile for {ssid}.\n")
        display_saved_profiles()  # Refresh the displayed profiles
    except FileNotFoundError:
        output_field.insert(tk.END, "No saved profiles found.\n")


def display_saved_profiles():
    # Clear existing widgets from the profile_container
    for widget in profile_container.winfo_children():
        widget.destroy()

    try:
        with open("saved_profiles.txt", "r") as file:
            profiles = [line.strip() for line in file.readlines()]

        for profile in profiles:
            ssid, password = profile.split(':')
            profile_frame = tk.Frame(profile_container, bg="black") # Notice this change
            profile_frame.pack()
            remove_button = tk.Button(profile_frame, text="[X]", fg="red", bg="black", command=lambda s=ssid: remove_saved_profile(s))
            remove_button.pack(side=tk.LEFT)
            profile_label = tk.Label(profile_frame, text=f"{ssid} : {password}", fg="green", bg="black")
            profile_label.pack(side=tk.LEFT)
            connect_button = tk.Button(profile_frame, text="[Connect]", fg="green", bg="black", command=lambda s=ssid, p=password: connect_saved_profile(s, p))
            connect_button.pack(side=tk.LEFT)
    except FileNotFoundError:
        output_field.insert(tk.END, "No saved profiles found.\n")


def remove_button_action():
    ssid_to_remove = remove_ssid_entry.get().strip()  # Get the SSID from the entry field
    remove_profile(ssid_to_remove)  # Call the remove_profile function


def insert_output(text):
    output_field.insert(tk.END, text)
    output_field.see(tk.END)


def connect_to_wifi(ssid, password):
    wifi = PyWiFi()
    iface = wifi.interfaces()[0]
    iface.disconnect()
    profile = Profile()
    profile.ssid = ssid
    profile.auth = const.AUTH_ALG_OPEN
    profile.akm.append(const.AKM_TYPE_WPA2PSK)
    profile.cipher = const.CIPHER_TYPE_CCMP
    profile.key = password

    profile = iface.add_network_profile(profile)
    iface.connect(profile)

    for _ in range(5):
        time.sleep(1)
        if iface.status() == const.IFACE_CONNECTED:
            insert_output(f"Connected to {ssid} successfully!\n")
            save_button.config(state=tk.NORMAL)  # Enable save button after successful connection
            return True

    insert_output(f"Failed to connect to {ssid}.\n")
    return False


def login():
    ssid = ssid_entry.get().strip()  # Strip leading and trailing whitespaces
    password = password_entry.get()
    connect_to_wifi(ssid, password)


def save_profile():
    ssid = ssid_entry.get().strip()  # Strip leading and trailing whitespaces
    password = password_entry.get()

    if ssid and password:  # Only save if both fields are not empty
        try:
            with open("saved_profiles.txt", "r") as file:
                profiles = [line.strip() for line in file.readlines()]

            # Check if profile already exists
            if f"{ssid}:{password}" in profiles:
                output_field.insert(tk.END, f"Profile for {ssid} already exists.\n")
                return

            # Append new profile
            profiles.append(f"{ssid}:{password}")

            with open("saved_profiles.txt", "w") as file:
                file.write("\n".join(profiles))

            output_field.insert(tk.END, f"Saved profile for {ssid}.\n")
        except FileNotFoundError:
            # If file does not exist, create it and save the profile
            with open("saved_profiles.txt", "w") as file:
                file.write(f"{ssid}:{password}\n")
            output_field.insert




root = tk.Tk()
root.title("Wi-Fi Login")
root.configure(bg="black")


welcome_label = tk.Label(root, text="Welcome to Wi-Fi Login", fg="green", bg="black", font=("Helvetica", 16))
welcome_label.grid(row=0, column=0, columnspan=3, pady=10)

ssid_label = tk.Label(root, text="SSID:", fg="green", bg="black")
ssid_label.grid(row=1, column=0, pady=5)
ssid_entry = tk.Entry(root, fg="green", bg="black")
ssid_entry.grid(row=1, column=1, columnspan=2)

password_label = tk.Label(root, text="Password:", fg="green", bg="black")
password_label.grid(row=2, column=0, pady=5)
password_entry = tk.Entry(root, show="*", fg="green", bg="black")
password_entry.grid(row=2, column=1, columnspan=2)

save_button = tk.Button(root, text="Save Profile", fg="green", bg="black", command=save_profile, state=tk.DISABLED)
save_button.grid(row=3, column=0, columnspan=1, pady=5)

display_profiles_button = tk.Button(root, text="Display Saved Profiles", fg="green", bg="black",
                                    command=display_saved_profiles)
display_profiles_button.grid(row=3, column=1, columnspan=2, pady=5)

login_button = tk.Button(root, text="Login", fg="green", bg="black", command=login)
login_button.grid(row=3, column=3, pady=5)

output_field = tk.Text(root, height=10, width=35, wrap=tk.WORD, fg="green", bg="black")
output_field.grid(row=4, column=1, columnspan=2, pady=10)

# Somewhere near where you define root
profile_container = tk.Frame(root, bg="black")
profile_container.grid(row=5, column=0, columnspan=4)  # or wherever you want it in the layout

exit_button = tk.Button(root, text="Exit", fg="red", bg="black", command=root.quit)
exit_button.grid(row=6, column=3, columnspan=1, pady=5)

root.mainloop()
