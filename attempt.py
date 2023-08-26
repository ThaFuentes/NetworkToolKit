import json
import time
import tkinter as tk
from tkinter import scrolledtext


def count_passwords(filename='output.json'):
    try:
        with open(filename, 'r') as file:
            data = json.load(file)
        result = []
        for ssid, passwords in data.items():
            password_count = len(passwords)
            result.append(f"SSID: {ssid} | Password Attempts: {password_count}")
        return '\n'.join(result)
    except Exception as e:
        return f"An error occurred: {e}"


def pass_attempts():
    def update_text():
        text = count_passwords()
        text_box.config(state=tk.NORMAL)
        text_box.delete(1.0, tk.END)
        text_box.insert(tk.INSERT, text)
        text_box.config(state=tk.DISABLED)
        root.after(10000, update_text)

    def loading_animation():
        loading_symbols = [
            "○",
            "◔",
            "◑",
            "◕",
            "●"
        ]
        loading_label.config(text=loading_symbols[loading_animation.index])
        loading_animation.index = (loading_animation.index + 1) % len(loading_symbols)
        root.after(2000, loading_animation)

    global root
    root = tk.Tk()
    root.title("WiFi Password Counter")
    root.config(bg="black")

    text_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=10, bg="black", fg="green", state=tk.DISABLED)
    text_box.pack(pady=10)

    loading_label = tk.Label(root, text="", bg="black", fg="green", font=("Courier", 20))
    loading_label.pack()

    loading_animation.index = 0

    update_text()
    loading_animation()
    root.mainloop()
