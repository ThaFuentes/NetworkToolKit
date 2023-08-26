import random
import json
import tkinter as tk
import string
import os
import subprocess

common_names = [
    "John", "James", "Michael", "William", "David", "Richard", "Joseph", "Thomas", "Charles", "Daniel",
    "Matthew", "George", "Donald", "Paul", "Mark", "Andrew", "Edward", "Brian", "Kevin", "Jason",
    "Robert", "Ronald", "Timothy", "Anthony", "Chris", "Ryan", "Gary", "Jacob", "Larry", "Justin",
    "Nick", "Eric", "Adam", "Nathan", "Jeffrey", "Steve", "Samuel", "Frank", "Joshua", "Brandon",
    "Dylan", "Gregory", "Henry", "Dennis", "Walter", "Patrick", "Peter", "Roger", "Jerry", "Douglas",
    "Zachary", "Harold", "Carl", "Keith", "Gerald", "Terry", "Scott", "Alexander", "Benjamin", "Bruce",
    "Raymond", "Phillip", "Jeremy", "Victor", "Jack", "Albert", "Willie", "Billy", "Joe", "Johnny",
    "Fred", "Sam", "Roy", "Louis", "Arthur", "Lawrence", "Randy", "Harry", "Wayne", "Russell",
    "Jimmy", "Alan", "Stanley", "Howard", "Martin", "Oscar", "Eugene", "Vincent", "Bobby", "Ralph",
    "Clarence", "Sean", "Jesse", "Marvin", "Ernest", "Earl", "Curtis", "Leroy", "Wesley", "Norman",
    "Leonard", "Francis", "Tom", "Travis", "Glenn", "Floyd", "Gordon", "Mike", "Dale", "Charlie",
    "Lewis", "Alfred", "Clyde", "Vernon", "Milton", "Theodore", "Melvin", "Bernard", "Edwin", "Calvin",
    "Sidney", "Lloyd", "Maurice", "Chester", "Leslie", "Max", "Herman", "Leon", "Tony", "Dean",
    "Derrick", "Allan", "Gilbert", "Glen", "Gene", "Ross", "Don", "Isaac", "Arnold", "Lester",
    "Elmer", "Felix", "Neil", "Hugo", "Oliver", "Miles", "Perry", "Ted", "Karl", "Nelson",
    "Duane", "Gabriel", "Morris", "Manuel", "Phillip", "Clifford", "Marshall", "Jon", "Lewis",
    "Owen", "Freddie", "Clayton", "Cecil", "Julian", "Kelly", "Guy", "Warren", "Mack", "Daryl",
    "Cory", "Claude", "Neil", "Lonnie", "Lyle", "Alvin", "Simon", "Stuart", "Wendell", "Jerome"
]


def somewhere_in_password(password, insert_text):
    # Determine a random position to insert the additional text
    insert_position = random.randint(0, len(password))

    # Insert the additional text at the random position
    return password[:insert_position] + insert_text + password[insert_position:]


def generate_passwords(length_range, include_name, mode, desired_output_size, sequential_numbers, known_start,
                       known_end, insert_text):
    characters = ''
    if mode == 'Random':
        characters = string.ascii_letters + string.digits + string.punctuation
    elif mode == 'Numbers Only':
        characters = string.digits
    else:  # Full Mix
        characters = string.ascii_letters + string.digits + string.punctuation

    total_output_size = 0
    for num in range(length_range[0], length_range[1] + 1):
        if sequential_numbers:
            min_num = int('1' * num)
            max_num = int('9' * num)
            for i in range(min_num, max_num + 1):
                password = str(i).zfill(num)
                yield {"password": password}
                total_output_size += len(json.dumps({"password": password}))
                if total_output_size >= desired_output_size:
                    return
        else:
            while True:
                password_length = num - len(known_start) - len(known_end) - len(insert_text)  # Subtract insert_text
                if password_length < 0:
                    continue
                password = known_start + ''.join(random.choice(characters) for _ in range(password_length))
                if include_name:
                    password += random.choice(common_names)  # Add common name if include_name is True
                if insert_text:
                    password = somewhere_in_password(password, insert_text)
                password += known_end
                # Check the length after inserting all elements
                if len(password) == num:
                    yield {"password": password}
                    total_output_size += len(json.dumps({"password": password}))
                    if total_output_size >= desired_output_size:
                        return


def generate_password_with_consecutive_numbers():
    include_name = include_name_var.get()
    mode = mode_var.get()
    sequential_numbers = sequential_numbers_var.get()
    known_start = known_start_var.get()  # Retrieve the known start
    known_end = known_end_var.get()  # Retrieve the known end
    insert_text = insert_text_var.get()  # Retrieve the text to insert

    folder_path = 'lists'
    os.makedirs(folder_path, exist_ok=True)
    file_path = os.path.join(folder_path, 'auto_pass_generated.json')

    length_range = [int(value) for value in length_range_var.get().split('-')]
    desired_output_size = int(desired_size_var.get()) * (1024 * 1024)

    total_output_size = 0
    num_passwords = 0
    with open(file_path, 'w') as file:
        for password in generate_passwords(length_range, include_name, mode, desired_output_size, sequential_numbers,
                                           known_start, known_end, insert_text):  # Added insert_text argument
            json.dump([password], file)
            total_output_size += len(json.dumps([password]))
            num_passwords += 1
            if total_output_size >= desired_output_size:
                break

    output_file_size = total_output_size / (1024 * 1024)
    password_label.config(
        text=f"Password list generated: {num_passwords} passwords. Output file size: {output_file_size:.2f} MB.")


def run_duplicates_script():
    try:
        result = subprocess.run(["python", "duplicates.py"], stdout=subprocess.PIPE, check=True, text=True)
        duplicate_result_label.config(text=result.stdout.strip())
    except subprocess.CalledProcessError as e:
        duplicate_result_label.config(text=f"An error occurred: {e}")


label_style = {'bg': 'black', 'fg': 'green'}
root = tk.Tk()
root.title("Password Generator")
root.configure(bg='black')

include_name_var = tk.BooleanVar()
mode_var = tk.StringVar()
mode_var.set('Numbers Only')
length_range_var = tk.StringVar()
custom_input_var = tk.StringVar()
known_start_var = tk.StringVar()
insert_text_var = tk.StringVar()
known_end_var = tk.StringVar()
desired_size_var = tk.StringVar()
sequential_numbers_var = tk.BooleanVar()
sequential_numbers_var.set(False)

# Welcome Label (outside the frames, at the top)
welcome_label = tk.Label(root, text="  Welcome to Password Generator  \nExample Pass:cats7777", **label_style,
                         font=("Helvetica", 16))
welcome_label.pack(pady=10)

# Create frames
left_frame = tk.Frame(root, bg='black')
left_frame.pack(side=tk.LEFT, padx=10, pady=10)
right_frame = tk.Frame(root, bg='black')
right_frame.pack(side=tk.LEFT, padx=10, pady=10)

# Adjust the row for the "Mode:" label in the right frame
mode_label = tk.Label(right_frame, text="Mode:", **label_style)
mode_label.grid(row=0, column=0, pady=5, sticky="w")  # Align label with the start of the cell

mode_menu = tk.OptionMenu(right_frame, mode_var, 'Numbers Only', 'Letters Only', 'Mix Numbers Letters',
                          'Mix Numbers Letters Special Characters')
mode_menu.config(bg='black', fg='green')
mode_menu.grid(row=0, column=1)

include_name_checkbox = tk.Checkbutton(right_frame, text="Include common name", variable=include_name_var,
                                       **label_style)
include_name_checkbox.grid(row=1, column=0, columnspan=2, pady=5, sticky="w")

sequential_numbers_checkbox = tk.Checkbutton(right_frame, text="Sequential numbers", variable=sequential_numbers_var,
                                             **label_style)
sequential_numbers_checkbox.grid(row=2, column=0, columnspan=2, pady=5, sticky="w")

exclusive_notice_label = tk.Label(right_frame, text="Only Pick One(1)", **label_style)
exclusive_notice_label.grid(row=3, column=0, columnspan=2, pady=5, sticky="w")

# Right Frame
length_range_label = tk.Label(left_frame, text="Length range (e.g. 8-10):\n", **label_style)
length_range_label.grid(row=0, column=0, pady=5)
length_range_entry = tk.Entry(left_frame, fg='green', bg='black', textvariable=length_range_var)
length_range_entry.grid(row=0, column=1)

known_start_label = tk.Label(left_frame, text="Known Start (e.g. cats):", **label_style)
known_start_label.grid(row=1, column=0, pady=5)
known_start_entry = tk.Entry(left_frame, fg='green', bg='black', textvariable=known_start_var)
known_start_entry.grid(row=1, column=1)

insert_text_label = tk.Label(left_frame, text="Somewhere In Pass(e.g ats):", **label_style)
insert_text_label.grid(row=2, column=0, pady=5)
insert_text_entry = tk.Entry(left_frame, fg='green', bg='black', textvariable=insert_text_var)
insert_text_entry.grid(row=2, column=1)

known_end_label = tk.Label(left_frame, text="Known End (e.g. 7777):", **label_style)
known_end_label.grid(row=3, column=0, pady=5)
known_end_entry = tk.Entry(left_frame, fg='green', bg='black', textvariable=known_end_var)
known_end_entry.grid(row=3, column=1)

desired_size_label = tk.Label(left_frame, text="Desired size (MB):", **label_style)
desired_size_label.grid(row=4, column=0, pady=5)
desired_size_entry = tk.Entry(left_frame, fg='green', bg='black', textvariable=desired_size_var)
desired_size_entry.grid(row=4, column=1)
desired_size_entry.insert(0, "1")

generate_button = tk.Button(right_frame, text="Generate Password", command=generate_password_with_consecutive_numbers,
                            fg='green', bg='black')
generate_button.grid(row=5, column=0, columnspan=2, pady=10)

remove_duplicates_button = tk.Button(right_frame, text="Remove Duplicates", command=run_duplicates_script, fg='green',
                                     bg='black')
remove_duplicates_button.grid(row=6, column=0, columnspan=2, pady=10)

password_label = tk.Label(left_frame, text="", **label_style)
password_label.grid(row=7, column=0, columnspan=2)

duplicate_result_label = tk.Label(left_frame, text="", **label_style)
duplicate_result_label.grid(row=8, column=0, columnspan=2)

root.mainloop()
