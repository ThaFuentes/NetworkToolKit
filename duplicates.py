import os
import json


def remove_duplicates(passwords):
    return list(set(passwords))


def main():
    folder_path = 'lists'
    os.makedirs(folder_path, exist_ok=True)

    password_files = [file for file in os.listdir(folder_path) if file.endswith('.json')]

    for password_file in password_files:
        file_path = os.path.join(folder_path, password_file)
        with open(file_path, 'r') as file:
            content = file.read()

        # Replacing "][" with ",", to transform into a valid JSON array
        content = content.replace("][", "],[")
        data = json.loads('[' + content + ']')

        # Extracting passwords and removing duplicates
        passwords = [entry['password'] for sublist in data for entry in sublist]
        unique_passwords = remove_duplicates(passwords)

        # Calculate and print the number of duplicates removed
        num_removed = len(passwords) - len(unique_passwords)
        if num_removed > 0:
            print(f"Removed {num_removed} duplicate passwords from {password_file}")
        else:
            print(f"No duplicates found in {password_file}")

        # Writing the unique passwords back to the file
        with open(file_path, 'w') as file:
            json.dump([{"password": password} for password in unique_passwords], file, indent=4)


if __name__ == "__main__":
    main()
