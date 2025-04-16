# File Integrity Checker

*COMPANY* : CODTECH IT SOLUTIONS<br>
*NAME* : AVINANADAN ROY<br>
*INTERN id* : CT04WT128<br>
*DOMAIN* : Cyber Security & Ethical Hacking<br>
*DURATION* : 4 Weeks<br>
*MENTOR* : NEELA SANTOSH<br>

---

## Overview
The File Integrity Monitor is a Python script that monitors a specified file for changes and ensures its integrity by comparing its hash value with a stored hash value. The script uses SHA-256 hashing to generate a unique hash for the file, which is saved in a JSON file. The user can also check the integrity of the file at any time.

---

## Features
- Generate a SHA-256 hash of a specified file.
- Save the hash value to a JSON file for future reference.
- Monitor the file for changes and notify the user if any changes are detected.
- Ensure the integrity of the file by comparing its current hash with a stored hash.

---

## Prerequisites

Before running the File Integrity Monitor, ensure you have the following:

- **Python**: Version 3.6 or higher is recommended. You can download it from [python.org](https://www.python.org/downloads/).

No additional libraries need to be installed, as the script uses built-in Python libraries:
- `hashlib`: For generating SHA-256 hash values.
- `json`: For reading and writing JSON files.
- `os`: For file path manipulations and checking file existence.
- `time`: For implementing delays and tracking time for monitoring.

---

## Functions
The script contains the following functions:

1. **`hash_file(file_path)`**
   - Generates a SHA-256 hash of the specified file.
   - **Parameters**: 
     - `file_path`: The path to the file to be hashed.
   - **Returns**: The SHA-256 hash as a hexadecimal string.

2. **`save_hash_to_json(file_path, hash_value)`**
   - Saves the hash value to a JSON file.
   - **Parameters**: 
     - `file_path`: The path to the original file.
     - `hash_value`: The hash value to be saved.
   - **Returns**: None.

3. **`compare_hashes(file_path, new_hash)`**
   - Compares the newly generated hash with the existing hash stored in a JSON file.
   - **Parameters**: 
     - `file_path`: The path to the original file.
     - `new_hash`: The newly generated hash value.
   - **Returns**: None.

4. **`ensure_integrity(hash_file_path, file_path)`**
   - Ensures the integrity of the file by comparing its current hash with the stored hash in the JSON file.
   - **Parameters**: 
     - `hash_file_path`: The path to the JSON file containing the stored hash.
     - `file_path`: The path to the original file.
   - **Returns**: None.

5. **`monitor_file(file_path, check_interval=5, timeout=30)`**
   - Monitors the specified file for changes and stops after a timeout if no changes are detected.
   - **Parameters**: 
     - `file_path`: The path to the file to be monitored.
     - `check_interval`: The interval (in seconds) to check for changes (default is 5 seconds).
     - `timeout`: The duration (in seconds) to monitor before stopping (default is 30 seconds).
   - **Returns**: None.

6. **`main()`**
   - The main function that orchestrates the execution of the script.
   - Prompts the user for the file path, performs initial hashing, saves the hash, compares hashes, and starts monitoring.
   - Also prompts the user to check the integrity of the file after monitoring.
   - **Returns**: None.

---

## Usage
1. Clone the repository or download the script.
2. Ensure you have Python installed on your machine.
3. Run the script using the command:
   ```bash
         python File_integrity_checker.py

---

## Outputs

- Output 1 
![Image](https://github.com/user-attachments/assets/f7752428-815f-4058-b97a-29b8926e67d2)

- Output 2
![Image](https://github.com/user-attachments/assets/1c9678a4-db6f-4d15-a144-f3cf7c468046)
   
