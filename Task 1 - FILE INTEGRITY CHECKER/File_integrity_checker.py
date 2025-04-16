import hashlib
import json
import os
import time

def hash_file(file_path):
    """Generate SHA-256 hash of the file."""
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

def save_hash_to_json(file_path, hash_value):
    """Save the hash value to a JSON file."""
    data = {
        "file_path": file_path,
        "hash_value": hash_value
    }
    
    json_file_path = os.path.splitext(file_path)[0] + "_hash.json"
    
    with open(json_file_path, 'w') as json_file:
        json.dump(data, json_file, indent=4)
    
    print(f"Hash value saved to '{json_file_path}'")

def compare_hashes(file_path, new_hash):
    """Compare the new hash with existing hash files in the same directory."""
    directory = os.path.dirname(file_path)
    hash_file_pattern = os.path.join(directory, os.path.basename(file_path).replace('.txt', '') + '_hash.json')
    
    if os.path.isfile(hash_file_pattern):
        with open(hash_file_pattern, 'r') as json_file:
            data = json.load(json_file)
            existing_hash = data.get("hash_value")
            print(f"Existing hash value from '{hash_file_pattern}': {existing_hash}")
            if existing_hash == new_hash:
                print("The hash values match.")
            else:
                print("The hash values do not match.")
                print("File integrity compromised!")
    else:
        print("No existing hash file found for comparison.")

def ensure_integrity(hash_file_path, file_path):
    """Ensure the integrity of the file by comparing its hash with the stored hash."""
    if not os.path.isfile(hash_file_path):
        print(f"The hash file '{hash_file_path}' does not exist.")
        return
    
    current_hash = hash_file(file_path)
    
    with open(hash_file_path, 'r') as json_file:
        data = json.load(json_file)
        stored_hash = data.get("hash_value")
        
        print(f"Current hash of '{file_path}': {current_hash}")
        print(f"Stored hash from '{hash_file_path}': {stored_hash}")
        
        if current_hash == stored_hash:
            print("The file is intact. Integrity verified.")
        else:
            print("The file integrity is compromised! Hash values do not match.")

def monitor_file(file_path, check_interval=5, timeout=30):
    """Monitor the file for changes and stop after a timeout if no changes are detected."""
    print("Monitoring files for changes...")
    last_hash = hash_file(file_path)
    last_change_time = time.time()
    
    while True:
        time.sleep(check_interval)
        current_hash = hash_file(file_path)
        
        if current_hash != last_hash:
            print(f"Change detected in '{file_path}'!")
            print(f"New hash value: {current_hash}")
            last_hash = current_hash  # Update last_hash to the new hash
            last_change_time = time.time()  # Reset the last change time
        elif time.time() - last_change_time > timeout:
            print(f"No changes detected for {timeout} seconds. Stopping monitoring.")
            break

def main():
    # Prompt the user to enter the path to the text file
    file_path = input("Please enter the path to the text file: ")
    
    # Check if the file exists
    if not os.path.isfile(file_path):
        print("The specified file does not exist. Please check the path and try again.")
        return
    
    # Get the initial hash value
    new_hash = hash_file(file_path)
    
    # Print the hash value
    print(f"SHA-256 Hash of the file '{file_path}': {new_hash}")
    
    # Save the hash value to a JSON file
    save_hash_to_json(file_path, new_hash)
    
    # Compare the new hash with existing hash files
    compare_hashes(file_path, new_hash)
    
    # Start monitoring the file for changes with a timeout of 30 seconds
    monitor_file(file_path, check_interval=5, timeout=30)

    # Ask the user if they want to ensure integrity of the file
    check_integrity_choice = input("Do you want to ensure the integrity of the file? (yes/no): ").strip().lower()
    if check_integrity_choice == 'yes':
        hash_file_path = os.path.splitext(file_path)[0] + "_hash.json"
        ensure_integrity(hash_file_path, file_path)

if __name__ == "__main__":
    main()