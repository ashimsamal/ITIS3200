import os
import json
import hashlib
from pathlib import Path

# Calculates SHA-256 hash of file contents.
def hash_file(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read file in chunks.
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"Error hashing file {filepath}: {e}")
        return None

# Goes to user-specified folder and calls hash_file function.
def traverse_directory(directory_path):
    hash_dict = {}
    try:
        # Convert to Path object.
        dir_path = Path(directory_path)

        if not dir_path.exists():
            print(f"Error: Directory '{directory_path}' does not exist.")
            return None

        if not dir_path.is_dir():
            print(f"Error: '{directory_path}' is not a directory.")
            return None

        # Traverse all files in the folder.
        for item in dir_path.iterdir():
            if item.is_file():
                file_hash = hash_file(item)
                if file_hash:
                    # Store relative path.
                    hash_dict[str(item)] = file_hash
                    print(f"Hashed: {item.name}")

        return hash_dict

    except Exception as e:
        print(f"Error traversing directory: {e}")
        return None

# Calls traverse_directory function, takes generated hashes, 
# and makes JSON file.
def generate_table(directory_path, output_file="hash_table.json"):
    print(f"\nGenerating hash table for directory: {directory_path}")
    print("=" * 60)
    hash_dict = traverse_directory(directory_path)
    if hash_dict is None:
        return False

    if not hash_dict:
        print("No files found in directory.")
        return False

    # Save hash table to JSON file.
    try:
        with open(output_file, 'w') as f:
            json.dump(hash_dict, f, indent=4)

        print("=" * 60)
        print(f"Hash table generated successfully!")
        print(f"Hash table saved to: {output_file}")
        print(f"Total files hashed: {len(hash_dict)}")
        return True

    except Exception as e:
        print(f"Error saving hash table: {e}")
        return False

# Compares computed hashes to stored values in hash table.
def validate_hash(hash_table_file="hash_table.json"):
    try:
        # Load hash table.
        with open(hash_table_file, 'r') as f:
            stored_hashes = json.load(f)
    except FileNotFoundError:
        print(f"Error: Hash table file '{hash_table_file}' not found.")
        print("Please generate hash table first.")
        return False
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{hash_table_file}'.")
        return False
    except Exception as e:
        print(f"Error reading hash table: {e}")
        return False

    if not stored_hashes:
        print("Hash table is empty.")
        return False

    print("\nVerifying hashes...")
    print("=" * 60)

    # Get all folders from stored paths.
    directories = set()
    for filepath in stored_hashes.keys():
        directories.add(str(Path(filepath).parent))

    # Build current state: filepath -> hash
    current_files = {}
    for directory in directories:
        dir_path = Path(directory)
        if dir_path.exists() and dir_path.is_dir():
            for item in dir_path.iterdir():
                if item.is_file():
                    file_hash = hash_file(item)
                    if file_hash:
                        current_files[str(item)] = file_hash

    # Track matched stored files.
    matched_stored_files = set()
    updated_hash_table = {}
    changes_detected = False

    # Check current file.
    for current_path, current_hash in current_files.items():
        if current_path in stored_hashes:
            # File exists w/ same name.
            if stored_hashes[current_path] == current_hash:
                print(f"{current_path}: hash is VALID")
                updated_hash_table[current_path] = current_hash
                matched_stored_files.add(current_path)
            else:
                print(f"{current_path}: hash is INVALID")
                updated_hash_table[current_path] = current_hash
                matched_stored_files.add(current_path)
        else:
            # File does not exist w/ this name in stored hashes.
            # Check if hash matches any stored file.
            renamed_from = None
            for stored_path, stored_hash in stored_hashes.items():
                if stored_hash == current_hash and stored_path not in matched_stored_files:
                    # Found a match / renamed file.
                    renamed_from = stored_path
                    break

            if renamed_from:
                # File was renamed.
                old_name = Path(renamed_from).name
                new_name = Path(current_path).name
                print(f"File name change detected: '{old_name}' was renamed to '{new_name}'")
                updated_hash_table[current_path] = current_hash
                matched_stored_files.add(renamed_from)
                changes_detected = True
            else:
                # Really a new file.
                print(f"{current_path}: New file detected")
                updated_hash_table[current_path] = current_hash

    # Check for deleted files.
    for stored_path in stored_hashes.keys():
        if stored_path not in matched_stored_files:
            file_name = Path(stored_path).name
            print(f"{stored_path}: file has been deleted")

    print("=" * 60)
    print("Verification complete!")

    # Update hash table if rename detected.
    if changes_detected:
        try:
            with open(hash_table_file, 'w') as f:
                json.dump(updated_hash_table, f, indent=4)
            print(f"Hash table updated with renamed files.")
        except Exception as e:
            print(f"Warning: Could not update hash table: {e}")

    return True

# Handles logic for user input, calls functions, and outputs messages.
def main():
    print("=" * 60)
    print("ITIS-3200 Lab 02 Hashing Program")
    print("=" * 60)

    while True:
        print("\nPlease select an option:")
        print("1. Generate new hash table")
        print("2. Verify hashes")
        print("3. Exit")
        print()

        choice = input("Enter your choice (1, 2, or 3): ").strip()

        if choice == "1":
            # Generate new hash table.
            print()
            directory_path = input("Enter directory path to hash: ").strip()

            if directory_path:
                generate_table(directory_path)
            else:
                print("Error: No directory path provided.")

        elif choice == "2":
            # Verify hashes.
            validate_hash()

        elif choice == "3":
            # Exit.
            print("\nExiting program. Goodbye!")
            break

        else:
            print("\nInvalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()