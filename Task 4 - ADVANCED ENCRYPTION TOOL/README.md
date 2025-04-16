#  AES-256 File Encryption Tool

*COMPANY* : CODTECH IT SOLUTIONS<br>
*NAME* : AVINANADAN ROY<br>
*INTERN id* : CT04WT128<br>
*DOMAIN* : Cyber Security & Ethical Hacking<br>
*DURATION* : 4 Weeks<br>
*MENTOR* : NEELA SANTOSH<br>

---

##  Overview

This project is a file encryption and decryption tool using AES-256 encryption with a user-friendly GUI built using PyQt5. It allows users to securely encrypt and decrypt any file with a password, leveraging secure cryptographic standards.

---

##  Objective

To build a robust encryption application using AES-256 that:

- Provides a graphical interface for usability.
- Implements secure encryption and decryption.
- Uses strong password-based key derivation and cryptographic principles.

---

##  Prerequisites

Install required libraries:

```bash
pip install cryptography pyqt5
 
---

##  Project Steps Performed

1. **Planning**: Defined project requirements and selected AES-256 as the core encryption algorithm.  
2. **Library Selection**: Chose `cryptography` for encryption and `PyQt5` for building the GUI.  
3. **Environment Setup**: Installed all required Python libraries.  
4. **Encryption Logic**: Implemented AES-256 encryption using CBC mode with proper padding and secure key derivation using PBKDF2.  
5. **GUI Development**: Created an interactive application using PyQt5 to select files and enter passwords.  
6. **Integration**: Linked GUI with encryption and decryption functions.  
7. **Testing**: Verified functionality for various file types.

---

##  Libraries Used

- **`cryptography`** – Provides cryptographic recipes and primitives including AES encryption.  
- **`PyQt5`** – Used for building the GUI components of the application.  
- **`os`, `base64`** – Standard libraries for file handling and binary encoding.

---

##  Functions Used

###  1. `derive_key(password: str, salt: bytes)`

- Derives a 256-bit key from the password and salt using PBKDF2-HMAC-SHA256.
- Ensures strong resistance against brute-force attacks.

###  2. `encrypt_file(file_path, password)`

- Generates a random salt and IV.
- Derives a key from the password.
- Applies AES-256 encryption in CBC mode with padding.
- Saves encrypted data with salt and IV prefixed.

###  3. `decrypt_file(file_path, password)`

- Extracts salt and IV from the encrypted file.
- Derives the same key using the provided password and salt.
- Decrypts the ciphertext and removes padding.
- Saves the decrypted content to a new file.

###  4. `select_file()`

- Opens a file dialog for the user to select a file.

###  5. `encrypt()` (method of `EncryptionApp` class)

- Initiates the encryption process by selecting a file and password.

###  6. `decrypt()` (method of `EncryptionApp` class)

- Initiates the decryption process for an encrypted file using the password.

###  7. `init_ui()` (method of `EncryptionApp` class)

- Builds the graphical interface with input fields, buttons, and layout.

---

## Running the Application

- Run the tool:
``` bash
      python Advanced_encryption_tool.py

---

## Usage
Encrypt: Select a file, enter a password, and click "Encrypt File".

Decrypt: Select an .enc file, enter the original password, and click "Decrypt File".